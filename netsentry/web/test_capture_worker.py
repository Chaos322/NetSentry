"""Unit tests for netsentry.web.capture_worker — no real capture, no PySide6."""

import queue
import sys
import types

# ── Guard: poison PySide6 before any project import ────────────────────────
_poison = types.ModuleType("PySide6")
_poison.__path__ = []
sys.modules["PySide6"] = _poison
for _sub in ("PySide6.QtCore", "PySide6.QtWidgets", "PySide6.QtGui"):
    _m = types.ModuleType(_sub)
    sys.modules[_sub] = _m

# ── Imports under test ──────────────────────────────────────────────────────
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether           # noqa: E402

from netsentry.web.capture_worker import (  # noqa: E402
    WebCaptureWorker,
    _BATCH_SIZE,
    _QUEUE_MAXSIZE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _NoopWriter:
    """Drop-in for PcapWriter that does no file I/O.

    Accepts and ignores all constructor arguments so it can be patched
    directly over PcapWriter in the capture_worker module namespace.
    """
    def __init__(self, *args, **kwargs):
        pass

    def write(self, pkt):
        pass

    def close(self):
        pass


def _make_tcp(src="10.0.0.1", dst="10.0.0.2",
              sport=1234, dport=80, flags="S"):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = 1_700_000_000.0
    return pkt


def _make_udp(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=53):
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    pkt.time = 1_700_000_000.0
    return pkt


def _fresh_worker():
    """Return a worker wired with a no-op writer but no real thread."""
    w = WebCaptureWorker(interface="lo", output_path="captures/test_tmp.pcap")
    w._writer = _NoopWriter()
    return w


# ---------------------------------------------------------------------------
# Test 1 — Row schema
# ---------------------------------------------------------------------------

def test_row_schema():
    w = _fresh_worker()
    w._process_packet(_make_tcp())

    with w._lock:
        assert len(w._pending_rows) == 1
        row = w._pending_rows[0]

    expected = {"timestamp", "protocol", "src", "sport", "dst", "dport", "size", "flags"}
    assert set(row.keys()) == expected, f"Schema mismatch: {set(row.keys())}"
    assert row["protocol"] == "TCP"
    assert row["src"] == "10.0.0.1"
    assert row["dst"] == "10.0.0.2"
    assert row["sport"] == "1234"
    assert row["dport"] == "80"
    assert row["flags"] == "S"
    assert isinstance(row["size"], int) and row["size"] > 0
    print("PASS  test_row_schema")


# ---------------------------------------------------------------------------
# Test 2 — Batch threshold triggers a packets message
# ---------------------------------------------------------------------------

def test_batch_threshold():
    w = _fresh_worker()
    pkt = _make_tcp()
    for _ in range(_BATCH_SIZE):
        w._process_packet(pkt)

    # Drain all queued messages — alerts may arrive before the packets batch
    msgs = {}
    while not w.queue.empty():
        m = w.queue.get_nowait()
        msgs[m["type"]] = m

    assert "packets" in msgs, f"No packets message found; got types: {list(msgs)}"
    assert len(msgs["packets"]["data"]) == _BATCH_SIZE, (
        f"Expected {_BATCH_SIZE} rows, got {len(msgs['packets']['data'])}"
    )
    with w._lock:
        assert w._pending_rows == [], "pending_rows not cleared after batch"
    print(f"PASS  test_batch_threshold  ({_BATCH_SIZE} rows)")


# ---------------------------------------------------------------------------
# Test 3 — Stats counter accumulation
# ---------------------------------------------------------------------------

def test_stats_counters():
    w = _fresh_worker()
    for _ in range(3):
        w._process_packet(_make_tcp())
    for _ in range(2):
        w._process_packet(_make_udp())

    with w._lock:
        assert w._packet_count == 5
        assert w._total_bytes > 0
        assert w._protocol_counts.get("TCP") == 3
        assert w._protocol_counts.get("UDP") == 2
    print("PASS  test_stats_counters")


# ---------------------------------------------------------------------------
# Test 4 — flush_pending drains rows and emits packets + stats messages
# ---------------------------------------------------------------------------

def test_flush_pending():
    w = _fresh_worker()
    w._last_pps_time = 0.0  # trigger valid pps calculation
    for _ in range(3):
        w._process_packet(_make_tcp())

    w._flush_pending()

    # Collect all messages from queue
    msgs = {}
    while not w.queue.empty():
        m = w.queue.get_nowait()
        msgs[m["type"]] = m

    assert "packets" in msgs, "No packets message after flush"
    assert len(msgs["packets"]["data"]) == 3
    assert "stats" in msgs, "No stats message after flush"
    stats = msgs["stats"]["data"]
    assert stats["count"] == 3
    assert stats["bytes"] > 0
    assert "protocols" in stats
    assert "pps" in stats
    with w._lock:
        assert w._pending_rows == [], "pending_rows not cleared after flush"
    print("PASS  test_flush_pending")


# ---------------------------------------------------------------------------
# Test 5 — Security detector integration (SYN flood triggers alert)
# ---------------------------------------------------------------------------

def test_security_detector_syn_flood():
    w = _fresh_worker()
    # Default threshold is 10 SYNs in 10 s — send 11
    syn = _make_tcp(flags="S")
    for _ in range(11):
        w._process_packet(syn)

    # Drain queue for alert messages
    alerts_found = []
    while not w.queue.empty():
        m = w.queue.get_nowait()
        if m["type"] == "alerts":
            alerts_found.extend(m["data"])

    assert len(alerts_found) >= 1, "Expected at least one SYN flood alert"
    alert = alerts_found[0]
    expected_alert_keys = {
        "timestamp", "type", "severity",
        "source_ip", "destination_ip", "destination_port", "reason",
    }
    assert set(alert.keys()) == expected_alert_keys, (
        f"Alert schema mismatch: {set(alert.keys())}"
    )
    assert alert["type"] == "Repeated TCP SYN attempts"
    assert alert["severity"] == "High"
    assert alert["source_ip"] == "10.0.0.1"
    print("PASS  test_security_detector_syn_flood")


# ---------------------------------------------------------------------------
# Test 6 — Watched-port alert
# ---------------------------------------------------------------------------

def test_security_detector_watched_port():
    w = _fresh_worker()
    # Port 4444 is in the default watched set
    pkt = _make_tcp(dport=4444, flags="PA")
    w._process_packet(pkt)

    alerts_found = []
    while not w.queue.empty():
        m = w.queue.get_nowait()
        if m["type"] == "alerts":
            alerts_found.extend(m["data"])

    assert len(alerts_found) >= 1, "Expected watched-port alert for port 4444"
    assert alerts_found[0]["type"] == "Watched destination port"
    assert alerts_found[0]["destination_port"] == 4444
    print("PASS  test_security_detector_watched_port")


# ---------------------------------------------------------------------------
# Test 7 — Stop signal prevents further packet processing
# ---------------------------------------------------------------------------

def test_stop_prevents_processing():
    w = _fresh_worker()
    w._process_packet(_make_tcp())           # one row buffered

    w._stop_event.set()                      # simulate stop signal
    w._process_packet(_make_tcp())           # must be a no-op

    with w._lock:
        assert len(w._pending_rows) == 1, (
            "Stop event did not prevent subsequent packet processing"
        )
    print("PASS  test_stop_prevents_processing")


# ---------------------------------------------------------------------------
# Test 8 — Double-start raises RuntimeError
# ---------------------------------------------------------------------------

def test_double_start_raises():
    w = WebCaptureWorker(interface="lo", output_path="captures/test_tmp.pcap")
    # Fake an already-started thread
    w._thread = object()
    try:
        w.start()
        print("FAIL  test_double_start_raises — no exception raised")
    except RuntimeError:
        print("PASS  test_double_start_raises")


# ---------------------------------------------------------------------------
# Test 9 — Queue overflow drops messages without blocking
# ---------------------------------------------------------------------------

def test_queue_overflow():
    w = _fresh_worker()
    # Fill queue to capacity with dummy messages
    for i in range(_QUEUE_MAXSIZE):
        w.queue.put_nowait({"type": "dummy", "data": i})

    # _put_nowait on a full queue must not raise or block
    w._put_nowait({"type": "overflow", "data": "dropped"})
    assert w.queue.full()
    # The overflow message was dropped — queue size unchanged
    assert w.queue.qsize() == _QUEUE_MAXSIZE
    print(f"PASS  test_queue_overflow  (maxsize={_QUEUE_MAXSIZE})")


# ---------------------------------------------------------------------------
# Test 10 — is_running reflects thread state correctly
# ---------------------------------------------------------------------------

def test_is_running_states():
    w = WebCaptureWorker(interface="lo", output_path="captures/test_tmp.pcap")
    assert not w.is_running, "New worker must not be running"

    # After stop() with no thread started — must not raise
    w.stop()
    assert not w.is_running
    print("PASS  test_is_running_states")


# ---------------------------------------------------------------------------
# Test 11 — Startup error reported via queue (fully synthetic — no real I/O)
# ---------------------------------------------------------------------------

def test_startup_error_queued():
    """
    Verify that a worker whose sniffer raises on stop() emits a terminal
    'error' status message.

    Fully synthetic: AsyncSniffer and PcapWriter are replaced with in-test
    fakes injected into the capture_worker module namespace.  No real Npcap
    socket is opened, no PCAP file is written, and the PcapWriter warning
    cannot occur.

    The fake sniffer simulates the Windows behaviour where:
      - start()           succeeds silently
      - .running          stays True
      - stop(join=True)   raises ValueError (bad interface discovered late)
    """
    import netsentry.web.capture_worker as cw_mod

    # ── Fake AsyncSniffer ────────────────────────────────────────────────
    class _FakeSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self._prn = kwargs.get("prn")

        def start(self):
            self.running = True          # succeeds silently, like Windows

        def stop(self, join=True):
            # Simulates the ValueError raised for an invalid interface
            raise ValueError("Interface '__no_such_iface_xyz__' not found !")

    # ── Patch capture_worker module names before start() is called ───────
    orig_sniffer_cls = cw_mod.AsyncSniffer
    orig_writer_cls  = cw_mod.PcapWriter
    cw_mod.AsyncSniffer = _FakeSniffer
    cw_mod.PcapWriter   = _NoopWriter   # already defined in this test module

    try:
        w = WebCaptureWorker(
            interface="__no_such_iface_xyz__",
            output_path="captures/test_tmp.pcap",
        )
        w.start()
        # stop() sets the event, which makes the stats-flush loop exit on its
        # next wake-up (_STATS_INTERVAL = 0.25 s), then the finally block runs.
        w.stop()

    finally:
        # Always restore the real classes, even if an assertion fails.
        cw_mod.AsyncSniffer = orig_sniffer_cls
        cw_mod.PcapWriter   = orig_writer_cls

    # ── Collect status messages from queue ───────────────────────────────
    status_msgs = []
    while not w.queue.empty():
        try:
            msg = w.queue.get_nowait()
            if msg["type"] == "status":
                status_msgs.append(msg)
        except queue.Empty:
            break

    assert status_msgs, "No status message received at all"
    terminal = [m for m in status_msgs if m["data"]["state"] in ("error", "stopped")]
    assert terminal, (
        f"No terminal status; states seen: "
        f"{[m['data']['state'] for m in status_msgs]}"
    )
    final = terminal[-1]
    assert final["data"]["state"] == "error", (
        f"Expected 'error' state for sniffer stop failure, "
        f"got {final['data']['state']!r}"
    )
    assert "not found" in final["data"]["message"].lower(), (
        f"Expected ValueError text in message, got: {final['data']['message']!r}"
    )
    print(f"PASS  test_startup_error_queued  "
          f"(state={final['data']['state']!r}, "
          f"message={final['data']['message']!r})")


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_row_schema,
        test_batch_threshold,
        test_stats_counters,
        test_flush_pending,
        test_security_detector_syn_flood,
        test_security_detector_watched_port,
        test_stop_prevents_processing,
        test_double_start_raises,
        test_queue_overflow,
        test_is_running_states,
        test_startup_error_queued,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as exc:
            print(f"FAIL  {t.__name__}: {exc}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
