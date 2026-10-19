"""
Thread-based packet capture worker for the NetSentry web dashboard.

Runs entirely in a stdlib threading.Thread — no PySide6 dependency.
Communicates with the asyncio layer via a bounded queue.Queue whose
items are already-serialised message dicts ready to fan out over
WebSockets.

Message types placed on the queue
----------------------------------
{"type": "packets", "data": [<row>, ...]}
{"type": "stats",   "data": {"count": int, "bytes": int,
                              "pps": float, "protocols": dict}}
{"type": "alerts",  "data": [<alert>, ...]}
{"type": "status",  "data": {"state": "running"|"stopped"|"error",
                              "message": str}}

Row schema (identical to the desktop CaptureWorker)
----------------------------------------------------
{"timestamp": str, "protocol": str,
 "src": str, "sport": str,
 "dst": str, "dport": str,
 "size": int, "flags": str}

Alert schema (produced by SecurityDetector.analyze_packet)
-----------------------------------------------------------
{"timestamp": str, "type": str, "severity": str,
 "source_ip": str, "destination_ip": str,
 "destination_port": int|None, "reason": str}
"""

import queue
import threading
from datetime import datetime
from pathlib import Path
from time import monotonic

from scapy.all import AsyncSniffer, PcapWriter, TCP

from main import get_protocol, get_addresses, get_ports
from netsentry.security_detector import SecurityDetector

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Maximum items held in the outbound queue before overflow policy kicks in.
# At ~50-row batches this is ~200 batches ≈ 10 000 queued rows, well within
# memory limits while providing ample head-room for a slow consumer.
_QUEUE_MAXSIZE = 200

# Rows accumulated per packet batch before a "packets" message is emitted.
_BATCH_SIZE = 50

# How often (seconds) the stats-flush loop wakes up to publish a "stats"
# snapshot even when the batch threshold hasn't been reached.
_STATS_INTERVAL = 0.25


class WebCaptureWorker:
    """Capture packets in a background thread and feed a bounded queue.

    Usage
    -----
    worker = WebCaptureWorker(interface="eth0", bpf_filter="tcp",
                               output_path="captures/capture.pcap")
    worker.start()          # returns immediately
    msg = worker.queue.get()
    worker.stop()           # signal stop; blocks until thread exits
    worker.join(timeout=5)  # optional extra safety join

    The worker becomes unusable after stop()/join().  Create a new instance
    for the next capture session.

    Thread-safety
    -------------
    All mutable state is protected by self._lock.
    queue.Queue is thread-safe by design.
    The Scapy callback thread writes into _pending_rows and _stats counters
    under the lock; the stats-flush loop drains them at _STATS_INTERVAL.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str | None = None,
        output_path: str = "captures/capture.pcap",
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter or None
        self.output_path = Path(output_path)

        # Outbound message queue consumed by the asyncio drain task.
        # maxsize prevents unbounded growth when the consumer is slow.
        self.queue: queue.Queue[dict] = queue.Queue(maxsize=_QUEUE_MAXSIZE)

        # Detector is reset at each start() call.
        self._detector = SecurityDetector()

        # Internal state — all access under self._lock.
        self._lock = threading.Lock()
        self._pending_rows: list[dict] = []
        self._packet_count: int = 0
        self._total_bytes: int = 0
        self._protocol_counts: dict[str, int] = {}
        self._last_pps_time: float = 0.0
        self._last_pps_count: int = 0

        # Concurrency primitives.
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Scapy objects — set inside the thread, cleared on exit.
        self._sniffer: AsyncSniffer | None = None
        self._writer: PcapWriter | None = None

        # Set to True once stop() has been called so callers can check.
        self._stopping: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the capture thread.  Raises RuntimeError if already started."""
        if self._thread is not None:
            raise RuntimeError(
                "WebCaptureWorker.start() called on an already-started worker. "
                "Create a new instance for each capture session."
            )
        self._stop_event.clear()
        self._stopping = False
        self._detector.reset()
        self._thread = threading.Thread(
            target=self._run,
            name="WebCaptureWorker",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the worker to stop and wait for the thread to exit.

        Safe to call multiple times.  Returns immediately if the worker
        was never started or has already stopped.
        """
        self._stopping = True
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=8)

    def join(self, timeout: float | None = None) -> None:
        """Extra join for callers that want to wait with a custom timeout."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        """True while the capture thread is alive and not yet stopped."""
        return (
            self._thread is not None
            and self._thread.is_alive()
            and not self._stopping
        )

    # ------------------------------------------------------------------
    # Internal — capture thread entry point
    # ------------------------------------------------------------------

    def _run(self) -> None:
        error_message: str | None = None

        try:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

            self._writer = PcapWriter(
                str(self.output_path),
                append=False,
                sync=False,
            )

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=False,
            )

            self._sniffer.start()
            now = monotonic()
            with self._lock:
                self._last_pps_time = now
                self._last_pps_count = 0

            self._put_status("running", "Capture started.")

            # Stats-flush loop: wakes every _STATS_INTERVAL seconds.
            # Exits when stop is requested or the sniffer dies on its own.
            while not self._stop_event.wait(timeout=_STATS_INTERVAL):
                if not self._sniffer.running:
                    break
                self._flush_pending()

            # Drain any final rows after the loop exits.
            self._flush_pending()

        except Exception as exc:
            error_message = str(exc)

        finally:
            # Stop the sniffer if still running.  After this block the Scapy
            # callback thread is fully dead, so no more _process_packet calls
            # can arrive.
            try:
                if self._sniffer is not None and self._sniffer.running:
                    self._sniffer.stop(join=True)
            except Exception as exc:
                if error_message is None:
                    error_message = f"Sniffer stop failed: {exc}"

            # Flush any rows that arrived between the pre-finally drain
            # (end of the stats loop) and the sniffer callback thread
            # fully exiting.  Safe to call here because the callback is
            # guaranteed dead; runs regardless of whether stop raised.
            self._flush_pending()

            # Close the PCAP writer.
            try:
                if self._writer is not None:
                    self._writer.close()
            except Exception as exc:
                if error_message is None:
                    error_message = f"PCAP close failed: {exc}"

            self._sniffer = None
            self._writer = None

            if error_message:
                self._put_status("error", error_message)
            else:
                with self._lock:
                    count = self._packet_count
                self._put_status(
                    "stopped",
                    f"Capture stopped. {count} packets saved to "
                    f"{self.output_path.resolve()}",
                )

    # ------------------------------------------------------------------
    # Scapy callback — runs on Scapy's internal OS thread
    # ------------------------------------------------------------------

    def _process_packet(self, packet) -> None:
        """Process one packet from Scapy.

        Must not block: if the queue is full the packet row is silently
        dropped rather than stalling the Scapy capture thread.
        """
        if self._stop_event.is_set():
            return

        try:
            protocol = str(get_protocol(packet))
            src, dst = get_addresses(packet)
            sport, dport = get_ports(packet)
            packet_size = len(packet)

            flags = (
                str(packet[TCP].flags)
                if packet.haslayer(TCP)
                else "-"
            )

            try:
                timestamp = datetime.fromtimestamp(
                    float(packet.time)
                ).strftime("%H:%M:%S.%f")[:-3]
            except (ValueError, TypeError, OSError, OverflowError):
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            row = {
                "timestamp": timestamp,
                "protocol": protocol,
                "src": str(src),
                "sport": str(sport),
                "dst": str(dst),
                "dport": str(dport),
                "size": packet_size,
                "flags": flags,
            }

            # Write to PCAP and accumulate stats under the lock.
            batch_to_emit: list[dict] | None = None
            with self._lock:
                if self._writer is not None:
                    self._writer.write(packet)

                self._packet_count += 1
                self._total_bytes += packet_size
                self._protocol_counts[protocol] = (
                    self._protocol_counts.get(protocol, 0) + 1
                )
                self._pending_rows.append(row)

                if len(self._pending_rows) >= _BATCH_SIZE:
                    batch_to_emit = self._pending_rows
                    self._pending_rows = []

            # Run detection outside the lock — no shared state modified here.
            alerts = self._detector.analyze_packet(row)
            if alerts:
                self._put_nowait({"type": "alerts", "data": alerts})

            if batch_to_emit is not None:
                self._put_nowait({"type": "packets", "data": batch_to_emit})

        except Exception:
            # Never let a packet-processing exception propagate into Scapy's
            # internal sniffer thread — it would kill the capture silently.
            pass

    # ------------------------------------------------------------------
    # Stats flush — runs on the capture thread
    # ------------------------------------------------------------------

    def _flush_pending(self) -> None:
        """Drain pending rows and emit a stats snapshot."""
        now = monotonic()
        with self._lock:
            batch = self._pending_rows
            self._pending_rows = []
            count = self._packet_count
            total_bytes = self._total_bytes
            protocol_counts = dict(self._protocol_counts)
            elapsed = now - self._last_pps_time
            delta_packets = count - self._last_pps_count
            self._last_pps_time = now
            self._last_pps_count = count

        if batch:
            self._put_nowait({"type": "packets", "data": batch})

        pps = round(delta_packets / elapsed, 1) if elapsed > 0 else 0.0
        self._put_nowait({
            "type": "stats",
            "data": {
                "count": count,
                "bytes": total_bytes,
                "pps": pps,
                "protocols": protocol_counts,
            },
        })

    # ------------------------------------------------------------------
    # Queue helpers
    # ------------------------------------------------------------------

    def _put_nowait(self, message: dict) -> None:
        """Put a message on the queue without blocking.

        If the queue is full the message is dropped.  This keeps the
        Scapy callback and the stats-flush loop non-blocking even when
        the asyncio consumer falls behind.
        """
        try:
            self.queue.put_nowait(message)
        except queue.Full:
            pass

    def _put_status(self, state: str, message: str) -> None:
        """Emit a status message.  Blocks briefly to ensure delivery."""
        try:
            self.queue.put(
                {"type": "status", "data": {"state": state, "message": message}},
                timeout=2,
            )
        except queue.Full:
            pass
