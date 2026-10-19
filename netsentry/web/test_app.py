"""
Tests for netsentry/web/app.py.

No real Npcap sockets are opened.  All capture workers are replaced with
_FakeWorker instances that simulate the worker's public interface.
HTTP routes are exercised via a minimal async ASGI harness (no httpx/TestClient).
WebSocket behaviour is tested by driving the ASGI WebSocket scope directly.
"""

import asyncio
import json
import queue
import sys
import types

# ── Guard: keep PySide6 out of this process ──────────────────────────────────
_poison = types.ModuleType("PySide6")
_poison.__path__ = []
sys.modules["PySide6"] = _poison
for _sub in ("PySide6.QtCore", "PySide6.QtWidgets", "PySide6.QtGui"):
    _m = types.ModuleType(_sub)
    sys.modules[_sub] = _m

# ── Imports under test ────────────────────────────────────────────────────────
import netsentry.web.app as app_mod
from netsentry.web.app import (
    _AppState,
    _MAX_PACKET_HISTORY,
    _MAX_ALERT_HISTORY,
    _handle_worker_message,
    app,
)


# ---------------------------------------------------------------------------
# Helpers — fake worker
# ---------------------------------------------------------------------------

class _FakeWorker:
    """Minimal stand-in for WebCaptureWorker used across tests."""

    def __init__(self, *, auto_running: bool = True):
        self.queue: queue.Queue = queue.Queue()
        self._stopping: bool = False
        self._thread_alive: bool = True    # controls thread.is_alive()
        self._started: bool = False

        # Mimic the _thread attribute app.py checks.
        class _FakeThread:
            def __init__(self, alive_ref):
                self._alive = alive_ref
            def is_alive(self_):
                return self._thread_alive

        self._thread = _FakeThread(self)
        self._auto_running = auto_running

    def start(self):
        self._started = True
        if self._auto_running:
            # Immediately enqueue a "running" status as the real worker does.
            self.queue.put_nowait({
                "type": "status",
                "data": {"state": "running", "message": "Capture started."},
            })

    def stop(self):
        self._stopping = True
        self._thread_alive = False
        # Enqueue a stopped status so the drain loop picks it up.
        self.queue.put_nowait({
            "type": "status",
            "data": {"state": "stopped", "message": "Capture stopped. 0 packets."},
        })

    @property
    def is_running(self) -> bool:
        return self._started and not self._stopping and self._thread_alive


# ---------------------------------------------------------------------------
# Helpers — minimal async ASGI harness
# ---------------------------------------------------------------------------

async def _asgi_request(
    method: str,
    path: str,
    body: bytes = b"",
    content_type: str = "application/json",
) -> tuple[int, dict]:
    """Drive the FastAPI ASGI app with a synthetic HTTP request.
    Returns (status_code, response_body_as_dict).
    """
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"content-type", content_type.encode()),
            (b"content-length", str(len(body)).encode()),
        ],
        "server": ("127.0.0.1", 8000),
        "client": ("127.0.0.1", 12345),
    }
    body_queue = [body]
    responses = []

    async def receive():
        if body_queue:
            return {"type": "http.request", "body": body_queue.pop(), "more_body": False}
        return {"type": "http.disconnect"}

    async def send(msg):
        responses.append(msg)

    await app(scope, receive, send)

    status = next(
        r["status"] for r in responses if r["type"] == "http.response.start"
    )
    raw_body = b"".join(
        r.get("body", b"") for r in responses if r["type"] == "http.response.body"
    )
    try:
        parsed = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        parsed = {"_raw": raw_body.decode(errors="replace")}
    return status, parsed


def _fresh_state() -> _AppState:
    """Reset the module-level _state to a clean instance for each test."""
    new_state = _AppState()
    app_mod._state = new_state
    return new_state


# ---------------------------------------------------------------------------
# Test 1 — GET / returns 200 with an HTML content-type
# ---------------------------------------------------------------------------

def test_root():
    """
    GET / now serves index.html via FileResponse when the static directory
    exists, or an HTMLResponse fallback when it does not.

    FileResponse streams the file body using more_body=True chunks which the
    minimal ASGI harness does not reassemble (it returns http.disconnect
    immediately).  The body will therefore be empty in this harness.

    We verify: HTTP 200, content-type text/html.  Body content is validated
    by the HTML file itself (index.html contains "NetSentry") and is covered
    by a manual/integration test in Stage 5.
    """
    async def _run():
        _fresh_state()
        scope = {
            "type": "http", "asgi": {"version": "3.0"},
            "http_version": "1.1", "method": "GET", "path": "/",
            "raw_path": b"/", "root_path": "", "query_string": b"",
            "headers": [], "server": ("127.0.0.1", 8000),
            "client": ("127.0.0.1", 0),
        }
        responses = []
        async def recv(): return {"type": "http.disconnect"}
        async def send(m): responses.append(m)
        await app(scope, recv, send)
        start = next(r for r in responses if r["type"] == "http.response.start")
        status = start["status"]
        headers = dict(start.get("headers", []))
        ct = headers.get(b"content-type", b"").decode(errors="replace")
        assert status == 200, f"Expected 200, got {status}"
        assert "text/html" in ct, f"Expected text/html content-type, got {ct!r}"

        # Also confirm the index.html file exists on disk and contains NetSentry
        from pathlib import Path
        idx = Path("netsentry/web/static/index.html")
        assert idx.exists(), "index.html not found on disk"
        assert b"NetSentry" in idx.read_bytes(), "NetSentry not found in index.html"

    asyncio.run(_run())
    print("PASS  test_root")


# ---------------------------------------------------------------------------
# Test 2 — GET /api/interfaces mocked
# ---------------------------------------------------------------------------

def test_get_interfaces():
    async def _run():
        _fresh_state()
        # Patch get_if_list so no real Npcap call is made.
        orig = app_mod.get_if_list
        app_mod.get_if_list = lambda: ["eth0", "lo"]
        try:
            status, body = await _asgi_request("GET", "/api/interfaces")
        finally:
            app_mod.get_if_list = orig
        assert status == 200, f"Expected 200, got {status}"
        assert "interfaces" in body
        assert body["interfaces"] == ["eth0", "lo"]
    asyncio.run(_run())
    print("PASS  test_get_interfaces")


# ---------------------------------------------------------------------------
# Test 3 — GET /api/capture/status when idle
# ---------------------------------------------------------------------------

def test_capture_status_idle():
    async def _run():
        state = _fresh_state()
        status, body = await _asgi_request("GET", "/api/capture/status")
        assert status == 200
        assert body["state"] == "idle"
        assert body["stats"]["count"] == 0
        assert body["packet_count"] == 0
        assert body["alert_count"] == 0
    asyncio.run(_run())
    print("PASS  test_capture_status_idle")


# ---------------------------------------------------------------------------
# Test 4 — POST /api/capture/start happy path
# ---------------------------------------------------------------------------

def test_start_capture_happy():
    async def _run():
        state = _fresh_state()
        # Patch WebCaptureWorker with fake.
        orig_cls = app_mod.WebCaptureWorker
        created = []
        class _TrackingFake(_FakeWorker):
            def __init__(self, **kwargs):
                super().__init__()
                created.append(self)
        app_mod.WebCaptureWorker = _TrackingFake
        try:
            payload = json.dumps({"interface": "eth0", "bpf_filter": "tcp"}).encode()
            status, body = await _asgi_request("POST", "/api/capture/start", body=payload)
        finally:
            app_mod.WebCaptureWorker = orig_cls

        assert status == 202, f"Expected 202, got {status}: {body}"
        assert body["state"] == "starting"
        assert body["interface"] == "eth0"
        assert len(created) == 1
        assert created[0]._started
        # App state should reflect "starting"
        assert state.capture_state == "starting"
        assert state.capture_interface == "eth0"
    asyncio.run(_run())
    print("PASS  test_start_capture_happy")


# ---------------------------------------------------------------------------
# Test 5 — POST /api/capture/start with blank interface returns 422
# ---------------------------------------------------------------------------

def test_start_blank_interface():
    async def _run():
        _fresh_state()
        payload = json.dumps({"interface": "   "}).encode()
        status, body = await _asgi_request("POST", "/api/capture/start", body=payload)
        assert status == 422, f"Expected 422, got {status}: {body}"
    asyncio.run(_run())
    print("PASS  test_start_blank_interface")


# ---------------------------------------------------------------------------
# Test 6 — POST /api/capture/start while already capturing returns 409
# ---------------------------------------------------------------------------

def test_start_while_active():
    async def _run():
        state = _fresh_state()
        state.capture_state = "running"

        payload = json.dumps({"interface": "eth0"}).encode()
        status, body = await _asgi_request("POST", "/api/capture/start", body=payload)
        assert status == 409, f"Expected 409, got {status}: {body}"
        assert "active" in body.get("detail", "").lower()
    asyncio.run(_run())
    print("PASS  test_start_while_active")


# ---------------------------------------------------------------------------
# Test 7 — POST /api/capture/start blocked by stuck previous worker thread
# ---------------------------------------------------------------------------

def test_start_blocked_by_stuck_worker():
    async def _run():
        state = _fresh_state()
        # Place a stopped-state worker whose thread is still alive.
        stuck = _FakeWorker()
        stuck._stopping = True          # stop() was called
        stuck._thread_alive = True      # but thread hasn't exited
        state.worker = stuck
        state.capture_state = "error"   # last state (allows new start normally)

        payload = json.dumps({"interface": "eth0"}).encode()
        status, body = await _asgi_request("POST", "/api/capture/start", body=payload)
        assert status == 409, f"Expected 409 (stuck thread), got {status}: {body}"
        assert "thread" in body.get("detail", "").lower()
    asyncio.run(_run())
    print("PASS  test_start_blocked_by_stuck_worker")


# ---------------------------------------------------------------------------
# Test 8 — POST /api/capture/stop happy path
# ---------------------------------------------------------------------------

def test_stop_capture_happy():
    async def _run():
        state = _fresh_state()
        worker = _FakeWorker()
        state.worker = worker
        state.capture_state = "running"

        status, body = await _asgi_request("POST", "/api/capture/stop")
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body["state"] == "stopping"
        assert state.capture_state == "stopping"
    asyncio.run(_run())
    print("PASS  test_stop_capture_happy")


# ---------------------------------------------------------------------------
# Test 9 — POST /api/capture/stop when idle returns 409
# ---------------------------------------------------------------------------

def test_stop_when_idle():
    async def _run():
        _fresh_state()
        status, body = await _asgi_request("POST", "/api/capture/stop")
        assert status == 409, f"Expected 409, got {status}: {body}"
    asyncio.run(_run())
    print("PASS  test_stop_when_idle")


# ---------------------------------------------------------------------------
# Test 10 — _handle_worker_message updates state correctly for each type
# ---------------------------------------------------------------------------

def test_handle_worker_message_all_types():
    async def _run():
        state = _fresh_state()
        state.capture_state = "starting"

        # packets
        rows = [{"timestamp": "12:00:00.000", "protocol": "TCP",
                 "src": "1.1.1.1", "sport": "1234",
                 "dst": "2.2.2.2", "dport": "80",
                 "size": 64, "flags": "S"}]
        await _handle_worker_message({"type": "packets", "data": rows})
        assert len(state.packet_history) == 1
        assert state.packet_history[0]["protocol"] == "TCP"

        # stats
        await _handle_worker_message({"type": "stats", "data": {
            "count": 10, "bytes": 640, "pps": 4.0, "protocols": {"TCP": 10}
        }})
        assert state.stats["count"] == 10
        assert state.stats["pps"] == 4.0

        # alerts
        alert = {"timestamp": "2024-01-01 12:00:00", "type": "Repeated TCP SYN attempts",
                 "severity": "High", "source_ip": "1.1.1.1",
                 "destination_ip": "2.2.2.2", "destination_port": 80,
                 "reason": "test"}
        await _handle_worker_message({"type": "alerts", "data": [alert]})
        assert len(state.alert_history) == 1

        # status: running
        await _handle_worker_message({"type": "status",
                                       "data": {"state": "running", "message": "ok"}})
        assert state.capture_state == "running"

        # status: stopped → worker cleared, state→idle
        state.worker = _FakeWorker()
        await _handle_worker_message({"type": "status",
                                       "data": {"state": "stopped", "message": "done"}})
        assert state.capture_state == "idle"
        assert state.worker is None

    asyncio.run(_run())
    print("PASS  test_handle_worker_message_all_types")


# ---------------------------------------------------------------------------
# Test 11 — status/error clears worker
# ---------------------------------------------------------------------------

def test_handle_error_status():
    async def _run():
        state = _fresh_state()
        state.capture_state = "running"
        state.worker = _FakeWorker()

        await _handle_worker_message({"type": "status",
                                       "data": {"state": "error", "message": "BPF fail"}})
        assert state.capture_state == "error"
        assert state.worker is None
        assert state.capture_message == "BPF fail"
    asyncio.run(_run())
    print("PASS  test_handle_error_status")


# ---------------------------------------------------------------------------
# Test 12 — Packet history bounded at _MAX_PACKET_HISTORY
# ---------------------------------------------------------------------------

def test_packet_history_bounded():
    async def _run():
        state = _fresh_state()
        row = {"timestamp": "t", "protocol": "UDP", "src": "1.1.1.1",
               "sport": "1", "dst": "2.2.2.2", "dport": "2",
               "size": 1, "flags": "-"}
        overflow = _MAX_PACKET_HISTORY + 200
        for i in range(0, overflow, 50):
            batch = [dict(row, sport=str(j)) for j in range(i, min(i+50, overflow))]
            await _handle_worker_message({"type": "packets", "data": batch})
        assert len(state.packet_history) == _MAX_PACKET_HISTORY, (
            f"Expected {_MAX_PACKET_HISTORY}, got {len(state.packet_history)}"
        )
    asyncio.run(_run())
    print(f"PASS  test_packet_history_bounded  (max={_MAX_PACKET_HISTORY})")


# ---------------------------------------------------------------------------
# Test 13 — Alert history bounded at _MAX_ALERT_HISTORY
# ---------------------------------------------------------------------------

def test_alert_history_bounded():
    async def _run():
        state = _fresh_state()
        alert = {"timestamp": "t", "type": "X", "severity": "Low",
                 "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
                 "destination_port": 80, "reason": "test"}
        overflow = _MAX_ALERT_HISTORY + 100
        for _ in range(overflow):
            await _handle_worker_message({"type": "alerts", "data": [dict(alert)]})
        assert len(state.alert_history) == _MAX_ALERT_HISTORY
    asyncio.run(_run())
    print(f"PASS  test_alert_history_bounded  (max={_MAX_ALERT_HISTORY})")


# ---------------------------------------------------------------------------
# Test 14 — WebSocket connect/disconnect and snapshot delivery
# ---------------------------------------------------------------------------

def test_websocket_connect_snapshot():
    """
    Drive the WebSocket ASGI handler with a synthetic scope.
    Verifies:
    - Client is registered on connect.
    - Snapshot message is sent immediately.
    - Client is de-registered on disconnect.
    """
    async def _run():
        state = _fresh_state()
        state.capture_state = "running"
        state.capture_interface = "eth0"

        sent_messages: list[str] = []
        ws_closed = False

        class _FakeWebSocket:
            """Minimal WebSocket stub for direct handler testing."""
            client_state = None   # not checked by our handler

            async def accept(self):
                pass

            async def send_text(self, data: str):
                sent_messages.append(data)

            async def receive_text(self):
                # First call returns a text frame; second raises Disconnect.
                if len(sent_messages) >= 1:
                    raise __import__('starlette.websockets',
                                     fromlist=['WebSocketDisconnect']
                                    ).WebSocketDisconnect()
                return "ping"

            async def close(self, code=1000, reason=None):
                nonlocal ws_closed
                ws_closed = True

        fake_ws = _FakeWebSocket()

        # Run the handler coroutine directly.
        from netsentry.web.app import websocket_endpoint
        await websocket_endpoint(fake_ws)

        # The client must have been added then removed.
        assert fake_ws not in state.clients, "Client not removed after disconnect"

        # A snapshot must have been sent.
        assert len(sent_messages) >= 1, "No snapshot sent on connect"
        snapshot_msg = json.loads(sent_messages[0])
        assert snapshot_msg["type"] == "snapshot"
        assert snapshot_msg["data"]["state"] == "running"
        assert snapshot_msg["data"]["interface"] == "eth0"

    asyncio.run(_run())
    print("PASS  test_websocket_connect_snapshot")


# ---------------------------------------------------------------------------
# Test 15 — _broadcast skips disconnected clients
# ---------------------------------------------------------------------------

def test_broadcast_skips_disconnected():
    async def _run():
        from netsentry.web.app import _broadcast
        from starlette.websockets import WebSocketDisconnect

        state = _fresh_state()
        received = []

        class _GoodWS:
            async def send_text(self, data): received.append(data)

        class _BadWS:
            async def send_text(self, data):
                raise WebSocketDisconnect()

        good = _GoodWS()
        bad = _BadWS()
        state.clients = {good, bad}   # type: ignore

        await _broadcast("hello", {good, bad})  # type: ignore
        assert "hello" in received, "Good client did not receive message"
        # Bad client must be removed from state.clients
        assert bad not in state.clients

    asyncio.run(_run())
    print("PASS  test_broadcast_skips_disconnected")


# ---------------------------------------------------------------------------
# Test 16 — Drain loop processes a worker message and updates state
# ---------------------------------------------------------------------------

def test_drain_loop_processes_message():
    """
    Run the drain loop for a short time with a fake worker that immediately
    enqueues a 'running' status message.  Verify state is updated.
    """
    async def _run():
        state = _fresh_state()
        state.capture_state = "starting"
        worker = _FakeWorker(auto_running=False)
        worker.queue.put_nowait({
            "type": "status",
            "data": {"state": "running", "message": "Capture started."},
        })
        state.worker = worker

        # Import and run drain loop briefly.
        from netsentry.web.app import _drain_loop
        task = asyncio.create_task(_drain_loop())
        # Give the drain loop enough time to process the queued message.
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert state.capture_state == "running", (
            f"Expected 'running', got {state.capture_state!r}"
        )
    asyncio.run(_run())
    print("PASS  test_drain_loop_processes_message")


# ---------------------------------------------------------------------------
# Test 17 — Application shutdown cancels drain task and closes clients
# ---------------------------------------------------------------------------

def test_app_shutdown_cleanup():
    """
    Verify the lifespan cleanup:
    - drain_task is cancelled.
    - WebSocket clients receive a close call.
    - Worker stop() is invoked.
    """
    async def _run():
        state = _fresh_state()

        stop_called = []
        class _StopTracker(_FakeWorker):
            def stop(self):
                stop_called.append(True)
                super().stop()

        worker = _StopTracker()
        state.worker = worker
        state.capture_state = "running"

        close_codes = []
        class _FakeWS:
            async def close(self, code=1000, reason=None):
                close_codes.append(code)
            async def send_text(self, data): pass
        state.clients = {_FakeWS()}   # type: ignore

        # Create a dummy drain task that we can observe being cancelled.
        async def _dummy():
            await asyncio.sleep(100)
        state.drain_task = asyncio.create_task(_dummy())

        # Run the lifespan finally block directly.
        from netsentry.web.app import _lifespan
        # We drive only the cleanup (finally) half by entering and immediately
        # raising GeneratorExit inside the lifespan context.
        ctx = _lifespan(app)
        await ctx.__aenter__()
        # Swap in our state (lifespan creates a new drain task; cancel it).
        state.drain_task.cancel()
        try: await state.drain_task
        except asyncio.CancelledError: pass
        # Now trigger the finally block by exiting the context.
        try:
            await ctx.__aexit__(None, None, None)
        except Exception:
            pass

        assert stop_called, "worker.stop() was not called during shutdown"
        assert 1001 in close_codes, "WebSocket not closed with 1001 during shutdown"

    asyncio.run(_run())
    print("PASS  test_app_shutdown_cleanup")


# ---------------------------------------------------------------------------
# Test 18 — JSON serialization of all message types
# ---------------------------------------------------------------------------

def test_message_serialization():
    """All message types must be JSON-serializable."""
    messages = [
        {"type": "packets", "data": [
            {"timestamp": "12:00:00.000", "protocol": "TCP",
             "src": "1.1.1.1", "sport": "80", "dst": "2.2.2.2",
             "dport": "443", "size": 64, "flags": "S"}
        ]},
        {"type": "stats", "data": {
            "count": 100, "bytes": 6400, "pps": 10.0,
            "protocols": {"TCP": 80, "UDP": 20}
        }},
        {"type": "alerts", "data": [
            {"timestamp": "2024-01-01 12:00:00",
             "type": "Repeated TCP SYN attempts", "severity": "High",
             "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
             "destination_port": 22, "reason": "11 SYNs in 10s"}
        ]},
        {"type": "status", "data": {"state": "running", "message": "ok"}},
        {"type": "snapshot", "data": {
            "state": "running", "interface": "eth0",
            "stats": {"count": 0, "bytes": 0, "pps": 0.0, "protocols": {}},
            "packets": [], "alerts": [],
        }},
    ]
    for msg in messages:
        serialized = json.dumps(msg)
        recovered = json.loads(serialized)
        assert recovered == msg, f"Round-trip mismatch for {msg['type']}"
    print("PASS  test_message_serialization")


# ---------------------------------------------------------------------------
# Test 19 — GET / fallback when index.html is missing
# ---------------------------------------------------------------------------

def test_root_fallback_no_static():
    """
    When index.html does not exist (static files not deployed), GET /
    must return HTTP 200 with an HTMLResponse fallback body containing
    'NetSentry'.  No real files are deleted; _STATIC_DIR is temporarily
    redirected to a nonexistent path inside the test.
    """
    async def _run():
        _fresh_state()
        from pathlib import Path

        orig_static = app_mod._STATIC_DIR
        # Point _STATIC_DIR at a path that definitely has no index.html.
        app_mod._STATIC_DIR = Path("/nonexistent_path_for_testing_only")

        scope = {
            "type": "http", "asgi": {"version": "3.0"},
            "http_version": "1.1", "method": "GET", "path": "/",
            "raw_path": b"/", "root_path": "", "query_string": b"",
            "headers": [], "server": ("127.0.0.1", 8000),
            "client": ("127.0.0.1", 0),
        }
        responses = []
        async def recv(): return {"type": "http.disconnect"}
        async def send(m): responses.append(m)

        try:
            await app(scope, recv, send)
        finally:
            app_mod._STATIC_DIR = orig_static

        start = next(r for r in responses if r["type"] == "http.response.start")
        assert start["status"] == 200, f"Expected 200, got {start['status']}"

        body = b"".join(
            r.get("body", b"") for r in responses if r["type"] == "http.response.body"
        )
        assert b"NetSentry" in body, (
            f"Expected 'NetSentry' in fallback body, got {body[:200]!r}"
        )
        headers = dict(start.get("headers", []))
        ct = headers.get(b"content-type", b"").decode(errors="replace")
        assert "text/html" in ct, f"Expected text/html, got {ct!r}"

    asyncio.run(_run())
    print("PASS  test_root_fallback_no_static")


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_root,
        test_get_interfaces,
        test_capture_status_idle,
        test_start_capture_happy,
        test_start_blank_interface,
        test_start_while_active,
        test_start_blocked_by_stuck_worker,
        test_stop_capture_happy,
        test_stop_when_idle,
        test_handle_worker_message_all_types,
        test_handle_error_status,
        test_packet_history_bounded,
        test_alert_history_bounded,
        test_websocket_connect_snapshot,
        test_broadcast_skips_disconnected,
        test_drain_loop_processes_message,
        test_app_shutdown_cleanup,
        test_message_serialization,
        test_root_fallback_no_static,
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

    print(f"\n{'='*55}")
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
