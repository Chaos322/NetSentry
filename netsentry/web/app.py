"""
NetSentry web dashboard — FastAPI application.

Binds to 127.0.0.1 only (configured in run_web.py).
No authentication or remote-access features.

Endpoints
---------
GET  /                      Temporary placeholder until Stage 4 HTML is added.
GET  /api/interfaces        List Scapy network interfaces.
GET  /api/capture/status    Current capture state and live statistics.
POST /api/capture/start     Start a new capture session.
POST /api/capture/stop      Request capture shutdown.
WS   /ws                    Live WebSocket feed (packets / stats / alerts / status).

Application state
-----------------
All mutable app state lives in _AppState and is protected by a single
asyncio.Lock.  The lock is never held across an await that could block
indefinitely, and is never touched from the worker thread — the worker
writes only to its own queue.Queue.

Concurrency model
-----------------
One asyncio background task (_drain_task) reads from the worker's
queue.Queue via run_in_executor (non-blocking to the event loop) and
fans the resulting JSON messages out to every connected WebSocket client.
Per-client sends use asyncio.wait_for with a short timeout so a slow
or dead client never stalls the broadcast loop or other clients.
"""

import asyncio
import json
import logging
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from scapy.all import get_if_list

from netsentry.web.capture_worker import WebCaptureWorker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Absolute upper bounds on in-memory history kept in app state.
_MAX_PACKET_HISTORY = 1_000
_MAX_ALERT_HISTORY = 500

# Timeout (seconds) for a single per-client WebSocket send.
# A client that cannot accept a message within this window is disconnected.
_WS_SEND_TIMEOUT = 2.0

# How long (seconds) the drain loop sleeps when the worker queue is empty.
_DRAIN_IDLE_SLEEP = 0.05

# PCAP output path for web-initiated captures.
_CAPTURE_OUTPUT = "captures/capture.pcap"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class StartCaptureRequest(BaseModel):
    interface: str
    bpf_filter: str = ""


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

class _AppState:
    """All mutable state for a running NetSentry web server instance."""

    def __init__(self) -> None:
        # Protects every field below.  Held only for in-memory mutations;
        # never held across an await.
        self.lock = asyncio.Lock()

        # Current worker; None when idle.
        self.worker: WebCaptureWorker | None = None

        # Human-readable capture state string mirrored from worker status msgs.
        # Values: "idle" | "starting" | "running" | "stopping" | "error"
        self.capture_state: str = "idle"
        self.capture_message: str = ""
        self.capture_interface: str = ""

        # Live statistics — updated from worker "stats" messages.
        self.stats: dict[str, Any] = {
            "count": 0,
            "bytes": 0,
            "pps": 0.0,
            "protocols": {},
        }

        # Bounded rolling history.
        self.packet_history: deque[dict] = deque(maxlen=_MAX_PACKET_HISTORY)
        self.alert_history: deque[dict] = deque(maxlen=_MAX_ALERT_HISTORY)

        # Connected WebSocket clients.
        self.clients: set[WebSocket] = set()

        # Background drain task handle.
        self.drain_task: asyncio.Task | None = None


# Module-level singleton — created once during app startup.
_state = _AppState()


# ---------------------------------------------------------------------------
# Lifespan — startup and shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Start the drain task on startup; clean up on shutdown."""
    _state.drain_task = asyncio.create_task(
        _drain_loop(), name="netsentry-drain"
    )
    try:
        yield
    finally:
        # Signal capture stop if active.
        async with _state.lock:
            worker = _state.worker
            _state.capture_state = "stopping"
        if worker is not None:
            await asyncio.get_event_loop().run_in_executor(None, worker.stop)

        # Cancel the drain task.
        if _state.drain_task is not None:
            _state.drain_task.cancel()
            try:
                await asyncio.wait_for(_state.drain_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        # Close all WebSocket connections.
        async with _state.lock:
            clients = set(_state.clients)
        for ws in clients:
            try:
                await ws.close(code=1001, reason="Server shutting down")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NetSentry Web Dashboard",
    version="0.1.0",
    lifespan=_lifespan,
)


# ---------------------------------------------------------------------------
# Background drain task
# ---------------------------------------------------------------------------

async def _drain_loop() -> None:
    """Continuously drain the worker queue and broadcast to WebSocket clients.

    Runs as a long-lived asyncio Task.  Uses run_in_executor to call
    queue.get_nowait() without blocking the event loop.  When the worker
    is absent or its queue is empty, the loop sleeps briefly to avoid
    busy-waiting.
    """
    loop = asyncio.get_event_loop()

    while True:
        try:
            async with _state.lock:
                worker = _state.worker

            if worker is None:
                await asyncio.sleep(_DRAIN_IDLE_SLEEP)
                continue

            # Non-blocking queue check via executor.
            try:
                msg: dict = await loop.run_in_executor(
                    None, worker.queue.get_nowait
                )
            except Exception:
                # queue.Empty (or worker replaced between check and get).
                await asyncio.sleep(_DRAIN_IDLE_SLEEP)
                continue

            await _handle_worker_message(msg)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Drain loop error: %s", exc)
            await asyncio.sleep(_DRAIN_IDLE_SLEEP)


async def _handle_worker_message(msg: dict) -> None:
    """Update app state and broadcast the message to all WebSocket clients."""
    msg_type = msg.get("type")
    data = msg.get("data")

    async with _state.lock:
        if msg_type == "packets" and isinstance(data, list):
            _state.packet_history.extend(data)

        elif msg_type == "stats" and isinstance(data, dict):
            _state.stats = data

        elif msg_type == "alerts" and isinstance(data, list):
            _state.alert_history.extend(data)

        elif msg_type == "status" and isinstance(data, dict):
            state_val = data.get("state", "")
            message_val = data.get("message", "")
            _state.capture_message = message_val

            if state_val == "running":
                _state.capture_state = "running"
            elif state_val == "stopped":
                _state.capture_state = "idle"
                _state.worker = None
            elif state_val == "error":
                _state.capture_state = "error"
                _state.worker = None

        clients_snapshot = set(_state.clients)

    # Broadcast outside the lock so per-client send timeouts don't hold it.
    if clients_snapshot:
        payload = json.dumps(msg)
        await _broadcast(payload, clients_snapshot)


async def _broadcast(payload: str, clients: set[WebSocket]) -> None:
    """Send payload to every client; disconnect unresponsive ones."""
    disconnected: list[WebSocket] = []

    for ws in clients:
        try:
            await asyncio.wait_for(ws.send_text(payload), timeout=_WS_SEND_TIMEOUT)
        except (asyncio.TimeoutError, WebSocketDisconnect, RuntimeError):
            disconnected.append(ws)
        except Exception as exc:
            logger.debug("WebSocket send error: %s", exc)
            disconnected.append(ws)

    if disconnected:
        async with _state.lock:
            for ws in disconnected:
                _state.clients.discard(ws)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# Resolve the static directory relative to this file so the app works
# regardless of the working directory it is launched from.
_STATIC_DIR = Path(__file__).resolve().parent / "static"

# Mount static files only when the directory exists (it is created in Stage 4).
# This keeps the module importable during tests that run before static/ exists.
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", response_class=FileResponse, include_in_schema=False)
async def root() -> FileResponse:
    """Serve the single-page dashboard."""
    index = _STATIC_DIR / "index.html"
    if not index.exists():
        # Fallback until static files are deployed (tests, bare imports).
        from fastapi.responses import HTMLResponse
        return HTMLResponse(  # type: ignore[return-value]
            "<html><head><title>NetSentry</title></head>"
            "<body><h1>NetSentry</h1><p>Static files not found.</p></body></html>"
        )
    return FileResponse(str(index))


@app.get("/api/interfaces")
async def get_interfaces() -> JSONResponse:
    """Return available Scapy network interfaces."""
    loop = asyncio.get_event_loop()
    try:
        ifaces: list[str] = await loop.run_in_executor(None, get_if_list)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list interfaces: {exc}")
    return JSONResponse({"interfaces": ifaces})


@app.get("/api/capture/status")
async def capture_status() -> JSONResponse:
    """Return current capture state and statistics snapshot."""
    async with _state.lock:
        return JSONResponse({
            "state":     _state.capture_state,
            "message":   _state.capture_message,
            "interface": _state.capture_interface,
            "stats":     _state.stats,
            "packet_count":  len(_state.packet_history),
            "alert_count":   len(_state.alert_history),
        })


@app.post("/api/capture/start")
async def start_capture(req: StartCaptureRequest) -> JSONResponse:
    """Start a new capture session.

    Returns 409 if:
    - A capture is already active (capture_state not idle/error).
    - The previous worker thread is still alive after stop() timed out.

    Returns 422 if the interface name is blank.

    Note: BPF filter syntax is validated by Scapy at socket-open time, which
    happens asynchronously inside the worker thread.  A syntactically invalid
    filter will produce a status/error message over the WebSocket within
    ~1 second.  We do not claim the filter is valid before Scapy accepts it.
    """
    iface = req.interface.strip()
    bpf = req.bpf_filter.strip() or None

    if not iface:
        raise HTTPException(status_code=422, detail="Interface name must not be blank.")

    async with _state.lock:
        # Reject if a capture is already in progress.
        if _state.capture_state not in ("idle", "error"):
            raise HTTPException(
                status_code=409,
                detail=f"A capture is already active (state={_state.capture_state!r}). "
                       "Stop it before starting a new one.",
            )

        # Reject if the previous worker thread is still alive (stuck after timeout).
        old_worker = _state.worker
        if old_worker is not None:
            thread = old_worker._thread
            if thread is not None and thread.is_alive():
                raise HTTPException(
                    status_code=409,
                    detail="Previous capture worker thread has not exited yet. "
                           "Try again in a moment.",
                )

        # Create and register the new worker.
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = f"captures/capture_{timestamp}.pcap"
        worker = WebCaptureWorker(
            interface=iface,
            bpf_filter=bpf,
            output_path=output_path,
        )

        _state.worker = worker
        _state.capture_state = "starting"
        _state.capture_message = "Capture starting…"
        _state.capture_interface = iface
        # Reset history for the new session.
        _state.packet_history.clear()
        _state.alert_history.clear()
        _state.stats = {"count": 0, "bytes": 0, "pps": 0.0, "protocols": {}}

    # Start the worker thread outside the lock.
    worker.start()

    return JSONResponse(
        {"state": "starting", "interface": iface, "output": output_path},
        status_code=202,
    )


@app.post("/api/capture/stop")
async def stop_capture() -> JSONResponse:
    """Signal the active capture to stop.

    Returns 409 if no capture is active.
    The worker thread is stopped in a background executor so the HTTP
    response is not delayed by the 8-second join timeout.
    """
    async with _state.lock:
        if _state.capture_state not in ("starting", "running"):
            raise HTTPException(
                status_code=409,
                detail=f"No active capture to stop (state={_state.capture_state!r}).",
            )
        worker = _state.worker
        _state.capture_state = "stopping"
        _state.capture_message = "Stop requested."

    if worker is not None:
        # Run the blocking join in a thread-pool executor so we don't block
        # the event loop during the up-to-8-second worker join.
        asyncio.get_event_loop().run_in_executor(None, worker.stop)

    return JSONResponse({"state": "stopping"})


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Accept a WebSocket connection and register it for live updates.

    Sends an immediate snapshot of current state on connect.
    Reads incoming messages (discards them — dashboard is read-only).
    Removes the client cleanly on disconnect or send failure.
    """
    await websocket.accept()

    async with _state.lock:
        _state.clients.add(websocket)
        snapshot = {
            "state":     _state.capture_state,
            "interface": _state.capture_interface,
            "stats":     _state.stats,
            "packets":   list(_state.packet_history)[-100:],  # last 100 rows
            "alerts":    list(_state.alert_history),
        }

    # Send initial snapshot so the dashboard loads current state immediately.
    try:
        await websocket.send_text(json.dumps({"type": "snapshot", "data": snapshot}))
    except Exception:
        async with _state.lock:
            _state.clients.discard(websocket)
        return

    # Keep the connection alive; discard any incoming frames.
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WebSocket receive error: %s", exc)
    finally:
        async with _state.lock:
            _state.clients.discard(websocket)
