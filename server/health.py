"""A plain-HTTP health port for Meru mode (D127): the kubelet's probes carry no client certificate, so they can't pass
the mTLS port. This port answers only GET /api/health, and only 200 when the real server is there: its TLS port takes
connections and the index answers. Nothing else is served here - no question ever goes over plain HTTP.

  DRIVE_RAG_HEALTH_PORT  the port (Meru mode only; unset: no health port)
"""

import json
import logging
import socket
import threading

import uvicorn

from server.app import state

log = logging.getLogger(__name__)


def make_app(main_port: int):
    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        if scope["method"] != "GET" or scope["path"] != "/api/health":
            await _answer(send, 404, {"detail": "not found"})
            return
        try:
            socket.create_connection(("127.0.0.1", main_port), 2).close()
            n = state["db"].execute("SELECT count(*) FROM chunks").fetchone()[0]
        except (OSError, KeyError) as e:  # KeyError: the main app hasn't started yet
            await _answer(send, 503, {"ok": False, "detail": type(e).__name__})
            return
        await _answer(send, 200, {"ok": True, "chunks": n})

    return app


async def _answer(send, status: int, body: dict) -> None:
    data = json.dumps(body).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(data)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": data})


def start(host: str, port: int, main_port: int) -> threading.Thread:
    """Serve the health port in a thread of its own (no lifespan, no signal handlers - the main server owns those)."""
    config = uvicorn.Config(
        make_app(main_port), host=host, port=port, lifespan="off", log_level="warning"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="health", daemon=True)
    thread.start()
    log.info("health on plain HTTP %s:%s (GET /api/health only)", host, port)
    return thread
