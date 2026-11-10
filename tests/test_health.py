"""server.health: the plain-HTTP probe port answers only /api/health, and only while the real server is up."""

import json
import socket
import sqlite3
import time
import urllib.error
import urllib.request

import pytest

from server import health
from server.app import state


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get(port, path="/api/health", method="GET"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture(scope="module")
def ports():
    main = socket.socket()
    main.bind(("127.0.0.1", 0))
    main.listen()
    hp = _free_port()
    health.start("127.0.0.1", hp, main.getsockname()[1])
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", hp), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield hp, main
    main.close()


def test_not_ready_before_the_app_starts(ports):
    state.pop("db", None)
    assert _get(ports[0])[0] == 503


def test_ok_with_the_index(ports):
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE chunks (id INTEGER)")
    db.executemany("INSERT INTO chunks VALUES (?)", [(1,), (2,)])
    state["db"] = db
    assert _get(ports[0]) == (200, {"ok": True, "chunks": 2})


@pytest.mark.parametrize(
    ("path", "method"), [("/api/ask", "POST"), ("/", "GET"), ("/api/health", "POST")]
)
def test_nothing_else(ports, path, method):
    assert _get(ports[0], path, method)[0] == 404


def test_down_when_the_tls_port_is(ports):
    hp, main = ports
    main.close()
    assert _get(hp)[0] == 503
