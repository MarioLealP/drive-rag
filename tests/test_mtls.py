"""server.mtls against a real test PKI shaped like clockmost's (root ->
pki_felt-style intermediate with the D6 name constraints -> leaves)."""

import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

from server import mtls

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="needs the openssl CLI"
)
FELT_CORE = "spiffe://clockmost.internal/workload/felt-core"


def _openssl(*a, cwd):
    subprocess.run(["openssl", *a], cwd=cwd, check=True, capture_output=True)


def _leaf(d, name, issuer, ext):
    _openssl(
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        f"{name}.key",
        "-subj",
        f"/CN={name}",
        "-out",
        f"{name}.csr",
        cwd=d,
    )
    (d / f"{name}.ext").write_text(ext)
    _openssl(
        "x509",
        "-req",
        "-in",
        f"{name}.csr",
        "-CA",
        f"{issuer}.pem",
        "-CAkey",
        f"{issuer}.key",
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        f"{name}.ext",
        "-out",
        f"{name}.pem",
        cwd=d,
    )


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    for ca in ("root", "wrong"):
        _openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            f"{ca}.key",
            "-subj",
            f"/CN={ca}",
            "-days",
            "2",
            "-out",
            f"{ca}.pem",
            cwd=d,
        )
    _leaf(
        d,
        "feltint",
        "root",
        "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "nameConstraints=critical,permitted;URI:clockmost.internal,permitted;DNS:felt.internal,"
        "excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::\n",
    )
    cli = "basicConstraints=critical,CA:false\nextendedKeyUsage=clientAuth\nsubjectAltName="
    srv = "basicConstraints=critical,CA:false\nextendedKeyUsage=serverAuth\nsubjectAltName="
    _leaf(
        d,
        "voice",
        "feltint",
        srv
        + "DNS:drive-rag.felt.internal,URI:spiffe://clockmost.internal/workload/drive-rag\n",
    )
    _leaf(
        d,
        "voice2",
        "feltint",
        srv
        + "DNS:drive-rag.felt.internal,URI:spiffe://clockmost.internal/workload/drive-rag\n",
    )
    _leaf(d, "core", "feltint", cli + f"DNS:felt-core.felt.internal,URI:{FELT_CORE}\n")
    _leaf(
        d,
        "tray",
        "feltint",
        cli + "DNS:tray.felt.internal,URI:spiffe://clockmost.internal/workload/tray\n",
    )
    _leaf(d, "rogue", "wrong", cli + f"URI:{FELT_CORE}\n")
    for n, iss in (
        ("voice", "feltint"),
        ("voice2", "feltint"),
        ("core", "feltint"),
        ("tray", "feltint"),
        ("rogue", "wrong"),
    ):
        (d / f"{n}.bundle").write_text(
            (d / f"{n}.key").read_text()
            + (d / f"{n}.pem").read_text()
            + (d / f"{iss}.pem").read_text()
        )
    return d


async def _app(scope, receive, send):
    if scope["type"] != "http":
        return
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", b"2")],
        }
    )
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.fixture(scope="module")
def server(pki):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    live = pki / "live.bundle"
    shutil.copy(pki / "voice.bundle", live)
    threading.Thread(
        target=mtls.serve,
        args=(
            _app,
            "127.0.0.1",
            port,
            str(live),
            str(pki / "feltint.pem"),
            [FELT_CORE],
            0.2,
        ),
        daemon=True,
    ).start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return port, live


def _get(pki, port, bundle=None, max_tls=None):
    """GET / as felt-core would: trust felt-ca only, verify the server by name."""
    ctx = ssl.create_default_context(cafile=str(pki / "feltint.pem"))
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    if max_tls:
        ctx.maximum_version = max_tls
    if bundle:
        ctx.load_cert_chain(str(pki / bundle))
    with ctx.wrap_socket(
        socket.create_connection(("127.0.0.1", port), 5),
        server_hostname="drive-rag.felt.internal",
    ) as s:
        cert = s.getpeercert()
        s.sendall(
            b"GET / HTTP/1.1\r\nHost: drive-rag.felt.internal\r\nConnection: close\r\n\r\n"
        )
        return s.recv(200), cert


def test_felt_core_gets_through(pki, server):
    data, _ = _get(pki, server[0], "core.bundle")
    assert data.startswith(b"HTTP/1.1 200")


def test_no_client_cert_refused(pki, server):
    try:
        data, _ = _get(pki, server[0])
    except (ssl.SSLError, ConnectionError):
        return
    assert data == b""  # TLS 1.3: the server's refusal can arrive as a closed read


def test_other_felt_identity_refused(pki, server):
    try:
        data, _ = _get(pki, server[0], "tray.bundle")
    except (ssl.SSLError, ConnectionError):
        return
    assert (
        data == b""
    )  # handshake passes (valid Felt cert), connection dropped before any response


def test_wrong_ca_refused(pki, server):
    try:
        data, _ = _get(pki, server[0], "rogue.bundle")
    except (ssl.SSLError, ConnectionError):
        return
    assert data == b""


def test_tls12_refused(pki, server):
    with pytest.raises(ssl.SSLError):
        _get(pki, server[0], "core.bundle", max_tls=ssl.TLSVersion.TLSv1_2)


def test_renewed_cert_is_picked_up(pki, server):
    port, live = server
    _, before = _get(pki, port, "core.bundle")
    shutil.copy(pki / "voice2.bundle", live)
    time.sleep(1.0)
    _, after = _get(pki, port, "core.bundle")
    assert before["serialNumber"] != after["serialNumber"]


def test_refusal_logs_no_traceback(pki, server, caplog):
    """A refused peer is one warning line, not an asyncio callback traceback."""
    test_other_felt_identity_refused(pki, server)
    time.sleep(0.3)
    assert "is not allowed" in caplog.text
    assert "Exception in callback" not in caplog.text
