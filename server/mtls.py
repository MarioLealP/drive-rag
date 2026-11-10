"""mTLS for drive-rag's API (WP-62 M2b B5.2, decision D10.2).

Same module as felt-voice's (felt_voice/mtls.py, B5.1): felt-core is the only
caller. She presents her 2-hour Felt client cert; drive-rag presents its own
(``drive-rag.felt.internal``). Both certs come from clockmost's server-side
helper as ``bundle.pem`` (key + cert + intermediate) next to ``felt-ca.pem``
(the pki_felt intermediate: the ONLY trust anchor - never the clockmost root).

- The TLS handshake requires a client cert that chains to ``felt-ca.pem``.
- Every connection's peer must carry exactly one SPIFFE URI and it must be in
  ``allowed`` (felt-core's), checked before a single request byte is read.
- The server cert is re-read when the bundle changes (renewed hourly).

Meru mode (D127, on k3s): the same server with Meru's in-cluster certs (nuwa-app ``certificate``: ``tls.crt``,
``tls.key``, ``ca.crt`` from OpenBao ``pki_meru``). Those carry DNS names only - ``<app>.<namespace>.svc``, a name
pki_meru signs only for a pod of that namespace - so the peer passes when one of its DNS names is allowed
(``kind="DNS"``). Who is calling and what it may do is the Authentik token on top (server/auth.py).

Off unless DRIVE_RAG_TLS_BUNDLE or DRIVE_RAG_TLS_CERT is set (plain HTTP as before).
"""

import logging
import os
import ssl
import threading

import uvicorn
from uvicorn.protocols.http.auto import AutoHTTPProtocol

log = logging.getLogger(__name__)


def peer_names(transport, kind: str = "URI") -> list[str]:
    cert = transport.get_extra_info("peercert") or {}
    return [v for k, v in cert.get("subjectAltName", ()) if k == kind]


def peer_uris(transport) -> list[str]:
    return peer_names(transport, "URI")


def is_allowed(names: list[str], allowed: frozenset[str], kind: str) -> bool:
    """URI (Felt certs): exactly one SPIFFE identity, and it's allowed. DNS (Meru certs): a cert names its Service
    twice (``.svc`` and ``.svc.cluster.local``), so one allowed name is enough."""
    if kind == "URI":
        return len(names) == 1 and names[0] in allowed
    return any(n in allowed for n in names)


def make_protocol(allowed: frozenset[str], kind: str = "URI"):
    """The HTTP protocol, refusing any peer whose identity isn't allowed."""

    class MTLSProtocol(AutoHTTPProtocol):
        def connection_made(self, transport):  # after the TLS handshake
            names = peer_names(transport, kind)
            if not is_allowed(names, allowed, kind):
                log.warning(
                    "refused TLS client %s: identity %s is not allowed",
                    transport.get_extra_info("peername"),
                    names or "none",
                )
                self._refused = True
                transport.abort()
                return
            super().connection_made(transport)

        def connection_lost(self, exc):
            if getattr(self, "_refused", False):  # nothing was set up to tear down
                return
            super().connection_lost(exc)

    return MTLSProtocol


def harden(ctx: ssl.SSLContext) -> None:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN  # felt-ca.pem is an intermediate


def watch_bundle(
    ctx: ssl.SSLContext,
    bundle: str,
    interval: float,
    stop: threading.Event,
    key: str | None = None,
) -> None:
    """Reload the server cert into the live context whenever the renewer
    replaces the bundle (or, Meru mode, the kubelet swaps the Secret's files:
    both names follow the same new ``..data`` link, so cert and key match)."""
    seen = os.stat(bundle).st_mtime_ns
    while not stop.wait(interval):
        try:
            now = os.stat(bundle).st_mtime_ns
            if now != seen:
                ctx.load_cert_chain(bundle, key)
                seen = now
                log.info("reloaded the server certificate from %s", bundle)
        except (OSError, ssl.SSLError) as e:
            log.error(
                "server certificate reload failed (keeping the current one): %s", e
            )


def serve(
    app,
    host: str,
    port: int,
    bundle: str,
    ca: str,
    allowed,
    reload_s: float = 60,
    *,
    key: str | None = None,
    kind: str = "URI",
) -> None:
    """``bundle`` is the cert (+ key when ``key`` is None, as the Felt bundle.pem); ``kind`` the SAN type checked."""
    if kind not in ("URI", "DNS"):
        raise ValueError(f"kind must be URI or DNS, not {kind!r}")
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        ssl_certfile=bundle,
        ssl_keyfile=key or bundle,
        ssl_ca_certs=ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        http=make_protocol(frozenset(allowed), kind),
    )
    config.load()
    harden(config.ssl)
    stop = threading.Event()
    threading.Thread(
        target=watch_bundle, args=(config.ssl, bundle, reload_s, stop, key), daemon=True
    ).start()
    log.info(
        "mTLS on %s:%s, allowed clients: %s", host, port, ", ".join(sorted(allowed))
    )
    try:
        uvicorn.Server(config).run()
    finally:
        stop.set()
