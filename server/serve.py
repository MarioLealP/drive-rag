"""drive-rag's entry point: plain uvicorn, or mTLS in one of two modes. Settings from the environment:

Felt mode (compose, WP-62 M2b B5.2):
  DRIVE_RAG_TLS_BUNDLE   server bundle.pem (key + cert + intermediate)
  DRIVE_RAG_TLS_CA       felt-ca.pem (the pki_felt intermediate)
  DRIVE_RAG_TLS_ALLOWED  allowed client SPIFFE URIs, comma-separated
                         (default: felt-core)

Meru mode (k3s, D127 - nuwa-app's certificate, files from pki_meru):
  DRIVE_RAG_TLS_CERT         tls.crt
  DRIVE_RAG_TLS_KEY          tls.key
  DRIVE_RAG_TLS_CA           ca.crt (Meru's in-cluster CA)
  DRIVE_RAG_TLS_ALLOWED_DNS  allowed client Service names, comma-separated
                             (default: felt-core.felt-core.svc)
  DRIVE_RAG_HEALTH_PORT      a plain-HTTP port for the kubelet's probes, GET /api/health only (server/health.py)
  + the Authentik token check, server/auth.py (DRIVE_RAG_AUTH_*).
"""

import logging
import os

import uvicorn

from server.app import app

FELT_CORE = "spiffe://clockmost.internal/workload/felt-core"
FELT_CORE_SVC = "felt-core.felt-core.svc"


def _names(var: str, default: str) -> list[str]:
    return [n.strip() for n in os.environ.get(var, default).split(",") if n.strip()]


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    host, port = "0.0.0.0", 8000
    bundle = os.environ.get("DRIVE_RAG_TLS_BUNDLE")
    cert = os.environ.get("DRIVE_RAG_TLS_CERT")
    if bundle and cert:
        raise SystemExit("set DRIVE_RAG_TLS_BUNDLE (Felt mode) or DRIVE_RAG_TLS_CERT (Meru mode), not both")
    if not bundle and not cert:
        uvicorn.run(app, host=host, port=port)
        return
    ca = os.environ.get("DRIVE_RAG_TLS_CA") or ""
    if not ca:
        raise SystemExit("DRIVE_RAG_TLS_CA isn't set")
    from server import mtls

    if bundle:
        mtls.serve(app, host, port, bundle, ca, _names("DRIVE_RAG_TLS_ALLOWED", FELT_CORE))
        return
    key = os.environ.get("DRIVE_RAG_TLS_KEY") or ""
    if not key:
        raise SystemExit("DRIVE_RAG_TLS_CERT is set but DRIVE_RAG_TLS_KEY isn't")
    allowed = _names("DRIVE_RAG_TLS_ALLOWED_DNS", FELT_CORE_SVC)
    if health_port := os.environ.get("DRIVE_RAG_HEALTH_PORT"):
        from server import health

        health.start(host, int(health_port), port)
    mtls.serve(app, host, port, cert, ca, allowed, key=key, kind="DNS")


if __name__ == "__main__":
    main()
