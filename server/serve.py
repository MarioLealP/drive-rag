"""drive-rag's entry point: plain uvicorn, or mTLS when DRIVE_RAG_TLS_BUNDLE is
set (WP-62 M2b B5.2). Settings from the environment:

  DRIVE_RAG_TLS_BUNDLE   server bundle.pem (key + cert + intermediate)
  DRIVE_RAG_TLS_CA       felt-ca.pem (the pki_felt intermediate)
  DRIVE_RAG_TLS_ALLOWED  allowed client SPIFFE URIs, comma-separated
                         (default: felt-core)
"""

import logging
import os

import uvicorn

from server.app import app

FELT_CORE = "spiffe://clockmost.internal/workload/felt-core"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    host, port = "0.0.0.0", 8000
    bundle = os.environ.get("DRIVE_RAG_TLS_BUNDLE")
    if not bundle:
        uvicorn.run(app, host=host, port=port)
        return
    ca = os.environ.get("DRIVE_RAG_TLS_CA") or ""
    if not ca:
        raise SystemExit("DRIVE_RAG_TLS_BUNDLE is set but DRIVE_RAG_TLS_CA isn't")
    allowed = [u.strip() for u in os.environ.get("DRIVE_RAG_TLS_ALLOWED", FELT_CORE).split(",") if u.strip()]
    from server import mtls

    mtls.serve(app, host, port, bundle, ca, allowed)


if __name__ == "__main__":
    main()
