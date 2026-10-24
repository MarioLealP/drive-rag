# drive-rag

RAG over my local Google Drive sync (docs, PDFs, the Obsidian vault). felt-core's search_documents skill is the only caller; answers via felt-llm (local).

Deployed on clockmost: push to `main` -> CI builds `git.clockmost.com/benylin/drive-rag:<sha>` and bumps its tag in the infra repo; the deploy loop health-checks it and auto-reverts on failure (Felt WP-53). The index (`/data`) is mounted on the server, not in this repo.

Until 2026-10-02 this code lived vendored inside the infra repo (`projects/drive-rag/app`).
