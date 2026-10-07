# drive-rag backend — FastAPI + model2vec + sqlite-vec.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    HF_HOME=/models \
    DRIVE_DB=/data/drive.db

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --group server

# bake the embedding model into the image so the container is offline-capable
RUN uv run python -c "from model2vec import StaticModel; StaticModel.from_pretrained('minishlab/potion-retrieval-32M')"

COPY server/ ./server/

EXPOSE 8000
# plain uvicorn, or mTLS when DRIVE_RAG_TLS_BUNDLE is set (server/serve.py, WP-62 M2b)
CMD ["uv", "run", "--no-dev", "--group", "server", "python", "-m", "server.serve"]
