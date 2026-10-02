"""drive-rag backend — hybrid retrieval + a Gemini answer, called internally
by felt-core's search_documents skill (not a human-facing chat UI, so this is
a plain JSON request/response, not SSE like poe2rag's).

Env:
  DRIVE_DB          path to drive.db            (default ./data/drive.db)
  EMBED_MODEL       model2vec model name        (default minishlab/potion-retrieval-32M)
  LLM_BASE_URL      OpenAI-compatible endpoint  (default http://ninerouter:20128/v1)
  LLM_API_KEY       key for that endpoint
  LLM_MODEL         model id                    (default ag/gemini-3.8-flash)
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from .retrieve import Hit, connect, search

DB = os.getenv("DRIVE_DB", "data/drive.db")
EMBED_MODEL = os.getenv("EMBED_MODEL", "minishlab/potion-retrieval-32M")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://ninerouter:20128/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "ag/gemini-3.8-flash")
TOP_K = int(os.getenv("TOP_K", "6"))

SYSTEM = (
    "You are searching Mario's personal documents (his local Google Drive sync "
    "and Obsidian vault) to answer a question. Answer using ONLY the numbered "
    "passages below.\n"
    "Style:\n"
    "- Lead with the direct answer in one sentence. No preamble.\n"
    "- Keep it short — a few sentences or a tight bullet list.\n"
    "- Cite each claim with its passage number, e.g. [2].\n"
    "- Always mention which file(s) the answer came from by name, so Mario can "
    "go open it directly.\n"
    "- If the passages don't actually answer the question, say so plainly — do "
    "NOT guess or invent something that sounds plausible."
)

state: dict = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    from model2vec import StaticModel

    state["db"] = connect(DB)
    state["embed"] = StaticModel.from_pretrained(EMBED_MODEL)
    state["http"] = httpx.AsyncClient(timeout=120)
    yield
    await state["http"].aclose()
    state["db"].close()


app = FastAPI(title="drive-rag", lifespan=lifespan)


class Ask(BaseModel):
    question: str


def embed_query(q: str) -> list[float]:
    return state["embed"].encode([q])[0].astype("float32").tolist()


def build_prompt(question: str, hits: list[Hit]) -> str:
    blocks = []
    for i, h in enumerate(hits, 1):
        loc = f"{h.title}" + (f" — {h.section}" if h.section else "")
        blocks.append(f"[{i}] (file: {h.url}, {loc})\n{h.text}")
    return "\n\n".join(blocks) + f"\n\n---\nQuestion: {question}"


@app.get("/api/health")
async def health():
    n = state["db"].execute("SELECT count(*) FROM chunks").fetchone()[0]
    return {"ok": True, "chunks": n, "model": LLM_MODEL}


@app.post("/api/ask")
async def ask(body: Ask):
    hits = search(state["db"], embed_query(body.question), body.question, k=TOP_K)
    sources = [
        {"n": i, "title": h.title, "url": h.url, "section": h.section} for i, h in enumerate(hits, 1)
    ]

    if not hits:
        return {"answer": "No matching documents found.", "sources": []}

    payload = {
        "model": LLM_MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": build_prompt(body.question, hits)},
        ],
    }
    headers = {"Authorization": f"Bearer {LLM_API_KEY}"} if LLM_API_KEY else {}
    response = await state["http"].post(f"{LLM_BASE_URL}/chat/completions", json=payload, headers=headers)
    response.raise_for_status()
    answer = response.json()["choices"][0]["message"]["content"]
    return {"answer": answer, "sources": sources}
