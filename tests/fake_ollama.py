"""A fake Ollama on loopback, for the tests of asking a model (ADR-0017).

It lists the models, answers the questions each test gives it, turns text into vectors
by `tests.memory_fakes`' concepts, and records what it was sent. It never starts or reaches a real model server.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tests.memory_fakes import concept_vector


class FakeOllama(ThreadingHTTPServer):
    seen: list[tuple[str, str, Any]]
    tags: dict[str, Any]
    chat: bytes
    #: Answers to questions, in order, each used once; when empty, `chat` answers.
    answers: list[bytes]
    #: When set, the raw answer to every embedding request; otherwise each text's vector
    #: comes from `tests.memory_fakes.concept_vector`.
    embedding: bytes | None
    #: Cleared, the server holds every answer to a question until it is set again: a
    #: model that is still thinking.
    release: threading.Event
    #: Loaded models, as `/api/ps` lists them. A request with no messages loads one, or
    #: unloads it when `keep_alive` is 0.
    ps: list[dict[str, Any]]
    #: Bytes of every model loaded from now on that do not fit on the card.
    spill: int
    #: What `/api/show` says each model can do. A model not named here gets an answer
    #: with no `capabilities`, as an older server gives. One that cannot `completion`
    #: is refused a chat with a 400, as Ollama refuses an embedding model.
    capabilities: dict[str, list[str]]
    #: Set, `/api/show` says nothing of what any model can do, as an older server.
    hide_capabilities: bool


class _Handler(BaseHTTPRequestHandler):
    server: FakeOllama

    def _reply(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        self.server.seen.append((self.command, self.path, json.loads(raw) if raw else None))
        if self.path == "/api/chat":
            self.server.release.wait(30)
        sent = json.loads(raw) if raw else {}
        status = 200
        can = self.server.capabilities.get(str(sent.get("model")))
        if self.path == "/api/chat" and can is not None and "completion" not in can:
            status = 400
            body = json.dumps({"error": f'"{sent.get("model")}" does not support chat'}).encode()
        elif self.path == "/api/show":
            body = json.dumps(
                {"capabilities": can}
                if can is not None and not self.server.hide_capabilities
                else {"license": "a licence"}
            ).encode()
        elif self.path == "/api/tags":
            body = json.dumps(self.server.tags).encode()
        elif self.path == "/api/ps":
            body = json.dumps({"models": self.server.ps}).encode()
        elif self.path == "/api/chat" and sent.get("messages") == []:
            body = self._load(sent)
        elif self.path == "/api/embed":
            texts = json.loads(raw).get("input", []) if raw else []
            body = (
                self.server.embedding
                or json.dumps({"embeddings": [concept_vector(text) for text in texts]}).encode()
            )
        elif self.path == "/api/chat" and self.server.answers:
            body = self.server.answers.pop(0)
        else:
            body = self.server.chat
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _load(self, sent: dict[str, Any]) -> bytes:
        name = sent.get("model")
        self.server.ps = [m for m in self.server.ps if m["name"] != name]
        if sent.get("keep_alive") == 0:
            return json.dumps({"model": name, "done": True, "done_reason": "unload"}).encode()
        size = next(
            (m["size"] for m in self.server.tags.get("models", []) if m.get("name") == name),
            815_000_000,
        )
        self.server.ps.append(
            {
                "name": name,
                "model": name,
                "size": size,
                "size_vram": max(0, size - self.server.spill),
                "context_length": sent.get("options", {}).get("num_ctx", 4096),
                "expires_at": "2026-10-08T15:00:00Z",
            }
        )
        return json.dumps(
            {"model": name, "done": True, "done_reason": "load", "load_duration": 1_500_000_000}
        ).encode()

    do_GET = _reply
    do_POST = _reply

    def log_message(self, *_: object) -> None:
        pass


def chat_answer(text: str, **extra: object) -> bytes:
    return json.dumps(
        {"message": {"role": "assistant", "content": text}, "done": True, **extra}
    ).encode()


def fake_ollama() -> Iterator[FakeOllama]:
    """For a fixture: `yield from fake_ollama()`. Two models, one small, one too big."""
    srv = FakeOllama(("127.0.0.1", 0), _Handler)
    srv.seen = []
    srv.tags = {
        "models": [
            {"name": "gemma3:1b", "size": 815_000_000},
            {"name": "qwen3-coder:30b", "size": 18_000_000_000},
        ]
    }
    srv.chat = chat_answer("Hello.", prompt_eval_count=12, eval_count=3, done_reason="stop")
    srv.embedding = None
    srv.ps = []
    srv.spill = 0
    srv.capabilities = {}
    srv.hide_capabilities = False
    srv.answers = []
    srv.release = threading.Event()
    srv.release.set()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv
    finally:
        srv.release.set()
        srv.shutdown()
        srv.server_close()
