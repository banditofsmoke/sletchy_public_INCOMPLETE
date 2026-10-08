"""Embeddings through the door (ADR-0019): one more question for a model, on the record first.

A fake Ollama runs on loopback and records what it is sent; nothing here starts or
reaches a real model server.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.local import (
    EMBED_ACTION,
    EMBED_BATCH_CHARS,
    EgressDenied,
    LocalModel,
    ModelRefused,
    ModelUnreadable,
)
from sletchy.mind.memory import LocalEmbedder, MemoryStore, document
from sletchy.warden.egress.local import LOCAL_ACTION, LocalModelDoor
from tests.fake_ollama import FakeOllama, fake_ollama

SMALL = "gemma3:1b"
BIG = "qwen3-coder:30b"


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    yield from fake_ollama()


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    opened = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    yield opened
    opened.close()


@pytest.fixture
def payloads(tmp_path: Path) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads")


def model(ledger: Ledger, payloads: PayloadStore, port: int, *, on: bool = True) -> LocalModel:
    return LocalModel.on_this_machine(
        ledger=ledger, store=payloads, actor_id="test", switched_on=lambda: on, port=port
    )


def posted(ollama: FakeOllama) -> list[list[str]]:
    return [body["input"] for method, path, body in ollama.seen if path == "/api/embed"]


def test_embed_is_recorded_before_each_request_reaches_the_door(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    vectors = model(ledger, payloads, ollama.server_address[1]).embed(SMALL, ["red car", "rose"])

    assert len(vectors) == 2 and all(isinstance(x, float) for x in vectors[0])
    assert posted(ollama) == [["red car", "rose"]]
    trail = [(e.action, e.subject.identifier) for e in ledger.entries()]
    embed_at = next(i for i, (a, _) in enumerate(trail) if a == EMBED_ACTION)
    door_at = next(
        i for i, (a, s) in enumerate(trail) if a == LOCAL_ACTION and s.endswith("/api/embed")
    )
    assert embed_at < door_at


def test_embed_sends_long_input_in_batches_each_on_the_record(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    texts = ["x" * 5000] * 7  # 35,000 characters

    vectors = model(ledger, payloads, ollama.server_address[1]).embed(SMALL, texts)

    batches = posted(ollama)
    assert len(vectors) == 7
    assert [len(b) for b in batches] == [3, 3, 1]
    assert all(sum(len(t) for t in b) <= EMBED_BATCH_CHARS for b in batches)
    assert sum(e.action == EMBED_ACTION for e in ledger.entries()) == 3


def test_embed_refuses_a_model_over_the_budget_and_never_sends(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    with pytest.raises(ModelRefused, match="at most"):
        model(ledger, payloads, ollama.server_address[1]).embed(BIG, ["text"])

    assert posted(ollama) == []


def test_embed_switched_off_never_reaches_the_server(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    with pytest.raises(EgressDenied, match="switched off"):
        model(ledger, payloads, ollama.server_address[1], on=False).embed(SMALL, ["text"])

    assert ollama.seen == []


@pytest.mark.parametrize(
    "reply",
    [
        {"embeddings": [[0.1, 0.2]]},  # one vector for two texts
        {"embeddings": [[0.1, "x"], [0.2, 0.3]]},
        {"embeddings": [[], [0.2]]},
        {"embeddings": [[True, 1.0], [0.2, 0.3]]},
        {"vectors": []},
    ],
)
def test_an_answer_that_is_not_one_vector_per_text_is_unreadable(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, reply: dict[str, object]
) -> None:
    ollama.embedding = json.dumps(reply).encode()

    with pytest.raises(ModelUnreadable):
        model(ledger, payloads, ollama.server_address[1]).embed(SMALL, ["a", "b"])


def test_no_texts_ask_nothing(ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore) -> None:
    assert model(ledger, payloads, ollama.server_address[1]).embed(SMALL, []) == []
    assert ollama.seen == []


@pytest.mark.adversarial
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/embed"),
        ("POST", "/api/embeddings"),
        ("POST", "/api/embed/"),
        ("POST", "/api/embed?model=x"),
        ("POST", "/api/pull"),
        ("DELETE", "/api/delete"),
    ],
)
def test_the_door_asks_for_embeddings_and_nothing_more(
    ollama: FakeOllama, ledger: Ledger, method: str, path: str
) -> None:
    door = LocalModelDoor(
        ledger=ledger,
        actor_id="test",
        switched_on=lambda: True,
        engine="ollama",
        port=ollama.server_address[1],
    )

    with pytest.raises(EgressDenied, match="not a question"):
        door.request(method, path, b"{}")

    assert ollama.seen == []
    assert door.request("POST", "/api/embed", b'{"input": ["a"]}').status == 200


def test_memory_searches_by_meaning_through_the_door(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, tmp_path: Path
) -> None:
    local = model(ledger, payloads, ollama.server_address[1])
    store = MemoryStore(
        tmp_path / "memory",
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=lambda: True,
        embedder=LocalEmbedder(local, SMALL),
    )
    store.add(document("notes.md", "My automobile is red.\n\nThe roses want water."))

    found = store.search("car")

    assert found.by_meaning is True
    assert found.passages[0].text == "My automobile is red."
    assert len(posted(ollama)) == 2  # the chunks, then the question
