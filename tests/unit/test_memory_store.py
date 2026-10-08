"""The recall store (ADR-0019, #194): words and meaning, merged, on the record, forgettable.

Embeddings come from `tests.memory_fakes.Concepts`; nothing here reaches a model server.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.kernel.contracts import Decision, LedgerEntry, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.local import ANSWER_ACTION
from sletchy.mind.memory import (
    ADD_ACTION,
    FORGET_ACTION,
    FOUND_ACTION,
    SEARCH_ACTION,
    Chunk,
    MemoryRefused,
    MemoryStore,
    document,
    turn,
)
from sletchy.mind.memory.store import COLUMNS, FILENAME, fts_query, fuse
from tests.memory_fakes import Concepts

NOTES = """# Garage

My automobile is red, and it needs new tyres before winter.

# Garden

The roses flower in spring. They want water every second day. Slugs eat the leaves.
"""


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    opened = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    yield opened
    opened.close()


@pytest.fixture
def payloads(tmp_path: Path) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads")


class Switch:
    def __init__(self, on: bool = True) -> None:
        self.on = on

    def __call__(self) -> bool:
        return self.on


def memory(
    tmp_path: Path,
    ledger: Ledger,
    payloads: PayloadStore,
    *,
    on: Switch | None = None,
    embedder: Concepts | None = None,
    max_bytes: int | None = None,
) -> MemoryStore:
    kwargs = {} if max_bytes is None else {"max_bytes": max_bytes}
    return MemoryStore(
        tmp_path / "memory",
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=on or Switch(),
        embedder=embedder,
        **kwargs,
    )


def actions(ledger: Ledger) -> list[str]:
    return [e.action for e in ledger.entries()]


def answer_entry(ledger: Ledger) -> LedgerEntry:
    """An answer on the record, as the harness writes one."""
    return ledger.append(
        plane=Plane.MIND,
        actor_id="test",
        action=ANSWER_ACTION,
        subject=Subject(kind=SubjectKind.MODEL, identifier="gemma3:1b"),
        verdict=Verdict(decision=Decision.ALLOW, reason="an answer"),
    )


# ── words ────────────────────────────────────────────────────────────────────


def test_a_search_finds_a_paragraph_by_its_words(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads)
    store.add(document("notes.md", NOTES))

    found = store.search("when do the roses want water?")

    assert found.passages[0].text.startswith("The roses flower in spring.")
    assert found.passages[0].header == "notes.md > Garden"
    assert found.passages[0].by == ("words",)
    assert found.by_meaning is False


def test_a_window_match_returns_its_paragraph_once(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads)
    store.add(document("notes.md", NOTES))

    found = store.search("slugs leaves water", k=5)

    texts = [p.text for p in found.passages]
    assert texts.count(texts[0]) == 1
    assert texts[0].startswith("The roses")
    assert all(p.id for p in found.passages)


def test_a_header_is_searched_with_the_words(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads)
    store.add(document("notes.md", NOTES))

    assert store.search("garage").passages[0].text.startswith("My automobile")


def test_a_question_with_no_words_finds_nothing(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads)
    store.add(document("notes.md", NOTES))

    assert store.search("?!").passages == ()


# ── meaning ──────────────────────────────────────────────────────────────────


def test_meaning_finds_what_words_cannot(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    by_words = memory(tmp_path / "a", ledger, payloads)
    by_words.add(document("notes.md", NOTES))
    by_both = memory(tmp_path / "b", ledger, payloads, embedder=Concepts())
    by_both.add(document("notes.md", NOTES))

    assert by_words.search("car").passages == ()
    found = by_both.search("car")
    assert found.by_meaning is True
    assert found.passages[0].text.startswith("My automobile")
    assert found.passages[0].by == ("meaning",)


def test_a_match_by_both_ranks_above_a_match_by_one(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads, embedder=Concepts())
    store.add(document("pets.md", "Our puppy sleeps all day.\n\nThe dog barks at night."))

    found = store.search("dog")

    assert found.passages[0].text == "The dog barks at night."
    assert found.passages[0].by == ("meaning", "words")
    assert found.passages[1].by == ("meaning",)


def test_when_the_embedder_fails_search_falls_back_to_words_and_says_so(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    concepts = Concepts()
    store = memory(tmp_path, ledger, payloads, embedder=concepts)
    store.add(document("notes.md", NOTES))
    concepts.fail = True

    found = store.search("roses")

    assert found.by_meaning is False
    assert found.passages[0].text.startswith("The roses")


def test_an_embedder_failure_while_adding_stores_nothing(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    concepts = Concepts()
    concepts.fail = True
    store = memory(tmp_path, ledger, payloads, embedder=concepts)

    with pytest.raises(OSError):
        store.add(document("notes.md", NOTES))

    assert ADD_ACTION not in actions(ledger)
    concepts.fail = False
    assert store.sources() == []


def test_vectors_from_another_model_are_never_compared(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads, embedder=Concepts())
    store.add(document("notes.md", NOTES))
    other = Concepts()
    other.name = "another:model"
    again = memory(tmp_path, ledger, payloads, embedder=other)

    assert again.search("car").by_meaning is False


# ── storing once, forgetting ────────────────────────────────────────────────


def test_adding_the_same_document_twice_stores_it_once(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads)
    first = store.add(document("notes.md", NOTES))
    again = store.add(document("notes.md", NOTES))

    assert first.new > 0 and first.already == 0
    assert again.new == 0 and again.already == first.new
    assert store.sources()[0][2] == first.new


def test_forget_removes_a_source_and_the_chain_still_verifies(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads, embedder=Concepts())
    added = store.add(document("notes.md", NOTES))
    store.add(document("other.md", "Unrelated roses."))

    assert store.forget("notes.md") == added.new

    assert [s for s, _, _ in store.sources()] == ["other.md"]
    assert all(p.source == "other.md" for p in store.search("roses automobile").passages)
    db = sqlite3.connect(tmp_path / "memory" / FILENAME)
    left = db.execute("SELECT COUNT(*) FROM words").fetchone()[0]
    vectors_left = db.execute("SELECT COUNT(*) FROM vectors").fetchone()[0]
    db.close()
    assert left == vectors_left == store.sources()[0][2] - 1  # the section is never indexed
    assert ledger.verify() == ledger.length


def test_a_conversation_turn_is_kept_and_found_with_its_answer_entry(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads)
    answered = answer_entry(ledger)
    store.add(turn("c-1", 1, "My name is Ada.", "Hello, Ada.", cites=answered.seq))

    found = store.search("what is my name")

    assert found.passages[0].cites == answered.seq
    assert found.passages[0].header == "conversation c-1 > turn 1"


# ── the switch and the record ───────────────────────────────────────────────


def test_switched_off_memory_adds_and_finds_nothing(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    switch = Switch(on=False)
    concepts = Concepts()
    store = memory(tmp_path, ledger, payloads, on=switch, embedder=concepts)

    for call in (
        lambda: store.add(document("notes.md", NOTES)),
        lambda: store.search("roses"),
        lambda: store.forget("notes.md"),
        store.sources,
    ):
        with pytest.raises(MemoryRefused, match="switched off"):
            call()

    assert concepts.calls == []
    assert not (tmp_path / "memory").exists()
    denied = [e for e in ledger.entries() if e.verdict.decision is Decision.DENY]
    assert len(denied) == 4


def test_every_add_and_search_is_on_the_record_before_it_takes_effect(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    concepts = Concepts()
    store = memory(tmp_path, ledger, payloads, embedder=concepts)
    seen: list[tuple[str, int, int]] = []
    append = ledger.append

    def watched(**kwargs: object) -> LedgerEntry:
        path = tmp_path / "memory" / FILENAME
        rows = 0
        if path.exists():
            db = sqlite3.connect(path)
            rows = db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
            db.close()
        seen.append((str(kwargs["action"]), rows, len(concepts.calls)))
        return append(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ledger, "append", watched)
    store.add(document("notes.md", NOTES))
    store.search("roses")

    assert seen[0] == (ADD_ACTION, 0, 1)  # embedded, recorded, and nothing stored yet
    assert seen[1][0] == SEARCH_ACTION
    assert seen[1][2] == 1  # the question was not yet embedded
    assert seen[2][0] == FOUND_ACTION


def test_the_record_holds_the_question_and_what_was_found(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore
) -> None:
    store = memory(tmp_path, ledger, payloads)
    store.add(document("notes.md", NOTES))

    found = store.search("roses water")

    entries = {e.seq: e for e in ledger.entries()}
    asked, answered = entries[found.search_seq], entries[found.found_seq]
    assert asked.payload_hash is not None and answered.payload_hash is not None
    assert payloads.get(asked.payload_hash) == b"roses water"
    held = json.loads(payloads.get(answered.payload_hash))
    assert [h["id"] for h in held] == [p.id for p in found.passages]
    assert f"search {found.search_seq}" in answered.verdict.reason
    add = next(e for e in ledger.entries() if e.action == ADD_ACTION)
    assert add.subject.kind is SubjectKind.MEMORY
    assert FORGET_ACTION not in actions(ledger)


@pytest.mark.parametrize(
    ("question", "k", "reason"),
    [("   ", 5, "empty"), ("x" * 2001, 5, "over 2000"), ("roses", 0, "k must"), ("a", 51, "k")],
)
def test_a_bad_search_is_refused_on_the_record(
    tmp_path: Path, ledger: Ledger, payloads: PayloadStore, question: str, k: int, reason: str
) -> None:
    store = memory(tmp_path, ledger, payloads)

    with pytest.raises(MemoryRefused, match=reason) as refused:
        store.search(question, k=k)

    entry = next(e for e in ledger.entries() if e.seq == refused.value.seq)
    assert entry.verdict.decision is Decision.DENY


def test_one_add_holds_one_source(tmp_path: Path, ledger: Ledger, payloads: PayloadStore) -> None:
    store = memory(tmp_path, ledger, payloads)

    with pytest.raises(MemoryRefused, match="exactly one source"):
        store.add([*document("a.md", "One."), *document("b.md", "Two.")])
    with pytest.raises(MemoryRefused, match="exactly one source"):
        store.add([])


# ── the shape of the store ──────────────────────────────────────────────────


def test_the_table_columns_are_the_chunk_fields() -> None:
    """LAW 6: the columns are generated from `Chunk`, never typed a second time."""
    assert [name for name, _ in COLUMNS] == [*Chunk.model_fields, "added_seq"]
    assert dict(COLUMNS)["parent"] == "TEXT"
    assert dict(COLUMNS)["cites"] == "INTEGER"
    assert dict(COLUMNS)["position"] == "INTEGER NOT NULL"


def test_a_question_reaches_fts5_as_quoted_words_only() -> None:
    assert fts_query('NEAR(roses "water") OR text:x*') == (
        '"near" OR "roses" OR "water" OR "text" OR "x"'
    )
    assert fts_query("!!!") is None


def test_words_that_match_everything_are_not_searched() -> None:
    assert fts_query("What is my name?") == '"name"'
    assert fts_query("Who are you?") is None


def test_fusion_adds_reciprocal_ranks() -> None:
    scores = fuse([1, 2], [2, 3])

    assert scores[2] == pytest.approx(1 / 62 + 1 / 61)
    assert max(scores, key=lambda k: scores[k]) == 2
