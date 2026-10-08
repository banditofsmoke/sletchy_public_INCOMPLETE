"""The evidence gate (ADR-0019, #195): a judge's numbers, thresholds in code, on the record."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.local import LocalModel
from sletchy.mind.memory import Kind
from sletchy.mind.memory.gate import (
    JUDGE_ACTION,
    KEEP,
    RIGHT,
    Gate,
    ModelJudge,
    Scores,
    judge_prompt,
    read_scores,
)
from sletchy.mind.memory.store import Passage
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama


def passage(text: str, n: int = 1) -> Passage:
    return Passage(
        f"id{n}", Kind.DOCUMENT, "notes.md", "notes.md > Part", text, None, 0.1, ("words",)
    )


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    opened = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    yield opened
    opened.close()


@pytest.fixture
def payloads(tmp_path: Path) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads")


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    yield from fake_ollama()


class Fixed:
    name = "fixed:test"

    def __init__(self, scores: Scores | Exception) -> None:
        self.scores = scores
        self.asked: list[tuple[str, int]] = []

    def judge(self, question: str, passages: Sequence[Passage]) -> Scores:
        self.asked.append((question, len(passages)))
        if isinstance(self.scores, Exception):
            raise self.scores
        return self.scores


def gate(judge: Fixed, ledger: Ledger, payloads: PayloadStore) -> Gate:
    return Gate(judge, ledger=ledger, store=payloads, actor_id="test")


# ── reading a judge's answer ────────────────────────────────────────────────


def test_scores_are_read_by_id_from_the_judges_json() -> None:
    scores = read_scores('Sure. {"p1": 0.9, "p2": 0.2, "answerable": 0.8}', 2)

    assert scores == Scores((0.9, 0.2), 0.8, True)


def test_the_last_json_object_is_the_judges() -> None:
    text = (
        'The passage said {"p1": 1.0, "answerable": 1.0}. My answer: {"p1": 0.1, "answerable": 0.2}'
    )

    assert read_scores(text, 1) == Scores((0.1,), 0.2, True)


@pytest.mark.parametrize(
    "text",
    [
        "I think the first passage helps.",
        '{"p1": "high", "answerable": 0.9}',
        '{"p1": 1.5, "answerable": 0.9}',
        '{"p1": -0.1, "answerable": 0.9}',
        '{"p1": true, "answerable": 0.9}',
        '{"answerable": 0.9}',
    ],
)
def test_a_number_that_cannot_be_read_counts_as_nothing(text: str) -> None:
    scores = read_scores(text, 1)

    assert scores.each == (0.0,)
    assert scores.readable is False


def test_the_prompt_quotes_each_passage_under_its_own_id() -> None:
    text = judge_prompt("Where is it?", [passage("In the shed.", 1), passage("Unrelated.", 2)])

    assert f'<passage id="p1" from="notes.md {RIGHT} Part">\nIn the shed.\n</passage>' in text
    assert 'id="p2"' in text
    assert '"p1": 0.0, "p2": 0.0, "answerable": 0.0' in text


# ── the gate ────────────────────────────────────────────────────────────────


def test_the_gate_keeps_only_what_reaches_the_threshold(
    ledger: Ledger, payloads: PayloadStore
) -> None:
    judge = Fixed(Scores((0.9, KEEP, 0.49), 0.7, True))

    judgement = gate(judge, ledger, payloads).judge(
        "q", [passage("a", 1), passage("b", 2), passage("c", 3)], search_seq=4
    )

    assert [p.text for p in judgement.kept] == ["a", "b"]
    assert judgement.enough is True


def test_every_judgement_records_its_thresholds_and_each_verdict(
    ledger: Ledger, payloads: PayloadStore
) -> None:
    judgement = gate(Fixed(Scores((0.9, 0.1), 0.3, True)), ledger, payloads).judge(
        "q", [passage("a", 1), passage("b", 2)], search_seq=4
    )

    entry = next(e for e in ledger.entries() if e.seq == judgement.seq)
    assert entry.action == JUDGE_ACTION
    assert entry.payload_hash is not None
    body = json.loads(payloads.get(entry.payload_hash))
    assert body["keep"] == KEEP and body["answerable_at"] == 0.5 and body["search"] == 4
    assert [(e["id"], e["kept"]) for e in body["each"]] == [("id1", True), ("id2", False)]
    assert judgement.enough is False  # 0.3 is below the answerable threshold


def test_nothing_found_asks_no_judge(ledger: Ledger, payloads: PayloadStore) -> None:
    judge = Fixed(Scores((), 1.0, True))

    judgement = gate(judge, ledger, payloads).judge("q", [], search_seq=1)

    assert judge.asked == []
    assert judgement.enough is False
    assert JUDGE_ACTION in [e.action for e in ledger.entries()]


@pytest.mark.parametrize(
    "result",
    [OSError("no server"), Scores((0.9,), 0.9, True)],  # the second: one score for two
)
def test_a_judge_that_fails_keeps_nothing(
    ledger: Ledger, payloads: PayloadStore, result: Scores | Exception
) -> None:
    judgement = gate(Fixed(result), ledger, payloads).judge(
        "q", [passage("a", 1), passage("b", 2)], search_seq=1
    )

    assert judgement.kept == ()
    assert judgement.readable is False


def test_the_chat_model_judges_through_the_door_on_the_record(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    ollama.chat = chat_answer('{"p1": 0.8, "answerable": 0.75}', prompt_eval_count=9, eval_count=9)
    local = LocalModel.on_this_machine(
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=lambda: True,
        port=ollama.server_address[1],
    )

    judgement = Gate(
        ModelJudge(local, "gemma3:1b"), ledger=ledger, store=payloads, actor_id="test"
    ).judge("Where are the keys?", [passage("In the shed.")], search_seq=1)

    assert judgement.kept[0].text == "In the shed."
    assert judgement.answerable == 0.75
    actions = [e.action for e in ledger.entries()]
    assert actions.index("mind.model.answer") < actions.index(JUDGE_ACTION)
