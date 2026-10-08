"""What is not evidence stays out of memory and away from the judge (#205).

Measured on my own record, 2026-10-08: a small model's refusal ("no access to your
Personally Identifiable Information ... your name") was kept as memory, and the next search
found it, my bare question and a piece of it ahead of the fact, which a judge then turned
away. These replay that, with a fake Ollama; nothing here reaches a real model server.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.kernel.contracts import AgentEvent, AgentEventType, Decision
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.harness import Conversation
from sletchy.mind.harness.context import PLAN_ACTION
from sletchy.mind.harness.hosts.cli import render
from sletchy.mind.local import ANSWER_ACTION, LocalModel
from sletchy.mind.memory import MemoryStore
from sletchy.mind.memory.chunk import Kind, turn
from sletchy.mind.memory.evidence import non_answer, only_questions, set_aside
from sletchy.mind.memory.gate import Gate, ModelJudge
from sletchy.mind.memory.recall import Recall
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

SMALL = "gemma3:1b"
DASH = chr(0x2014)
CURLY = chr(0x2019)
#: The two refusals from my record, word for word.
SMALL_REFUSAL = (
    "I am sorry, but I do not have access to your Personally Identifiable Information (PII). "
    "That includes your name. To figure out what name you are referring to, please tell me:"
)
LARGE_REFUSAL = (
    f"I{CURLY}m sorry {DASH} I don{CURLY}t have access to your Personally Identifiable "
    "Information (PII), so I don't know your name unless you tell me. What should I call you?"
)


# ── telling them apart ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "answer",
    [
        SMALL_REFUSAL,
        LARGE_REFUSAL,
        "**I don't know your name.** You have not told me yet.",
        "As an AI language model, I can't remember previous conversations.",
        "I do not retain anything between conversations.",
    ],
)
def test_the_refusals_measured_in_205_are_non_answers(answer: str) -> None:
    assert non_answer(answer)


@pytest.mark.parametrize(
    "answer",
    [
        "Yes, your name is Sam. I found it in our earlier conversation.",
        "The keys are in the shed.",
        "Noted.",
        "I do not know.",  # too short to tell from an honest answer: kept, and judged
        "x" * 500 + " I don't have access to that.",  # past the opening, an answer's own words
    ],
)
def test_an_answer_is_not_a_non_answer(answer: str) -> None:
    assert not non_answer(answer)


@pytest.mark.parametrize(
    ("text", "only"),
    [
        ("what is my name? do you know it?", True),
        ("what is my name", True),
        ("Where are the keys?", True),
        ("My name is Sam. Do you remember it?", False),
        ("The keys are in the shed.", False),
        ("", False),
    ],
)
def test_a_question_alone_states_nothing(text: str, only: bool) -> None:
    assert only_questions(text) is only


@pytest.mark.parametrize(
    ("text", "why"),
    [
        (f"Question: what is my name?\nAnswer: {SMALL_REFUSAL}", "a non-answer"),
        (f"Answer: {LARGE_REFUSAL}", "a non-answer"),
        ("Question: what is my name? do you know it?", "a question alone"),
        ("Question: what is my name? do you know it?\nAnswer:", "a question alone"),
        ("Question: My name is Sam. Do you remember me?", None),
        ("Question: what is my name?\nAnswer: Your name is Sam.", None),
        ("Further into an answer, a line that says nothing of whose words.", None),
    ],
)
def test_a_found_passage_is_set_aside_with_a_reason(text: str, why: str | None) -> None:
    assert set_aside(Kind.CONVERSATION, text) == why


def test_a_document_is_never_set_aside() -> None:
    assert set_aside(Kind.DOCUMENT, f"Answer: {SMALL_REFUSAL}") is None


# ── in a conversation ───────────────────────────────────────────────────────


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


@pytest.fixture
def store(ledger: Ledger, payloads: PayloadStore, tmp_path: Path) -> Iterator[MemoryStore]:
    opened = MemoryStore(
        tmp_path / "memory",
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=lambda: True,
    )
    yield opened
    opened.close()


def talk(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, store: MemoryStore
) -> Conversation:
    local = LocalModel.on_this_machine(
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=lambda: True,
        port=ollama.server_address[1],
    )
    gate = Gate(ModelJudge(local, SMALL), ledger=ledger, store=payloads, actor_id="test")
    return Conversation(local, SMALL, ledger=ledger, actor_id="test", recall=Recall(store, gate))


def said(text: str) -> bytes:
    return chat_answer(text, prompt_eval_count=20, eval_count=5, done_reason="stop")


def events(conversation: Conversation, question: str) -> list[AgentEvent]:
    seen: list[AgentEvent] = []
    conversation.play(question, seen.append)
    return seen


def chats(ollama: FakeOllama) -> list[str]:
    """Every question sent, the judge's included: the last message of each chat."""
    return [body["messages"][-1]["content"] for _, p, body in ollama.seen if p == "/api/chat"]


def last_add(ledger: Ledger) -> tuple[Decision, str]:
    entry = [e for e in ledger.entries() if e.action == "mind.memory.add"][-1]
    return entry.verdict.decision, entry.verdict.reason


def test_a_question_answered_with_a_non_answer_keeps_nothing(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, store: MemoryStore
) -> None:
    ollama.answers = [said(SMALL_REFUSAL)]

    events(talk(ollama, ledger, payloads, store), "what is my name?")

    decision, reason = last_add(ledger)
    assert decision is Decision.DENY
    assert "turn 1: a question and a non-answer, so nothing to remember" in reason
    assert store.sources() == []


def test_my_words_answered_with_a_non_answer_are_kept_alone(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, store: MemoryStore
) -> None:
    ollama.answers = [said("I don't have memory of earlier conversations, so I can't say.")]

    events(talk(ollama, ledger, payloads, store), "My name is Sam. Do you remember me?")

    decision, reason = last_add(ledger)
    assert decision is Decision.ALLOW
    assert reason.endswith("turn 1: its answer left out, a non-answer")
    found = store.search("Sam", k=4).passages
    assert [p.text for p in found] == ["Question: My name is Sam. Do you remember me?"]


def test_the_205_replay_judges_the_fact_and_sets_the_rest_aside(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, store: MemoryStore
) -> None:
    ollama.answers = [said("Hello Sam. I am Sletchy.")]
    events(talk(ollama, ledger, payloads, store), "My name is Sam. You are Sletchy, built by me.")
    cites = [e.seq for e in ledger.entries() if e.action == ANSWER_ACTION][-1]
    # As memory held them before #205: a refusal kept whole, and a question whose answer
    # began with a blank line, so it stands in a paragraph alone.
    store.add(turn("c-refused", 1, "what is my name?", SMALL_REFUSAL, cites=cites))
    store.add(turn("c-asked", 1, "what is my name? do you know it?", "\n\nIt is Sam.", cites=cites))
    scores = {f"p{i}": 0.9 for i in range(1, 9)}
    ollama.answers = [said(json.dumps({**scores, "answerable": 0.9})), said("Your name is Sam.")]

    seen = events(talk(ollama, ledger, payloads, store), "What is my name?")

    judge = chats(ollama)[-2]
    assert "My name is Sam." in judge
    assert "Personally Identifiable" not in judge
    assert "do you know it?" not in judge
    plan = [e for e in ledger.entries() if e.action == PLAN_ACTION][-1]
    assert plan.payload_hash is not None
    aside = json.loads(payloads.get(plan.payload_hash))["set_aside"]
    assert sorted(a["why"] for a in aside) == ["a non-answer", "a question alone"]
    assert "set aside" in plan.verdict.reason
    assert next(e for e in seen if e.type is AgentEventType.STATUS).data["recalled"] == 1


def test_a_judge_that_cannot_be_read_is_said_not_silent(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, store: MemoryStore
) -> None:
    ollama.answers = [said("Noted: the keys are in the shed.")]
    events(talk(ollama, ledger, payloads, store), "The keys are in the shed.")
    ollama.answers = [said("p1 looks right to me"), said("I could not say.")]

    seen = events(talk(ollama, ledger, payloads, store), "Where are the keys?")

    status = next(e for e in seen if e.type is AgentEventType.STATUS)
    assert status.data["recalled"] == 0
    assert status.data["memory_unchecked"] is True
    assert "memory not checked: this model could not judge what memory found" in render(status)
    plan = [e for e in ledger.entries() if e.action == PLAN_ACTION][-1]
    assert "the judge's answer was not all readable" in plan.verdict.reason


def test_a_judge_that_reads_says_nothing_of_it(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, store: MemoryStore
) -> None:
    ollama.answers = [said("Noted: the keys are in the shed.")]
    events(talk(ollama, ledger, payloads, store), "The keys are in the shed.")
    ollama.answers = [said(json.dumps({"p1": 0.9, "answerable": 0.9})), said("In the shed.")]

    seen = events(talk(ollama, ledger, payloads, store), "Where are the keys?")

    status = next(e for e in seen if e.type is AgentEventType.STATUS)
    assert status.data["memory_unchecked"] is False
    assert "memory not checked" not in render(status)
