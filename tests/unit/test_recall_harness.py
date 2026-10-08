"""Recall in a conversation (ADR-0019, #195, #193): remembered across conversations, judged,
quoted with its source, and the plan on the record before the question.

A fake Ollama answers both the judge and the conversation, in the order the test queues
them; nothing here reaches a real model server.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import EXIT_OK, main
from sletchy.kernel.contracts import AgentEvent, AgentEventType
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.harness import Conversation
from sletchy.mind.harness.context import PLAN_ACTION, WHO_SAID, with_passages
from sletchy.mind.harness.hosts.cli import render
from sletchy.mind.local import LocalModel
from sletchy.mind.memory import MemoryStore
from sletchy.mind.memory.gate import JUDGE_ACTION, RIGHT, Gate, ModelJudge
from sletchy.mind.memory.recall import Recall
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

SMALL = "gemma3:1b"
T = AgentEventType


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


def judged(**scores: float) -> bytes:
    return chat_answer(json.dumps(scores), prompt_eval_count=20, eval_count=10)


def said(text: str) -> bytes:
    return chat_answer(text, prompt_eval_count=20, eval_count=5, done_reason="stop")


def talk(
    ollama: FakeOllama,
    ledger: Ledger,
    payloads: PayloadStore,
    tmp_path: Path,
    *,
    only: bool = False,
    memory_on: bool = True,
) -> Conversation:
    local = LocalModel.on_this_machine(
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=lambda: True,
        port=ollama.server_address[1],
    )
    store = MemoryStore(
        tmp_path / "memory",
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=lambda: memory_on,
    )
    gate = Gate(ModelJudge(local, SMALL), ledger=ledger, store=payloads, actor_id="test")
    return Conversation(
        local,
        SMALL,
        ledger=ledger,
        actor_id="test",
        recall=Recall(store, gate),
        only_from_memory=only,
    )


def events(conversation: Conversation, question: str) -> list[AgentEvent]:
    seen: list[AgentEvent] = []
    conversation.play(question, seen.append)
    return seen


def chats(ollama: FakeOllama) -> list[list[dict[str, str]]]:
    return [body["messages"] for _, path, body in ollama.seen if path == "/api/chat"]


def test_a_new_conversation_remembers_what_an_earlier_one_was_told(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, tmp_path: Path
) -> None:
    first = talk(ollama, ledger, payloads, tmp_path)
    ollama.answers = [said("Hello, Ada.")]
    events(first, "My name is Ada.")

    second = talk(ollama, ledger, payloads, tmp_path)
    ollama.answers = [judged(p1=0.95, answerable=0.9), said("Your name is Ada.")]
    seen = events(second, "What is my name?")

    asked = chats(ollama)[-1]
    assert len(asked) == 1  # a new conversation: no earlier turns, only the passage
    prompt = asked[0]["content"]
    assert prompt.endswith("My question: What is my name?")
    assert "Question: My name is Ada.\nAnswer: Hello, Ada." in prompt
    assert f'source="conversation {first.id} {RIGHT} turn 1"' in prompt
    status = next(e for e in seen if e.type is T.STATUS)
    assert status.data["recalled"] == 1
    assert "1 passage from memory, plan entry" in render(status)
    assert second.history == (("What is my name?", "Your name is Ada."),)


def test_the_plan_and_the_judgement_are_on_the_record_before_the_question(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, tmp_path: Path
) -> None:
    first = talk(ollama, ledger, payloads, tmp_path)
    ollama.answers = [said("Noted: the keys are in the shed.")]
    events(first, "The keys are in the shed.")
    ollama.answers = [judged(p1=0.9, answerable=0.9), said("In the shed.")]

    events(talk(ollama, ledger, payloads, tmp_path), "Where are the keys?")

    trail = [e.action for e in ledger.entries()]
    tail = trail[trail.index("mind.memory.search", trail.index("mind.memory.add") + 1) :]
    order = [
        a
        for a in tail
        if a
        in {"mind.memory.search", "mind.memory.found", JUDGE_ACTION, PLAN_ACTION, "mind.model.ask"}
    ]
    assert order[:3] == ["mind.memory.search", "mind.memory.found", "mind.model.ask"]  # the judge
    assert order[3:6] == [JUDGE_ACTION, PLAN_ACTION, "mind.model.ask"]  # then the question
    plan = [e for e in ledger.entries() if e.action == PLAN_ACTION][-1]
    assert plan.payload_hash is not None
    body = json.loads(payloads.get(plan.payload_hash))
    assert body["passages"][0]["probability"] == 0.9
    assert body["passages"][0]["entry"] is not None


def test_a_passage_the_judge_turns_away_never_reaches_the_model(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, tmp_path: Path
) -> None:
    first = talk(ollama, ledger, payloads, tmp_path)
    ollama.answers = [said("Noted.")]
    events(first, "My cat is called Tom.")
    ollama.answers = [judged(p1=0.1, answerable=0.1), said("I do not know.")]

    seen = events(talk(ollama, ledger, payloads, tmp_path), "What is my cat called?")

    assert chats(ollama)[-1] == [{"role": "user", "content": "What is my cat called?"}]
    assert next(e for e in seen if e.type is T.STATUS).data["recalled"] == 0


def test_only_from_memory_answers_not_in_my_memory_without_asking(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, tmp_path: Path
) -> None:
    first = talk(ollama, ledger, payloads, tmp_path)
    ollama.answers = [said("Noted.")]
    events(first, "The roses want water.")
    ollama.answers = [judged(p1=0.2, answerable=0.1)]
    asked_before = len(chats(ollama))

    seen = events(talk(ollama, ledger, payloads, tmp_path, only=True), "When do roses flower?")

    assert len(chats(ollama)) == asked_before + 1  # the judge only
    assert [e.type for e in seen] == [T.COMPLETE]
    assert seen[0].data["outcome"] == "not_in_memory"
    entry = next(e for e in ledger.entries() if e.seq == seen[0].ledger_seq)
    assert entry.action == JUDGE_ACTION
    assert "not in my memory" in render(seen[0])


def test_only_from_memory_with_memory_off_is_refused_not_not_in_memory(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, tmp_path: Path
) -> None:
    seen = events(talk(ollama, ledger, payloads, tmp_path, only=True, memory_on=False), "Anything?")

    assert [e.type for e in seen] == [T.POLICY, T.COMPLETE]
    assert seen[1].data["outcome"] == "refused"
    assert "sletchy flags set mind_memory on" in render(seen[0])
    assert chats(ollama) == []


def test_an_answer_from_memory_is_not_put_back_into_memory(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore, tmp_path: Path
) -> None:
    first = talk(ollama, ledger, payloads, tmp_path)
    ollama.answers = [said("Noted.")]
    events(first, "The roses want water.")
    adds = sum(e.action == "mind.memory.add" for e in ledger.entries())
    ollama.answers = [judged(p1=0.9, answerable=0.9), said("Water.")]

    events(talk(ollama, ledger, payloads, tmp_path, only=True), "What do the roses want?")

    assert sum(e.action == "mind.memory.add" for e in ledger.entries()) == adds


def test_only_from_memory_needs_a_memory(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    local = LocalModel.on_this_machine(
        ledger=ledger, store=payloads, actor_id="t", switched_on=lambda: True, port=1024
    )
    with pytest.raises(ValueError, match="needs a memory"):
        Conversation(local, SMALL, ledger=ledger, actor_id="t", only_from_memory=True)


# ── from a terminal ─────────────────────────────────────────────────────────


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FlagStore]:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(
        "sletchy.cli.main.KeyringKeySource", lambda *a, **k: InMemoryKeySource(b"k" * 32)
    )
    opened = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    flags = FlagStore.open(opened, paths.flags_file())
    yield flags
    opened.close()


def test_chat_with_memory_on_remembers_across_conversations(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home.set("mind_local_models", True, reason="testing")
    home.set("mind_memory", True, reason="testing")
    port = str(ollama.server_address[1])
    monkeypatch.setattr("sys.stdin", io.StringIO("My name is Ada.\n\n"))
    ollama.answers = [said("Hello, Ada.")]
    assert main(["chat", "--port", port, SMALL]) == EXIT_OK
    assert "Memory is on" in capsys.readouterr().err

    monkeypatch.setattr("sys.stdin", io.StringIO("What is my name?\n\n"))
    ollama.answers = [judged(p1=0.9, answerable=0.9), said("Your name is Ada.")]
    assert main(["chat", "--port", port, SMALL]) == EXIT_OK
    out = capsys.readouterr().out
    assert "1 passage from memory" in out
    assert "> Your name is Ada." in out


def test_memory_ask_says_not_in_my_memory_from_a_terminal(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home.set("mind_local_models", True, reason="testing")
    home.set("mind_memory", True, reason="testing")
    monkeypatch.setattr("sys.stdin", io.StringIO("The roses want water."))
    assert main(["memory", "add", "notes.md"]) == EXIT_OK
    ollama.answers = [judged(p1=0.1, answerable=0.0)]

    port = str(ollama.server_address[1])
    assert (
        main(["memory", "ask", "--port", port, SMALL, "When", "is", "the", "dentist?"]) == EXIT_OK
    )

    assert "not in my memory" in capsys.readouterr().out


def test_the_passages_say_who_said_what() -> None:
    """#208: a model answered "my name is Ornith" to "what is my name?", reading an earlier
    model's answer about itself as mine."""
    prompt = with_passages("What is my name?", ())

    assert "Question is what I said and Answer is what a model said back" in prompt
    assert prompt.index(WHO_SAID) < prompt.index("My question:")
