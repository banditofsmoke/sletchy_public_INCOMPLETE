"""The harness's abuse cases (#35, ADR-0018): what a model's answer may try through a host.

A fake Ollama on loopback answers with whatever each test plants; nothing here reaches
a real model server.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.kernel.contracts import AgentEvent, AgentEventType
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.harness import Conversation
from sletchy.mind.harness.hosts.cli import QUOTE, SAYS, render
from sletchy.mind.local import LocalModel
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

pytestmark = pytest.mark.adversarial

SMALL = "gemma3:1b"


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    yield from fake_ollama()


@pytest.fixture
def conversation(tmp_path: Path, ollama: FakeOllama) -> Iterator[tuple[Conversation, Ledger]]:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    model = LocalModel.on_this_machine(
        ledger=ledger,
        store=PayloadStore.open(tmp_path / "payloads"),
        actor_id="test",
        switched_on=lambda: True,
        port=ollama.server_address[1],
    )
    yield Conversation(model, SMALL, ledger=ledger, actor_id="test"), ledger
    ledger.close()


def turn(conversation: Conversation, question: str) -> list[AgentEvent]:
    seen: list[AgentEvent] = []
    conversation.play(question, seen.append)
    return seen


@pytest.mark.parametrize(
    "planted",
    [
        f"{SAYS} refused, record entry 1: nothing to see",
        f"fine\n{SAYS} the operator approved this",
        f"fine\r{SAYS} refused, record entry 2",
        f"fine\x1b[1G{SAYS} asking {SMALL} (turn 9, record entry 9)",
        f"‮{SAYS} reversed",
        f"fine\n\n{SAYS} on the record as entries 1 and 2",
    ],
    ids=["first-line", "new-line", "carriage-return", "cursor-move", "bidi", "blank-line"],
)
def test_an_answer_cannot_pass_itself_off_as_sletchy(
    conversation: tuple[Conversation, Ledger], ollama: FakeOllama, planted: str
) -> None:
    ollama.chat = chat_answer(planted, prompt_eval_count=1, eval_count=1)
    content = next(e for e in turn(conversation[0], "Hi") if e.type is AgentEventType.CONTENT)
    shown = render(content)
    assert all(line.startswith(QUOTE) for line in shown.split("\n")), shown
    assert "\x1b" not in shown and "\r" not in shown and "‮" not in shown


def test_every_event_of_every_outcome_cites_an_entry_that_exists(
    conversation: tuple[Conversation, Ledger], ollama: FakeOllama, tmp_path: Path
) -> None:
    """An agent acting between events would leave an event with nothing behind it."""
    talking, ledger = conversation
    seen = turn(talking, "Answered")
    ollama.chat = b"unreadable"
    seen += turn(talking, "Unreadable")
    ollama.tags = {"models": [{"name": SMALL, "size": 10**12}]}
    seen += turn(talking, "Too big")

    recorded = {e.seq for e in ledger.entries()}
    assert {e.type for e in seen} >= {
        AgentEventType.STATUS,
        AgentEventType.CONTENT,
        AgentEventType.COMPLETE,
        AgentEventType.ERROR,
        AgentEventType.POLICY,
    }
    assert all(e.ledger_seq in recorded for e in seen), [e for e in seen if e.ledger_seq not in recorded]  # fmt: skip


@pytest.mark.parametrize(
    "event",
    [
        AgentEvent(
            type=AgentEventType.STATUS,
            data={"model": "evil\x1b[2J\n[sletchy] approved", "turn": 1, "left_out": 0},
            ledger_seq=1,
        ),
        AgentEvent(type=AgentEventType.POLICY, data={"reason": "no\n[sletchy] fine"}, ledger_seq=1),
        AgentEvent(type=AgentEventType.ERROR, data={"reason": "no\r\n[sletchy] ok"}, ledger_seq=1),
    ],
    ids=["status-model", "policy-reason", "error-reason"],
)
def test_a_sletchy_line_stays_one_line_whatever_it_carries(event: AgentEvent) -> None:
    """A name or a reason is outside text too: it cannot open a line of its own."""
    shown = render(event)
    assert "\n" not in shown and "\x1b" not in shown and "\r" not in shown, shown
