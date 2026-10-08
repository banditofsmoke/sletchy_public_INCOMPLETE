"""The harness (ADR-0018): one stream per turn, every event cited and recorded first.

A fake Ollama runs on loopback and records what it is sent; nothing here starts or
reaches a real model server.
"""

from __future__ import annotations

import asyncio
import io
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import EXIT_FAILED, EXIT_OK, main
from sletchy.kernel.contracts import AgentEvent, AgentEventType, Decision, LedgerEntry
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.harness import ERROR_ACTION, Conversation
from sletchy.mind.harness.hosts.cli import QUOTE, SAYS, render
from sletchy.mind.local import ASK_ACTION, LocalModel
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

SMALL = "gemma3:1b"
BIG = "qwen3-coder:30b"
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
def store(tmp_path: Path) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads")


def talk(
    ledger: Ledger,
    store: PayloadStore,
    port: int,
    *,
    on: bool = True,
    name: str = SMALL,
    context_tokens: int = 4096,
) -> Conversation:
    model = LocalModel.on_this_machine(
        ledger=ledger, store=store, actor_id="test", switched_on=lambda: on, port=port
    )
    return Conversation(model, name, ledger=ledger, actor_id="test", context_tokens=context_tokens)


def events(conversation: Conversation, question: str) -> list[AgentEvent]:
    seen: list[AgentEvent] = []
    conversation.play(question, seen.append)
    return seen


def chats(ollama: FakeOllama) -> list[list[dict[str, str]]]:
    """The messages of every question the server was sent."""
    return [body["messages"] for _, path, body in ollama.seen if path == "/api/chat"]


def cited(ledger: Ledger, event: AgentEvent) -> LedgerEntry:
    """The record entry an event cites. Entry 0 is the first of a fresh record."""
    assert event.ledger_seq is not None, event
    return next(e for e in ledger.entries() if e.seq == event.ledger_seq)


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


# ── one turn ─────────────────────────────────────────────────────────────────


def test_a_turn_is_asked_then_answered_then_complete_each_citing_its_entry(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    seen = events(talk(ledger, store, ollama.server_address[1]), "Say hello.")

    assert [e.type for e in seen] == [T.STATUS, T.CONTENT, T.COMPLETE]
    assert cited(ledger, seen[0]).action == ASK_ACTION
    assert cited(ledger, seen[1]).action == "mind.model.answer"
    assert seen[1].data["text"] == "Hello."
    assert seen[2].ledger_seq == seen[1].ledger_seq
    assert seen[2].data["outcome"] == "answered"
    assert (seen[2].data["prompt_tokens"], seen[2].data["answer_tokens"]) == (12, 3)
    assert seen[2].data["asked_seq"] == seen[0].ledger_seq


def test_every_event_is_on_the_record_before_a_host_sees_it(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    """LAW 1: the host checks the record at the moment each event reaches it."""
    found: list[bool] = []

    def host(event: AgentEvent) -> None:
        found.append(any(e.seq == event.ledger_seq for e in ledger.entries()))

    talk(ledger, store, ollama.server_address[1]).play("Hi", host)
    assert found == [True, True, True]


def test_the_stream_is_the_source_and_play_only_consumes_it(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    """LAW 5: the non-streaming call wraps the stream, never the reverse."""
    port = ollama.server_address[1]

    async def drain() -> list[AgentEvent]:
        return [e async for e in talk(ledger, store, port).turn("Hi")]

    streamed = asyncio.run(drain())
    played = events(talk(ledger, store, port), "Hi")
    assert [e.type for e in streamed] == [e.type for e in played]


def test_the_answer_is_carried_as_the_model_wrote_it(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    """Untrusted, and unchanged: making it safe to show is a host's job."""
    ollama.chat = chat_answer("a\x1b[2Jb", prompt_eval_count=1, eval_count=1)
    seen = events(talk(ledger, store, ollama.server_address[1]), "Hi")
    assert seen[1].data["text"] == "a\x1b[2Jb"


# ── a conversation ───────────────────────────────────────────────────────────


def test_earlier_turns_are_sent_with_each_question(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    conversation = talk(ledger, store, ollama.server_address[1])
    events(conversation, "My name is Ada.")
    ollama.chat = chat_answer("Your name is Ada.", prompt_eval_count=30, eval_count=5)
    second = events(conversation, "What is my name?")

    assert chats(ollama)[1] == [
        {"role": "user", "content": "My name is Ada."},
        {"role": "assistant", "content": "Hello."},
        {"role": "user", "content": "What is my name?"},
    ]
    assert second[0].data == {
        "state": "asked",
        "model": SMALL,
        "turn": 2,
        "earlier_turns": 1,
        "left_out": 0,
    }
    assert conversation.turns == 2


def test_the_oldest_turns_are_left_out_when_room_runs_short(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    """40 tokens: 90 characters for the conversation, a quarter kept for the answer."""
    conversation = talk(ledger, store, ollama.server_address[1], context_tokens=40)
    ollama.chat = chat_answer("x" * 30)
    for question in ("first " * 5, "second " * 4, "third"):
        last = events(conversation, question)

    assert chats(ollama)[2] == [
        {"role": "user", "content": "second " * 4},
        {"role": "assistant", "content": "x" * 30},
        {"role": "user", "content": "third"},
    ]
    assert (last[0].data["earlier_turns"], last[0].data["left_out"]) == (1, 1)
    asked = [e for e in ledger.entries() if e.action == ASK_ACTION][-1]
    assert "turn 3 of conversation " + conversation.id in asked.verdict.reason
    assert "1 earlier turns sent, 1 left out to leave room for the answer" in (asked.verdict.reason)


def test_each_question_names_its_turn_and_its_conversation(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    conversation = talk(ledger, store, ollama.server_address[1])
    events(conversation, "One")
    events(conversation, "Two")
    reasons = [e.verdict.reason for e in ledger.entries() if e.action == ASK_ACTION]
    assert [f"turn {n} of conversation {conversation.id}" in r for n, r in [(1, reasons[0]), (2, reasons[1])]] == [True, True]  # fmt: skip
    assert conversation.id != talk(ledger, store, ollama.server_address[1]).id


# ── refused, or not answered ─────────────────────────────────────────────────


def test_switched_off_the_refusal_is_inline_with_its_entry_and_nothing_is_sent(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    seen = events(talk(ledger, store, ollama.server_address[1], on=False), "Hi")

    assert [e.type for e in seen] == [T.POLICY, T.COMPLETE]
    denied = cited(ledger, seen[0])
    assert (denied.action, denied.verdict.decision) == ("warden.egress.local", Decision.DENY)
    assert seen[0].data["switched_off"] is True
    assert seen[1].data == {"outcome": "refused"}
    assert ollama.seen == []


def test_a_model_over_the_budget_is_refused_inline(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    seen = events(talk(ledger, store, ollama.server_address[1], name=BIG), "Hi")
    assert seen[0].type is T.POLICY
    assert "70% of the card" in str(seen[0].data["reason"])
    assert chats(ollama) == []


def test_a_refused_turn_is_not_remembered(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    state = {"on": False}
    model = LocalModel.on_this_machine(
        ledger=ledger,
        store=store,
        actor_id="test",
        switched_on=lambda: state["on"],
        port=ollama.server_address[1],
    )
    conversation = Conversation(model, SMALL, ledger=ledger, actor_id="test")
    events(conversation, "Refused")
    state["on"] = True
    events(conversation, "Asked")
    assert chats(ollama) == [[{"role": "user", "content": "Asked"}]]
    assert conversation.turns == 1


def test_no_model_server_is_an_error_on_the_record(ledger: Ledger, store: PayloadStore) -> None:
    seen = events(talk(ledger, store, closed_port()), "Hi")

    assert [e.type for e in seen] == [T.ERROR]
    entry = cited(ledger, seen[0])
    assert (entry.action, entry.verdict.decision) == (ERROR_ACTION, Decision.DENY)
    assert seen[0].data["kind"] == "no_model_server"
    assert "never starts one" in str(seen[0].data["reason"])


def test_an_unreadable_answer_is_an_error_on_the_record(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    ollama.chat = b"not an answer"
    seen = events(talk(ledger, store, ollama.server_address[1]), "Hi")

    assert [e.type for e in seen] == [T.STATUS, T.ERROR]
    assert seen[1].data["kind"] == "model_unreadable"
    assert cited(ledger, seen[1]).action == ERROR_ACTION


# ── the terminal host ────────────────────────────────────────────────────────


def test_the_terminal_shows_the_answer_quoted_and_the_meter(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    ollama.chat = chat_answer("Line one.\nLine two.", prompt_eval_count=9, eval_count=4)
    shown = [render(e) for e in events(talk(ledger, store, ollama.server_address[1]), "Hi")]

    assert shown[0].startswith(f"{SAYS} asking {SMALL} (turn 1, record entry ")
    assert shown[1] == f"{QUOTE}Line one.\n{QUOTE}Line two."
    assert "context 13 of 4096 tokens; on the record as entries" in shown[2]


def test_a_refusal_appears_inline_in_the_terminal_with_its_entry(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    seen = events(talk(ledger, store, ollama.server_address[1], on=False), "Hi")
    shown = render(seen[0])
    assert shown.startswith(f"{SAYS} refused, record entry {seen[0].ledger_seq}: ")
    assert "sletchy flags set mind_local_models on" in shown
    assert render(seen[1]) == ""


def test_the_terminal_host_holds_no_state_and_does_no_io(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LAW 5: a host translates. It opens nothing, connects nowhere, starts nothing."""
    from sletchy.mind.harness.hosts import cli as host

    seen = events(talk(ledger, store, ollama.server_address[1]), "Hi")

    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("the host tried to do something beyond translating")

    for target in ("builtins.open", "socket.socket", "subprocess.Popen", "os.system"):
        monkeypatch.setattr(target, refuse)
    first = [render(e) for e in seen]
    assert [render(e) for e in seen] == first, "the same events rendered differently"
    held = {k: v for k, v in vars(host).items() if not k.startswith("__")}
    assert all(isinstance(v, str) or callable(v) or k == "annotations" for k, v in held.items())


# ── `sletchy chat` ───────────────────────────────────────────────────────────


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


def test_chat_holds_a_conversation_from_a_terminal(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home.set("mind_local_models", True, reason="testing")
    monkeypatch.setattr("sys.stdin", io.StringIO("My name is Ada.\nWhat is my name?\n\n"))
    port = str(ollama.server_address[1])

    assert main(["chat", "--port", port, SMALL]) == EXIT_OK
    out = capsys.readouterr()
    assert out.out.count(f"{QUOTE}Hello.") == 2
    assert f"{SAYS} asking {SMALL} (turn 2, record entry" in out.out
    assert "2 answered; conversation c-" in out.err
    assert len(chats(ollama)[1]) == 3


def test_chat_switched_off_says_so_inline_and_fails(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("Hi\n"))
    port = str(ollama.server_address[1])

    assert main(["chat", "--port", port, SMALL]) == EXIT_FAILED
    out = capsys.readouterr().out
    assert f"{SAYS} refused, record entry" in out
    assert "sletchy flags set mind_local_models on" in out
    assert ollama.seen == []
