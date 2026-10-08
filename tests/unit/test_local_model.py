"""Asking a model on this machine (ADR-0017): the record, the card budget, the meter.

A fake Ollama runs on loopback: it lists models and answers questions with whatever
each test gives it, and records what it was sent. Nothing here starts or reaches a real
model server.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import EXIT_FAILED, EXIT_OK, main
from sletchy.kernel.contracts import Decision
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind import local as local_mind
from sletchy.mind.local import (
    CARD_BYTES,
    CONTEXT_TOKENS,
    MAX_MODEL_BYTES,
    LocalModel,
    ModelRefused,
    ModelUnreadable,
    inert,
)
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

SMALL = "gemma3:1b"
BIG = "qwen3-coder:30b"


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    yield from fake_ollama()


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))


@pytest.fixture
def store(tmp_path: Path) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads")


def model(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama, *, on: bool = True
) -> LocalModel:
    return LocalModel.on_this_machine(
        ledger=ledger,
        store=store,
        actor_id="test",
        switched_on=lambda: on,
        port=ollama.server_address[1],
    )


def actions(ledger: Ledger) -> list[tuple[str, Decision]]:
    return [(e.action, e.verdict.decision) for e in ledger.entries()]


# ── the record ───────────────────────────────────────────────────────────────


def test_the_question_is_recorded_before_it_is_asked_and_the_answer_after(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    answer = model(ledger, store, ollama).ask(SMALL, "Say hello.")
    assert answer.text == "Hello."
    assert [a for a, _ in actions(ledger)] == [
        "warden.egress.local",  # the model list, for the budget
        "mind.model.ask",
        "warden.egress.local",  # the question itself
        "mind.model.answer",
    ]
    entries = list(ledger.entries())
    assert store.get(entries[1].payload_hash or "") == b"Say hello."
    assert store.get(entries[3].payload_hash or "") == b"Hello."
    assert (answer.asked_seq, answer.answered_seq) == (entries[1].seq, entries[3].seq)


def test_the_same_context_size_is_sent_with_every_question(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    model(ledger, store, ollama).ask(SMALL, "One.")
    [(_, _, sent)] = [s for s in ollama.seen if s[1] == "/api/chat"]
    assert sent["options"] == {"num_ctx": CONTEXT_TOKENS}
    assert sent["stream"] is False
    assert sent["messages"] == [{"role": "user", "content": "One."}]


# ── the card budget ──────────────────────────────────────────────────────────


def test_a_model_may_take_at_most_seventy_percent_of_the_card() -> None:
    """The operator's choice: the rest of the card is the context's.

    60% on 2026-10-05; 70% on 2026-10-06, so a 9B model (5.6 GB) can be asked.
    """
    assert MAX_MODEL_BYTES == int(CARD_BYTES * 0.7)
    assert CARD_BYTES == 8151 * 1024**2  # measured on the operator's card, ADR-0015


def test_a_model_over_the_budget_is_refused_and_never_asked(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    with pytest.raises(ModelRefused, match="so its context fits"):
        model(ledger, store, ollama).ask(BIG, "Write me a compiler.")
    assert [path for _, path, _ in ollama.seen] == ["/api/tags"]
    assert actions(ledger)[-1] == ("mind.model.ask", Decision.DENY)


def test_a_model_just_over_the_line_is_refused_and_one_on_it_is_asked(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    ollama.tags = {
        "models": [
            {"name": "on:line", "size": MAX_MODEL_BYTES},
            {"name": "over:line", "size": MAX_MODEL_BYTES + 1},
        ]
    }
    asker = model(ledger, store, ollama)
    asker.ask("on:line", "Hi.")
    with pytest.raises(ModelRefused):
        asker.ask("over:line", "Hi.")


def test_a_model_the_server_does_not_have_is_refused(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    with pytest.raises(ModelRefused, match="no model by that name"):
        model(ledger, store, ollama).ask("nothere:1b", "Hi.")


def test_a_model_whose_size_is_not_said_is_refused(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    ollama.tags = {"models": [{"name": SMALL}]}
    with pytest.raises(ModelRefused, match="-1 bytes"):
        model(ledger, store, ollama).ask(SMALL, "Hi.")


# ── the meter ────────────────────────────────────────────────────────────────


def test_the_meter_says_how_much_context_was_used(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    answer = model(ledger, store, ollama).ask(SMALL, "Hi.")
    assert (answer.prompt_tokens, answer.answer_tokens) == (12, 3)
    assert answer.context_tokens == CONTEXT_TOKENS
    assert not answer.out_of_room
    assert f"context 15 of {CONTEXT_TOKENS} tokens" in list(ledger.entries())[-1].verdict.reason


def test_an_answer_cut_short_for_room_says_so(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    ollama.chat = chat_answer("It was the best of", prompt_eval_count=4090, eval_count=6,
                              done_reason="length")  # fmt: skip
    answer = model(ledger, store, ollama).ask(SMALL, "Tell me a long story.")
    assert answer.out_of_room
    assert "out of room" in list(ledger.entries())[-1].verdict.reason


# ── refusals before anything is sent ─────────────────────────────────────────


@pytest.mark.parametrize(
    "name", ["", "../etc/passwd", "a b", "Gemma3:1B", "gemma3:1b\x1b[31m", "x" * 200, ":1b"]
)
def test_a_name_that_is_not_a_model_name_is_refused_unsent(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama, name: str
) -> None:
    with pytest.raises(ModelRefused, match="not a model name"):
        model(ledger, store, ollama).ask(name, "Hi.")
    assert ollama.seen == []
    assert actions(ledger) == [("mind.model.ask", Decision.DENY)]


@pytest.mark.parametrize("question", ["", "   \n", "x" * (local_mind.MAX_PROMPT_CHARS + 1)])
def test_an_empty_or_huge_question_is_refused_unsent(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama, question: str
) -> None:
    with pytest.raises(ModelRefused):
        model(ledger, store, ollama).ask(SMALL, question)
    assert ollama.seen == []


def test_switched_off_nothing_is_sent(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    with pytest.raises(local_mind.EgressDenied, match="switched off"):
        model(ledger, store, ollama, on=False).ask(SMALL, "Hi.")
    assert ollama.seen == []


def test_an_answer_that_is_not_an_answer_is_unreadable_not_shown(
    ledger: Ledger, store: PayloadStore, ollama: FakeOllama
) -> None:
    ollama.chat = b"<html>not json</html>"
    with pytest.raises(ModelUnreadable):
        model(ledger, store, ollama).ask(SMALL, "Hi.")
    ollama.chat = json.dumps({"message": {"content": 42}}).encode()
    with pytest.raises(ModelUnreadable):
        model(ledger, store, ollama).ask(SMALL, "Hi.")


# ── the commands ─────────────────────────────────────────────────────────────


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FlagStore]:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(
        "sletchy.cli.main.KeyringKeySource", lambda *a, **k: InMemoryKeySource(b"k" * 32)
    )
    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    flags = FlagStore.open(ledger, paths.flags_file())
    yield flags
    ledger.close()


def test_ask_says_how_to_switch_it_on_when_it_is_off(
    home: FlagStore, ollama: FakeOllama, capsys: pytest.CaptureFixture[str]
) -> None:
    port = str(ollama.server_address[1])
    assert main(["ask", "--port", port, SMALL, "Hi."]) == EXIT_FAILED
    assert "sletchy flags set mind_local_models on" in capsys.readouterr().err
    assert ollama.seen == []


def test_ask_prints_the_answer_inert_and_the_meter(
    home: FlagStore, ollama: FakeOllama, capsys: pytest.CaptureFixture[str]
) -> None:
    home.set("mind_local_models", True, reason="testing")
    ollama.chat = chat_answer("Hi \x1b[2J\x1b]0;owned\x07 there", prompt_eval_count=9,
                              eval_count=4, done_reason="stop")  # fmt: skip
    port = str(ollama.server_address[1])
    assert main(["ask", "--port", port, SMALL, "Say", "hi."]) == EXIT_OK
    out = capsys.readouterr()
    assert "\x1b" not in out.out and "\x07" not in out.out
    assert "Hi ?[2J?]0;owned? there" in out.out
    assert f"context 13 of {CONTEXT_TOKENS} tokens" in out.err


def test_ask_says_so_when_no_model_server_is_answering(
    home: FlagStore, capsys: pytest.CaptureFixture[str]
) -> None:
    import socket

    home.set("mind_local_models", True, reason="testing")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = str(probe.getsockname()[1])
    assert main(["ask", "--port", free, SMALL, "Hi."]) == EXIT_FAILED
    assert "Sletchy never starts one" in capsys.readouterr().err


def test_models_marks_what_is_too_big_for_a_conversation(
    home: FlagStore, ollama: FakeOllama, capsys: pytest.CaptureFixture[str]
) -> None:
    home.set("mind_local_models", True, reason="testing")
    assert main(["models", "--port", str(ollama.server_address[1])]) == EXIT_OK
    out = capsys.readouterr().out
    assert "70%" in out
    [small] = [line for line in out.splitlines() if SMALL in line]
    [big] = [line for line in out.splitlines() if BIG in line]
    assert "not asked" not in small
    assert "too big to leave room for a conversation" in big


def test_inert_keeps_lines_and_tabs_and_nothing_else_unseen() -> None:
    assert inert("a\nb\tc") == "a\nb\tc"
    assert inert("x\x1b[31my‮z\x00") == "x?[31my?z?"
