"""The window asks a model through the same door, budget and record as `sletchy ask`.

ADR-0017, from the desktop: `models.list`, `model.ask` and `model.answer`. A question
runs on a worker thread and `model.ask` answers at once with a ticket, so a model that
thinks for minutes never holds up the window's other requests, Stop everything
included.

A fake Ollama runs on loopback and records what it is sent, and the bridge is pointed
at it; nothing here starts or reaches a real model server, and no test leaves the
bridge on Ollama's own port, where the operator's real server may be listening.
"""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sletchy.cli import paths
from sletchy.cli.bridge import KEEP_QUESTIONS, MAX_ANSWER_CHARS, Bridge, handle_line
from sletchy.kernel.contracts import Decision
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.mind.local import ANSWER_ACTION, ASK_ACTION, CARD_BYTES, MAX_MODEL_BYTES
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

KEY = InMemoryKeySource(b"k" * 32)
SMALL = "gemma3:1b"
HI = {"model": SMALL, "question": "Hi"}


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules", lambda *, dry_run=False: (0, 0, None)
    )


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    yield from fake_ollama()


@pytest.fixture
def bridge(ollama: FakeOllama) -> Bridge:
    Ledger.open(paths.ledger_dir(), KEY).close()
    return Bridge(KEY, model_port=ollama.server_address[1])


def call(bridge: Bridge, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    line = json.dumps({"id": 3, "method": method, "params": params or {}}).encode()
    response: dict[str, Any] = json.loads(handle_line(bridge, line))
    return response


def switch_on(bridge: Bridge) -> None:
    flip = {"name": "mind_local_models", "enabled": True, "reason": "a question"}
    assert call(bridge, "flags.set", flip)["ok"]


def ask(bridge: Bridge, params: dict[str, Any]) -> dict[str, Any]:
    """Ask, then check back until the question is done, as the window does."""
    ticket = call(bridge, "model.ask", params)["result"]["ticket"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state: dict[str, Any] = call(bridge, "model.answer", {"ticket": ticket})["result"]
        if state["state"] != "thinking":
            return state
        time.sleep(0.02)
    raise AssertionError("the question never finished")


def record(action_prefix: str) -> list[tuple[str, Decision, str]]:
    ledger = Ledger.open(paths.ledger_dir(), KEY, create=False)
    try:
        return [
            (e.action, e.verdict.decision, e.actor_id)
            for e in ledger.entries()
            if e.action.startswith(action_prefix)
        ]
    finally:
        ledger.close()


def test_switched_off_the_window_is_refused_and_nothing_is_sent(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    assert call(bridge, "models.list")["error"]["code"] == "switched_off"
    state = ask(bridge, HI)
    assert (state["state"], state["error_code"]) == ("failed", "switched_off")
    assert ollama.seen == []
    assert [d for _, d, _ in record("warden.egress.local")] == [Decision.DENY, Decision.DENY]


def test_the_window_asks_through_the_door_and_both_texts_are_on_the_record(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    switch_on(bridge)
    state = ask(bridge, {"model": SMALL, "question": "Say hello."})
    answer = state["answer"]

    assert state["state"] == "answered"
    assert answer["text"] == "Hello."
    assert answer["cut"] is False
    assert (answer["prompt_tokens"], answer["answer_tokens"]) == (12, 3)
    assert answer["out_of_room"] is False
    assert record("mind.model") == [
        (ASK_ACTION, Decision.ALLOW, "operator-desktop"),
        (ANSWER_ACTION, Decision.ALLOW, "operator-desktop"),
    ]
    assert answer["answered_seq"] == answer["asked_seq"] + 2  # the door's own entry between


def test_stop_everything_answers_while_a_model_is_still_thinking(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    """The emergency control never waits on a model (the reason questions have tickets)."""
    switch_on(bridge)
    ollama.release.clear()
    ticket = call(bridge, "model.ask", HI)["result"]["ticket"]
    while not [p for _, p, _ in ollama.seen if p == "/api/chat"]:
        time.sleep(0.01)  # the question has reached the model, which is now thinking

    started = time.monotonic()
    stopped = call(bridge, "stop.run")["result"]
    assert time.monotonic() - started < 5
    assert stopped["flags_reset"] == 1
    assert call(bridge, "model.answer", {"ticket": ticket})["result"]["state"] == "thinking"

    ollama.release.set()
    deadline = time.monotonic() + 20
    while call(bridge, "model.answer", {"ticket": ticket})["result"]["state"] == "thinking":
        assert time.monotonic() < deadline
        time.sleep(0.02)
    # The question was already sent; its answer arrives and is recorded like any other.
    assert [a for a, _, _ in record("mind.model")] == [ASK_ACTION, ANSWER_ACTION]


def test_one_question_at_a_time(bridge: Bridge, ollama: FakeOllama) -> None:
    switch_on(bridge)
    ollama.release.clear()
    first = call(bridge, "model.ask", HI)["result"]["ticket"]
    assert call(bridge, "model.ask", HI)["error"]["code"] == "model_busy"
    ollama.release.set()
    while call(bridge, "model.answer", {"ticket": first})["result"]["state"] == "thinking":
        time.sleep(0.02)
    assert ask(bridge, HI)["state"] == "answered"


def test_an_unknown_or_forgotten_ticket_is_refused(bridge: Bridge) -> None:
    assert call(bridge, "model.answer", {"ticket": 99})["error"]["code"] == "no_such_question"
    tickets = [ask(bridge, HI)["ticket"] for _ in range(KEEP_QUESTIONS + 1)]
    assert call(bridge, "model.answer", {"ticket": tickets[0]})["error"]["code"] == (
        "no_such_question"
    )
    assert call(bridge, "model.answer", {"ticket": tickets[-1]})["ok"]


def test_the_model_list_marks_what_fits_the_card_budget(bridge: Bridge, ollama: FakeOllama) -> None:
    """The operator's models (2026-10-06): at 70%, ornith:9b fits and gemma4:12b does not."""
    ollama.tags = {
        "models": [
            {"name": "gemma4:12b", "size": 7_600_000_000},
            {"name": "ornith:9b", "size": 5_600_000_000},
            {"name": SMALL, "size": 815_000_000},
        ]
    }
    switch_on(bridge)
    listed = call(bridge, "models.list")["result"]

    assert [(m["name"], m["fits"]) for m in listed["models"]] == [
        (SMALL, True),
        ("ornith:9b", True),
        ("gemma4:12b", False),
    ]
    assert (listed["card_bytes"], listed["budget_bytes"]) == (CARD_BYTES, MAX_MODEL_BYTES)
    assert listed["share"] == 0.7


def test_a_model_over_the_budget_is_refused_with_its_reason_and_never_asked(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    ollama.tags = {"models": [{"name": "gemma4:12b", "size": 7_600_000_000}]}
    switch_on(bridge)
    state = ask(bridge, {"model": "gemma4:12b", "question": "Hi"})

    assert (state["state"], state["error_code"]) == ("failed", "model_refused")
    assert "70% of the card" in state["error"]
    assert [path for _, path, _ in ollama.seen] == ["/api/tags"]


def test_the_answer_reaches_the_window_inert(bridge: Bridge, ollama: FakeOllama) -> None:
    ollama.chat = chat_answer("\x1b[2Jcleared‮hidden\nnext\tline")
    switch_on(bridge)
    text = ask(bridge, HI)["answer"]["text"]
    assert text == "?[2Jcleared?hidden\nnext\tline"


def test_a_long_answer_is_cut_for_the_window_and_says_so(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    ollama.chat = chat_answer("a" * (MAX_ANSWER_CHARS + 1))
    switch_on(bridge)
    answer = ask(bridge, HI)["answer"]
    assert answer["cut"] is True
    assert len(answer["text"]) == MAX_ANSWER_CHARS


def test_no_model_server_is_a_sentence_not_a_crash() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
    Ledger.open(paths.ledger_dir(), KEY).close()
    bridge = Bridge(KEY, model_port=closed)
    switch_on(bridge)
    error = call(bridge, "models.list")["error"]
    assert error["code"] == "no_model_server"
    assert "never starts one" in error["message"]
    state = ask(bridge, HI)
    assert (state["state"], state["error_code"]) == ("failed", "no_model_server")


@pytest.mark.parametrize(
    "params",
    [
        {"model": SMALL},
        {"question": "Hi"},
        {"model": SMALL, "question": ""},
        {"model": SMALL, "question": "Hi", "port": 80},
        {"model": "x" * 201, "question": "Hi"},
    ],
    ids=["no-question", "no-model", "empty", "a-port-smuggled", "long-name"],
)
def test_a_malformed_question_is_refused_before_anything_is_sent(
    bridge: Bridge, ollama: FakeOllama, params: dict[str, Any]
) -> None:
    switch_on(bridge)
    assert call(bridge, "model.ask", params)["error"]["code"] == "invalid_params"
    assert ollama.seen == []


def chats(ollama: FakeOllama) -> list[list[dict[str, str]]]:
    return [body["messages"] for _, path, body in ollama.seen if path == "/api/chat"]


def test_the_window_holds_a_conversation(bridge: Bridge, ollama: FakeOllama) -> None:
    """ADR-0018: each question goes with the conversation so far, one turn at a time."""
    switch_on(bridge)
    first = ask(bridge, {"model": SMALL, "question": "My name is Ada."})["answer"]
    second = ask(bridge, {"model": SMALL, "question": "What is my name?"})["answer"]

    assert (first["turn"], second["turn"]) == (1, 2)
    assert first["conversation"] == second["conversation"]
    assert (second["earlier_turns"], second["left_out"]) == (1, 0)
    assert chats(ollama)[1] == [
        {"role": "user", "content": "My name is Ada."},
        {"role": "assistant", "content": "Hello."},
        {"role": "user", "content": "What is my name?"},
    ]


def test_a_fresh_question_or_another_model_starts_a_new_conversation(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    ollama.tags = {
        "models": [
            {"name": SMALL, "size": 815_000_000},
            {"name": "phi3:latest", "size": 2_200_000_000},
        ]
    }
    switch_on(bridge)
    first = ask(bridge, HI)["answer"]
    fresh = ask(bridge, {**HI, "fresh": True})["answer"]
    other = ask(bridge, {"model": "phi3:latest", "question": "Hi"})["answer"]

    assert [a["turn"] for a in (first, fresh, other)] == [1, 1, 1]
    assert len({a["conversation"] for a in (first, fresh, other)}) == 3
    assert [len(messages) for messages in chats(ollama)] == [1, 1, 1]


def test_a_refused_question_keeps_the_conversation_it_was_asked_in(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    switch_on(bridge)
    first = ask(bridge, HI)["answer"]
    ollama.tags = {"models": [{"name": SMALL, "size": 10**12}]}
    refused = ask(bridge, {"model": SMALL, "question": "Again"})
    ollama.tags = {"models": [{"name": SMALL, "size": 815_000_000}]}
    third = ask(bridge, {"model": SMALL, "question": "And again"})["answer"]

    assert refused["error_code"] == "model_refused"
    assert (third["turn"], third["conversation"]) == (2, first["conversation"])
