"""The window remembers (ADR-0019): with Memory on, the Talk plate recalls what an earlier
conversation was told, as `sletchy chat` does, and says which passages went with it.

A fake Ollama answers the judge and the conversation in turn; nothing here starts or
reaches a real model server, and the bridge is never left on Ollama's own port.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sletchy.cli import paths
from sletchy.cli.bridge import Bridge, handle_line
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

KEY = InMemoryKeySource(b"k" * 32)
SMALL = "gemma3:1b"


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


def switch(bridge: Bridge, name: str) -> None:
    assert call(bridge, "flags.set", {"name": name, "enabled": True, "reason": "testing"})["ok"]


def ask(bridge: Bridge, params: dict[str, Any]) -> dict[str, Any]:
    ticket = call(bridge, "model.ask", params)["result"]["ticket"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state: dict[str, Any] = call(bridge, "model.answer", {"ticket": ticket})["result"]
        if state["state"] != "thinking":
            return state
        time.sleep(0.02)
    raise AssertionError("the question never finished")


def chats(ollama: FakeOllama) -> list[list[dict[str, str]]]:
    return [body["messages"] for _, path, body in ollama.seen if path == "/api/chat"]


def test_with_memory_on_a_new_conversation_remembers_an_old_one(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    switch(bridge, "mind_local_models")
    switch(bridge, "mind_memory")
    ollama.answers = [chat_answer("Hello, Ada.")]
    ask(bridge, {"model": SMALL, "question": "My name is Ada."})

    ollama.answers = [
        chat_answer(json.dumps({"p1": 0.9, "answerable": 0.9})),
        chat_answer("Your name is Ada."),
    ]
    answer = ask(bridge, {"model": SMALL, "question": "What is my name?", "fresh": True})["answer"]

    assert answer["turn"] == 1
    assert answer["recalled"] == 1
    assert isinstance(answer["plan_seq"], int)
    assert "Question: My name is Ada." in chats(ollama)[-1][0]["content"]
    assert answer["text"] == "Your name is Ada."


def test_with_memory_off_the_window_recalls_nothing(bridge: Bridge, ollama: FakeOllama) -> None:
    switch(bridge, "mind_local_models")

    answer = ask(bridge, {"model": SMALL, "question": "Hi"})["answer"]

    assert answer["recalled"] == 0
    assert answer["plan_seq"] is None
    assert not (paths.memory_dir()).exists()


def test_a_model_that_cannot_judge_says_memory_was_not_checked(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    switch(bridge, "mind_local_models")
    switch(bridge, "mind_memory")
    ollama.answers = [chat_answer("Noted: the keys are in the shed.")]
    ask(bridge, {"model": SMALL, "question": "The keys are in the shed."})

    ollama.answers = [chat_answer("p1 looks right to me"), chat_answer("I could not say.")]
    answer = ask(bridge, {"model": SMALL, "question": "Where are the keys?", "fresh": True})[
        "answer"
    ]

    assert answer["recalled"] == 0
    assert answer["memory_unchecked"] is True  # said, where before #205 it was silent
