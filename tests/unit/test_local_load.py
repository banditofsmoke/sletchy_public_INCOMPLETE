"""Loading a model is its own step, measured; the context is chosen (#202).

A fake Ollama loads, unloads and lists what it holds, as Ollama does; nothing here starts
or reaches a real model server, and the bridge is never left on Ollama's own port.
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
from sletchy.cli.main import EXIT_OK, main
from sletchy.kernel.contracts import Decision
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.mind.local import (
    KEEP_ALIVE,
    LOAD_ACTION,
    LOADED_ACTION,
    MAX_SPILL_BYTES,
    UNLOAD_ACTION,
    EgressDenied,
    LocalModel,
    ModelRefused,
)
from sletchy.warden.egress.local import LOCAL_ACTION, LocalModelDoor
from tests.fake_ollama import FakeOllama, fake_ollama

KEY = InMemoryKeySource(b"k" * 32)
SMALL = "gemma3:1b"
BIG = "qwen3-coder:30b"


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    yield from fake_ollama()


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    opened = Ledger.open(tmp_path / "ledger", KEY)
    yield opened
    opened.close()


@pytest.fixture
def payloads(tmp_path: Path) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads")


def model(
    ledger: Ledger, payloads: PayloadStore, port: int, *, context: int = 16384, on: bool = True
) -> LocalModel:
    return LocalModel.on_this_machine(
        ledger=ledger,
        store=payloads,
        actor_id="test",
        switched_on=lambda: on,
        port=port,
        context_tokens=context,
    )


def sent(ollama: FakeOllama, path: str) -> list[Any]:
    return [body for _, p, body in ollama.seen if p == path]


# ── the model ───────────────────────────────────────────────────────────────


def test_load_is_recorded_then_measured_from_the_server(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    loaded = model(ledger, payloads, ollama.server_address[1]).load(SMALL)

    assert sent(ollama, "/api/chat") == [
        {"model": SMALL, "messages": [], "keep_alive": KEEP_ALIVE, "options": {"num_ctx": 16384}}
    ]
    assert (loaded.running.name, loaded.running.context_tokens) == (SMALL, 16384)
    assert loaded.running.vram_bytes == loaded.running.size_bytes
    assert loaded.load_seconds == 1.5
    trail = [(e.action, e.subject.identifier) for e in ledger.entries()]
    load_at = trail.index((LOAD_ACTION, SMALL))
    door_at = next(
        i for i, (a, s) in enumerate(trail) if a == LOCAL_ACTION and s.endswith("/api/chat")
    )
    assert load_at < door_at < trail.index((LOADED_ACTION, SMALL))


def test_a_spill_within_the_bound_is_loaded_and_said(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    ollama.spill = 200_000_000

    loaded = model(ledger, payloads, ollama.server_address[1]).load(SMALL)

    assert loaded.running.spill_bytes == 200_000_000
    entry = next(e for e in ledger.entries() if e.action == LOADED_ACTION)
    assert "75% on the card" in entry.verdict.reason


def test_a_load_that_spills_past_the_bound_is_unloaded_and_refused(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    """The weights fit the budget; the context does not, and runs past the bound."""
    ollama.tags = {"models": [{"name": SMALL, "size": 5 * 1024**3}]}
    ollama.spill = MAX_SPILL_BYTES + 1

    with pytest.raises(ModelRefused, match="past the card"):
        model(ledger, payloads, ollama.server_address[1], context=32768).load(SMALL)

    assert ollama.ps == []
    assert sent(ollama, "/api/chat")[-1]["keep_alive"] == 0
    entries = list(ledger.entries())
    assert (entries[-1].action, entries[-1].verdict.decision) == (LOAD_ACTION, Decision.DENY)
    assert UNLOAD_ACTION in [e.action for e in entries[:-1]]
    assert LOADED_ACTION not in [e.action for e in entries]


def test_a_model_over_the_budget_is_never_loaded(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    with pytest.raises(ModelRefused, match="at most"):
        model(ledger, payloads, ollama.server_address[1]).load(BIG)

    assert sent(ollama, "/api/chat") == []


def test_load_switched_off_sends_nothing(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    with pytest.raises(EgressDenied, match="switched off"):
        model(ledger, payloads, ollama.server_address[1], on=False).load(SMALL)

    assert ollama.seen == []


def test_unload_takes_the_model_off_the_card(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    local = model(ledger, payloads, ollama.server_address[1])
    local.load(SMALL)

    seq = local.unload(SMALL)

    assert local.running() == []
    assert sent(ollama, "/api/chat")[-1] == {"model": SMALL, "messages": [], "keep_alive": 0}
    assert next(e for e in ledger.entries() if e.seq == seq).action == UNLOAD_ACTION


def test_questions_carry_the_chosen_context_and_keep_alive(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    answer = model(ledger, payloads, ollama.server_address[1], context=8192).ask(SMALL, "Hi")

    body = sent(ollama, "/api/chat")[-1]
    assert (body["options"], body["keep_alive"]) == ({"num_ctx": 8192}, KEEP_ALIVE)
    assert answer.context_tokens == 8192


def test_a_context_not_on_the_list_is_refused(ledger: Ledger, payloads: PayloadStore) -> None:
    with pytest.raises(ValueError, match="not one of"):
        model(ledger, payloads, 1024, context=5000)


@pytest.mark.adversarial
@pytest.mark.parametrize(("method", "path"), [("POST", "/api/ps"), ("GET", "/api/ps?all=1")])
def test_the_door_reads_what_is_loaded_and_nothing_more(
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
        door.request(method, path)

    assert door.request("GET", "/api/ps").status == 200


# ── the window ──────────────────────────────────────────────────────────────


@pytest.fixture
def bridge(ollama: FakeOllama, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bridge:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules", lambda *, dry_run=False: (0, 0, None)
    )
    Ledger.open(paths.ledger_dir(), KEY).close()
    made = Bridge(KEY, model_port=ollama.server_address[1])
    flip = {"name": "mind_local_models", "enabled": True, "reason": "a question"}
    assert call(made, "flags.set", flip)["ok"]
    return made


def call(bridge: Bridge, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    line = json.dumps({"id": 3, "method": method, "params": params or {}}).encode()
    response: dict[str, Any] = json.loads(handle_line(bridge, line))
    return response


def finished(bridge: Bridge, ticket: int) -> dict[str, Any]:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state: dict[str, Any] = call(bridge, "model.answer", {"ticket": ticket})["result"]
        if state["state"] != "thinking":
            return state
        time.sleep(0.02)
    raise AssertionError("the load never finished")


def test_the_window_loads_on_a_ticket_and_lists_what_is_loaded(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    ticket = call(bridge, "model.load", {"model": SMALL, "context": 16384})["result"]["ticket"]
    state = finished(bridge, ticket)

    assert state["state"] == "loaded"
    assert state["loaded"]["running"]["context_tokens"] == 16384
    listed = call(bridge, "models.list")["result"]
    assert listed["context_choices"] == [4096, 8192, 16384, 32768]
    assert [r["model"] for r in listed["running"]] == [SMALL]


def test_the_window_asks_with_the_context_it_loaded(bridge: Bridge, ollama: FakeOllama) -> None:
    ticket = call(bridge, "model.ask", {"model": SMALL, "question": "Hi", "context": 8192})[
        "result"
    ]["ticket"]
    answer = finished(bridge, ticket)["answer"]

    assert answer["context_tokens"] == 8192
    assert sent(ollama, "/api/chat")[-1]["options"] == {"num_ctx": 8192}


def test_another_context_starts_another_conversation(bridge: Bridge, ollama: FakeOllama) -> None:
    first = finished(
        bridge, call(bridge, "model.ask", {"model": SMALL, "question": "Hi"})["result"]["ticket"]
    )["answer"]
    second = finished(
        bridge,
        call(bridge, "model.ask", {"model": SMALL, "question": "Hi", "context": 8192})["result"][
            "ticket"
        ],
    )["answer"]

    assert second["turn"] == 1
    assert second["conversation"] != first["conversation"]


def test_the_window_unloads_at_once(bridge: Bridge, ollama: FakeOllama) -> None:
    finished(bridge, call(bridge, "model.load", {"model": SMALL})["result"]["ticket"])

    result = call(bridge, "model.unload", {"model": SMALL})["result"]

    assert result["model"] == SMALL
    assert call(bridge, "models.list")["result"]["running"] == []


def test_a_context_not_on_the_list_is_refused_by_the_window(bridge: Bridge) -> None:
    refused = call(bridge, "model.load", {"model": SMALL, "context": 5000})

    assert refused["error"]["code"] == "invalid_params"


def test_a_refused_load_says_why_in_the_window(bridge: Bridge, ollama: FakeOllama) -> None:
    state = finished(bridge, call(bridge, "model.load", {"model": BIG})["result"]["ticket"])

    assert (state["state"], state["error_code"]) == ("failed", "model_refused")


# ── from a terminal ─────────────────────────────────────────────────────────


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr("sletchy.cli.main.KeyringKeySource", lambda *a, **k: KEY)
    opened = Ledger.open(paths.ledger_dir(), KEY)
    FlagStore.open(opened, paths.flags_file()).set("mind_local_models", True, reason="testing")
    opened.close()
    yield


def test_load_models_and_unload_from_a_terminal(
    home: None, ollama: FakeOllama, capsys: pytest.CaptureFixture[str]
) -> None:
    port = str(ollama.server_address[1])

    assert main(["load", "--port", port, "--context", "16384", SMALL]) == EXIT_OK
    out = capsys.readouterr()
    assert "loaded: a context of 16384 tokens, 100% on the card" in out.out
    assert main(["models", "--port", port]) == EXIT_OK
    assert "loaded: a context of 16384 tokens" in capsys.readouterr().out
    assert main(["unload", "--port", port, SMALL]) == EXIT_OK
    assert f"Unloaded {SMALL}" in capsys.readouterr().out
    assert ollama.ps == []


def test_a_context_not_on_the_list_is_refused_at_the_terminal(
    home: None, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit):
        main(["load", "--context", "5000", SMALL])
    assert "one of 4096, 8192, 16384, 32768" in capsys.readouterr().err
