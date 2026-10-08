"""A model that cannot talk is never offered for talking to, and a failed load ends on the
record (#204).

Measured on my own record, 2026-10-08: `nomic-embed-text` was picked in the window, its
load was recorded and its failure was not, and it was then asked to judge memory and to
answer, each failing with the server's 400. A fake Ollama says what each model can do, as
`/api/show` does, and refuses a chat to an embedding model as Ollama does; nothing here
starts or reaches a real model server.
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
    LOAD_ACTION,
    LOADED_ACTION,
    EgressDenied,
    LocalModel,
    ModelRefused,
    ModelUnreadable,
    can_talk,
)
from sletchy.warden.egress.local import LOCAL_ACTION, LocalModelDoor
from tests.fake_ollama import FakeOllama, fake_ollama

KEY = InMemoryKeySource(b"k" * 32)
SMALL = "gemma3:1b"
BIG = "qwen3-coder:30b"
EMBED = "nomic-embed-text:latest"


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    for srv in fake_ollama():
        srv.tags["models"].append({"name": EMBED, "size": 274_000_000, "digest": "d1"})
        srv.capabilities = {SMALL: ["completion", "vision"], EMBED: ["embedding"]}
        yield srv


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    opened = Ledger.open(tmp_path / "ledger", KEY)
    yield opened
    opened.close()


@pytest.fixture
def payloads(tmp_path: Path) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads")


def model(ledger: Ledger, payloads: PayloadStore, port: int) -> LocalModel:
    return LocalModel.on_this_machine(
        ledger=ledger, store=payloads, actor_id="test", switched_on=lambda: True, port=port
    )


def chats(ollama: FakeOllama) -> list[Any]:
    return [body for _, p, body in ollama.seen if p == "/api/chat"]


# ── the model ───────────────────────────────────────────────────────────────


def test_what_a_model_can_do_is_read_from_the_server(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    local = model(ledger, payloads, ollama.server_address[1])

    assert local.capabilities(SMALL) == frozenset({"completion", "vision"})
    assert local.capabilities(EMBED) == frozenset({"embedding"})
    assert local.capabilities(BIG) is None  # the server did not say: an older one
    assert [can_talk(local.capabilities(m)) for m in (SMALL, EMBED, BIG)] == [True, False, None]
    assert next(body for _, p, body in ollama.seen if p == "/api/show") == {"model": SMALL}


def test_an_embedding_model_is_never_loaded(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    local = model(ledger, payloads, ollama.server_address[1])

    with pytest.raises(ModelRefused, match="an embedding model"):
        local.load(EMBED)

    refused = list(ledger.entries())[-1]
    assert (refused.action, refused.verdict.decision) == (LOAD_ACTION, Decision.DENY)
    assert "turns text into numbers for memory search" in refused.verdict.reason
    assert chats(ollama) == []


def test_a_failed_load_ends_on_the_record(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    ollama.hide_capabilities = True  # an older server, which cannot say, then refuses
    local = model(ledger, payloads, ollama.server_address[1])

    with pytest.raises(ModelUnreadable, match="does not support chat"):
        local.load(EMBED)

    load = next(e for e in ledger.entries() if e.action == LOAD_ACTION)
    ended = list(ledger.entries())[-1]
    assert (ended.action, ended.verdict.decision) == (LOADED_ACTION, Decision.DENY)
    assert ended.verdict.reason.startswith(f"not loaded, to load {load.seq}: ")
    assert "answered 400" in ended.verdict.reason


def test_the_server_s_own_reason_is_said(
    ollama: FakeOllama, ledger: Ledger, payloads: PayloadStore
) -> None:
    local = model(ledger, payloads, ollama.server_address[1])

    with pytest.raises(ModelUnreadable) as caught:
        local.ask(EMBED, "Hello")

    assert str(caught.value) == f'the model server answered 400: "{EMBED}" does not support chat'


@pytest.mark.adversarial
@pytest.mark.parametrize(("method", "path"), [("GET", "/api/show"), ("POST", "/api/show?v=1")])
def test_the_door_asks_what_a_model_can_do_and_nothing_more(
    ollama: FakeOllama, ledger: Ledger, method: str, path: str
) -> None:
    door = LocalModelDoor(
        ledger=ledger,
        actor_id="test",
        switched_on=lambda: True,
        engine="ollama",
        port=ollama.server_address[1],
    )

    with pytest.raises(EgressDenied, match="not a question this door asks"):
        door.request(method, path, b"{}")

    assert ollama.seen == []
    assert list(ledger.entries())[-1].action == LOCAL_ACTION


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


def test_the_window_lists_an_embedding_model_as_one_that_cannot_talk(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    listed = call(bridge, "models.list")["result"]["models"]

    talks = {m["name"]: m["can_chat"] for m in listed}
    assert talks == {SMALL: True, EMBED: False, BIG: None}


def test_the_window_asks_each_model_once(bridge: Bridge, ollama: FakeOllama) -> None:
    call(bridge, "models.list")
    call(bridge, "models.list")

    shown = [body["model"] for _, p, body in ollama.seen if p == "/api/show"]
    assert sorted(shown) == sorted([SMALL, BIG, EMBED])


def test_a_new_pull_under_the_same_name_is_asked_again(bridge: Bridge, ollama: FakeOllama) -> None:
    call(bridge, "models.list")
    ollama.tags["models"][-1]["digest"] = "d2"
    ollama.capabilities[EMBED] = ["completion"]

    listed = call(bridge, "models.list")["result"]["models"]

    assert next(m for m in listed if m["name"] == EMBED)["can_chat"] is True


def test_the_window_says_why_an_embedding_model_is_not_loaded(
    bridge: Bridge, ollama: FakeOllama
) -> None:
    ticket = call(bridge, "model.load", {"model": EMBED})["result"]["ticket"]
    deadline = time.monotonic() + 20
    state = call(bridge, "model.answer", {"ticket": ticket})["result"]
    while state["state"] == "thinking" and time.monotonic() < deadline:
        time.sleep(0.02)
        state = call(bridge, "model.answer", {"ticket": ticket})["result"]
    assert state["state"] == "failed"
    assert state["error_code"] == "model_refused"
    assert "an embedding model" in state["error"]


# ── from a terminal ─────────────────────────────────────────────────────────


def test_sletchy_models_says_which_cannot_talk(
    ollama: FakeOllama,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr("sletchy.cli.main.KeyringKeySource", lambda *a, **k: KEY)
    opened = Ledger.open(paths.ledger_dir(), KEY)
    FlagStore.open(opened, paths.flags_file()).set("mind_local_models", True, reason="testing")
    opened.close()

    assert main(["models", "--port", str(ollama.server_address[1])]) == EXIT_OK

    line = next(x for x in capsys.readouterr().out.splitlines() if EMBED in x)
    assert line.endswith("for memory search, not for talking to")
