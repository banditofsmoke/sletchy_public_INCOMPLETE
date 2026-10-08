"""Someone gets a handle on the bridge's stdin. What can they do?

The bridge does not listen, so reaching it at all means owning the window's process -
but the window renders content, and content can be hostile. These tests assume the
worst sender and check that every malformed, oversized, smuggled or escalating
request is refused with a code, never crashes the bridge, and never changes state.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from sletchy.cli import paths
from sletchy.cli.bridge import Bridge, handle_line, serve
from sletchy.cli.bridge_contracts import ERROR_CODES, MAX_LINE_BYTES
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

pytestmark = pytest.mark.adversarial

KEY = InMemoryKeySource(b"k" * 32)


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules", lambda *, dry_run=False: (0, 0, None)
    )


@pytest.fixture
def bridge() -> Bridge:
    Ledger.open(paths.ledger_dir(), KEY).close()
    return Bridge(KEY)


def answer(bridge: Bridge, raw: bytes) -> dict[str, Any]:
    response: dict[str, Any] = json.loads(handle_line(bridge, raw))
    return response


def code(bridge: Bridge, raw: bytes) -> str:
    response = answer(bridge, raw)
    assert response["ok"] is False, response
    assert response["error"]["code"] in ERROR_CODES
    result: str = response["error"]["code"]
    return result


def req(method: str, params: object = None, rid: object = 1) -> bytes:
    return json.dumps({"id": rid, "method": method, "params": params or {}}).encode()


def dangerous_on() -> list[str]:
    store = FlagStore.open(Ledger.open(paths.ledger_dir(), KEY), paths.flags_file())
    return [f.name for f in store.registry.dangerous() if store.is_on(f.name)]


# ── malformed input ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"null",
        b"[]",
        b'"status"',
        b"\xff\xfe\x00garbage",
        b"{" * 100_000,  # recursion bomb
        b'{"id": 1}',
        b'{"method": "status"}',
        b'{"id": -1, "method": "status", "params": {}}',
        b'{"id": 99999999999, "method": "status", "params": {}}',
        b'{"id": true, "method": "status", "params": {}}',
        b'{"id": "1", "method": "status", "params": {}}',
        b'{"id": 1, "method": "status", "params": []}',
        b'{"id": 1, "method": "status", "params": {}, "admin": true}',
        b'{"id": 1, "method": "' + b"a" * 65 + b'", "params": {}}',
    ],
    # Short ids: Windows caps an environment variable (PYTEST_CURRENT_TEST) at 32767
    # characters, and the recursion bomb alone is 100000.
    ids=lambda raw: f"{raw[:12]!r}..{len(raw)}b",
)
def test_malformed_requests_are_refused_not_crashed(bridge: Bridge, raw: bytes) -> None:
    assert code(bridge, raw) == "bad_request"


@pytest.mark.parametrize(
    "method",
    [
        "evil.exec",
        "__init__",
        "handlers",
        "_ledger",
        "flags.set ",
        "Flags.Set",
        "flags.set\n",
        "status;stop.run",
        "../status",
        "flags.reset_all",
        "ledger.append",
        "ledger.repair",
        "panic.plan",  # the old names: renamed, never kept beside the new ones
        "panic.run",
    ],
)
def test_only_allowlisted_methods_exist(bridge: Bridge, method: str) -> None:
    assert code(bridge, req(method)) == "method_not_allowed"


# ── parameter smuggling ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "params",
    [
        {"name": "senses_camera", "enabled": "true", "reason": "r", "confirm": "senses_camera"},
        {"name": "senses_camera", "enabled": 1, "reason": "r", "confirm": "senses_camera"},
        {
            "name": "senses_camera",
            "enabled": True,
            "reason": "r",
            "confirm": "senses_camera",
            "actor_id": "operator",
        },
        {"name": "Senses_Camera", "enabled": True, "reason": "r", "confirm": "Senses_Camera"},
        {"name": "senses_camera; rm", "enabled": True},
        {"name": "x" * 100, "enabled": True},
        {"name": "senses_camera", "enabled": True, "reason": "r" * 513, "confirm": "senses_camera"},
    ],
)
def test_smuggled_or_coerced_flag_params_are_refused(bridge: Bridge, params: object) -> None:
    assert code(bridge, req("flags.set", params)) == "invalid_params"
    assert dangerous_on() == []


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 100_000}, {"limit": "5"}, {"action_prefix": "../../etc"}, {"x": 1}],
)
def test_ledger_tail_params_are_bounded(bridge: Bridge, params: object) -> None:
    assert code(bridge, req("ledger.tail", params)) == "invalid_params"


@pytest.mark.parametrize("method", ["status", "selfcheck", "flags.list", "stop.plan", "init"])
def test_a_no_params_method_takes_nothing(bridge: Bridge, method: str) -> None:
    assert code(bridge, req(method, {"anything": 1})) == "invalid_params"


# ── escalation ───────────────────────────────────────────────────────────────


def test_no_route_turns_a_dangerous_flag_on_without_both_proofs(bridge: Bridge) -> None:
    attempts = [
        {"name": "egress_enabled", "enabled": True},
        {"name": "egress_enabled", "enabled": True, "reason": "please"},
        {"name": "egress_enabled", "enabled": True, "confirm": "egress_enabled"},
        {"name": "egress_enabled", "enabled": True, "reason": "   ", "confirm": "egress_enabled"},
        {"name": "egress_enabled", "enabled": True, "reason": "r", "confirm": "EGRESS_ENABLED"},
        {"name": "egress_enabled", "enabled": True, "reason": "r", "confirm": " egress_enabled"},
        {"name": "egress_enabled", "enabled": True, "reason": "r", "confirm": "Internet access"},
    ]
    for params in attempts:
        answer(bridge, req("flags.set", params))
    assert dangerous_on() == [], "a dangerous flag was enabled without reason and confirmation"


def test_a_refused_flip_leaves_no_ledger_entry(bridge: Bridge) -> None:
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    before = ledger.verify()
    answer(bridge, req("flags.set", {"name": "egress_enabled", "enabled": True}))
    assert Ledger.open(paths.ledger_dir(), KEY).verify() == before


def test_the_id_of_a_failed_request_is_echoed_only_when_it_is_valid(bridge: Bridge) -> None:
    assert answer(bridge, b'{"id": 5, "method": 3}')["id"] == 5
    assert answer(bridge, b'{"id": true, "method": 3}')["id"] is None


# ── the stream ───────────────────────────────────────────────────────────────


def test_an_oversized_line_is_refused_and_the_stream_recovers(bridge: Bridge) -> None:
    huge = (
        b'{"id": 1, "method": "status", "params": {"pad": "'
        + b"x" * (MAX_LINE_BYTES * 3)
        + b'"}}\n'
    )
    good = b'{"id": 2, "method": "status", "params": {}}\n'
    out = io.BytesIO()
    serve(bridge, io.BytesIO(huge + good), out)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [line["ok"] for line in lines] == [False, True]
    assert lines[0]["error"]["code"] == "too_large"
    assert lines[1]["id"] == 2


def test_responses_are_one_ascii_line_each_whatever_the_input(bridge: Bridge) -> None:
    """A newline or non-ASCII byte in a response would split or corrupt the stream."""
    nasty = req("flags.set", {"name": "‮not_a_flag\n", "enabled": True})
    raw = handle_line(bridge, nasty)
    assert b"\n" not in raw
    raw.decode("ascii")


def test_a_crashing_handler_is_an_answer_not_a_dead_bridge(
    bridge: Bridge, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_: object) -> None:
        raise RuntimeError("handler exploded")

    monkeypatch.setitem(bridge.handlers, "status", boom)
    response = answer(bridge, req("status"))
    assert response["error"]["code"] == "internal_error"
    assert answer(bridge, req("flags.list"))["ok"] is True


def test_stray_prints_cannot_reach_the_protocol_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """`run()` points sys.stdout at stderr before serving."""
    import sys

    from sletchy.cli import bridge as bridge_mod

    seen: dict[str, object] = {}

    def fake_serve(_b: object, _i: object, out: object) -> int:
        seen["stdout_is_stderr"] = sys.stdout is sys.stderr
        seen["out"] = out
        return 0

    monkeypatch.setattr(bridge_mod, "serve", fake_serve)
    monkeypatch.setattr(bridge_mod, "Bridge", lambda: object())
    assert bridge_mod.run() == 0
    assert seen["stdout_is_stderr"] is True
