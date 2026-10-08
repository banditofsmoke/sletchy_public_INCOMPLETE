"""The desktop bridge does what the CLI does, and nothing more.

Every request goes through `handle_line` exactly as bytes from the window would, so
these tests exercise the wire, the dispatch and the handlers together.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from sletchy.cli import paths
from sletchy.cli.bridge import ACTOR, Bridge, handle_line, serve
from sletchy.cli.bridge_contracts import METHODS, PROTOCOL_VERSION
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

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


def call(bridge: Bridge, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    line = json.dumps({"id": 7, "method": method, "params": params or {}}).encode()
    response: dict[str, Any] = json.loads(handle_line(bridge, line))
    assert response["id"] == 7
    return response


def ok(bridge: Bridge, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    response = call(bridge, method, params)
    assert response["ok"], response
    result: dict[str, Any] = response["result"]
    return result


def refused(bridge: Bridge, method: str, params: dict[str, Any] | None = None) -> str:
    response = call(bridge, method, params)
    assert not response["ok"], response
    code: str = response["error"]["code"]
    return code


def test_every_method_has_a_handler_and_nothing_else_does(bridge: Bridge) -> None:
    assert set(bridge.handlers) == set(METHODS)


def test_status(bridge: Bridge) -> None:
    result = ok(bridge, "status")
    assert result["protocol"] == PROTOCOL_VERSION
    assert result["ledger_state"] == "ok"
    assert result["dangerous_on"] == []


def test_status_before_setup_says_so_rather_than_failing(tmp_path: Path) -> None:
    from sletchy.kernel.ledger import KeyringKeySource

    class NoKey(KeyringKeySource):
        def get(self) -> bytes:
            from sletchy.kernel.ledger import SigningKeyMissing

            raise SigningKeyMissing("none")

    assert ok(Bridge(NoKey()), "status")["ledger_state"] == "not_initialised"


def test_flags_list_is_the_whole_registry(bridge: Bridge) -> None:
    flags = ok(bridge, "flags.list")["flags"]
    names = [f["name"] for f in flags]
    assert len(names) == len(set(names)) > 10
    assert all(f["label"] and f["description"] for f in flags)
    assert not any(f["enabled"] for f in flags if f["risk"] == "dangerous")


def test_a_safe_flag_flips_and_is_ledgered_as_the_desktop(bridge: Bridge) -> None:
    view = ok(bridge, "flags.set", {"name": "cli_verbose", "enabled": True})
    assert view["enabled"] is True

    ledger = Ledger.open(paths.ledger_dir(), KEY)
    last = list(ledger.entries())[-1]
    assert last.actor_id == ACTOR
    assert last.action == "kernel.flag.flip"


def test_a_dangerous_flag_needs_a_reason_and_its_name_typed_back(bridge: Bridge) -> None:
    on = {"name": "senses_camera", "enabled": True}
    assert refused(bridge, "flags.set", on) == "confirmation_required"
    assert refused(bridge, "flags.set", {**on, "confirm": "senses_camera"}) == "reason_required"
    assert refused(bridge, "flags.set", {**on, "reason": "x", "confirm": "Camera"}) == (
        "confirmation_required"
    )
    view = ok(bridge, "flags.set", {**on, "reason": "video call", "confirm": "senses_camera"})
    assert view["enabled"] is True


def test_turning_anything_off_is_never_obstructed(bridge: Bridge) -> None:
    ok(
        bridge,
        "flags.set",
        {"name": "senses_camera", "enabled": True, "reason": "r", "confirm": "senses_camera"},
    )
    view = ok(bridge, "flags.set", {"name": "senses_camera", "enabled": False})
    assert view["enabled"] is False


def test_an_unknown_flag_is_named_as_such(bridge: Bridge) -> None:
    assert refused(bridge, "flags.set", {"name": "make_coffee", "enabled": True}) == "unknown_flag"


def test_ledger_tail_verifies_and_reads(bridge: Bridge) -> None:
    ok(bridge, "flags.set", {"name": "cli_verbose", "enabled": True})
    result = ok(bridge, "ledger.tail", {"limit": 5})
    assert result["verified"] >= 1
    assert result["entries"][-1]["actor"] == ACTOR


def test_selfcheck_answers_with_a_score_and_its_limits(bridge: Bridge) -> None:
    result = ok(bridge, "selfcheck")
    assert 0 <= result["score"] <= result["ceiling"] <= 100
    assert result["does_not_prove"]


def test_panic_plan_changes_nothing_and_panic_run_resets(bridge: Bridge) -> None:
    ok(
        bridge,
        "flags.set",
        {"name": "senses_camera", "enabled": True, "reason": "r", "confirm": "senses_camera"},
    )

    plan = ok(bridge, "stop.plan")
    assert plan["dry_run"] is True
    assert FlagStore.open(Ledger.open(paths.ledger_dir(), KEY), paths.flags_file()).is_on(
        "senses_camera"
    )

    run = ok(bridge, "stop.run")
    assert run["dry_run"] is False
    assert run["flags_reset"] == 1
    assert run["clean"] is True
    assert not FlagStore.open(Ledger.open(paths.ledger_dir(), KEY), paths.flags_file()).is_on(
        "senses_camera"
    )


def test_panic_run_takes_no_confirmation(bridge: Bridge) -> None:
    """LAW 0 §2: panic never asks. Not here either."""
    assert refused(bridge, "stop.run", {"confirm": "yes"}) == "invalid_params"
    assert ok(bridge, "stop.run")["dry_run"] is False


def test_init_on_an_in_memory_key_creates_the_home_and_provisions_nothing(tmp_path: Path) -> None:
    result = ok(Bridge(KEY), "init")
    assert result["provisioned"] is False
    assert Path(result["home"]).is_dir()


def test_serve_answers_in_order_and_stops_at_end_of_input(bridge: Bridge) -> None:
    requests = b"".join(
        json.dumps({"id": i, "method": "status", "params": {}}).encode() + b"\n" for i in range(3)
    )
    out = io.BytesIO()
    assert serve(bridge, io.BytesIO(requests + b"\n"), out) == 0
    ids = [json.loads(line)["id"] for line in out.getvalue().splitlines()]
    assert ids == [0, 1, 2]


def test_the_window_in_a_folder_with_no_sletchy_says_so_and_creates_nothing() -> None:
    """Every read the window makes, before setup: an answer, and no `var/` (#102)."""
    window = Bridge(KEY)

    status = ok(window, "status")
    assert status["ledger_state"] == "not_initialised"
    assert "no ledger in" in status["detail"]
    assert refused(window, "flags.list") == "not_initialised"
    assert refused(window, "ledger.tail") == "not_initialised"
    ledger_check = next(c for c in ok(window, "selfcheck")["checks"] if c["id"] == "ledger")
    assert ledger_check["status"] == "fail"
    assert ok(window, "stop.plan")["dry_run"] is True
    assert not paths.home().exists(), "a read from the window created a home"

    assert ok(window, "init")["home"] == str(paths.home())
    assert ok(window, "status")["ledger_state"] == "ok"


def test_set_up_pressed_twice_changes_nothing_and_the_record_verifies() -> None:
    window = Bridge(KEY)
    ok(window, "init")
    ok(window, "flags.set", {"name": "cli_verbose", "enabled": True})
    home = Path(ok(window, "status")["home"])
    before = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}

    second = ok(window, "init")

    assert second["provisioned"] is False
    assert {p: p.read_bytes() for p in home.rglob("*") if p.is_file()} == before
    assert Ledger.open(paths.ledger_dir(), KEY).verify() == 1


def test_stop_everything_still_works_from_the_window_when_the_record_is_damaged() -> None:
    window = Bridge(KEY)
    ok(window, "init")
    ok(window, "flags.set", {"name": "cli_verbose", "enabled": True})
    segment = paths.ledger_dir() / "segment-00000.ndjson"
    segment.write_bytes(segment.read_bytes().replace(b"cli_verbose", b"cli_vxrbose"))
    damaged = segment.read_bytes()
    (paths.runtime_dir() / "sletchy.lock").write_text("", encoding="utf-8")

    assert ok(window, "status")["ledger_state"] == "corrupt"
    result = ok(window, "stop.run")

    assert result["dry_run"] is False
    assert result["runtime_files_cleared"] == 1, "panic stopped at the damaged record"
    assert result["ledger_sealed"] is False, (
        "it cannot have written to a record that does not verify"
    )
    assert segment.read_bytes() == damaged, "panic repaired or rewrote the record"
