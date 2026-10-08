"""Someone turns a dangerous switch on by editing `flags.json`. Does Sletchy believe it?

Measured 2026-10-03 (#100): writing `{"egress_enabled": true}` to `var/flags.json` made
`sletchy status` print `DANGEROUS ON: egress_enabled`, while the ledger held nothing at
all. The file was believed; the record said no one had ever turned it on.

LAW 8 says dangerous flags are off unless something recorded turning them on, and LAW 2
says a tie goes to deny. So a dangerous flag the ledger cannot explain now reads as off,
everywhere, and is named. The file is never rewritten to hide it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sletchy.cli import main as cli_main
from sletchy.cli import paths
from sletchy.cli.bridge import Bridge
from sletchy.cli.main import EXIT_FAILED, main
from sletchy.cli.selfcheck import run_selfcheck
from sletchy.kernel.flags import RESET_ACTION, FlagStore, FlagWriteFailed
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(cli_main, "KeyringKeySource", lambda *a, **k: InMemoryKeySource(KEY))


def ledger() -> Ledger:
    return Ledger.open(paths.ledger_dir(), InMemoryKeySource(KEY))


def store() -> FlagStore:
    return FlagStore.open(ledger(), paths.flags_file())


def hand_edit(**flags: bool) -> None:
    """What anything able to write `var/` can do."""
    path = paths.flags_file()
    current = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({**current, **flags}), encoding="utf-8")


def file_claims() -> dict[str, bool]:
    claims: dict[str, bool] = json.loads(paths.flags_file().read_text(encoding="utf-8"))
    return claims


# ── the edit is not believed ─────────────────────────────────────────────────


def test_a_dangerous_flag_turned_on_by_hand_reads_as_off_and_is_named() -> None:
    ledger().close()
    hand_edit(egress_enabled=True)

    flags = store()

    assert not flags.is_on("egress_enabled")
    assert flags.unexplained == ("egress_enabled",)
    assert not flags.snapshot()["egress_enabled"]


def test_turned_off_on_the_record_then_back_on_by_hand_reads_as_off() -> None:
    flags = store()
    flags.set("senses_camera", True, reason="video call")
    flags.set("senses_camera", False)
    hand_edit(senses_camera=True)

    assert not store().is_on("senses_camera")
    assert store().unexplained == ("senses_camera",)


def test_reset_on_the_record_then_back_on_by_hand_reads_as_off() -> None:
    flags = store()
    flags.set("senses_microphone", True, reason="dictation")
    flags.reset_all(reason="panic")
    hand_edit(senses_microphone=True)

    assert store().unexplained == ("senses_microphone",)


def test_a_flip_on_whose_write_failed_does_not_explain_a_later_hand_edit() -> None:
    """The record says the flip did not take effect (#104), so it explains nothing."""
    flags = store()
    paths.flags_file().mkdir()
    with pytest.raises(FlagWriteFailed):
        flags.set("egress_enabled", True, reason="testing")
    paths.flags_file().rmdir()
    hand_edit(egress_enabled=True)

    assert store().unexplained == ("egress_enabled",)


# ── what the ledger does explain is still believed ───────────────────────────


def test_a_dangerous_flag_turned_on_through_the_record_stays_on() -> None:
    """The control: the reconciliation must not turn off what was recorded."""
    store().set("senses_camera", True, reason="video call")

    flags = store()
    assert flags.is_on("senses_camera")
    assert flags.unexplained == ()


def test_an_off_flip_whose_write_failed_leaves_the_flag_explained_as_on() -> None:
    """The camera stayed on, the record says it stayed on: nothing unexplained."""
    flags = store()
    flags.set("senses_camera", True, reason="video call")
    paths.flags_file().unlink()
    paths.flags_file().mkdir()
    with pytest.raises(FlagWriteFailed):
        flags.set("senses_camera", False)
    paths.flags_file().rmdir()
    hand_edit(senses_camera=True)

    reopened = store()
    assert reopened.is_on("senses_camera")
    assert reopened.unexplained == ()


# ── the evidence is kept until a person or a reset deals with it ─────────────


def test_flipping_another_switch_keeps_the_hand_edit_in_the_file() -> None:
    ledger().close()
    hand_edit(egress_enabled=True)

    store().set("cli_verbose", True)

    assert file_claims()["egress_enabled"] is True, "an ordinary flip erased the evidence"
    assert store().unexplained == ("egress_enabled",)


def test_a_reset_names_the_hand_edit_in_its_entry_before_clearing_it() -> None:
    ledger().close()
    hand_edit(egress_enabled=True)

    store().reset_all(reason="panic")

    reset = [e for e in ledger().entries() if e.action == RESET_ACTION][-1]
    assert "no ledger entry, dropped: egress_enabled" in reset.verdict.reason
    assert file_claims() == {}


# ── every reader says so ─────────────────────────────────────────────────────


def test_status_names_it_and_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    ledger().close()
    hand_edit(egress_enabled=True)

    assert main(["status"]) == EXIT_FAILED
    out = capsys.readouterr().out
    assert "UNEXPLAINED: egress_enabled" in out
    assert "DANGEROUS ON" not in out


def test_the_window_and_the_self_check_name_it() -> None:
    ledger().close()
    hand_edit(egress_enabled=True)

    status = Bridge(InMemoryKeySource(KEY)).status(None)  # type: ignore[arg-type]
    assert "egress_enabled turned on outside Sletchy" in status.detail
    assert status.dangerous_on == ()

    switches = next(
        c
        for c in run_selfcheck(
            open_ledger=ledger, elevated=lambda: False, var_bytes=lambda: 0
        ).checks
        if c.id == "switches"
    )
    assert switches.status == "fail"
    assert "egress_enabled" in switches.detail
