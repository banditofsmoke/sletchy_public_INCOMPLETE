"""The trust meter is only ever the sum of what was proven in this run.

Each check is driven through its seam with a known host: a real ledger on an
in-memory key, a chosen Windows build, a chosen elevation. Nothing here reads the
real keychain or depends on the machine the suite runs on.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from sletchy.cli import rules as rules_mod
from sletchy.cli import selfcheck as sc
from sletchy.cli.selfcheck import DOES_NOT_PROVE, MEASURED_WINDOWS_BUILD, run_selfcheck
from sletchy.cli.selfcheck import _read_firewall as real_read_firewall
from sletchy.kernel import paths
from sletchy.kernel.contracts import SANDBOX_LANES, HostChange
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.hostchanges import journal_path, record
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, SigningKeyMissing
from tests.adversarial.appcontainer import derive_sid

KEY = InMemoryKeySource(b"k" * 32)

#: What the rule reader says on a machine where `sletchy install-rules` never ran.
NONE_INSTALLED = [f"{lane}: missing" for lane in SANDBOX_LANES]


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))


def open_ledger() -> Ledger:
    return Ledger.open(paths.ledger_dir(), KEY)


def check(**overrides: object) -> sc.SelfCheck:
    seams: dict[str, object] = {
        "open_ledger": open_ledger,
        "elevated": lambda: False,
        "build": lambda: MEASURED_WINDOWS_BUILD,
        "var_bytes": lambda: 0,
        "firewall": lambda: [],  # the rules installed, exactly as planned
    }
    seams.update(overrides)
    return run_selfcheck(**seams)  # type: ignore[arg-type]


def by_id(report: sc.SelfCheck) -> dict[str, sc.Check]:
    return {c.id: c for c in report.checks}


def test_a_healthy_machine_scores_everything_it_can_measure() -> None:
    report = check()
    statuses = {c.id: c.status for c in report.checks}
    assert statuses == {
        "ledger": "pass",
        "switches": "pass",
        "privilege": "pass",
        "files": "pass",
        "network": "unmeasured",
        "leftovers": "pass",
        "disk": "pass",
    }
    assert (report.score, report.ceiling) == (85, 85)


def test_the_meter_cannot_reach_100_while_network_containment_is_unbuilt() -> None:
    """The honest ceiling, with the rules in place. When #71 measures UDP and IPv6, this
    test is the one that should change."""
    assert check().ceiling < 100
    assert by_id(check())["network"].status == "unmeasured"


def test_weights_add_up_to_100() -> None:
    assert sum(c.weight for c in check().checks) == 100


def test_ids_are_unique() -> None:
    ids = [c.id for c in check().checks]
    assert len(ids) == len(set(ids))


def test_a_machine_that_was_never_set_up() -> None:
    def missing() -> Ledger:
        raise SigningKeyMissing("no key")

    report = check(open_ledger=missing)
    checks = by_id(report)
    assert checks["ledger"].status == "fail"
    assert "not been set up" in checks["ledger"].plain
    assert checks["switches"].status == "unmeasured"
    assert (report.score, report.ceiling) == (40, 70)


def test_a_tampered_ledger_fails_loudly_in_plain_words() -> None:
    store = FlagStore.open(open_ledger(), paths.flags_file())
    store.set("cli_verbose", True)
    segment = paths.ledger_dir() / "segment-00000.ndjson"
    segment.write_text(segment.read_text("utf-8").replace("cli_verbose", "tampered"), "utf-8")

    checks = by_id(check())
    assert checks["ledger"].status == "fail"
    assert "something other than Sletchy" in checks["ledger"].plain


def test_a_dangerous_switch_on_is_a_warning_that_names_it() -> None:
    store = FlagStore.open(open_ledger(), paths.flags_file())
    store.set("senses_camera", True, reason="video call")

    report = check()
    switches = by_id(report)["switches"]
    assert switches.status == "warn"
    assert "Camera" in switches.plain
    assert report.score == 78  # 85 - half of 15, rounded


def test_running_elevated_fails() -> None:
    checks = by_id(check(elevated=lambda: True))
    assert checks["privilege"].status == "fail"
    assert "administrator" in checks["privilege"].plain


@pytest.mark.parametrize("build", [22631, None])
def test_an_unmeasured_windows_build_is_not_assumed_safe(build: int | None) -> None:
    report = check(build=lambda: build)
    assert by_id(report)["files"].status == "unmeasured"
    assert report.ceiling == 70


def test_leftover_host_changes_are_a_warning() -> None:
    record(HostChange(context_id="left", profile="Sletchy-left"))
    leftovers = by_id(check())["leftovers"]
    assert leftovers.status == "warn"
    assert "Stop everything" in leftovers.plain


@pytest.mark.parametrize(
    ("used", "status"),
    [(0, "pass"), (int(sc.VAR_QUOTA_BYTES * 0.85), "warn"), (sc.VAR_QUOTA_BYTES, "fail")],
)
def test_disk_use_against_the_law_0_quota(used: int, status: str) -> None:
    assert by_id(check(var_bytes=lambda: used))["disk"].status == status


def test_the_score_never_exceeds_the_ceiling() -> None:
    """Across every combination of the seams that change status."""

    def missing() -> Ledger:
        raise SigningKeyMissing("no key")

    for ledger, elevated, build in itertools.product(
        (open_ledger, missing), (False, True), (MEASURED_WINDOWS_BUILD, 1)
    ):
        report = check(open_ledger=ledger, elevated=lambda e=elevated: e, build=lambda b=build: b)
        assert 0 <= report.score <= report.ceiling <= 100


def test_what_it_cannot_prove_is_part_of_the_answer() -> None:
    report = check()
    assert report.does_not_prove == DOES_NOT_PROVE
    assert any("fake" in line for line in report.does_not_prove)


def test_every_plain_sentence_is_plain() -> None:
    """No flag names, no file paths, no jargon in the words Simple mode shows."""

    def broken() -> list[str]:
        raise OSError("no firewall")

    for report in (
        check(),
        check(elevated=lambda: True, build=lambda: None),
        check(firewall=lambda: NONE_INSTALLED),
        check(firewall=lambda: ["Sletchy-lane3: switched off"]),
        check(firewall=broken),
        check(firewall=None),
    ):
        for c in report.checks:
            assert "_" not in c.plain, c.plain
            assert "\\" not in c.plain and "/" not in c.plain, c.plain


def test_a_self_check_changes_nothing(tmp_path: Path) -> None:
    open_ledger().close()

    def snapshot() -> dict[str, bytes]:
        root = tmp_path / "var"
        return {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}

    before = snapshot()
    check()
    assert snapshot() == before


def test_an_unreadable_undo_line_is_not_nothing_left_behind() -> None:
    """One torn line used to read as "no unfinished changes" (#103, L009)."""
    journal_path().parent.mkdir(parents=True, exist_ok=True)
    journal_path().write_bytes(b'{"context_id": "torn", "profile": "Sletchy-to\n')
    leftovers = by_id(check())["leftovers"]
    assert leftovers.status == "warn"
    assert "could not be read" in leftovers.plain
    assert "1 unreadable" in leftovers.detail


def test_a_folder_with_no_sletchy_fails_the_ledger_check_and_creates_nothing() -> None:
    report = check(open_ledger=lambda: Ledger.open(paths.ledger_dir(), KEY, create=False))
    ledger = by_id(report)["ledger"]
    assert ledger.status == "fail"
    assert "not set up in this folder" in ledger.plain
    assert not paths.ledger_dir().exists()


# --- the firewall rules (#33) -------------------------------------------------------


def test_rules_in_place_are_named_but_the_network_is_still_not_claimed() -> None:
    """A complete set is reported, not passed: UDP and IPv6 are unmeasured (#71)."""
    network = by_id(check(firewall=lambda: []))["network"]
    assert network.status == "unmeasured"
    assert "in place" in network.plain
    assert "not measured" in network.plain


def test_no_rules_installed_fails_and_says_how_to_add_them() -> None:
    report = check(firewall=lambda: NONE_INSTALLED)
    network = by_id(report)["network"]
    assert network.status == "fail"
    assert "not installed" in network.plain
    assert "install-rules" in network.plain
    assert report.ceiling == 100, "a failure counts against the meter; unmeasured does not"


def test_a_changed_rule_set_fails_and_names_the_change() -> None:
    network = by_id(check(firewall=lambda: ["Sletchy-lane3: switched off"]))["network"]
    assert network.status == "fail"
    assert "not as planned" in network.plain
    assert "Sletchy-lane3: switched off" in network.detail


def test_a_firewall_that_cannot_be_read_is_never_called_in_place() -> None:
    """Could not look is not nothing there (L009)."""

    def broken() -> list[str]:
        raise OSError("firewall query failed (exit 1)")

    network = by_id(check(firewall=broken))["network"]
    assert network.status == "unmeasured"
    assert "could not read" in network.plain
    assert "exit 1" in network.detail


def test_where_there_are_no_rules_to_read_the_network_is_unmeasured() -> None:
    assert by_id(check(firewall=None))["network"].status == "unmeasured"


def test_the_host_reader_compares_the_installed_rules_with_the_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planned = rules_mod.plan(derive=derive_sid)
    installed = [
        rules_mod.Found(
            name=rule.name,
            direction=rules_mod.OUTBOUND,
            action=rules_mod.BLOCK,
            protocol=rules_mod.ANY_PROTOCOL,
            remote=",".join(rules_mod.NOT_THIS_MACHINE),
            package=rule.sid,
            enabled=True,
            profiles=rules_mod.ALL_PROFILES,
        )
        for rule in planned
    ]
    monkeypatch.setattr(rules_mod, "plan", lambda: planned)
    monkeypatch.setattr(rules_mod, "read_rules", lambda: installed)
    assert real_read_firewall() == []
    monkeypatch.setattr(rules_mod, "read_rules", lambda: installed[1:])
    assert real_read_firewall() == [f"{planned[0].lane}: missing"]


def test_no_test_reads_this_machines_firewall_through_the_self_check() -> None:
    """The conftest stub is what a default self-check reads in a test (L016)."""
    with pytest.raises(OSError, match="tests never read"):
        sc._read_firewall()
