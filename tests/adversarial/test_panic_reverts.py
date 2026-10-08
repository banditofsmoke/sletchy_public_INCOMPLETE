"""Panic must prove each undo before it reports one.

Until 2026-10-02 four steps of `sletchy panic` could fail and report success:

- the firewall step ran a `netsh` delete with an argument `netsh` does not accept,
  failed every time, and read every failure as "nothing to remove" (L009)
- a failed `icacls` revoke was counted as reverted, and its journal entry forgotten
- a failed profile delete was ignored, and its journal entry forgotten
- `clear_runtime` deleted the journal itself, so a failed revert lost its record

Every test here would have failed against that code. None runs a real process: the
fake below refuses any command it was not told to expect, so a test cannot reach the
host's firewall or ACLs (LAW 0 §6). `remove_firewall_rules` is exercised directly
against that fake rather than stubbed out, because its behaviour is the point.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sletchy.cli import panic as panic_mod
from sletchy.cli import paths
from sletchy.cli.panic import (
    COUNT_RULES_SCRIPT,
    REMOVE_RULES_SCRIPT,
    clear_runtime,
    panic,
    remove_firewall_rules,
    revert_host_changes,
)
from sletchy.kernel.hostchanges import HostChange, journal_path, pending, record, unreadable
from tests.adversarial.appcontainer import derive_sid

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

Reply = subprocess.CompletedProcess[str] | Exception


@dataclass
class FakeHost:
    """Stands in for every process panic launches. Unexpected calls fail the test."""

    counts: list[Reply] = field(default_factory=list)
    removals: list[Reply] = field(default_factory=list)
    icacls: list[Reply] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    def run(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if argv[0] == "powershell" and argv[-1] == COUNT_RULES_SCRIPT:
            self.calls.append("count")
            return self._next(self.counts, "count")
        if argv[0] == "powershell" and argv[-1] == REMOVE_RULES_SCRIPT:
            self.calls.append("remove")
            return self._next(self.removals, "remove")
        if argv[0] == "icacls":
            self.calls.append("icacls")
            return self._next(self.icacls, "icacls")
        raise AssertionError(f"panic launched something no test expected: {argv}")

    @staticmethod
    def _next(queue: list[Reply], what: str) -> subprocess.CompletedProcess[str]:
        assert queue, f"unexpected extra {what} call"
        reply = queue.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def ok(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, stdout, "")


def fail(code: int, stderr: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, "", stderr)


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> FakeHost:
    fake = FakeHost()
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: f"C:/fake/{name}.exe")
    # The real module attribute, so a process launched by *anything* during the
    # test is refused, not only one launched by panic.
    monkeypatch.setattr(subprocess, "run", fake.run)
    # Panic checks each record's SID against the one Windows derives from its
    # profile name (#94). The fake is Windows' own algorithm, held equal to the real
    # call by test_abuser_panic.py, and the records below carry the SID it gives.
    monkeypatch.setattr(panic_mod, "_call_derive_sid", derive_sid)
    # Removal is an administrator's step; the unelevated tests below say so.
    monkeypatch.setattr(panic_mod, "_is_elevated", lambda: True)
    return fake


@pytest.fixture
def profiles(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Profile deletes succeed and are recorded, unless a test says otherwise."""
    deleted: list[str] = []

    def delete(name: str) -> int:
        deleted.append(name)
        return panic_mod.S_OK

    monkeypatch.setattr(panic_mod, "_call_delete_profile", delete)
    return deleted


# ── the firewall step: count, remove, count again ────────────────────────────


def test_a_clean_host_costs_one_read_and_no_removal(host: FakeHost) -> None:
    host.counts = [ok("0")]
    assert remove_firewall_rules() == (0, 0, None)
    assert host.calls == ["count"]


def test_rules_present_are_removed_and_the_removal_is_counted(host: FakeHost) -> None:
    host.counts = [ok("3"), ok("0")]
    host.removals = [ok()]
    assert remove_firewall_rules() == (3, 0, None)
    assert host.calls == ["count", "remove", "count"]


# ── unelevated: the rules are kept, counted, and never touched (#179) ────────


@pytest.mark.parametrize("dry_run", [False, True], ids=["run", "dry-run"])
def test_unelevated_the_rules_are_kept_counted_and_never_touched(
    host: FakeHost, monkeypatch: pytest.MonkeyPatch, dry_run: bool
) -> None:
    """Removing needs an administrator, so trying could only fail; nothing is tried."""
    monkeypatch.setattr(panic_mod, "_is_elevated", lambda: False)
    host.counts = [ok("8")]
    assert remove_firewall_rules(dry_run=dry_run) == (0, 8, None)
    assert host.calls == ["count"], "an unelevated panic reached for the rules"


def test_unelevated_a_count_that_cannot_be_taken_is_still_an_error(
    host: FakeHost, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kept is a count. Could-not-look is never reported as nothing kept (L009)."""
    monkeypatch.setattr(panic_mod, "_is_elevated", lambda: False)
    host.counts = [fail(1, "New-Object : Cannot create the COM object")]
    removed, kept, error = remove_firewall_rules()
    assert (removed, kept) == (0, 0)
    assert error is not None
    assert "could not check" in error


def test_unelevated_panic_with_rules_kept_is_clean_and_says_why(
    host: FakeHost, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator's emergency control does not warn on every press."""
    monkeypatch.setattr(panic_mod, "remove_firewall_rules", remove_firewall_rules)  # the real step
    monkeypatch.setattr(panic_mod, "_is_elevated", lambda: False)
    host.counts = [ok("8")]
    report = panic()
    assert report.clean, report.errors
    assert (report.firewall_rules_removed, report.firewall_rules_kept) == (0, 8)
    rendered = report.render()
    assert "firewall rules kept    8" in rendered
    assert panic_mod.KEPT_RULES_NOTE in rendered
    assert "install-rules --remove" in panic_mod.KEPT_RULES_NOTE


def test_a_report_with_nothing_kept_has_no_note() -> None:
    assert panic_mod.KEPT_RULES_NOTE not in panic_mod.PanicReport().render()


# ── elevated: a rule left behind is an error ─────────────────────────────────


def test_a_refused_removal_reports_every_rule_that_remains(host: FakeHost) -> None:
    host.counts = [ok("3"), ok("3")]
    host.removals = [fail(1, "Access is denied.")]

    removed, kept, error = remove_firewall_rules()

    assert (removed, kept) == (0, 0)
    assert error is not None
    assert "3 firewall rule(s)" in error
    assert "remain" in error
    assert "Access is denied." in error
    assert "administrator" in error


def test_a_partial_removal_reports_the_remainder(host: FakeHost) -> None:
    host.counts = [ok("3"), ok("1")]
    host.removals = [ok()]
    removed, _kept, error = remove_firewall_rules()
    assert removed == 2
    assert error is not None
    assert error.startswith("1 firewall rule(s)")


def test_an_exit_code_of_zero_is_not_taken_as_proof(host: FakeHost) -> None:
    """The removal claims success; the recount says otherwise; the recount wins."""
    host.counts = [ok("2"), ok("2")]
    host.removals = [ok()]
    removed, _kept, error = remove_firewall_rules()
    assert removed == 0
    assert error is not None
    assert "2 firewall rule(s)" in error


@pytest.mark.parametrize(
    "reply",
    [
        fail(1, "'group' is not a valid argument for this command."),  # the L009 bug
        fail(1, "New-Object : Cannot create the COM object"),
        ok(""),
        ok("not a number"),
        subprocess.TimeoutExpired(cmd="powershell", timeout=60),
    ],
    ids=["rejected-argument", "com-blocked", "empty", "garbage", "timeout"],
)
def test_a_count_that_cannot_be_taken_is_an_error_never_a_zero(
    host: FakeHost, reply: Reply
) -> None:
    host.counts = [reply]
    removed, _kept, error = remove_firewall_rules()
    assert removed == 0
    assert error is not None, "could-not-look was reported as nothing-there"
    assert "could not check" in error
    assert host.calls == ["count"], "nothing may be removed on an unknown count"


def test_missing_powershell_is_an_error(host: FakeHost, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    removed, _kept, error = remove_firewall_rules()
    assert (removed, host.calls) == (0, [])
    assert error is not None
    assert "powershell not found" in error


def test_a_failed_recount_is_an_error(host: FakeHost) -> None:
    host.counts = [ok("2"), fail(1, "RPC server unavailable")]
    host.removals = [ok()]
    removed, _kept, error = remove_firewall_rules()
    assert removed == 0
    assert error is not None
    assert "could not recount" in error


def test_a_dry_run_counts_but_never_removes(host: FakeHost) -> None:
    host.counts = [ok("4")]
    assert remove_firewall_rules(dry_run=True) == (4, 0, None)
    assert host.calls == ["count"]


def test_off_windows_the_step_launches_nothing(
    host: FakeHost, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: False)
    assert remove_firewall_rules() == (0, 0, None)
    assert host.calls == []


def test_removal_is_by_group_never_by_rule_name() -> None:
    """Two rules can share a name; a name-based delete could take one that is not ours."""
    assert f"-Group '{paths.FIREWALL_GROUP}'" in REMOVE_RULES_SCRIPT
    assert ".Remove(" not in REMOVE_RULES_SCRIPT
    assert f"-eq '{paths.FIREWALL_GROUP}'" in COUNT_RULES_SCRIPT
    # The count must be read-only: no verb that changes anything.
    for verb in ("Remove", "Set-", "New-NetFirewallRule", "Disable", "Enable"):
        assert verb not in COUNT_RULES_SCRIPT


# ── the journal: forgotten only once the undo is proven ──────────────────────


def change(context_id: str, granted: Path | None = None, profile: str = "") -> HostChange:
    return HostChange(
        context_id=context_id,
        profile=profile,
        sid=derive_sid(f"Sletchy-{context_id}") if granted else "",
        granted_paths=(str(granted),) if granted else (),
    )


def test_a_failed_acl_revoke_keeps_its_journal_entry(
    host: FakeHost, profiles: list[str], tmp_path: Path
) -> None:
    record(change("ctxa", granted=tmp_path))
    host.icacls = [fail(5, "Access is denied.")]

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert len(errors) == 1
    assert "icacls exit 5" in errors[0]
    assert [c.context_id for c in pending()] == ["ctxa"], "the only record was erased"


def test_a_failed_profile_delete_keeps_its_journal_entry(
    host: FakeHost, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(panic_mod, "_call_delete_profile", lambda name: 0x80070057)
    record(change("ctxb", profile="Sletchy-ctxb"))

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert "0x80070057" in errors[0]
    assert [c.context_id for c in pending()] == ["ctxb"]


def test_one_failure_does_not_keep_the_others(
    host: FakeHost, profiles: list[str], tmp_path: Path
) -> None:
    record(change("good", profile="Sletchy-good"))
    record(change("bad", granted=tmp_path))
    host.icacls = [fail(1, "nope")]

    reverted, errors = revert_host_changes()

    assert reverted == 1
    assert len(errors) == 1
    assert profiles == ["Sletchy-good"]
    assert [c.context_id for c in pending()] == ["bad"]


def test_a_timed_out_revoke_is_kept_not_raised(
    host: FakeHost, profiles: list[str], tmp_path: Path
) -> None:
    record(change("slow", granted=tmp_path))
    host.icacls = [subprocess.TimeoutExpired(cmd="icacls", timeout=60)]
    reverted, errors = revert_host_changes()
    assert reverted == 0
    assert "TimeoutExpired" in errors[0]
    assert len(pending()) == 1


def test_missing_icacls_is_an_error_when_a_grant_exists(
    host: FakeHost, profiles: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    record(change("noacl", granted=tmp_path))
    reverted, errors = revert_host_changes()
    assert reverted == 0
    assert "icacls not found" in errors[0]
    assert len(pending()) == 1


def test_a_vanished_path_has_no_grant_left_to_revoke(
    host: FakeHost, profiles: list[str], tmp_path: Path
) -> None:
    record(change("gone", granted=tmp_path / "deleted-long-ago"))
    assert revert_host_changes() == (1, ())
    assert host.calls == [], "nothing to revoke on a path that does not exist"
    assert pending() == ()


def test_a_full_revert_revokes_then_deletes_then_forgets(
    host: FakeHost, profiles: list[str], tmp_path: Path
) -> None:
    record(change("full", granted=tmp_path, profile="Sletchy-full"))
    host.icacls = [ok("Successfully processed 1 files")]
    assert revert_host_changes() == (1, ())
    assert host.calls == ["icacls"]
    assert profiles == ["Sletchy-full"]
    assert pending() == ()
    assert not journal_path().exists()


def test_a_dry_run_reports_what_would_be_reverted_and_touches_nothing(
    host: FakeHost, profiles: list[str], tmp_path: Path
) -> None:
    record(change("one", profile="Sletchy-one"))
    record(change("two", granted=tmp_path))
    assert revert_host_changes(dry_run=True) == (2, ())
    assert host.calls == []
    assert profiles == []
    assert len(pending()) == 2


# ── clear_runtime and the end-to-end path ────────────────────────────────────


def test_clear_runtime_never_deletes_the_journal() -> None:
    record(change("kept", profile="Sletchy-kept"))
    (paths.runtime_dir() / "sletchy.lock").write_text("", encoding="utf-8")

    cleared = clear_runtime()

    assert cleared == 1
    assert journal_path().exists()
    assert [c.context_id for c in pending()] == ["kept"]


def test_a_failed_revert_survives_panic_and_the_next_panic_retries(
    host: FakeHost, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point: one bad run must not cost the record of what is still on the host."""
    results = iter([0x80070005, panic_mod.S_OK])
    deleted: list[str] = []

    def delete(name: str) -> int:
        deleted.append(name)
        return next(results)

    monkeypatch.setattr(panic_mod, "_call_delete_profile", delete)
    record(change("retry", profile="Sletchy-retry"))

    host.counts = [ok("0")]
    first = panic()
    assert not first.clean
    assert first.sandbox_changes_reverted == 0
    assert [c.context_id for c in pending()] == ["retry"]

    host.counts = [ok("0")]
    second = panic()
    assert second.clean, second.errors
    assert second.sandbox_changes_reverted == 1
    assert pending() == ()
    assert deleted == ["Sletchy-retry", "Sletchy-retry"]


@pytest.mark.parametrize("make_error", [lambda: OSError("disk"), lambda: RuntimeError("bug")])
def test_a_crashing_revert_step_is_reported_not_raised(
    host: FakeHost, monkeypatch: pytest.MonkeyPatch, make_error: Callable[[], Exception]
) -> None:
    def explode(*, dry_run: bool = False) -> tuple[int, tuple[str, ...]]:
        raise make_error()

    monkeypatch.setattr(panic_mod, "revert_host_changes", explode)
    host.counts = [ok("0")]
    report = panic()
    assert not report.clean
    assert "could not revert sandbox changes" in report.errors[0]


def test_a_removal_that_times_out_is_reported_with_what_remains(host: FakeHost) -> None:
    host.counts = [ok("2"), ok("2")]
    host.removals = [subprocess.TimeoutExpired(cmd="powershell", timeout=120)]
    removed, _kept, error = remove_firewall_rules()
    assert removed == 0
    assert error is not None
    assert "removal did not finish" in error
    assert "2 firewall rule(s)" in error


def test_the_report_shows_every_error_it_collected() -> None:
    rendered = panic_mod.PanicReport(errors=("first thing", "second thing")).render()
    assert "! first thing" in rendered
    assert "! second thing" in rendered
    assert not panic_mod.PanicReport(errors=("x",)).clean


# ── a line panic cannot read (#103) ──────────────────────────────────────────

#: What a crash part-way through `record()` leaves: a record with no end.
TORN = b'{"context_id": "torn", "profile": "Sletchy-to'


def write_lines(*lines: bytes) -> None:
    journal_path().parent.mkdir(parents=True, exist_ok=True)
    with journal_path().open("ab") as handle:
        for line in lines:
            handle.write(line + b"\n")


@pytest.mark.parametrize(
    "line",
    [TORN, b"not json at all", b'{"context_id": "x\xff\xfe"}', b"{}"],
    ids=["torn", "garbage", "not utf-8", "no context id"],
)
def test_an_unreadable_journal_line_makes_panic_unclean_and_is_kept(
    host: FakeHost, line: bytes
) -> None:
    """It used to be skipped, and panic reported a clean host over it."""
    write_lines(line)
    host.counts = [ok("0")]

    report = panic()

    assert not report.clean, "panic called a journal it could not read clean"
    assert report.sandbox_changes_reverted == 0
    assert any("journal line 1 could not be read and was kept" in e for e in report.errors)
    assert journal_path().read_bytes().splitlines() == [line], "the line was changed or dropped"


def test_a_readable_record_still_reverts_beside_an_unreadable_line(
    host: FakeHost, profiles: list[str]
) -> None:
    """One bad line must not stop the rest: that would be failing destructive."""
    write_lines(TORN)
    record(change("good", profile="Sletchy-good"))

    reverted, errors = revert_host_changes()

    assert reverted == 1
    assert profiles == ["Sletchy-good"]
    assert len(errors) == 1 and "journal line 1" in errors[0]
    # Content kept byte for byte. The terminator is the platform's, as record() writes.
    assert journal_path().read_bytes().splitlines() == [TORN], (
        "forget() dropped what it cannot read"
    )


def test_the_unreadable_line_is_named_by_its_number(host: FakeHost) -> None:
    record(change("first", profile="Sletchy-first"))
    write_lines(b"", TORN)
    _, errors = revert_host_changes(dry_run=True)
    assert errors == (
        f"journal line 3 could not be read and was kept ({journal_path()}); it may record "
        "a sandbox change still on this computer. Check, then delete that line by hand",
    )


def test_a_plan_reports_an_unreadable_line_too(host: FakeHost) -> None:
    write_lines(TORN)
    would_revert, errors = revert_host_changes(dry_run=True)
    assert would_revert == 0
    assert len(errors) == 1


def test_a_journal_that_reads_cleanly_reports_nothing(host: FakeHost) -> None:
    """The control: the new check does not turn every journal into an error."""
    record(change("fine", profile="Sletchy-fine"))
    assert unreadable() == ()
    assert revert_host_changes(dry_run=True) == (1, ())
