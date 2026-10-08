"""Someone writes a line into panic's undo journal. Can they aim Stop everything?

The host-change journal (`var/run/host-changes.ndjson`) is readable without the
signing key on purpose: panic must work when the keychain is gone. So anything that
can write `var/` can also write a record, and a record tells panic which directory to
walk with `icacls /remove:g ... /T` and which AppContainer profile to delete.

Until #94, one forged line made panic strip the user's own SID from their home folder
and from `C:\\`, delete another app's container profile, and report a clean revert. Since
then a record is acted on only when it is exactly what the Warden writes: a sandbox lane
or its own `Sletchy-<context_id>` profile, the SID Windows derives from that name, and
granted paths the Warden's own grant guard accepts. Since #33 a lane comes back on later
runs, so a lane's record is reverted only while panic holds that lane.

**Nothing here touches the host.** `subprocess.run` is replaced for the whole test with
a fake that records and refuses, the profile delete is replaced with a recorder, and
`test_the_fakes_are_the_ones_installed` asserts them before anything relies on them.
SIDs are derived by `tests/adversarial/appcontainer.py`, which is Windows' own algorithm,
held equal to the real call by `test_the_derivation_is_the_one_windows_uses`.
Every path handed to the fake is under `tmp_path`, so even a fake that failed to install
would aim at a throwaway directory with a SID that names nobody.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sletchy.cli import panic as panic_mod
from sletchy.cli import paths
from sletchy.cli.panic import panic, revert_host_changes
from sletchy.kernel import grantguard
from sletchy.kernel.contracts import SANDBOX_LANES
from sletchy.kernel.hostchanges import HostChange, pending, record
from tests.adversarial.appcontainer import derive_sid

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

#: The SID Windows gives `Sletchy-genuine`: the only SID a record for `genuine` may carry.
CONTAINER_SID = derive_sid("Sletchy-genuine")
#: The SID Windows gives a real app's container. AppContainer-shaped, and not Sletchy's.
OTHER_APP_SID = derive_sid("microsoft.windows.photos_8wekyb3d8bbwe")
#: Captured before any fixture replaces it, for the one test that asks Windows itself.
REAL_DERIVE = panic_mod._call_derive_sid
#: Shaped as a local user's SID. Fictional: no account on any machine has it.
USER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
#: Captured before any fixture replaces them, for the one test that takes a real lane.
REAL_TAKE_LANE = panic_mod._call_take_lane
REAL_RELEASE_LANE = panic_mod._call_release_lane


@dataclass
class Host:
    """Records every process and profile delete panic attempts. Runs nothing."""

    launched: list[list[str]] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    #: Lanes a live sandbox holds, so panic cannot take them.
    busy: set[str] = field(default_factory=set)
    #: Lanes panic held, in order, and whether each was let go again.
    taken: list[str] = field(default_factory=list)
    released: list[str] = field(default_factory=list)

    def run(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.launched.append(list(argv))
        if argv[0] != "icacls":
            raise AssertionError(f"panic launched something no test expected: {argv}")
        return subprocess.CompletedProcess(argv, 0, "Successfully processed 1 files", "")

    def delete(self, name: str) -> int:
        self.deleted.append(name)
        return panic_mod.S_OK

    def take_lane(self, lane: str) -> int | None:
        if lane in self.busy:
            return None
        self.taken.append(lane)
        return len(self.taken)

    def release_lane(self, handle: int) -> None:
        self.released.append(self.taken[handle - 1])


@pytest.fixture(autouse=True)
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Host:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    fake = Host()
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: f"C:/fake/{name}.exe")
    # The module attribute, so a process launched by anything in the test is caught.
    monkeypatch.setattr(subprocess, "run", fake.run)
    monkeypatch.setattr(panic_mod, "_call_delete_profile", fake.delete)
    monkeypatch.setattr(panic_mod, "_call_derive_sid", derive_sid)
    monkeypatch.setattr(panic_mod, "_call_take_lane", fake.take_lane)
    monkeypatch.setattr(panic_mod, "_call_release_lane", fake.release_lane)
    monkeypatch.setattr(panic_mod, "remove_firewall_rules", lambda *, dry_run=False: (0, 0, None))
    return fake


def test_the_fakes_are_the_ones_installed(host: Host) -> None:
    """Every refusal below means nothing if a real `icacls` could have run."""
    installed: dict[str, object] = {
        "run": subprocess.run,
        "delete": panic_mod._call_delete_profile,
        "derive": panic_mod._call_derive_sid,
        "take lane": panic_mod._call_take_lane,
        "release lane": panic_mod._call_release_lane,
    }
    assert installed == {
        "run": host.run,
        "delete": host.delete,
        "derive": derive_sid,
        "take lane": host.take_lane,
        "release lane": host.release_lane,
    }


# ── the forgery from #94 ─────────────────────────────────────────────────────


def test_a_forged_record_naming_the_users_own_sid_never_reaches_icacls(
    host: Host, tmp_path: Path
) -> None:
    record(HostChange(context_id="forged", sid=USER_SID, granted_paths=(str(tmp_path),)))

    reverted, errors = revert_host_changes()

    assert host.launched == [], "panic walked a directory for a SID that is not a container"
    assert reverted == 0
    assert any("not an AppContainer SID" in e for e in errors)
    assert [c.context_id for c in pending()] == ["forged"], "a refused record must be kept"


def test_a_forged_record_naming_another_apps_profile_is_never_deleted(host: Host) -> None:
    record(HostChange(context_id="forged", profile="Microsoft.NotARealPackage_fake"))

    reverted, errors = revert_host_changes()

    assert host.deleted == [], "panic deleted a profile Sletchy never created"
    assert reverted == 0
    assert any("is not Sletchy's" in e for e in errors)
    assert len(pending()) == 1


def test_a_sletchy_profile_belonging_to_another_record_is_refused(host: Host) -> None:
    """A record may name only its own profile, so one record cannot aim at another run."""
    record(HostChange(context_id="mine", profile="Sletchy-theirs"))
    reverted, errors = revert_host_changes()
    assert host.deleted == []
    assert reverted == 0
    assert "a sandbox lane or 'Sletchy-mine'" in errors[0]


@pytest.mark.parametrize(
    "sid",
    [
        USER_SID,
        "S-1-1-0",  # Everyone
        "S-1-5-32-544",  # Administrators
        "S-1-5-18",  # Local System
        "S-1-15-2-1",  # ALL APPLICATION PACKAGES
        "S-1-15-2-2",  # ALL RESTRICTED APPLICATION PACKAGES
        "S-1-15-2-1-2-3",  # too few parts
        CONTAINER_SID + "-8",  # too many parts
        CONTAINER_SID + " /grant *S-1-1-0:F",  # an icacls argument riding along
        "*" + CONTAINER_SID,
        "s-1-15-2-1-2-3-4-5-6-7",  # lower case is not how Windows writes one
    ],
)
def test_only_an_appcontainer_sid_is_ever_handed_to_icacls(
    host: Host, tmp_path: Path, sid: str
) -> None:
    record(HostChange(context_id="forged", sid=sid, granted_paths=(str(tmp_path),)))
    reverted, errors = revert_host_changes()
    assert host.launched == []
    assert reverted == 0
    assert len(errors) == 1


def test_a_refusal_makes_panic_unclean_and_says_why(host: Host) -> None:
    record(HostChange(context_id="forged", profile="Microsoft.NotARealPackage_fake"))

    report = panic(None)

    assert not report.clean
    assert report.sandbox_changes_reverted == 0
    assert any("refused journal record forged" in e for e in report.errors)
    assert len(pending()) == 1, "panic must never delete the record it refused"


def test_a_plan_does_not_count_a_record_the_run_would_refuse(host: Host) -> None:
    record(HostChange(context_id="forged", profile="Microsoft.NotARealPackage_fake"))
    record(HostChange(context_id="real", profile="Sletchy-real"))

    would_revert, errors = revert_host_changes(dry_run=True)

    assert would_revert == 1
    assert len(errors) == 1
    assert host.launched == [] and host.deleted == []


# ── the two gaps #109 left: a real app's SID, and a path the Warden would refuse ──


def genuine(*granted: Path, sid: str = CONTAINER_SID) -> HostChange:
    """A record exactly as the Warden writes it, except for what a test changes."""
    return HostChange(
        context_id="genuine",
        profile="Sletchy-genuine",
        sid=sid,
        granted_paths=tuple(str(p) for p in granted),
    )


def test_another_apps_container_sid_is_refused_even_under_a_sletchy_name(
    host: Host, tmp_path: Path
) -> None:
    """Shaped right, named right, and still not Sletchy's: the SID is not the derived one."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    record(genuine(workspace, sid=OTHER_APP_SID))

    reverted, errors = revert_host_changes()

    assert host.launched == [], "panic removed another app's ACEs"
    assert host.deleted == [], "a refused record is refused whole, profile included"
    assert reverted == 0
    assert any("is not the one Windows gives 'Sletchy-genuine'" in e for e in errors)
    assert len(pending()) == 1


def test_a_sid_that_cannot_be_checked_is_refused_and_kept(
    host: Host, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Could not look is not "looked and it was fine" (L009). The record waits."""

    def cannot(_: str) -> str:
        msg = "userenv is not answering"
        raise OSError(msg)

    monkeypatch.setattr(panic_mod, "_call_derive_sid", cannot)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    record(genuine(workspace))

    reverted, errors = revert_host_changes()

    assert host.launched == [] and host.deleted == []
    assert reverted == 0
    assert any("could not check SID" in e and "userenv is not answering" in e for e in errors)
    assert len(pending()) == 1


def refused_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Paths the Warden's guard refuses, built under `tmp_path` wherever possible."""
    home = tmp_path / "Users" / "someone"
    home.mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    big = tmp_path / "project"
    big.mkdir()
    for index in range(5):
        (big / f"file-{index}.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(grantguard, "MAX_GRANT_ENTRIES", 3)
    a_file = tmp_path / "a-file.txt"
    a_file.write_text("not a directory", encoding="utf-8")
    return {
        "the users home": home,
        "a folder holding the users home": tmp_path / "Users",
        "a drive root": Path(tmp_path.anchor),
        "a tree too big to be a workspace": big,
        "a file": a_file,
    }


@pytest.mark.parametrize(
    "target",
    [
        "the users home",
        "a folder holding the users home",
        "a drive root",
        "a tree too big to be a workspace",
        "a file",
    ],
)
def test_a_granted_path_the_warden_would_refuse_is_never_walked(
    host: Host, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    """The right profile and the right SID, aimed at a path the Warden never grants."""
    path = refused_paths(tmp_path, monkeypatch)[target]
    record(genuine(path))

    reverted, errors = revert_host_changes()

    assert host.launched == [], f"panic walked {target} with icacls /T"
    assert host.deleted == []
    assert reverted == 0
    assert any("grant guard refuses this path" in e for e in errors)
    assert len(pending()) == 1


def test_a_plan_refuses_a_guarded_path_too(
    host: Host, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record(genuine(refused_paths(tmp_path, monkeypatch)["the users home"]))
    assert revert_host_changes(dry_run=True)[0] == 0


def test_the_warden_and_panic_share_one_guard() -> None:
    """One object, not two copies: the copy that drifted is what #94 was."""
    assert vars(panic_mod)["assert_grantable"] is grantguard.assert_grantable
    if sys.platform == "win32":
        from sletchy.warden.isolation import _win32

        assert vars(_win32)["assert_grantable"] is grantguard.assert_grantable


@pytest.mark.skipif(sys.platform != "win32", reason="asks Windows itself")
def test_the_derivation_is_the_one_windows_uses(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fake above is only worth trusting if Windows agrees with it.

    `DeriveAppContainerSidFromAppContainerName` reads nothing and creates nothing: it
    computes a SID from a name, and the profile need not exist.
    """
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: True)
    for name in ("Sletchy-genuine", "Sletchy-s0123456789abcdef", "SLETCHY-Mixed", "x"):
        assert REAL_DERIVE(name) == derive_sid(name), name
    assert REAL_DERIVE("Sletchy-a") != REAL_DERIVE("Sletchy-b")


def test_off_windows_a_sid_cannot_be_derived_so_nothing_is_reverted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: False)
    with pytest.raises(OSError, match="only be derived on Windows"):
        REAL_DERIVE("Sletchy-genuine")


# ── positive controls: what the Warden writes still reverts ──────────────────


def test_a_record_shaped_as_the_warden_writes_it_still_reverts(host: Host, tmp_path: Path) -> None:
    """Without this, a panic that refused everything would pass every test above."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    record(
        HostChange(
            context_id="genuine",
            profile="Sletchy-genuine",
            sid=CONTAINER_SID,
            granted_paths=(str(workspace),),
        )
    )

    assert revert_host_changes() == (1, ())
    assert host.launched == [
        ["icacls", str(workspace), "/remove:g", f"*{CONTAINER_SID}", "/T", "/C", "/Q"]
    ]
    assert host.deleted == ["Sletchy-genuine"]
    assert pending() == ()


def test_one_forgery_does_not_stop_a_genuine_record_reverting(host: Host) -> None:
    record(HostChange(context_id="forged", profile="Microsoft.NotARealPackage_fake"))
    record(HostChange(context_id="genuine", profile="Sletchy-genuine"))

    reverted, errors = revert_host_changes()

    assert reverted == 1
    assert host.deleted == ["Sletchy-genuine"]
    assert len(errors) == 1
    assert [c.context_id for c in pending()] == ["forged"]


@pytest.mark.skipif(sys.platform != "win32", reason="the Warden's Win32 module loads only there")
def test_panic_and_the_warden_agree_on_the_profile_name() -> None:
    """Two copies of one name, because `cli` may not import `warden`. This keeps them one."""
    from sletchy.warden.isolation import _win32

    assert panic_mod.PROFILE_PREFIX == _win32.PROFILE_PREFIX
    assert all(lane.startswith(f"{panic_mod.PROFILE_PREFIX}-") for lane in SANDBOX_LANES)


# ── lanes (#33): the same name comes back on the next run ────────────────────


def _lane_record(context_id: str, lane: str, workspace: Path) -> HostChange:
    return HostChange(
        context_id=context_id,
        profile=lane,
        sid=derive_sid(lane),
        granted_paths=(str(workspace),),
    )


def test_a_lane_a_dead_run_left_is_reverted_while_panic_holds_it(
    host: Host, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    lane = SANDBOX_LANES[3]
    record(_lane_record("dead", lane, workspace))

    assert revert_host_changes() == (1, ())
    assert host.taken == [lane]
    assert host.deleted == [lane]
    assert host.released == [lane], "panic kept the lane after reverting it"
    assert pending() == ()


def test_a_lane_a_live_sandbox_holds_is_never_touched(host: Host, tmp_path: Path) -> None:
    """A dead run's record can name the lane a live run now holds. Its grant is not ours."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    lane = SANDBOX_LANES[0]
    host.busy.add(lane)
    record(_lane_record("dead", lane, workspace))

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert host.launched == [], "panic walked a live run's SID"
    assert host.deleted == [], "panic deleted a live run's profile"
    assert len(errors) == 1
    assert "still running" in errors[0]
    assert [c.context_id for c in pending()] == ["dead"], "the record was not kept"


def test_a_lane_that_cannot_be_checked_is_kept(
    host: Host, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def cannot(_lane: str) -> int | None:
        raise OSError("no answer")

    monkeypatch.setattr(panic_mod, "_call_take_lane", cannot)
    record(_lane_record("dead", SANDBOX_LANES[1], tmp_path))

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert host.launched == []
    assert host.deleted == []
    assert "could not check" in errors[0]
    assert len(pending()) == 1


def test_a_lane_carrying_another_lanes_sid_is_refused(host: Host, tmp_path: Path) -> None:
    record(
        HostChange(
            context_id="forged",
            profile=SANDBOX_LANES[0],
            sid=derive_sid(SANDBOX_LANES[1]),
            granted_paths=(str(tmp_path),),
        )
    )

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert host.launched == []
    assert host.deleted == []
    assert host.taken == [], "a refused record took a lane"
    assert "is not the one Windows gives" in errors[0]


def test_a_name_beside_the_lanes_is_not_one(host: Host) -> None:
    """Exactly the eight lanes; `Sletchy-lane8` is not Sletchy's and is not deleted."""
    record(HostChange(context_id="forged", profile=f"Sletchy-lane{len(SANDBOX_LANES)}"))

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert host.deleted == []
    assert "is not Sletchy's" in errors[0]


@pytest.mark.skipif(sys.platform != "win32", reason="the Warden's Win32 module loads only there")
def test_panic_and_the_warden_take_the_same_lane_lock() -> None:
    """Two copies of one lock. If they named different mutexes, panic would delete a
    live run's profile believing its lane free."""
    from tests.adversarial.test_winjob_containment import HeldElsewhere

    # Another thread, as panic is another process: a mutex lets its owner take it again.
    with HeldElsewhere() as held:
        assert REAL_TAKE_LANE(held) is None, "panic took a lane the Warden holds"
    handle = REAL_TAKE_LANE(held)
    assert handle is not None, "panic could not take a lane nobody holds"
    REAL_RELEASE_LANE(handle)
