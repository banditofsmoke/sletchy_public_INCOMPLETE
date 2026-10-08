"""`winjob` - the assertions the shared conformance suite cannot make.

The conformance suite asks "is this backend as strong as it claims". This file
asks the two questions that are specific to how `winjob` gets that strength:

- **Does it leave anything behind?** It creates an AppContainer profile and an ACE
  on the workspace. Both are host changes outside `var/`, so both need a residue
  check - including on the path where the run raises partway through.
- **Are the limits real before the process is?** A ceiling applied after launch is
  a race, and a race in a security boundary is a vulnerability (LAW 0 §5).

Everything here runs against Sletchy's own containers on loopback-free, inert
commands. Nothing targets the host's services (LAW 0 §6).
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from pathlib import Path

import pytest

from sletchy.kernel.contracts import (
    SANDBOX_LANES,
    IsolationBackend,
    IsolationProfile,
    ResourceLimits,
)
from sletchy.kernel.grantguard import UnsafeGrantTarget, assert_grantable
from sletchy.kernel.hostchanges import journal_path, pending
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.kernel.paths import ENV_HOME, ledger_dir, payload_dir
from sletchy.warden.isolation import LaunchRefused, SandboxRecorder, WinJobSandbox
from tests.adversarial import probes

pytestmark = [
    pytest.mark.adversarial,
    pytest.mark.skipif(not WinJobSandbox.available(), reason="winjob requires Windows"),
]

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_HOME, str(tmp_path / "sletchy-home"))


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def recorder(_sandboxed_home: None) -> SandboxRecorder:
    """A real ledger. These tests exercise the same launch path as production,
    and that path now requires one."""
    return SandboxRecorder(
        ledger=Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32)),
        actor_id="winjob_tests",
        payloads=PayloadStore.open(payload_dir()),
    )


def profile(**kw: object) -> IsolationProfile:
    return IsolationProfile.model_validate({"backend": IsolationBackend.WINJOB, **kw})


def appcontainer_profiles() -> set[str]:
    """Every AppContainer profile folder currently on this user's machine."""
    packages = Path(os.environ["LOCALAPPDATA"]) / "Packages"
    if not packages.is_dir():
        return set()
    return {p.name for p in packages.iterdir() if p.is_dir()}


@pytest.fixture
def created_profiles(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    r"""The AppContainer profile names this test's runs create, and only those.

    The residue tests once diffed every folder in `%LOCALAPPDATA%\Packages` before
    and after a run, so anything else on the machine that touched that folder in
    between failed them: a Store update, or a second copy of this suite running beside
    this one. Every profile the backend makes is an `AppContainerProfile`, so recording
    the names it is given names exactly what this run created.
    """
    from sletchy.warden.isolation import _win32

    names: list[str] = []
    real = _win32.AppContainerProfile

    class Recording(real):  # type: ignore[valid-type, misc]
        def __init__(self, name: str, context_id: str) -> None:
            super().__init__(name, context_id)
            names.append(name)

    monkeypatch.setattr(_win32, "AppContainerProfile", Recording)
    return names


def left_behind(names: list[str]) -> list[str]:
    """The names whose profile is still here with nobody using it.

    A lane comes back on later runs, so a second copy of this suite can hold the
    same lane a moment after this run let it go. A lane's profile is looked for only
    while this test holds the lane: then it is residue or it is nothing. A lane
    someone else holds is theirs, not this run's leftovers.
    """
    from sletchy.warden.isolation import _win32

    found: list[str] = []
    for name in names:
        lane = _win32.Lane(name) if name in SANDBOX_LANES else None
        if lane is not None and not lane.take():
            continue
        try:
            if name.lower() in {p.lower() for p in appcontainer_profiles()}:
                found.append(name)
        finally:
            if lane is not None:
                lane.release()
    return found


def test_the_residue_check_sees_a_profile_that_is_there() -> None:
    # Positive control: `left_behind` must be able to say yes, or "nothing left
    # behind" proves nothing. Any folder already in Packages stands in for a profile.
    existing = sorted(appcontainer_profiles())
    if not existing:
        pytest.skip("no AppContainer profiles on this machine to stand in")
    assert left_behind([existing[0].upper()]) == [existing[0].upper()]
    assert left_behind(["Sletchy-sdefinitelynothere0000"]) == []


# ── residue ──────────────────────────────────────────────────────────────────


@pytest.mark.law_zero
def test_a_run_leaves_no_appcontainer_profile(
    workspace: Path, recorder: SandboxRecorder, created_profiles: list[str]
) -> None:
    """Ephemerality is the isolation. A surviving profile is a surviving identity."""
    WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert created_profiles, "the run created no profile, so this would prove nothing"
    assert left_behind(created_profiles) == []


# ── lanes (#33) ──────────────────────────────────────────────────────────────


def _free_lane_or_none() -> object:
    from sletchy.warden.isolation import _win32

    for name in SANDBOX_LANES:
        lane = _win32.Lane(name)
        if lane.take():
            return lane
    return None


def _free_lane() -> object:
    """A lane this test now holds, or a skip when the machine is using all of them."""
    lane = _free_lane_or_none()
    if lane is None:
        pytest.skip("every lane is in use on this machine right now")
    return lane


class HeldElsewhere:
    """A lane held by another thread, as another run would hold it.

    Not this thread: a thread may take a mutex it already holds, so a hold on the
    test's own thread would not be another run at all.
    """

    def __init__(self) -> None:
        self.name = ""
        self._ready = threading.Event()
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._hold, daemon=True)

    def _hold(self) -> None:
        from sletchy.warden.isolation import _win32

        lane = _free_lane_or_none()
        if isinstance(lane, _win32.Lane):
            self.name = lane.name
        self._ready.set()
        self._done.wait(60)
        if isinstance(lane, _win32.Lane):
            lane.release()

    def __enter__(self) -> str:
        self._thread.start()
        self._ready.wait(10)
        if not self.name:
            pytest.skip("every lane is in use on this machine right now")
        return self.name

    def __exit__(self, *_exc: object) -> None:
        self._done.set()
        self._thread.join(10)


@pytest.mark.law_zero
def test_a_run_is_contained_under_a_lane_and_lets_it_go(
    workspace: Path, recorder: SandboxRecorder, created_profiles: list[str]
) -> None:
    """The firewall rules name the lanes' SIDs, so a container outside them is unruled."""
    from sletchy.warden.isolation import _win32

    WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert created_profiles, "the run created no profile, so this would prove nothing"
    assert set(created_profiles) <= set(SANDBOX_LANES)
    lane = _win32.Lane(created_profiles[0])
    try:
        assert lane.take(), "the run ended still holding its lane"
    finally:
        lane.release()


def test_a_lane_another_run_holds_is_never_shared(
    workspace: Path, recorder: SandboxRecorder, created_profiles: list[str]
) -> None:
    """Two runs on one SID would be two sandboxes that can read each other's workspace."""
    with HeldElsewhere() as held:
        WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert created_profiles, "the run created no profile, so this would prove nothing"
    assert held not in created_profiles


def test_a_lane_this_thread_holds_is_not_taken_twice() -> None:
    """A mutex lets its owner take it again. A lane does not."""
    from sletchy.warden.isolation import _win32

    first = _free_lane()
    assert isinstance(first, _win32.Lane)
    try:
        assert not _win32.Lane(first.name).take()
    finally:
        first.release()
    again = _win32.Lane(first.name)
    assert again.take(), "a released lane could not be taken again"
    again.release()


def test_a_lane_left_behind_is_skipped_never_reused(
    workspace: Path, recorder: SandboxRecorder, created_profiles: list[str]
) -> None:
    """Whatever was granted to a dead run's SID may still be granted. Its lane waits for panic."""
    from sletchy.warden.isolation import _win32

    lane = _free_lane()
    assert isinstance(lane, _win32.Lane)
    # A profile with no run holding its lane: exactly what a hard kill leaves.
    try:
        residue = _win32.AppContainerProfile(lane.name, "residue")
    finally:
        lane.release()
    try:
        WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))
    finally:
        residue.close()

    assert created_profiles[0] == lane.name, "the residue was not made, so nothing was tested"
    assert len(created_profiles) == 2, "the run made no profile of its own"
    assert created_profiles[1] != lane.name, "the run reused a lane left behind"


def test_a_revoke_that_fails_lets_the_lane_go_and_leaves_it_marked(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    recorder: SandboxRecorder,
    created_profiles: list[str],
) -> None:
    """The lane must not be held forever, and must not be reused while its grant stands.

    The revoke comes before the profile delete, so a failed revoke leaves the profile,
    and a later run skips the lane as left behind. Here the test then clears it, as
    panic would.
    """
    from sletchy.warden.isolation import _win32

    real_revoke = _win32.revoke_path

    def failing(*_args: object, **_kwargs: object) -> None:
        raise OSError("deliberate: the revoke did not happen")

    monkeypatch.setattr(_win32, "revoke_path", failing)
    with pytest.raises(OSError, match="deliberate"):
        WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    lane_name = created_profiles[0]
    lane = _win32.Lane(lane_name)
    try:
        assert lane.take(), "a failed revoke left the lane held"
        assert lane_name.lower() in {p.lower() for p in appcontainer_profiles()}, (
            "the profile went while its grant stayed, so the lane would look clean"
        )
        assert {c.profile for c in pending()} == {lane_name}, "the journal lost the record"
    finally:
        real_revoke(workspace, pending()[-1].sid)
        _win32._userenv.DeleteAppContainerProfile(lane_name)
        lane.release()


def test_with_no_lane_free_the_run_is_refused_and_recorded(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    recorder: SandboxRecorder,
    created_profiles: list[str],
) -> None:
    """Never a container outside the lanes: one the firewall rules do not name."""
    from sletchy.warden.isolation import winjob

    with HeldElsewhere() as held:
        monkeypatch.setattr(winjob, "SANDBOX_LANES", (held,))
        with pytest.raises(LaunchRefused, match="sandbox lanes are in use"):
            WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert created_profiles == [], "a refused run created a profile"
    assert pending() == (), "a refused run left a journal entry"


@pytest.mark.law_zero
def test_a_run_that_raises_midway_still_leaves_no_profile(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    recorder: SandboxRecorder,
    created_profiles: list[str],
) -> None:
    """The rail that mattered most in the spike, asserted rather than hoped for.

    One spike run crashed after the profile was created and cleanup still
    completed, because the delete sits first in the same `finally`. This forces
    that crash deliberately.
    """
    from sletchy.warden.isolation import _win32

    def exploding_spawn(*_args: object, **_kwargs: object) -> object:
        msg = "deliberate failure after the profile exists"
        raise OSError(msg)

    monkeypatch.setattr(_win32, "spawn", exploding_spawn)

    with pytest.raises(OSError, match="deliberate failure"):
        WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert created_profiles, "the run failed before creating a profile; nothing was tested"
    assert left_behind(created_profiles) == [], "a raising run left a profile behind"


@pytest.mark.law_zero
def test_a_run_leaves_no_ace_on_the_workspace(workspace: Path, recorder: SandboxRecorder) -> None:
    """The grant is for one execution. It must not outlive it."""
    result = WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))
    sid = result.diagnostics["container_sid"]

    listing = subprocess.run(
        ["icacls", str(workspace)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    assert sid not in listing.stdout, f"the container SID is still on the workspace ACL:\n{sid}"


@pytest.mark.law_zero
def test_the_undo_journal_is_empty_after_a_clean_run(
    workspace: Path, recorder: SandboxRecorder
) -> None:
    WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert pending() == ()
    assert not journal_path().exists()


@pytest.mark.law_zero
def test_the_journal_records_a_change_before_it_is_made(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, recorder: SandboxRecorder
) -> None:
    """Ordering is the whole point: a change made before it is journalled is a
    change `panic` cannot find.

    Fails the run at the moment the profile exists but nothing has been granted,
    then asserts the journal already knew about the profile.
    """
    from sletchy.warden.isolation import _win32

    seen: list[tuple[str, ...]] = []
    real_grant = _win32.grant_path

    def watched_grant(path: Path, sid: str, **kwargs: object) -> None:
        seen.append(tuple(c.profile for c in pending()))
        real_grant(path, sid, **kwargs)  # type: ignore[arg-type]
        msg = "stop here, with the grant made"
        raise OSError(msg)

    monkeypatch.setattr(_win32, "grant_path", watched_grant)

    with pytest.raises(OSError, match="stop here"):
        WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert seen, "the grant was never attempted"
    assert any(name.startswith("Sletchy-") for name in seen[0]), (
        "the profile was created before the journal knew about it"
    )
    assert pending() == (), "the journal was not cleared by the finally"


# ── limits precede the process ───────────────────────────────────────────────


@pytest.mark.law_zero
def test_job_limits_are_applied_before_the_process_starts(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, recorder: SandboxRecorder
) -> None:
    """LAW 0 §5, asserted as an ordering rather than an outcome."""
    from sletchy.warden.isolation import _win32

    order: list[str] = []
    real_apply = _win32.JobObject.apply
    real_spawn = _win32.spawn

    def watched_apply(self: _win32.JobObject, **kwargs: int) -> None:
        order.append("limits")
        real_apply(self, **kwargs)

    def watched_spawn(*args: object, **kwargs: object) -> object:
        order.append("spawn")
        return real_spawn(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(_win32.JobObject, "apply", watched_apply)
    monkeypatch.setattr(_win32, "spawn", watched_spawn)

    WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert order == ["limits", "spawn"], f"limits were not applied first: {order}"


def test_no_process_is_ever_added_to_a_job_after_creation() -> None:
    """The structural half of the same rule.

    `AssignProcessToJobObject` is the only way to put an already-running process
    into a job. It is deliberately never bound in the Warden, so the ordering
    asserted above cannot be undone later by a helpful convenience.

    Matches the **attribute access** rather than the bare name, so the prose in
    `_win32.py` explaining the ban does not read as a violation of it. A check
    that flags its own defence trains people to ignore the check.
    """
    warden = REPO / "src" / "sletchy" / "warden"
    hits = [
        path.relative_to(warden).as_posix()
        for path in warden.rglob("*.py")
        if re.search(r"\.\s*AssignProcessToJobObject", path.read_text("utf-8"))
    ]
    assert hits == [], f"a post-launch job assignment appeared in: {hits}"


def test_the_declared_ceilings_reach_the_job(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, recorder: SandboxRecorder
) -> None:
    """The profile's numbers, not defaults invented by the backend (LAW 3)."""
    from sletchy.warden.isolation import _win32

    captured: dict[str, int] = {}
    real_apply = _win32.JobObject.apply

    def watched_apply(self: _win32.JobObject, **kwargs: int) -> None:
        captured.update(kwargs)
        real_apply(self, **kwargs)

    monkeypatch.setattr(_win32.JobObject, "apply", watched_apply)

    limits = ResourceLimits(memory_mb=256, cpu_percent=25, max_processes=4)
    WinJobSandbox(workspace, profile(resources=limits), recorder=recorder).run(probes.exit_with(0))

    assert captured == {"memory_mb": 256, "cpu_percent": 25, "max_processes": 4}


# ── the process tree ─────────────────────────────────────────────────────────


@pytest.mark.law_zero
def test_a_detached_grandchild_is_inside_the_job_and_dies_with_it(workspace: Path) -> None:
    """The evidence behind `kills_process_tree`.

    The control has two parts, and the second was learned the hard way. A
    grandchild that detached from its parent must be

    1. **alive inside the job** - so `BREAKAWAY_OK` is genuinely unset, and
    2. **actually running** - burning CPU inside the job.

    (2) exists because (1) alone is not enough. An earlier version of the probe
    was malformed, `start` failed, and Windows put a modal error dialog on the
    desktop; that dialog was a live process in the job, so "one process is alive"
    passed while measuring nothing. A blocked dialog consumes no CPU, so
    requiring the job to accrue processor time tells the two apart. This is
    ADR-0005 §4's lesson applied to the control itself.
    """
    from sletchy.warden.isolation import _win32

    context_id = _win32.new_context_id()
    container = _win32.AppContainerProfile(f"Sletchy-{context_id}", context_id)
    job = _win32.JobObject()
    token = None
    capture = workspace / "out.txt"
    try:
        _win32.grant_path(workspace, container.sid_string)
        job.apply(memory_mb=256, cpu_percent=50, max_processes=16)
        token = _win32.restricted_token()

        with capture.open("wb") as sink:
            launched = _win32.spawn(
                _win32.command_line(probes.spawn_detached_child()),
                sid=container.sid,
                job=job,
                token=token,
                cwd=str(workspace),
                env={
                    "SYSTEMROOT": os.environ["SYSTEMROOT"],
                    "LOCALAPPDATA": os.environ["LOCALAPPDATA"],
                    "PATH": "",
                },
                stdout_handle=_win32.inheritable_handle(sink),
            )
        launched.wait(20)
        launched.close()

        alive = job.active_processes()
        assert alive >= 1, (
            "no process survived the parent, so this test proves nothing about "
            "tree kill: the grandchild either never started or broke away unseen"
        )

        before = job.cpu_time_ns()
        time.sleep(0.5)
        assert job.cpu_time_ns() > before, (
            "a process is alive in the job but consuming no CPU. The probe is not "
            "running what this test thinks it is - check for a blocked child or a "
            "dialog rather than trusting the process count"
        )

        job.terminate()
        assert job.active_processes() == 0, "a detached grandchild survived the job terminate"
    finally:
        job.terminate()
        job.close()
        if token is not None:
            _win32.close_handle(token)
        _win32.revoke_path(workspace, container.sid_string)
        container.close()


# ── the recursive ACL change is the dangerous primitive ──────────────────────


@pytest.mark.law_zero
@pytest.mark.parametrize(
    "target",
    [
        pytest.param("drive_root", id="drive-root"),
        pytest.param("systemroot", id="systemroot"),
        pytest.param("userprofile", id="userprofile"),
        pytest.param("localappdata", id="localappdata"),
        pytest.param("missing", id="does-not-exist"),
        pytest.param("a_file", id="not-a-directory"),
    ],
)
def test_a_dangerous_grant_target_is_refused_without_touching_the_host(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`icacls /T` is recursive. Pointed at a drive root or a home directory it
    would rewrite permissions across the whole tree.

    The second half of this test is the important half: `icacls` must never be
    reached. A refusal that has already started walking the host is not a refusal.
    """
    from sletchy.warden.isolation import _win32

    calls: list[tuple[str, ...]] = []

    def recording_icacls(*args: str) -> tuple[bool, str]:
        calls.append(args)
        return True, ""

    monkeypatch.setattr(_win32, "_icacls", recording_icacls)

    a_file = tmp_path / "a-file.txt"
    a_file.write_text("not a directory", encoding="utf-8")
    paths = {
        "drive_root": Path(Path.cwd().anchor),
        "systemroot": Path(os.environ["SYSTEMROOT"]),
        "userprofile": Path(os.environ["USERPROFILE"]),
        "localappdata": Path(os.environ["LOCALAPPDATA"]),
        "missing": tmp_path / "nope" / "still-nope",
        "a_file": a_file,
    }

    with pytest.raises(UnsafeGrantTarget):
        _win32.grant_path(paths[target], "S-1-15-2-1")

    assert calls == [], f"icacls was invoked on {paths[target]} before the refusal"


def test_a_real_workspace_is_still_grantable(workspace: Path) -> None:
    """The positive control. A guard that refuses everything is not a guard."""

    assert_grantable(workspace)


@pytest.mark.law_zero
def test_a_tree_too_large_to_be_a_workspace_is_refused(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Size is the check that catches a plausible-looking wrong path.

    A directory deep enough to pass every name check can still be someone's whole
    project tree. The cap is lowered here rather than building 10,000 files.
    """
    from sletchy.warden.isolation import _win32

    monkeypatch.setattr("sletchy.kernel.grantguard.MAX_GRANT_ENTRIES", 3)
    for index in range(5):
        (workspace / f"file-{index}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(UnsafeGrantTarget, match="not a sandbox workspace"):
        _win32.grant_path(workspace, "S-1-15-2-1")


def test_the_backend_refuses_the_run_rather_than_launching_uncontained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recorder: SandboxRecorder,
    created_profiles: list[str],
) -> None:
    """A workspace we will not grant is a run that does not happen.

    The alternative - launch anyway, with a container that cannot use its own
    workspace - is the silent-downgrade shape ADR-0002 exists to prevent.
    """
    from sletchy.warden.isolation import _win32

    def refuse(*_args: object, **_kwargs: object) -> None:
        msg = "refusing to grant on a test-forced unsafe target"
        raise UnsafeGrantTarget(msg)

    monkeypatch.setattr(_win32, "grant_path", refuse)
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(LaunchRefused, match="refusing to grant"):
        WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert left_behind(created_profiles) == [], "the refused run left a profile behind"


# ── failing closed ───────────────────────────────────────────────────────────


def test_an_empty_command_is_refused(workspace: Path, recorder: SandboxRecorder) -> None:
    with pytest.raises(LaunchRefused, match="empty command"):
        WinJobSandbox(workspace, profile(), recorder=recorder).run([])


def test_a_missing_local_app_data_fails_closed_rather_than_launching(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, recorder: SandboxRecorder
) -> None:
    """Without it the container cannot start, and the answer is not to start it
    uncontained."""
    monkeypatch.delenv("LOCALAPPDATA", raising=False)

    with pytest.raises(LaunchRefused, match="LOCALAPPDATA"):
        WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))
