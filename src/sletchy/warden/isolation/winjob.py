"""`winjob` - real containment on a stock Windows machine, with nothing installed.

Four kernel-enforced mechanisms, driven entirely from user mode
([ADR-0001](../../../../docs/adr/0001-no-kernel-driver.md)):

| Control | Mechanism |
|---|---|
| Deny filesystem by default | AppContainer profile with **zero** capabilities |
| Memory / CPU / process ceilings | Job Object, applied before the child exists |
| Whole-tree kill, no breakaway | `KILL_ON_JOB_CLOSE`, and `BREAKAWAY_OK` left unset |
| Privileges dropped | a restricted derivative of our own token |
| No inherited environment | the `kernel/secrets` allowlist |

**Its one door out.** A run whose profile allows any host, given an egress gate,
gets a proxy on loopback for the length of the run (`warden/egress/`, #32), and the
child is told where it is through `HTTP_PROXY` and `HTTPS_PROXY`. Every request
through it is decided and recorded before anything connects. A run given no gate, or
whose profile allows no host, gets no door at all: less than it asked for, never more.

**What it does not do.** It does not claim `confines_network`. An AppContainer
without the network capability is *expected* to be unable to open a socket, and
the firewall app rule is *expected* to bind to a contained process, but neither
has been measured, and an unmeasured claim riding in beside a measured one is
exactly how a control becomes decorative. That claim arrives with its own issue
and its own probe.

## The two behaviours that surprise people

**A contained child cannot use its own workspace until it is given one.**
AppContainer denies a directory the parent created seconds earlier, so `winjob`
adds one ACE for the per-execution container SID and removes it when the run ends.
That is the sandbox being handed its single usable area, not the sandbox being
loosened - everything outside stays denied, which the conformance suite asserts.

**Output cannot be redirected from inside.** The container cannot open the null
device, so a child that redirects its own output measures its plumbing rather than
its confinement - the mistake that invalidated three spike runs (ADR-0005 §4).
The parent opens the file and passes the handle in; a handle already open needs no
access check.

## Lanes

A run's container is named for one of eight lanes, not for the run (#33,
[ADR-0013](../../../../docs/adr/0013-sandbox-lanes-so-a-firewall-rule-can-name-the-container.md)).
Windows derives a container's SID from its name, and a firewall rule names a SID,
so a rule written once can only cover containers whose names are known in
advance. A lane is held by one run at a time, through a named mutex, and is let go
only after its profile is deleted and its grant revoked. A lane whose profile is
still on the machine was left behind by a run that never reached its `finally`; it
is skipped, never reused, because whatever was granted to its SID may still be
granted. `sletchy panic` clears it. With every lane busy or left behind, the run
is refused, never given a container outside the lanes.

## Reversibility

Every host change is undone in a `finally`, and journalled *before* it is made so
that `sletchy panic` can undo it after a hard kill
([LAW 0 §2](../../../../docs/LAW/00-do-no-harm.md)). Nothing survives a run:
profile deleted, ACE revoked, journal entry dropped, lane let go.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import SANDBOX_LANES, IsolationBackend
from sletchy.kernel.grantguard import UnsafeGrantTarget
from sletchy.kernel.hostchanges import HostChange, forget, record
from sletchy.kernel.paths import runtime_dir
from sletchy.kernel.secrets import child_env
from sletchy.warden.egress import EgressProxy
from sletchy.warden.isolation.base import (
    BackendUnavailable,
    Capabilities,
    LaunchResult,
    Sandbox,
)

if TYPE_CHECKING:
    from pathlib import Path

    from sletchy.kernel.contracts import IsolationProfile
    from sletchy.warden.egress import EgressGate
    from sletchy.warden.isolation import _win32
    from sletchy.warden.isolation.recorder import SandboxRecorder


class WinJobSandbox(Sandbox):
    """Job Object + restricted token + AppContainer, per execution."""

    backend = IsolationBackend.WINJOB

    def __init__(
        self,
        workspace: Path,
        profile: IsolationProfile,
        *,
        recorder: SandboxRecorder,
        egress: EgressGate | None = None,
    ) -> None:
        super().__init__(workspace, profile, recorder=recorder)
        self.egress = egress
        if not self.available():
            msg = (
                "the winjob backend requires Windows with the AppContainer and Job "
                "Object APIs. The capability does not run; nothing weaker is "
                "substituted."
            )
            # Recorded before raising: "the isolation this needed was unavailable"
            # is exactly the kind of refusal an operator later wants to find.
            self.recorder.refused(command=[], reason=msg)
            raise BackendUnavailable(msg)
        self.workspace.mkdir(parents=True, exist_ok=True)

    @classmethod
    def available(cls) -> bool:
        if sys.platform != "win32":
            return False
        try:
            from sletchy.warden.isolation import _win32
        except (ImportError, OSError):
            return False
        return _win32.api_available()

    @classmethod
    def capabilities(cls) -> Capabilities:
        """Exactly what has been measured on the target build, and no more.

        `confines_network` stays False deliberately. See the module docstring.
        """
        return Capabilities(
            confines_filesystem=True,
            confines_network=False,
            enforces_resource_limits=True,
            kills_process_tree=True,
            strips_environment=True,
        )

    # ── the run ──────────────────────────────────────────────────────────────

    def run(self, command: list[str], *, timeout: float | None = None) -> LaunchResult:
        """Run `command` inside a fresh container, and leave nothing behind.

        The whole of the host-visible state is created and destroyed here rather
        than across the object's lifetime, so a caller that forgets `cleanup()`
        still leaves a clean host.
        """
        from sletchy.warden.isolation import _win32

        if not command:
            raise self.refuse(command, "winjob refuses an empty command")

        limit = timeout if timeout is not None else self.profile.resources.wall_clock_seconds
        context_id = _win32.new_context_id()

        lane: _win32.Lane | None = None
        door: EgressProxy | None = None
        container: _win32.AppContainerProfile | None = None
        job: _win32.JobObject | None = None
        token = None
        granted = False
        capture = runtime_dir() / f"sandbox-{context_id}.out"
        capture.parent.mkdir(parents=True, exist_ok=True)

        try:
            door = self._door()
            environment = self._environment(command, door)
            lane, container = self._claim_lane(command, context_id)

            record(
                HostChange(
                    context_id=context_id,
                    profile=container.name,
                    sid=container.sid_string,
                    granted_paths=(str(self.workspace),),
                )
            )
            try:
                _win32.grant_path(self.workspace, container.sid_string)
            except UnsafeGrantTarget as exc:
                # The workspace is not something we will re-ACL. Refuse the run
                # rather than proceeding with a container that cannot use it.
                raise self.refuse(command, str(exc)) from exc
            granted = True

            # Every ceiling is set on the job before a process exists to enter it.
            job = _win32.JobObject()
            job.apply(
                memory_mb=self.profile.resources.memory_mb,
                cpu_percent=self.profile.resources.cpu_percent,
                max_processes=self.profile.resources.max_processes,
            )
            token = _win32.restricted_token()

            # Everything that could refuse has refused by now, and the process does
            # not exist yet. This is the last moment at which the record can
            # truthfully precede the action (LAW 1).
            self.recorder.launching(
                command=command,
                backend=self.backend,
                profile=self.profile,
                workspace=str(self.workspace),
            )

            return self._launch(
                command,
                container=container,
                job=job,
                token=token,
                capture=capture,
                environment=environment,
                limit=float(limit),
            )
        finally:
            # Order matters: the job dies first so nothing is still running while
            # the rest is torn down, and the profile delete comes before the SID
            # is released (ADR-0005 §2). The grant is revoked before the profile
            # goes, so a revoke that fails leaves the profile too, and the lane is
            # skipped as left behind until panic clears both.
            try:
                if job is not None:
                    job.terminate()
                    job.close()
                if door is not None:
                    door.stop()
                if token is not None:
                    _win32.close_handle(token)
                if container is not None:
                    if granted:
                        _win32.revoke_path(self.workspace, container.sid_string)
                    container.close()
                capture.unlink(missing_ok=True)
                forget(context_id)
            finally:
                # Last, and whatever failed above: a lane still held would be
                # lost to every later run in this process.
                if lane is not None:
                    lane.release()

    def _claim_lane(
        self, command: list[str], context_id: str
    ) -> tuple[_win32.Lane, _win32.AppContainerProfile]:
        """Take the first free lane and create its profile, or refuse the run.

        Each lane is journalled before its profile is created: an entry with no
        profile is a no-op to revert, a profile with no entry is residue nobody can
        find. A lane that turns out to be left behind gets its entry dropped again,
        because this run created nothing there.
        """
        from sletchy.warden.isolation import _win32

        left_behind: list[str] = []
        for name in SANDBOX_LANES:
            lane = _win32.Lane(name)
            if not lane.take():
                continue  # another run is using it
            try:
                record(HostChange(context_id=context_id, profile=name))
                return lane, _win32.AppContainerProfile(name, context_id)
            except _win32.ProfileExists:
                left_behind.append(name)
                forget(context_id)
                lane.release()
            except BaseException:
                lane.release()
                raise
        reason = f"all {len(SANDBOX_LANES)} sandbox lanes are in use"
        if left_behind:
            reason += (
                f", {len(left_behind)} of them left behind by a run that did not finish "
                f"({', '.join(left_behind)}). `sletchy stop` clears those"
            )
        raise self.refuse(command, reason + ". Nothing was run.")

    def _launch(
        self,
        command: list[str],
        *,
        container: _win32.AppContainerProfile,
        job: _win32.JobObject,
        token: _win32.Handle,
        capture: Path,
        environment: dict[str, str],
        limit: float,
    ) -> LaunchResult:
        """Start the child, wait for it, and report what happened.

        The parent's copy of the capture handle is closed as soon as the child
        holds its own. The child keeps writing through the handle it inherited,
        and nothing is left holding the file open if the wait goes wrong.
        """
        from sletchy.warden.isolation import _win32

        with capture.open("wb") as sink:
            launched = _win32.spawn(
                _win32.command_line(command),
                sid=container.sid,
                job=job,
                token=token,
                cwd=str(self.workspace),
                env=environment,
                stdout_handle=_win32.inheritable_handle(sink),
            )

        diagnostics = {
            "context_id": container.context_id,
            "profile": container.name,
            "container_sid": container.sid_string,
            "pid": str(launched.pid),
        }
        try:
            if launched.wait(limit):
                result = LaunchResult(
                    exit_code=launched.exit_code(),
                    stdout=self._read(capture),
                    backend=self.backend,
                    diagnostics=diagnostics,
                )
            else:
                # We stopped it. Killing the job takes the whole tree, not just the
                # process we were waiting on, so a detached child cannot outlive the
                # timeout that was meant to bound it.
                job.terminate()
                result = LaunchResult(
                    exit_code=None,
                    stdout=self._read(capture),
                    timed_out=True,
                    killed_by_limit=True,
                    backend=self.backend,
                    diagnostics={**diagnostics, "limit_seconds": str(limit)},
                )
            self.recorder.finished(command=command, result=result)
            return result
        finally:
            launched.close()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _door(self) -> EgressProxy | None:
        """The run's proxy, started, or None when the run may reach nothing."""
        if self.egress is None or not self.profile.network.allow_egress:
            return None
        return EgressProxy(self.egress.narrowed(self.profile.network)).start()

    def _environment(self, command: list[str], door: EgressProxy | None) -> dict[str, str]:
        """The allowlist, plus the one variable the container cannot start without.

        `LOCALAPPDATA` is not a convenience: the AppContainer launch path resolves
        the container's redirected app-data folder from it, and without it
        `CreateProcess` fails with `ERROR_ENVVAR_NOT_FOUND`. It is added here
        rather than in the Kernel's allowlist because it is a `winjob`
        requirement, and widening the shared allowlist to satisfy one backend
        would hand it to every other one too.
        """
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            msg = (
                "LOCALAPPDATA is unset, and an AppContainer cannot be launched "
                "without it. Failing closed rather than launching uncontained."
            )
            raise self.refuse(command, msg)
        extra = {"LOCALAPPDATA": local_app_data}
        if door is not None:
            extra |= {"HTTP_PROXY": door.url, "HTTPS_PROXY": door.url}
        return child_env(extra=extra)

    def _read(self, capture: Path) -> str:
        """Read captured output, capped at the declared ceiling."""
        if not capture.is_file():
            return ""
        cap = self.profile.resources.max_output_bytes
        data = capture.read_bytes()[:cap]
        return data.decode("utf-8", errors="replace")
