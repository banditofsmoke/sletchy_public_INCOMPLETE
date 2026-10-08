"""`subproc` - a child process with a scrubbed environment and a hard timeout.

Weak, and it says so. It confines **nothing** about the filesystem or the network:
the child runs as the same user with the same access. What it does provide is an
allowlisted environment and a wall-clock ceiling, which is enough for a developer
loop and nowhere near enough for an untrusted agent.

Its honest `Capabilities` is what keeps that distinction enforceable: policy
requiring `confines_filesystem` will not select it, and `select()` raises rather
than substituting it.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import IsolationBackend
from sletchy.kernel.secrets import child_env
from sletchy.warden.isolation.base import Capabilities, LaunchResult, Sandbox

if TYPE_CHECKING:
    from pathlib import Path

    from sletchy.kernel.contracts import IsolationProfile
    from sletchy.warden.isolation.recorder import SandboxRecorder


class SubprocSandbox(Sandbox):
    """A plain child process, env-scrubbed and time-limited."""

    backend = IsolationBackend.SUBPROC

    def __init__(
        self, workspace: Path, profile: IsolationProfile, *, recorder: SandboxRecorder
    ) -> None:
        super().__init__(workspace, profile, recorder=recorder)
        self.workspace.mkdir(parents=True, exist_ok=True)

    @classmethod
    def available(cls) -> bool:
        return True

    @classmethod
    def capabilities(cls) -> Capabilities:
        """Only what it actually does.

        A wall-clock kill is a resource limit; memory and CPU ceilings are not
        available without a job object, so this does not claim them.
        """
        return Capabilities(strips_environment=True, enforces_resource_limits=True)

    def run(self, command: list[str], *, timeout: float | None = None) -> LaunchResult:
        if not command:
            raise self.refuse(command, "subproc refuses an empty command")

        limit = timeout if timeout is not None else self.profile.resources.wall_clock_seconds

        # Before the process exists, and fsynced. LAW 1.
        self.recorder.launching(
            command=command,
            backend=self.backend,
            profile=self.profile,
            workspace=str(self.workspace),
        )
        try:
            result = subprocess.run(  # noqa: S603
                command,
                capture_output=True,
                text=True,
                timeout=limit,
                check=False,
                cwd=self.workspace,
                # The allowlist from kernel/secrets: the child never inherits a
                # credential, an import hook, or a PATH it could search.
                env=child_env(),
            )
        except subprocess.TimeoutExpired:
            stopped = LaunchResult(
                exit_code=None,
                timed_out=True,
                killed_by_limit=True,
                backend=self.backend,
                diagnostics={"limit_seconds": str(limit)},
            )
            self.recorder.finished(command=command, result=stopped)
            return stopped

        finished = LaunchResult(
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            backend=self.backend,
        )
        self.recorder.finished(command=command, result=finished)
        return finished
