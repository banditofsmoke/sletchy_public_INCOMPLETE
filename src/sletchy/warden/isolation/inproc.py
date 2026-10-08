"""`inproc` - no isolation whatsoever. Tests only.

This backend exists so the conformance suite has a known-weak baseline: a suite of
should-fail assertions passes trivially when nothing runs, and `inproc` is how we
prove the suite can tell the difference.

**It refuses to load outside a test run.** A convenience that bypasses a security
boundary will eventually be reached for in production, and the cheapest place to
stop that is at construction.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import IsolationBackend
from sletchy.warden.isolation.base import (
    BackendUnavailable,
    Capabilities,
    LaunchResult,
    Sandbox,
)

if TYPE_CHECKING:
    from pathlib import Path

    from sletchy.kernel.contracts import IsolationProfile
    from sletchy.warden.isolation.recorder import SandboxRecorder


class InProcSandbox(Sandbox):
    """Runs the command with no confinement at all."""

    backend = IsolationBackend.INPROC

    def __init__(
        self, workspace: Path, profile: IsolationProfile, *, recorder: SandboxRecorder
    ) -> None:
        if "pytest" not in sys.modules and not os.environ.get("SLETCHY_ALLOW_INPROC"):
            msg = (
                "InProcSandbox provides NO isolation and was constructed outside a "
                "test run. Use a real backend. If this is a deliberate developer "
                "loop, set SLETCHY_ALLOW_INPROC=1 explicitly and know what it means."
            )
            raise BackendUnavailable(msg)
        super().__init__(workspace, profile, recorder=recorder)

    @classmethod
    def available(cls) -> bool:
        return "pytest" in sys.modules or bool(os.environ.get("SLETCHY_ALLOW_INPROC"))

    @classmethod
    def capabilities(cls) -> Capabilities:
        """Claims nothing, because it enforces nothing."""
        return Capabilities()

    def run(self, command: list[str], *, timeout: float | None = None) -> LaunchResult:
        if not command:
            raise self.refuse(command, "inproc refuses an empty command")

        # Even the backend that confines nothing records what it ran. LAW 1 is not
        # conditional on the isolation being any good.
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
                timeout=timeout,
                check=False,
                cwd=self.workspace,
            )
        except subprocess.TimeoutExpired:
            stopped = LaunchResult(exit_code=None, timed_out=True, backend=self.backend)
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
