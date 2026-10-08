"""`container` - a rootless Podman container, on Linux only (#70, ADR-0014).

The ladder's rung above `winjob`, and the one that is not Windows-specific. On Linux
a rootless container is an ordinary process tree the operator owns: no hypervisor,
nothing in the boot configuration, nothing with more rights than the operator.

**Never on Windows** ([ADR-0014](../../../../docs/adr/0014-the-container-backend-runs-on-linux-only.md)).
There a container needs a WSL2 virtual machine, which changes how the machine boots.
`available()` is False on Windows whatever is installed, so the ladder there is what
it was.

**Never installs, enables, starts or pulls anything.** The backend is available only
when `podman` is already present **and** the image, pinned by digest, is already on
the machine. Fetching it is the operator's step, or CI's. A run never pulls
(`--pull=never`).

What a run gets, and nothing more:

| | |
|---|---|
| Network | none (`--network=none`) |
| Filesystem | the image, read-only; its own `/tmp`; the workspace, mounted at the same path |
| Privileges | every capability dropped, no new privileges, rootless |
| Ceilings | processes, memory and CPU from the profile; the wall clock by our own watchdog |
| Environment | only the Kernel's allowlist, passed one variable at a time |

It does not claim `confines_network`: `--network=none` is expected to refuse a socket,
and expected is not measured. The container is journalled before it exists and
removed in a `finally`; `sletchy panic` removes any a hard kill left behind.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import uuid
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import IsolationBackend
from sletchy.kernel.hostchanges import HostChange, forget, record
from sletchy.kernel.secrets import child_env
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

RUNTIME = "podman"
#: Debian 12 slim, by the digest of its multi-platform index (LAW 4), never by tag.
#: Its shell, `cat` and `sleep` sit where an Ubuntu host keeps them, so the conformance
#: probes resolve the same paths inside and out.
IMAGE = (
    "docker.io/library/debian"
    "@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"
)
#: Every container is `sletchy-<context id>`, so panic can tell its own from anyone's.
NAME_PREFIX = "sletchy-"


def _platform() -> str:
    """One seam for the platform, so tests can ask the Linux question anywhere."""
    return sys.platform


def container_name(context_id: str) -> str:
    return f"{NAME_PREFIX}{context_id}"


class ContainerSandbox(Sandbox):
    """One rootless container per run, removed when the run ends."""

    backend = IsolationBackend.CONTAINER

    def __init__(
        self, workspace: Path, profile: IsolationProfile, *, recorder: SandboxRecorder
    ) -> None:
        super().__init__(workspace, profile, recorder=recorder)
        if not self.available():
            msg = (
                "the container backend needs Linux, podman, and its pinned image already "
                "on the machine. Sletchy installs and pulls nothing. The capability does "
                "not run; nothing weaker is substituted."
            )
            self.recorder.refused(command=[], reason=msg)
            raise BackendUnavailable(msg)
        self.workspace.mkdir(parents=True, exist_ok=True)

    @classmethod
    def available(cls) -> bool:
        if _platform() != "linux":
            return False
        runtime = shutil.which(RUNTIME)
        if runtime is None:
            return False
        try:
            found = subprocess.run(  # noqa: S603 - the runtime, asking about one image
                [runtime, "image", "exists", IMAGE],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return found.returncode == 0

    @classmethod
    def capabilities(cls) -> Capabilities:
        """What the conformance suite holds it to. Not the network: unmeasured."""
        return Capabilities(
            confines_filesystem=True,
            confines_network=False,
            enforces_resource_limits=True,
            kills_process_tree=True,
            strips_environment=True,
        )

    def argv(self, name: str, command: list[str]) -> list[str]:
        """The exact `podman run` line. Public so a test can hold every flag."""
        limits = self.profile.resources
        workspace = str(self.workspace)
        line = [
            shutil.which(RUNTIME) or RUNTIME,
            "run",
            "--rm",
            "--name",
            name,
            "--pull=never",
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/tmp",  # noqa: S108 - the container's own /tmp, in memory, not the host's
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit",
            str(limits.max_processes),
            "--memory",
            f"{limits.memory_mb}m",
            "--cpus",
            f"{max(limits.cpu_percent, 1) / 100:.2f}",
            "--volume",
            f"{workspace}:{workspace}:rw",
            "--workdir",
            workspace,
        ]
        for key, value in sorted(child_env().items()):
            line += ["--env", f"{key}={value}"]
        return [*line, IMAGE, *command]

    def run(self, command: list[str], *, timeout: float | None = None) -> LaunchResult:
        if not command:
            raise self.refuse(command, "container refuses an empty command")
        limit = timeout if timeout is not None else self.profile.resources.wall_clock_seconds
        context_id = f"c{uuid.uuid4().hex[:16]}"
        name = container_name(context_id)
        line = self.argv(name, command)

        # Journalled before it exists: an entry with no container is a no-op to revert.
        record(HostChange(context_id=context_id, kind="container", profile=name))
        self.recorder.launching(
            command=command,
            backend=self.backend,
            profile=self.profile,
            workspace=str(self.workspace),
        )
        removed = False
        try:
            try:
                done = subprocess.run(  # noqa: S603 - the runtime, with the line above
                    line,
                    capture_output=True,
                    text=True,
                    timeout=limit,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                result = LaunchResult(
                    exit_code=None,
                    timed_out=True,
                    killed_by_limit=True,
                    backend=self.backend,
                    diagnostics={"container": name, "limit_seconds": str(limit)},
                )
            else:
                result = LaunchResult(
                    exit_code=done.returncode,
                    stdout=done.stdout,
                    stderr=done.stderr,
                    backend=self.backend,
                    diagnostics={"container": name},
                )
            self.recorder.finished(command=command, result=result)
            return result
        finally:
            removed = _remove(name)
            if removed:
                forget(context_id)


def _remove(name: str) -> bool:
    """Remove the container, running or not. True when it is gone.

    `--force` stops it first, which kills every process in it: the container is the
    tree. `--ignore` makes "already gone" a success. Anything else keeps the journal
    entry, so panic tries again.
    """
    runtime = shutil.which(RUNTIME)
    if runtime is None:
        return False
    try:
        gone = subprocess.run(  # noqa: S603 - the runtime, removing our own container
            [runtime, "rm", "--force", "--ignore", name],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return gone.returncode == 0
