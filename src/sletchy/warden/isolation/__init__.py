"""Isolation backends - one interface, several substrates.

See [ADR-0002](../../../../docs/adr/0002-pluggable-isolation-backends.md) for why
this is an interface rather than a vendor, and
[ADR-0005](../../../../docs/adr/0005-appcontainer-findings.md) for what was
measured about `winjob`'s substrate.

Shipped today: `inproc` (no isolation, tests only), `subproc` (weak),
**`winjob`**, which provides real, kernel-enforced containment on Windows - of the
filesystem, of resources, and of the process tree - and **`container`**, a rootless
Podman container on Linux only (ADR-0014). Neither claims to confine the network:
that claim needs its own measurement.
"""

from sletchy.warden.isolation.base import (
    BackendUnavailable,
    Capabilities,
    IsolationError,
    LaunchRefused,
    LaunchResult,
    Sandbox,
)
from sletchy.warden.isolation.container import ContainerSandbox
from sletchy.warden.isolation.inproc import InProcSandbox
from sletchy.warden.isolation.recorder import SandboxRecorder
from sletchy.warden.isolation.registry import BACKENDS, available_backends, select
from sletchy.warden.isolation.subproc import SubprocSandbox
from sletchy.warden.isolation.winjob import WinJobSandbox

__all__ = [
    "BACKENDS",
    "BackendUnavailable",
    "Capabilities",
    "ContainerSandbox",
    "InProcSandbox",
    "IsolationError",
    "LaunchRefused",
    "LaunchResult",
    "Sandbox",
    "SandboxRecorder",
    "SubprocSandbox",
    "WinJobSandbox",
    "available_backends",
    "select",
]
