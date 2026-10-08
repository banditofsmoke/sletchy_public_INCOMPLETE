"""The isolation interface - one contract, several substrates.

[ADR-0002](../../../../docs/adr/0002-pluggable-isolation-backends.md): isolation is
an interface, not a vendor. On a stock Windows machine with nothing installed,
`winjob` gives real containment; Docker/Podman is an optional accelerator.

Three rules make this a ladder rather than a loophole:

1. **Policy declares a minimum per capability.** "Egress requires ≥ `winjob`."
2. **If the minimum is unavailable, the capability does not run.** `select()` raises.
   It never silently returns something weaker - a downgrade-on-missing-dependency is
   how isolation quietly becomes decorative.
3. **Backends are tested against one shared conformance suite** that asserts
   *behaviour* - this write is refused, this connection is refused - never
   implementation. Each declares what it can and cannot do, and the suite holds it
   to exactly that.

A backend that overclaims fails the suite. A backend that underclaims still runs,
which is the safe direction.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import IsolationBackend

if TYPE_CHECKING:
    from pathlib import Path

    from sletchy.kernel.contracts import IsolationProfile
    from sletchy.warden.isolation.recorder import SandboxRecorder


class IsolationError(Exception):
    """Base for isolation failures."""


class BackendUnavailable(IsolationError):
    """The requested backend cannot run here.

    Fatal by design. The capability does not run, and nothing weaker is substituted.
    """


class LaunchRefused(IsolationError):
    """The backend refused to start the process."""


@dataclass(frozen=True)
class Capabilities:
    """What a backend honestly claims to enforce.

    Every field defaults to **False**: a new backend claims nothing until it says
    otherwise, so forgetting to declare something under-claims rather than
    over-claims. The conformance suite reads these and asserts each claim, so a
    backend cannot pass by declaring itself strong.
    """

    #: Reads and writes outside the workspace are refused.
    confines_filesystem: bool = False
    #: Outbound connections are refused unless explicitly allowed.
    confines_network: bool = False
    #: Memory / CPU / wall-clock ceilings are applied before the process starts.
    enforces_resource_limits: bool = False
    #: Killing the sandbox kills every descendant.
    kills_process_tree: bool = False
    #: The child receives an allowlisted environment, not the parent's.
    strips_environment: bool = False

    def satisfies(self, required: Capabilities) -> tuple[bool, tuple[str, ...]]:
        """Whether this backend covers everything `required` asks for."""
        missing = tuple(
            name
            for name in (
                "confines_filesystem",
                "confines_network",
                "enforces_resource_limits",
                "kills_process_tree",
                "strips_environment",
            )
            if getattr(required, name) and not getattr(self, name)
        )
        return (not missing, missing)


@dataclass(frozen=True)
class LaunchResult:
    """The outcome of running something in a sandbox.

    Reports the exit code and whether the sandbox itself intervened. `timed_out` and
    `killed_by_limit` are separate from a non-zero exit on purpose: "the program
    failed" and "we stopped the program" are different events, and only one of them
    is a signal.
    """

    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    killed_by_limit: bool = False
    backend: IsolationBackend = IsolationBackend.INPROC
    diagnostics: dict[str, str] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.killed_by_limit


class Sandbox(ABC):
    """One isolation substrate.

    Implementations are constructed with a workspace, a profile, and a **required**
    recorder, and must apply every limit **before** the process starts. Applying
    them afterwards is a race, and a race in a security boundary is a vulnerability
    ([LAW 0 §5](../../../../docs/LAW/00-do-no-harm.md)).

    **The recorder has no default.** A sandbox that could be constructed without a
    ledger is a launch path that can skip the ledger, and [LAW 1](../../../../docs/LAW/laws.md#law-1)
    does not have an exception for convenience. Making it a required keyword means
    the failure is a `TypeError` at construction rather than a missing entry
    discovered during an incident.
    """

    #: The rung this backend occupies.
    backend: IsolationBackend

    def __init__(
        self,
        workspace: Path,
        profile: IsolationProfile,
        *,
        recorder: SandboxRecorder,
    ) -> None:
        self.workspace = workspace
        self.profile = profile
        self.recorder = recorder

    def refuse(self, command: list[str], reason: str) -> LaunchRefused:
        """Record a refusal and return the exception to raise.

        Returns rather than raises so the caller writes `raise self.refuse(...)`,
        which keeps the control flow visible at the call site instead of hiding a
        raise inside a helper. Every refusal path goes through here, so none of
        them can quietly forget to record.
        """
        self.recorder.refused(command=command, reason=reason)
        return LaunchRefused(reason)

    @classmethod
    @abstractmethod
    def available(cls) -> bool:
        """Whether this backend can run on this host, right now."""

    @classmethod
    @abstractmethod
    def capabilities(cls) -> Capabilities:
        """What this backend honestly enforces. The conformance suite checks each."""

    @abstractmethod
    def run(self, command: list[str], *, timeout: float | None = None) -> LaunchResult:
        """Run `command` inside the sandbox and return what happened."""

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Release anything the sandbox created. Must be safe to call repeatedly.

        Not abstract: a backend that creates nothing has nothing to release, and
        forcing it to write an empty override would make the no-op look deliberate
        in one place and accidental in another.
        """
        return
