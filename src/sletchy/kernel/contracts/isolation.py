"""What a capability declares it needs, and the ladder it runs on.

LAW 3 lives here in code: `IsolationProfile.tighten` is the only merge offered, and
it raises rather than returning a wider profile. There is no `loosen`, and adding
one would be a security regression, not a feature.

See docs/LAW/isolation.md and ADR-0002.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from sletchy.kernel.contracts.base import Contract

#: Sandbox context ids. Deliberately narrower than `Name`: these become Windows
#: AppContainer profile names, so the alphabet is restricted to what that API
#: accepts, and a leading letter keeps the name valid whatever the id.
CONTEXT_ID_PATTERN = r"^[a-z][a-z0-9]{1,31}$"
ContextId = Annotated[str, Field(pattern=CONTEXT_ID_PATTERN)]

#: The AppContainer names a sandbox runs under, one run per lane at a time (#33,
#: ADR-0013). A fixed set, because a firewall rule names a container by its SID and
#: Windows derives that SID from the name: with a new name for every run there is no
#: SID to write a rule for before the run starts. Here because the Warden claims
#: lanes and `sletchy panic` and `sletchy install-rules` name them, and neither of
#: those may import the Warden.
SANDBOX_LANES: tuple[str, ...] = tuple(f"Sletchy-lane{n}" for n in range(8))


def lane_lock_name(lane: str) -> str:
    """The named mutex a run holds for as long as it uses `lane`.

    `Local\\` is this logon session's namespace. A contained process has its own,
    so nothing inside a sandbox can take or hold a lane.
    """
    return f"Local\\{lane}"


# Ladder order. Higher is stronger; a tighten picks the higher.
_STRENGTH: dict[str, int] = {
    "inproc": 0,
    "subproc": 1,
    "winjob": 2,
    "container": 3,
    "vm": 4,
}


class IsolationBackend(StrEnum):
    """The isolation ladder - ADR-0002.

    `INPROC` provides no isolation at all and refuses to load outside a test run.
    It exists so tests can exercise the interface, not so production can fall back
    to it.
    """

    INPROC = "inproc"
    SUBPROC = "subproc"
    WINJOB = "winjob"
    CONTAINER = "container"
    VM = "vm"

    @property
    def strength(self) -> int:
        return _STRENGTH[self.value]

    def satisfies(self, minimum: IsolationBackend) -> bool:
        """True when this backend is at least as strong as `minimum`.

        A capability whose minimum cannot be met does not run. It never silently
        downgrades - that rule is what keeps the ladder from being a loophole.
        """
        return self.strength >= minimum.strength


class ResourceLimits(Contract):
    """Ceilings applied *before* a process starts.

    Applying limits after launch is a race, and a race in a security boundary is a
    vulnerability. Defaults come from LAW 0 §5.
    """

    memory_mb: Annotated[int, Field(ge=16, le=32_768)] = 2048
    cpu_percent: Annotated[int, Field(ge=1, le=100)] = 50
    wall_clock_seconds: Annotated[int, Field(ge=1, le=86_400)] = 300
    max_processes: Annotated[int, Field(ge=1, le=256)] = 16
    max_output_bytes: Annotated[int, Field(ge=1024, le=1_073_741_824)] = 10_485_760

    def tighten(self, other: ResourceLimits) -> ResourceLimits:
        """Per-field minimum. Every dimension can only shrink."""
        return ResourceLimits(
            memory_mb=min(self.memory_mb, other.memory_mb),
            cpu_percent=min(self.cpu_percent, other.cpu_percent),
            wall_clock_seconds=min(self.wall_clock_seconds, other.wall_clock_seconds),
            max_processes=min(self.max_processes, other.max_processes),
            max_output_bytes=min(self.max_output_bytes, other.max_output_bytes),
        )


class FilesystemMount(Contract):
    """One path a capability may see, and how."""

    path: Annotated[str, Field(min_length=1, max_length=4096)]
    access: Literal["ro", "rw"] = "ro"
    ephemeral: bool = True
    max_size_mb: Annotated[int, Field(ge=1, le=1_048_576)] = 512

    def tighten(self, other: FilesystemMount) -> FilesystemMount:
        if self.path != other.path:
            msg = f"cannot merge mounts for different paths: {self.path!r} vs {other.path!r}"
            raise ValueError(msg)
        return FilesystemMount(
            path=self.path,
            # ro is stricter than rw.
            access="ro" if "ro" in (self.access, other.access) else "rw",
            ephemeral=self.ephemeral or other.ephemeral,
            max_size_mb=min(self.max_size_mb, other.max_size_mb),
        )


class NetworkPolicy(Contract):
    """Where a capability may reach. Deny-all is the default and stays the default."""

    #: Hostnames, exact or single trailing `*`. Empty means no egress at all.
    allow_egress: tuple[str, ...] = ()
    allow_ports: tuple[int, ...] = (443,)
    deny_all_by_default: Literal[True] = True

    @model_validator(mode="after")
    def _ports_are_valid(self) -> Self:
        for port in self.allow_ports:
            if not 1 <= port <= 65535:
                msg = f"port {port} out of range"
                raise ValueError(msg)
        return self

    def tighten(self, other: NetworkPolicy) -> NetworkPolicy:
        """Intersection. A destination must be permitted by *both* sides."""
        return NetworkPolicy(
            allow_egress=tuple(sorted(set(self.allow_egress) & set(other.allow_egress))),
            allow_ports=tuple(sorted(set(self.allow_ports) & set(other.allow_ports))),
        )


class IsolationProfile(Contract):
    """The full declaration: backend, filesystem, network, resources.

    Declared by a capability, tightened by policy, enforced by the Warden. Three
    different components - a component that enforces its own limits is enforcing
    nothing (LAW 3).
    """

    backend: IsolationBackend = IsolationBackend.WINJOB
    mounts: tuple[FilesystemMount, ...] = ()
    network: NetworkPolicy = NetworkPolicy()
    resources: ResourceLimits = ResourceLimits()

    @model_validator(mode="after")
    def _mount_paths_are_unique(self) -> Self:
        paths = [m.path for m in self.mounts]
        if len(paths) != len(set(paths)):
            msg = "duplicate mount paths; each path may be declared once"
            raise ValueError(msg)
        return self

    def tighten(self, other: IsolationProfile) -> IsolationProfile:
        """Merge two profiles, keeping the stricter of every dimension.

        Mounts intersect by path: a path either side omits is dropped entirely,
        because "policy did not mention it" must never mean "policy allowed it".
        """
        mine = {m.path: m for m in self.mounts}
        theirs = {m.path: m for m in other.mounts}
        shared = sorted(set(mine) & set(theirs))

        return IsolationProfile(
            backend=(
                self.backend if self.backend.strength >= other.backend.strength else other.backend
            ),
            mounts=tuple(mine[p].tighten(theirs[p]) for p in shared),
            network=self.network.tighten(other.network),
            resources=self.resources.tighten(other.resources),
        )

    def is_tighter_than_or_equal_to(self, other: IsolationProfile) -> bool:
        """True when this profile grants no more than `other` on any dimension.

        The Warden asserts this before enforcing a merged profile. If it is ever
        False, a merge widened something and the capability must not start.
        """
        return (
            self.backend.strength >= other.backend.strength
            and set(self.network.allow_egress) <= set(other.network.allow_egress)
            and set(self.network.allow_ports) <= set(other.network.allow_ports)
            and self.resources.memory_mb <= other.resources.memory_mb
            and self.resources.cpu_percent <= other.resources.cpu_percent
            and self.resources.wall_clock_seconds <= other.resources.wall_clock_seconds
            and self.resources.max_processes <= other.resources.max_processes
            and {m.path for m in self.mounts} <= {m.path for m in other.mounts}
        )


class HostChange(Contract):
    """The reversible host changes made for one sandboxed execution.

    Written by the Warden, read by `sletchy panic`, and defined here because
    neither may import the other and a schema two planes disagree about is not a
    schema (LAW 6). It sits beside `IsolationProfile` for the same reason that
    does: the isolation vocabulary is shared, so the Kernel owns it.

    One record per execution rather than one per change - the changes share a
    lifetime and are reverted together, and a partial revert is not a state worth
    representing.

    **This is not a ledger entry.** It carries only what a revert needs, and it is
    readable without a signing key precisely because `panic` has to work when
    everything else is broken.
    """

    context_id: ContextId
    #: The AppContainer profile to delete. Empty when none was created.
    profile: str = ""
    #: The profile's SID, as a string. That is what an ACE names, so it is what a
    #: revoke needs - the profile may already be gone by the time panic runs.
    sid: str = ""
    #: Directories granted to `sid`, to be revoked. Order is not significant.
    granted_paths: tuple[str, ...] = ()

    #: `sandbox` is a `winjob` run: `profile` is its AppContainer. `container` is a
    #: `container` run (#70): `profile` is the container's name, and it has no SID
    #: and no grants.
    kind: Literal["sandbox", "container"] = "sandbox"
