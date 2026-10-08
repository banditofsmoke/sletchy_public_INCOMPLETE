"""The flag registry - one switchboard, and the flags Sletchy actually ships.

LAW 8 is enforced twice, deliberately. `Flag`'s own validator (from #1) refuses a
DANGEROUS flag that defaults on, and `FlagRegistry` re-checks the whole set at
construction. One check is a rule; two independent checks is a control - the second
catches a flag that reaches the registry without going through the constructor
(loaded from a future config format, say).

This registry is the **only** source of flag definitions. The CLI listing and the
desktop flag panel are generated from it. A hand-written flag list somewhere else is
a list that will drift.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sletchy.kernel.contracts import Flag, FlagRisk
from sletchy.kernel.flags.errors import FlagRegistryInvalid, UnknownFlag

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Everything Sletchy can be told to do that it will not do unless told.
#:
#: Names use underscores because `Name` forbids dots - dots are reserved for
#: actions, where they carry prefix-matching meaning.
DEFAULT_FLAGS: tuple[Flag, ...] = (
    # ── network ──────────────────────────────────────────────────────────────
    Flag(
        name="egress_enabled",
        label="Internet access",
        serves=("time", "connection"),
        risk=FlagRisk.DANGEROUS,
        description="Allow any outbound network connection through the Warden proxy.",
    ),
    Flag(
        name="egress_hosted_models",
        label="Online AI models",
        serves=("time",),
        risk=FlagRisk.DANGEROUS,
        description="Allow calls to hosted model endpoints. Prompts leave the bubble.",
    ),
    # ── filesystem ───────────────────────────────────────────────────────────
    Flag(
        name="fs_outside_var",
        label="Your files",
        serves=("time",),
        risk=FlagRisk.DANGEROUS,
        description="Allow reads or writes outside var/. Off means Sletchy cannot touch your files.",
    ),
    # ── senses ───────────────────────────────────────────────────────────────
    Flag(
        name="senses_microphone",
        label="Microphone",
        serves=("time", "connection"),
        risk=FlagRisk.DANGEROUS,
        description="Allow microphone capture. Emits a ledger event whenever active.",
    ),
    Flag(
        name="senses_camera",
        label="Camera",
        serves=("connection",),
        risk=FlagRisk.DANGEROUS,
        description="Allow camera capture. Emits a ledger event whenever active.",
    ),
    Flag(
        name="senses_screen",
        label="Screen capture",
        serves=("time",),
        risk=FlagRisk.DANGEROUS,
        description="Allow screen capture. Emits a ledger event whenever active.",
    ),
    # ── forge and vault ──────────────────────────────────────────────────────
    Flag(
        name="forge_training",
        label="Model training",
        serves=("time", "money"),
        risk=FlagRisk.DANGEROUS,
        description="Allow model training runs. Resource-capped; can thermally load the host.",
    ),
    Flag(
        name="vault_deploy_testnet",
        label="Test-network contracts",
        serves=("money",),
        risk=FlagRisk.DANGEROUS,
        description="Allow contract deployment to a test network.",
    ),
    Flag(
        name="vault_deploy_mainnet",
        label="Live-network contracts",
        serves=("money",),
        risk=FlagRisk.DANGEROUS,
        description="Allow contract deployment to a live network. Real value at risk.",
    ),
    # ── SOC ──────────────────────────────────────────────────────────────────
    Flag(
        name="honeypot_enabled",
        label="Decoy traps",
        serves=("safety",),
        risk=FlagRisk.DANGEROUS,
        description="Run honeypot listeners. Loopback only unless the bind flag is also on.",
    ),
    Flag(
        name="honeypot_bind_beyond_loopback",
        label="Decoy traps on the network",
        serves=("safety",),
        risk=FlagRisk.DANGEROUS,
        description=(
            "Expose honeypots beyond loopback. A honeypot reachable from a network is an "
            "invitation, and possibly a legal problem. Read LAW 0 section 4 first."
        ),
    ),
    Flag(
        name="soc_auto_freeze",
        label="Automatic lockdown",
        serves=("safety",),
        risk=FlagRisk.ELEVATED,
        description="Let the SOC revoke an actor's capabilities automatically on a high-confidence signal.",
    ),
    Flag(
        name="soc_watch_machine",
        label="Watch the whole PC",
        serves=("safety",),
        risk=FlagRisk.DANGEROUS,
        wired=True,
        description=(
            "Let the SOC look at every process and connection on this machine, not only "
            "Sletchy's own. A record of everything you run is sensitive in itself (ADR-0011)."
        ),
    ),
    # ── local compute ────────────────────────────────────────────────────────
    Flag(
        name="mind_local_models",
        label="Local AI models",
        serves=("time",),
        risk=FlagRisk.ELEVATED,
        wired=True,
        description=(
            "Let Sletchy ask a model server on this computer (Ollama today), through one "
            "local port. Every question and answer is recorded. Nothing leaves the machine."
        ),
    ),
    Flag(
        name="mind_memory",
        label="Memory",
        serves=("time",),
        risk=FlagRisk.ELEVATED,
        wired=True,
        description=(
            "Let Sletchy keep what was said and documents you add, under var/, and search "
            "them by words and by meaning. Every add, search and forget is recorded."
        ),
    ),
    Flag(
        name="mind_memory_rollups",
        label="Memory summaries",
        serves=("time",),
        risk=FlagRisk.ELEVATED,
        description="Build hourly/daily/monthly memory digests from interaction history.",
    ),
    # ── cosmetic ─────────────────────────────────────────────────────────────
    Flag(
        name="cli_colour",
        label="Coloured terminal text",
        serves=("time",),
        risk=FlagRisk.SAFE,
        default=True,
        description="Colourise CLI output.",
    ),
    Flag(
        name="cli_verbose",
        label="Explain every decision",
        serves=("safety",),
        risk=FlagRisk.SAFE,
        description="Print policy reasoning alongside every decision.",
    ),
)


class FlagRegistry:
    """The declared flags. Immutable, enumerable, and the only definition source."""

    __slots__ = ("_by_name",)

    def __init__(self, flags: tuple[Flag, ...] = DEFAULT_FLAGS) -> None:
        by_name: dict[str, Flag] = {}
        for flag in flags:
            if flag.name in by_name:
                msg = f"duplicate flag {flag.name!r}"
                raise FlagRegistryInvalid(msg)
            # Belt and braces over Flag's own validator - see the module docstring.
            if flag.risk is FlagRisk.DANGEROUS and flag.default:
                msg = (
                    f"flag {flag.name!r} is DANGEROUS and defaults on; LAW 8 requires "
                    "a fresh install to be inert"
                )
                raise FlagRegistryInvalid(msg)
            by_name[flag.name] = flag
        self._by_name = by_name

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def __len__(self) -> int:
        return len(self._by_name)

    def __iter__(self) -> Iterator[Flag]:
        return iter(sorted(self._by_name.values(), key=lambda f: f.name))

    def get(self, name: str) -> Flag:
        """Look up a declared flag, or raise.

        Raising rather than returning `None` means a caller cannot accidentally
        treat an unknown flag as a disabled one and carry on.
        """
        try:
            return self._by_name[name]
        except KeyError as exc:
            msg = (
                f"unknown flag {name!r}. Flags are declared in "
                "sletchy.kernel.flags.registry.DEFAULT_FLAGS; there are no ad-hoc flags."
            )
            raise UnknownFlag(msg) from exc

    def dangerous(self) -> tuple[Flag, ...]:
        return tuple(f for f in self if f.risk is FlagRisk.DANGEROUS)

    def defaults(self) -> dict[str, bool]:
        return {f.name: f.default for f in self}
