"""Sletchy checks itself - the evidence behind the trust meter.

The meter on the desktop shows one number. **That number is only ever the sum of what
was proven in this run.** Nothing is remembered from an earlier check and nothing is
taken on trust from a design document. A check that has not been measured on this
machine scores zero rather than being assumed, so the meter cannot reach 100 while any
control is unbuilt or unmeasured, and the reason is printed beside it.

It is observation, not enforcement: it reads the ledger, the flags, the host-change
journal, the process token and the `Sletchy` firewall rules, and changes none of them.
It imports the Kernel, and the rule reader beside it in the Shell, which needs no
administrator to look (#33).

**Why `cli/` and not `soc/`.** Observation is the SOC's job, and this began there. But
`test_import_layers.py` forbids `cli` importing `soc`, while `architecture.md` says the
Shell talks to the SOC. Those two disagree, and the place to settle that is its own
issue - not by loosening a guard in the change that wanted past it. Everything here
needs only the Kernel, so it lives with the operator surface until that is decided.

**What it cannot prove is part of its output**, not a footnote (`DOES_NOT_PROVE`).
A self-check runs as the user, on the user's machine. Anything that already controls
that account could fake every line of it.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import Field

from sletchy.cli import rules as rules_mod
from sletchy.kernel import paths
from sletchy.kernel.contracts import SANDBOX_LANES, Contract, Name
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.hostchanges import pending, unreadable
from sletchy.kernel.ledger import (
    KeyringKeySource,
    Ledger,
    LedgerCorrupt,
    LedgerError,
    LedgerMissing,
    SigningKeyMissing,
)

Status = Literal["pass", "warn", "fail", "unmeasured"]

#: How much of a check's weight each status earns. A warning is a choice the operator
#: made (a dangerous switch turned on) or a mess panic can clean; it costs half.
#: Unmeasured earns nothing: an unknown is not half-safe.
EARNS: dict[Status, float] = {"pass": 1.0, "warn": 0.5, "fail": 0.0, "unmeasured": 0.0}

#: The Windows build `winjob`'s filesystem containment was measured on (ADR-0005).
#: Another build may behave differently, and the check says so rather than assuming.
MEASURED_WINDOWS_BUILD = 19045

#: LAW 0 §5: the disk ceiling for everything under `var/`.
VAR_QUOTA_BYTES = 5 * 1024**3

DOES_NOT_PROVE: tuple[str, ...] = (
    "It runs on this computer, as you. Something that already controls your Windows "
    "account could fake every check on this page.",
    "It checks Sletchy, not the rest of your computer. It is not an antivirus.",
    "A check that passes now says nothing about a minute from now. Open it again to check again.",
)


class Check(Contract):
    """One thing Sletchy checked about itself, just now."""

    id: Name
    label: Annotated[str, Field(min_length=1, max_length=48)]
    status: Status
    weight: Annotated[int, Field(ge=1, le=100)]
    #: One sentence a non-technical person can act on.
    plain: Annotated[str, Field(min_length=1, max_length=240)]
    #: The technical fact behind it, for the people who want it.
    detail: Annotated[str, Field(max_length=400)] = ""


class SelfCheck(Contract):
    """Every check, and the score they add up to."""

    checked_at: datetime
    score: Annotated[int, Field(ge=0, le=100)]
    #: The highest score possible right now: the weight of every check that could be
    #: measured. While network containment is unbuilt this is below 100, and the UI
    #: says why instead of implying the gap is the operator's fault.
    ceiling: Annotated[int, Field(ge=0, le=100)]
    checks: tuple[Check, ...]
    does_not_prove: tuple[str, ...]


def _default_open_ledger() -> Ledger:
    return Ledger.open(paths.ledger_dir(), KeyringKeySource(), create=False)


def is_elevated() -> bool:
    """True when this process runs as an administrator (or root)."""
    if sys.platform == "win32":
        import ctypes

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.IsUserAnAdmin.argtypes = []
        shell32.IsUserAnAdmin.restype = ctypes.c_int  # L004: always set restype
        return bool(shell32.IsUserAnAdmin())
    return hasattr(os, "geteuid") and os.geteuid() == 0


def windows_build() -> int | None:
    if sys.platform != "win32":
        return None
    return sys.getwindowsversion().build


def _var_bytes() -> int:
    root = paths.home()
    total = 0
    if root.is_dir():
        for path in root.rglob("*"):
            try:
                if path.is_file():
                    total += path.stat().st_size
            except OSError:
                continue
    return total


def check_ledger(open_ledger: Callable[[], Ledger]) -> tuple[Check, Ledger | None]:
    weight = 30
    try:
        ledger = open_ledger()  # Ledger.open verifies before it returns
        entries = ledger.length
    except LedgerMissing:
        return Check(
            id="ledger",
            label="Sletchy's record",
            status="fail",
            weight=weight,
            plain="Sletchy is not set up in this folder.",
            detail=f"no ledger at {paths.ledger_dir()}; run `sletchy init` here, or set "
            "SLETCHY_HOME to where Sletchy lives",
        ), None
    except SigningKeyMissing:
        return Check(
            id="ledger",
            label="Sletchy's record",
            status="fail",
            weight=weight,
            plain="Sletchy has not been set up on this computer yet.",
            detail="no ledger signing key in the OS keychain; run `sletchy init`",
        ), None
    except LedgerCorrupt as exc:
        return Check(
            id="ledger",
            label="Sletchy's record",
            status="fail",
            weight=weight,
            plain=(
                "Sletchy's record was changed by something other than Sletchy. It will "
                "not run until someone looks at this."
            ),
            detail=f"{type(exc).__name__}: {exc}"[:400],
        ), None
    except (LedgerError, OSError) as exc:
        return Check(
            id="ledger",
            label="Sletchy's record",
            status="fail",
            weight=weight,
            plain="Sletchy could not read its own record.",
            detail=f"{type(exc).__name__}: {exc}"[:400],
        ), None
    return Check(
        id="ledger",
        label="Sletchy's record",
        status="pass",
        weight=weight,
        plain="Sletchy's record of everything it has done is intact.",
        detail=f"{entries} entries, every signature and chain link verified",
    ), ledger


def check_switches(ledger: Ledger | None) -> Check:
    weight = 15
    if ledger is None:
        return Check(
            id="switches",
            label="Dangerous switches",
            status="unmeasured",
            weight=weight,
            plain="Sletchy could not read its switches, because its record is unavailable.",
            detail="flag state is read through the ledger",
        )
    store = FlagStore.open(ledger, paths.flags_file())
    if store.unexplained:
        return Check(
            id="switches",
            label="Dangerous switches",
            status="fail",
            weight=weight,
            plain=(
                "Something turned on a dangerous switch without Sletchy recording it. "
                "Sletchy is treating it as off."
            ),
            detail=f"on in flags.json with no ledger entry: {', '.join(store.unexplained)}"[:400],
        )
    on = [f for f in store.registry.dangerous() if store.is_on(f.name)]
    if not on:
        return Check(
            id="switches",
            label="Dangerous switches",
            status="pass",
            weight=weight,
            plain="Every dangerous switch is off.",
            detail=f"{len(store.registry.dangerous())} dangerous flags, all at their default",
        )
    names = ", ".join(f.label or f.name for f in on)
    return Check(
        id="switches",
        label="Dangerous switches",
        status="warn",
        weight=weight,
        plain=f"You turned on {len(on)} dangerous switch{'es' if len(on) > 1 else ''}: {names}."[
            :240
        ],
        detail=", ".join(f.name for f in on)[:400],
    )


def check_privilege(elevated: Callable[[], bool]) -> Check:
    weight = 15
    if elevated():
        return Check(
            id="privilege",
            label="Runs as a normal user",
            status="fail",
            weight=weight,
            plain="Sletchy is running as an administrator. It never should; close it and "
            "start it normally.",
            detail="process token is elevated (LAW 0 section 3)",
        )
    return Check(
        id="privilege",
        label="Runs as a normal user",
        status="pass",
        weight=weight,
        plain="Sletchy is running as a normal user, with no extra power over this computer.",
        detail="process token is not elevated (LAW 0 section 3)",
    )


def check_file_containment(build: int | None) -> Check:
    weight = 15
    if build == MEASURED_WINDOWS_BUILD:
        return Check(
            id="files",
            label="Keeps programs out of your files",
            status="pass",
            weight=weight,
            plain="Programs Sletchy runs cannot reach your files. This was measured on "
            "this version of Windows.",
            detail=f"winjob filesystem denial measured on build {build} (ADR-0005)",
        )
    where = f"build {build}" if build is not None else "this operating system"
    return Check(
        id="files",
        label="Keeps programs out of your files",
        status="unmeasured",
        weight=weight,
        plain="Nobody has measured whether Sletchy keeps programs out of your files on "
        "this version of Windows yet.",
        detail=f"measured on build {MEASURED_WINDOWS_BUILD}; this is {where}",
    )


def _read_firewall() -> list[str]:
    """How the `Sletchy` rules differ from the plan; empty means exactly as planned.

    Read-only and unelevated. Raises `OSError` when it cannot look, which is never read
    as "nothing there" (L009). Every test replaces it (`tests/conftest.py`), so no test
    reads this machine's firewall.
    """
    return rules_mod.check(rules_mod.plan(), rules_mod.read_rules())


def _host_firewall() -> Callable[[], list[str]] | None:
    """The firewall reader for this machine, or None where there are no rules to read."""
    return _read_firewall if sys.platform == "win32" else None


def check_network_containment(read: Callable[[], list[str]] | None) -> Check:
    """The rules are reported; the network is not claimed.

    A missing or changed rule set fails, because a lock is off and only an administrator
    can put it back. A complete set stays unmeasured, not passed: it is measured to refuse
    TCP and UDP over IPv4 (ADR-0006 findings 8 and 9), but IPv6 is not measured (#173),
    and loopback reaches every service on this machine.
    """
    weight = 15
    label = "Keeps programs off the internet"
    if read is None:
        return Check(
            id="network",
            label=label,
            status="unmeasured",
            weight=weight,
            plain="Nobody has measured whether Sletchy keeps programs off the network on "
            "this operating system.",
            detail="the sandbox firewall rules exist on Windows only (ADR-0013)",
        )
    try:
        problems = read()
    except OSError as exc:
        return Check(
            id="network",
            label=label,
            status="unmeasured",
            weight=weight,
            plain="Sletchy could not read its firewall rules, so it cannot say whether they "
            "are in place.",
            detail=f"could not look, which is not the same as nothing there (L009): {exc}"[:400],
        )
    if problems:
        missing = [p for p in problems if p.endswith(": missing")]
        if len(missing) == len(problems) == len(SANDBOX_LANES):
            plain = (
                "Sletchy's firewall rules are not installed, so a program it runs has one "
                "lock against the network instead of two. An administrator can add them "
                "with sletchy install-rules."
            )
        else:
            plain = (
                "Sletchy's firewall rules are not as planned: something changed or removed "
                "them. sletchy install-rules --check says what, and an administrator can "
                "put them back."
            )
        return Check(
            id="network",
            label=label,
            status="fail",
            weight=weight,
            plain=plain,
            detail="; ".join(problems)[:400],
        )
    return Check(
        id="network",
        label=label,
        status="unmeasured",
        weight=weight,
        plain="Sletchy's firewall rules are in place, and keep the programs it runs off other "
        "computers over TCP and UDP. IPv6 is not measured yet, and they can still reach this "
        "computer's own services.",
        detail=f"{len(SANDBOX_LANES)} of {len(SANDBOX_LANES)} rules as planned; TCP and UDP over "
        "IPv4 refused by the container and the rules (ADR-0006 findings 5, 8 and 9); IPv6 "
        "unmeasured (#173) and loopback open, so winjob claims no confines_network",
    )


def check_leftovers() -> Check:
    left = len(pending())
    unread = len(unreadable())
    if not left and not unread:
        return Check(
            id="leftovers",
            label="Nothing left behind",
            status="pass",
            weight=5,
            plain="Sletchy has no unfinished changes on this computer.",
            detail="host-change journal is empty",
        )
    said = []
    if left:
        said.append(
            f"{left} change{'s' if left > 1 else ''} Sletchy made to this computer "
            "were not undone. Press Stop everything to clean up."
        )
    if unread:
        # Could not read is not nothing there (L009, #103): the line may be a change.
        said.append(
            f"{unread} line{'s' if unread > 1 else ''} of its undo list could not be "
            "read, so Sletchy cannot say nothing was left behind."
        )
    return Check(
        id="leftovers",
        label="Nothing left behind",
        status="warn",
        weight=5,
        plain=" ".join(said),
        detail=f"{left} entries and {unread} unreadable lines in the host-change journal",
    )


def check_disk(used: int) -> Check:
    share = used / VAR_QUOTA_BYTES
    status: Status = "pass" if share < 0.8 else "warn" if share < 1 else "fail"
    plain = {
        "pass": "Sletchy is well inside the disk space it is allowed.",
        "warn": "Sletchy is close to the disk space it is allowed.",
        "fail": "Sletchy is over the disk space it is allowed.",
    }[status]
    return Check(
        id="disk",
        label="Stays inside its disk space",
        status=status,
        weight=5,
        plain=plain,
        detail=f"{used} of {VAR_QUOTA_BYTES} bytes under {paths.home()} (LAW 0 section 5)",
    )


def run_selfcheck(
    *,
    open_ledger: Callable[[], Ledger] = _default_open_ledger,
    elevated: Callable[[], bool] = is_elevated,
    build: Callable[[], int | None] = windows_build,
    var_bytes: Callable[[], int] = _var_bytes,
    firewall: Callable[[], list[str]] | Literal["host"] | None = "host",
) -> SelfCheck:
    """Check everything that can be checked right now, and add it up.

    The seams exist for tests; production passes nothing and gets the real host.
    `firewall` is looked up when called, not when defined, so a test's stub holds.
    """
    read = _host_firewall() if firewall == "host" else firewall
    ledger_check, ledger = check_ledger(open_ledger)
    checks = (
        ledger_check,
        check_switches(ledger),
        check_privilege(elevated),
        check_file_containment(build()),
        check_network_containment(read),
        check_leftovers(),
        check_disk(var_bytes()),
    )
    if ledger is not None:
        ledger.close()
    score = round(sum(c.weight * EARNS[c.status] for c in checks))
    ceiling = sum(c.weight for c in checks if c.status != "unmeasured")
    return SelfCheck(
        checked_at=datetime.now(UTC),
        score=score,
        ceiling=ceiling,
        checks=checks,
        does_not_prove=DOES_NOT_PROVE,
    )


__all__ = ["DOES_NOT_PROVE", "Check", "SelfCheck", "Status", "is_elevated", "run_selfcheck"]
