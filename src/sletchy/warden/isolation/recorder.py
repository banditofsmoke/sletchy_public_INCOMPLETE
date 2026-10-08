"""The Warden's ledger handle - sandbox events, appended before they take effect.

[LAW 1](../../../../docs/LAW/laws.md#law-1) says nothing happens off-ledger. Until
now the isolation backends were the exception: they created AppContainer profiles,
applied job limits, granted ACLs and killed process trees, and not one of those
reached the chain. The interface from #13 simply had nowhere to write.

This is that somewhere. It is deliberately small - four methods and no decisions -
because the backends should not have to know how a ledger entry is shaped, and the
event vocabulary should live in exactly one place rather than being spelled slightly
differently at each call site.

## The ordering rule

`launching()` is called **before** `CreateProcess`, and it fsyncs. That costs a
disk write on the launch path, and it is not negotiable: a record written after the
process starts is a record that goes missing precisely when the process does
something that kills us.

The two directions fail differently, which is the whole reason for the ordering:

- Entry written, process never started -> the ledger over-reports. Noise, harmless,
  and visible as a launch with no matching outcome.
- Process started, entry never written -> an execution nobody can account for. This
  is the one that must be impossible.

## When the payload store is full

The store refuses past its ceiling, or near the drive's floor (LAW 0 section 5). A
launch is then **refused, and the refusal recorded**: its whole command line could not
be kept, and a launch whose record is incomplete does not happen. An outcome or a
refusal is still recorded, without its body, and says so: by then the process has run
or been stopped, and losing that entry would be worse than losing its details.

## What is deliberately not here

No second logging path, no in-memory ring buffer, no debug channel. The SOC will
read these entries from the chain; it does not get its own stream (LAW 1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import (
    Decision,
    LedgerEntry,
    Plane,
    Subject,
    SubjectKind,
    Verdict,
)
from sletchy.kernel.ledger import PayloadStoreFull

if TYPE_CHECKING:
    from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
    from sletchy.kernel.ledger import Ledger, PayloadStore
    from sletchy.warden.isolation.base import LaunchResult

#: The sandbox vocabulary. Four actions, each a distinct fact:
#: a launch that is about to happen, one that finished on its own, one we stopped,
#: and one that never started. `killed` is separate from `complete` because "the
#: program failed" and "we stopped the program" are different events and only one
#: of them is a signal.
LAUNCH_ACTION = "warden.sandbox.launch"
COMPLETE_ACTION = "warden.sandbox.complete"
KILLED_ACTION = "warden.sandbox.killed"
REFUSED_ACTION = "warden.sandbox.refused"


@dataclass(frozen=True)
class SandboxRecorder:
    """A ledger, an actor, and the four things a sandbox can report.

    Frozen: a recorder that could be repointed at a different ledger mid-execution
    would let one half of an execution be recorded somewhere the other half is not.

    `payloads` is optional because a payload store is an optimisation, not a
    control - without one the command line is summarised into the entry's reason
    instead of being stored whole. The *entry* is never optional.
    """

    ledger: Ledger
    actor_id: str
    payloads: PayloadStore | None = None

    def launching(
        self,
        *,
        command: list[str],
        backend: IsolationBackend,
        profile: IsolationProfile,
        workspace: str,
    ) -> LedgerEntry:
        """Record an execution **about to start**. Call before the process exists.

        Raises `PayloadStoreFull`, after recording the refusal, when the command line
        cannot be kept: the process must then not start.
        """
        body: dict[str, object] = {
            "command": command,
            "backend": backend.value,
            "workspace": workspace,
            "resources": profile.resources.model_dump(mode="json"),
        }
        try:
            payload = self._store(body)
        except PayloadStoreFull as exc:
            self.refused(command=command, reason=f"not launched: {exc}")
            raise
        return self.ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=LAUNCH_ACTION,
            subject=Subject(kind=SubjectKind.PROCESS, identifier=_program(command)),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"launching under {backend.value} with "
                    f"{profile.resources.memory_mb} MB / "
                    f"{profile.resources.cpu_percent}% CPU / "
                    f"{profile.resources.wall_clock_seconds}s"
                ),
            ),
            payload_hash=payload,
        )

    def finished(self, *, command: list[str], result: LaunchResult) -> LedgerEntry:
        """Record how an execution ended.

        A run we stopped is recorded under a different action from one that ended
        by itself, so a reader never has to infer which happened from an exit code.
        """
        stopped = result.timed_out or result.killed_by_limit
        payload, lost = self._store_if_room(
            {
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "killed_by_limit": result.killed_by_limit,
                "backend": result.backend.value,
                "diagnostics": result.diagnostics,
            }
        )
        reason = (
            "stopped by the sandbox: "
            + ("wall-clock limit" if result.timed_out else "resource limit")
            if stopped
            else f"exited {result.exit_code}"
        )
        return self.ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=KILLED_ACTION if stopped else COMPLETE_ACTION,
            subject=Subject(kind=SubjectKind.PROCESS, identifier=_program(command)),
            verdict=Verdict(decision=Decision.ALLOW, reason=_truncate(reason + lost)),
            payload_hash=payload,
        )

    def refused(self, *, command: list[str], reason: str) -> LedgerEntry:
        """Record a launch that did **not** happen, and why.

        Refusals are the entries that matter most. A system that logs only what it
        allowed cannot tell you what it stopped.
        """
        payload, lost = self._store_if_room({"command": command, "reason": reason})
        return self.ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=REFUSED_ACTION,
            subject=Subject(
                kind=SubjectKind.PROCESS, identifier=_program(command) if command else "<empty>"
            ),
            verdict=Verdict(decision=Decision.DENY, reason=_truncate(reason + lost)),
            payload_hash=payload,
        )

    def _store(self, body: dict[str, object]) -> str | None:
        if self.payloads is None:
            return None
        return self.payloads.put(json.dumps(body, sort_keys=True, default=str).encode("utf-8"))

    def _store_if_room(self, body: dict[str, object]) -> tuple[str | None, str]:
        """The body's hash, or None and a note for the reason when it could not be kept."""
        try:
            return self._store(body), ""
        except PayloadStoreFull:
            return None, " (details not kept: the payload store is full)"


def _program(command: list[str]) -> str:
    """The subject of a sandbox event is the program, not the whole command line.

    The full argv goes in the payload. Keeping the subject short means policy can
    match on it and a human can read a chain of entries without scrolling.
    """
    return command[0][:1024] if command else "<empty>"


def _truncate(reason: str) -> str:
    """`Verdict.reason` caps at 512 characters, and a refusal must never fail to
    record because its explanation was long."""
    return reason if len(reason) <= 512 else reason[:509] + "..."
