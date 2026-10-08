"""Flag state - reading, flipping, and resetting.

Persisted as a small JSON file under `var/`. Only *deviations* from the declared
defaults are stored, which has a useful property: deleting the file returns Sletchy
to a fresh-install posture rather than to an empty and undefined one.

Every flip is a ledger entry carrying who, when, and why. Reads are not logged -
they happen constantly and would drown the signal.

**The record and the file must not disagree** (#104). A change is written in three
steps: the new state is staged in a temporary file, the ledger entry goes in (LAW 1:
the record before the effect), then the temporary file replaces `flags.json`. A
failure while staging records nothing, because nothing happened. A failure to replace
records a second entry saying the change did not take effect, and raises. Before
this, a read-only `flags.json` left the ledger saying the camera went off while it
stayed on.
"""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import Decision, FlagRisk, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.flags.errors import FlagWriteFailed, ReasonRequired
from sletchy.kernel.flags.registry import FlagRegistry

if TYPE_CHECKING:
    from pathlib import Path

    from sletchy.kernel.ledger import Ledger

FLIP_ACTION = "kernel.flag.flip"
RESET_ACTION = "kernel.flag.reset"
#: A flip or reset whose entry is in the ledger but whose file could not be
#: replaced, so the change did not take effect (#104).
WRITE_FAILED_ACTION = "kernel.flag.write_failed"


def _visible(reason: str) -> bool:
    """Whether a person reading the record could see anything in this reason.

    `str.strip()` alone let a zero-width space, a word joiner or a NUL count as a
    reason for turning a dangerous flag on (#96). A reason needs at least one printable
    character that is not whitespace - in any script.
    """
    return any(ch.isprintable() and not ch.isspace() for ch in reason)


class FlagStore:
    """Current flag values, over a registry, backed by the ledger and a JSON file."""

    __slots__ = ("_ledger", "_overrides", "_path", "_registry", "_unexplained")

    def __init__(
        self,
        registry: FlagRegistry,
        ledger: Ledger,
        path: Path,
    ) -> None:
        self._registry = registry
        self._ledger = ledger
        self._path = path
        self._overrides: dict[str, bool] = {}
        self._unexplained: tuple[str, ...] = ()

    @classmethod
    def open(cls, ledger: Ledger, path: Path, registry: FlagRegistry | None = None) -> FlagStore:
        """Load persisted deviations. A missing or unreadable file means defaults.

        Unreadable is treated as absent **only** because the fallback is the *safe*
        direction: every dangerous flag returns to off. Nothing is granted by a
        parse failure, so failing open here is not failing open at all.
        """
        store = cls(registry or FlagRegistry(), ledger, path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return store
        if isinstance(raw, dict):
            # Filter against the store's OWN registry. An entry naming a flag this
            # registry does not declare is dropped rather than carried, so a stale
            # or hand-edited file cannot smuggle in a value nothing will validate.
            store._overrides = {
                name: value
                for name, value in raw.items()
                if name in store._registry and isinstance(value, bool)
            }
        store._distrust_what_the_ledger_cannot_explain()
        return store

    @property
    def unexplained(self) -> tuple[str, ...]:
        """Dangerous flags `flags.json` says are on with no ledger entry turning them on.

        Each reads as **off** (#100). The file is not rewritten to hide it - it is
        evidence, and rewriting it from the ledger is ruled out - so flipping another
        switch keeps the claim in the file, and every reader keeps naming it. It goes
        when that flag is itself flipped, or when a reset names it in its entry.
        """
        return self._unexplained

    def _distrust_what_the_ledger_cannot_explain(self) -> None:
        """Treat as off any dangerous flag the ledger never recorded turning on (#100).

        Editing `flags.json` by hand turned a dangerous flag on with no record at all:
        `status` showed it on while the ledger held nothing. LAW 8 says dangerous flags
        are off unless something recorded turning them on, and LAW 2 says a tie goes to
        deny, so such a flag reads as off, and is named.

        One pass over the ledger, made only when the file claims a dangerous flag is on,
        so the common case - nothing dangerous on - costs nothing.
        """
        claimed = [
            name
            for name, value in self._overrides.items()
            if value and self._registry.get(name).risk is FlagRisk.DANGEROUS
        ]
        if not claimed:
            return
        recorded = self._recorded_state(claimed)
        self._unexplained = tuple(name for name in claimed if not recorded[name])
        for name in self._unexplained:
            del self._overrides[name]

    def _recorded_state(self, names: list[str]) -> dict[str, bool]:
        """Whether the ledger's own history leaves each flag on.

        A flip sets it; a reset returns every flag to its default; a write failure
        (#104) undoes whichever of those it follows, because that change never took
        effect.
        """
        state = {name: self._registry.get(name).default for name in names}
        before = dict(state)
        for entry in self._ledger.entries():
            target = entry.subject.identifier
            if entry.action == FLIP_ACTION and target in state:
                before[target] = state[target]
                state[target] = entry.verdict.decision is Decision.ALLOW
            elif entry.action == RESET_ACTION:
                before = dict(state)
                state = {name: self._registry.get(name).default for name in names}
            elif entry.action == WRITE_FAILED_ACTION:
                if target == "all":
                    state = dict(before)
                elif target in state:
                    state[target] = before[target]
        return state

    @property
    def registry(self) -> FlagRegistry:
        return self._registry

    def is_on(self, name: str) -> bool:
        """Current value. Raises `UnknownFlag` for anything not declared."""
        flag = self._registry.get(name)
        return self._overrides.get(name, flag.default)

    def snapshot(self) -> dict[str, bool]:
        """Every declared flag and its current value - what the UI renders."""
        return {flag.name: self.is_on(flag.name) for flag in self._registry}

    def set(
        self,
        name: str,
        value: bool,
        *,
        reason: str = "",
        actor_id: str = "operator",
    ) -> None:
        """Flip a flag, recording who, when, and why.

        Turning a DANGEROUS flag **on** requires a reason. Turning one off does not -
        the safe direction should never be obstructed, because an obstructed
        safe action is an action that gets skipped in a hurry.
        """
        flag = self._registry.get(name)

        if value and flag.risk is FlagRisk.DANGEROUS and not _visible(reason):
            msg = f"turning on {name!r} requires a reason. It is DANGEROUS: {flag.description}"
            raise ReasonRequired(msg)

        overrides = dict(self._overrides)
        if value == flag.default:
            overrides.pop(name, None)
        else:
            overrides[name] = value
        # A flag the ledger cannot explain stays in the file as it was found, so flipping
        # some other switch never erases the evidence (#100). Flipping that flag itself,
        # either way, is a recorded decision about it, and replaces the claim.
        kept_claims = {n: True for n in self._unexplained if n != name}
        staged = self._stage({**kept_claims, **overrides})

        detail = reason.strip() or ("disabled" if not value else "enabled")
        self._record(
            staged,
            actor_id=actor_id,
            action=FLIP_ACTION,
            identifier=name,
            decision=Decision.ALLOW if value else Decision.DENY,
            reason=f"{name} -> {'on' if value else 'off'}: {detail}",
            safer=not value,
        )
        self._commit(
            staged,
            overrides,
            actor_id=actor_id,
            identifier=name,
            kept=f"{name} stayed {'on' if self.is_on(name) else 'off'}",
        )
        self._unexplained = tuple(n for n in self._unexplained if n != name)

    def reset_all(self, *, actor_id: str = "operator", reason: str = "stop everything") -> int:
        """Return every flag to its declared default. Called by `sletchy panic`.

        Returns the number of flags that actually changed, so the caller can report
        honestly rather than claiming a reset that was a no-op.
        """
        changed = len(self._overrides)
        # The reset clears flags.json, including any claim the ledger could not explain,
        # so the claim is written into the reset's own entry first (#100).
        dropped = (
            f"; on in flags.json with no ledger entry, dropped: {', '.join(self._unexplained)}"
            if self._unexplained
            else ""
        )
        staged = self._stage({})
        self._record(
            staged,
            actor_id=actor_id,
            action=RESET_ACTION,
            identifier="all",
            decision=Decision.DENY,
            reason=f"all flags reset to defaults ({changed} changed{dropped}): {reason}",
            safer=True,
        )
        self._commit(staged, {}, actor_id=actor_id, identifier="all", kept="no flag was reset")
        self._unexplained = ()
        return changed

    def _stage(self, overrides: dict[str, bool]) -> Path:
        """Write the new state beside `flags.json`. A failure here records nothing."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        staged = self._path.with_suffix(".tmp")
        staged.write_text(json.dumps(overrides, indent=2, sort_keys=True), encoding="utf-8")
        return staged

    def _record(
        self,
        staged: Path,
        *,
        actor_id: str,
        action: str,
        identifier: str,
        decision: Decision,
        reason: str,
        safer: bool,
    ) -> None:
        """The ledger entry. If it cannot be written, the staged state is dropped.

        `safer` lets switching something off use the reserve a full ledger keeps (#101).
        """
        try:
            self._ledger.append(
                plane=Plane.KERNEL,
                actor_id=actor_id,
                action=action,
                subject=Subject(kind=SubjectKind.FLAG, identifier=identifier),
                verdict=Verdict(decision=decision, reason=reason[:512], rule_id=None),
                safer=safer,
            )
        except BaseException:
            with contextlib.suppress(OSError):
                staged.unlink(missing_ok=True)
            raise

    def _commit(
        self,
        staged: Path,
        overrides: dict[str, bool],
        *,
        actor_id: str,
        identifier: str,
        kept: str,
    ) -> None:
        """Replace `flags.json`, or record that the change did not take effect."""
        try:
            staged.replace(self._path)
        except OSError as exc:
            with contextlib.suppress(OSError):
                staged.unlink(missing_ok=True)
            why = exc.strerror or type(exc).__name__
            self._ledger.append(
                plane=Plane.KERNEL,
                actor_id=actor_id,
                action=WRITE_FAILED_ACTION,
                subject=Subject(kind=SubjectKind.FLAG, identifier=identifier),
                verdict=Verdict(
                    decision=Decision.DENY,
                    reason=f"{kept}: could not write {self._path.name}: {why}"[:512],
                    rule_id=None,
                ),
                safer=True,
            )
            msg = f"{why}; {kept}, and the ledger says so"
            raise FlagWriteFailed(exc.errno, msg, exc.filename, None, exc.filename2) from exc
        self._overrides = overrides
