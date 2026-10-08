"""Findings reach the ledger; snapshots never do (#146, ADR-0011 decision 4).

An append is an fsync and the ledger stops at its ceiling, so a sensor that recorded
everything it saw would let a busy machine, or anyone able to start processes, fill
the ledger and switch Sletchy off through its own watcher. Two limits stop that:

- **once a day**: the same finding about the same thing is recorded at most once per
  day. What was recorded is kept in `var/soc/recorded.json`; losing that file costs at
  most one repeat per finding, never a flood
- **a ceiling per run**: at most `MAX_PER_RUN` findings, then one entry saying how many
  more were not recorded, so a flood is itself on the record
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from sletchy.kernel.contracts.identity import Plane, Subject, SubjectKind
from sletchy.kernel.contracts.policy import Decision, Verdict
from sletchy.kernel.ledger import Ledger
from sletchy.soc.sensors.model import Finding

ACTOR = "soc"
ACTION_PREFIX = "soc.finding."
OVER_CEILING_ACTION = "soc.finding.over_ceiling"
MAX_PER_RUN = 10

#: Rules whose finding is about a network service rather than a program on disk.
_HOST_RULES = frozenset({"exposed_service"})


@dataclass
class Recorded:
    recorded: list[Finding] = field(default_factory=list)
    already_today: list[Finding] = field(default_factory=list)
    not_recorded: list[Finding] = field(default_factory=list)


def _key(finding: Finding) -> str:
    return f"{finding.rule}|{finding.identifier}"


def _load(seen_file: Path) -> dict[str, str]:
    try:
        data = json.loads(seen_file.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def _save(seen_file: Path, seen: dict[str, str], today: date) -> None:
    kept = {k: v for k, v in seen.items() if v == today.isoformat()}  # only today matters
    seen_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = seen_file.with_suffix(".tmp")
    temporary.write_bytes(json.dumps(kept, indent=1, sort_keys=True).encode("utf-8"))
    os.replace(temporary, seen_file)


def record(ledger: Ledger, found: list[Finding], *, today: date, seen_file: Path) -> Recorded:
    """Append each finding not already recorded today, up to the ceiling."""
    result = Recorded()
    seen = _load(seen_file)
    unique: dict[str, Finding] = {}
    for finding in found:
        unique.setdefault(_key(finding), finding)
    for key, finding in unique.items():
        if seen.get(key) == today.isoformat():
            result.already_today.append(finding)
        elif len(result.recorded) >= MAX_PER_RUN:
            result.not_recorded.append(finding)
        else:
            ledger.append(
                plane=Plane.SOC,
                actor_id=ACTOR,
                action=ACTION_PREFIX + finding.rule,
                subject=Subject(
                    kind=SubjectKind.HOST if finding.rule in _HOST_RULES else SubjectKind.PROCESS,
                    identifier=finding.identifier,
                ),
                # A finding decides nothing, so it is recorded the way a completed launch
                # is: allowed, with the words in the reason.
                verdict=Verdict(
                    decision=Decision.ALLOW, reason=finding.summary, rule_id=finding.rule
                ),
            )
            seen[key] = today.isoformat()
            result.recorded.append(finding)
    if result.not_recorded:
        ledger.append(
            plane=Plane.SOC,
            actor_id=ACTOR,
            action=OVER_CEILING_ACTION,
            subject=Subject(kind=SubjectKind.LEDGER, identifier="soc findings"),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"{len(result.not_recorded)} more findings were not recorded this run: "
                    f"at most {MAX_PER_RUN} are, so a flood cannot fill the ledger"
                ),
            ),
        )
    _save(seen_file, seen, today)
    return result
