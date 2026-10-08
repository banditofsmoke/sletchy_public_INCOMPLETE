"""The System log, read for the patterns an operator should hear about (#146).

`sletchy-soc events` reads four kinds of entry from Windows' System log, over the last
few days, and names two patterns:

- **a crash loop**: a service that stopped unexpectedly over and over (7031, 7034).
  A graphics-driver service on the operator's machine had done that about 3,000 times
  a day for 8 days (3,285 on 2026-10-03, measured by this sensor), and nothing told
  anyone
- **an unexpected shutdown**: the machine went off without shutting down (41, 6008):
  a freeze, a power cut, or the power button held

The log is the whole machine's, not Sletchy's, so it is read only when the dangerous
flag `soc_watch_machine` is on (ADR-0011 decision 5).

Every entry is untrusted text: a service names itself. The XML Windows renders is
parsed only after refusing anything that declares a document type or an entity, which
no rendered event contains, and every string is escaped before it is shown.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta
from typing import Annotated

from pydantic import Field

from sletchy.kernel.contracts.base import Contract
from sletchy.soc.sensors.model import Finding, shown
from sletchy.soc.sensors.snapshot import SensorUnavailable

CRASHED = (7031, 7034)
SHUT_DOWN_BADLY = (41, 6008)
#: A service that stops unexpectedly this often in one day is in a loop, not unlucky:
#: about once an hour.
CRASH_LOOP_PER_DAY = 24
#: How many entries one look reads at most, so a flooded log cannot stall it.
MAX_EVENTS = 100_000
MAX_DAYS = 30
#: Event 41 and event 6008 are written for the same shutdown, minutes apart.
SAME_SHUTDOWN = timedelta(minutes=15)

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class SystemEvent(Contract):
    event_id: Annotated[int, Field(ge=0)]
    provider: Annotated[str, Field(max_length=256)]
    time: datetime
    data: tuple[str, ...]


class Look(Contract):
    events: tuple[SystemEvent, ...]
    days: Annotated[int, Field(ge=1, le=MAX_DAYS)]
    capped: bool
    unreadable: Annotated[int, Field(ge=0)]


def xpath(days: int) -> str:
    ids = " or ".join(f"EventID={i}" for i in (*CRASHED, *SHUT_DOWN_BADLY))
    return f"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {days * 86_400_000}]]]"


def parse(xml: str) -> SystemEvent:
    """One rendered event. Raises ValueError for anything that is not a plain event."""
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        msg = "an event declared a document type or an entity; rendered events never do"
        raise ValueError(msg)
    root = ET.fromstring(xml)  # noqa: S314 - refused above: no DTD, no entities
    system = root.find(f"{_NS}System")
    if system is None:
        msg = "an event without a System block"
        raise ValueError(msg)
    event_id = system.findtext(f"{_NS}EventID")
    created = system.find(f"{_NS}TimeCreated")
    provider = system.find(f"{_NS}Provider")
    if event_id is None or created is None or not created.get("SystemTime"):
        msg = "an event without an id or a time"
        raise ValueError(msg)
    stamp = created.get("SystemTime", "").rstrip("Z")
    when = datetime.fromisoformat(stamp[:26]).replace(tzinfo=UTC)
    data = tuple((d.text or "") for d in root.iter(f"{_NS}Data"))
    return SystemEvent(
        event_id=int(event_id.strip()),
        provider=shown(provider.get("Name", "") if provider is not None else "", 256),
        time=when,
        data=tuple(shown(d, 512) for d in data),
    )


def take(*, days: int) -> Look:
    if sys.platform != "win32":
        msg = "the event sensor is written for Windows only, so far"
        raise SensorUnavailable(msg)
    from sletchy.soc.sensors import _win32

    raw, capped = _win32.read_events("System", xpath(days), MAX_EVENTS)
    events, unreadable = [], 0
    for xml in raw:
        try:
            events.append(parse(xml))
        except (ValueError, ET.ParseError):
            unreadable += 1
    return Look(events=tuple(events), days=days, capped=capped, unreadable=unreadable)


# ── the patterns ─────────────────────────────────────────────────────────────


def _local_day(moment: datetime) -> date:
    return moment.astimezone().date()


def crash_loops(events: Iterable[SystemEvent], *, today: date) -> list[Finding]:
    """A service that stopped unexpectedly at least `CRASH_LOOP_PER_DAY` times in a day."""
    per_day: dict[str, Counter[date]] = defaultdict(Counter)
    for event in events:
        if event.event_id in CRASHED and event.data:
            per_day[event.data[0]][_local_day(event.time)] += 1
    findings = []
    for service, days in sorted(per_day.items()):
        worst_day, worst = days.most_common(1)[0]
        if worst < CRASH_LOOP_PER_DAY:
            continue
        total = sum(days.values())
        findings.append(
            Finding(
                rule="service_crash_loop",
                identifier=shown(service, 1024),
                summary=shown(
                    f'The service "{service}" stopped unexpectedly {days.get(today, 0)} times today, '
                    f"and {total} times since {min(days).isoformat()}; the most in one day was "
                    f"{worst}, on {worst_day.isoformat()}. Windows restarts it each time, so nothing "
                    "says so. A driver or program update usually ends it",
                    480,
                ),
            )
        )
    return findings


def unexpected_shutdowns(events: Iterable[SystemEvent]) -> list[Finding]:
    """Each time the machine went off without shutting down. 41 and 6008 for the same
    shutdown are one finding."""
    moments = sorted(e.time for e in events if e.event_id in SHUT_DOWN_BADLY)
    shutdowns: list[datetime] = []
    for moment in moments:
        if not shutdowns or moment - shutdowns[-1] > SAME_SHUTDOWN:
            shutdowns.append(moment)
    return [
        Finding(
            rule="unexpected_shutdown",
            identifier=moment.astimezone().strftime("%Y-%m-%d %H:%M"),
            summary=(
                f"Windows did not shut down properly around {moment.astimezone().strftime('%Y-%m-%d %H:%M')}: "
                "a freeze, a power cut, or the power button held"
            ),
        )
        for moment in shutdowns
    ]


def findings(look: Look, *, today: date) -> list[Finding]:
    return [*crash_loops(look.events, today=today), *unexpected_shutdowns(look.events)]
