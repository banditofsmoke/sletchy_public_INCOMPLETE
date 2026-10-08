"""`sletchy-soc events`: the System log's crash loops and unexpected shutdowns (#146).

The planted cases are the real ones, measured by this sensor on 2026-10-04: a
graphics-driver service had stopped unexpectedly 2,445 to 3,303 times a day for 9 days,
3,285 of them on 2026-10-03, and the machine had gone off without shutting down twice
in five days. #146's
definition of done: that loop, as a planted log pattern, becomes exactly one finding a
day.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.soc import cli as soc_cli
from sletchy.soc.findings import record
from sletchy.soc.sensors import events as ev
from sletchy.soc.sensors.events import Look, SystemEvent

pytestmark = pytest.mark.adversarial

needs_windows = pytest.mark.skipif(sys.platform != "win32", reason="the sensor reads Windows")
NOON = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
LOOPING = "NVIDIA LocalSystem Container"


def crash(at: datetime, service: str = LOOPING, event_id: int = 7031) -> SystemEvent:
    return SystemEvent(
        event_id=event_id, provider="Service Control Manager", time=at, data=(service, "1")
    )


def shutdown(at: datetime, event_id: int = 41) -> SystemEvent:
    return SystemEvent(
        event_id=event_id, provider="Microsoft-Windows-Kernel-Power", time=at, data=()
    )


def day_of_crashes(
    start: datetime, count: int, every: timedelta = timedelta(seconds=13)
) -> list[SystemEvent]:
    return [crash(start + i * every) for i in range(count)]


def today_of(moment: datetime) -> date:
    return moment.astimezone().date()


# ── the patterns ─────────────────────────────────────────────────────────────


def test_the_graphics_driver_loop_is_one_finding() -> None:
    events = day_of_crashes(NOON - timedelta(hours=11), 3285, every=timedelta(seconds=20))
    found = ev.crash_loops(events, today=today_of(NOON))
    assert [f.rule for f in found] == ["service_crash_loop"]
    assert LOOPING in found[0].summary and "3285" in found[0].summary


def test_the_loop_is_recorded_once_a_day_however_often_it_is_looked_at(tmp_path: Path) -> None:
    """The definition of done, end to end through the record."""
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    seen = tmp_path / "seen.json"
    events = day_of_crashes(NOON - timedelta(hours=11), 3285, every=timedelta(seconds=20))
    for _ in range(5):
        record(
            ledger,
            ev.crash_loops(events, today=today_of(NOON)),
            today=today_of(NOON),
            seen_file=seen,
        )
    tomorrow = today_of(NOON) + timedelta(days=1)
    record(ledger, ev.crash_loops(events, today=tomorrow), today=tomorrow, seen_file=seen)
    assert [e.action for e in ledger.entries()] == ["soc.finding.service_crash_loop"] * 2


@pytest.mark.parametrize("count", [1, 5, 23])
def test_a_service_that_stops_now_and_then_is_not_a_loop(count: int) -> None:
    events = day_of_crashes(NOON, count, every=timedelta(minutes=30))
    assert ev.crash_loops(events, today=today_of(NOON)) == []


def test_both_crash_events_count_and_each_service_is_its_own_finding() -> None:
    events = [
        *[crash(NOON + timedelta(minutes=i), "A", 7031) for i in range(20)],
        *[crash(NOON + timedelta(minutes=i, seconds=30), "A", 7034) for i in range(20)],
        *[crash(NOON + timedelta(minutes=i), "B", 7031) for i in range(10)],
    ]
    found = ev.crash_loops(events, today=today_of(NOON))
    assert [f.identifier for f in found] == ["A"], "A: 40 in a day; B: 10, not a loop"


def test_two_records_of_one_shutdown_are_one_finding() -> None:
    events = [shutdown(NOON, 41), shutdown(NOON + timedelta(minutes=1), 6008)]
    assert len(ev.unexpected_shutdowns(events)) == 1


def test_two_shutdowns_days_apart_are_two_findings() -> None:
    events = [shutdown(NOON - timedelta(days=4)), shutdown(NOON)]
    assert len(ev.unexpected_shutdowns(events)) == 2


def test_a_hostile_service_name_cannot_write_to_the_terminal() -> None:
    name = "svc\x1b[2J\nFAKE: all clear"
    events = [crash(NOON + timedelta(minutes=i), name) for i in range(30)]
    found = ev.crash_loops(events, today=today_of(NOON))
    assert found and all(ch.isprintable() for ch in found[0].summary + found[0].identifier)


# ── parsing what Windows renders ─────────────────────────────────────────────

#: What Windows renders, built on the module's own namespace. The namespace is an
#: identifier, not an address anything connects to.
RENDERED = (
    f'<Event xmlns="{ev._NS[1:-1]}"><System>'
    '<Provider Name="Service Control Manager"/><EventID Qualifiers="49152">7031</EventID>'
    '<TimeCreated SystemTime="2026-10-03T21:04:14.4567890Z"/></System>'
    '<EventData><Data Name="param1">NVIDIA LocalSystem Container</Data><Data Name="param2">1</Data>'
    "</EventData></Event>"
)


def test_a_rendered_event_parses() -> None:
    event = ev.parse(RENDERED)
    assert event.event_id == 7031
    assert event.data[0] == LOOPING
    assert event.time == datetime(2026, 10, 3, 21, 4, 14, 456789, tzinfo=UTC)


@pytest.mark.parametrize(
    "hostile",
    [
        '<!DOCTYPE e [<!ENTITY x "y">]><Event/>',
        '<!ENTITY lol "lol"><Event/>',
    ],
)
def test_an_event_that_declares_a_document_type_or_entity_is_refused(hostile: str) -> None:
    """Rendered events never carry a DTD. One that does is refused before parsing,
    so no entity can expand."""
    with pytest.raises(ValueError, match="document type or an entity"):
        ev.parse(hostile)


def test_the_query_asks_for_the_four_events_and_a_bounded_window() -> None:
    query = ev.xpath(10)
    assert all(f"EventID={i}" in query for i in (7031, 7034, 41, 6008))
    assert "864000000" in query


# ── only with the operator's say-so ──────────────────────────────────────────


def test_without_the_flag_the_log_is_not_read(tmp_path: Path) -> None:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    asked: list[int] = []

    def look(*, days: int) -> Look:
        asked.append(days)
        return Look(events=(), days=days, capped=False, unreadable=0)

    lines: list[str] = []
    args = argparse.Namespace(view="events", days=10, dry_run=True, top=25)
    assert soc_cli.run(args, ledger, read_log=look, out=lines.append) == 0
    assert asked == []
    assert any(soc_cli.WATCH_FLAG in line for line in lines)


# ── the sensor reads this machine's log ─────────────────────────────────────


@needs_windows
def test_the_log_reader_reads_this_machines_system_log() -> None:
    """Positive control: service state changes (7036) are in every System log. A query
    that silently read nothing would otherwise look like "no crashes" (L009)."""
    from sletchy.soc.sensors import _win32

    raw, _ = _win32.read_events("System", "*[System[(EventID=7036)]]", 5)
    assert len(raw) == 5
    assert all(ev.parse(xml).event_id == 7036 for xml in raw)


@needs_windows
def test_a_bad_query_raises_instead_of_reading_as_nothing() -> None:
    from sletchy.soc.sensors import _win32

    with pytest.raises(OSError):
        _win32.read_events("System", "*[this is not xpath", 5)
