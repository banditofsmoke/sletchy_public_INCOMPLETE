"""`sletchy-soc`: what is running and what is listening, read-only, in words (#146).

The SOC's own entry point. The Shell never imports it (ADR-0011): what it finds reaches
everything else as ledger entries, which `sletchy ledger show --action soc` reads.

    sletchy-soc processes [--top N] [--dry-run]
    sletchy-soc network [--dry-run]
    sletchy-soc events [--days N] [--dry-run]
    sletchy-soc startup [--dry-run]

It never changes anything it looks at: no stopping, suspending or re-prioritising a
process, no closing a port. It explains; the operator decides. It never asks for
elevation, and what an ordinary user cannot read is counted and said, never guessed.

Without the dangerous flag `soc_watch_machine` it looks only at Sletchy's own
processes, and does not read the machine's System log or startup entries at all. `--dry-run` shows the view and the findings and records nothing.

Exit codes: 0 looked; 1 no Sletchy here, or no sensor on this platform; 2 the ledger
does not verify.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import date
from pathlib import Path

from sletchy.kernel import paths
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import Ledger, LedgerCorrupt, LedgerMissing
from sletchy.kernel.ledger.keys import KeyringKeySource
from sletchy.soc.findings import MAX_PER_RUN, Recorded, record
from sletchy.soc.sensors import events, rules, startup
from sletchy.soc.sensors.events import Look
from sletchy.soc.sensors.model import EVERY_INTERFACE, Finding, Snapshot, TcpState, shown
from sletchy.soc.sensors.snapshot import SensorUnavailable, take
from sletchy.soc.sensors.startup import Kind, StartupLook

WATCH_FLAG = "soc_watch_machine"
MB = 1024 * 1024


def seen_file() -> Path:
    return paths.home() / "soc" / "recorded.json"


# ── views ────────────────────────────────────────────────────────────────────


def _size(n: int) -> str:
    return f"{n / MB / 1024:.1f} GB" if n >= 1024 * MB else f"{n / MB:.0f} MB"


def _where(path: str | None, width: int = 90) -> str:
    """A long path keeps its end, where the program's own name is."""
    if path is None:
        return "could not read"
    safe = shown(path, 32768)
    return safe if len(safe) <= width else "..." + safe[-(width - 3) :]


def render_processes(snapshot: Snapshot, top: int) -> list[str]:
    groups: dict[tuple[str, str | None], list[int]] = defaultdict(list)
    memory: dict[tuple[str, str | None], int] = defaultdict(int)
    cpu: dict[tuple[str, str | None], float] = defaultdict(float)
    for proc in snapshot.processes:
        key = (proc.name.lower(), proc.path)
        groups[key].append(proc.pid)
        memory[key] += proc.memory_bytes
        cpu[key] += proc.cpu_seconds
    unreadable = sum(1 for p in snapshot.processes if p.path is None)
    total = sum(p.memory_bytes for p in snapshot.processes)
    lines = [
        f"{len(snapshot.processes)} processes, {len(groups)} programs, "
        f"{_size(total)} in use by them",
        "Looking at: "
        + ("the whole machine" if snapshot.whole_machine else "Sletchy's own processes only"),
        f"Could not read where {unreadable} of them run from without administrator rights",
        "",
        f"{'Program':<32} {'Copies':>6} {'Memory':>9} {'CPU':>9}  Runs from",
    ]
    ranked = sorted(groups, key=lambda k: memory[k], reverse=True)
    for key in ranked[:top]:
        name = next(p.name for p in snapshot.processes if p.pid == groups[key][0]) or "?"
        where = _where(key[1])
        lines.append(
            f"{shown(name, 32):<32} {len(groups[key]):>6} {memory[key] / MB:>7.0f}MB "
            f"{cpu[key]:>8.0f}s  {where}"
        )
    if len(ranked) > top:
        lines.append(f"... and {len(ranked) - top} more programs (--top to show more)")
    return lines


def _exposure(address: str) -> str:
    if address in EVERY_INTERFACE:
        return "every network"
    if address.startswith("127.") or address == "::1":
        return "this machine only"
    return f"one address, {address}"


def render_network(snapshot: Snapshot) -> list[str]:
    names = {p.pid: p.name for p in snapshot.processes}
    listeners = sorted(
        {(s.local_port, _exposure(s.local_address), s.pid) for s in snapshot.sockets if s.listening}
    )
    # Open connections only: one closing, or closed and held by Windows for a while,
    # is owned by no program any more.
    connected: dict[str, int] = defaultdict(int)
    for sock in snapshot.sockets:
        if sock.state is TcpState.ESTABLISHED:
            connected[shown(names.get(sock.pid, "") or f"process {sock.pid}", 40)] += 1
    lines = [
        "Looking at: "
        + ("the whole machine" if snapshot.whole_machine else "Sletchy's own processes only"),
        "",
        f"Listening for connections ({len(listeners)}):",
        f"  {'Port':>6}  {'Reachable from':<28} Program",
    ]
    for port, exposure, pid in listeners:
        lines.append(
            f"  {port:>6}  {exposure:<28} {shown(names.get(pid, '') or '?', 40)} (pid {pid})"
        )
    lines += ["", f"Open connections, by program ({sum(connected.values())}):"]
    for name, count in sorted(connected.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {count:>4}  {name}")
    lines.append("  (where they connect to is not listed, and never recorded)")
    return lines


def render_findings(found: list[Finding], outcome: Recorded | None) -> list[str]:
    if not found:
        return ["", "Nothing found wrong by the rules this looks for."]
    lines = ["", f"Found ({len(found)}):"]
    lines += [f"  - {f.summary}" for f in found]
    if outcome is None:
        lines.append("Dry run: nothing was recorded.")
    else:
        lines.append(
            f"Recorded {len(outcome.recorded)}; {len(outcome.already_today)} already recorded today"
            + (
                f"; {len(outcome.not_recorded)} over the limit of {MAX_PER_RUN}"
                if outcome.not_recorded
                else ""
            )
            + ". Read them with: sletchy ledger show --action soc"
        )
    return lines


# ── the command ──────────────────────────────────────────────────────────────


def render_events(look: Look) -> list[str]:
    crashes: dict[str, int] = {}
    for event in look.events:
        if event.event_id in events.CRASHED and event.data:
            crashes[event.data[0]] = crashes.get(event.data[0], 0) + 1
    shutdowns = events.unexpected_shutdowns(look.events)
    lines = [
        f"The System log, last {look.days} days: {len(look.events)} entries about crashes and "
        "shutdowns" + (f" (stopped at {events.MAX_EVENTS}; there are more)" if look.capped else ""),
    ]
    if look.unreadable:
        lines.append(f"{look.unreadable} entries could not be read and were skipped")
    lines += ["", f"Services that stopped unexpectedly ({len(crashes)}):"]
    for name, count in sorted(crashes.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {count:>6}  {shown(name, 70)}")
    lines += ["", f"Times Windows went off without shutting down: {len(shutdowns)}"]
    lines += [f"  {f.identifier}" for f in shutdowns]
    return lines


def render_startup(look: StartupLook) -> list[str]:
    titles: dict[Kind, str] = {
        "registry": "Started by the registry's startup keys",
        "folder": "In a Startup folder",
        "service": "Services that start automatically",
        "task": "Scheduled tasks that run at boot or logon",
    }
    lines = [f"{len(look.entries)} things start with this machine without being asked"]
    if look.unreadable:
        lines.append(f"{look.unreadable} places could not be read without administrator rights")
    for kind, title in titles.items():
        entries = startup.of_kind(look.entries, kind)
        lines += ["", f"{title} ({len(entries)}):"]
        for entry in entries:
            lines.append(
                f"  {shown(entry.name, 48):<48} {shown(entry.where, 24):<24} {shown(entry.command, 90)}"
            )
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sletchy-soc", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="view", required=True)
    processes = sub.add_parser("processes", help="what is running, grouped by program")
    processes.add_argument("--top", type=int, default=25, help="how many programs to show")
    network = sub.add_parser("network", help="what is listening, and who holds connections")
    log = sub.add_parser("events", help="crash loops and unexpected shutdowns in the System log")
    log.add_argument(
        "--days",
        type=int,
        default=10,
        choices=range(1, events.MAX_DAYS + 1),
        metavar="N",
        help=f"how far back to read, 1 to {events.MAX_DAYS} (default 10)",
    )
    boot = sub.add_parser("startup", help="what starts with the machine without being asked")
    for p in (processes, network, log, boot):
        p.add_argument("--dry-run", action="store_true", help="show, and record nothing")
    return parser


def run(
    args: argparse.Namespace,
    ledger: Ledger | None,
    *,
    look: Callable[..., Snapshot] = take,
    read_log: Callable[..., Look] = events.take,
    read_startup: Callable[[], StartupLook] = startup.take,
    today: date | None = None,
    out: Callable[[str], None] = print,
) -> int:
    """One look. `ledger` is None only for a dry run where no Sletchy exists."""
    whole_machine = ledger is not None and FlagStore.open(ledger, paths.flags_file()).is_on(
        WATCH_FLAG
    )
    day = today or date.today()
    if args.view in ("events", "startup") and not whole_machine:
        what = "The System log" if args.view == "events" else "What starts with the machine"
        out(f"{what} is the whole machine's, not Sletchy's: reading it needs the dangerous")
        out(f"flag {WATCH_FLAG} (with a reason). Nothing was read.")
        return 0
    view: list[str]
    found: list[Finding]
    try:
        if args.view == "events":
            log = read_log(days=args.days)
            view, found = render_events(log), events.findings(log, today=day)
        elif args.view == "startup":
            boot_look = read_startup()
            view, found = render_startup(boot_look), startup.findings(boot_look)
        else:
            snapshot = look(whole_machine=whole_machine)
            view = (
                render_processes(snapshot, args.top)
                if args.view == "processes"
                else render_network(snapshot)
            )
            found = rules.findings(snapshot)
    except SensorUnavailable as exc:
        print(f"sletchy-soc: {exc}", file=sys.stderr)
        return 1
    outcome = None
    if not args.dry_run and ledger is not None:
        outcome = record(ledger, found, today=day, seen_file=seen_file())
    for line in [*view, *render_findings(found, outcome)]:
        out(line)
    if not whole_machine:
        out(
            f"\nTo look at the whole machine, turn on the dangerous flag {WATCH_FLAG} (with a reason)."
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ledger = Ledger.open(paths.ledger_dir(), KeyringKeySource(), create=False)
    except LedgerMissing:
        if not args.dry_run:
            print(
                f"sletchy-soc: no Sletchy in {paths.home()}: findings go on its record, so "
                "there must be one (sletchy init). --dry-run looks without recording.",
                file=sys.stderr,
            )
            return 1
        ledger = None
    except LedgerCorrupt as exc:
        print(f"LEDGER CORRUPT: {exc}", file=sys.stderr)
        return 2
    try:
        return run(args, ledger)
    finally:
        if ledger is not None:
            ledger.close()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
