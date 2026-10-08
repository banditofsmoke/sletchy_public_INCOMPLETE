"""`sletchy sandbox run` - the Warden from a terminal, through its supervisor (#52).

`winjob` is real, measured containment, and until now the only way to reach it was to
import it from Python. This is the operator's way in, and it goes through the one door
the Shell has into the Warden: the supervisor (ADR-0011), which decides whether a program
may run, records the decision first, and then runs it in the strongest sandbox allowed.

**Nothing runs until a program is on the allowlist**, `var/allowlist.toml`:

    [programs]
    curl = "C:/Windows/System32/curl.exe"

**Flags only tighten.** `--timeout`, `--memory-mb` and `--cpu-percent` may lower the
defaults (LAW 0 section 5) and are refused above them, before anything is opened (LAW 3).
`--backend` names a minimum; if it cannot be met, nothing runs and nothing weaker is used.
There is no flag that weakens isolation, and there never will be (#52, out of scope
permanently).

**The exit code says who stopped it.** The program's own code when it ended by itself;
124 when the sandbox stopped it at the wall-clock limit; 125 when a resource limit did;
126 when it was refused and never started. A line on stderr says the same in words.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from sletchy.cli import paths
from sletchy.kernel.contracts import IsolationBackend, IsolationProfile, ResourceLimits
from sletchy.kernel.ledger import PayloadStore
from sletchy.warden.supervisor import (
    IsolationError,
    LaunchDenied,
    Supervisor,
    load_allowlist,
    plan,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sletchy.kernel.ledger import Ledger

ACTOR = "operator_cli"

EXIT_TIMED_OUT = 124
EXIT_KILLED = 125
EXIT_REFUSED = 126

#: Backends an operator may ask for. `inproc` is not one: it runs nothing apart from
#: Sletchy and refuses to load outside a test run.
BACKENDS = (IsolationBackend.SUBPROC.value, IsolationBackend.WINJOB.value)

_DEFAULTS = ResourceLimits()


def at_most(ceiling: int, unit: str) -> Callable[[str], int]:
    """An argparse type that accepts a whole number from 1 to `ceiling`, and refuses more."""

    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            value = 0
        if not 1 <= value <= ceiling:
            msg = f"must be a whole number from 1 to {ceiling} {unit}: a flag may only tighten"
            raise argparse.ArgumentTypeError(msg)
        return value

    return parse


def add_parser(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    func: Callable[[argparse.Namespace], int],
) -> None:
    sandbox = sub.add_parser("sandbox", help="run one program inside the sandbox").add_subparsers(
        dest="sandbox_command", required=True
    )
    run = sandbox.add_parser(
        "run",
        help="run an allowlisted program in the strongest sandbox available",
        description=(
            "Run one program inside Sletchy's sandbox. It must be on the allowlist, "
            f"{paths.allowlist_file()}; nothing is on it until you add it, so nothing "
            "runs until then. Every decision is recorded before anything starts."
        ),
    )
    run.add_argument("--workspace", required=True, metavar="DIR", help="the folder it may use")
    run.add_argument(
        "--backend",
        choices=BACKENDS,
        default=IsolationBackend.WINJOB.value,
        help="the weakest sandbox you will accept (default: winjob); never weakened",
    )
    run.add_argument(
        "--timeout",
        type=at_most(_DEFAULTS.wall_clock_seconds, "seconds"),
        metavar="S",
        help=f"wall-clock limit, at most {_DEFAULTS.wall_clock_seconds}",
    )
    run.add_argument(
        "--memory-mb",
        type=at_most(_DEFAULTS.memory_mb, "MB"),
        metavar="MB",
        help=f"memory limit, at most {_DEFAULTS.memory_mb}",
    )
    run.add_argument(
        "--cpu-percent",
        type=at_most(_DEFAULTS.cpu_percent, "percent"),
        metavar="P",
        help=f"CPU limit, at most {_DEFAULTS.cpu_percent}",
    )
    run.add_argument(
        "--dry-run", action="store_true", help="say what would run; start and record nothing"
    )
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- PROGRAM [ARGS...]")
    run.set_defaults(func=func)


def profile_from(args: argparse.Namespace) -> IsolationProfile:
    """The default profile, tightened by whatever flags were given. Never widened."""
    asked = ResourceLimits(
        memory_mb=args.memory_mb or _DEFAULTS.memory_mb,
        cpu_percent=args.cpu_percent or _DEFAULTS.cpu_percent,
        wall_clock_seconds=args.timeout or _DEFAULTS.wall_clock_seconds,
    )
    return IsolationProfile(
        backend=IsolationBackend(args.backend), resources=_DEFAULTS.tighten(asked)
    )


def command_from(args: argparse.Namespace) -> list[str]:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    return command


def _refused(why: str) -> int:
    print(f"sandbox: refused, nothing was run. {why}", file=sys.stderr)
    return EXIT_REFUSED


def dry_run(args: argparse.Namespace) -> int:
    """The plan, with nothing started and nothing recorded."""
    try:
        allowlist = load_allowlist(paths.allowlist_file())
        planned = plan(
            allowlist,
            command_from(args),
            workspace=Path(args.workspace),
            profile=profile_from(args),
        )
    except (ValueError, LaunchDenied, IsolationError) as exc:
        return _refused(str(exc))
    profile = profile_from(args)
    print(f"would run   {' '.join(planned.argv)}")
    print(f"allowed as  {planned.rule}")
    print(f"sandbox     {planned.backend}")
    print(
        f"limits      {profile.resources.wall_clock_seconds} s, {profile.resources.memory_mb} MB, "
        f"{profile.resources.cpu_percent}% CPU"
    )
    print("dry run: nothing was started and nothing was recorded")
    return 0


def run(args: argparse.Namespace, ledger: Ledger) -> int:
    """Decide, record, run, and report who stopped it."""
    try:
        allowlist = load_allowlist(paths.allowlist_file())
    except ValueError as exc:
        return _refused(str(exc))
    supervisor = Supervisor.for_ledger(
        allowlist, ledger=ledger, actor_id=ACTOR, payloads=PayloadStore.open(paths.payload_dir())
    )
    try:
        result = supervisor.launch(
            command_from(args), workspace=Path(args.workspace), profile=profile_from(args)
        )
    except (LaunchDenied, IsolationError) as exc:
        return _refused(f"{exc}. The refusal is on the record: sletchy ledger show --denied")
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.timed_out:
        print(f"sandbox: stopped at the wall-clock limit ({result.backend.value})", file=sys.stderr)
        return EXIT_TIMED_OUT
    if result.killed_by_limit:
        print(f"sandbox: stopped by a resource limit ({result.backend.value})", file=sys.stderr)
        return EXIT_KILLED
    print(f"sandbox: exited {result.exit_code} ({result.backend.value})", file=sys.stderr)
    return result.exit_code if result.exit_code is not None else 1
