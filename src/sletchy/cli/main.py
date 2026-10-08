"""The `sletchy` command - the operator surface.

Deliberately small. This is for inspecting state and stopping things, not for
running agents; the user surface is the desktop shell (Wave 6).

Every command that reads the ledger opens it through `Ledger.open()`, which
verifies before returning. So `sletchy status` on a tampered ledger fails loudly
rather than printing a reassuring summary over a broken chain.

**`stop` is the exception**: it must work when everything else is broken, so it
never opens the ledger to do its work. It writes a final entry only if it can.
Its old name, `panic`, still works and is listed nowhere (`OLD_NAMES`).
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from sletchy import __version__
from sletchy.cli import ask as ask_cmd
from sletchy.cli import memory as memory_cmd
from sletchy.cli import paths
from sletchy.cli import rules as rules_cmd
from sletchy.cli import sandbox as sandbox_cmd
from sletchy.cli.bridge import run as run_bridge
from sletchy.cli.ledger_view import EntryNotFound, read_entries, read_payload, render_payload
from sletchy.cli.ledger_view import render as render_entries
from sletchy.cli.panic import PANIC_LOCK_WAIT_SECONDS
from sletchy.cli.panic import panic as run_panic
from sletchy.cli.selfcheck import run_selfcheck
from sletchy.kernel.flags import FlagStore, ReasonRequired, UnknownFlag
from sletchy.kernel.ledger import (
    LOCK_WAIT_SECONDS,
    Ledger,
    LedgerCorrupt,
    LedgerError,
    LedgerMissing,
    PayloadStore,
    SigningKeyMissing,
)
from sletchy.kernel.ledger.keys import KeyringKeySource

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CORRUPT = 2


def _open_ledger(*, lock_wait: float = LOCK_WAIT_SECONDS) -> Ledger:
    """Every command but `init` opens an existing ledger and never creates one (#102)."""
    return Ledger.open(paths.ledger_dir(), KeyringKeySource(), create=False, lock_wait=lock_wait)


def _open_flags(ledger: Ledger) -> FlagStore:
    return FlagStore.open(ledger, paths.flags_file())


# ── commands ─────────────────────────────────────────────────────────────────


def _say_corrupt(exc: LedgerCorrupt) -> int:
    print(f"LEDGER CORRUPT: {exc}", file=sys.stderr)
    print(
        "\nSletchy will not run against a chain that does not verify, and it does "
        "not repair one. The file has not been modified.",
        file=sys.stderr,
    )
    return EXIT_CORRUPT


def cmd_status(_: argparse.Namespace) -> int:
    print(f"sletchy {__version__}")
    print(f"home    {paths.home()}")

    try:
        ledger = _open_ledger()
    except LedgerMissing:
        print(f"ledger  NOT SET UP in this folder - there is no {paths.ledger_dir()}")
        print("        run `sletchy init` here, or set SLETCHY_HOME to where Sletchy lives")
        return EXIT_FAILED
    except SigningKeyMissing:
        print("ledger  NOT INITIALISED - run `sletchy init`")
        return EXIT_FAILED
    except LedgerCorrupt as exc:
        print(f"ledger  CORRUPT - {exc}")
        return EXIT_CORRUPT

    entries = ledger.length
    print(f"ledger  {entries} entries, chain verified")
    full = ledger.full()
    if full:
        print(f"        FULL - {full}")
    if ledger.mark_behind:
        print(
            f"        the keychain's record of the ledger's length is {ledger.mark_behind} "
            "behind, so cutting that many entries off the end would not be caught (#99)"
        )

    if paths.payload_dir().is_dir():
        payloads = PayloadStore.open(paths.payload_dir())
        print(f"payloads {len(list(payloads.digests()))} objects, {payloads.total_bytes()} bytes")
    else:
        print("payloads none")

    flags = _open_flags(ledger)
    on = [name for name, value in flags.snapshot().items() if value]
    dangerous_on = [f.name for f in flags.registry.dangerous() if flags.is_on(f.name)]
    print(f"flags   {len(on)} on of {len(flags.registry)}")
    if dangerous_on:
        print(f"        DANGEROUS ON: {', '.join(sorted(dangerous_on))}")
    else:
        print("        no dangerous flags enabled")
    if flags.unexplained:
        # Named on every status until someone looks (#100): the file says on, nothing
        # in the ledger turned it on, so it is treated as off.
        print(
            f"        UNEXPLAINED: {', '.join(flags.unexplained)} on in flags.json with no "
            "ledger entry turning it on - treated as off"
        )
        return EXIT_FAILED
    return EXIT_FAILED if full else EXIT_OK


def cmd_ledger_verify(_: argparse.Namespace) -> int:
    try:
        entries = _open_ledger().verify()
    except SigningKeyMissing as exc:
        print(f"cannot verify: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except LedgerCorrupt as exc:
        return _say_corrupt(exc)
    print(f"chain verified: {entries} entries")
    return EXIT_OK


def cmd_ledger_show(args: argparse.Namespace) -> int:
    """Print entries oldest-first. The chain is verified before anything is shown (#50)."""
    try:
        ledger = _open_ledger()
    except SigningKeyMissing as exc:
        print(f"cannot read the ledger: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except LedgerCorrupt as exc:
        print(f"LEDGER CORRUPT: {exc}", file=sys.stderr)
        print("Nothing is shown from a chain that does not verify.", file=sys.stderr)
        return EXIT_CORRUPT
    if args.payload is not None:
        return _show_payload(ledger, args)
    try:
        entries = read_entries(
            ledger, tail=args.tail, action_prefix=args.action, denied_only=args.denied
        )
    finally:
        ledger.close()
    print(render_entries(entries))
    return EXIT_OK


def _show_payload(ledger: Ledger, args: argparse.Namespace) -> int:
    """`--payload SEQ`: one entry and its body, secrets masked (#86).

    The store is constructed, not opened, so a read never creates a folder (#102).
    """
    try:
        if args.tail is not None or args.action or args.denied:
            print(
                "--payload shows one entry; it cannot be combined with --tail, --action "
                "or --denied",
                file=sys.stderr,
            )
            return EXIT_FAILED
        try:
            entry, payload = read_payload(ledger, PayloadStore(paths.payload_dir()), args.payload)
        except EntryNotFound as exc:
            print(f"{exc}. `sletchy ledger show --tail 20` lists recent ones.", file=sys.stderr)
            return EXIT_FAILED
    finally:
        ledger.close()
    print(render_payload(entry, payload))
    return EXIT_OK


def cmd_sandbox_run(args: argparse.Namespace) -> int:
    """`sandbox run`: through the supervisor, which decides and records first (#52)."""
    if args.dry_run:
        return sandbox_cmd.dry_run(args)
    try:
        ledger = _open_ledger()
    except SigningKeyMissing as exc:
        print(f"cannot run anything: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except LedgerCorrupt as exc:
        return _say_corrupt(exc)
    try:
        return sandbox_cmd.run(args, ledger)
    finally:
        ledger.close()


def _with_flags(args: argparse.Namespace, run: Callable[..., int]) -> int:
    """Open the ledger and the switches, run, close. For commands that read a switch."""
    try:
        ledger = _open_ledger()
    except SigningKeyMissing as exc:
        print(f"cannot run anything: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except LedgerCorrupt as exc:
        return _say_corrupt(exc)
    try:
        return run(args, ledger, _open_flags(ledger))
    finally:
        ledger.close()


def cmd_models(args: argparse.Namespace) -> int:
    """`models`: what the model server on this computer has (ADR-0017)."""
    return _with_flags(args, ask_cmd.models)


def cmd_ask(args: argparse.Namespace) -> int:
    """`ask`: one question to a model on this computer, recorded before and after."""
    return _with_flags(args, ask_cmd.ask)


def cmd_load(args: argparse.Namespace) -> int:
    """`load`: put a model on the card with a context, before any question (#202)."""
    return _with_flags(args, ask_cmd.load)


def cmd_unload(args: argparse.Namespace) -> int:
    """`unload`: take a model off the card now (#202)."""
    return _with_flags(args, ask_cmd.unload)


def cmd_chat(args: argparse.Namespace) -> int:
    """`chat`: a conversation with a model on this computer, through the harness (ADR-0018)."""
    return _with_flags(args, ask_cmd.chat)


def cmd_memory_add(args: argparse.Namespace) -> int:
    """`memory add`: a document from standard input into the recall store (ADR-0019)."""
    return _with_flags(args, memory_cmd.add)


def cmd_memory_search(args: argparse.Namespace) -> int:
    """`memory search`: the paragraphs that best match a question."""
    return _with_flags(args, memory_cmd.search)


def cmd_memory_list(args: argparse.Namespace) -> int:
    """`memory list`: what the recall store holds."""
    return _with_flags(args, memory_cmd.listing)


def cmd_memory_ask(args: argparse.Namespace) -> int:
    """`memory ask`: a question answered from memory alone, or "not in my memory"."""
    return _with_flags(args, memory_cmd.ask)


def cmd_memory_measure(args: argparse.Namespace) -> int:
    """`memory measure`: score a model as the evidence gate's judge on a labelled set."""
    return _with_flags(args, memory_cmd.measure)


def cmd_memory_forget(args: argparse.Namespace) -> int:
    """`memory forget`: remove a document or a conversation from the recall store."""
    return _with_flags(args, memory_cmd.forget)


def cmd_selfcheck(_: argparse.Namespace) -> int:
    """Run every self-check now and print the evidence behind the trust meter."""
    report = run_selfcheck()
    print(f"trust meter  {report.score} / 100   (highest possible right now: {report.ceiling})")
    for check in report.checks:
        print(f"  {check.status:<10} {check.weight:>3}  {check.label}")
        print(f"             {check.plain}")
    print()
    print("what this does not prove:")
    for line in report.does_not_prove:
        print(f"  - {line}")
    return EXIT_OK if all(c.status != "fail" for c in report.checks) else EXIT_FAILED


def cmd_bridge(_: argparse.Namespace) -> int:
    """JSON lines on stdin/stdout for the desktop shell. Not for humans; see ADR-0008."""
    return run_bridge()


def cmd_flags_list(args: argparse.Namespace) -> int:
    try:
        ledger = _open_ledger()
    except LedgerError as exc:
        print(f"cannot read flags: {exc}", file=sys.stderr)
        return EXIT_FAILED

    flags = _open_flags(ledger)
    width = max(len(f.name) for f in flags.registry)
    for flag in flags.registry:
        value = flags.is_on(flag.name)
        if args.only_on and not value:
            continue
        state = "ON " if value else "off"
        marker = "!" if flag.risk.value == "dangerous" else " "
        print(f"{marker} {state}  {flag.name:<{width}}  {flag.description}")
    return EXIT_OK


def cmd_flags_set(args: argparse.Namespace) -> int:
    try:
        ledger = _open_ledger()
        flags = _open_flags(ledger)
        flags.set(args.name, args.value == "on", reason=args.reason or "")
    except UnknownFlag as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED
    except ReasonRequired as exc:
        print(f'{exc}\n\nRe-run with --reason "why you are enabling this".', file=sys.stderr)
        return EXIT_FAILED
    except LedgerError as exc:
        print(f"cannot flip flag: {exc}", file=sys.stderr)
        return EXIT_FAILED
    print(f"{args.name} -> {args.value}")
    return EXIT_OK


def cmd_stop(args: argparse.Namespace) -> int:
    """Stop everything and revert every host change.

    Flags are reset through the ledger when it is readable. When it is not - a
    missing key, a corrupt chain - it still undoes what it can and clears
    runtime files, because a broken ledger is precisely when stopping matters most.
    """
    flags: FlagStore | None = None
    try:
        flags = _open_flags(_open_ledger(lock_wait=PANIC_LOCK_WAIT_SECONDS))
    except Exception as exc:
        # Deliberately broad. Stop is the command you run when the host is already
        # broken, so ANY failure to reach the ledger - a corrupt chain, an
        # unreachable keychain, a full disk - must degrade to "reset what we can"
        # rather than crash. A narrower except here was a real bug: on a host with
        # no keyring backend, it raised instead of running.
        print(
            f"note: ledger unavailable ({type(exc).__name__}); continuing anyway", file=sys.stderr
        )

    report = run_panic(flags, dry_run=args.dry_run)
    print("STOP EVERYTHING - dry run, nothing changed" if args.dry_run else "STOP EVERYTHING")
    print(report.render())
    return EXIT_OK if report.clean else EXIT_FAILED


def cmd_install_rules(args: argparse.Namespace) -> int:
    """The one step that may need an administrator: the egress firewall rules (#33)."""
    if args.plan or args.check:
        return rules_cmd.run(args, None)
    try:
        ledger = _open_ledger()
    except LedgerMissing:
        return rules_cmd.run(args, None)
    except LedgerCorrupt as exc:
        return _say_corrupt(exc)
    try:
        return rules_cmd.run(args, ledger)
    finally:
        ledger.close()


def cmd_init(_: argparse.Namespace) -> int:
    """Provision the signing keys. The one command that writes to the keychain."""
    home = paths.home()
    home.mkdir(parents=True, exist_ok=True)
    paths.runtime_dir().mkdir(parents=True, exist_ok=True)

    source = KeyringKeySource()
    try:
        source.provision()
        print("ledger signing key provisioned in the OS keychain")
    except ValueError:
        print("ledger signing key already exists - left untouched")
    except Exception as exc:
        print(f"could not provision a signing key: {exc}", file=sys.stderr)
        return EXIT_FAILED

    Ledger.open(paths.ledger_dir(), source)
    PayloadStore.open(paths.payload_dir())
    print(f"initialised at {home}")
    print("every dangerous flag is off - see `sletchy flags list`")
    return EXIT_OK


# ── parser ───────────────────────────────────────────────────────────────────


def _positive_int(text: str) -> int:
    """`--tail`: a whole number above zero, refused before anything is opened (#96).

    `-1` crashed `ledger show` with a ValueError, and `0` printed "no entries match",
    which was not true.
    """
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        msg = f"must be a whole number above zero, not {text!r}"
        raise argparse.ArgumentTypeError(msg)
    return value


def _sequence_number(text: str) -> int:
    """`--payload`: a whole number, zero or more, refused before anything is opened."""
    try:
        value = int(text)
    except ValueError:
        value = -1
    if value < 0:
        msg = f"must be an entry's sequence number (0 or more), not {text!r}"
        raise argparse.ArgumentTypeError(msg)
    return value


def _never_crash_on_output() -> None:
    """Escape what the output encoding cannot hold, rather than crash on it.

    Redirected on Windows (`sletchy ledger show > audit.txt`), stdout is cp1252, and one
    emoji in a stored reason was a UnicodeEncodeError with nothing printed (#96). The
    stored text is not changed; only what cannot be written is shown as its escape.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sletchy",
        description="Operator surface for the Sletchy enclave.",
    )
    parser.add_argument("--version", action="version", version=f"sletchy {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="provision signing keys and create var/").set_defaults(
        func=cmd_init
    )
    sub.add_parser("status", help="what is running, verified, and enabled").set_defaults(
        func=cmd_status
    )

    ledger = sub.add_parser("ledger", help="ledger operations").add_subparsers(
        dest="ledger_command", required=True
    )
    ledger.add_parser("verify", help="verify the whole chain").set_defaults(func=cmd_ledger_verify)
    show = ledger.add_parser("show", help="print entries, oldest first, after verifying")
    show.add_argument(
        "--tail", type=_positive_int, metavar="N", help="only the last N matching entries"
    )
    show.add_argument("--action", metavar="PREFIX", help="only actions under this prefix")
    show.add_argument("--denied", action="store_true", help="only refusals")
    show.add_argument(
        "--payload",
        type=_sequence_number,
        metavar="SEQ",
        help="one entry and its stored body, with secrets masked",
    )
    show.set_defaults(func=cmd_ledger_show)

    sandbox_cmd.add_parser(sub, cmd_sandbox_run)

    listing_models = sub.add_parser("models", help="the models on this computer's model server")
    listing_models.add_argument(
        "--port", type=ask_cmd.port, default=ask_cmd.DEFAULT_PORT, help="its local port"
    )
    listing_models.set_defaults(func=cmd_models)
    question = sub.add_parser("ask", help="ask a model on this computer one question")
    question.add_argument("model", help="the model's name, as `sletchy models` lists it")
    question.add_argument("question", nargs="+", help="the question")
    question.add_argument(
        "--port", type=ask_cmd.port, default=ask_cmd.DEFAULT_PORT, help="its local port"
    )
    question.set_defaults(func=cmd_ask)
    talking = sub.add_parser("chat", help="talk with a model on this computer, a line at a time")
    talking.add_argument("model", help="the model's name, as `sletchy models` lists it")
    talking.add_argument(
        "--port", type=ask_cmd.port, default=ask_cmd.DEFAULT_PORT, help="its local port"
    )
    talking.set_defaults(func=cmd_chat)
    loading = sub.add_parser("load", help="put a model on the card before talking to it")
    loading.add_argument("model", help="the model's name, as `sletchy models` lists it")
    loading.set_defaults(func=cmd_load)
    unloading = sub.add_parser("unload", help="take a model off the card now")
    unloading.add_argument("model", help="the model's name")
    unloading.add_argument(
        "--port", type=ask_cmd.port, default=ask_cmd.DEFAULT_PORT, help="its local port"
    )
    unloading.set_defaults(func=cmd_unload)
    for each in (question, talking, loading):
        each.add_argument(
            "--context",
            type=ask_cmd.context,
            default=ask_cmd.DEFAULT_CONTEXT,
            help="the conversation's context in tokens: 4096, 8192, 16384 or 32768",
        )
    loading.add_argument(
        "--port", type=ask_cmd.port, default=ask_cmd.DEFAULT_PORT, help="its local port"
    )

    remembering = sub.add_parser(
        "memory", help="what Sletchy remembers: add, search, list, forget"
    ).add_subparsers(dest="memory_command", required=True)
    adding = remembering.add_parser("add", help="add a document, read from standard input")
    adding.add_argument("name", help="what to call it, as search results will show it")
    searching = remembering.add_parser("search", help="the paragraphs that best match")
    searching.add_argument("question", nargs="+", help="the question")
    searching.add_argument("--k", type=int, default=5, help="how many paragraphs (1 to 50)")
    remembering.add_parser("list", help="what memory holds").set_defaults(func=cmd_memory_list)
    forgetting = remembering.add_parser("forget", help="remove a document or a conversation")
    forgetting.add_argument("name")
    answering = remembering.add_parser("ask", help="a question answered from memory alone")
    answering.add_argument("model", help="the model that judges and answers")
    answering.add_argument("question", nargs="+", help="the question")
    answering.add_argument(
        "--context",
        type=ask_cmd.context,
        default=ask_cmd.DEFAULT_CONTEXT,
        help="the context the model was loaded with",
    )
    measuring = remembering.add_parser(
        "measure", help="score a model as the gate's judge, on a labelled set from stdin"
    )
    measuring.add_argument("model", help="the model to judge with")
    talking.add_argument(
        "--embed", metavar="MODEL", help="with memory on, an embedding model to search by meaning"
    )
    for each in (adding, searching, answering):
        each.add_argument(
            "--embed", metavar="MODEL", help="an embedding model, to search by meaning too"
        )
    for each, func in (
        (adding, cmd_memory_add),
        (searching, cmd_memory_search),
        (forgetting, cmd_memory_forget),
        (answering, cmd_memory_ask),
        (measuring, cmd_memory_measure),
    ):
        each.set_defaults(func=func)
    for each in remembering.choices.values():
        each.add_argument(
            "--port",
            type=ask_cmd.port,
            default=ask_cmd.DEFAULT_PORT,
            help="the model server's port",
        )

    sub.add_parser(
        "selfcheck", help="check Sletchy now and show the evidence behind the trust meter"
    ).set_defaults(func=cmd_selfcheck)
    sub.add_parser(
        "bridge", help="the desktop shell's channel (JSON lines on stdin/stdout); not for humans"
    ).set_defaults(func=cmd_bridge)

    flags = sub.add_parser("flags", help="capability switches").add_subparsers(
        dest="flags_command", required=True
    )
    listing = flags.add_parser("list", help="show every flag and its state")
    listing.add_argument("--only-on", action="store_true", help="only show enabled flags")
    listing.set_defaults(func=cmd_flags_list)

    setter = flags.add_parser("set", help="turn a flag on or off")
    setter.add_argument("name")
    setter.add_argument("value", choices=["on", "off"])
    setter.add_argument("--reason", help="required when turning a DANGEROUS flag on")
    setter.set_defaults(func=cmd_flags_set)

    stop = sub.add_parser(
        "stop",
        help="stop everything: every switch off, Sletchy's own host changes undone",
        description=(
            "Resets all flags, undoes Sletchy's own host changes and clears runtime files. "
            "Run as administrator, it also removes the Sletchy firewall rules. Never "
            "prompts. Never deletes the ledger, payloads, or keychain."
        ),
    )
    stop.add_argument("--dry-run", action="store_true", help="report without changing anything")
    stop.set_defaults(func=cmd_stop)

    install = sub.add_parser(
        "install-rules",
        help="the sandbox firewall rules: show, add (administrator), check or remove",
        description=(
            "Adds one outbound block rule per sandbox lane, in the Sletchy group only. "
            "Shows exactly what it will do first and waits for yes. Never asks Windows "
            "for administrator rights itself."
        ),
    )
    mode = install.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="show the rules; change nothing")
    mode.add_argument(
        "--check", action="store_true", help="are they installed as planned? (no administrator)"
    )
    mode.add_argument("--remove", action="store_true", help="remove them all (administrator)")
    install.set_defaults(func=cmd_install_rules)

    return parser


def _command_name(args: argparse.Namespace) -> str:
    sub = getattr(args, "ledger_command", None) or getattr(args, "flags_command", None)
    return f"sletchy {args.command}" + (f" {sub}" if sub else "")


def _plain(exc: LedgerError | OSError) -> str:
    """What failed, and where, in one line."""
    if isinstance(exc, OSError) and exc.filename:
        where = str(exc.filename)
        if exc.filename2:
            where += f" -> {exc.filename2}"
        return f"could not use {where}: {exc.strerror or type(exc).__name__}"
    return str(exc) or type(exc).__name__


#: Old command names that still work, and appear in no help or usage line. `panic`
#: became `stop`: the operator's emergency control should not read as an alarm, and
#: notes and habits that say `sletchy panic` should not break.
OLD_NAMES = {"panic": "stop"}


def _new_name(argv: Sequence[str]) -> list[str]:
    """The command's current name for an old one; anything else as given."""
    args = list(argv)
    if args and args[0] in OLD_NAMES:
        args[0] = OLD_NAMES[args[0]]
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Run one command. A failure it can name is a sentence and an exit code (#97).

    A corrupt ledger is exit 2 and any other ledger or filesystem failure is exit 1,
    from every command, `init` included - a crash also exited 1, but by accident
    rather than by contract, and printed a traceback at the operator. Anything else
    still raises: a programming error is not disguised as an operational one.
    `stop` keeps its own broader handling inside `cmd_stop`.
    """
    _never_crash_on_output()
    args = build_parser().parse_args(_new_name(sys.argv[1:] if argv is None else argv))
    try:
        result: int = args.func(args)
    except LedgerCorrupt as exc:
        return _say_corrupt(exc)
    except (LedgerError, OSError) as exc:
        print(f"{_command_name(args)}: {_plain(exc)}", file=sys.stderr)
        return EXIT_FAILED
    return result


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
