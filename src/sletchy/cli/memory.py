"""`sletchy memory` - what Sletchy remembers, from a terminal (ADR-0019, #194).

    sletchy memory add NAME < notes.md          a document, read from standard input
    sletchy memory search "what did I decide"   the paragraphs that match best
    sletchy memory list                         what it holds
    sletchy memory forget NAME                  remove a document or a conversation
    sletchy memory search --embed embeddinggemma:300m "..."   by meaning too
    sletchy memory ask gemma3:1b "where did I put the keys"  answered from memory alone
    sletchy memory measure gemma3:1b < docs/measure/judge-seed.jsonl   score a judge

**Sletchy reads no file itself.** A document comes in on standard input, so the shell
reads it, and `fs_outside_var` stays off. Everything is stored under `var/memory/`.

**Off until the operator turns it on**: `sletchy flags set mind_memory on`. Searching by
meaning asks an embedding model through the same door as `sletchy ask`, so it needs
`mind_local_models` on too; without it, search is by words alone and says so.

**What it shows is inert**: stored text can hold anything, so control characters are
shown as `?`, and every line of a passage is quoted under its source.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from sletchy.cli import paths
from sletchy.cli.ask import ACTOR, EXIT_FAILED, EXIT_OK, _failed, _model, recall_for
from sletchy.kernel.contracts import AgentEvent, AgentEventType
from sletchy.kernel.ledger import PayloadStore
from sletchy.mind.harness import Conversation
from sletchy.mind.harness.hosts.cli import render
from sletchy.mind.local import SWITCH as LOCAL_SWITCH
from sletchy.mind.local import EgressDenied, ModelRefused, ModelUnreadable, inert
from sletchy.mind.memory import (
    SWITCH,
    LocalEmbedder,
    MemoryRefused,
    MemoryStore,
    document,
)
from sletchy.mind.memory.gate import ModelJudge
from sletchy.mind.memory.measure import measure as run_measure
from sletchy.mind.memory.measure import read_set

if TYPE_CHECKING:
    from sletchy.kernel.flags import FlagStore
    from sletchy.kernel.ledger import Ledger

#: The most a document may be, read from standard input.
MAX_DOCUMENT_CHARS = 2_000_000
#: The most a labelled set may be, read from standard input.
MAX_SET_CHARS = 2_000_000
QUOTE = "  > "


def _store(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> MemoryStore:
    embed = getattr(args, "embed", None)
    return MemoryStore(
        paths.memory_dir(),
        ledger=ledger,
        store=PayloadStore.open(paths.payload_dir()),
        actor_id=ACTOR,
        switched_on=lambda: flags.is_on(SWITCH),
        embedder=LocalEmbedder(_model(ledger, flags, args.port), embed) if embed else None,
    )


def _refused(exc: MemoryRefused) -> int:
    if "switched off" in exc.reason:
        print(
            "Memory is switched off. To let Sletchy keep and search what was said: "
            f'sletchy flags set {SWITCH} on --reason "..."',
            file=sys.stderr,
        )
    else:
        print(f"refused: {exc.reason} (record entry {exc.seq})", file=sys.stderr)
    return EXIT_FAILED


def add(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    text = sys.stdin.read(MAX_DOCUMENT_CHARS + 1)
    if len(text) > MAX_DOCUMENT_CHARS:
        print(f"refused: a document over {MAX_DOCUMENT_CHARS} characters", file=sys.stderr)
        return EXIT_FAILED
    chunks = document(args.name, text)
    if not chunks:
        print("Nothing to add: the document has no text.", file=sys.stderr)
        return EXIT_FAILED
    memory = _store(args, ledger, flags)
    try:
        added = memory.add(chunks)
    except MemoryRefused as exc:
        return _refused(exc)
    except (EgressDenied, ModelRefused, ModelUnreadable, OSError) as exc:
        return _failed(exc, args.port)
    finally:
        memory.close()
    print(
        f"{inert(added.source)}: {added.new} new chunks, {added.already} already held"
        + (f", {added.embedded} with vectors" if added.embedded else "")
        + f". On the record as entry {added.seq}."
    )
    return EXIT_OK


def search(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    memory = _store(args, ledger, flags)
    try:
        found = memory.search(" ".join(args.question), k=args.k)
    except MemoryRefused as exc:
        return _refused(exc)
    finally:
        memory.close()
    if not found.passages:
        print("Nothing in memory matches.")
    for i, passage in enumerate(found.passages, start=1):
        print(f"[{i}] {inert(passage.header)}  ({'+'.join(passage.by)}, {passage.score:.4f})")
        if passage.cites is not None:
            print(f"    from the answer at record entry {passage.cites}")
        for line in inert(passage.text).split("\n"):
            print(f"{QUOTE}{line}")
    how = "words and meaning" if found.by_meaning else "words only"
    print(
        f"\n(searched by {how}; on the record as entries {found.search_seq} and {found.found_seq})",
        file=sys.stderr,
    )
    return EXIT_OK


def listing(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    memory = _store(args, ledger, flags)
    try:
        held = memory.sources()
    except MemoryRefused as exc:
        return _refused(exc)
    finally:
        memory.close()
    if not held:
        print("Memory is empty.")
    for source, kind, count in held:
        print(f"  {kind:<12} {count:>6} chunks  {inert(source)}")
    return EXIT_OK


def ask(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    """One question, answered from memory alone, or "not in my memory" (ADR-0019).

    Exits 0 when it was answered or found not to be in memory; 1 when it was refused or
    not answered.
    """
    model = _model(ledger, flags, args.port, args.context)
    conversation = Conversation(
        model,
        args.model,
        ledger=ledger,
        actor_id=ACTOR,
        recall=recall_for(args, ledger, flags, model),
        only_from_memory=True,
    )
    unanswered: list[AgentEvent] = []

    def show(event: AgentEvent) -> None:
        if event.type in (AgentEventType.POLICY, AgentEventType.ERROR):
            unanswered.append(event)
        text = render(event)
        if text:
            print(text, flush=True)

    conversation.play(" ".join(args.question), show)
    return EXIT_FAILED if unanswered else EXIT_OK


def measure(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    """Score a model as the gate's judge on a labelled set, read from standard input (#195)."""
    if not flags.is_on(LOCAL_SWITCH):
        print(
            "Local AI models are switched off, and measuring a judge asks one. To turn them "
            f'on: sletchy flags set {LOCAL_SWITCH} on --reason "..."',
            file=sys.stderr,
        )
        return EXIT_FAILED
    try:
        items = read_set(sys.stdin.read(MAX_SET_CHARS).splitlines())
    except ValueError as exc:
        print(f"not a labelled set: {exc}", file=sys.stderr)
        return EXIT_FAILED
    if not items:
        print("The set is empty.", file=sys.stderr)
        return EXIT_FAILED
    report = run_measure(ModelJudge(_model(ledger, flags, args.port), args.model), items)
    for line in report.lines():
        print(inert(line))
    return EXIT_OK


def forget(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    memory = _store(args, ledger, flags)
    try:
        count = memory.forget(args.name)
    except MemoryRefused as exc:
        return _refused(exc)
    finally:
        memory.close()
    print(f"Forgot {count} chunks of {inert(args.name)}. The record keeps that it was there.")
    return EXIT_OK
