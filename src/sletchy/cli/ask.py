"""`sletchy models`, `ask` and `chat` - a model on this computer, from a terminal.

    sletchy models                         what the model server has, and what fits
    sletchy ask gemma3:1b "Hello"          one question, one answer
    sletchy chat gemma3:1b                 a conversation: one question a line
    sletchy ask --port 8080 ...            a server on another local port
    sletchy load gemma3:1b --context 16384  put a model on the card before talking
    sletchy unload gemma3:1b               take it off the card now
    sletchy chat --context 16384 gemma3:1b the same context it was loaded with

With `mind_memory` on, `chat` remembers (ADR-0019): each question is searched for in
memory, the model judges what it found, and what helps is quoted before the question
with where it came from; every answered turn is kept. `--embed MODEL` searches by meaning
too.

`ask` is ADR-0017's; `chat` runs the harness (ADR-0018), so each question is sent with
the conversation so far, and every line Sletchy prints is from an event on the record.

**Off until the operator turns it on**: `sletchy flags set mind_local_models on`. Every
question and answer is on the ledger, with both texts in the payload store, so
`sletchy ledger show --action mind.model` reads the conversation back.

**Sletchy never starts a model server.** If none is answering, it says so and stops:
start Ollama yourself. Nothing here reaches beyond `127.0.0.1`.

**The answer is shown inert.** It is a model's text, and a model can be talked into
writing terminal escape codes; every control character but a newline and a tab is
shown as `?`.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from sletchy.cli import paths
from sletchy.kernel.contracts import AgentEvent, AgentEventType
from sletchy.kernel.ledger import PayloadStore
from sletchy.mind.harness import Conversation
from sletchy.mind.harness.hosts.cli import render
from sletchy.mind.local import (
    CARD_BYTES,
    CONTEXT_CHOICES,
    CONTEXT_TOKENS,
    KEEP_ALIVE,
    MAX_MODEL_BYTES,
    MODEL_SHARE,
    OLLAMA_PORT,
    SWITCH,
    EgressDenied,
    LocalModel,
    ModelRefused,
    ModelUnreadable,
    Running,
    can_talk,
    inert,
)
from sletchy.mind.memory import SWITCH as MEMORY_SWITCH
from sletchy.mind.memory import LocalEmbedder, MemoryStore
from sletchy.mind.memory.gate import Gate, ModelJudge
from sletchy.mind.memory.recall import Recall

if TYPE_CHECKING:
    from sletchy.kernel.flags import FlagStore
    from sletchy.kernel.ledger import Ledger

ACTOR = "operator_cli"

#: Where Ollama listens unless `--port` says otherwise.
DEFAULT_PORT = OLLAMA_PORT
#: The context unless `--context` says otherwise (#202).
DEFAULT_CONTEXT = CONTEXT_TOKENS

EXIT_OK = 0
EXIT_FAILED = 1


def port(text: str) -> int:
    """A local port an unprivileged server can use, for `--port`."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a port: {text!r}") from None
    if not 1024 <= value <= 65535:
        raise argparse.ArgumentTypeError("a port from 1024 to 65535")
    return value


def context(text: str) -> int:
    """A context the conversation may have, for `--context` (#202)."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of tokens: {text!r}") from None
    if value not in CONTEXT_CHOICES:
        raise argparse.ArgumentTypeError(f"one of {', '.join(map(str, CONTEXT_CHOICES))}")
    return value


def _model(
    ledger: Ledger, flags: FlagStore, port: int, context_tokens: int = CONTEXT_TOKENS
) -> LocalModel:
    return LocalModel.on_this_machine(
        ledger=ledger,
        store=PayloadStore.open(paths.payload_dir()),
        actor_id=ACTOR,
        switched_on=lambda: flags.is_on(SWITCH),
        port=port,
        context_tokens=context_tokens,
    )


def _failed(exc: Exception, port: int) -> int:
    if isinstance(exc, EgressDenied) and "switched off" in exc.reason:
        print(
            "Local AI models are switched off. To let Sletchy ask a model on this "
            f'computer: sletchy flags set {SWITCH} on --reason "..."',
            file=sys.stderr,
        )
    elif isinstance(exc, (EgressDenied, ModelRefused)):
        print(f"refused: {exc.reason}", file=sys.stderr)
    elif isinstance(exc, ModelUnreadable):
        print(f"the model server's answer could not be read: {exc}", file=sys.stderr)
    else:
        print(
            f"No model server is answering on 127.0.0.1:{port}. Sletchy never starts one: "
            "start Ollama yourself, then ask again.",
            file=sys.stderr,
        )
    return EXIT_FAILED


def models(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    try:
        local = _model(ledger, flags, args.port)
        found = local.models()
        try:
            held = {r.name: r for r in local.running()}
        except (ModelUnreadable, OSError):
            held = {}
        talks = {m.name: _talks(local, m.name) for m in found}
    except (EgressDenied, ModelUnreadable, OSError) as exc:
        return _failed(exc, args.port)
    print(
        f"Sletchy asks models up to {MAX_MODEL_BYTES / 1024**3:.2f} GiB: {MODEL_SHARE:.0%} of "
        f"this card's {CARD_BYTES / 1024**3:.2f} GiB, so the rest is left for the conversation."
        " (Ollama lists sizes in GB, 1000-based; these are GiB, 1024-based.)"
    )
    if not found:
        print("The model server has no models.")
        return EXIT_OK
    for model in sorted(found, key=lambda m: m.size_bytes):
        fits = 0 <= model.size_bytes <= MAX_MODEL_BYTES
        size = f"{model.size_bytes / 1024**3:6.2f} GiB" if model.size_bytes >= 0 else "     ? GiB"
        note = "" if fits else "   too big to leave room for a conversation: not asked"
        if talks[model.name] is False:
            note += "   for memory search, not for talking to"
        if model.name in held:
            note += "   " + _held(held[model.name])
        print(f"  {size}  {inert(model.name)}{note}")
    return EXIT_OK


def _talks(local: LocalModel, name: str) -> bool | None:
    """Whether the server says a model can hold a conversation (#204); None if not said."""
    try:
        return can_talk(local.capabilities(name))
    except (ModelRefused, ModelUnreadable, OSError):
        return None


def _held(running: Running) -> str:
    """One loaded model in a line: its context, how much is on the card, until when."""
    share = running.vram_bytes / running.size_bytes if running.size_bytes > 0 else 0.0
    return (
        f"loaded: a context of {running.context_tokens} tokens, {share:.0%} on the card"
        + (", the rest on the processor, slower" if share < 1 else "")
        + (f", until {inert(running.expires_at)[:40]}" if running.expires_at else "")
    )


def load(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    """Put a model on the card with a context, before any question (#202)."""
    print(
        f"Loading {inert(args.model)[:80]} with a context of {args.context} tokens. The first "
        "load from disk can take minutes.",
        file=sys.stderr,
    )
    try:
        loaded = _model(ledger, flags, args.port, args.context).load(args.model)
    except (EgressDenied, ModelRefused, ModelUnreadable, OSError) as exc:
        return _failed(exc, args.port)
    print(f"{inert(args.model)[:80]} {_held(loaded.running)}")
    print(
        f"(in {loaded.seconds:.1f} s, {loaded.load_seconds:.1f} s of it the server's own load; "
        f"kept {KEEP_ALIVE} after its last request; on the record as entries "
        f"{loaded.load_seq} and {loaded.loaded_seq})",
        file=sys.stderr,
    )
    return EXIT_OK


def unload(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    """Take a model off the card now (#202)."""
    try:
        seq = _model(ledger, flags, args.port).unload(args.model)
    except (EgressDenied, ModelRefused, ModelUnreadable, OSError) as exc:
        return _failed(exc, args.port)
    print(f"Unloaded {inert(args.model)[:80]}. On the record as entry {seq}.")
    return EXIT_OK


def ask(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    question = " ".join(args.question)
    try:
        answer = _model(ledger, flags, args.port, args.context).ask(args.model, question)
    except (EgressDenied, ModelRefused, ModelUnreadable, OSError) as exc:
        return _failed(exc, args.port)
    print(inert(answer.text))
    used = answer.prompt_tokens + answer.answer_tokens
    print(
        f"\n({answer.model}, {answer.seconds:.1f} s; context {used} of "
        f"{answer.context_tokens} tokens; on the record as entries {answer.asked_seq} and "
        f"{answer.answered_seq})",
        file=sys.stderr,
    )
    if answer.out_of_room:
        print(
            f"The answer stopped early: the model ran out of room in its context "
            f"({answer.context_tokens} tokens). Ask a shorter question.",
            file=sys.stderr,
        )
    return EXIT_OK


def recall_for(
    args: argparse.Namespace, ledger: Ledger, flags: FlagStore, model: LocalModel
) -> Recall:
    """Memory for a conversation (ADR-0019): the store, by meaning too if `--embed` names a
    model, and the gate, judged by the conversation's own model."""
    payloads = PayloadStore.open(paths.payload_dir())
    embed = getattr(args, "embed", None)
    store = MemoryStore(
        paths.memory_dir(),
        ledger=ledger,
        store=payloads,
        actor_id=ACTOR,
        switched_on=lambda: flags.is_on(MEMORY_SWITCH),
        embedder=LocalEmbedder(model, embed) if embed else None,
    )
    gate = Gate(ModelJudge(model, args.model), ledger=ledger, store=payloads, actor_id=ACTOR)
    return Recall(store, gate)


def chat(args: argparse.Namespace, ledger: Ledger, flags: FlagStore) -> int:
    """A conversation: one question a line, until an empty line or the end of input.

    Exits 0 only if every question asked was answered.
    """
    model = _model(ledger, flags, args.port, args.context)
    recall = recall_for(args, ledger, flags, model) if flags.is_on(MEMORY_SWITCH) else None
    conversation = Conversation(model, args.model, ledger=ledger, actor_id=ACTOR, recall=recall)
    print(
        f"A conversation with {inert(args.model)[:80]}, every word on the record. "
        "An empty line ends it.",
        file=sys.stderr,
    )
    if recall is not None:
        print(
            "Memory is on: each question is searched for in memory first, what helps is "
            "quoted with where it came from, and every answered turn is kept under "
            "var/memory/.",
            file=sys.stderr,
        )
    unanswered: list[AgentEvent] = []

    def show(event: AgentEvent) -> None:
        if event.type in (AgentEventType.POLICY, AgentEventType.ERROR):
            unanswered.append(event)
        text = render(event)
        if text:
            print(text, flush=True)

    while True:
        try:
            question = input("you> ")
        except EOFError:
            break
        if not question.strip():
            break
        conversation.play(question, show)
    print(
        f"{conversation.turns} answered; conversation {conversation.id} is on the record.",
        file=sys.stderr,
    )
    return EXIT_FAILED if unanswered else EXIT_OK
