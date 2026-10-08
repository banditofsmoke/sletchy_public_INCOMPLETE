"""Ask a model on this machine: the Mind's first light (ADR-0017).

Two things, both through the door in `warden/egress/local.py`:

- `models()`: what the model server has, by name and size
- `ask(model, prompt)`: one question and one answer, nothing streamed. It is two steps,
  `begin` (checked, then recorded) and `send` (asked, then the answer recorded), so the
  harness can say a question is on the record before its answer comes (ADR-0018), and
  a conversation can send its earlier turns with it

**Every question is on the ledger before it is asked** (`mind.model.ask`), with the
prompt in the payload store, and every answer after it arrives (`mind.model.answer`),
with the answer stored beside it and how long it took. A refusal is recorded too. So a
conversation can be read back months later, word for word, and checked against the
chain (LAW 1).

**The card budget (the operator's design, 2026-10-05).** A model needs the card's
memory twice: once for its weights, about its file's size, and again for the
conversation it is holding, its context, which grows with every word. A model that fills
the card leaves no room for the context, and the server then spills onto the processor
or stops, without saying why. So a model may take at most `MODEL_SHARE` of the card, by
the size the server reports, and is refused before it is asked otherwise; the rest is
the context's. Every question carries the same context size, `CONTEXT_TOKENS`, so the
server never picks one that does not fit. Loading a model far bigger than the card would
also push it into system memory, and on this machine that is a machine that stops
answering (LAW 0 section 5). #54 replaces the card's measured size with free memory,
measured at the time.

**The context meter.** Every answer says how many tokens of the context it used, and
whether it stopped because it ran out of room, so a full context is a sentence on the
screen, not an answer that never comes.

**Loading is its own step (#202).** `load` puts a model on the card with no question,
with the context the operator chose from `CONTEXT_CHOICES`, and then reads what the
server holds (`running`, from `/api/ps`): its size, how much of it is on the card, its
context, and when it unloads. A model that runs more than `MAX_SPILL_BYTES` past the card
is unloaded at once and refused (LAW 0 section 5). Every request asks the server to keep
the model `KEEP_ALIVE` after it, not Ollama's five minutes; `unload` frees the card.

**The answer is untrusted text.** It is returned as a string and nothing here acts on
it: no tool call, no code, no instruction is followed. Whoever shows it on a screen
makes it inert first, with `inert()`.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, NoReturn, get_args

from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.warden.egress import EgressDenied
from sletchy.warden.egress.local import LocalModelDoor

#: Where Ollama listens unless told otherwise.
OLLAMA_PORT = 11434

if TYPE_CHECKING:
    from sletchy.kernel.ledger import Ledger, PayloadStore

ASK_ACTION = "mind.model.ask"
ANSWER_ACTION = "mind.model.answer"
EMBED_ACTION = "mind.model.embed"

#: The most text one embedding request carries, in characters. JSON writes a character
#: outside ASCII as six bytes, so this stays inside the door's request limit for nearly any
#: text; a request that does not is refused by the door, on the record.
EMBED_BATCH_CHARS = 16_000

#: The switch this reads, from the registry. Off on a fresh install.
SWITCH = "mind_local_models"

#: The card's memory, as measured on the operator's machine (ADR-0015: 8151 MiB).
CARD_BYTES = 8151 * 1024**2
#: The most of the card a model's weights may take; the rest is left for its context.
#: 0.6 until 2026-10-06, when the operator raised it to run a 9B model (ADR-0017).
MODEL_SHARE = 0.7
MAX_MODEL_BYTES = int(CARD_BYTES * MODEL_SHARE)
#: The contexts a conversation may have, in tokens (#202). Every question of one
#: conversation carries the same one, never left to the server to choose, so the server
#: never reloads the model to change it.
ContextTokens = Literal[4096, 8192, 16384, 32768]
CONTEXT_CHOICES: tuple[int, ...] = get_args(ContextTokens)
#: The context when nobody chose one.
CONTEXT_TOKENS: ContextTokens = 4096
#: How long the server keeps a model loaded after its last request. Ollama's own is five
#: minutes, which made every pause a reload.
KEEP_ALIVE = "30m"
#: The most a loaded model may run past the card, into system memory, by the server's own
#: report. Past it the model is unloaded at once: system memory filling is a machine that
#: stops answering (LAW 0 section 5). Chosen for the operator's machine, 19.9 GB of it.
MAX_SPILL_BYTES = 4 * 1024**3

LOAD_ACTION = "mind.model.load"
LOADED_ACTION = "mind.model.loaded"
UNLOAD_ACTION = "mind.model.unload"
#: Asking the server what a model can do (#204): a read, recorded at the door.
SHOW_ACTION = "mind.model.show"

MAX_PROMPT_CHARS = 32_000

#: Who may have said an earlier message in a conversation.
ROLES = frozenset({"user", "assistant"})

#: Model names as Ollama writes them: `gemma3:1b`, `library/name:tag`, `name-v2.5:latest`.
_MODEL_NAME = re.compile(
    r"^[a-z0-9][a-z0-9._-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63})?(:[a-z0-9._-]{1,63})?$"
)


def inert(text: str) -> str:
    """A model's text, safe to show: no escape codes, no invisible controls.

    Every control character but a newline and a tab becomes `?`, so an answer cannot
    move a terminal's cursor, clear a screen or reverse a line's direction.
    """
    return "".join(ch if ch in "\n\t" or ch.isprintable() else "?" for ch in text)


class ModelRefused(Exception):
    """Sletchy will not ask this. On the ledger as entry `seq`."""

    def __init__(self, reason: str, seq: int | None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.seq = seq


class ModelUnreadable(Exception):
    """The server answered with something that is not an answer."""


@dataclass(frozen=True)
class Model:
    name: str
    size_bytes: int
    #: The server's digest of the model's files: a new pull under the same name changes it.
    digest: str = ""


@dataclass(frozen=True)
class Running:
    """A model the server holds in memory now, as it reports it (`/api/ps`)."""

    name: str
    size_bytes: int
    #: How much of it is on the card. The rest runs on the processor, from system memory.
    vram_bytes: int
    context_tokens: int
    #: When the server will unload it, as the server writes the time.
    expires_at: str

    @property
    def spill_bytes(self) -> int:
        return max(0, self.size_bytes - self.vram_bytes)


@dataclass(frozen=True)
class Loaded:
    running: Running
    #: How long the load took, end to end, and the server's own count of it.
    seconds: float
    load_seconds: float
    #: Ledger entries: the load, then what was measured.
    load_seq: int
    loaded_seq: int


@dataclass(frozen=True)
class Question:
    """A question on the record, not yet sent. `begin` makes one; `send` asks it."""

    model: str
    prompt: str
    #: The conversation so far, oldest first, as `(role, text)`: sent before the prompt.
    earlier: tuple[tuple[str, str], ...]
    asked_seq: int


@dataclass(frozen=True)
class Answer:
    model: str
    text: str
    seconds: float
    #: The context meter: tokens read, tokens written, out of `context_tokens`.
    prompt_tokens: int
    answer_tokens: int
    context_tokens: int
    #: True when the answer stopped because the model ran out of room, not because it
    #: had finished.
    out_of_room: bool
    #: Ledger entries: the question, then the answer.
    asked_seq: int
    answered_seq: int


class LocalModel:
    """Ollama's API, through the door, with every question and answer recorded."""

    def __init__(
        self,
        *,
        ledger: Ledger,
        store: PayloadStore,
        door: LocalModelDoor,
        actor_id: str,
        max_model_bytes: int = MAX_MODEL_BYTES,
        clock: Callable[[], float] = time.monotonic,
        context_tokens: int = CONTEXT_TOKENS,
    ) -> None:
        if door.engine != "ollama":
            raise ValueError(f"this speaks Ollama's API; the door is for {door.engine}")
        if context_tokens not in CONTEXT_CHOICES:
            raise ValueError(
                f"a context of {context_tokens} tokens is not one of {CONTEXT_CHOICES}"
            )
        self.context_tokens = context_tokens
        self._ledger = ledger
        self._store = store
        self._door = door
        self.actor_id = actor_id
        self.max_model_bytes = max_model_bytes
        self._clock = clock

    @classmethod
    def on_this_machine(
        cls,
        *,
        ledger: Ledger,
        store: PayloadStore,
        actor_id: str,
        switched_on: Callable[[], bool],
        port: int = OLLAMA_PORT,
        context_tokens: int = CONTEXT_TOKENS,
    ) -> LocalModel:
        """Ollama on this machine, through a door built for it. The Shell's way in."""
        door = LocalModelDoor(
            ledger=ledger, actor_id=actor_id, switched_on=switched_on, engine="ollama", port=port
        )
        return cls(
            ledger=ledger, store=store, door=door, actor_id=actor_id, context_tokens=context_tokens
        )

    def models(self) -> list[Model]:
        """The server's models. Raises `EgressDenied`, `OSError` or `ModelUnreadable`."""
        reply = self._door.request("GET", "/api/tags")
        data = _json(reply.status, reply.body)
        found = data.get("models") if isinstance(data, dict) else None
        if not isinstance(found, list):
            raise ModelUnreadable("the model list had no models in it")
        out: list[Model] = []
        for item in found:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                size, digest = item.get("size"), item.get("digest")
                out.append(
                    Model(
                        item["name"],
                        size if isinstance(size, int) else -1,
                        digest if isinstance(digest, str) else "",
                    )
                )
        return out

    def capabilities(self, model: str) -> frozenset[str] | None:
        """What the server says a model can do (`completion`, `embedding`, `vision`, ...),
        or None when it does not say: an older server (#204). Raises `ModelRefused`,
        `EgressDenied`, `OSError` or `ModelUnreadable`."""
        self._check_name(model, SHOW_ACTION)
        body = json.dumps({"model": model}).encode("utf-8")
        reply = self._door.request("POST", "/api/show", body)
        data = _json(reply.status, reply.body)
        found = data.get("capabilities") if isinstance(data, dict) else None
        if not isinstance(found, list):
            return None
        return frozenset(c for c in found if isinstance(c, str))

    def ask(self, model: str, prompt: str) -> Answer:
        """One question. Raises `ModelRefused`, `EgressDenied`, `OSError` or `ModelUnreadable`."""
        return self.send(self.begin(model, prompt))

    def begin(
        self,
        model: str,
        prompt: str,
        *,
        earlier: Sequence[tuple[str, str]] = (),
        note: str = "",
    ) -> Question:
        """Check a question, then put it on the record. Nothing is sent yet.

        `earlier` is the conversation so far, sent before the prompt; `note` goes into the
        record's reason (which turn of which conversation). Raises `ModelRefused`,
        `EgressDenied`, `OSError` or `ModelUnreadable`.
        """
        self._check(model, prompt)
        if any(role not in ROLES or not isinstance(text, str) for role, text in earlier):
            self._refuse(model, "an earlier message from someone other than the user or the model")
        self._fits(model)
        asked = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=ASK_ACTION,
            subject=Subject(kind=SubjectKind.MODEL, identifier=model),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"{len(prompt)} characters to {model} on {self._door.where}"
                    + (f"; {note}" if note else "")
                )[:512],
            ),
            payload_hash=self._store.put(prompt.encode("utf-8")),
        )
        return Question(model, prompt, tuple(earlier), asked.seq)

    def send(self, question: Question) -> Answer:
        """Ask a recorded question, and record its answer. Raises `EgressDenied`, `OSError`
        or `ModelUnreadable`."""
        model = question.model
        messages = [{"role": role, "content": text} for role, text in question.earlier]
        messages.append({"role": "user", "content": question.prompt})
        body = json.dumps(
            {
                "model": model,
                "messages": messages,
                "stream": False,
                "keep_alive": KEEP_ALIVE,
                "options": {"num_ctx": self.context_tokens},
            }
        ).encode("utf-8")
        start = self._clock()
        reply = self._door.request("POST", "/api/chat", body)
        seconds = self._clock() - start
        data = _json(reply.status, reply.body)
        message = data.get("message") if isinstance(data, dict) else None
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str):
            raise ModelUnreadable("the answer had no text in it")
        assert isinstance(data, dict)  # noqa: S101 - `message` was read from it above
        read, written = _count(data, "prompt_eval_count"), _count(data, "eval_count")
        out_of_room = data.get("done_reason") == "length"
        answered = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=ANSWER_ACTION,
            subject=Subject(kind=SubjectKind.MODEL, identifier=model),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"{len(text)} characters in {seconds:.1f} s, to question {question.asked_seq}; "
                    f"context {read + written} of {self.context_tokens} tokens"
                    + ("; stopped: out of room" if out_of_room else "")
                ),
            ),
            payload_hash=self._store.put(text.encode("utf-8")),
        )
        return Answer(
            model=model,
            text=text,
            seconds=seconds,
            prompt_tokens=read,
            answer_tokens=written,
            context_tokens=self.context_tokens,
            out_of_room=out_of_room,
            asked_seq=question.asked_seq,
            answered_seq=answered.seq,
        )

    def running(self) -> list[Running]:
        """What the server holds in memory now. Raises `EgressDenied`, `OSError` or
        `ModelUnreadable`."""
        reply = self._door.request("GET", "/api/ps")
        data = _json(reply.status, reply.body)
        found = data.get("models") if isinstance(data, dict) else None
        if not isinstance(found, list):
            raise ModelUnreadable("the list of loaded models had no models in it")
        out: list[Running] = []
        for item in found:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                expires = item.get("expires_at")
                out.append(
                    Running(
                        name=item["name"],
                        size_bytes=_count(item, "size"),
                        vram_bytes=_count(item, "size_vram"),
                        context_tokens=_count(item, "context_length"),
                        expires_at=expires if isinstance(expires, str) else "",
                    )
                )
        return out

    def load(self, model: str) -> Loaded:
        """Put a model on the card with this conversation's context and no question, then
        read what the server holds. A model past `MAX_SPILL_BYTES` is unloaded again and
        refused. Raises `ModelRefused`, `EgressDenied`, `OSError` or `ModelUnreadable`."""
        self._check_name(model, LOAD_ACTION)
        self._fits(model, LOAD_ACTION)
        self._can_talk(model, LOAD_ACTION)
        asked = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=LOAD_ACTION,
            subject=Subject(kind=SubjectKind.MODEL, identifier=model),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"load {model} with a context of {self.context_tokens} tokens, kept "
                    f"{KEEP_ALIVE} after its last request, on {self._door.where}"
                ),
            ),
        )
        body = {
            "model": model,
            "messages": [],
            "keep_alive": KEEP_ALIVE,
            "options": {"num_ctx": self.context_tokens},
        }
        start = self._clock()
        try:
            reply = self._door.request("POST", "/api/chat", json.dumps(body).encode("utf-8"))
            seconds = self._clock() - start
            data = _json(reply.status, reply.body)
            if not isinstance(data, dict) or data.get("done") is not True:
                raise ModelUnreadable("the server did not say the model was loaded")
            load_seconds = _count(data, "load_duration") / 1e9
            held = next((r for r in self.running() if r.name == model), None)
            if held is None:
                raise ModelUnreadable("the server does not list the model it just loaded")
        except (ModelUnreadable, OSError) as exc:
            # The attempt is on the record, so its end is too (#204). A refusal at the
            # door is recorded by the door.
            self._not_loaded(model, asked.seq, str(exc) or type(exc).__name__)
            raise
        if held.spill_bytes > MAX_SPILL_BYTES:
            self.unload(model)
            self._refuse(
                model,
                f"with a context of {self.context_tokens} tokens it runs "
                f"{held.spill_bytes / 1024**3:.1f} GiB past the card, over the bound of "
                f"{MAX_SPILL_BYTES / 1024**3:.0f} GiB, so it was unloaded; a smaller context fits",
                LOAD_ACTION,
            )
        on_card = held.vram_bytes / held.size_bytes if held.size_bytes > 0 else 0.0
        loaded = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=LOADED_ACTION,
            subject=Subject(kind=SubjectKind.MODEL, identifier=model),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"{held.size_bytes} bytes, {on_card:.0%} on the card, a context of "
                    f"{held.context_tokens} tokens, in {seconds:.1f} s, to load {asked.seq}"
                )[:512],
            ),
        )
        return Loaded(held, seconds, load_seconds, asked.seq, loaded.seq)

    def unload(self, model: str) -> int:
        """Take a model off the card now. Returns the entry. Raises `ModelRefused`,
        `EgressDenied`, `OSError` or `ModelUnreadable`."""
        self._check_name(model, UNLOAD_ACTION)
        entry = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=UNLOAD_ACTION,
            subject=Subject(kind=SubjectKind.MODEL, identifier=model),
            verdict=Verdict(
                decision=Decision.ALLOW, reason=f"unload {model} from {self._door.where}"
            ),
        )
        body = {"model": model, "messages": [], "keep_alive": 0}
        reply = self._door.request("POST", "/api/chat", json.dumps(body).encode("utf-8"))
        _json(reply.status, reply.body)
        return entry.seq

    def embed(self, model: str, texts: Sequence[str]) -> list[list[float]]:
        """Vectors for texts, from an embedding model through the door (ADR-0019).

        Texts go in requests of at most `EMBED_BATCH_CHARS` characters, each on the record
        (`mind.model.embed`) before it is sent. The texts themselves are not stored again:
        whoever asks for them holds them. Raises `ModelRefused`, `EgressDenied`, `OSError`
        or `ModelUnreadable`.
        """
        for text in texts:
            self._check(model, text, EMBED_ACTION)
        if not texts:
            return []
        self._fits(model, EMBED_ACTION)
        out: list[list[float]] = []
        for batch in _batches(texts, EMBED_BATCH_CHARS):
            self._ledger.append(
                plane=Plane.MIND,
                actor_id=self.actor_id,
                action=EMBED_ACTION,
                subject=Subject(kind=SubjectKind.MODEL, identifier=model),
                verdict=Verdict(
                    decision=Decision.ALLOW,
                    reason=(
                        f"{len(batch)} texts, {sum(len(t) for t in batch)} characters, to "
                        f"{model} on {self._door.where}"
                    ),
                ),
            )
            body = json.dumps(
                {"model": model, "input": batch, "options": {"num_ctx": CONTEXT_TOKENS}}
            ).encode("utf-8")
            reply = self._door.request("POST", "/api/embed", body)
            data = _json(reply.status, reply.body)
            found = data.get("embeddings") if isinstance(data, dict) else None
            if not isinstance(found, list) or len(found) != len(batch):
                raise ModelUnreadable(
                    f"{len(batch)} texts did not come back as {len(batch)} vectors"
                )
            for vector in found:
                if (
                    not isinstance(vector, list)
                    or not vector
                    or not all(
                        isinstance(x, (int, float)) and not isinstance(x, bool) for x in vector
                    )
                ):
                    raise ModelUnreadable("a vector that is not a list of numbers")
                out.append([float(x) for x in vector])
        return out

    def _fits(self, model: str, action: str = ASK_ACTION) -> None:
        """Refuse a model the server does not have, or one too big to leave its context room."""
        sizes = {m.name: m.size_bytes for m in self.models()}
        if model not in sizes:
            self._refuse(model, "the model server has no model by that name", action)
        if sizes[model] < 0 or sizes[model] > self.max_model_bytes:
            self._refuse(
                model,
                f"the model is {sizes[model]} bytes; a model may take at most "
                f"{self.max_model_bytes}, {MODEL_SHARE:.0%} of the card, so its context fits",
                action,
            )

    def _can_talk(self, model: str, action: str) -> None:
        """Refuse a model the server says cannot hold a conversation, such as an embedding
        model, before it is sent anything (#204). A server that does not say is believed
        to be able to: an older Ollama, which answers a model that cannot."""
        can = self.capabilities(model)
        if can is None or "completion" in can:
            return
        what = (
            "an embedding model: it turns text into numbers for memory search"
            if "embedding" in can
            else "a model that does " + (", ".join(sorted(can))[:120] or "nothing the server names")
        )
        self._refuse(model, f"{what}, and cannot hold a conversation", action)

    def _not_loaded(self, model: str, load_seq: int, why: str) -> None:
        self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=LOADED_ACTION,
            subject=Subject(kind=SubjectKind.MODEL, identifier=model),
            verdict=Verdict(
                decision=Decision.DENY, reason=f"not loaded, to load {load_seq}: {why}"[:512]
            ),
        )

    def _check_name(self, model: str, action: str = ASK_ACTION) -> None:
        if not _MODEL_NAME.match(model):
            self._refuse(model, "not a model name", action)

    def _check(self, model: str, prompt: str, action: str = ASK_ACTION) -> None:
        self._check_name(model, action)
        if not prompt.strip():
            self._refuse(model, "an empty question", action)
        if len(prompt) > MAX_PROMPT_CHARS:
            self._refuse(model, f"a question over {MAX_PROMPT_CHARS} characters", action)

    def _refuse(self, model: str, reason: str, action: str = ASK_ACTION) -> NoReturn:
        shown = "".join(ch if ch.isprintable() else "?" for ch in model)[:80] or "?"
        entry = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=action,
            subject=Subject(kind=SubjectKind.MODEL, identifier=shown),
            verdict=Verdict(decision=Decision.DENY, reason=reason[:512]),
        )
        raise ModelRefused(reason, entry.seq)


def can_talk(capabilities: frozenset[str] | None) -> bool | None:
    """Whether a model can hold a conversation, by the server's own word (#204); None
    when the server did not say."""
    return None if capabilities is None else "completion" in capabilities


def _batches(texts: Sequence[str], limit: int) -> list[list[str]]:
    """Texts in order, grouped so no group holds more than `limit` characters (one text
    longer than that goes alone; `_check` already capped it)."""
    out: list[list[str]] = []
    size = 0
    for text in texts:
        if not out or size + len(text) > limit:
            out.append([])
            size = 0
        out[-1].append(text)
        size += len(text)
    return out


def _count(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    return value if isinstance(value, int) and value >= 0 else 0


def _json(status: int, body: bytes) -> object:
    if status != 200:
        raise ModelUnreadable(f"the model server answered {status}{_said(body)}")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise ModelUnreadable("the model server's answer is not JSON") from exc


def _said(body: bytes) -> str:
    """The server's own reason for an answer that is not 200, shown inert and short:
    Ollama says, for one, that a model "does not support chat"."""
    try:
        data = json.loads(body)
    except ValueError:
        return ""
    error = data.get("error") if isinstance(data, dict) else None
    if not isinstance(error, str) or not error.strip():
        return ""
    return ": " + "".join(ch if ch.isprintable() else "?" for ch in error)[:160]


__all__ = [
    "ANSWER_ACTION",
    "ASK_ACTION",
    "CARD_BYTES",
    "CONTEXT_CHOICES",
    "CONTEXT_TOKENS",
    "EMBED_ACTION",
    "EMBED_BATCH_CHARS",
    "KEEP_ALIVE",
    "LOADED_ACTION",
    "LOAD_ACTION",
    "MAX_MODEL_BYTES",
    "MAX_SPILL_BYTES",
    "MODEL_SHARE",
    "OLLAMA_PORT",
    "SHOW_ACTION",
    "SWITCH",
    "UNLOAD_ACTION",
    "Answer",
    "ContextTokens",
    "EgressDenied",
    "Loaded",
    "LocalModel",
    "Model",
    "ModelRefused",
    "ModelUnreadable",
    "Question",
    "Running",
    "can_talk",
    "inert",
]
