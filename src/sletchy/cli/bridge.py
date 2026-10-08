"""`sletchy bridge` - the desktop shell's channel to the Kernel.

**Nothing listens.** The window starts this as its own child process and speaks JSON
lines over stdin and stdout. There is no port, so no web page, no other user and no
other machine can reach it; the only party that can send a request is the process
holding the pipe ([ADR-0008](../../../docs/adr/0008-desktop-shell.md)).

**A host, in LAW 5's sense: pure translation.** Each request opens the ledger, calls
the same Kernel functions the CLI calls, and closes it. The bridge holds no state
between requests and adds no capability the CLI does not already have. A flag flip
here is the Kernel's flag flip, ledgered by the Kernel, with the actor recorded as
`operator-desktop` so the record says which surface it came from.

**Deny by default (LAW 2).** A method not in `METHODS` is refused. Parameters are
strict models that reject unknown fields. Turning a DANGEROUS flag on needs a reason
(the Kernel's rule) and the flag's exact name typed back (this file's rule). Turning
anything *off*, and `stop.run`, need neither: the safe direction is never obstructed,
and Stop everything never asks (LAW 0 §2).

**stdout carries protocol and nothing else.** While serving, `sys.stdout` is pointed
at stderr, so a stray `print` anywhere below cannot corrupt a response.
"""

from __future__ import annotations

import itertools
import json
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Literal

from pydantic import BaseModel, ValidationError

from sletchy import __version__
from sletchy.cli import paths
from sletchy.cli.bridge_contracts import (
    MAX_LINE_BYTES,
    METHODS,
    PROTOCOL_VERSION,
    ErrorCode,
    FlagsListResult,
    FlagsSetParams,
    FlagView,
    InitResult,
    LedgerPayloadParams,
    LedgerPayloadResult,
    LedgerTailParams,
    LedgerTailResult,
    ModelAnswerParams,
    ModelAnswerResult,
    ModelAnswerState,
    ModelAskParams,
    ModelAskResult,
    ModelLoadedResult,
    ModelLoadParams,
    ModelsListResult,
    ModelUnloadParams,
    ModelUnloadResult,
    ModelView,
    PanicResult,
    Request,
    RunningView,
    StatusResult,
)
from sletchy.cli.ledger_view import EntryNotFound, read_entries, read_payload
from sletchy.cli.panic import PANIC_LOCK_WAIT_SECONDS
from sletchy.cli.panic import panic as run_panic
from sletchy.cli.selfcheck import SelfCheck, run_selfcheck
from sletchy.kernel.contracts import AgentEvent, AgentEventType, Flag, FlagRisk
from sletchy.kernel.flags import FlagStore, ReasonRequired, UnknownFlag
from sletchy.kernel.ledger import (
    KeyringKeySource,
    KeySource,
    Ledger,
    LedgerCorrupt,
    LedgerError,
    LedgerMissing,
    PayloadStore,
    SigningKeyMissing,
)
from sletchy.mind.harness import Conversation
from sletchy.mind.local import (
    CARD_BYTES,
    CONTEXT_TOKENS,
    MAX_MODEL_BYTES,
    MAX_PROMPT_CHARS,
    MODEL_SHARE,
    OLLAMA_PORT,
    SWITCH,
    EgressDenied,
    LocalModel,
    Model,
    ModelRefused,
    ModelUnreadable,
    Running,
    can_talk,
    inert,
)
from sletchy.mind.memory import SWITCH as MEMORY_SWITCH
from sletchy.mind.memory import MemoryStore
from sletchy.mind.memory.gate import Gate, ModelJudge
from sletchy.mind.memory.recall import Recall

ACTOR = "operator-desktop"

#: The most of an answer the window is sent. A model's answer is usually a few
#: thousand characters; the door allows 8 MB. The whole of it is on the record.
MAX_ANSWER_CHARS = 100_000

#: How many questions' outcomes are kept for `model.answer` to read back.
KEEP_QUESTIONS = 8


@dataclass(frozen=True)
class _Talk:
    """The window's conversation: which model, which conversation, what was said."""

    model: str
    context: int = CONTEXT_TOKENS
    id: str | None = None
    history: tuple[tuple[str, str], ...] = ()


def _running_view(running: Running) -> RunningView:
    return RunningView(
        model=inert(running.name)[:200],
        size_bytes=running.size_bytes,
        vram_bytes=running.vram_bytes,
        context_tokens=running.context_tokens,
        expires_at=inert(running.expires_at)[:64],
    )


class _Question:
    """One question on its worker thread, and how it ended."""

    def __init__(self, ticket: int) -> None:
        self.ticket = ticket
        self.started = time.monotonic()
        self.answer: ModelAnswerResult | None = None
        self.loaded: ModelLoadedResult | None = None
        self.error: BridgeError | None = None
        self.done = threading.Event()


class BridgeError(Exception):
    """A refusal with a code the window can act on."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _count(value: object) -> int:
    """A count from an event's data: a whole number, never negative."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


class Bridge:
    """The method handlers. Constructed with a key source so tests use an in-memory key."""

    def __init__(self, keys: KeySource | None = None, *, model_port: int = OLLAMA_PORT) -> None:
        self._keys = keys or KeyringKeySource()
        #: Where the model server listens. Tests point it at a fake; nothing else does.
        self._model_port = model_port
        self._questions: dict[int, _Question] = {}
        self._questions_lock = threading.Lock()
        self._tickets = itertools.count(1)
        #: The window's conversation, carried from one question to the next (ADR-0018).
        self._talk: _Talk | None = None
        #: Whether each model can hold a conversation, by (name, digest), asked of the
        #: server once while the window is open (#204).
        self._talks: dict[tuple[str, str], bool | None] = {}
        self.handlers: dict[str, Callable[[BaseModel], BaseModel]] = {
            "status": self.status,
            "selfcheck": self.selfcheck,
            "flags.list": self.flags_list,
            "flags.set": self.flags_set,
            "ledger.tail": self.ledger_tail,
            "ledger.payload": self.ledger_payload,
            "stop.plan": self.stop_plan,
            "stop.run": self.stop_run,
            "models.list": self.models_list,
            "model.ask": self.model_ask,
            "model.load": self.model_load,
            "model.unload": self.model_unload,
            "model.answer": self.model_answer,
            "init": self.init,
        }

    # ── helpers ──────────────────────────────────────────────────────────────

    def _ledger(self) -> Ledger:
        try:
            return Ledger.open(paths.ledger_dir(), self._keys, create=False)
        except LedgerMissing as exc:
            msg = f"Sletchy is not set up in {paths.home()}"
            raise BridgeError("not_initialised", msg) from exc
        except SigningKeyMissing as exc:
            raise BridgeError("not_initialised", "Sletchy has not been set up yet") from exc
        except LedgerCorrupt as exc:
            raise BridgeError("ledger_corrupt", f"the ledger does not verify: {exc}") from exc

    @staticmethod
    def _view(flag: Flag, store: FlagStore) -> FlagView:
        return FlagView(
            name=flag.name,
            label=flag.label or flag.name,
            description=flag.description,
            risk=flag.risk.value,
            default=flag.default,
            enabled=store.is_on(flag.name),
            wired=flag.wired,
            serves=flag.serves,
        )

    # ── methods ──────────────────────────────────────────────────────────────

    @staticmethod
    def _status(
        state: Literal["ok", "not_initialised", "corrupt", "unavailable"],
        detail: str,
        entries: int | None = None,
        flags_on: int = 0,
        dangerous_on: tuple[str, ...] = (),
    ) -> StatusResult:
        return StatusResult(
            protocol=PROTOCOL_VERSION,
            version=__version__,
            home=str(paths.home()),
            ledger_state=state,
            entries=entries,
            detail=detail[:400],
            flags_on=flags_on,
            dangerous_on=dangerous_on,
        )

    def status(self, _: BaseModel) -> StatusResult:
        try:
            ledger = Ledger.open(paths.ledger_dir(), self._keys, create=False)
        except LedgerMissing:
            return self._status("not_initialised", f"no ledger in {paths.home()}; run setup")
        except SigningKeyMissing:
            return self._status("not_initialised", "no signing key; run setup")
        except LedgerCorrupt as exc:
            return self._status("corrupt", str(exc))
        except (LedgerError, OSError) as exc:
            return self._status("unavailable", f"{type(exc).__name__}: {exc}")
        try:
            store = FlagStore.open(ledger, paths.flags_file())
            detail = "chain verified"
            full = ledger.full()
            if full:
                detail += f"; full: {full}"
            if ledger.mark_behind:
                detail += f"; length record {ledger.mark_behind} behind"
            if store.unexplained:
                detail += (
                    f"; {', '.join(store.unexplained)} turned on outside Sletchy, with no "
                    "record of it, and treated as off"
                )
            return self._status(
                "ok",
                detail,
                entries=ledger.length,
                flags_on=sum(store.snapshot().values()),
                dangerous_on=tuple(
                    f.name for f in store.registry.dangerous() if store.is_on(f.name)
                ),
            )
        finally:
            ledger.close()

    def selfcheck(self, _: BaseModel) -> SelfCheck:
        return run_selfcheck(
            open_ledger=lambda: Ledger.open(paths.ledger_dir(), self._keys, create=False)
        )

    def flags_list(self, _: BaseModel) -> FlagsListResult:
        ledger = self._ledger()
        try:
            store = FlagStore.open(ledger, paths.flags_file())
            return FlagsListResult(flags=tuple(self._view(f, store) for f in store.registry))
        finally:
            ledger.close()

    def flags_set(self, params: BaseModel) -> FlagView:
        assert isinstance(params, FlagsSetParams)  # noqa: S101 - dispatch guarantees it
        ledger = self._ledger()
        try:
            store = FlagStore.open(ledger, paths.flags_file())
            try:
                flag = store.registry.get(params.name)
            except UnknownFlag as exc:
                raise BridgeError("unknown_flag", str(exc)) from exc
            if params.enabled and flag.risk is FlagRisk.DANGEROUS and params.confirm != flag.name:
                raise BridgeError(
                    "confirmation_required",
                    f"turning on {flag.name!r} needs its name typed back exactly",
                )
            try:
                store.set(flag.name, params.enabled, reason=params.reason, actor_id=ACTOR)
            except ReasonRequired as exc:
                raise BridgeError("reason_required", str(exc)) from exc
            return self._view(flag, store)
        finally:
            ledger.close()

    def _model(self, ledger: Ledger, context: int = CONTEXT_TOKENS) -> LocalModel:
        """The same door, budget and record as `sletchy ask`, as the window."""
        flags = FlagStore.open(ledger, paths.flags_file())
        return LocalModel.on_this_machine(
            ledger=ledger,
            store=PayloadStore.open(paths.payload_dir()),
            actor_id=ACTOR,
            switched_on=lambda: flags.is_on(SWITCH),
            port=self._model_port,
            context_tokens=context,
        )

    def _recall(self, ledger: Ledger, model: LocalModel, name: str) -> Recall | None:
        """Memory for the Talk plate, as `sletchy chat` has it, when `mind_memory` is on
        (ADR-0019): searched by words, judged by the conversation's own model."""
        flags = FlagStore.open(ledger, paths.flags_file())
        if not flags.is_on(MEMORY_SWITCH):
            return None
        payloads = PayloadStore.open(paths.payload_dir())
        store = MemoryStore(
            paths.memory_dir(),
            ledger=ledger,
            store=payloads,
            actor_id=ACTOR,
            switched_on=lambda: flags.is_on(MEMORY_SWITCH),
        )
        gate = Gate(ModelJudge(model, name), ledger=ledger, store=payloads, actor_id=ACTOR)
        return Recall(store, gate)

    def _model_failed(self, exc: Exception) -> BridgeError:
        """A refusal the window can say in a sentence. Every one is on the record first."""
        if isinstance(exc, EgressDenied) and "switched off" in exc.reason:
            return BridgeError("switched_off", "Local AI models are switched off")
        if isinstance(exc, (EgressDenied, ModelRefused)):
            return BridgeError("model_refused", exc.reason[:400])
        if isinstance(exc, ModelUnreadable):
            return BridgeError("model_unreadable", str(exc)[:400])
        return BridgeError(
            "no_model_server",
            f"no model server is answering on 127.0.0.1:{self._model_port}; "
            "Sletchy never starts one",
        )

    def models_list(self, _: BaseModel) -> ModelsListResult:
        ledger = self._ledger()
        try:
            model = self._model(ledger)
            found = model.models()
            talks = {m.name: self._can_talk(model, m) for m in found}
            try:
                running = model.running()
            except (ModelUnreadable, OSError):
                running = []  # an older server, or none: nothing shown as loaded
        except (EgressDenied, ModelUnreadable, OSError) as exc:
            raise self._model_failed(exc) from exc
        finally:
            ledger.close()
        return ModelsListResult(
            card_bytes=CARD_BYTES,
            budget_bytes=MAX_MODEL_BYTES,
            share=MODEL_SHARE,
            context_tokens=CONTEXT_TOKENS,
            max_question_chars=MAX_PROMPT_CHARS,
            models=tuple(
                ModelView(
                    name=inert(m.name)[:200],
                    size_bytes=m.size_bytes,
                    fits=0 <= m.size_bytes <= MAX_MODEL_BYTES,
                    can_chat=talks.get(m.name),
                )
                for m in sorted(found, key=lambda m: m.size_bytes)
            ),
            running=tuple(_running_view(r) for r in running),
        )

    def _can_talk(self, model: LocalModel, found: Model) -> bool | None:
        """Whether a model can hold a conversation, by the server's word, asked once per
        name and digest while the window is open. None: the server did not say, or could
        not be asked, which is not remembered."""
        key = (found.name, found.digest)
        if key not in self._talks:
            try:
                self._talks[key] = can_talk(model.capabilities(found.name))
            except (ModelRefused, ModelUnreadable, OSError):
                return None
        return self._talks[key]

    def model_ask(self, params: BaseModel) -> ModelAskResult:
        """Start one question on a worker thread, and answer at once with its ticket.

        A model can think for minutes, and the window's shell waits for each answer
        before it sends the next request, so a question answered here inline would
        hold up everything else, Stop everything included. Every request stays quick
        instead: the window asks `model.answer` with the ticket until it is done.
        One question at a time.
        """
        assert isinstance(params, ModelAskParams)  # noqa: S101 - dispatch guarantees it
        with self._questions_lock:
            if any(not q.done.is_set() for q in self._questions.values()):
                raise BridgeError("model_busy", "a model is already answering a question")
            question = _Question(next(self._tickets))
            self._questions[question.ticket] = question
            for old in sorted(self._questions)[:-KEEP_QUESTIONS]:
                del self._questions[old]
            if (
                params.fresh
                or self._talk is None
                or self._talk.model != params.model
                or self._talk.context != params.context
            ):
                self._talk = _Talk(params.model, params.context)
            talk = self._talk
        threading.Thread(
            target=self._ask,
            args=(question, talk, params.question),
            name=f"model-question-{question.ticket}",
            daemon=True,
        ).start()
        return ModelAskResult(ticket=question.ticket)

    def _ask(self, question: _Question, talk: _Talk, text: str) -> None:
        """The worker: one turn of the harness, with its own ledger handle (the ledger's
        lock excludes this process too). The window is one more host of the same stream."""
        try:
            ledger = self._ledger()
            try:
                model = self._model(ledger, talk.context)
                conversation = Conversation(
                    model,
                    talk.model,
                    ledger=ledger,
                    actor_id=ACTOR,
                    earlier=talk.history,
                    conversation_id=talk.id,
                    recall=self._recall(ledger, model, talk.model),
                )
                events: list[AgentEvent] = []
                conversation.play(text, events.append)
            finally:
                ledger.close()
            with self._questions_lock:
                if self._talk is talk:  # not replaced by a fresh conversation meanwhile
                    self._talk = _Talk(
                        talk.model, talk.context, conversation.id, conversation.history
                    )
            question.answer = self._answered(conversation, events)
        except BridgeError as exc:
            question.error = exc
        except Exception as exc:  # a worker must never end without saying how
            question.error = BridgeError("internal_error", type(exc).__name__)
        finally:
            question.done.set()

    def model_load(self, params: BaseModel) -> ModelAskResult:
        """Load a model on a worker thread and answer at once with a ticket, as a question
        does: a load can take minutes, and nothing else may wait on it (#202)."""
        assert isinstance(params, ModelLoadParams)  # noqa: S101 - dispatch guarantees it
        with self._questions_lock:
            if any(not q.done.is_set() for q in self._questions.values()):
                raise BridgeError("model_busy", "a model is already loading or answering")
            question = _Question(next(self._tickets))
            self._questions[question.ticket] = question
            for old in sorted(self._questions)[:-KEEP_QUESTIONS]:
                del self._questions[old]
        threading.Thread(
            target=self._load,
            args=(question, params.model, params.context),
            name=f"model-load-{question.ticket}",
            daemon=True,
        ).start()
        return ModelAskResult(ticket=question.ticket)

    def _load(self, question: _Question, name: str, context: int) -> None:
        try:
            ledger = self._ledger()
            try:
                loaded = self._model(ledger, context).load(name)
            finally:
                ledger.close()
            question.loaded = ModelLoadedResult(
                running=_running_view(loaded.running),
                seconds=round(loaded.seconds, 1),
                load_seconds=round(loaded.load_seconds, 1),
                load_seq=loaded.load_seq,
                loaded_seq=loaded.loaded_seq,
            )
        except (EgressDenied, ModelRefused, ModelUnreadable, OSError) as exc:
            question.error = self._model_failed(exc)
        except BridgeError as exc:
            question.error = exc
        except Exception as exc:  # a worker must never end without saying how
            question.error = BridgeError("internal_error", type(exc).__name__)
        finally:
            question.done.set()

    def model_unload(self, params: BaseModel) -> ModelUnloadResult:
        """Take a model off the card now. Quick: the server answers at once (#202)."""
        assert isinstance(params, ModelUnloadParams)  # noqa: S101 - dispatch guarantees it
        ledger = self._ledger()
        try:
            seq = self._model(ledger).unload(params.model)
        except (EgressDenied, ModelRefused, ModelUnreadable, OSError) as exc:
            raise self._model_failed(exc) from exc
        finally:
            ledger.close()
        return ModelUnloadResult(model=inert(params.model)[:200], unload_seq=seq)

    def _answered(self, conversation: Conversation, events: list[AgentEvent]) -> ModelAnswerResult:
        """One turn's events, as the window shows them; a refusal or a failure as its code."""
        by_type = {event.type: event for event in events}
        refused = by_type.get(AgentEventType.POLICY)
        if refused is not None:
            if refused.data.get("switched_off"):
                raise BridgeError("switched_off", "Local AI models are switched off")
            raise BridgeError("model_refused", str(refused.data.get("reason", ""))[:400])
        failed = by_type.get(AgentEventType.ERROR)
        if failed is not None:
            if failed.data.get("kind") == "model_unreadable":
                raise BridgeError("model_unreadable", str(failed.data.get("reason", ""))[:400])
            raise BridgeError(
                "no_model_server",
                f"no model server is answering on 127.0.0.1:{self._model_port}; "
                "Sletchy never starts one",
            )
        asked = by_type[AgentEventType.STATUS]
        content = by_type[AgentEventType.CONTENT]
        done = by_type[AgentEventType.COMPLETE].data
        shown = inert(str(content.data.get("text", "")))
        seconds = done.get("seconds")
        return ModelAnswerResult(
            model=conversation.name,
            text=shown[:MAX_ANSWER_CHARS],
            cut=len(shown) > MAX_ANSWER_CHARS,
            seconds=float(seconds) if isinstance(seconds, (int, float)) else 0.0,
            prompt_tokens=_count(done.get("prompt_tokens")),
            answer_tokens=_count(done.get("answer_tokens")),
            context_tokens=_count(done.get("context_tokens")),
            out_of_room=done.get("out_of_room") is True,
            asked_seq=_count(asked.ledger_seq),
            answered_seq=_count(content.ledger_seq),
            conversation=conversation.id,
            turn=_count(asked.data.get("turn")),
            earlier_turns=_count(asked.data.get("earlier_turns")),
            left_out=_count(asked.data.get("left_out")),
            recalled=_count(asked.data.get("recalled")),
            plan_seq=plan if isinstance(plan := asked.data.get("plan_seq"), int) else None,
            memory_unchecked=asked.data.get("memory_unchecked") is True,
        )

    def model_answer(self, params: BaseModel) -> ModelAnswerState:
        assert isinstance(params, ModelAnswerParams)  # noqa: S101 - dispatch guarantees it
        with self._questions_lock:
            question = self._questions.get(params.ticket)
        if question is None:
            raise BridgeError("no_such_question", f"no question has ticket {params.ticket}")
        seconds = round(time.monotonic() - question.started, 1)
        if not question.done.is_set():
            return ModelAnswerState(ticket=question.ticket, state="thinking", seconds=seconds)
        if question.loaded is not None:
            return ModelAnswerState(
                ticket=question.ticket, state="loaded", seconds=seconds, loaded=question.loaded
            )
        if question.error is not None:
            return ModelAnswerState(
                ticket=question.ticket,
                state="failed",
                seconds=seconds,
                error_code=question.error.code,
                error=question.error.message,
            )
        return ModelAnswerState(
            ticket=question.ticket, state="answered", seconds=seconds, answer=question.answer
        )

    def ledger_payload(self, params: BaseModel) -> LedgerPayloadResult:
        """One entry and its body, masked as `sletchy ledger show --payload` masks it (#86).

        The store is constructed, not opened, so a read never creates a folder (#102).
        """
        assert isinstance(params, LedgerPayloadParams)  # noqa: S101 - dispatch guarantees it
        ledger = self._ledger()
        try:
            entry, payload = read_payload(ledger, PayloadStore(paths.payload_dir()), params.seq)
        except EntryNotFound as exc:
            raise BridgeError("no_such_entry", str(exc)) from exc
        finally:
            ledger.close()
        return LedgerPayloadResult(entry=entry, payload=payload)

    def ledger_tail(self, params: BaseModel) -> LedgerTailResult:
        assert isinstance(params, LedgerTailParams)  # noqa: S101 - dispatch guarantees it
        ledger = self._ledger()
        try:
            return LedgerTailResult(
                verified=ledger.length,
                entries=tuple(
                    read_entries(
                        ledger,
                        tail=params.limit,
                        action_prefix=params.action_prefix,
                        denied_only=params.denied_only,
                    )
                ),
            )
        finally:
            ledger.close()

    def _panic(self, *, dry_run: bool) -> PanicResult:
        store: FlagStore | None = None
        ledger: Ledger | None = None
        try:
            ledger = Ledger.open(
                paths.ledger_dir(), self._keys, create=False, lock_wait=PANIC_LOCK_WAIT_SECONDS
            )
            store = FlagStore.open(ledger, paths.flags_file())
        except Exception:  # panic degrades when the ledger is unreachable, as `sletchy panic` does
            store = None
        try:
            report = run_panic(
                store,
                reason="operator pressed Stop everything in the desktop shell",
                dry_run=dry_run,
            )
        finally:
            if ledger is not None:
                ledger.close()
        return PanicResult(
            dry_run=dry_run,
            clean=report.clean,
            flags_reset=report.flags_reset,
            firewall_rules_removed=report.firewall_rules_removed,
            firewall_rules_kept=report.firewall_rules_kept,
            processes_terminated=report.processes_terminated,
            sandbox_changes_reverted=report.sandbox_changes_reverted,
            runtime_files_cleared=report.runtime_files_cleared,
            ledger_sealed=report.ledger_sealed,
            errors=report.errors,
        )

    def stop_plan(self, _: BaseModel) -> PanicResult:
        return self._panic(dry_run=True)

    def stop_run(self, _: BaseModel) -> PanicResult:
        return self._panic(dry_run=False)

    def init(self, _: BaseModel) -> InitResult:
        home = paths.home()
        home.mkdir(parents=True, exist_ok=True)
        paths.runtime_dir().mkdir(parents=True, exist_ok=True)
        provisioned = False
        detail = "signing key already present - left untouched"
        # Only the real keychain can be provisioned; an in-memory key (tests) exists already.
        if isinstance(self._keys, KeyringKeySource):
            try:
                self._keys.provision()
                provisioned = True
                detail = "signing key created in the OS keychain"
            except ValueError:
                pass  # already provisioned, and provision() never overwrites by default
        Ledger.open(paths.ledger_dir(), self._keys).close()
        PayloadStore.open(paths.payload_dir())
        return InitResult(home=str(home), provisioned=provisioned, detail=detail)


# ── the wire ─────────────────────────────────────────────────────────────────


def _error(request_id: int | None, code: ErrorCode, message: str) -> bytes:
    body = {"id": request_id, "ok": False, "error": {"code": code, "message": message[:1000]}}
    return json.dumps(body, ensure_ascii=True).encode("ascii")


def _ok(request_id: int, result: BaseModel) -> bytes:
    payload = result.model_dump(mode="json")
    return json.dumps({"id": request_id, "ok": True, "result": payload}, ensure_ascii=True).encode(
        "ascii"
    )


def _salvage_id(raw: object) -> int | None:
    """Echo a well-formed id from a request that failed later, so the caller can match it."""
    if isinstance(raw, dict):
        value = raw.get("id")
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**31:
            return value
    return None


def handle_line(bridge: Bridge, line: bytes) -> bytes:
    """One request in, one response out. Never raises."""
    try:
        text = line.decode("utf-8")
        raw = json.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return _error(None, "bad_request", f"not a JSON request: {type(exc).__name__}")

    try:
        request = Request.model_validate(raw, strict=True)
    except ValidationError as exc:
        return _error(
            _salvage_id(raw), "bad_request", f"not a request: {exc.error_count()} error(s)"
        )

    if request.method not in METHODS:
        return _error(request.id, "method_not_allowed", f"no such method: {request.method[:64]!r}")
    params_model, _ = METHODS[request.method]

    try:
        params = params_model.model_validate(request.params, strict=True)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in e["loc"]) or "params" for e in exc.errors())
        return _error(request.id, "invalid_params", f"invalid params: {fields}"[:1000])

    try:
        result = bridge.handlers[request.method](params)
    except BridgeError as exc:
        return _error(request.id, exc.code, exc.message)
    except Exception as exc:  # the window must always get an answer, never a dead pipe
        return _error(request.id, "internal_error", f"{type(exc).__name__}: {exc}")
    return _ok(request.id, result)


def serve(bridge: Bridge, stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Answer requests until stdin closes. One line in, one line out, in order."""
    while True:
        line = stdin.readline(MAX_LINE_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE_BYTES:
            # Discard the rest of the oversized line before answering, so the next
            # read starts on a real request boundary.
            while line and not line.endswith(b"\n"):
                line = stdin.readline(MAX_LINE_BYTES + 1)
            response = _error(None, "too_large", f"request over {MAX_LINE_BYTES} bytes")
        elif not line.strip():
            continue
        else:
            response = handle_line(bridge, line)
        stdout.write(response + b"\n")
        stdout.flush()


def run() -> int:
    """Entry point for `sletchy bridge`."""
    protocol_out = sys.stdout.buffer
    sys.stdout = sys.stderr  # nothing but protocol may reach the real stdout
    return serve(Bridge(), sys.stdin.buffer, protocol_out)
