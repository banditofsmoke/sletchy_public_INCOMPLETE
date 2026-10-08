"""The desktop bridge's wire format. The only definition of it anywhere.

LAW 6: the TypeScript the window is written against, and the method allowlist the
Rust shell enforces, are both **generated** from this file by
`scripts/gen_desktop_contracts.py`, and a test fails when either is stale. Nobody
types this schema twice.

Every model forbids unknown fields and coerces nothing (`Contract` is strict), so a
request that says `"limit": "50"` is refused rather than quietly read as 50.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, JsonValue

from sletchy.cli.ledger_view import MAX_TAIL, EntryView, PayloadView
from sletchy.cli.selfcheck import SelfCheck
from sletchy.kernel.contracts import Contract, Name
from sletchy.mind.local import CONTEXT_CHOICES, CONTEXT_TOKENS, MAX_PROMPT_CHARS, ContextTokens

#: Bumped when a method changes shape. The window refuses a bridge it does not speak.
#: 2: `panic.plan` and `panic.run` became `stop.plan` and `stop.run`, so a window built
#: before says to rebuild it, rather than offering a Stop button the Kernel refuses.
PROTOCOL_VERSION = 2

#: The largest request line accepted, in bytes. A request is a method name and a few
#: small fields; anything near this is not a request.
MAX_LINE_BYTES = 64 * 1024

ErrorCode = Literal[
    "bad_request",
    "too_large",
    "method_not_allowed",
    "invalid_params",
    "not_initialised",
    "ledger_corrupt",
    "no_such_entry",
    "unknown_flag",
    "reason_required",
    "confirmation_required",
    "switched_off",
    "no_model_server",
    "model_refused",
    "model_unreadable",
    "model_busy",
    "no_such_question",
    "internal_error",
]

ERROR_CODES: tuple[str, ...] = ErrorCode.__args__  # type: ignore[attr-defined]


# ── envelopes ────────────────────────────────────────────────────────────────


class Request(Contract):
    id: Annotated[int, Field(ge=0, le=2**31)]
    method: Annotated[str, Field(min_length=1, max_length=64)]
    params: dict[str, JsonValue] = Field(default_factory=dict)


class ErrorBody(Contract):
    code: ErrorCode
    message: Annotated[str, Field(max_length=1000)]


# ── params ───────────────────────────────────────────────────────────────────


class NoParams(Contract):
    """A method that takes nothing takes *nothing*: `{}` and only `{}`."""


class FlagsSetParams(Contract):
    name: Name
    enabled: bool
    #: Required by the Kernel to turn a DANGEROUS flag on.
    reason: Annotated[str, Field(max_length=512)] = ""
    #: Required by the bridge to turn a DANGEROUS flag on: the flag's exact name,
    #: typed back. A reason proves intent; this proves it was this switch.
    confirm: Annotated[str, Field(max_length=64)] = ""


class LedgerTailParams(Contract):
    limit: Annotated[int, Field(ge=1, le=MAX_TAIL)] = 50
    action_prefix: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.]{0,63}$")] | None = None
    denied_only: bool = False


class ModelAskParams(Contract):
    """One question to a model on this computer, with the conversation so far (ADR-0018)."""

    model: Annotated[str, Field(min_length=1, max_length=200)]
    question: Annotated[str, Field(min_length=1, max_length=MAX_PROMPT_CHARS)]
    #: Start a new conversation with this question. Asking another model does too.
    fresh: bool = False
    #: The conversation's context, in tokens: the one the model was loaded with (#202).
    #: Another context is another conversation.
    context: ContextTokens = CONTEXT_TOKENS


class ModelLoadParams(Contract):
    """Put a model on the card with a context and no question (#202). Answers with a
    ticket, as a question does: loading can take minutes."""

    model: Annotated[str, Field(min_length=1, max_length=200)]
    context: ContextTokens = CONTEXT_TOKENS


class ModelUnloadParams(Contract):
    """Take a model off the card now (#202)."""

    model: Annotated[str, Field(min_length=1, max_length=200)]


class ModelAnswerParams(Contract):
    """Has the question with this ticket been answered yet?"""

    ticket: Annotated[int, Field(ge=1, le=2**31)]


class LedgerPayloadParams(Contract):
    """One entry's body, by sequence number (#86)."""

    seq: Annotated[int, Field(ge=0, le=2**53)]


# ── results ──────────────────────────────────────────────────────────────────


class StatusResult(Contract):
    protocol: int
    version: str
    home: str
    ledger_state: Literal["ok", "not_initialised", "corrupt", "unavailable"]
    entries: int | None
    detail: str
    flags_on: int
    dangerous_on: tuple[str, ...]


class FlagView(Contract):
    name: str
    label: str
    description: str
    risk: Literal["safe", "elevated", "dangerous"]
    default: bool
    enabled: bool
    #: False means nothing in Sletchy reads this switch yet. The window says so.
    wired: bool
    #: Which human questions it answers: time, money, connection, or safety.
    serves: tuple[Literal["time", "money", "connection", "safety"], ...]


class FlagsListResult(Contract):
    flags: tuple[FlagView, ...]


class LedgerTailResult(Contract):
    verified: int
    entries: tuple[EntryView, ...]


class LedgerPayloadResult(Contract):
    """The entry and its body: secrets masked, length bounded, state stated (#86)."""

    entry: EntryView
    payload: PayloadView


class PanicResult(Contract):
    dry_run: bool
    clean: bool
    flags_reset: int
    firewall_rules_removed: int
    firewall_rules_kept: int
    processes_terminated: int
    sandbox_changes_reverted: int
    runtime_files_cleared: int
    ledger_sealed: bool
    errors: tuple[str, ...]


class ModelView(Contract):
    name: str
    size_bytes: int
    #: Within the card budget, so its context fits. A model that does not is never asked.
    fits: bool
    #: Whether it can hold a conversation, by the server's word (#204): False for an
    #: embedding model, which is listed and never offered to talk to. None: not said.
    can_chat: bool | None = None


class RunningView(Contract):
    """A model the server holds in memory now, by its own report (#202)."""

    model: str
    size_bytes: int
    #: How much of it is on the card; the rest runs on the processor.
    vram_bytes: int
    context_tokens: int
    #: When the server will unload it, as the server writes the time.
    expires_at: str


class ModelsListResult(Contract):
    card_bytes: int
    budget_bytes: int
    share: float
    context_tokens: int
    max_question_chars: int
    models: tuple[ModelView, ...]
    #: The contexts a conversation may have (#202), and what the server holds now.
    context_choices: tuple[int, ...] = CONTEXT_CHOICES
    running: tuple[RunningView, ...] = ()


class ModelLoadedResult(Contract):
    """A model loaded, as measured just after (#202)."""

    running: RunningView
    #: End to end, and the server's own count of the load.
    seconds: float
    load_seconds: float
    load_seq: int
    loaded_seq: int


class ModelUnloadResult(Contract):
    model: str
    unload_seq: int


class ModelAnswerResult(Contract):
    model: str
    #: Shown inert: every control character but a newline and a tab is `?`.
    text: str
    #: True when `text` is cut to fit the window; the whole answer is on the record.
    cut: bool
    seconds: float
    prompt_tokens: int
    answer_tokens: int
    context_tokens: int
    out_of_room: bool
    asked_seq: int
    answered_seq: int
    #: Which conversation, and which turn of it, this answers (ADR-0018).
    conversation: str
    turn: int
    #: How many earlier turns were sent with the question, and how many were left out
    #: to leave room for the answer.
    earlier_turns: int
    left_out: int
    #: Passages from memory that went before the question, and the plan's record entry
    #: (ADR-0019). None: memory was off.
    recalled: int = 0
    plan_seq: int | None = None
    #: True when memory found something and the model could not judge it, so nothing
    #: from memory went with the question (#205).
    memory_unchecked: bool = False


class ModelAskResult(Contract):
    """The question is on its way. Ask `model.answer` with this ticket for the answer."""

    ticket: int


class ModelAnswerState(Contract):
    ticket: int
    #: `loaded` answers a `model.load`; `answered` a `model.ask`.
    state: Literal["thinking", "answered", "loaded", "failed"]
    #: Seconds since the question was asked.
    seconds: float
    answer: ModelAnswerResult | None = None
    loaded: ModelLoadedResult | None = None
    error_code: ErrorCode | None = None
    error: str = ""


class InitResult(Contract):
    home: str
    provisioned: bool
    detail: str


#: Method name -> (params model, result model). The allowlist, in one place.
#: Handlers live in `bridge.py`; a test asserts the two cover the same names.
METHODS: dict[str, tuple[type[Contract], type[Contract]]] = {
    "status": (NoParams, StatusResult),
    "selfcheck": (NoParams, SelfCheck),
    "flags.list": (NoParams, FlagsListResult),
    "flags.set": (FlagsSetParams, FlagView),
    "ledger.tail": (LedgerTailParams, LedgerTailResult),
    "ledger.payload": (LedgerPayloadParams, LedgerPayloadResult),
    "stop.plan": (NoParams, PanicResult),
    "stop.run": (NoParams, PanicResult),
    "models.list": (NoParams, ModelsListResult),
    "model.ask": (ModelAskParams, ModelAskResult),
    "model.load": (ModelLoadParams, ModelAskResult),
    "model.unload": (ModelUnloadParams, ModelUnloadResult),
    "model.answer": (ModelAnswerParams, ModelAnswerState),
    "init": (NoParams, InitResult),
}
