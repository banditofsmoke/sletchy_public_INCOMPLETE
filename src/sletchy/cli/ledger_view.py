"""Reading the ledger as a person would: newest last, filtered, never altered.

One function serves `sletchy ledger show` and the desktop bridge, so the terminal and
the window cannot disagree about what the record says.

**Read-only by construction.** Nothing here writes, trims or re-verifies-after-
filtering. The chain is verified by `Ledger.open()` before a single entry is read,
so a forged history is never shown with the confidence of a real one (#50).
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field

from sletchy.kernel.contracts import Contract, Decision
from sletchy.kernel.ledger import PayloadMissing, content_hash
from sletchy.kernel.secrets.shapes import masked

if TYPE_CHECKING:
    from sletchy.kernel.contracts import LedgerEntry
    from sletchy.kernel.ledger import Ledger, PayloadStore

#: The most entries one read returns. A bigger window is a pager's job, and the NOC's.
MAX_TAIL = 500

#: The most of one body shown at once, in characters. A body may be 32 MB; a terminal
#: or the window is not the place to read that much, and the bridge's lines are bounded.
MAX_BODY_SHOWN = 64 * 1024


class EntryView(Contract):
    """One ledger entry, flattened for display. Never the signature or hashes."""

    seq: int
    ts: str
    plane: str
    actor: str
    action: str
    subject: str
    decision: str
    reason: Annotated[str, Field(max_length=512)]
    has_payload: bool


def matches_action(action: str, prefix: str) -> bool:
    """Segment-aware: `warden.sandbox` matches `warden.sandbox.launch`, not `warden.sandboxes`."""
    return action == prefix or action.startswith(prefix + ".")


def view(entry: LedgerEntry) -> EntryView:
    return EntryView(
        seq=entry.seq,
        ts=entry.ts_wall.isoformat(timespec="seconds"),
        plane=entry.plane.value,
        actor=entry.actor_id,
        action=entry.action,
        subject=f"{entry.subject.kind.value}:{entry.subject.identifier}",
        decision=entry.verdict.decision.value,
        reason=entry.verdict.reason,
        has_payload=entry.payload_hash is not None,
    )


def read_entries(
    ledger: Ledger,
    *,
    tail: int | None = None,
    action_prefix: str | None = None,
    denied_only: bool = False,
) -> list[EntryView]:
    """Entries oldest-first, after filtering, keeping at most the last `tail`.

    Walks every segment; `tail` bounds memory, not time. That cost is #50's stated
    gap, and the reason the bridge caps `tail` at `MAX_TAIL`.
    """
    keep = min(tail, MAX_TAIL) if tail is not None else None
    window: deque[EntryView] = deque(maxlen=keep)
    for entry in ledger.entries():
        if action_prefix and not matches_action(entry.action, action_prefix):
            continue
        if denied_only and entry.verdict.decision is not Decision.DENY:
            continue
        window.append(view(entry))
    return list(window)


class EntryNotFound(LookupError):
    """No entry has that sequence number. Not corruption: a number out of range."""


PayloadState = Literal["stored", "none", "deleted", "altered"]


class PayloadView(Contract):
    """One entry's stored body, as it may be shown: secrets masked, length bounded.

    `state` says why `body` is empty when it is: the entry never had one (`none`), it was
    forgotten (`deleted`), or the file no longer matches the hash its entry signed
    (`altered`), which is shown as nothing, never as the record.
    """

    seq: int
    state: PayloadState
    body: Annotated[str, Field(max_length=MAX_BODY_SHOWN)] = ""
    size: Annotated[int, Field(ge=0)] = 0
    truncated: bool = False
    masked: list[str] = Field(default_factory=list)


def read_payload(ledger: Ledger, payloads: PayloadStore, seq: int) -> tuple[EntryView, PayloadView]:
    """The entry at `seq` and its body, after the chain verified (`Ledger.open`).

    The body is checked against the hash its entry signed before a byte is shown. A file
    planted or edited under that hash is `altered`: shown as nothing, because showing it
    would present someone's text as the record. Secrets are masked before the body is cut
    to length, so a key straddling the cut cannot survive half-masked.
    """
    entry = next((e for e in ledger.entries() if e.seq == seq), None)
    if entry is None:
        msg = f"no entry with sequence number {seq}"
        raise EntryNotFound(msg)
    shown = view(entry)
    if entry.payload_hash is None:
        return shown, PayloadView(seq=seq, state="none")
    try:
        data = payloads.get(entry.payload_hash)
    except PayloadMissing:
        return shown, PayloadView(seq=seq, state="deleted")
    if content_hash(data) != entry.payload_hash:
        return shown, PayloadView(seq=seq, state="altered", size=len(data))
    text, found = masked(data.decode("utf-8", errors="replace"))
    return shown, PayloadView(
        seq=seq,
        state="stored",
        body=text[:MAX_BODY_SHOWN],
        size=len(data),
        truncated=len(text) > MAX_BODY_SHOWN,
        masked=list(found),
    )


_STATE_LINES: dict[str, str] = {
    "none": "body: none was recorded with this entry",
    "deleted": "body: no longer in the store (forgotten or removed); the entry still verifies",
    "altered": (
        "body: NOT SHOWN. The stored file does not match the hash its entry signed, so it "
        "is not the record. Run `sletchy ledger verify`, and treat the file as tampered"
    ),
}


def render_payload(entry: EntryView, payload: PayloadView) -> str:
    """The entry's line, then its body or why there is none. Every field goes through `inert`."""
    lines = [render([entry])]
    if payload.state != "stored":
        lines.append(_STATE_LINES[payload.state])
        return "\n".join(lines)
    note = f"body: {payload.size} bytes"
    if payload.masked:
        note += f", secrets masked ({', '.join(payload.masked)})"
    lines.append(note)
    # Every body line behind a gutter, so a body can never print a line that passes for
    # a real entry (the trick #96 closed for reasons).
    lines.extend(f"  | {inert(line)}" for line in payload.body.split("\n"))
    if payload.truncated:
        lines.append(f"(cut at {MAX_BODY_SHOWN} characters of {payload.size} bytes)")
    return "\n".join(lines)


def inert(text: str) -> str:
    """`text` with every non-printable character shown as its escape, never interpreted.

    A reason is free text, signed as typed, and printed to a terminal. Unescaped, a
    newline in one printed a second line indistinguishable from a real entry, and an
    escape sequence could erase or recolour what was printed around it (#96). Printable
    text in any script, accents and emoji included, is left exactly as typed.
    """
    return "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text
    )


def render(entries: list[EntryView]) -> str:
    """One line per entry. Every text field goes through `inert`, not only the reason."""
    if not entries:
        return "no entries match"
    width = max(len(inert(e.action)) for e in entries)
    return "\n".join(
        f"{e.seq:>6}  {inert(e.ts)}  {inert(e.plane):<7} {inert(e.actor):<16} "
        f"{inert(e.action):<{width}}  {inert(e.decision):<5} {inert(e.reason)}"
        for e in entries
    )
