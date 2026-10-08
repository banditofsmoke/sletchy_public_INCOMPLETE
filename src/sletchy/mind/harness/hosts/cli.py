"""The terminal host: one event in, its lines out (ADR-0018 decision 5).

`render(event)` is the whole host. It holds no state, reads nothing and writes nothing;
whoever calls it prints what it returns.

**Nothing a model writes can look like Sletchy speaking.** Sletchy's own lines start with
`[sletchy]`. Every line of an answer starts with `> ` instead, and is shown inert, so a
carriage return cannot take a line back to its start either. An answer that says it was
refused, or names a record entry, is shown as what it is: something the model wrote. A
name or a reason inside one of Sletchy's lines is kept to that line (`_line`), so it
cannot open a line of its own.
"""

from __future__ import annotations

from sletchy.kernel.contracts import AgentEvent, AgentEventType
from sletchy.mind.local import SWITCH, inert
from sletchy.mind.memory import SWITCH as MEMORY_SWITCH

#: What starts every line Sletchy itself says, and no line of an answer.
SAYS = "[sletchy]"
#: What starts every line of an answer.
QUOTE = "> "


def render(event: AgentEvent) -> str:
    """The lines for one event, without a trailing newline. Empty: nothing to show."""
    data = event.data
    seq = event.ledger_seq
    if event.type is AgentEventType.CONTENT:
        lines = inert(str(data.get("text", ""))).split("\n")
        return "\n".join(QUOTE + line for line in lines)
    if event.type is AgentEventType.STATUS:
        left_out = _int(data.get("left_out"))
        return (
            f"{SAYS} asking {_name(data)} (turn {_int(data.get('turn'))}, record entry {seq})"
            + (
                f"; {left_out} earlier turn{'s' if left_out != 1 else ''} left out "
                "to leave room for the answer"
                if left_out
                else ""
            )
            + (
                f"; {recalled} passage{'s' if recalled != 1 else ''} from memory, "
                f"plan entry {_int(data.get('plan_seq'))}"
                if (recalled := _int(data.get("recalled")))
                else ""
            )
            + (
                "; memory not checked: this model could not judge what memory found, "
                "so none of it went with the question; a larger model can"
                if data.get("memory_unchecked") is True
                else ""
            )
        )
    if event.type is AgentEventType.POLICY:
        line = f"{SAYS} refused, record entry {seq}: {_line(data.get('reason', ''))}"
        if data.get("switched_off"):
            line += (
                f"\n{SAYS} To let Sletchy ask a model on this computer: "
                f'sletchy flags set {SWITCH} on --reason "..."'
            )
        if data.get("memory_switched_off"):
            line += (
                f"\n{SAYS} To let Sletchy keep and search what was said: "
                f'sletchy flags set {MEMORY_SWITCH} on --reason "..."'
            )
        return line
    if event.type is AgentEventType.ERROR:
        return f"{SAYS} not answered, record entry {seq}: {_line(data.get('reason', ''))}"
    if event.type is AgentEventType.COMPLETE:
        if data.get("outcome") == "not_in_memory":
            return (
                f"{SAYS} not in my memory: nothing found answers it, so no model was asked to "
                f"answer (record entry {seq})"
            )
        if data.get("outcome") != "answered":
            return ""
        used = _int(data.get("prompt_tokens")) + _int(data.get("answer_tokens"))
        seconds = data.get("seconds")
        line = (
            f"{SAYS} {_name(data)}, "
            f"{seconds if isinstance(seconds, (int, float)) else 0:.1f} s; context {used} of "
            f"{_int(data.get('context_tokens'))} tokens; on the record as entries "
            f"{_int(data.get('asked_seq'))} and {seq}"
        )
        if data.get("out_of_room"):
            line += (
                f"\n{SAYS} The answer stopped early: the model ran out of room in its context."
                " Start a new conversation, or ask a shorter question."
            )
        return line
    return f"{SAYS} {event.type.value}"


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _line(value: object) -> str:
    """Outside text inside one of Sletchy's lines: inert, and kept to that one line."""
    return inert(str(value)).replace("\n", "?").replace("\t", " ")


def _name(data: dict[str, object]) -> str:
    return _line(data.get("model", "?"))[:80]


__all__ = ["QUOTE", "SAYS", "render"]
