"""A conversation with a model on this machine, one stream of events per turn (ADR-0018).

    conversation = Conversation(model, "gemma3:1b", ledger=ledger, actor_id="operator_cli")
    async for event in conversation.turn("Hello"):
        ...                                  # a host translates each event, nothing more

**Every event is on the record before it is yielded, and cites its entry** (LAW 1,
ADR-0018 decision 2):

| Event | Cites | Says |
|---|---|---|
| `STATUS` | `mind.model.ask` | the question is recorded and on its way |
| `CONTENT` | `mind.model.answer` | the answer, whole, as the model wrote it |
| `COMPLETE` | `mind.model.answer`, or the refusal | the turn is over: the meter, or "refused" |
| `POLICY` | the refusal (`mind.model.ask` or `warden.egress.local`, denied) | refused, and why |
| `ERROR` | `mind.conversation.error` | not answered: no model server, or an unreadable answer |

**Earlier turns go with each question** (decision 4), oldest left out first when the
conversation would leave less than `ANSWER_SHARE` of the context for the answer, by an
estimate of `CHARS_PER_TOKEN` characters a token. The meter shows the server's own count.

**The answer is untrusted text.** It is carried in `CONTENT` as the model wrote it; a
host shows it inert (`sletchy.mind.local.inert`). Nothing here acts on it.

**With recall (ADR-0019)**, each question first goes to memory: the store searches, the
gate keeps what helps, and the kept passages go before the question as labelled quotes
(`context.py`), with the plan on the record (`mind.context.plan`) before the question.
The question kept in the conversation is mine alone, so passages are never sent twice.
An answered turn is put into memory, citing its answer. `only_from_memory` answers from
memory or not at all: when nothing passes the gate, the turn ends `not_in_memory`, citing
the judgement, and no model is asked to guess.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator, Callable, Sequence
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import (
    AgentEvent,
    AgentEventType,
    Decision,
    Plane,
    Subject,
    SubjectKind,
    Verdict,
)
from sletchy.mind.harness.context import record_plan, with_passages
from sletchy.mind.local import (
    EgressDenied,
    LocalModel,
    ModelRefused,
    ModelUnreadable,
    inert,
)

if TYPE_CHECKING:
    from sletchy.kernel.ledger import Ledger
    from sletchy.mind.memory.recall import Recall, Recalled

ERROR_ACTION = "mind.conversation.error"

#: Characters a token, for the estimate before the server counts. English runs nearer
#: four, so three overstates a conversation's size and errs towards leaving a turn out.
CHARS_PER_TOKEN = 3
#: The share of the context kept for the answer when earlier turns are sent.
ANSWER_SHARE = 0.25


class Conversation:
    """One conversation with one model, held in memory; every turn on the record.

    `earlier` and `conversation_id` carry a conversation on from a `history` and an `id`
    taken before, for a caller that opens its ledger afresh for every question (the
    window's bridge does).
    """

    def __init__(
        self,
        model: LocalModel,
        name: str,
        *,
        ledger: Ledger,
        actor_id: str,
        context_tokens: int | None = None,
        earlier: Sequence[tuple[str, str]] = (),
        conversation_id: str | None = None,
        recall: Recall | None = None,
        only_from_memory: bool = False,
    ) -> None:
        if only_from_memory and recall is None:
            raise ValueError("answering only from memory needs a memory to recall from")
        self._model = model
        self._recall = recall
        self.only_from_memory = only_from_memory
        self.name = name
        self._ledger = ledger
        self.actor_id = actor_id
        #: The model's own context unless a smaller budget is asked for (#202).
        self.context_tokens = context_tokens or model.context_tokens
        #: Short, random and unguessable: it groups this conversation's entries.
        self.id = conversation_id or "c-" + secrets.token_hex(4)
        #: Answered turns, oldest first: (question, answer).
        self._turns: list[tuple[str, str]] = list(earlier)

    @property
    def turns(self) -> int:
        """How many questions have been answered."""
        return len(self._turns)

    @property
    def history(self) -> tuple[tuple[str, str], ...]:
        """The answered turns, oldest first, as (question, answer)."""
        return tuple(self._turns)

    async def turn(self, question: str) -> AsyncIterator[AgentEvent]:
        """Ask one question, with the conversation so far. Ends with `COMPLETE` or `ERROR`."""
        number = len(self._turns) + 1
        recalled = None
        if self._recall is not None:
            recalled = await asyncio.to_thread(self._recall.recall, question)
            if self.only_from_memory and recalled.refused is not None:
                async for event in self._memory_refused(recalled):
                    yield event
                return
            if self.only_from_memory and not recalled.enough:
                yield self._not_in_memory(recalled)
                return
        prompt = (
            with_passages(question, recalled.passages, only=self.only_from_memory)
            if recalled is not None and recalled.passages
            else question
        )
        earlier, left_out = self._fit(prompt)
        plan_seq = None
        if self._recall is not None and recalled is not None:
            plan_seq = record_plan(
                self._ledger,
                self._recall.store.payloads,
                actor_id=self.actor_id,
                conversation=self.id,
                turn=number,
                earlier_turns=len(earlier) // 2,
                left_out_turns=left_out,
                recalled=recalled,
            )
        note = (
            f"turn {number} of conversation {self.id}; "
            f"{len(earlier) // 2} earlier turns sent"
            + (f", {left_out} left out to leave room for the answer" if left_out else "")
            + (f"; plan entry {plan_seq}" if plan_seq is not None else "")
        )
        try:
            asked = await asyncio.to_thread(
                self._model.begin, self.name, prompt, earlier=earlier, note=note
            )
        except (ModelRefused, EgressDenied) as exc:
            async for event in self._refused(exc):
                yield event
            return
        except (ModelUnreadable, OSError) as exc:
            yield self._error(exc)
            return
        yield AgentEvent(
            type=AgentEventType.STATUS,
            data={
                "state": "asked",
                "model": self.name,
                "turn": number,
                "earlier_turns": len(earlier) // 2,
                "left_out": left_out,
                **(
                    {
                        "recalled": len(recalled.passages),
                        "plan_seq": plan_seq,
                        # The judge could not be read, and so nothing went (#205).
                        "memory_unchecked": recalled.judgement is not None
                        and not recalled.judgement.readable
                        and not recalled.passages,
                    }
                    if recalled is not None
                    else {}
                ),
            },
            ledger_seq=asked.asked_seq,
        )
        try:
            answer = await asyncio.to_thread(self._model.send, asked)
        except EgressDenied as exc:
            async for event in self._refused(exc):
                yield event
            return
        except (ModelUnreadable, OSError) as exc:
            yield self._error(exc)
            return
        self._turns.append((question, answer.text))
        if self._recall is not None and not self.only_from_memory:
            await asyncio.to_thread(
                self._recall.keep,
                self.id,
                number,
                question,
                answer.text,
                answered_seq=answer.answered_seq,
            )
        yield AgentEvent(
            type=AgentEventType.CONTENT,
            data={"text": answer.text},
            ledger_seq=answer.answered_seq,
        )
        yield AgentEvent(
            type=AgentEventType.COMPLETE,
            data={
                "outcome": "answered",
                "model": answer.model,
                "seconds": round(answer.seconds, 2),
                "prompt_tokens": answer.prompt_tokens,
                "answer_tokens": answer.answer_tokens,
                "context_tokens": answer.context_tokens,
                "out_of_room": answer.out_of_room,
                "asked_seq": answer.asked_seq,
            },
            ledger_seq=answer.answered_seq,
        )

    async def each(self, question: str, host: Callable[[AgentEvent], None]) -> None:
        """Hand every event of one turn to `host` as it comes. For a host that is a function."""
        async for event in self.turn(question):
            host(event)

    def play(self, question: str, host: Callable[[AgentEvent], None]) -> None:
        """`each`, for a caller with no event loop of its own: a terminal, a worker thread."""
        asyncio.run(self.each(question, host))

    def _fit(self, question: str) -> tuple[list[tuple[str, str]], int]:
        """The earlier turns that fit beside `question`, oldest first, and how many did not."""
        budget = int(self.context_tokens * (1 - ANSWER_SHARE) * CHARS_PER_TOKEN)
        room = budget - len(question)
        kept: list[tuple[str, str]] = []
        for asked, answered in reversed(self._turns):
            size = len(asked) + len(answered)
            if size > room:
                break
            room -= size
            kept.insert(0, (asked, answered))
        earlier = [msg for q, a in kept for msg in (("user", q), ("assistant", a))]
        return earlier, len(self._turns) - len(kept)

    async def _refused(self, exc: ModelRefused | EgressDenied) -> AsyncIterator[AgentEvent]:
        if exc.seq is None:  # a refusal with no entry is not a record; record it as an error
            yield self._error(exc)
            return
        yield AgentEvent(
            type=AgentEventType.POLICY,
            data={
                "decision": Decision.DENY.value,
                "reason": exc.reason,
                "switched_off": isinstance(exc, EgressDenied) and "switched off" in exc.reason,
            },
            ledger_seq=exc.seq,
        )
        yield AgentEvent(
            type=AgentEventType.COMPLETE, data={"outcome": "refused"}, ledger_seq=exc.seq
        )

    def _not_in_memory(self, recalled: Recalled) -> AgentEvent:
        """Nothing in memory answers it, by the gate's judgement: say so, citing it."""
        judgement = recalled.judgement
        return AgentEvent(
            type=AgentEventType.COMPLETE,
            data={
                "outcome": "not_in_memory",
                "model": self.name,
                "found": len(recalled.found.passages) if recalled.found is not None else 0,
                "answerable": judgement.answerable if judgement is not None else 0.0,
                "readable": judgement.readable if judgement is not None else True,
            },
            ledger_seq=recalled.seq,
        )

    async def _memory_refused(self, recalled: Recalled) -> AsyncIterator[AgentEvent]:
        yield AgentEvent(
            type=AgentEventType.POLICY,
            data={
                "decision": Decision.DENY.value,
                "reason": recalled.refused or "memory refused",
                "switched_off": False,
                "memory_switched_off": "switched off" in (recalled.refused or ""),
            },
            ledger_seq=recalled.seq,
        )
        yield AgentEvent(
            type=AgentEventType.COMPLETE, data={"outcome": "refused"}, ledger_seq=recalled.seq
        )

    def _error(self, exc: Exception) -> AgentEvent:
        """Record a turn that was not answered, then say so, citing the entry."""
        unreadable = isinstance(exc, ModelUnreadable)
        why = (
            f"the model server's answer could not be read: {exc}"
            if unreadable
            else f"no model server answered ({type(exc).__name__}); Sletchy never starts one"
        )
        entry = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=ERROR_ACTION,
            subject=Subject(kind=SubjectKind.MODEL, identifier=inert(self.name)[:80] or "?"),
            verdict=Verdict(decision=Decision.DENY, reason=inert(why)[:512]),
        )
        return AgentEvent(
            type=AgentEventType.ERROR,
            data={"kind": "model_unreadable" if unreadable else "no_model_server", "reason": why},
            ledger_seq=entry.seq,
        )


__all__ = ["ANSWER_SHARE", "CHARS_PER_TOKEN", "ERROR_ACTION", "Conversation"]
