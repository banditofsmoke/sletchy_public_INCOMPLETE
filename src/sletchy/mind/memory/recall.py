"""Recall: search, then the gate, then a budget, for one question (ADR-0019).

What a conversation calls before it asks a model: the store finds candidates by words and
meaning (#194), what is not evidence is set aside (a non-answer, a question alone:
`evidence.py`, #205), the gate keeps only what helps answer (#195), and what is kept is cut to
`MAX_PASSAGE_CHARS`, so passages never crowd out the question or the conversation. Every
step is on the record by the store and the gate themselves.

After a turn is answered, `keep` puts it into memory, citing the answer's entry, so a
later conversation can find it. A non-answer is not kept: the turn keeps my words alone,
or nothing, on the record, when my words were only questions.

**Memory switched off is not an error here**: the refusal is on the record, and the
conversation goes on without recall.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sletchy.mind.local import EgressDenied, ModelRefused, ModelUnreadable
from sletchy.mind.memory.chunk import turn
from sletchy.mind.memory.evidence import non_answer, only_questions, set_aside
from sletchy.mind.memory.store import MemoryRefused

if TYPE_CHECKING:
    from sletchy.mind.memory.gate import Gate, Judgement
    from sletchy.mind.memory.store import Found, MemoryStore, Passage

#: Passages judged for each question.
SEARCHED = 4
#: How many more a search finds than are judged, so passages set aside do not take the
#: places of evidence: in #205 the fact was found fourth of four, behind three that
#: answered nothing.
SEARCH_WIDTH = 2
#: The most passage text placed before a model, in characters: about a quarter of the
#: room the context leaves for a question and its conversation.
MAX_PASSAGE_CHARS = 2400


@dataclass(frozen=True)
class Recalled:
    """What memory gave one question."""

    found: Found | None
    judgement: Judgement | None
    #: Kept by the gate and within the budget, best first.
    passages: tuple[Passage, ...]
    #: Kept by the gate, and left out for the budget.
    left_out: tuple[Passage, ...]
    #: The last entry recall wrote: the judgement, the search, or the refusal.
    seq: int
    #: Why memory refused, when it did (switched off, a bad question). Then nothing else is set.
    refused: str | None = None
    #: Found, and not judged, because they are not evidence: (passage, why), best first.
    set_aside: tuple[tuple[Passage, str], ...] = ()

    @property
    def enough(self) -> bool:
        return self.judgement is not None and self.judgement.enough and bool(self.passages)


class Recall:
    """A store and a gate, for a conversation."""

    def __init__(
        self,
        store: MemoryStore,
        gate: Gate,
        *,
        searched: int = SEARCHED,
        max_chars: int = MAX_PASSAGE_CHARS,
    ) -> None:
        self.store = store
        self.gate = gate
        self.searched = searched
        self.max_chars = max_chars

    def recall(self, question: str) -> Recalled:
        try:
            found = self.store.search(question, k=self.searched * SEARCH_WIDTH)
        except MemoryRefused as exc:
            return Recalled(None, None, (), (), exc.seq, exc.reason)
        evidence: list[Passage] = []
        aside: list[tuple[Passage, str]] = []
        for passage in found.passages:
            why = set_aside(passage.kind, passage.text)
            if why is not None:
                aside.append((passage, why))
            elif len(evidence) < self.searched:
                evidence.append(passage)
        judgement = self.gate.judge(question, evidence, search_seq=found.found_seq)
        kept: list[Passage] = []
        left: list[Passage] = []
        room = self.max_chars
        for passage in judgement.kept:
            if len(passage.text) <= room:
                kept.append(passage)
                room -= len(passage.text)
            else:
                left.append(passage)
        return Recalled(
            found, judgement, tuple(kept), tuple(left), judgement.seq, set_aside=tuple(aside)
        )

    def keep(
        self, conversation: str, number: int, question: str, answer: str, *, answered_seq: int
    ) -> int | None:
        """Put an answered turn into memory. Returns the add's entry, or None if it was not
        kept: refused or declined (on the record), or its vectors could not be made (the
        attempt is on the record, at the door). A turn not kept never undoes the answer.

        A non-answer is not memory: the turn keeps my question alone, and nothing when
        the question states nothing (#205)."""
        left_out = non_answer(answer)
        try:
            if left_out and only_questions(question):
                self.store.decline(
                    conversation,
                    f"turn {number}: a question and a non-answer, so nothing to remember",
                )
                return None
            chunks = turn(
                conversation, number, question, None if left_out else answer, cites=answered_seq
            )
            note = f"turn {number}: its answer left out, a non-answer" if left_out else ""
            return self.store.add(chunks, note=note).seq
        except (MemoryRefused, OSError, ValueError, EgressDenied, ModelRefused, ModelUnreadable):
            return None


__all__ = ["MAX_PASSAGE_CHARS", "SEARCHED", "SEARCH_WIDTH", "Recall", "Recalled"]
