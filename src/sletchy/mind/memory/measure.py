"""Measure a judge on a labelled set: numbers before adjectives (ADR-0019, #195).

A judge is a hypothesis: that it keeps the passages that help and turns away the ones
that only look relevant. This puts a number on it. A set is JSON lines, one question
each, with its passages and which of them help:

    {"question": "Where are the spare keys?",
     "passages": ["The spare keys hang by the back door.", "The front door is blue."],
     "helps": [0], "answerable": true}

`answerable` says whether the passages together answer the question. The hard rows are
the ones where a passage is about the right thing and still does not answer: "the wifi
network is called Orchard" for "what is the wifi password?". A similarity search ranks
it first; a judge should keep nothing.

The report counts, over every passage: kept and helps (right), kept and does not
(wrong), not kept and helps (missed); and over every question, whether the judge's
"answerable" matched. A judge that fails or answers in prose counts as keeping nothing,
as it does in the gate. Each judge call is on the record by the model it asks.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from sletchy.mind.local import EgressDenied, ModelRefused, ModelUnreadable
from sletchy.mind.memory.chunk import Kind
from sletchy.mind.memory.gate import ANSWERABLE, KEEP, Judge, Scores
from sletchy.mind.memory.store import Passage

#: The most a set may hold, so a mistaken file cannot keep a model busy for hours.
MAX_ITEMS = 500
MAX_PASSAGES = 8
MAX_TEXT_CHARS = 2000


@dataclass(frozen=True)
class Item:
    question: str
    passages: tuple[str, ...]
    #: Which passages help answer the question, by position.
    helps: frozenset[int]
    #: Whether the passages, together, answer it.
    answerable: bool


def read_set(lines: Iterable[str]) -> list[Item]:
    """A labelled set from JSON lines. Blank lines are skipped. Raises `ValueError`
    naming the line of the first row that is not a well-formed item."""
    items: list[Item] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            items.append(_item(json.loads(line)))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"line {number}: {exc}") from None
        if len(items) > MAX_ITEMS:
            raise ValueError(f"line {number}: a set holds at most {MAX_ITEMS} questions")
    return items


def _item(row: object) -> Item:
    if not isinstance(row, dict) or set(row) != {"question", "passages", "helps", "answerable"}:
        raise ValueError("a row is an object of question, passages, helps and answerable")
    question, passages, helps, answerable = (
        row["question"],
        row["passages"],
        row["helps"],
        row["answerable"],
    )
    if not isinstance(question, str) or not question.strip() or len(question) > MAX_TEXT_CHARS:
        raise ValueError("the question is not a short piece of text")
    if (
        not isinstance(passages, list)
        or not 1 <= len(passages) <= MAX_PASSAGES
        or not all(isinstance(p, str) and p.strip() and len(p) <= MAX_TEXT_CHARS for p in passages)
    ):
        raise ValueError(f"passages are 1 to {MAX_PASSAGES} short pieces of text")
    if not isinstance(helps, list) or not all(
        isinstance(i, int) and not isinstance(i, bool) and 0 <= i < len(passages) for i in helps
    ):
        raise ValueError("helps lists positions of passages")
    if not isinstance(answerable, bool):
        raise ValueError("answerable is true or false")
    return Item(question, tuple(passages), frozenset(helps), answerable)


@dataclass(frozen=True)
class Report:
    judge: str
    questions: int
    kept_right: int
    kept_wrong: int
    missed: int
    answerable_right: int
    unreadable: int
    seconds: tuple[float, ...]

    @property
    def precision(self) -> float:
        """Of the passages kept, the share that help. 1.0 when nothing was kept."""
        kept = self.kept_right + self.kept_wrong
        return self.kept_right / kept if kept else 1.0

    @property
    def recall(self) -> float:
        """Of the passages that help, the share kept. 1.0 when none helped."""
        helped = self.kept_right + self.missed
        return self.kept_right / helped if helped else 1.0

    @property
    def answerable_accuracy(self) -> float:
        return self.answerable_right / self.questions if self.questions else 0.0

    def lines(self) -> list[str]:
        mean = sum(self.seconds) / len(self.seconds) if self.seconds else 0.0
        return [
            f"judge        {self.judge}",
            f"questions    {self.questions}",
            f"precision    {self.precision:.2f}  ({self.kept_right} kept that help, "
            f"{self.kept_wrong} kept that do not)",
            f"recall       {self.recall:.2f}  ({self.missed} that help were missed)",
            f"answerable   {self.answerable_accuracy:.2f}  "
            f"({self.answerable_right} of {self.questions} right)",
            f"unreadable   {self.unreadable}",
            f"seconds      {mean:.1f} a question, {max(self.seconds, default=0.0):.1f} at most",
            f"thresholds   keep at {KEEP}, answerable at {ANSWERABLE}",
        ]


def measure(
    judge: Judge, items: Sequence[Item], *, clock: Callable[[], float] = time.monotonic
) -> Report:
    """Ask `judge` about every question in the set, and count."""
    right = wrong = missed = answered = unreadable = 0
    seconds: list[float] = []
    for n, item in enumerate(items, start=1):
        passages = [
            Passage(f"m{n}.{i}", Kind.DOCUMENT, "set", f"set question {n}", text, None, 0.0, ())
            for i, text in enumerate(item.passages)
        ]
        start = clock()
        try:
            scores = judge.judge(item.question, passages)
        except (OSError, EgressDenied, ModelRefused, ModelUnreadable):
            scores = Scores((0.0,) * len(passages), 0.0, False)
        seconds.append(clock() - start)
        if len(scores.each) != len(passages):
            scores = Scores((0.0,) * len(passages), 0.0, False)
        unreadable += not scores.readable
        kept = {i for i, p in enumerate(scores.each) if p >= KEEP}
        right += len(kept & item.helps)
        wrong += len(kept - item.helps)
        missed += len(item.helps - kept)
        answered += (bool(kept) and scores.answerable >= ANSWERABLE) == item.answerable
    return Report(
        judge.name, len(items), right, wrong, missed, answered, unreadable, tuple(seconds)
    )


__all__ = ["MAX_ITEMS", "MAX_PASSAGES", "Item", "Report", "measure", "read_set"]
