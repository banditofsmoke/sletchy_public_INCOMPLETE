"""What is not evidence, told apart before a judge reads it (#205).

A search finds text that shares the question's words, and two kinds of text share them
best while answering nothing:

- **A non-answer**: a model saying it does not know, cannot see, or has no access ("I do
  not have access to your personal information ... your name"). Kept as memory, it
  repeats the question's words, so it ranks above the fact it failed to find, and a judge
  was measured keeping it (#205: the refusal at 0.95, the fact at 0.35). Memory that keeps
  its own non-answers teaches itself not to know.
- **A question alone**: "what is my name?" is the question again, not its answer.

So a turn whose answer is a non-answer keeps only my words, and nothing at all when my
words were only questions (`Recall.keep`); and a found passage of either kind is set
aside before the judge reads anything, with the reason on the plan's record
(`Recall.recall`).

**Told by phrase, in English, and said so** (COVERAGE): a non-answer in other words is
kept and judged as before, and an answer opening with one of these phrases loses its
answer from memory while its question stays.
"""

from __future__ import annotations

import re

from sletchy.mind.memory.chunk import Kind, sentences

#: How a conversation turn is written into memory (`chunk.turn`).
QUESTION = "Question: "
ANSWER = "Answer: "

#: How much of an answer's opening is read for a non-answer: a refusal says so first.
OPENING_CHARS = 400

#: Phrases that open a non-answer, as `_plain` writes them: lower case, straight
#: apostrophes, no markdown.
NON_ANSWERS: tuple[str, ...] = (
    "i don't have access to",
    "i do not have access to",
    "i can't access",
    "i cannot access",
    "i'm not able to access",
    "i am not able to access",
    "i'm unable to access",
    "i am unable to access",
    "i don't know your",
    "i do not know your",
    "i don't know who you are",
    "i do not know who you are",
    "i don't have any information about you",
    "i do not have any information about you",
    "i don't have information about you",
    "i have no information about you",
    "i don't have any personal information",
    "i do not have any personal information",
    "personally identifiable information",
    "i don't have memory of",
    "i do not have memory of",
    "i don't have the ability to remember",
    "i do not have the ability to remember",
    "i don't retain",
    "i do not retain",
    "i can't remember previous",
    "i cannot remember previous",
    "unless you tell me",
    "as an ai language model",
    "not in my memory",
)

#: Words that open a question written without its question mark.
QUESTION_WORDS = frozenset(
    {
        "what", "who", "whom", "whose", "where", "when", "why", "how", "which",
        "do", "does", "did", "is", "are", "was", "were", "am",
        "can", "could", "would", "will", "should", "have", "has",
    }
)  # fmt: skip

_CURLY = str.maketrans({chr(0x2018): "'", chr(0x2019): "'"})
_MARKDOWN = re.compile(r"[*_`#>]")
_FIRST_WORD = re.compile(r"[a-z']+")


def _plain(text: str) -> str:
    return " ".join(_MARKDOWN.sub("", text.lower().translate(_CURLY)).split())


def non_answer(answer: str) -> bool:
    """True when an answer opens by saying it does not know or cannot see."""
    opening = _plain(answer[: OPENING_CHARS * 2])[:OPENING_CHARS]
    return any(phrase in opening for phrase in NON_ANSWERS)


def _is_question(sentence: str) -> bool:
    if sentence.endswith("?"):
        return True
    if sentence[-1:] in ".!":
        return False
    first = _FIRST_WORD.match(sentence.lower())
    return first is not None and first.group() in QUESTION_WORDS


def only_questions(text: str) -> bool:
    """True when every sentence is a question: nothing in it states anything."""
    found = sentences(text)
    return bool(found) and all(_is_question(s) for s in found)


def _split(text: str) -> tuple[str | None, str | None]:
    """A turn's paragraph as (question, answer); None for a part it does not hold."""
    if text.startswith(ANSWER):
        return None, text[len(ANSWER) :]
    if not text.startswith(QUESTION):
        return None, None  # further into an answer: nothing here says whose words
    # An answer that starts with a blank line leaves "Answer:" bare, closing the question's
    # paragraph: that question stands alone.
    question, sep, answer = text[len(QUESTION) :].partition("\n" + ANSWER.rstrip())
    return question, ((answer.strip() or None) if sep else None)


def set_aside(kind: Kind, text: str) -> str | None:
    """Why a found passage is not evidence, or None when a judge should read it."""
    if kind is not Kind.CONVERSATION:
        return None
    question, answer = _split(text)
    if answer is not None and non_answer(answer):
        return "a non-answer"
    if answer is None and question is not None and only_questions(question):
        return "a question alone"
    return None


__all__ = [
    "ANSWER",
    "NON_ANSWERS",
    "OPENING_CHARS",
    "QUESTION",
    "QUESTION_WORDS",
    "non_answer",
    "only_questions",
    "set_aside",
]
