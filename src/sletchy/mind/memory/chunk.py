"""Cut text into chunks at three sizes, each named by its content (ADR-0019, #194).

**Structure first.** A document is cut where its author cut it: by headings into
sections, sections into paragraphs, paragraphs into sentences. A conversation turn is
its own unit, the question and the answer together. Cutting every N characters would
split a sentence, and a split sentence matches nothing well.

**Three sizes, linked by parent:**

- a **section**: a heading and everything under it, or one turn of a conversation. Kept
  for its header path, never matched
- a **paragraph**: what a model reads. Matched, and what a search returns
- **sentences**: a window of `WINDOW` sentences, moving one sentence at a time, cut only
  from a paragraph longer than the window. Matched precisely, and a match returns its
  paragraph ("small to big")

**Every chunk says where it is**, in a header path: a document's name, then its
headings; a conversation's id and turn. The header is indexed with the words, so a
question can match where something was said as well as what.

**Named by content.** A chunk's id is the SHA-256 of its level, header and text, so the
same text in the same place is stored once, however often it is added.
"""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum

from sletchy.kernel.contracts import Contract

#: Sentences in a window, and so the overlap between neighbouring windows is one less.
WINDOW = 2
#: A paragraph longer than this is cut at sentence ends into pieces no longer than it, so
#: a piece fits a small embedding model's context with room to spare.
MAX_PARAGRAPH_CHARS = 1200
#: Header path separator.
SEP = " > "

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_BLANK = re.compile(r"\n\s*\n")
#: A sentence ends at . ! or ? followed by space; a line break inside a paragraph (a list)
#: ends one too.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+|\n+")


class Level(StrEnum):
    SECTION = "section"
    PARAGRAPH = "paragraph"
    SENTENCES = "sentences"


class Kind(StrEnum):
    CONVERSATION = "conversation"
    DOCUMENT = "document"


class Chunk(Contract):
    """One piece of something said or written, and where it sits."""

    id: str
    #: The chunk this one sits inside: a paragraph's section, a window's paragraph.
    parent: str | None
    level: Level
    kind: Kind
    #: A document's name, or a conversation's id.
    source: str
    header: str
    text: str
    #: Order within its source, so a source can be read back in order.
    position: int
    #: For a conversation: the ledger entry of the answer this turn came from.
    cites: int | None


def chunk_id(level: Level, header: str, text: str) -> str:
    return hashlib.sha256(f"{level}\n{header}\n{text}".encode()).hexdigest()


def sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_END.split(text) if s.strip()]


def paragraphs(text: str) -> list[str]:
    """Blank-line paragraphs, each cut at sentence ends to at most `MAX_PARAGRAPH_CHARS`."""
    out: list[str] = []
    for block in _BLANK.split(text):
        block = block.strip()
        if not block:
            continue
        if len(block) <= MAX_PARAGRAPH_CHARS:
            out.append(block)
            continue
        piece = ""
        for sentence in sentences(block):
            while len(sentence) > MAX_PARAGRAPH_CHARS:  # one enormous sentence
                if piece:
                    out.append(piece)
                    piece = ""
                out.append(sentence[:MAX_PARAGRAPH_CHARS])
                sentence = sentence[MAX_PARAGRAPH_CHARS:]
            if piece and len(piece) + 1 + len(sentence) > MAX_PARAGRAPH_CHARS:
                out.append(piece)
                piece = ""
            piece = f"{piece} {sentence}" if piece else sentence
        if piece:
            out.append(piece)
    return out


class _Builder:
    def __init__(self, kind: Kind, source: str, cites: int | None = None) -> None:
        self.kind = kind
        self.source = source
        self.cites = cites
        self.chunks: list[Chunk] = []
        self._seen: set[str] = set()

    def add(self, level: Level, parent: str | None, header: str, text: str) -> str:
        cid = chunk_id(level, header, text)
        if cid not in self._seen:
            self._seen.add(cid)
            self.chunks.append(
                Chunk(
                    id=cid,
                    parent=parent,
                    level=level,
                    kind=self.kind,
                    source=self.source,
                    header=header,
                    text=text,
                    position=len(self.chunks),
                    cites=self.cites,
                )
            )
        return cid

    def section(self, header: str, body: str) -> None:
        found = paragraphs(body)
        if not found:
            return
        section = self.add(Level.SECTION, None, header, "\n\n".join(found))
        for paragraph in found:
            pid = self.add(Level.PARAGRAPH, section, header, paragraph)
            said = sentences(paragraph)
            if len(said) > WINDOW:
                for i in range(len(said) - WINDOW + 1):
                    self.add(Level.SENTENCES, pid, header, " ".join(said[i : i + WINDOW]))


def document(name: str, text: str) -> list[Chunk]:
    """A document's chunks. Markdown headings make sections; plain text is one section."""
    build = _Builder(Kind.DOCUMENT, name)
    #: The headings above the current line, as (depth, title), outermost first.
    path: list[tuple[int, str]] = []
    body: list[str] = []

    def flush() -> None:
        build.section(SEP.join([name, *(title for _, title in path)]), "\n".join(body))
        body.clear()

    for line in text.replace("\r\n", "\n").split("\n"):
        heading = _HEADING.match(line)
        if heading:
            flush()
            depth = len(heading.group(1))
            while path and path[-1][0] >= depth:
                path.pop()
            path.append((depth, heading.group(2)))
        else:
            body.append(line)
    flush()
    return build.chunks


def turn(
    conversation: str, number: int, question: str, answer: str | None, *, cites: int
) -> list[Chunk]:
    """One answered turn of a conversation: the question and the answer, together.

    `cites` is the ledger entry of the answer (`mind.model.answer`), so a recalled turn can
    always be checked against the record it came from. `answer` None keeps the question
    alone: the answer was a non-answer, and is not memory (`evidence.py`, #205).
    """
    build = _Builder(Kind.CONVERSATION, conversation, cites)
    # One newline, so the question and the start of the answer are one paragraph; an
    # answer's own blank lines still make paragraphs of the rest.
    header = f"conversation {conversation}{SEP}turn {number}"
    said = f"Question: {question}" + (f"\nAnswer: {answer}" if answer is not None else "")
    build.section(header, said)
    return build.chunks


__all__ = [
    "MAX_PARAGRAPH_CHARS",
    "SEP",
    "WINDOW",
    "Chunk",
    "Kind",
    "Level",
    "chunk_id",
    "document",
    "paragraphs",
    "sentences",
    "turn",
]
