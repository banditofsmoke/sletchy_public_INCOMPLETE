"""The recall store: what was said, found again by its words and by its meaning (#194).

One SQLite file under `var/memory/`, from Python's standard library (ADR-0019):

- **chunks**: every chunk `chunk.py` cuts, its columns generated from `Chunk`'s own fields
  (LAW 6), plus the ledger entry that added it
- **words**: FTS5, ranked by BM25, over every paragraph and sentence window
- **vectors**: for the same chunks when an embedding model is given, each as a 256-bit
  code and its exact numbers (`vectors.py`)

A search runs both, merges the two rankings by reciprocal rank (k = `FUSION_K`), and
returns paragraphs: a window that matched brings back the paragraph it sits in, once.

**Off until the operator turns it on**: `mind_memory`, read on every call. Off, nothing
is added, searched, listed or embedded, and the refusal is on the record.

**On the record (LAW 1)**, each before it takes effect: an add (`mind.memory.add`, the
chunk ids in a payload), a search (`mind.memory.search`, the question in a payload) and
what it found (`mind.memory.found`, ids and scores in a payload), and a forget
(`mind.memory.forget`). A conversation's chunk must cite an answer entry that exists,
so nothing can pose as something I was told.

**Everything here is derived.** The record and my documents can rebuild it, so deleting
the file loses nothing that matters, and `sletchy stop` need not touch it.

**Stored text is data.** A chunk that says "ignore your instructions" is stored and
returned as text with its source; nothing here acts on what it holds.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import NoneType, UnionType
from typing import TYPE_CHECKING, Concatenate, NoReturn, Protocol, get_args

from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.mind.local import (
    ANSWER_ACTION,
    EgressDenied,
    LocalModel,
    ModelRefused,
    ModelUnreadable,
)
from sletchy.mind.memory import vectors
from sletchy.mind.memory.chunk import Chunk, Kind, Level

if TYPE_CHECKING:
    from sletchy.kernel.ledger import Ledger, PayloadStore

ADD_ACTION = "mind.memory.add"
SEARCH_ACTION = "mind.memory.search"
FOUND_ACTION = "mind.memory.found"
FORGET_ACTION = "mind.memory.forget"

#: The switch this reads, from the registry. Off on a fresh install.
SWITCH = "mind_memory"

FILENAME = "recall.sqlite3"
#: The most the store may grow to. Checked before every write (LAW 0).
MAX_STORE_BYTES = 1024**3
#: Reciprocal rank fusion's constant: a chunk ranked r-th scores 1 / (FUSION_K + r).
FUSION_K = 60
#: Candidates taken from each ranking before they are merged.
CANDIDATES = 50
MAX_QUESTION_CHARS = 2000
#: Words of a question that are searched. The rest are ignored.
MAX_QUESTION_WORDS = 32
#: Levels that are matched. Sections are kept for their header and never matched.
MATCHED = (Level.PARAGRAPH, Level.SENTENCES)

_WORD = re.compile(r"\w+")

#: Words so common they match nearly every chunk, so a question made only of them would
#: send everything to the judge. They are not searched; a question of nothing else finds
#: nothing. English only, and short on purpose.
STOPWORDS = frozenset(
    "a about am an and are as at be been but by can could did do does for from had has "
    "have he her him his how i if in into is it its me my no not of on or our she so "
    "than that the their them then there these they this to us was we were what when "
    "where which who whom why will with would you your".split()
)


class Embedder(Protocol):
    """A model that turns texts into vectors. `name` says which, so vectors from two models
    are never compared."""

    @property
    def name(self) -> str: ...

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


@dataclass(frozen=True)
class LocalEmbedder:
    """An embedding model on this computer, asked through the door (`LocalModel.embed`)."""

    model: LocalModel
    name: str

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return self.model.embed(self.name, texts)


class MemoryRefused(Exception):
    """Sletchy will not do this with its memory. On the ledger as entry `seq`."""

    def __init__(self, reason: str, seq: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.seq = seq


@dataclass(frozen=True)
class Added:
    source: str
    #: Chunks stored by this add, and chunks already held, which were left as they were.
    new: int
    already: int
    #: Chunks given vectors by this add.
    embedded: int
    seq: int


@dataclass(frozen=True)
class Passage:
    """A paragraph a search found, with where it came from."""

    id: str
    kind: Kind
    source: str
    header: str
    text: str
    #: For a conversation: the answer entry the paragraph came from.
    cites: int | None
    score: float
    #: How it was found: "words", "meaning", or both.
    by: tuple[str, ...]


@dataclass(frozen=True)
class Found:
    question: str
    passages: tuple[Passage, ...]
    #: False when meaning could not be searched: no embedding model, none of the stored
    #: vectors from it, or the model did not answer. Words still were.
    by_meaning: bool
    search_seq: int
    found_seq: int


def _sql_type(annotation: object) -> str:
    """A `Chunk` field's column type. Text and integers only, so a new field of another
    type fails here rather than being stored as something it is not."""
    args = get_args(annotation) if isinstance(annotation, UnionType) else ()
    nullable = NoneType in args
    base = next((a for a in args if a is not NoneType), None) if args else annotation
    if base is int:
        sql = "INTEGER"
    elif isinstance(base, type) and issubclass(base, str):
        sql = "TEXT"
    else:
        raise TypeError(f"no column type for {annotation!r}")
    return sql if nullable else f"{sql} NOT NULL"


#: The chunk table's columns, from `Chunk` itself (LAW 6), then the entry that added it.
COLUMNS: tuple[tuple[str, str], ...] = (
    *((name, _sql_type(field.annotation)) for name, field in Chunk.model_fields.items()),
    ("added_seq", "INTEGER NOT NULL"),
)

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS chunks (n INTEGER PRIMARY KEY, "
    + ", ".join(f"{name} {kind}" for name, kind in COLUMNS)
    + ", UNIQUE (id))",
    "CREATE INDEX IF NOT EXISTS chunks_by_source ON chunks (source)",
    "CREATE VIRTUAL TABLE IF NOT EXISTS words USING fts5("
    "header, text, tokenize = 'unicode61 remove_diacritics 2')",
    "CREATE TABLE IF NOT EXISTS vectors (n INTEGER PRIMARY KEY, model TEXT NOT NULL, "
    "code BLOB NOT NULL, vector BLOB NOT NULL)",
)


def fts_query(question: str) -> str | None:
    """The question's words, each quoted, joined by OR: only words reach FTS5, never its
    syntax. Words in `STOPWORDS` are left out. None when no word is left."""
    found = (w.lower() for w in _WORD.findall(question))
    words = list(dict.fromkeys(w for w in found if w not in STOPWORDS))[:MAX_QUESTION_WORDS]
    return " OR ".join(f'"{w}"' for w in words) if words else None


def fuse(*rankings: Sequence[int]) -> dict[int, float]:
    """Reciprocal rank fusion: each ranking, best first, adds 1 / (FUSION_K + rank)."""
    scores: dict[int, float] = {}
    for ranking in rankings:
        for rank, key in enumerate(ranking, start=1):
            scores[key] = scores.get(key, 0.0) + 1.0 / (FUSION_K + rank)
    return scores


def _one_at_a_time[**P, R](
    method: Callable[Concatenate[MemoryStore, P], R],
) -> Callable[Concatenate[MemoryStore, P], R]:
    """A public call holds the store's lock for its whole length: one connection, used by
    whichever thread asks (a conversation asks from worker threads), never by two at once."""

    def held(self: MemoryStore, /, *args: P.args, **kwargs: P.kwargs) -> R:
        with self._lock:
            return method(self, *args, **kwargs)

    held.__name__ = method.__name__
    held.__doc__ = method.__doc__
    return held


class MemoryStore:
    """Chunks, words and vectors in one file, the switch, and the record."""

    def __init__(
        self,
        folder: Path,
        *,
        ledger: Ledger,
        store: PayloadStore,
        actor_id: str,
        switched_on: Callable[[], bool],
        embedder: Embedder | None = None,
        max_bytes: int = MAX_STORE_BYTES,
    ) -> None:
        self.path = folder / FILENAME
        self._ledger = ledger
        self._payloads = store
        self.actor_id = actor_id
        self._switched_on = switched_on
        self.embedder = embedder
        self.max_bytes = max_bytes
        self._db: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    @property
    def payloads(self) -> PayloadStore:
        """Where this store's record entries keep their bodies; the context plan uses it too."""
        return self._payloads

    # ── the public calls ─────────────────────────────────────────────────────

    @_one_at_a_time
    def add(self, chunks: Sequence[Chunk], *, note: str = "") -> Added:
        """Store a source's chunks. Raises `MemoryRefused`; from the embedder, `OSError` or
        whatever it raises, in which case nothing is stored. `note` goes on the record
        with the add: what was left out of it, and why."""
        sources = {(c.kind, c.source) for c in chunks}
        if len(sources) != 1:
            self._refuse(ADD_ACTION, "?", "an add holds the chunks of exactly one source")
        kind, source = next(iter(sources))
        self._check_on(ADD_ACTION, source)
        if kind is Kind.CONVERSATION:
            for cited in {c.cites for c in chunks}:
                if cited is None or not self._is_answer(cited):
                    self._refuse(
                        ADD_ACTION, source, f"a conversation chunk cites no answer ({cited})"
                    )
        db = self._open()
        marks = ",".join("?" * len(chunks))
        held = {
            row[0]
            for row in db.execute(
                f"SELECT id FROM chunks WHERE id IN ({marks})",  # noqa: S608 - marks only
                [c.id for c in chunks],
            )
        }
        new = [c for c in chunks if c.id not in held]
        matched = [c for c in new if c.level in MATCHED]
        found = self._embed([c.header + "\n" + c.text for c in matched]) if matched else None
        size = sum(len(c.text.encode()) * 2 + len(c.header.encode()) + 200 for c in new)
        size += sum(len(v) * 4 + 32 for v in found) if found else 0
        if self._bytes() + size > self.max_bytes:
            self._refuse(
                ADD_ACTION, source, f"the store would pass its ceiling of {self.max_bytes} bytes"
            )
        entry = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=ADD_ACTION,
            subject=Subject(kind=SubjectKind.MEMORY, identifier=_shown(source)),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"{len(new)} chunks from {kind} {_shown(source)!r}, {len(held)} already held"
                    + (f", {len(found)} with vectors from {self._model_name()}" if found else "")
                    + (f"; {note}" if note else "")
                )[:512],
            ),
            payload_hash=self._payloads.put(
                json.dumps({"source": source, "ids": [c.id for c in new]}).encode()
            ),
        )
        with db:
            numbers: dict[str, int] = {}
            for chunk in new:
                values = [*(_value(getattr(chunk, name)) for name, _ in COLUMNS[:-1]), entry.seq]
                cursor = db.execute(
                    f"INSERT INTO chunks ({', '.join(n for n, _ in COLUMNS)}) "  # noqa: S608 - column names and placeholders only
                    f"VALUES ({', '.join('?' * len(COLUMNS))})",
                    values,
                )
                assert cursor.lastrowid is not None  # noqa: S101 - an INSERT always sets it
                numbers[chunk.id] = cursor.lastrowid
                if chunk.level in MATCHED:
                    db.execute(
                        "INSERT INTO words (rowid, header, text) VALUES (?, ?, ?)",
                        (cursor.lastrowid, chunk.header, chunk.text),
                    )
            if found:
                for chunk, vector in zip(matched, found, strict=True):
                    db.execute(
                        "INSERT INTO vectors (n, model, code, vector) VALUES (?, ?, ?, ?)",
                        (
                            numbers[chunk.id],
                            self._model_name(),
                            vectors.pack_code(vectors.code(vector)),
                            vectors.pack(vector),
                        ),
                    )
        return Added(source, len(new), len(held), len(found or ()), entry.seq)

    @_one_at_a_time
    def search(self, question: str, *, k: int = 5) -> Found:
        """The `k` paragraphs that best match the question. Raises `MemoryRefused`."""
        self._check_on(SEARCH_ACTION, "search")
        if not question.strip():
            self._refuse(SEARCH_ACTION, "search", "an empty question")
        if len(question) > MAX_QUESTION_CHARS:
            self._refuse(
                SEARCH_ACTION, "search", f"a question over {MAX_QUESTION_CHARS} characters"
            )
        if not 1 <= k <= CANDIDATES:
            self._refuse(SEARCH_ACTION, "search", f"k must be from 1 to {CANDIDATES}")
        asked = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=SEARCH_ACTION,
            subject=Subject(kind=SubjectKind.MEMORY, identifier="search"),
            verdict=Verdict(
                decision=Decision.ALLOW, reason=f"{len(question)} characters, best {k}"
            ),
            payload_hash=self._payloads.put(question.encode("utf-8")),
        )
        db = self._open()
        by_words = self._by_words(db, question)
        by_meaning = self._by_meaning(db, question)
        scores = fuse(by_words, by_meaning or [])
        how: dict[int, set[str]] = {}
        for n in by_words:
            how.setdefault(n, set()).add("words")
        for n in by_meaning or []:
            how.setdefault(n, set()).add("meaning")
        passages = self._paragraphs(db, scores, how)[:k]
        found = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=FOUND_ACTION,
            subject=Subject(kind=SubjectKind.MEMORY, identifier="search"),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"{len(passages)} passages for search {asked.seq}, by words"
                    + (" and meaning" if by_meaning is not None else " only")
                ),
            ),
            payload_hash=self._payloads.put(
                json.dumps([{"id": p.id, "score": round(p.score, 6)} for p in passages]).encode()
            ),
        )
        return Found(question, tuple(passages), by_meaning is not None, asked.seq, found.seq)

    @_one_at_a_time
    def forget(self, source: str) -> int:
        """Remove a source's chunks, words and vectors. Returns how many chunks. The ledger
        keeps its hashes, so the chain still verifies. Raises `MemoryRefused`."""
        self._check_on(FORGET_ACTION, source)
        db = self._open()
        rows = [n for (n,) in db.execute("SELECT n FROM chunks WHERE source = ?", (source,))]
        self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=FORGET_ACTION,
            subject=Subject(kind=SubjectKind.MEMORY, identifier=_shown(source)),
            verdict=Verdict(decision=Decision.ALLOW, reason=f"{len(rows)} chunks"),
        )
        with db:
            for n in rows:
                db.execute("DELETE FROM words WHERE rowid = ?", (n,))
                db.execute("DELETE FROM vectors WHERE n = ?", (n,))
            db.execute("DELETE FROM chunks WHERE source = ?", (source,))
        return len(rows)

    @_one_at_a_time
    def sources(self) -> list[tuple[str, Kind, int]]:
        """What the store holds: each source, its kind, and its chunks. Raises `MemoryRefused`."""
        self._check_on(SEARCH_ACTION, "sources")
        rows = self._open().execute(
            "SELECT source, kind, COUNT(*) FROM chunks GROUP BY source, kind ORDER BY MIN(n)"
        )
        return [(source, Kind(kind), count) for source, kind, count in rows]

    @_one_at_a_time
    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    # ── searching ────────────────────────────────────────────────────────────

    def _by_words(self, db: sqlite3.Connection, question: str) -> list[int]:
        query = fts_query(question)
        if query is None:
            return []
        return [
            n
            for (n,) in db.execute(
                "SELECT rowid FROM words WHERE words MATCH ? ORDER BY bm25(words) LIMIT ?",
                (query, CANDIDATES),
            )
        ]

    def _by_meaning(self, db: sqlite3.Connection, question: str) -> list[int] | None:
        """Chunks by meaning, best first; None when meaning cannot be searched."""
        if self.embedder is None:
            return None
        model = self._model_name()
        codes = [
            (n, vectors.unpack_code(code))
            for n, code in db.execute("SELECT n, code FROM vectors WHERE model = ?", (model,))
        ]
        if not codes:
            return None
        try:
            asked = self._embed([question])
        except (OSError, ValueError, EgressDenied, ModelRefused, ModelUnreadable):
            return None  # by words only, and `Found.by_meaning` says so
        if asked is None:
            return None
        q = asked[0]
        keep = vectors.shortlist(vectors.code(q), codes)
        held = {
            n: vectors.unpack(blob)
            for n, blob in db.execute(
                f"SELECT n, vector FROM vectors WHERE n IN ({','.join('?' * len(keep))})",  # noqa: S608 - column names and placeholders only
                keep,
            )
        }
        held = {n: v for n, v in held.items() if len(v) == len(q)}
        return [n for n, _ in vectors.rank(q, held, CANDIDATES)]

    def _paragraphs(
        self, db: sqlite3.Connection, scores: dict[int, float], how: dict[int, set[str]]
    ) -> list[Passage]:
        """Lift each scored chunk to its paragraph, which takes its best piece's score.

        The best, not the sum: a paragraph cut into many windows would otherwise outrank
        the one that matched, for having more pieces in the ranking."""
        if not scores:
            return []
        names = ", ".join(n for n, _ in COLUMNS)
        rows = {
            row[0]: row[1:]
            for row in db.execute(
                f"SELECT n, {names} FROM chunks WHERE n IN ({','.join('?' * len(scores))})",  # noqa: S608 - column names and placeholders only
                list(scores),
            )
        }
        lifted: dict[str, float] = {}
        ways: dict[str, set[str]] = {}
        for n, score in scores.items():
            row = rows.get(n)
            if row is None:
                continue
            chunk = dict(zip((c for c, _ in COLUMNS), row, strict=True))
            pid = chunk["parent"] if chunk["level"] == Level.SENTENCES else chunk["id"]
            lifted[pid] = max(lifted.get(pid, 0.0), score)
            ways.setdefault(pid, set()).update(how.get(n, ()))
        order = sorted(lifted, key=lambda pid: lifted[pid], reverse=True)
        found = {
            row[0]: row
            for row in db.execute(
                f"SELECT id, kind, source, header, text, cites FROM chunks "  # noqa: S608 - column names and placeholders only
                f"WHERE id IN ({','.join('?' * len(order))})",
                order,
            )
        }
        return [
            Passage(
                id=pid,
                kind=Kind(found[pid][1]),
                source=found[pid][2],
                header=found[pid][3],
                text=found[pid][4],
                cites=found[pid][5],
                score=lifted[pid],
                by=tuple(sorted(ways[pid])),
            )
            for pid in order
            if pid in found
        ]

    # ── the rest ─────────────────────────────────────────────────────────────

    def _embed(self, texts: Sequence[str]) -> list[list[float]] | None:
        if self.embedder is None:
            return None
        got = self.embedder.embed(texts)
        if len(got) != len(texts):
            raise ValueError(f"{len(texts)} texts gave {len(got)} vectors")
        return [vectors.unit(v) for v in got]

    def _model_name(self) -> str:
        return self.embedder.name if self.embedder is not None else ""

    def _is_answer(self, seq: int) -> bool:
        if not 0 <= seq < self._ledger.length:
            return False
        return any(e.seq == seq and e.action == ANSWER_ACTION for e in self._ledger.entries())

    def _bytes(self) -> int:
        return sum(
            p.stat().st_size
            for p in (self.path, self.path.with_name(FILENAME + "-journal"))
            if p.exists()
        )

    def _open(self) -> sqlite3.Connection:
        if self._db is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Any thread may use it; `_one_at_a_time` makes sure only one does at once.
            db = sqlite3.connect(self.path, check_same_thread=False)
            try:
                for statement in _SCHEMA:
                    db.execute(statement)
                db.commit()
            except sqlite3.OperationalError as exc:
                db.close()
                raise RuntimeError(f"this Python's SQLite cannot hold the store: {exc}") from exc
            self._db = db
        return self._db

    def decline(self, source: str, reason: str) -> int:
        """Keep nothing from a source, on the record: a DENY under `mind.memory.add`, with
        why. Returns the entry. Raises `MemoryRefused` when memory is switched off."""
        self._check_on(ADD_ACTION, source)
        return self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=ADD_ACTION,
            subject=Subject(kind=SubjectKind.MEMORY, identifier=_shown(source)),
            verdict=Verdict(decision=Decision.DENY, reason=reason[:512]),
        ).seq

    def _check_on(self, action: str, identifier: str) -> None:
        if not self._switched_on():
            self._refuse(action, identifier, "memory is switched off")

    def _refuse(self, action: str, identifier: str, reason: str) -> NoReturn:
        entry = self._ledger.append(
            plane=Plane.MIND,
            actor_id=self.actor_id,
            action=action,
            subject=Subject(kind=SubjectKind.MEMORY, identifier=_shown(identifier)),
            verdict=Verdict(decision=Decision.DENY, reason=reason[:512]),
        )
        raise MemoryRefused(reason, entry.seq)


def _shown(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:120] or "?"


def _value(value: object) -> object:
    return str(value) if isinstance(value, str) else value


__all__ = [
    "ADD_ACTION",
    "CANDIDATES",
    "COLUMNS",
    "FILENAME",
    "FORGET_ACTION",
    "FOUND_ACTION",
    "FUSION_K",
    "MAX_QUESTION_CHARS",
    "MAX_STORE_BYTES",
    "SEARCH_ACTION",
    "SWITCH",
    "Added",
    "Embedder",
    "Found",
    "LocalEmbedder",
    "MemoryRefused",
    "MemoryStore",
    "Passage",
    "fts_query",
    "fuse",
]
