"""Sletchy's memory: what was said, kept and found again (ADR-0019).

- `chunk.py` cuts a document or a conversation turn into chunks at three sizes
- `vectors.py` searches vectors with Python's standard library alone
- `store.py` keeps them under `var/memory/`, finds them by words and by meaning, and puts
  every add, search and forget on the record

Off until the operator turns on `mind_memory`.
"""

from sletchy.mind.memory.chunk import Chunk, Kind, Level, document, turn
from sletchy.mind.memory.store import (
    ADD_ACTION,
    FORGET_ACTION,
    FOUND_ACTION,
    SEARCH_ACTION,
    SWITCH,
    Added,
    Embedder,
    Found,
    LocalEmbedder,
    MemoryRefused,
    MemoryStore,
    Passage,
)

__all__ = [
    "ADD_ACTION",
    "FORGET_ACTION",
    "FOUND_ACTION",
    "SEARCH_ACTION",
    "SWITCH",
    "Added",
    "Chunk",
    "Embedder",
    "Found",
    "Kind",
    "Level",
    "LocalEmbedder",
    "MemoryRefused",
    "MemoryStore",
    "Passage",
    "document",
    "turn",
]
