"""Fakes for the memory tests (ADR-0019): an embedding model that knows a few synonyms.

`Concepts` turns text into a bag of concepts, so "car" and "automobile" point the same
way while sharing no word. That is the one thing a meaning search must do that a word
search cannot, and it needs no model.
"""

from __future__ import annotations

import re
import zlib
from collections.abc import Sequence

DIMS = 256

SYNONYMS = {
    "car": "vehicle",
    "automobile": "vehicle",
    "vehicle": "vehicle",
    "dog": "pet",
    "puppy": "pet",
    "hound": "pet",
}


def concept_vector(text: str) -> list[float]:
    vector = [0.0] * DIMS
    for word in re.findall(r"\w+", text.lower()):
        vector[zlib.crc32(SYNONYMS.get(word, word).encode()) % DIMS] += 1.0
    vector[-1] += 0.01  # never a zero vector
    return vector


class Concepts:
    name = "concepts:test"

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.fail = False

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        if self.fail:
            raise OSError("no model server is answering")
        return [concept_vector(t) for t in texts]
