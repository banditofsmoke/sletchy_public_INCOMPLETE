"""Vectors in Python's standard library: a code to search fast, the numbers to rank exactly.

An embedding model turns a piece of text into a few hundred numbers, and texts that
mean similar things get vectors that point the same way. Comparing a question with every
stored vector in pure Python is slow, so the search is two passes (ADR-0019):

1. **A 256-bit code per vector**, one bit for whether each of its first 256 numbers is
   above zero. Two codes are compared by counting the bits that differ (`int.bit_count`,
   in C), which is fast enough for a hundred thousand chunks: measured at 46 ms on the
   operator's machine
2. **The exact comparison**, a dot product of unit vectors, for the best `RESCORE` by code

Models trained Matryoshka-style (EmbeddingGemma among them) put the most meaning in their
first numbers, so the first 256 make a better code than any other 256.
"""

from __future__ import annotations

import math
from array import array
from collections.abc import Mapping, Sequence

#: Bits in a vector's code.
CODE_BITS = 256
#: How many candidates by code are rescored exactly.
RESCORE = 200


def unit(vector: Sequence[float]) -> list[float]:
    """`vector` scaled to length 1. Raises `ValueError` for no numbers, a zero vector, or a
    number that is not finite."""
    if not vector:
        raise ValueError("an empty vector")
    if not all(isinstance(x, (int, float)) and math.isfinite(x) for x in vector):
        raise ValueError("a vector with a number that is not finite")
    length = math.sqrt(math.fsum(x * x for x in vector))
    if length == 0:
        raise ValueError("a zero vector points nowhere")
    return [x / length for x in vector]


def code(vector: Sequence[float], bits: int = CODE_BITS) -> int:
    """One bit per number, set when it is above zero, from the first `bits` numbers."""
    out = 0
    for i, x in enumerate(vector[:bits]):
        if x > 0:
            out |= 1 << i
    return out


def distance(a: int, b: int) -> int:
    """Bits that differ between two codes."""
    return (a ^ b).bit_count()


def dot(a: Sequence[float], b: Sequence[float]) -> float:
    """For unit vectors, the cosine: 1 for the same direction, 0 for unrelated."""
    return math.fsum(x * y for x, y in zip(a, b, strict=True))


def pack(vector: Sequence[float]) -> bytes:
    return array("f", vector).tobytes()


def unpack(data: bytes) -> list[float]:
    numbers = array("f")
    numbers.frombytes(data)
    return numbers.tolist()


def pack_code(value: int) -> bytes:
    return value.to_bytes(CODE_BITS // 8, "little")


def unpack_code(data: bytes) -> int:
    return int.from_bytes(data, "little")


def shortlist(
    question_code: int, codes: Sequence[tuple[int, int]], keep: int = RESCORE
) -> list[int]:
    """The `keep` keys whose codes differ least from the question's, closest first."""
    ranked = sorted(codes, key=lambda item: distance(item[1], question_code))
    return [key for key, _ in ranked[:keep]]


def rank(
    question: Sequence[float], candidates: Mapping[int, Sequence[float]], limit: int
) -> list[tuple[int, float]]:
    """Candidates by exact similarity to the question, best first."""
    scored = [(key, dot(question, vector)) for key, vector in candidates.items()]
    scored.sort(key=lambda item: item[1], reverse=True)
    return scored[:limit]


__all__ = [
    "CODE_BITS",
    "RESCORE",
    "code",
    "distance",
    "dot",
    "pack",
    "pack_code",
    "rank",
    "shortlist",
    "unit",
    "unpack",
    "unpack_code",
]
