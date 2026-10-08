"""Vectors with the standard library alone (ADR-0019): a code to search fast, numbers to rank."""

from __future__ import annotations

import math

import pytest

from sletchy.mind.memory import vectors as v


def test_unit_scales_to_length_one() -> None:
    assert v.unit([3.0, 4.0]) == pytest.approx([0.6, 0.8])


@pytest.mark.parametrize("bad", [[], [0.0, 0.0], [1.0, math.nan], [math.inf, 1.0]])
def test_unit_refuses_a_vector_that_points_nowhere(bad: list[float]) -> None:
    with pytest.raises(ValueError):
        v.unit(bad)


def test_a_code_has_a_bit_for_each_positive_number_of_the_first_256() -> None:
    assert v.code([1.0, -1.0, 0.5, 0.0]) == 0b101
    assert v.code([1.0] * 300) == (1 << 256) - 1


def test_distance_counts_the_bits_that_differ() -> None:
    assert v.distance(0b1010, 0b0110) == 2
    assert v.distance(5, 5) == 0


def test_numbers_and_codes_survive_storage() -> None:
    vector = v.unit([math.sin(i * 1.7) for i in range(768)])
    assert v.unpack(v.pack(vector)) == pytest.approx(vector, abs=1e-6)
    big = (1 << 256) - 12345
    assert v.unpack_code(v.pack_code(big)) == big


def test_the_shortlist_is_closest_code_first() -> None:
    question = 0b1111
    codes = [(1, 0b0000), (2, 0b1111), (3, 0b0111)]

    assert v.shortlist(question, codes, keep=2) == [2, 3]


def test_rank_is_exact_similarity_best_first() -> None:
    q = v.unit([1.0, 0.0])
    candidates = {1: v.unit([0.0, 1.0]), 2: v.unit([1.0, 0.1]), 3: v.unit([1.0, 1.0])}

    assert [key for key, _ in v.rank(q, candidates, limit=3)] == [2, 3, 1]
    assert len(v.rank(q, candidates, limit=1)) == 1


def test_codes_keep_near_vectors_near() -> None:
    """The first pass is only useful if similar vectors get similar codes."""
    base = [math.sin(i * 1.7) for i in range(256)]
    near = [x + 0.1 * math.cos(i * 3.1) for i, x in enumerate(base)]
    far = [math.sin(i * 0.37 + 2.0) for i in range(256)]

    assert v.distance(v.code(base), v.code(near)) < v.distance(v.code(base), v.code(far))
