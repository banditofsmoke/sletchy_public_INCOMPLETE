"""A switch whose file write fails is not recorded as switched (#104).

Measured 2026-10-03: with `var/flags.json` read-only, `flags set senses_camera off`
appended "senses_camera -> off" to the ledger, then failed to replace the file. The
camera stayed on; the record said it went off. Panic's reset did the same, then
reported "final ledger entry not written" over an entry that had been written.

Now a change is staged before its entry and committed after it. A staging failure
records nothing; a commit failure records a second entry saying the change did not
take effect. Each test reads the chain back, because the chain is what has to be true.
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from sletchy.kernel.flags import (
    FLIP_ACTION,
    RESET_ACTION,
    WRITE_FAILED_ACTION,
    FlagStore,
    FlagWriteFailed,
)
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

KEY = b"k" * 32

HOW = [
    pytest.param("a folder in its place", id="folder"),
    pytest.param(
        "read-only",
        id="read-only",
        marks=pytest.mark.skipif(
            sys.platform != "win32", reason="a read-only file blocks a rename on Windows only"
        ),
    ),
]


def open_store(tmp_path: Path) -> FlagStore:
    return FlagStore.open(
        Ledger.open(tmp_path / "ledger", InMemoryKeySource(KEY)), tmp_path / "flags.json"
    )


def chain(tmp_path: Path) -> list[tuple[str, str, str]]:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(KEY))
    return [(e.action, e.subject.identifier, e.verdict.reason) for e in ledger.entries()]


@contextmanager
def unreplaceable(path: Path, how: str) -> Iterator[None]:
    if how == "a folder in its place":
        path.unlink()
        path.mkdir()
        yield
        return
    os.chmod(path, stat.S_IREAD)
    try:
        yield
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


@pytest.mark.parametrize("how", HOW)
def test_a_flip_that_cannot_be_written_is_recorded_as_not_taking_effect(
    tmp_path: Path, how: str
) -> None:
    store = open_store(tmp_path)
    store.set("senses_camera", True, reason="video call")

    with unreplaceable(tmp_path / "flags.json", how):
        with pytest.raises(
            FlagWriteFailed, match="senses_camera stayed on, and the ledger says so"
        ):
            store.set("senses_camera", False)
        assert store.is_on("senses_camera"), "the store says off while the file says on"

    flip, failed = chain(tmp_path)[-2:]
    assert flip[:2] == (FLIP_ACTION, "senses_camera")
    assert "-> off" in flip[2]
    assert failed[:2] == (WRITE_FAILED_ACTION, "senses_camera")
    assert "senses_camera stayed on" in failed[2]
    assert not (tmp_path / "flags.tmp").exists()
    if how == "read-only":
        assert open_store(tmp_path).is_on("senses_camera"), "the file no longer says on"


@pytest.mark.parametrize("how", HOW)
def test_a_reset_that_cannot_be_written_is_recorded_as_not_taking_effect(
    tmp_path: Path, how: str
) -> None:
    store = open_store(tmp_path)
    store.set("senses_camera", True, reason="video call")

    with unreplaceable(tmp_path / "flags.json", how):
        with pytest.raises(FlagWriteFailed, match="no flag was reset"):
            store.reset_all(reason="panic")
        assert store.is_on("senses_camera")

    reset, failed = chain(tmp_path)[-2:]
    assert reset[:2] == (RESET_ACTION, "all")
    assert failed[:2] == (WRITE_FAILED_ACTION, "all")


def test_a_flip_that_cannot_be_staged_records_nothing(tmp_path: Path) -> None:
    """Nothing happened, so nothing is recorded: the entry comes after the staging."""
    store = open_store(tmp_path)
    before = chain(tmp_path)
    (tmp_path / "flags.tmp").mkdir()

    with pytest.raises(OSError) as raised:
        store.set("senses_camera", True, reason="video call")

    assert not isinstance(raised.value, FlagWriteFailed)
    assert chain(tmp_path) == before, "a flip that never happened was recorded"
    assert not store.is_on("senses_camera")


def test_a_flip_that_writes_records_one_entry_and_leaves_no_temp_file(tmp_path: Path) -> None:
    """The control: the ordinary path is unchanged."""
    store = open_store(tmp_path)
    store.set("senses_camera", True, reason="video call")

    assert [a for a, _, _ in chain(tmp_path)] == [FLIP_ACTION]
    assert open_store(tmp_path).is_on("senses_camera")
    assert not (tmp_path / "flags.tmp").exists()
