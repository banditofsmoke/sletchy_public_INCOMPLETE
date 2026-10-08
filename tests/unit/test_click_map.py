"""`apps/desktop/WHAT-A-CLICK-CAN-DO.md` is a claim about every way out of the window.

My question, 2026-10-03: "we certain i can click on things without breaking anything?
everything and every path has been mapped to its outcome?" The page answers yes, by
listing every request the window can send. These tests keep that answer true: a
request added to the bridge without a row fails here, and so does a row citing a
test that does not exist (the help registry already caught one invented name).
"""

from __future__ import annotations

import re
from pathlib import Path

from sletchy.cli.bridge_contracts import METHODS

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "apps" / "desktop" / "WHAT-A-CLICK-CAN-DO.md"

#: `path::name`, where path is a repo-relative Python or Rust file.
CITATION = re.compile(r"`((?:tests|apps/desktop/src-tauri/src)/[\w/.-]+\.(?:py|rs))::(\w+)`")
ROW = re.compile(r"^\| `([a-z_.]+)` \|", re.MULTILINE)


def citations(text: str) -> list[tuple[str, str]]:
    return CITATION.findall(text)


def cited_test_exists(path: str, name: str) -> bool:
    source = ROOT / path
    if not source.is_file():
        return False
    keyword = "def" if path.endswith(".py") else "fn"
    return f"{keyword} {name}(" in source.read_text(encoding="utf-8")


def test_every_request_the_window_can_send_has_a_row() -> None:
    rows = set(ROW.findall(MAP.read_text(encoding="utf-8")))
    assert set(METHODS) <= rows, f"no row for {sorted(set(METHODS) - rows)}"
    # The shell's own command is the only other way out, and it has a row too.
    assert rows - set(METHODS) == {"bridge_info"}


def test_the_checker_can_tell_a_real_test_from_an_invented_one() -> None:
    # Positive control: it must be able to say no, or the next test proves nothing.
    assert cited_test_exists("tests/unit/test_bridge.py", "test_status")
    assert not cited_test_exists("tests/unit/test_bridge.py", "test_that_was_never_written")
    assert not cited_test_exists("tests/no/such/file.py", "test_status")
    assert cited_test_exists("apps/desktop/src-tauri/src/job.rs", "the_job_counts_what_ran_in_it")
    assert citations("`tests/unit/test_bridge.py::test_status`") == [
        ("tests/unit/test_bridge.py", "test_status")
    ]


def test_every_test_the_page_cites_exists() -> None:
    cited = citations(MAP.read_text(encoding="utf-8"))
    assert len(cited) >= len(METHODS), "the page cites suspiciously few tests"
    missing = [f"{path}::{name}" for path, name in cited if not cited_test_exists(path, name)]
    assert missing == []
