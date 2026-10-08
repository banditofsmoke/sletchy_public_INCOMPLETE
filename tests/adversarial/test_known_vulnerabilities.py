"""`scripts/known_vulnerabilities.py` (#34): everything but the network, which CI provides.

The script asks OSV about every locked package and fails on a known vulnerability
nobody accepted. These tests run its reading of the three lockfiles for real, and its
verdict against answers written here: the suite may not reach OSV (LAW 0 §6), and a
check that has only ever answered "clean" proves nothing (L009).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "known_vulnerabilities.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("known_vulnerabilities", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["known_vulnerabilities"] = module
    spec.loader.exec_module(module)
    return module


kv = _load()
Post = Callable[[str, bytes], bytes]

pytestmark = pytest.mark.adversarial

TODAY = date(2026, 10, 4)


def answering(ids_by_name: dict[str, list[str]], *, broken: str = "") -> Post:
    """An OSV that knows these vulnerabilities, and records what it was asked."""

    def post(url: str, body: bytes) -> bytes:
        assert url == kv.QUERY_URL
        queries = json.loads(body)["queries"]
        if broken == "short":
            return json.dumps({"results": []}).encode()
        results = []
        for query in queries:
            name = query["package"]["name"]
            result: dict[str, object] = {}
            if name in ids_by_name:
                result["vulns"] = [{"id": i} for i in ids_by_name[name]]
            if broken == "paged" and name in ids_by_name:
                result["next_page_token"] = "more"
            results.append(result)
        return json.dumps({"results": results}).encode()

    return post


# ── reading the locks ────────────────────────────────────────────────────────


def test_every_lockfile_is_read() -> None:
    packages = kv.locked()
    ecosystems = {p.ecosystem for p in packages}

    assert ecosystems == {"PyPI", "npm", "crates.io"}
    names = {(p.ecosystem, p.name) for p in packages}
    assert ("PyPI", "pydantic") in names
    assert ("PyPI", "sletchy") not in names, "the project itself is not a dependency"
    assert all(p.version for p in packages)


def test_the_list_mode_sends_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    def never(url: str, body: bytes) -> bytes:
        raise AssertionError("--list sent a request")

    assert kv.main(["--list"], post=never) == 0
    assert "nothing was sent" in capsys.readouterr().out


# ── the verdict ──────────────────────────────────────────────────────────────


def test_nothing_known_is_a_pass(capsys: pytest.CaptureFixture[str]) -> None:
    assert kv.main([], post=answering({}), today=TODAY) == 0
    assert "0 not accepted" in capsys.readouterr().out


def test_a_known_vulnerability_nobody_accepted_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert kv.main([], post=answering({"pydantic": ["GHSA-test-0001"]}), today=TODAY) == 1
    out = capsys.readouterr().out
    assert "GHSA-test-0001" in out
    assert "osv.dev/vulnerability/GHSA-test-0001" in out


def test_an_accepted_one_passes_until_its_date_and_fails_after() -> None:
    text = "| `GHSA-test-0002` | pydantic | not reachable: the code path is unused | 2026-12-31 |\n"
    found = {kv.Package("PyPI", "pydantic", "1"): ["GHSA-test-0002"]}

    ok, expired = kv.accepted(text, TODAY)
    assert kv.verdict(found, ok, expired) == []

    ok, expired = kv.accepted(text, date(2027, 1, 1))
    lines = kv.verdict(found, ok, expired)
    assert len(lines) == 1
    assert "run out" in lines[0]


@pytest.mark.parametrize(
    "row",
    [
        "| `GHSA-test-0003` | pydantic |  | 2026-12-31 |",
        "| `GHSA-test-0003` | pydantic | a reason | someday |",
        "| `GHSA-test-0003` | pydantic | a reason |",
    ],
)
def test_an_acceptance_without_a_reason_or_a_date_accepts_nothing(row: str) -> None:
    ok, _ = kv.accepted(row, TODAY)
    assert "GHSA-test-0003" not in ok


@pytest.mark.parametrize("broken", ["short", "paged"])
def test_a_partial_answer_is_a_failure_never_a_pass(
    broken: str, capsys: pytest.CaptureFixture[str]
) -> None:
    post = answering({"pydantic": ["GHSA-test-0004"]}, broken=broken)

    assert kv.main([], post=post, today=TODAY) == 1
    assert "could not ask OSV" in capsys.readouterr().out


def test_an_unreachable_service_is_a_failure(capsys: pytest.CaptureFixture[str]) -> None:
    def down(url: str, body: bytes) -> bytes:
        raise OSError("no route")

    assert kv.main([], post=down, today=TODAY) == 1
    assert "nothing is known clean" in capsys.readouterr().out


def test_the_record_of_accepted_vulnerabilities_reads_cleanly() -> None:
    """Whatever the file holds today, each row it means to accept is accepted."""
    ok, expired = kv.accepted(kv.ACCEPTED.read_text("utf-8"), TODAY)
    assert expired == [], f"acceptances that have run out: {expired}"
    assert isinstance(ok, dict)


def test_ci_asks_on_every_pull_request() -> None:
    workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    assert "python scripts/known_vulnerabilities.py" in workflow
