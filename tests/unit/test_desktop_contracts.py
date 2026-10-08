"""The window's types and the Rust allowlist are generated, and never stale (LAW 6)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from sletchy.cli.bridge_contracts import ERROR_CODES, METHODS, NoParams, StatusResult

ROOT = Path(__file__).resolve().parents[2]


def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_desktop_contracts", ROOT / "scripts" / "gen_desktop_contracts.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GEN = generator()


def test_the_typescript_is_current() -> None:
    assert GEN.TS_OUT.read_text(encoding="utf-8") == GEN.render_ts(), (
        "run: uv run python scripts/gen_desktop_contracts.py"
    )


def test_the_rust_allowlist_is_current() -> None:
    assert GEN.RS_OUT.read_text(encoding="utf-8") == GEN.render_rs(), (
        "run: uv run python scripts/gen_desktop_contracts.py"
    )


def test_every_method_and_error_code_reaches_both_sides() -> None:
    ts, rs = GEN.render_ts(), GEN.render_rs()
    for method in METHODS:
        assert f'"{method}"' in ts
        assert f'"{method}"' in rs
    for code in ERROR_CODES:
        assert f'"{code}"' in ts


def test_the_check_would_notice_a_new_method(monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control: a change on the Python side changes the generated files."""
    before = GEN.render_ts(), GEN.render_rs()
    monkeypatch.setitem(GEN.METHODS, "made.up", (NoParams, StatusResult))
    after = GEN.render_ts(), GEN.render_rs()
    assert before[0] != after[0]
    assert before[1] != after[1]


def test_an_unsupported_schema_raises_rather_than_guessing() -> None:
    with pytest.raises(GEN.Unsupported):
        GEN.ts_type({"type": "object", "properties": {"x": {}}}, {}, {})
