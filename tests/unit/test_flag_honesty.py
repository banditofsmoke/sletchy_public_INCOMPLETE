"""A switch must never look like it does something it does not.

Every flag has a plain-words `label` for the desktop's Simple mode, and a `wired`
fact saying whether any code reads it. `wired` is checked against the source here,
so the registry cannot claim a switch works before the feature behind it exists -
and cannot forget to say so once it does.
"""

from __future__ import annotations

import ast
from pathlib import Path

from sletchy.kernel.flags import FlagRegistry

SRC = Path(__file__).resolve().parents[2] / "src" / "sletchy"
REGISTRY = SRC / "kernel" / "flags" / "registry.py"


def string_constants(root: Path, *, skip: Path) -> set[str]:
    found: set[str] = set()
    for path in root.rglob("*.py"):
        if path == skip:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                found.add(node.value)
    return found


def test_every_flag_has_a_label_a_person_can_read() -> None:
    registry = FlagRegistry()
    for flag in registry:
        assert flag.label, f"{flag.name} has no label"
        assert flag.label != flag.name, f"{flag.name}'s label is just its name"
        assert "_" not in flag.label, f"{flag.name}'s label reads like code: {flag.label!r}"


def test_labels_are_unique() -> None:
    labels = [flag.label for flag in FlagRegistry()]
    assert len(labels) == len(set(labels))


def test_the_scanner_finds_a_flag_name_used_in_code(tmp_path: Path) -> None:
    """Positive control: the check below must be able to see a real use."""
    (tmp_path / "uses.py").write_text('if store.is_on("senses_camera"):\n    pass\n')
    (tmp_path / "skipped.py").write_text('NAME = "cli_verbose"\n')
    found = string_constants(tmp_path, skip=tmp_path / "skipped.py")
    assert "senses_camera" in found
    assert "cli_verbose" not in found


def test_wired_matches_the_source() -> None:
    """`wired=True` exactly when some code outside the registry names the flag."""
    used = string_constants(SRC, skip=REGISTRY)
    wrong = [
        f"{flag.name}: registry says wired={flag.wired}, source says {flag.name in used}"
        for flag in FlagRegistry()
        if flag.wired != (flag.name in used)
    ]
    assert not wrong, "\n".join(wrong)


def test_these_switches_are_read_today() -> None:
    """Recorded on purpose, so the day this changes is a visible diff, not a quiet one.

    2026-10-02: no code read any flag. `cli_colour` defaults on and says it
    colourises CLI output; nothing reads it. The desktop says so on every switch.
    2026-10-04: `sletchy-soc` reads `soc_watch_machine` (#146), the first switch
    that does what it says.
    2026-10-05: `sletchy ask` reads `mind_local_models` (ADR-0017), the second. Every
    other switch is still not connected.
    2026-10-08: `sletchy memory` reads `mind_memory` (ADR-0019), the third.
    """
    assert [flag.name for flag in FlagRegistry() if flag.wired] == [
        "mind_local_models",
        "mind_memory",
        "soc_watch_machine",
    ]


def test_every_flag_says_which_human_question_it_serves() -> None:
    """principles.md: every feature answers time, money or connection - or says it is
    the safety floor beneath them. A switch that answers none has no reason to exist."""
    for flag in FlagRegistry():
        assert flag.serves, f"{flag.name} serves no human question"
        assert len(set(flag.serves)) == len(flag.serves), f"{flag.name} repeats a question"
