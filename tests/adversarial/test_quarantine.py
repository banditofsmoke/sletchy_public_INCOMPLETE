"""The quarantine run (#34): every shipped dependency, imported once with an audit hook watching.

Two halves. The positive controls are modules this test writes, each trying one thing
the quarantine must refuse or record; without them, "every dependency imported clean"
could mean the hook saw nothing. Then every shipped package installed on this platform
is imported in quarantine, and must attempt nothing refused.

The child process is not under this suite's host shield, so the controls only ever aim
at this machine and this test's own folder: a connection to loopback, a write next to
the module, a Python that would do nothing if it started.
"""

from __future__ import annotations

import importlib.metadata
import sys
import tomllib
from pathlib import Path

import pytest

from sletchy.warden.supply import quarantine

pytestmark = pytest.mark.adversarial

REPO = Path(__file__).resolve().parents[2]

#: What to import for each shipped distribution. A dependency missing from this table
#: fails `test_every_shipped_dependency_has_an_import_to_quarantine`, so a new one cannot
#: arrive without being profiled.
IMPORT_NAMES: dict[str, str] = {
    "annotated-types": "annotated_types",
    "cffi": "cffi",
    "cryptography": "cryptography",
    "jaraco-classes": "jaraco.classes",
    "jaraco-context": "jaraco.context",
    "jaraco-functools": "jaraco.functools",
    "jeepney": "jeepney",
    "keyring": "keyring",
    "more-itertools": "more_itertools",
    "pycparser": "pycparser",
    "pydantic": "pydantic",
    "pydantic-core": "pydantic_core",
    "pywin32-ctypes": "win32ctypes",
    "secretstorage": "secretstorage",
    "typing-extensions": "typing_extensions",
    "typing-inspection": "typing_inspection",
}


def shipped() -> list[str]:
    """The runtime closure of `sletchy` in `uv.lock`, as `test_supply_chain.py` reads it."""
    lock = tomllib.loads((REPO / "uv.lock").read_text("utf-8"))
    packages = {p["name"]: p for p in lock["package"]}
    seen: set[str] = set()
    todo = [d["name"] for d in packages["sletchy"].get("dependencies", [])]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo += [d["name"] for d in packages[name].get("dependencies", [])]
    return sorted(seen)


def installed(distribution: str) -> bool:
    try:
        importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


# ── positive controls ────────────────────────────────────────────────────────


def control(tmp_path: Path, body: str) -> quarantine.Profile:
    folder = tmp_path / "controls"
    folder.mkdir(exist_ok=True)
    (folder / "control_module.py").write_text(body, encoding="utf-8")
    return quarantine.profile("control_module", path=folder)


def test_a_module_that_does_nothing_is_clean(tmp_path: Path) -> None:
    result = control(tmp_path, "VALUE = 1\n")

    assert result.clean, result


def test_a_connection_is_refused_and_recorded(tmp_path: Path) -> None:
    result = control(
        tmp_path,
        "import socket\ns = socket.socket()\ntry:\n    s.connect(('127.0.0.1', 9))\n"
        "except OSError:\n    pass\n",
    )

    assert "socket.connect" in {e.event for e in result.refused}
    assert not result.clean


def test_a_lookup_is_refused(tmp_path: Path) -> None:
    result = control(
        tmp_path,
        "import socket\ntry:\n    socket.getaddrinfo('localhost', 80)\nexcept OSError:\n    pass\n",
    )

    assert "socket.getaddrinfo" in {e.event for e in result.refused}


def test_starting_a_program_is_refused(tmp_path: Path) -> None:
    result = control(
        tmp_path,
        "import subprocess, sys\ntry:\n    subprocess.run([sys.executable, '-c', 'pass'])\n"
        "except OSError:\n    pass\n",
    )

    assert "subprocess.Popen" in {e.event for e in result.refused}


def test_a_write_outside_the_quarantine_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "written.txt"
    result = control(
        tmp_path,
        f"try:\n    open({str(target)!r}, 'w').write('x')\nexcept OSError:\n    pass\n",
    )

    assert [e.event for e in result.refused] == ["open"]
    assert not target.exists(), "the refused write happened anyway"


def test_a_delete_outside_the_quarantine_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "keep.txt"
    target.write_text("keep", encoding="utf-8")
    result = control(
        tmp_path,
        f"import os\ntry:\n    os.remove({str(target)!r})\nexcept OSError:\n    pass\n",
    )

    assert [e.event for e in result.refused] == ["os.remove"]
    assert target.exists(), "the refused delete happened anyway"


def test_a_read_outside_python_is_recorded_not_refused(tmp_path: Path) -> None:
    target = tmp_path / "read-me.txt"
    target.write_text("data", encoding="utf-8")
    result = control(tmp_path, f"open({str(target)!r}).read()\n")

    assert result.clean
    assert any(e.event == "read" and "read-me.txt" in e.detail for e in result.events)


def test_an_import_that_fails_is_not_clean(tmp_path: Path) -> None:
    result = control(tmp_path, "raise RuntimeError('broken on purpose')\n")

    assert not result.clean
    assert result.error is not None
    assert "broken on purpose" in result.error


# ── every shipped dependency ─────────────────────────────────────────────────


def test_every_shipped_dependency_has_an_import_to_quarantine() -> None:
    assert sorted(IMPORT_NAMES) == shipped(), "a shipped dependency has no quarantine run"


@pytest.mark.parametrize("distribution", sorted(IMPORT_NAMES))
def test_every_shipped_dependency_imports_without_reaching_out(distribution: str) -> None:
    if not installed(distribution):
        pytest.skip(f"{distribution} is not installed on {sys.platform}")

    result = quarantine.profile(IMPORT_NAMES[distribution])

    assert result.error is None, result.summary()
    assert result.refused == (), (
        result.summary() + "\n" + "\n".join(f"  {e.event} {e.detail}" for e in result.refused)
    )
