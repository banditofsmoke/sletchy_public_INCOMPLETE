"""The secret scanner is itself a control, so it gets adversarial tests.

Every fake key below is syntactically valid and semantically dead - random
characters shaped like the real thing. None of these has ever been a live
credential.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCANNER = Path(__file__).resolve().parents[2] / "scripts" / "secret_scan.py"


def run_scan(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


# Shaped like real keys, deliberately never issued. The trailing markers keep this
# file from tripping the very scanner it tests.
FAKE_KEYS = [
    ("groq", "gsk_0000000000000000000000000000000000000000000000000A"),  # secret-scan: allow
    ("openai", "sk-proj-0000000000000000000000000000000000000000000A"),  # secret-scan: allow
    ("anthropic", "sk-ant-api00-000000000000000000000000000000000000A"),  # secret-scan: allow
    ("huggingface", "hf_00000000000000000000000000000000000A"),  # secret-scan: allow
    ("google", "AIza0000000000000000000000000000000000A"),  # secret-scan: allow
    ("github", "ghp_0000000000000000000000000000000000A"),  # secret-scan: allow
    ("aws", "AKIA0000000000000000"),  # secret-scan: allow
]


@pytest.mark.parametrize(("name", "key"), FAKE_KEYS)
def test_detects_key_shape(tmp_path: Path, name: str, key: str) -> None:
    f = tmp_path / f"{name}_leak.py"
    f.write_text(f'API_KEY = "{key}"\n', encoding="utf-8")

    r = run_scan(f)

    assert r.returncode == 1, f"{name} key was not detected"
    assert "SECRET SCAN FAILED" in r.stderr


@pytest.mark.parametrize(("name", "key"), FAKE_KEYS)
def test_finding_is_masked_never_printed_in_full(tmp_path: Path, name: str, key: str) -> None:
    """A scanner that echoes the secret has moved the leak, not stopped it."""
    f = tmp_path / f"{name}_leak.py"
    f.write_text(f'API_KEY = "{key}"\n', encoding="utf-8")

    r = run_scan(f)

    assert key not in r.stderr
    assert key not in r.stdout
    assert key[:10] in r.stderr, "masked prefix should still identify the key"


def test_detects_secret_as_env_fallback_default(tmp_path: Path) -> None:
    """The exact footgun from old Sletchy's config.py:11.

    A live key as the fallback default of an env lookup works *silently* when the
    env var is missing, so nothing ever surfaces that a baked-in key is in use.
    That is how one Groq key reached eight files across three projects.
    """
    f = tmp_path / "config.py"
    bad = 'GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "baked-in")'  # secret-scan: allow
    f.write_text(f"import os\n{bad}\n", encoding="utf-8")

    r = run_scan(f)

    assert r.returncode == 1
    assert "fallback default" in r.stderr
    assert "fail closed" in r.stderr


def test_env_lookup_without_default_is_clean(tmp_path: Path) -> None:
    f = tmp_path / "config.py"
    f.write_text(
        'import os\nGROQ_API_KEY = os.environ["GROQ_API_KEY"]\n',
        encoding="utf-8",
    )

    assert run_scan(f).returncode == 0


def test_private_key_block_detected(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f = f.with_suffix(".txt")
    header = "-----BEGIN RSA PRIVATE" + " KEY-----"  # split so this file stays clean
    f.write_text(f"{header}\nnot-a-real-key\n", encoding="utf-8")

    assert run_scan(f).returncode == 1


def test_ordinary_code_is_clean(tmp_path: Path) -> None:
    f = tmp_path / "ok.py"
    f.write_text(
        "from sletchy.kernel.secrets import SecretRef\n"
        'GROQ = SecretRef(name="groq_api_key")\n'
        "def greet(name: str) -> str:\n"
        '    return f"hello {name}"\n',
        encoding="utf-8",
    )

    r = run_scan(f)

    assert r.returncode == 0, r.stderr
    assert "clean" in r.stdout


def test_allow_marker_suppresses_a_line(tmp_path: Path) -> None:
    """Needed so this test file - full of key-shaped strings - can live in the repo."""
    f = tmp_path / "fixture.py"
    key = FAKE_KEYS[0][1]
    f.write_text(f'SAMPLE = "{key}"  # secret-scan: allow\n', encoding="utf-8")

    assert run_scan(f).returncode == 0
