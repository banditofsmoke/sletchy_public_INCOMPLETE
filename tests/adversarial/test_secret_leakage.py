"""Adversarial tests for secrets.

The value used throughout is `FAKE`, a dead string shaped like nothing in
particular. The point of every test below is that it must not appear anywhere it
was not explicitly revealed.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from sletchy.kernel.contracts import SecretRef
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.kernel.secrets import (
    KeyringBackend,
    Secret,
    SecretBackendUnavailable,
    SecretMissing,
    SecretResolver,
    child_env,
    stripped_from,
)

pytestmark = pytest.mark.adversarial

FAKE = "not-a-real-credential-0000"
REF = SecretRef(name="groq_api_key")


class FakeKeyring:
    """Stands in for the OS keychain. No real credential store is touched."""

    def __init__(self, store: dict[tuple[str, str], str] | None = None) -> None:
        self.store = store or {}
        self.writes: list[tuple[str, str]] = []

    def get_password(self, service: str, name: str) -> str | None:
        return self.store.get((service, name))

    def set_password(self, service: str, name: str, value: str) -> None:
        self.writes.append((service, name))
        self.store[(service, name)] = value

    def delete_password(self, service: str, name: str) -> None:
        del self.store[(service, name)]


class BrokenKeyring:
    """A keychain that is present but not answering."""

    def get_password(self, service: str, name: str) -> str | None:
        msg = "keyring service is not running"
        raise RuntimeError(msg)

    def set_password(self, service: str, name: str, value: str) -> None:
        msg = "keyring service is not running"
        raise RuntimeError(msg)

    def delete_password(self, service: str, name: str) -> None:
        msg = "keyring service is not running"
        raise RuntimeError(msg)


def resolver(
    tmp_path: Path, keyring: KeyringBackend | None = None
) -> tuple[SecretResolver, Ledger]:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    backend = keyring if keyring is not None else FakeKeyring({("sletchy", "groq_api_key"): FAKE})
    return SecretResolver(ledger, backend), ledger


# ── fail closed ──────────────────────────────────────────────────────────────


def test_a_missing_secret_raises(tmp_path: Path) -> None:
    r, _ = resolver(tmp_path, FakeKeyring())
    with pytest.raises(SecretMissing, match="no fallback default"):
        r.resolve(REF)


def test_there_is_no_default_parameter() -> None:
    """The absence of this parameter IS the control.

    A `default=` here would reintroduce exactly the pattern that put one live key
    into eight files across three projects.
    """
    import inspect

    params = set(inspect.signature(SecretResolver.resolve).parameters)
    assert params == {"self", "ref", "actor_id"}
    for forbidden in ("default", "fallback", "or_else", "env_fallback"):
        assert forbidden not in params


def test_a_missing_secret_does_not_read_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No env fallback, even when a plausible variable is sitting right there."""
    monkeypatch.setenv("GROQ_API_KEY", FAKE)
    r, _ = resolver(tmp_path, FakeKeyring())

    with pytest.raises(SecretMissing):
        r.resolve(REF)


def test_a_missing_secret_does_not_create_one(tmp_path: Path) -> None:
    keyring = FakeKeyring()
    r, _ = resolver(tmp_path, keyring)

    with pytest.raises(SecretMissing):
        r.resolve(REF)

    assert keyring.writes == [], "the read path must never write a secret"


def test_a_broken_keychain_is_distinct_from_a_missing_secret(tmp_path: Path) -> None:
    """'The vault is locked' and 'the vault lacks this' need different responses."""
    r, _ = resolver(tmp_path, BrokenKeyring())
    with pytest.raises(SecretBackendUnavailable):
        r.resolve(REF)


def test_the_missing_message_does_not_contain_a_value(tmp_path: Path) -> None:
    r, _ = resolver(tmp_path, FakeKeyring())
    with pytest.raises(SecretMissing) as exc:
        r.resolve(REF)
    assert FAKE not in str(exc.value)


# ── the value does not escape by accident ────────────────────────────────────


def test_a_resolved_secret_is_usable(tmp_path: Path) -> None:
    r, _ = resolver(tmp_path)
    assert r.resolve(REF).reveal() == FAKE


@pytest.mark.parametrize(
    "render",
    [
        repr,
        str,
        lambda s: f"{s}",
        lambda s: "{}".format(s),  # noqa: UP032 - the point is that .format() is covered
        lambda s: f"{s!s}",
    ],
    ids=["repr", "str", "fstring", "format", "fstring-str"],
)
def test_no_rendering_path_leaks_the_value(tmp_path: Path, render: object) -> None:
    r, _ = resolver(tmp_path)
    secret = r.resolve(REF)

    rendered = render(secret)  # type: ignore[operator]
    assert FAKE not in rendered
    assert "groq_api_key" in rendered


def test_logging_a_secret_does_not_leak_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The realistic accident: someone logs the object during debugging."""
    r, _ = resolver(tmp_path)
    secret = r.resolve(REF)

    with caplog.at_level(logging.INFO):
        logging.getLogger("t").info("using %s", secret)

    assert FAKE not in caplog.text


def test_a_traceback_does_not_leak_the_value(tmp_path: Path) -> None:
    import traceback

    r, _ = resolver(tmp_path)
    secret = r.resolve(REF)

    try:
        msg = f"boom while using {secret}"
        raise RuntimeError(msg)
    except RuntimeError:
        assert FAKE not in traceback.format_exc()


def test_comparing_against_a_bare_string_is_a_type_error(tmp_path: Path) -> None:
    """An accidental `secret == "hunter2"` must not become a timing oracle."""
    r, _ = resolver(tmp_path)
    secret = r.resolve(REF)
    assert (secret == FAKE) is False
    assert secret == Secret(REF, FAKE)


def test_a_secret_hashes_by_ref_not_by_value(tmp_path: Path) -> None:
    r, _ = resolver(tmp_path)
    assert hash(r.resolve(REF)) == hash(Secret(REF, "a-different-value"))


def test_the_fingerprint_is_safe_to_log(tmp_path: Path) -> None:
    r, _ = resolver(tmp_path)
    secret = r.resolve(REF)
    fp = secret.fingerprint()

    assert FAKE not in fp
    assert fp == Secret(REF, FAKE).fingerprint()
    assert fp != Secret(REF, "rotated").fingerprint()


# ── the ledger records the ref, never the value ──────────────────────────────


def test_resolution_is_recorded(tmp_path: Path) -> None:
    r, ledger = resolver(tmp_path)
    r.resolve(REF, actor_id="agent_a")

    entry = next(e for e in ledger.entries() if e.action == "kernel.secret.resolve")
    assert entry.actor_id == "agent_a"
    assert entry.subject.identifier == "sletchy/groq_api_key"


def test_no_ledger_entry_contains_the_value(tmp_path: Path) -> None:
    r, _ = resolver(tmp_path)
    r.resolve(REF)
    with pytest.raises(SecretMissing):
        r.resolve(SecretRef(name="absent_key"))

    raw = (tmp_path / "ledger" / "segment-00000.ndjson").read_text(encoding="utf-8")
    assert FAKE not in raw


def test_a_failed_resolution_is_recorded_too(tmp_path: Path) -> None:
    r, ledger = resolver(tmp_path, FakeKeyring())
    with pytest.raises(SecretMissing):
        r.resolve(REF)

    entries = [e for e in ledger.entries() if e.action == "kernel.secret.resolve"]
    assert len(entries) == 1
    assert "not present" in entries[0].verdict.reason


def test_exists_does_not_write_a_resolution(tmp_path: Path) -> None:
    """`sletchy status` should not fill the ledger with reads it did not perform."""
    r, ledger = resolver(tmp_path)
    assert r.exists(REF)
    assert list(ledger.entries()) == []


# ── the child environment allowlist ──────────────────────────────────────────


PARENT = {
    "SYSTEMROOT": r"C:\Windows",
    "PATH": r"C:\evil",
    "GROQ_API_KEY": FAKE,
    "AWS_SECRET_ACCESS_KEY": FAKE,
    "DATABASE_URL": f"postgres://user:{FAKE}@host/db",
    # Inert strings shaped like injection payloads; nothing is written to disk.
    "LD_PRELOAD": "/x/evil.so",
    "PYTHONPATH": "/x/evil",
    "PYTHONSTARTUP": "/x/evil.py",
    "BASH_FUNC_x%%": "() { evil; }",
    "SOME_RANDOM_TOOL_TOKEN": FAKE,
}


def test_no_credential_reaches_the_child() -> None:
    env = child_env(parent=PARENT)
    assert FAKE not in json.dumps(env)


@pytest.mark.parametrize(
    "variable",
    ["GROQ_API_KEY", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "SOME_RANDOM_TOOL_TOKEN"],
)
def test_specific_credential_variables_are_dropped(variable: str) -> None:
    assert variable not in child_env(parent=PARENT)


@pytest.mark.parametrize("variable", ["LD_PRELOAD", "PYTHONPATH", "PYTHONSTARTUP"])
def test_code_injection_variables_are_dropped(variable: str) -> None:
    assert variable not in child_env(parent=PARENT)


def test_shellshock_function_exports_are_dropped() -> None:
    assert "BASH_FUNC_x%%" not in child_env(parent=PARENT)


def test_the_allowlist_is_not_a_blocklist() -> None:
    """An unknown variable is dropped by default, so a new tool's token is covered."""
    env = child_env(parent={**PARENT, "TOMORROWS_NEW_TOOL_SECRET": FAKE})
    assert "TOMORROWS_NEW_TOOL_SECRET" not in env


def test_path_is_supplied_not_inherited() -> None:
    """An inherited PATH is how a sandboxed process finds an interpreter."""
    assert child_env(parent=PARENT)["PATH"] == ""
    assert child_env(parent=PARENT, path=r"C:\allowed")["PATH"] == r"C:\allowed"


def test_the_minimum_needed_to_start_survives() -> None:
    assert child_env(parent=PARENT)["SYSTEMROOT"] == r"C:\Windows"


def test_declared_extras_are_forwarded() -> None:
    env = child_env(parent=PARENT, extra={"OLLAMA_HOST": "127.0.0.1:11434"})
    assert env["OLLAMA_HOST"] == "127.0.0.1:11434"


@pytest.mark.parametrize("variable", ["LD_PRELOAD", "PYTHONPATH", "BASH_FUNC_evil%%"])
def test_extras_cannot_reintroduce_an_injection_variable(variable: str) -> None:
    """A mistake in a declaration must not be able to hand a child an import hook."""
    assert variable not in child_env(parent=PARENT, extra={variable: "/x/evil"})


def test_stripped_from_reports_what_was_dropped() -> None:
    dropped = stripped_from(PARENT)
    assert "GROQ_API_KEY" in dropped
    assert "LD_PRELOAD" in dropped
    assert "SYSTEMROOT" not in dropped
