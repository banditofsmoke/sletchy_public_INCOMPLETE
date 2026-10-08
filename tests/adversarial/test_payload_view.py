"""`sletchy ledger show --payload` and the bridge's `ledger.payload` (#86).

A stored body is the one place Sletchy keeps whole what it did: a command line, a
sandbox's output. Showing it is how a person audits that, and it is also the one
output path most likely to carry a secret, because secrets travel in arguments and
output. Every body is masked with the scanner's own shapes before it is shown, checked
against the hash its entry signed, and bounded in length.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sletchy.cli import paths
from sletchy.cli.bridge import Bridge, handle_line
from sletchy.cli.ledger_view import (
    MAX_BODY_SHOWN,
    EntryNotFound,
    read_payload,
    render_payload,
)
from sletchy.cli.main import EXIT_CORRUPT, EXIT_FAILED, EXIT_OK, main
from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore, content_hash
from sletchy.kernel.secrets import shapes
from tests.unit.test_secret_scan import FAKE_KEYS

pytestmark = pytest.mark.adversarial

KEY = InMemoryKeySource(b"k" * 32)


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr("sletchy.cli.main.KeyringKeySource", lambda *a, **k: KEY)


def record(body: bytes | None) -> int:
    """Append one entry carrying `body`, and return its sequence number."""
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    digest = PayloadStore.open(paths.payload_dir()).put(body) if body is not None else None
    entry = ledger.append(
        plane=Plane.WARDEN,
        actor_id="tester",
        action="warden.sandbox.launch",
        subject=Subject(kind=SubjectKind.PROCESS, identifier="tool.exe"),
        verdict=Verdict(decision=Decision.ALLOW, reason="launching", rule_id=None),
        payload_hash=digest,
    )
    ledger.close()
    return entry.seq


def show(seq: int, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, str, str]:
    code = main(["ledger", "show", "--payload", str(seq), *extra])
    out = capsys.readouterr()
    return code, out.out, out.err


def bridge_payload(seq: object) -> dict[str, Any]:
    line = json.dumps({"id": 1, "method": "ledger.payload", "params": {"seq": seq}})
    answer = json.loads(handle_line(Bridge(KEY), line.encode("utf-8")))
    assert isinstance(answer, dict)
    return answer


# ── never a secret, on either path ───────────────────────────────────────────


@pytest.mark.parametrize(("shape", "key"), FAKE_KEYS)
def test_no_secret_shape_is_ever_shown(
    shape: str, key: str, capsys: pytest.CaptureFixture[str]
) -> None:
    seq = record(json.dumps({"command": ["tool.exe", "--token", key]}).encode())

    code, out, _ = show(seq, capsys)
    answer = bridge_payload(seq)

    assert code == EXIT_OK
    assert key not in out
    assert key[:10] not in out, "not even the prefix the scanner keeps"
    assert "[secret: " in out
    assert key not in json.dumps(answer)
    assert answer["result"]["payload"]["masked"], "the shape that matched is named"


def test_a_whole_private_key_is_hidden_not_only_its_header(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The scanner flags a file by the header line; a display must hide every line after it."""
    secret_line = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
    begin = "-----BEGIN RSA PRIVATE " + "KEY-----"
    end = "-----END RSA PRIVATE " + "KEY-----"
    seq = record(f"before\n{begin}\n{secret_line}\n{end}\nafter".encode())

    _, out, _ = show(seq, capsys)

    assert secret_line not in out
    assert "before" in out
    assert "after" in out
    assert "[secret: Private key block]" in out


def test_a_private_key_with_no_footer_hides_everything_after_its_header(
    capsys: pytest.CaptureFixture[str],
) -> None:
    begin = "-----BEGIN PRIVATE " + "KEY-----"
    seq = record(f"{begin}\nline one of the key\nline two of the key".encode())
    _, out, _ = show(seq, capsys)
    assert "line one" not in out
    assert "line two" not in out


def test_a_secret_cut_by_the_length_bound_is_still_masked(tmp_path: Path) -> None:
    """Masked first, cut second: a key straddling the cut cannot survive half-shown."""
    key = dict(FAKE_KEYS)["groq"]
    body = ("x" * (MAX_BODY_SHOWN - 10) + key).encode()
    seq = record(body)
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    _, payload = read_payload(ledger, PayloadStore(paths.payload_dir()), seq)
    ledger.close()

    assert payload.truncated
    assert "gsk_" not in payload.body, "cut first, the key's prefix would have survived"
    assert "Groq" in payload.masked


def test_the_scanner_and_the_display_use_one_list_of_shapes() -> None:
    """LAW 6: a shape added for commits is masked on screen, and the other way round."""
    import importlib.util
    import sys

    path = Path(__file__).resolve().parents[2] / "scripts" / "secret_scan.py"
    spec = importlib.util.spec_from_file_location("secret_scan_for_view", path)
    assert spec is not None
    assert spec.loader is not None
    scanner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = scanner
    spec.loader.exec_module(scanner)

    assert [name for name, _ in scanner.PATTERNS] == [name for name, _ in shapes.PATTERNS]
    assert [p.pattern for _, p in scanner.PATTERNS] == [p.pattern for _, p in shapes.PATTERNS]


# ── what is shown, and what is said instead ──────────────────────────────────


def test_a_stored_body_is_shown_with_its_size(capsys: pytest.CaptureFixture[str]) -> None:
    seq = record(b'{"command": ["tool.exe", "--help"]}')
    code, out, _ = show(seq, capsys)
    assert code == EXIT_OK
    assert "warden.sandbox.launch" in out
    assert "body: 35 bytes" in out
    assert '  | {"command": ["tool.exe", "--help"]}' in out


def test_an_entry_without_a_body_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    seq = record(None)
    code, out, _ = show(seq, capsys)
    assert code == EXIT_OK
    assert "none was recorded" in out
    assert bridge_payload(seq)["result"]["payload"]["state"] == "none"


def test_a_deleted_body_reads_as_deleted_never_as_corruption(
    capsys: pytest.CaptureFixture[str],
) -> None:
    body = b"forget me"
    seq = record(body)
    assert PayloadStore.open(paths.payload_dir()).delete(content_hash(body))

    code, out, err = show(seq, capsys)

    assert code == EXIT_OK
    assert "no longer in the store" in out
    assert "the entry still verifies" in out
    assert "CORRUPT" not in out + err
    assert bridge_payload(seq)["result"]["payload"]["state"] == "deleted"


def test_a_body_planted_or_edited_under_its_hash_is_not_shown(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Someone writes their own text into the file the entry points at. It is not the record."""
    seq = record(b"what really ran")
    for path in Path(paths.payload_dir()).rglob("*"):
        if path.is_file():
            path.write_bytes(b"what someone wants you to think ran")

    code, out, _ = show(seq, capsys)

    assert code == EXIT_OK
    assert "NOT SHOWN" in out
    assert "what someone wants" not in out
    answer = bridge_payload(seq)["result"]["payload"]
    assert answer["state"] == "altered"
    assert answer["body"] == ""


def test_a_body_cannot_print_a_line_that_passes_for_an_entry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every body line sits behind a gutter, and control characters are escaped (#96)."""
    forged = (
        "     7  2026-10-04T00:00:00+00:00  kernel  someone  kernel.flag.flip  allow  all clear"
    )
    seq = record(f"{forged}\n\x1b[2Kerased".encode())

    _, out, _ = show(seq, capsys)

    assert f"\n{forged}" not in out
    assert f"  | {forged}" in out
    assert "\x1b" not in out


def test_a_long_body_is_cut_and_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    seq = record(b"a" * (MAX_BODY_SHOWN + 500))
    _, out, _ = show(seq, capsys)
    assert f"cut at {MAX_BODY_SHOWN} characters of {MAX_BODY_SHOWN + 500} bytes" in out
    assert bridge_payload(seq)["result"]["payload"]["truncated"] is True


# ── refusals ─────────────────────────────────────────────────────────────────


def test_a_missing_entry_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    record(b"x")
    code, _, err = show(99, capsys)
    assert code == EXIT_FAILED
    assert "no entry with sequence number 99" in err
    assert bridge_payload(99)["error"]["code"] == "no_such_entry"
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    with pytest.raises(EntryNotFound):
        read_payload(ledger, PayloadStore(paths.payload_dir()), 99)
    ledger.close()


def test_nothing_is_shown_from_a_chain_that_does_not_verify(
    capsys: pytest.CaptureFixture[str],
) -> None:
    seq = record(b"the body")
    segment = next(Path(paths.ledger_dir()).glob("segment-*.ndjson"))
    segment.write_text(segment.read_text("utf-8").replace("launching", "lunching"), "utf-8")

    code, out, err = show(seq, capsys)

    assert code == EXIT_CORRUPT
    assert "the body" not in out
    assert "Nothing is shown" in err
    assert bridge_payload(seq)["error"]["code"] == "ledger_corrupt"


@pytest.mark.parametrize("extra", [("--tail", "3"), ("--action", "warden"), ("--denied",)])
def test_payload_takes_one_entry_and_no_filters(
    extra: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    seq = record(b"x")
    code, out, err = show(seq, capsys, *extra)
    assert code == EXIT_FAILED
    assert "cannot be combined" in err
    assert out == ""


@pytest.mark.parametrize("seq", [-1, "1", 1.5, True, None, 2**60])
def test_the_bridge_bounds_the_sequence_number(seq: object) -> None:
    record(b"x")
    assert bridge_payload(seq)["error"]["code"] == "invalid_params"


def test_reading_a_body_writes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    seq = record(b"x")
    home = Path(paths.home())
    before = sorted((p, p.stat().st_size) for p in home.rglob("*") if p.is_file())
    show(seq, capsys)
    bridge_payload(seq)
    after = sorted((p, p.stat().st_size) for p in home.rglob("*") if p.is_file())
    assert after == before


def test_render_names_the_masked_shapes() -> None:
    seq = record(("token " + dict(FAKE_KEYS)["github"]).encode())
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    entry, payload = read_payload(ledger, PayloadStore(paths.payload_dir()), seq)
    ledger.close()
    assert "secrets masked (GitHub)" in render_payload(entry, payload)
