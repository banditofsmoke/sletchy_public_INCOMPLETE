"""LAW 0 - do no harm to the host machine - asserted mechanically.

Sletchy runs on the operator's only computer. A law enforced only by review is
enforced until the first hurried merge, so the mechanical parts of
`docs/LAW/00-do-no-harm.md` live here as tests.

**Nothing in this file touches the real host.** `SLETCHY_HOME` is redirected to a
`tmp_path`, the firewall step is stubbed, and every fixture is inert. LAW 0 §6
forbids tests that target the host's real services or any third party - including
Sletchy's own tests.

What is asserted here, and what is not, is stated in `COVERAGE.md`. The job-object
row moved out of **Planned** when `winjob` landed and could be measured; the
honeypot's bind behaviour is still asserted only as a flag, because the honeypot
does not exist yet. Saying which is which is the point of LAW 10.
"""

from __future__ import annotations

import ast
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.panic import panic
from sletchy.kernel.flags import FlagRegistry, FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from tests.hostshield import (
    HOST_CHANGES,
    ORDINARY_CODE,
    HostChange,
    code_of,
    host_changes_in,
    is_shipped_code,
)

pytestmark = [pytest.mark.law_zero, pytest.mark.adversarial]

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "sletchy"

#: This file defines the banned markers, so it necessarily contains them. Scanners
#: below skip themselves; without this they fail on their own definitions, which is
#: noise rather than signal.
SELF = Path(__file__).name

#: The host shield's own proof plants a forbidden command or address in every test,
#: on purpose, and the shield refuses each one before it starts. Every probe there
#: is also harmless if run (its docstring says how), so it is exempt from the text
#: scans below for the same reason this file is.
SHIELD_PROOF = "test_host_shield.py"


def _other_test_files() -> list[Path]:
    return [p for p in (REPO / "tests").rglob("test_*.py") if p.name not in {SELF, SHIELD_PROOF}]


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))


def _flags(tmp_path: Path) -> FlagStore:
    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    return FlagStore.open(ledger, paths.flags_file())


def _source_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _tracked(*pathspecs: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", *pathspecs],
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return [p for p in out.split("\0") if p]


def _shipped_code() -> dict[str, str]:
    """Everything Sletchy ships or runs on the host, comments and docstrings removed.

    The Python package, the window's Rust and TypeScript, the scripts, the launcher
    and the git hook. Until 2026-10-03 the LAW 0 scans read `src/` only, so the
    window, which starts processes and creates Job Objects, was never looked at.
    """
    return {
        relative: code_of(REPO / relative, (REPO / relative).read_text("utf-8"))
        for relative in _tracked()
        if is_shipped_code(relative) and (REPO / relative).is_file()
    }


#: Shipped files allowed to name one catalogue entry, because they only read what it
#: names. The operator's decision, 2026-10-04 (#146): the SOC reads what starts with
#: the machine. Each file is held to read-only bindings by its own LAW 0 tests, and
#: every other entry still applies to it. A new row here is a visible decision.
READ_ONLY_SENSORS: dict[str, frozenset[str]] = {
    "src/sletchy/soc/sensors/_startup.py": frozenset({"start at boot"}),
}


def _host_changes(clauses: set[str], *, exempt: bool = True) -> list[str]:
    """Every line of shipped code naming a host change these LAW 0 clauses forbid."""
    hits: list[str] = []
    for relative, code in _shipped_code().items():
        allowed = READ_ONLY_SENSORS.get(relative, frozenset()) if exempt else frozenset()
        for number, line in enumerate(code.splitlines(), 1):
            hits.extend(
                f"{relative}:{number}: {change.what} (LAW 0 {change.clause}): {line.strip()[:80]}"
                for change in host_changes_in(line, where="shipped")
                if change.clause in clauses and change.what not in allowed
            )
    return hits


def _calls(source: str) -> set[str]:
    """Every dotted call name in a file."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            names.add(ast.unparse(node.func))
    return names


# ── §1 - no kernel-mode code, ever ───────────────────────────────────────────

#: Loading any of these means shipping something that can render the host
#: unbootable, or disabling the protections we are trying to add.
KERNEL_MODE_MARKERS = (
    "bcdedit",
    "testsigning",
    "CreateService",
    "SC_MANAGER",
    "SERVICE_KERNEL_DRIVER",
    "NtLoadDriver",
    "ZwLoadDriver",
    "FltRegisterFilter",
    "WdfDriverCreate",
    "\\\\.\\pipe\\driver",
    ".sys",
)


def test_no_source_file_references_kernel_mode_machinery() -> None:
    """ADR-0001: no drivers, no Test Signing Mode, no bootstart services.

    Enabling Test Signing Mode to load our own unsigned "security" driver would
    disable Windows security features in order to install one. Net loss on day one.
    """
    hits: list[str] = []
    for path in _source_files():
        text = path.read_text("utf-8")
        # Skip the prose that explains the ban.
        body = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith(("#", '"', "'"))
        )
        hits.extend(
            f"{path.relative_to(SRC)}: {marker}" for marker in KERNEL_MODE_MARKERS if marker in body
        )
    assert hits == [], f"kernel-mode machinery referenced: {hits}"


def test_no_declared_dependency_is_a_driver_toolkit() -> None:
    import tomllib

    config = tomllib.loads((REPO / "pyproject.toml").read_text("utf-8"))
    declared = " ".join(config["project"]["dependencies"]).lower()
    for banned in ("wdk", "driver", "winio", "inpout", "pywinio"):
        assert banned not in declared, f"{banned} looks like driver tooling"


# ── §3 - least privilege: no elevation at runtime ────────────────────────────


def test_nothing_requests_elevation_at_runtime() -> None:
    """Exactly one operation may prompt for elevation, and it is not implemented
    yet (firewall-rule installation, Wave 2). Nothing else may.

    Case-insensitive, over everything shipped: this used to match `runas` in Python
    only, so `-Verb RunAs` in a script, or `requireAdministrator` in the window's
    manifest, would have passed it.
    """
    hits = _host_changes({"§3"})
    assert hits == [], "runtime elevation requested:\n" + "\n".join(hits)


def test_the_test_suite_itself_is_not_running_elevated() -> None:
    """If the suite runs elevated, its privilege claims prove less than they say.

    **This does not run on CI, and that is a real limitation, not a convenience.**
    GitHub's `windows-latest` runner executes as an administrator, so the check
    would fail there for a reason that has nothing to do with Sletchy. Skipping is
    the honest option - the alternative is a permanently red job that people learn
    to ignore, which is worse than an acknowledged gap.

    What that costs: on CI, `test_nothing_requests_elevation_at_runtime` still
    proves no code *asks* for elevation, but nothing proves Sletchy *runs*
    unelevated. Only a developer machine proves that, and this test is what makes
    it fail loudly there. Recorded in COVERAGE.md as a residual gap.
    """
    if sys.platform != "win32":
        pytest.skip("Windows-specific privilege check")
    if os.environ.get("CI"):
        pytest.skip(
            "GitHub's windows runner is elevated by default; this assertion is "
            "meaningful only on a developer machine (see COVERAGE.md)"
        )
    import ctypes

    assert ctypes.windll.shell32.IsUserAnAdmin() == 0, (
        "the suite is running elevated; LAW 0 assertions about privilege are not "
        "meaningful in this process. Re-run from a non-elevated shell."
    )


# ── §2 - all state under one directory ───────────────────────────────────────


def test_a_full_session_writes_nothing_outside_sletchy_home(tmp_path: Path) -> None:
    """The whole of LAW 0 §2's storage promise, exercised end to end."""
    from sletchy.kernel.ledger import PayloadStore

    flags = _flags(tmp_path)
    flags.set("cli_verbose", True)
    flags.set("egress_enabled", True, reason="exercising the write paths")
    PayloadStore.open(paths.payload_dir()).put(b"a body")
    paths.runtime_dir().mkdir(parents=True, exist_ok=True)
    (paths.runtime_dir() / "daemon.pid").write_text("1", encoding="utf-8")

    home = paths.home()
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written, "expected the session to write something"
    for path in written:
        assert home in path.parents, f"{path} was written outside SLETCHY_HOME"


def test_every_declared_path_lives_under_home() -> None:
    home = paths.home()
    for path in (
        paths.ledger_dir(),
        paths.payload_dir(),
        paths.flags_file(),
        paths.runtime_dir(),
    ):
        assert home in path.parents


def test_nothing_writes_to_a_hardcoded_absolute_path() -> None:
    """A path that is not derived from `paths.home()` cannot be uninstalled."""
    suspicious = ("C:\\\\", "/etc/", "/usr/", "%APPDATA%", "%PROGRAMDATA%", "~/.")
    hits = [
        f"{p.relative_to(SRC)}: {marker}"
        for p in _source_files()
        for marker in suspicious
        if marker in p.read_text("utf-8")
    ]
    assert hits == [], f"hardcoded host paths: {hits}"


def test_no_registry_writes() -> None:
    """No registry values of Sletchy's own, from any language it ships.

    The first version looked for two `winreg` calls by their dotted names, so
    `from winreg import SetValueEx`, `reg add`, or `RegSetValueExW` from Rust or
    ctypes all passed it. Windows itself records each sandbox's AppContainer profile
    in the registry; that is journalled, and deleted by the run or by panic.
    """
    hits = [h for h in _host_changes({"§2"}) if "a registry write" in h]
    assert hits == [], "registry writes:\n" + "\n".join(hits)


# ── §4 - default-off, default-disarmed ───────────────────────────────────────


def test_every_dangerous_flag_is_off_on_a_fresh_install() -> None:
    """Enumerates the whole registry, not a sample."""
    registry = FlagRegistry()
    dangerous = registry.dangerous()
    assert dangerous, "expected dangerous flags to exist"
    for flag in dangerous:
        assert not flag.default, f"{flag.name} defaults on"


def test_the_honeypot_bind_flag_is_dangerous_and_off() -> None:
    """§4: a honeypot reachable from a network is an invitation, not a defense."""
    flag = FlagRegistry().get("honeypot_bind_beyond_loopback")
    assert flag.risk.value == "dangerous"
    assert not flag.default
    assert "LAW 0" in flag.description


def test_a_fresh_install_grants_nothing() -> None:
    """The shipped policy, loaded from the file an operator actually gets."""
    from sletchy.kernel.contracts import Action, Actor, ActorKind, Plane, Subject, SubjectKind
    from sletchy.kernel.policy import PolicyEngine, load_policy

    engine = PolicyEngine(load_policy(REPO / "config" / "policy.default.toml"))
    verdict = engine.evaluate(
        Actor(id="agent_a", kind=ActorKind.AGENT, plane=Plane.MIND),
        Action(name="warden.egress.request"),
        Subject(kind=SubjectKind.HOST, identifier="api.groq.com"),
    )
    assert not verdict.allowed


def test_nothing_registers_itself_to_start_at_boot() -> None:
    """§4: no auto-start unless explicitly opted in - and nothing opts in yet.

    Markers are specific rather than broad. An earlier draft matched bare
    "Startup", which fired on `PYTHONSTARTUP` in the env allowlist - a variable we
    *block*. A check that flags the defence as the attack is worse than no check,
    because it trains people to ignore it.
    """
    hits = _host_changes({"§4"})
    assert hits == [], "boot persistence:\n" + "\n".join(hits)


# ── §2 - panic reverts, and is the documented undo ───────────────────────────


def test_panic_returns_every_flag_to_its_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules", lambda *, dry_run=False: (0, 0, None)
    )
    flags = _flags(tmp_path)
    flags.set("egress_enabled", True, reason="a")
    flags.set("senses_camera", True, reason="b")

    panic(flags)

    assert flags.snapshot() == flags.registry.defaults()


def test_panic_leaves_no_runtime_residue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules", lambda *, dry_run=False: (0, 0, None)
    )
    run = paths.runtime_dir()
    run.mkdir(parents=True)
    for name in ("daemon.pid", "agent.lock", "proxy.sock"):
        (run / name).write_text("", encoding="utf-8")

    panic(_flags(tmp_path))

    assert list(run.iterdir()) == []


def test_firewall_rules_are_removed_by_one_named_group() -> None:
    """§2: removable wholesale, without enumerating them.

    This test used to assert that the text `group=` appeared in panic.py. It did, in
    a netsh command netsh rejects, so the test passed for six weeks while the step
    it guarded never ran successfully once (L009). Text in a source file is not
    evidence; the behaviour is tested in test_panic_reverts.py and the real query
    below.
    """
    from sletchy.cli.panic import REMOVE_RULES_SCRIPT

    assert paths.FIREWALL_GROUP == "Sletchy"
    assert f"-Group '{paths.FIREWALL_GROUP}'" in REMOVE_RULES_SCRIPT


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows Firewall exists only here")
def test_the_firewall_count_really_runs_on_windows() -> None:
    """Positive control (L001, L009): the read-only half of the firewall step, for real.

    Every panic test stubs the firewall, correctly - LAW 0 §6. That is exactly why the
    old step could fail for six weeks unseen: nothing ever ran it. Counting changes
    nothing on the host and needs no elevation, so it can run here, and a broken
    query fails this test instead of reading as "no rules".
    """
    from sletchy.cli.panic import count_firewall_rules

    count = count_firewall_rules()
    assert isinstance(count, int)
    assert count >= 0


# ── §7 - fail closed, never fail destructive ─────────────────────────────────


def test_a_corrupt_ledger_halts_rather_than_being_repaired(tmp_path: Path) -> None:
    from sletchy.kernel.ledger import BadSignature

    flags = _flags(tmp_path)
    flags.set("cli_verbose", True)

    segment = paths.ledger_dir() / "segment-00000.ndjson"
    before = segment.read_bytes()
    segment.write_text(segment.read_text("utf-8").replace("cli_verbose", "tampered"), "utf-8")

    with pytest.raises(BadSignature):
        Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))

    # Fail closed, but never fail destructive: the evidence is intact.
    assert segment.read_bytes() != before  # our own edit
    assert segment.stat().st_size > 0


def test_no_module_offers_a_ledger_repair_function() -> None:
    """A quietly repaired audit log is worse than no audit log."""
    forbidden = ("repair", "rebuild", "truncate_to_valid", "force_verify")
    hits = [
        f"{p.relative_to(SRC)}: {name}"
        for p in _source_files()
        for name in forbidden
        if f"def {name}" in p.read_text("utf-8")
    ]
    assert hits == [], f"ledger repair functions: {hits}"


# ── §6 - the host is never the test target ───────────────────────────────────


def test_no_test_shells_out_to_a_host_reconfiguration_command() -> None:
    """LAW 0 §6, applied to the suite itself.

    A test that reconfigures the host's firewall or Defender would be a bigger risk
    than anything it proves. `netsh` appears in `panic.py`; it must never appear
    unstubbed in a test.
    """
    banned = ("netsh advfirewall", "Set-MpPreference", "bcdedit", "sc.exe create")
    hits = [
        f"{p.name}: {marker}"
        for p in _other_test_files()
        for marker in banned
        if marker in p.read_text("utf-8")
    ]
    assert hits == [], f"tests reconfiguring the host: {hits}"


def test_the_panic_firewall_step_is_stubbed_in_every_panic_test() -> None:
    panic_tests = [p for p in _other_test_files() if "panic" in p.name]
    assert panic_tests, "expected panic tests to exist"
    for path in panic_tests:
        source = path.read_text("utf-8")
        assert "remove_firewall_rules" in source, f"{path.name} does not stub the firewall"


def test_no_test_targets_a_real_network_host() -> None:
    """Only reserved/documentation names may appear."""
    allowed = ("127.0.0.1", "localhost", ".example", ".local", ".invalid", "0.0.0.0")  # noqa: S104
    hits: list[str] = []
    for path in _other_test_files():
        for token in ("https://", "http://"):
            for line in path.read_text("utf-8").splitlines():
                if token in line and not any(a in line for a in allowed):
                    hits.append(f"{path.name}: {line.strip()[:70]}")
    assert hits == [], f"tests referencing real hosts: {hits}"


# ── §5 - the suite does not run unbounded work ───────────────────────────────


def test_resource_ceilings_are_declared_with_conservative_defaults() -> None:
    """§5: an out-of-memory host is a broken host."""
    from sletchy.kernel.contracts import ResourceLimits

    limits = ResourceLimits()
    assert limits.memory_mb <= 2048
    assert limits.cpu_percent <= 50
    assert limits.wall_clock_seconds <= 300


def test_the_repository_declares_no_network_call_at_import_time() -> None:
    """Importing sletchy must not reach out. Proven in a clean subprocess."""
    result = subprocess.run(
        [sys.executable, "-c", "import sletchy, sletchy.kernel, sletchy.cli; print('ok')"],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "SLETCHY_ALLOW_INMEMORY_KEY": "1"},
        cwd=REPO,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


# ── everything shipped, against one catalogue of forbidden host changes ──────
#
# `tests/hostshield.py` holds the catalogue. The same list refuses these operations
# at run time during the tests (`tests/conftest.py`), and is checked here against
# the code Sletchy ships, which no test shield surrounds.


@pytest.mark.parametrize("change", HOST_CHANGES, ids=lambda c: f"{c.clause}-{c.example[:24]}")
def test_every_catalogue_entry_catches_its_own_example(change: HostChange) -> None:
    """Positive control (L001): an entry that cannot fire is a hypothesis."""
    assert change.pattern.search(change.example), change.example


@pytest.mark.parametrize("line", ORDINARY_CODE)
def test_ordinary_code_trips_no_catalogue_entry(line: str) -> None:
    """Each line was a false alarm in a draft. A check that flags ordinary code gets ignored."""
    assert host_changes_in(line, where="shipped") == []
    assert host_changes_in(line, where="runtime") == []


def test_the_scan_reads_every_kind_of_code_sletchy_ships() -> None:
    """Positive control: a scan that read nothing would pass everything."""
    shipped = _shipped_code()
    assert len(shipped) > 100, f"scanned only {len(shipped)} files; the walk is broken"
    kinds = {Path(p).suffix for p in shipped} | {Path(p).name for p in shipped}
    for kind in (".py", ".rs", ".ts", ".tsx", ".cmd", ".toml", ".json", "pre-push"):
        assert kind in kinds, f"no {kind} file was scanned"
    for must in (
        "Open-Sletchy.cmd",
        "apps/desktop/src-tauri/src/bridge.rs",
        "src/sletchy/cli/panic.py",
    ):
        assert must in shipped, f"{must} was not scanned"


@pytest.mark.parametrize(
    ("name", "text", "kept", "dropped"),
    [
        ("a.py", '"""schtasks in a docstring"""\nrun(["schtasks"])  # setx\n', "schtasks", "setx"),
        ("a.rs", '// setx\nlet c = "schtasks"; /* reg add */\n', "schtasks", "setx"),
        ("a.rs", 'let u = "http://x"; let c = "schtasks";\n', "schtasks", "nothing"),
        ("a.cmd", "rem setx PATH\n:: setx\nschtasks /query\n", "schtasks", "setx"),
        ("a.toml", '# setx\nname = "schtasks"\n', "schtasks", "setx"),
    ],
)
def test_comments_are_skipped_and_strings_are_not(
    name: str, text: str, kept: str, dropped: str
) -> None:
    """Prose explaining a ban is not a breach; a command inside a string is one."""
    code = code_of(Path(name), text)
    assert kept in code
    assert dropped not in code


def test_shipped_code_makes_no_host_change_law_zero_forbids() -> None:
    """The whole catalogue, over everything shipped.

    Covers what the clause tests above do not have their own test for: system-wide
    network settings (§2), global environment variables and PATH (§2), the host's own
    defences (§6), killing processes by name (§7), and fetching or evaluating code at
    run time (LAW 4).
    """
    clauses = {change.clause for change in HOST_CHANGES}
    hits = _host_changes(clauses)
    assert hits == [], "LAW 0 host changes in shipped code:\n" + "\n".join(hits)


def test_the_read_only_sensor_exemption_is_one_file_and_one_rule() -> None:
    """Pinned, so widening it is a diff someone has to approve."""
    assert READ_ONLY_SENSORS == {
        "src/sletchy/soc/sensors/_startup.py": frozenset({"start at boot"})
    }
    assert {"start at boot"} <= {change.what for change in HOST_CHANGES}


def test_the_exemption_is_not_vacuous_and_covers_nothing_else() -> None:
    """Positive control: without the exemption the sensor trips exactly the rule it is
    allowed, and nothing else; with it, nothing."""
    clauses = {change.clause for change in HOST_CHANGES}
    sensor = "src/sletchy/soc/sensors/_startup.py"
    unexempted = [hit for hit in _host_changes(clauses, exempt=False) if hit.startswith(sensor)]
    assert unexempted, "the sensor no longer names the startup keys; drop its exemption"
    assert all(": start at boot (LAW 0" in hit for hit in unexempted), unexempted
    assert [hit for hit in _host_changes(clauses) if hit.startswith(sensor)] == []


def test_a_planted_host_change_in_shipped_code_is_caught(tmp_path: Path) -> None:
    """Positive control for the scan itself, in each language it reads."""
    planted = {
        "x.py": 'subprocess.run(["setx", "PATH", "x"])\n',
        "x.rs": 'Command::new("schtasks").args(["/create"]);\n',
        "x.ts": "const s = 'Start-Process app -Verb RunAs';\n",
        "x.cmd": "@echo off\nreg add HKCU\\Software\\x\n",
    }
    for name, text in planted.items():
        code = code_of(tmp_path / name, text)
        assert host_changes_in(code, where="shipped"), f"{name}: not caught"


# ── §6 - the suite and the scripts name no machine but this one ──────────────

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")


def _address_is_nobodys(text: str) -> bool:
    """Loopback, unspecified, or reserved for documentation (RFC 5737): never a host."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True  # not an address at all, e.g. a version number
    documentation = [
        ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ]
    return address.is_loopback or address.is_unspecified or any(address in n for n in documentation)


def test_no_test_or_script_names_an_address_off_this_machine() -> None:
    """LAW 0 §6 by address, where the URL check above only sees `http(s)://` hosts.

    `("8.8.8.8", 53)` in a socket call would pass a URL check. Documentation addresses
    are allowed as text, because the host shield's own tests need an address that is
    nobody's; the shield refuses to send to them anyway.
    """
    files = [
        f
        for f in _tracked("tests", "scripts")
        if f.endswith(".py") and Path(f).name not in {SELF, SHIELD_PROOF}
    ]
    assert len(files) > 30, f"scanned only {len(files)} files"
    hits = [
        f"{f}: {m.group(1)}"
        for f in files
        for m in _IPV4.finditer((REPO / f).read_text("utf-8"))
        if not _address_is_nobodys(m.group(1))
    ]
    assert hits == [], "addresses off this machine:\n" + "\n".join(hits)


def test_the_address_check_can_fail() -> None:
    assert not _address_is_nobodys("8.8.8.8")
    assert not _address_is_nobodys("192.168.1.1")
    assert _address_is_nobodys("127.0.0.1")
    assert _address_is_nobodys("192.0.2.1")
    assert _address_is_nobodys("3.13.0.1") is False
    assert _IPV4.findall("version 3.13.3 and 10.0.19045") == []
