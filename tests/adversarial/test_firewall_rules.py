"""`sletchy install-rules` (#33): the one step that may need an administrator.

LAW 0 §6 forbids a test touching the host's real firewall, so every host call here is
a fake that records what it was handed: the PowerShell that would run, the answers an
operator would type, the elevation Windows would report. The assertions are about the
**calls made**. Whether Windows honours them is measured by hand and recorded in
ADR-0013, never implied by these.

One test reads this machine's real firewall, read-only and unelevated: the read-back is
only worth trusting if it works against Windows itself.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from sletchy.cli import main as cli_main
from sletchy.cli import panic as panic_mod
from sletchy.cli import rules
from sletchy.kernel.contracts import SANDBOX_LANES
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from tests.adversarial.appcontainer import derive_sid

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]


@dataclass
class Firewall:
    """Stands in for PowerShell. Holds rules as the COM read would report them."""

    rules: list[dict[str, object]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    #: What `ledger.length` was when each script ran, to prove the record came first.
    ledger_length_at: list[int] = field(default_factory=list)
    ledger: Ledger | None = None
    #: When set, what the firewall holds after the install script runs.
    after_install: list[dict[str, object]] | None = None

    def __call__(self, script: str) -> subprocess.CompletedProcess[str]:
        self.scripts.append(script)
        self.ledger_length_at.append(self.ledger.length if self.ledger else -1)
        if script == rules.READ_RULES_SCRIPT:
            return subprocess.CompletedProcess([], 0, json.dumps(self.rules), "")
        if script.startswith("$ErrorActionPreference"):
            self.rules = self.after_install if self.after_install is not None else as_installed()
            return subprocess.CompletedProcess([], 0, "", "")
        raise AssertionError(f"a script no test expected: {script[:80]}")

    @property
    def changes(self) -> list[str]:
        return [s for s in self.scripts if s != rules.READ_RULES_SCRIPT]


def as_installed(**override: object) -> list[dict[str, object]]:
    """The group as the firewall reports it after a correct install."""
    return [
        {
            "name": f"{lane}: no direct network",
            "direction": rules.OUTBOUND,
            "action": rules.BLOCK,
            "protocol": rules.ANY_PROTOCOL,
            "remote": ",".join(rules.NOT_THIS_MACHINE),
            "package": derive_sid(lane),
            "enabled": True,
            "profiles": 0x7FFFFFFF,
            **override,
        }
        for lane in SANDBOX_LANES
    ]


@pytest.fixture(autouse=True)
def windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(panic_mod, "_call_derive_sid", derive_sid)

    def never(*_a: object, **_k: object) -> object:
        raise AssertionError("a real PowerShell was about to run")

    monkeypatch.setattr(panic_mod, "_powershell", never)


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))


@pytest.fixture
def firewall(ledger: Ledger) -> Firewall:
    return Firewall(ledger=ledger)


def install(
    firewall: Firewall,
    ledger: Ledger | None,
    *,
    elevated: bool = True,
    answer: str = "yes",
    **mode: bool,
) -> tuple[int, list[str], list[str]]:
    said: list[str] = []
    asked: list[str] = []

    def ask(prompt: str) -> str:
        asked.append(prompt)
        said.append(f"<asked> {prompt}")
        return answer

    args = SimpleNamespace(**{"plan": False, "check": False, "remove": False, **mode})
    code = rules.run(
        args, ledger, powershell=firewall, elevated=lambda: elevated, ask=ask, out=said.append
    )
    return code, said, asked


def actions(ledger: Ledger) -> list[str]:
    return [e.action for e in ledger.entries()]


# ── the rule set ─────────────────────────────────────────────────────────────


def test_one_rule_per_lane_each_naming_its_own_container() -> None:
    planned = rules.plan(derive_sid)

    assert [r.lane for r in planned] == list(SANDBOX_LANES)
    assert [r.sid for r in planned] == [derive_sid(lane) for lane in SANDBOX_LANES]
    assert len({r.sid for r in planned}) == len(SANDBOX_LANES)


def test_every_command_adds_one_blocking_rule_in_the_sletchy_group_and_nothing_else() -> None:
    lines = rules.script(rules.plan(derive_sid)).splitlines()

    assert lines[0] == "$ErrorActionPreference = 'Stop'"
    for lane, line in zip(SANDBOX_LANES, lines[1:], strict=True):
        assert line.startswith("New-NetFirewallRule ")
        assert "-Group 'Sletchy'" in line
        assert "-Direction Outbound" in line
        assert "-Action Block" in line
        assert f"-Package '{derive_sid(lane)}'" in line
        assert "Allow" not in line
        assert ";" not in line, "a second command could hide behind a semicolon"
    text = "\n".join(lines)
    for never in ("Set-NetFirewall", "Remove-", "Disable-", "Enable-", "netsh", "Profile Domain"):
        assert never not in text


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "127.255.255.255", "127.0.0.0", "::1"],
)
def test_this_machine_is_never_covered_so_the_proxy_stays_reachable(address: str) -> None:
    assert not covered(address)


#: The edges that matter, taken from the blocks themselves rather than written out: just
#: outside this machine's block on both sides, and both ends of each address space. A
#: test may not name an address off this machine (LAW 0 §6); these are interval edges.
_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
EDGES = [
    _LOOPBACK[0] - 1,
    _LOOPBACK[-1] + 1,
    ipaddress.IPv4Address(0),
    ipaddress.IPv4Address(2**32 - 1),
    ipaddress.IPv6Address(0),
    ipaddress.IPv6Address(2),
    ipaddress.IPv6Address(2**128 - 1),
]


@pytest.mark.parametrize(
    "address",
    [
        *(str(edge) for edge in EDGES),
        "192.0.2.1",
        "198.51.100.7",
        "203.0.113.9",
        "2001:db8::1",
        "::ffff:192.0.2.1",
    ],
)
def test_every_other_address_is_covered(address: str) -> None:
    assert covered(address)


def covered(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    spans = rules.EXPECTED_COVERAGE
    assert spans is not None
    return any(low <= int(ip) <= high for low, high in spans[ip.version])


# ── no elevation is ever asked for ───────────────────────────────────────────


def test_unelevated_it_shows_the_plan_says_how_and_changes_nothing(
    firewall: Firewall, ledger: Ledger
) -> None:
    code, said, asked = install(firewall, ledger, elevated=False)

    assert code == rules.EXIT_NOT_DONE
    assert firewall.scripts == [], "it touched the firewall without an administrator"
    assert asked == []
    assert ledger.length == 0
    assert any("New-NetFirewallRule" in line for line in said)
    assert any("administrator" in line for line in said)
    assert said[-1].endswith("Nothing was changed.")


def test_the_module_never_asks_windows_for_elevation() -> None:
    source = Path(rules.__file__).read_text(encoding="utf-8").lower()
    for request in ("runas", "shellexecute", "requireadministrator", "verb"):
        assert request not in source


# ── shown first, confirmed, recorded first ───────────────────────────────────


def test_the_plan_is_shown_in_full_before_the_question(firewall: Firewall, ledger: Ledger) -> None:
    _, said, _ = install(firewall, ledger)

    question = next(i for i, line in enumerate(said) if line.startswith("<asked>"))
    shown = said[:question]
    for rule in rules.plan(derive_sid):
        assert any(rule.command() in line for line in shown), f"{rule.lane} was not shown first"


@pytest.mark.parametrize("answer", ["", "no", "y", "YES please", "ye"])
def test_anything_but_yes_changes_nothing(firewall: Firewall, ledger: Ledger, answer: str) -> None:
    code, said, _ = install(firewall, ledger, answer=answer)

    assert code == rules.EXIT_NOT_DONE
    assert firewall.changes == []
    assert ledger.length == 0
    assert said[-1] == "Nothing was changed."


def test_yes_records_then_adds_then_reads_back(firewall: Firewall, ledger: Ledger) -> None:
    code, said, _ = install(firewall, ledger)

    assert code == rules.EXIT_OK
    assert firewall.changes == [rules.script(rules.plan(derive_sid))]
    install_at = firewall.scripts.index(firewall.changes[0])
    assert firewall.ledger_length_at[install_at] == 1, "the change ran before its record"
    assert actions(ledger) == ["warden.firewall.install", "warden.firewall.check"]
    last = list(ledger.entries())[-1]
    assert last.verdict.decision == "allow"
    assert "all 8 rules present and as planned" in last.verdict.reason
    assert said[-1].startswith("Done.")


def test_a_read_back_that_disagrees_is_recorded_as_a_failure(
    firewall: Firewall, ledger: Ledger
) -> None:
    """An exit code of zero is not evidence. What the firewall holds afterwards is."""
    firewall.after_install = as_installed(action=1)  # allow, where block was asked for

    code, said, _ = install(firewall, ledger)

    assert code == rules.EXIT_NOT_DONE
    last = list(ledger.entries())[-1]
    assert last.action == "warden.firewall.check"
    assert last.verdict.decision == "deny"
    assert "does not block" in last.verdict.reason
    assert any("NOT as planned" in line for line in said)


def test_rules_already_in_the_group_that_are_not_this_plan_stop_it(
    firewall: Firewall, ledger: Ledger
) -> None:
    firewall.rules = [{**as_installed()[0], "package": derive_sid("someone-else")}]

    code, said, asked = install(firewall, ledger)

    assert code == rules.EXIT_NOT_DONE
    assert firewall.changes == []
    assert asked == []
    assert ledger.length == 0
    assert any("--remove" in line for line in said)


def test_installed_already_is_a_no_op(firewall: Firewall, ledger: Ledger) -> None:
    firewall.rules = as_installed()

    code, said, asked = install(firewall, ledger)

    assert code == rules.EXIT_OK
    assert firewall.changes == []
    assert asked == []
    assert "already installed" in said[-1]


def test_without_a_sletchy_to_record_on_it_does_nothing(firewall: Firewall) -> None:
    code, _, asked = install(firewall, None)

    assert code == rules.EXIT_NOT_DONE
    assert firewall.changes == []
    assert asked == []


def test_off_windows_there_is_nothing_to_install(
    firewall: Firewall, ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: False)

    code, _, _ = install(firewall, ledger)

    assert code == rules.EXIT_NOT_DONE
    assert firewall.scripts == []


# ── the check ────────────────────────────────────────────────────────────────


def test_a_correct_set_checks_clean_however_the_firewall_writes_the_ranges(
    firewall: Firewall,
) -> None:
    """The firewall may give back subnets for the ranges we wrote; the coverage is what counts."""
    below = ipaddress.summarize_address_range(ipaddress.IPv4Address(0), _LOOPBACK[0] - 1)
    above = ipaddress.ip_network((_LOOPBACK[-1] + 1, 1))
    subnets = ",".join(
        [
            *(str(n) for n in below),
            str(above),
            "::-::",
            "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ]
    )
    firewall.rules = as_installed(remote=subnets, profiles=7)

    code, said, _ = install(firewall, None, check=True)

    assert code == rules.EXIT_OK, said
    assert firewall.changes == []


@pytest.mark.parametrize(
    ("override", "problem"),
    [
        ({"direction": 1}, "not outbound"),
        ({"action": 1}, "does not block"),
        ({"protocol": 6}, "not every protocol"),
        ({"enabled": False}, "switched off"),
        ({"profiles": 2}, "not on every network profile"),
        ({"remote": "*"}, "covers other addresses"),
        ({"remote": "LocalSubnet"}, "covers other addresses"),
        ({"remote": "192.0.2.0/24"}, "covers other addresses"),
    ],
)
def test_each_way_a_rule_can_be_wrong_is_named(
    firewall: Firewall, override: dict[str, object], problem: str
) -> None:
    firewall.rules = as_installed(**override)

    code, said, _ = install(firewall, None, check=True)

    assert code == rules.EXIT_NOT_DONE
    assert any(problem in line for line in said), said


def test_a_missing_lane_and_a_stranger_are_both_named(firewall: Firewall) -> None:
    present = as_installed()
    firewall.rules = [*present[1:], {**present[0], "package": derive_sid("stranger")}]

    code, said, _ = install(firewall, None, check=True)

    assert code == rules.EXIT_NOT_DONE
    assert any(f"{SANDBOX_LANES[0]}: missing" in line for line in said)
    assert any("not in this plan" in line for line in said)


def test_nothing_installed_is_said_plainly(firewall: Firewall) -> None:
    code, said, _ = install(firewall, None, check=True)

    assert code == rules.EXIT_NOT_DONE
    assert "No Sletchy firewall rules are installed" in said[0]


def test_a_firewall_that_cannot_be_read_is_never_called_clean() -> None:
    def broken(_script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, "", "Access is denied")

    with pytest.raises(OSError, match="Access is denied"):
        rules.read_rules(broken)


@pytest.mark.skipif(sys.platform != "win32", reason="reads Windows Firewall")
def test_the_read_back_reads_this_machine_without_an_administrator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read-only, unelevated: the same query `--check` makes. Whatever the group holds."""
    monkeypatch.undo()
    found = rules.read_rules()
    assert isinstance(found, list)


# ── removing ─────────────────────────────────────────────────────────────────


def test_remove_unelevated_shows_the_command_and_changes_nothing(
    firewall: Firewall, ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    firewall.rules = as_installed()
    removed: list[bool] = []

    def remove(**_: object) -> tuple[int, int, None]:
        removed.append(True)
        return 0, 0, None

    monkeypatch.setattr(panic_mod, "remove_firewall_rules", remove)

    code, said, asked = install(firewall, ledger, elevated=False, remove=True)

    assert code == rules.EXIT_NOT_DONE
    assert removed == []
    assert asked == []
    assert any(panic_mod.REMOVE_RULES_SCRIPT in line for line in said)


def test_remove_elevated_records_then_removes_by_group(
    firewall: Firewall, ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    firewall.rules = as_installed()
    lengths: list[int] = []

    def remove(**_: object) -> tuple[int, int, None]:
        lengths.append(ledger.length)
        return len(SANDBOX_LANES), 0, None

    monkeypatch.setattr(panic_mod, "remove_firewall_rules", remove)

    code, said, _ = install(firewall, ledger, remove=True)

    assert code == rules.EXIT_OK
    assert lengths == [1], "the rules were removed before the removal was recorded"
    assert actions(ledger) == ["warden.firewall.remove"]
    assert "is empty" in said[-1]


# ── the command line ─────────────────────────────────────────────────────────


def test_sletchy_install_rules_plan_prints_and_changes_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main.main(["install-rules", "--plan"]) == rules.EXIT_OK
    out = capsys.readouterr().out
    assert out.count("New-NetFirewallRule") == len(SANDBOX_LANES)
