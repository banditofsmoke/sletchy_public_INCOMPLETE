"""`sletchy install-rules` - the one step that may need an administrator (#33).

[LAW 0 §3](../../../docs/LAW/00-do-no-harm.md): exactly one operation may need
elevation, initial firewall-rule installation, as a separate one-shot step that
prints exactly what it will do first. This is that step.

**What it adds.** One outbound **block** rule per sandbox lane, in the `Sletchy`
group and nowhere else. Each names its lane's container SID, so it applies to a
program running in that sandbox and to nothing else on the machine, and each covers
every address but this machine's own (`127.0.0.0/8` and `::1`), so a contained
program can still reach Sletchy's proxy there. A rule only ever blocks: nothing here
opens a port, allows a program or changes a profile.

**Why per lane.** A firewall rule names a container by its SID, and Windows derives
the SID from the container's name. The Warden's containers are named for eight
fixed lanes ([ADR-0013](../../../docs/adr/0013-sandbox-lanes-so-a-firewall-rule-can-name-the-container.md)),
so eight rules, written once, cover every sandbox run.

**It never elevates itself.** Run unelevated, it prints the plan and how to run it
from an administrator PowerShell, and changes nothing. Elevated, it prints the plan,
waits for the operator to type `yes`, records on the ledger, adds the rules, and
reads them back: the result is what the firewall says, not the exit code.

    sletchy install-rules            show the plan, then add the rules (administrator)
    sletchy install-rules --plan     show the plan; change nothing
    sletchy install-rules --check    is every rule there and as planned? (no administrator)
    sletchy install-rules --remove   take them all away again (administrator)

`sletchy stop` removes the whole group too, as administrator. Run unelevated it keeps
them, counts them and says so, without an error (#179): these rules only restrict
Sletchy's own sandboxes, so leaving them is never the unsafe direction.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sletchy.cli import panic as panic_mod
from sletchy.cli.paths import FIREWALL_GROUP
from sletchy.kernel.contracts import (
    SANDBOX_LANES,
    Decision,
    Plane,
    Subject,
    SubjectKind,
    Verdict,
)

if TYPE_CHECKING:
    from sletchy.kernel.ledger import Ledger

#: Every address but this machine's own, which is where the proxy listens.
NOT_THIS_MACHINE: tuple[str, ...] = (
    "0.0.0.0-126.255.255.255",
    "128.0.0.0-255.255.255.255",
    "::",
    "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
)

#: `INetFwRule` values, as the firewall reports them.
OUTBOUND = 2
BLOCK = 0
ANY_PROTOCOL = 256
#: Domain, private and public. `-Profile Any` may also read back as 0x7FFFFFFF.
ALL_PROFILES = 0x7

ACTOR = "operator"
SUBJECT = Subject(kind=SubjectKind.HOST, identifier=f"firewall group {FIREWALL_GROUP}")

EXIT_OK = 0
EXIT_NOT_DONE = 1

#: Read-only. Every rule in the group, through the documented COM API, which needs no
#: elevation where `Get-NetFirewallRule` does (ADR-0006 finding 4).
READ_RULES_SCRIPT = (
    "$out = foreach ($r in (New-Object -ComObject HNetCfg.FwPolicy2).Rules) "
    f"{{ if ($r.Grouping -eq '{FIREWALL_GROUP}') {{ [pscustomobject]@{{ "
    "name = $r.Name; direction = $r.Direction; action = $r.Action; "
    "protocol = $r.Protocol; remote = $r.RemoteAddresses; "
    "package = $r.LocalAppPackageId; enabled = $r.Enabled; profiles = $r.Profiles "
    "} } }; ConvertTo-Json -Compress -InputObject @($out)"
)


@dataclass(frozen=True)
class Rule:
    """One planned rule: block everything but this machine, for one lane's container."""

    lane: str
    sid: str

    @property
    def name(self) -> str:
        return f"{self.lane}: no direct network"

    def command(self) -> str:
        """The exact PowerShell line that adds it. Every value is checked or constant."""
        remote = ",".join(f"'{address}'" for address in NOT_THIS_MACHINE)
        return (
            f"New-NetFirewallRule -DisplayName '{self.name}' -Group '{FIREWALL_GROUP}' "
            "-Direction Outbound -Action Block -Protocol Any -Profile Any "
            f"-RemoteAddress {remote} -Package '{self.sid}' -Enabled True | Out-Null"
        )


@dataclass(frozen=True)
class Found:
    """One rule as the firewall reports it."""

    name: str
    direction: int
    action: int
    protocol: int
    remote: str
    package: str
    enabled: bool
    profiles: int


def plan(derive: Callable[[str], str] | None = None) -> tuple[Rule, ...]:
    """The rule set, from the lanes. Raises `OSError` if a SID cannot be derived."""
    derive = derive or panic_mod._call_derive_sid
    rules = []
    for lane in SANDBOX_LANES:
        sid = derive(lane)
        if not panic_mod.APPCONTAINER_SID.fullmatch(sid):
            msg = f"Windows gave {lane!r} the SID {sid!r}, which is not an AppContainer SID"
            raise OSError(msg)
        rules.append(Rule(lane=lane, sid=sid))
    return tuple(rules)


def script(rules: tuple[Rule, ...]) -> str:
    return "\n".join(["$ErrorActionPreference = 'Stop'", *(r.command() for r in rules)])


def render_plan(rules: tuple[Rule, ...]) -> list[str]:
    return [
        f"This adds {len(rules)} firewall rules, all in the group '{FIREWALL_GROUP}':",
        "",
        "  - each one BLOCKS outgoing connections, and allows nothing",
        "  - each applies only to a program running inside one of Sletchy's sandboxes",
        "    (one rule per sandbox lane, named by the lane's container SID)",
        "  - each covers every address except this computer's own (127.0.0.0/8 and ::1),",
        "    where Sletchy's proxy listens",
        "  - nothing else on this computer is affected: no other rule, program or setting",
        "",
        "The exact commands:",
        "",
        *(f"  {line}" for line in script(rules).splitlines()),
        "",
        "To undo: sletchy install-rules --remove (or sletchy stop), as administrator.",
    ]


# ── reading back ─────────────────────────────────────────────────────────────


def _intervals(remote: str) -> dict[int, list[tuple[int, int]]] | None:
    """The addresses a rule covers, as merged intervals per IP version, or None.

    Format-agnostic on purpose: the firewall may report a range we wrote as a subnet,
    or abbreviate it. A keyword such as `LocalSubnet` cannot be checked and makes
    the answer None.
    """
    spans: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
    for part in (piece.strip() for piece in remote.split(",")):
        try:
            if part == "*":
                spans[4].append((0, 2**32 - 1))
                spans[6].append((0, 2**128 - 1))
            elif "-" in part:
                low, high = (ipaddress.ip_address(x) for x in part.split("-", 1))
                if low.version != high.version or int(low) > int(high):
                    return None
                spans[low.version].append((int(low), int(high)))
            elif "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                spans[net.version].append((int(net[0]), int(net[-1])))
            else:
                one = ipaddress.ip_address(part)
                spans[one.version].append((int(one), int(one)))
        except ValueError:
            return None
    merged: dict[int, list[tuple[int, int]]] = {}
    for version, items in spans.items():
        out: list[tuple[int, int]] = []
        for start, end in sorted(items):
            if out and start <= out[-1][1] + 1:
                out[-1] = (out[-1][0], max(out[-1][1], end))
            else:
                out.append((start, end))
        merged[version] = out
    return merged


EXPECTED_COVERAGE = _intervals(",".join(NOT_THIS_MACHINE))


def read_rules(run: Callable[[str], subprocess.CompletedProcess[str]] | None = None) -> list[Found]:
    """Every rule in the group, read-only. Raises `OSError` when it cannot look."""
    run = run or (lambda text: panic_mod._powershell(text, timeout=60))
    try:
        result = run(READ_RULES_SCRIPT)
    except subprocess.SubprocessError as exc:
        raise OSError(f"firewall query did not finish: {type(exc).__name__}") from exc
    if result.returncode != 0:
        msg = f"firewall query failed (exit {result.returncode}): {panic_mod._first_line(result)}"
        raise OSError(msg)
    try:
        raw = json.loads(result.stdout or "")
        items = raw if isinstance(raw, list) else [raw]
        return [
            Found(
                name=str(item.get("name") or ""),
                direction=int(item.get("direction") or 0),
                action=item["action"] if isinstance(item.get("action"), int) else -1,
                protocol=int(item.get("protocol") or 0),
                remote=str(item.get("remote") or ""),
                package=str(item.get("package") or ""),
                enabled=item.get("enabled") is True,
                profiles=int(item.get("profiles") or 0),
            )
            for item in items
            if isinstance(item, dict)
        ]
    except (ValueError, TypeError, AttributeError) as exc:
        raise OSError(f"firewall query returned something unreadable: {exc}") from exc


def _wrong(rule: Rule, found: Found) -> list[str]:
    problems = []
    if found.direction != OUTBOUND:
        problems.append("not outbound")
    if found.action != BLOCK:
        problems.append("does not block")
    if found.protocol != ANY_PROTOCOL:
        problems.append("not every protocol")
    if not found.enabled:
        problems.append("switched off")
    if found.profiles & ALL_PROFILES != ALL_PROFILES:
        problems.append("not on every network profile")
    if found.package != rule.sid:
        problems.append("names another container")
    if _intervals(found.remote) != EXPECTED_COVERAGE:
        problems.append(f"covers other addresses ({found.remote[:80]})")
    return problems


def check(rules: tuple[Rule, ...], found: list[Found]) -> list[str]:
    """Every way the group differs from the plan. Empty means exactly as planned."""
    problems: list[str] = []
    by_package: dict[str, list[Found]] = {}
    for item in found:
        by_package.setdefault(item.package, []).append(item)
    expected = {r.sid for r in rules}
    for rule in rules:
        mine = by_package.get(rule.sid, [])
        if not mine:
            problems.append(f"{rule.lane}: missing")
        elif len(mine) > 1:
            problems.append(f"{rule.lane}: {len(mine)} rules where there should be one")
        else:
            problems += [f"{rule.lane}: {p}" for p in _wrong(rule, mine[0])]
    strangers = [f for f in found if f.package not in expected]
    if strangers:
        problems.append(
            f"{len(strangers)} rule(s) in group '{FIREWALL_GROUP}' that are not in this plan"
        )
    return problems


# ── the command ──────────────────────────────────────────────────────────────


def _is_elevated() -> bool:
    """A question, never a request: Sletchy asks for no elevation (LAW 0 §3)."""
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _say_how_to_elevate(out: Callable[[str], None]) -> None:
    out("")
    out("Adding or removing firewall rules needs an administrator. Sletchy never asks")
    out("Windows for that itself. To go ahead: open PowerShell as administrator, go to")
    out("this folder, and run the same command there. Nothing was changed.")


def run(
    args: object,
    ledger: Ledger | None,
    *,
    derive: Callable[[str], str] | None = None,
    powershell: Callable[[str], subprocess.CompletedProcess[str]] | None = None,
    elevated: Callable[[], bool] = _is_elevated,
    ask: Callable[[str], str] = input,
    out: Callable[[str], None] = print,
) -> int:
    """One `sletchy install-rules`, with every host call behind a seam for the tests."""
    if not panic_mod._is_windows():
        out("There is no Windows Firewall here, so there is nothing to install.")
        return EXIT_NOT_DONE
    shell = powershell or (lambda text: panic_mod._powershell(text, timeout=120))
    rules = plan(derive)

    if getattr(args, "check", False):
        return _check(rules, shell, out)
    if getattr(args, "remove", False):
        return _remove(ledger, shell, elevated, ask, out)

    for line in render_plan(rules):
        out(line)
    if getattr(args, "plan", False):
        return EXIT_OK
    if not elevated():
        _say_how_to_elevate(out)
        return EXIT_NOT_DONE
    if ledger is None:
        out("")
        out("There is no Sletchy here to record this on (sletchy init). Nothing was changed.")
        return EXIT_NOT_DONE

    present = read_rules(shell)
    if present:
        if not check(rules, present):
            out("")
            out("They are already installed, exactly as planned. Nothing was changed.")
            return EXIT_OK
        out("")
        out(f"The group '{FIREWALL_GROUP}' already holds {len(present)} rule(s) that are not")
        out("this plan. Remove them first (sletchy install-rules --remove). Nothing was changed.")
        return EXIT_NOT_DONE

    out("")
    if ask(f"Type yes to add these {len(rules)} rules: ").strip().lower() != "yes":
        out("Nothing was changed.")
        return EXIT_NOT_DONE

    # On the record before the firewall changes (LAW 1).
    ledger.append(
        plane=Plane.WARDEN,
        actor_id=ACTOR,
        action="warden.firewall.install",
        subject=SUBJECT,
        verdict=Verdict(
            decision=Decision.ALLOW,
            reason=(
                f"the operator confirmed adding {len(rules)} outbound block rules, one per "
                "sandbox lane, each covering every address but this machine's"
            ),
        ),
    )
    try:
        result = shell(script(rules))
        detail = "" if result.returncode == 0 else panic_mod._first_line(result)
    except subprocess.SubprocessError as exc:
        detail = f"did not finish: {type(exc).__name__}"
    return _record_check(rules, ledger, shell, out, detail)


def _check(
    rules: tuple[Rule, ...],
    shell: Callable[[str], subprocess.CompletedProcess[str]],
    out: Callable[[str], None],
) -> int:
    try:
        present = read_rules(shell)
    except OSError as exc:
        out(f"Could not read the firewall: {exc}")
        return EXIT_NOT_DONE
    problems = check(rules, present)
    if not present:
        out("No Sletchy firewall rules are installed. A sandbox is kept off other machines")
        out("by its container alone (ADR-0006 finding 5): sletchy install-rules adds the")
        out("second lock.")
        return EXIT_NOT_DONE
    if problems:
        out(f"The rules are not as planned ({len(problems)}):")
        for problem in problems:
            out(f"  - {problem}")
        return EXIT_NOT_DONE
    out(f"All {len(rules)} rules are installed, exactly as planned.")
    return EXIT_OK


def _record_check(
    rules: tuple[Rule, ...],
    ledger: Ledger,
    shell: Callable[[str], subprocess.CompletedProcess[str]],
    out: Callable[[str], None],
    detail: str,
) -> int:
    """Read the rules back and put what the firewall says on the record."""
    try:
        problems = check(rules, read_rules(shell))
    except OSError as exc:
        problems = [f"could not read them back: {exc}"]
    if detail:
        problems.insert(0, f"PowerShell said: {detail}")
    reason = (
        f"read back: all {len(rules)} rules present and as planned"
        if not problems
        else "read back: " + "; ".join(problems)
    )
    ledger.append(
        plane=Plane.WARDEN,
        actor_id=ACTOR,
        action="warden.firewall.check",
        subject=SUBJECT,
        verdict=Verdict(
            decision=Decision.ALLOW if not problems else Decision.DENY, reason=reason[:512]
        ),
    )
    out("")
    if problems:
        out("The rules are NOT as planned:")
        for problem in problems:
            out(f"  - {problem}")
        out("sletchy install-rules --remove takes away whatever was added.")
        return EXIT_NOT_DONE
    out(f"Done. All {len(rules)} rules are installed, exactly as planned, and on the record.")
    return EXIT_OK


def _remove(
    ledger: Ledger | None,
    shell: Callable[[str], subprocess.CompletedProcess[str]],
    elevated: Callable[[], bool],
    ask: Callable[[str], str],
    out: Callable[[str], None],
) -> int:
    try:
        present = read_rules(shell)
    except OSError as exc:
        out(f"Could not read the firewall: {exc}")
        return EXIT_NOT_DONE
    if not present:
        out(f"The group '{FIREWALL_GROUP}' holds no rules. Nothing to remove.")
        return EXIT_OK
    out(f"This removes all {len(present)} rule(s) in the group '{FIREWALL_GROUP}', and nothing")
    out("else. The exact command:")
    out("")
    out(f"  {panic_mod.REMOVE_RULES_SCRIPT}")
    if not elevated():
        _say_how_to_elevate(out)
        return EXIT_NOT_DONE
    if ledger is None:
        out("")
        out("There is no Sletchy here to record this on (sletchy init). Nothing was changed.")
        return EXIT_NOT_DONE
    out("")
    if ask(f"Type yes to remove these {len(present)} rules: ").strip().lower() != "yes":
        out("Nothing was changed.")
        return EXIT_NOT_DONE
    ledger.append(
        plane=Plane.WARDEN,
        actor_id=ACTOR,
        action="warden.firewall.remove",
        subject=SUBJECT,
        verdict=Verdict(
            decision=Decision.ALLOW,
            reason=f"the operator confirmed removing all {len(present)} rules in the group",
        ),
    )
    removed, _kept, error = panic_mod.remove_firewall_rules()
    out("")
    if error:
        out(f"Removed {removed}; {error}")
        return EXIT_NOT_DONE
    out(f"Removed {removed}. The group '{FIREWALL_GROUP}' is empty.")
    return EXIT_OK
