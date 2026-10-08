#!/usr/bin/env python3
"""SPIKE probe: what keeps a sandbox off the network, with and without the rules (#71, #33).

Throwaway, like `egress_probe.py` (phase 1) before it. It produces findings for
ADR-0006 and ADR-0013, not product code. **The operator chose option B on #71
(2026-10-04)**: connection attempts only to addresses reserved for documentation and
never routed, `192.0.2.1` (RFC 5737) and `2001:db8::1` (RFC 3849).

## Two rounds, the same rows

Run it once with no Sletchy firewall rules, then again after `sletchy install-rules`
in an administrator PowerShell. It reads the rules itself, read-only, and says which
round it is measuring. A half-installed set stops it.

| | What | Expected |
|---|---|---|
| C1 | `curl --version`, contained | runs (control: curl starts in the container) |
| C3 | read a file outside the workspace, contained | fails (control: the container is applied) |
| L | HTTP to a listener on `127.0.0.1`, contained | **succeeds**: the proxy's path, with or without the rules |
| TU | TCP to 192.0.2.1, **un**contained | times out (control: nothing local refuses it) |
| T | TCP to 192.0.2.1, contained | refused at once (ADR-0006 finding 5) |
| DU | UDP to 192.0.2.1 (TFTP), **un**contained | times out (control) |
| D | UDP to 192.0.2.1 (TFTP), contained | times out either way (see below) |
| 6U | TCP to [2001:db8::1], **un**contained | times out, or fails at once with no IPv6 route |
| 6 | TCP to [2001:db8::1], contained | unreadable without an IPv6 route |
| C4 | `curl --version`, in the probe's own container, with `internetClient` | runs (control: the probe's launcher works) |
| OT | TCP to 192.0.2.1, a container **no rule names**, with `internetClient` | times out (control: the capability opens the container's own lock) |
| RT | TCP to 192.0.2.1, **a lane**, with `internetClient` | **refused at once if the rule binds**; times out with no rules |
| OD | UDP to 192.0.2.1, a container no rule names, with `internetClient` | times out (control) |
| RD | UDP to 192.0.2.1, a lane, with `internetClient` | the rule's answer for UDP, if curl can show it |

## Why the last five rows exist

Rounds 1 and 2 on 2026-10-04 printed the same table (ADR-0006 finding 7). None of the
first nine rows can see a rule. TCP is refused by the container's own lock before a
rule is consulted. A dropped datagram and an unanswered one both time out. Without an
IPv6 route nothing reaches the firewall at all. **A second lock cannot be seen while
the first one holds.**

So the last rows open the first lock. `internetClient` is the capability Windows'
container isolation checks; with it, the container lets an outbound connection
through and only a rule is left to stop it. Two containers get it: a lane, whose SID
a rule names, and one with a fresh name no rule names, which is the control. With the
rules installed, the lane refused at once while the control timed out means the rule
binds. With no rules, both time out.

`winjob` never grants a capability, so these rows are launched by this probe, from
`winjob`'s own pieces (lane, profile, job, restricted token) with the capability
added. They are not on any ledger.

curl runs with `-v`, and its own lines are printed under each attempt: an exit code
alone cannot say why a connection failed, and for UDP the only sign of a refusal may
be a send error curl reports and then waits past.

## Safety

- **Refuses to run elevated**: the result would not describe how Sletchy runs. The
  rules are added by `sletchy install-rules`, separately, by the operator
- **Nothing is sent until the operator types `yes`.** Then at most ten attempts, all to
  the two documentation addresses, each stopped after 5 seconds
- `internetClient` is given only to the probe's own two containers, for one curl
  each, and goes with them. Nothing on the machine is changed by it
- The loopback listener is this script's own, on `127.0.0.1` and a random port
- Its ledger and workspace live in a temp directory, never the real `var/`

`--plan` prints the rows and the rules' state, and sends nothing.
"""

from __future__ import annotations

import contextlib
import ctypes
import http.server
import os
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
CURL = SYSTEM32 / "curl.exe"
TARGET4 = "192.0.2.1"  # RFC 5737 TEST-NET-1: reserved for documentation, never routed
TARGET6 = "2001:db8::1"  # RFC 3849: reserved for documentation, never routed

CURL_OK = 0
CURL_TIMEOUT = 28
QUICK = 2.0  # seconds; a refusal is well under this, a timeout is the full five

#: The well-known SID of the `internetClient` capability.
INTERNET_CLIENT = "S-1-15-3-1"
SE_GROUP_ENABLED = 0x00000004

#: curl's own lines that say nothing about why an attempt ended.
NOISE = ("Trying", "set timeouts", "Closing connection", "using HTTP", "Request completely")
#: Words in a curl line that mean the system refused something.
REFUSAL_WORDS = ("denied", "forbidden", "permission", "not permitted", "access")


def refuse_if_elevated() -> None:
    if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        sys.exit("refusing to run elevated: the result would not describe how Sletchy runs")


def rules_state() -> str:
    """'none', 'installed', or why the set is neither. Read-only."""
    from sletchy.cli import rules

    found = rules.read_rules()
    if not found:
        return "none"
    problems = rules.check(rules.plan(), found)
    return "installed" if not problems else "; ".join(problems)


class Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args: object) -> None:
        return


# ── the probe's own launcher, for the capability rows ──────────────────────────


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = (("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_ulong))


@contextlib.contextmanager
def internet_client(win32: ModuleType) -> Iterator[None]:
    """`win32.spawn` with `internetClient` added, for the length of one launch.

    `spawn` builds its `SECURITY_CAPABILITIES` with none. Swapping the structure for
    one that fills in a single capability changes nothing else about the launch: the
    same attribute list, job, token and container.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(INTERNET_CLIENT, ctypes.byref(sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    entries = (SID_AND_ATTRIBUTES * 1)(SID_AND_ATTRIBUTES(sid.value, SE_GROUP_ENABLED))
    original = win32.SECURITY_CAPABILITIES

    class WithInternetClient(original):  # type: ignore[misc, valid-type]
        def __init__(self, **fields: object) -> None:
            fields |= {"Capabilities": ctypes.addressof(entries), "CapabilityCount": 1}
            super().__init__(**fields)

    win32.SECURITY_CAPABILITIES = WithInternetClient
    try:
        yield
    finally:
        win32.SECURITY_CAPABILITIES = original
        kernel32.LocalFree(sid)


def launch_open(
    win32: ModuleType, name: str, command: list[str], env: dict[str, str], capture: Path
) -> int | None:
    """Run `command` in a container named `name`, with `internetClient`. Leaves nothing.

    Raises `win32.ProfileExists` when `name` already has a profile.
    """
    profile = job = token = None
    try:
        profile = win32.AppContainerProfile(name, win32.new_context_id())
        job = win32.JobObject()
        job.apply(memory_mb=512, cpu_percent=50, max_processes=4)
        token = win32.restricted_token()
        with capture.open("wb") as sink, internet_client(win32):
            launched = win32.spawn(
                win32.command_line(command),
                sid=profile.sid,
                job=job,
                token=token,
                cwd=str(SYSTEM32),
                env=env,
                stdout_handle=win32.inheritable_handle(sink),
            )
        try:
            return launched.exit_code() if launched.wait(20) else None
        finally:
            launched.close()
    finally:
        if job is not None:
            job.terminate()
            job.close()
        if token is not None:
            win32.close_handle(token)
        if profile is not None:
            profile.close()


def launch_in_lane(
    win32: ModuleType, command: list[str], env: dict[str, str], capture: Path
) -> int | None:
    """`launch_open` in the first free lane, so a rule names the container's SID."""
    from sletchy.kernel.contracts import SANDBOX_LANES

    for name in SANDBOX_LANES:
        lane = win32.Lane(name)
        if not lane.take():
            continue
        try:
            return launch_open(win32, name, command, env, capture)
        except win32.ProfileExists:
            continue  # left behind by an earlier run; another lane will do
        finally:
            lane.release()
    sys.exit("no sandbox lane is free: nothing below could be measured")


# ── reading curl ───────────────────────────────────────────────────────────────


def curl_lines(text: str) -> list[str]:
    """curl's own `-v` lines about the attempt, without the noise."""
    kept = []
    for line in text.splitlines():
        line = line.strip()
        if not (line.startswith("* ") or line.startswith("curl: (")):
            continue
        if any(word in line for word in NOISE):
            continue
        kept.append(line[:110])
    return kept[:6]


def main() -> int:
    if sys.platform != "win32":
        sys.exit("windows only")
    refuse_if_elevated()

    state = rules_state()
    print(f"Sletchy firewall rules: {state}")
    if state not in ("none", "installed"):
        print("A partial or unexpected rule set. `sletchy install-rules --check` says what is")
        print("wrong. Stopping: this measures no rules, or the whole set.")
        return 1
    installed = state == "installed"
    round_name = "with the rules" if installed else "no rules"
    print(f"This round: {round_name}.")
    if "--plan" in sys.argv:
        print("\n--plan: nothing was sent, created or changed.")
        return 0
    if not CURL.is_file():
        sys.exit(f"no curl at {CURL}")

    answer = input(
        f"\nThis sends at most ten attempts, to {TARGET4} and {TARGET6} only. Type yes: "
    )
    if answer.strip().lower() != "yes":
        print("Nothing was sent.")
        return 0

    from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
    from sletchy.kernel.ledger import InMemoryKeySource, Ledger
    from sletchy.kernel.paths import ENV_HOME, ledger_dir
    from sletchy.warden.isolation import SandboxRecorder, SubprocSandbox, WinJobSandbox
    from sletchy.warden.isolation import _win32 as win32

    curl = [str(CURL), "-sS", "-v", "--max-time", "5"]
    results: dict[str, tuple[int | None, float]] = {}
    said: dict[str, list[str]] = {}

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        os.environ[ENV_HOME] = str(root / "home")
        os.environ["SLETCHY_ALLOW_INMEMORY_KEY"] = "1"
        workspace = root / "workspace"
        workspace.mkdir()
        outside = root / "outside.txt"
        outside.write_text("denied", encoding="utf-8")
        capture = root / "open.out"

        ledger = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
        recorder = SandboxRecorder(ledger=ledger, actor_id="egress_spike")
        profile = IsolationProfile.model_validate({"backend": IsolationBackend.WINJOB})
        contained = WinJobSandbox(workspace, profile, recorder=recorder)
        uncontained = SubprocSandbox(workspace, profile, recorder=recorder)
        env = contained._environment([str(CURL)], None)

        def run(tag: str, sandbox: object, command: list[str]) -> None:
            start = time.monotonic()
            result = sandbox.run(command, timeout=20)  # type: ignore[attr-defined]
            results[tag] = (result.exit_code, time.monotonic() - start)
            said[tag] = curl_lines((result.stdout or "") + (result.stderr or ""))

        def run_open(tag: str, command: list[str], *, lane: bool) -> None:
            start = time.monotonic()
            if lane:
                code = launch_in_lane(win32, command, env, capture)
            else:
                name = f"Sletchy-probe-{win32.new_context_id()}"
                code = launch_open(win32, name, command, env, capture)
            results[tag] = (code, time.monotonic() - start)
            text = capture.read_bytes().decode("utf-8", errors="replace")
            said[tag] = curl_lines(text) if "--version" not in command else text.splitlines()[:1]

        run("C1", contained, [str(CURL), "--version"])
        run("C3", contained, [os.environ["COMSPEC"], "/c", "type", str(outside)])
        run("L", contained, [*curl, f"http://127.0.0.1:{port}/"])
        run("TU", uncontained, [*curl, f"http://{TARGET4}/"])
        run("T", contained, [*curl, f"http://{TARGET4}/"])
        run("DU", uncontained, [*curl, f"tftp://{TARGET4}/x"])
        run("D", contained, [*curl, f"tftp://{TARGET4}/x"])
        run("6U", uncontained, [*curl, f"http://[{TARGET6}]/"])
        run("6", contained, [*curl, f"http://[{TARGET6}]/"])
        run_open("C4", [str(CURL), "--version"], lane=False)
        run_open("OT", [*curl, f"http://{TARGET4}/"], lane=False)
        run_open("RT", [*curl, f"http://{TARGET4}/"], lane=True)
        run_open("OD", [*curl, f"tftp://{TARGET4}/x"], lane=False)
        run_open("RD", [*curl, f"tftp://{TARGET4}/x"], lane=True)
    server.shutdown()

    print(f"\n--- {round_name} " + "-" * 56)
    for tag, (code, seconds) in results.items():
        print(f"{tag:3} exit={code!s:>5}  {seconds:5.1f}s")
        for line in said.get(tag, []):
            print(f"      {line}")
    print("-" * 72)
    print(f"Sletchy firewall rules afterwards: {rules_state()}")

    if results["C1"][0] != CURL_OK or results["C3"][0] == 0:
        print("\nCONTROLS FAILED: curl did not run contained, or the container was not applied.")
        print("Nothing below is a finding.")
        return 1

    def refused(tag: str) -> bool:
        code, seconds = results[tag]
        return code not in (CURL_OK, CURL_TIMEOUT) and seconds < QUICK

    def timed_out(tag: str) -> bool:
        return results[tag][0] == CURL_TIMEOUT

    def send_error(tag: str) -> str:
        """A line in which curl reported the system refusing something, or ''."""
        return next(
            (line for line in said[tag] if any(w in line.lower() for w in REFUSAL_WORDS)), ""
        )

    def udp(measured: str) -> str:
        if refused(measured):
            return "REFUSED at once"
        if not timed_out(measured):
            return "inconclusive. Record the table as it is"
        error = send_error(measured)
        if error:
            return f"timed out, but curl reported a refusal first: {error}"
        return "timed out with no error. A dropped datagram and an unanswered one look the same"

    print()
    print(
        "L    loopback: REACHED (the proxy's path is open)"
        if results["L"][0] == CURL_OK
        else "L    loopback: NOT reached. With the rules, that would block the proxy: record it"
    )

    print("\nThe container's own lock (rows T, D, 6):")
    if not timed_out("TU"):
        print("  TCP: the uncontained control did not time out, so this row cannot be read")
    elif refused("T"):
        print("  TCP: REFUSED at once, by the container or a rule: this row cannot tell which")
    else:
        print("  TCP: NOT refused. Record the table as it is")
    if not timed_out("DU"):
        print("  UDP: the uncontained control did not time out, so this row cannot be read")
    else:
        print(f"  UDP: {udp('D')}")
    if not timed_out("6U"):
        print("  IPv6: the uncontained control did not time out (no IPv6 route?): unreadable")
    elif refused("6"):
        print("  IPv6: REFUSED at once")
    else:
        print("  IPv6: NOT refused. Record the table as it is")

    print("\nThe rule, with the container's lock opened (rows OT, RT, OD, RD):")
    if results["C4"][0] != CURL_OK:
        print("  the probe's own launcher did not run curl: these rows cannot be read")
        return 1
    if not timed_out("OT"):
        print("  the capability did not open the container (OT): these rows cannot be read")
        return 1
    if refused("RT"):
        print(
            "  TCP: the rule BINDS. The lane was refused at once; the container no rule names was not"
            if installed
            else "  TCP: a lane was refused with no rules installed. Something else refuses it: record"
        )
    elif timed_out("RT"):
        print(
            "  TCP: the rule does NOT bind. The lane's attempt went out like the control's"
            if installed
            else "  TCP: with no rules, the lane is not refused either (the control for the next round)"
        )
    else:
        print("  TCP: inconclusive. Record the table as it is")
    if not timed_out("OD"):
        print("  UDP: the control did not time out, so this row cannot be read")
    else:
        print(f"  UDP: {udp('RD')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
