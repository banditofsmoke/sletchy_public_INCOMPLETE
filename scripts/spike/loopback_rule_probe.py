#!/usr/bin/env python3
"""SPIKE probe: can a firewall rule narrow a sandbox's loopback? (#184)

Throwaway, like the probes before it: it produces a finding, not product code. A
sandbox reaches every service on loopback (ADR-0006 finding 1). The proxy needs that,
but the model server is on loopback too, asks no password, and can be told to download
or delete a model (COVERAGE). If a rule naming a lane can refuse that lane one loopback
port and leave the others, a sandbox can be narrowed to its proxy. The firewall is
believed not to filter loopback. This measures it.

    uv run python scripts/spike/loopback_rule_probe.py           # run the rows
    uv run python scripts/spike/loopback_rule_probe.py --plan    # say what; run nothing

## Three phases, the same rows

1. No spike rule: the probe, unelevated
2. The operator adds the spike's one rule in an administrator PowerShell, with the line
   `--plan` prints. The probe again, unelevated
3. The operator removes it, with the line `--plan` prints. The probe once more, and
   `sletchy install-rules --check`

The probe reads which phase it is in itself, read-only, and stops on anything else.

| | What | Expected |
|---|---|---|
| C1 | `curl --version`, contained in the lane | runs (control: curl starts in the container) |
| C3 | read a file outside the workspace, contained | fails (control: the container is applied) |
| LA | HTTP to listener A (a random port), contained | succeeds in every phase: the proxy's path |
| BU | HTTP to listener B (the rule's port), **un**contained | succeeds in every phase: B listens, and the rule names only the lane |
| LB | HTTP to listener B, contained | **the measurement**: refused at once with the rule means it binds on loopback |

## Safety

- **Refuses to run elevated**: the result would not describe how Sletchy runs, and the
  probe never changes a rule. The operator adds and removes the spike's rule
- The rule is in its own group, `Sletchy loopback spike`, so `sletchy install-rules
  --check` and Stop everything never count it, and one line removes it. It names one
  lane and one loopback port that nothing uses
- Both listeners are the probe's own, on `127.0.0.1`. Nothing is sent beyond this
  machine, so it asks no `yes`
- The lane's container profile is the probe's for one run and goes with it; its ledger
  and workspace live in a temporary folder, never the real `var/`
"""

from __future__ import annotations

import ctypes
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import ModuleType

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
CURL = SYSTEM32 / "curl.exe"
CURL_OK = 0
CURL_COULD_NOT_CONNECT = 7
CURL_TIMEOUT = 28
QUICK = 2.0  # seconds; a refusal is well under this, a timeout is the full five

#: The lane the rule names, and the one loopback port it refuses. Checked free first.
LANE = "Sletchy-lane0"
PORT_B = 47613
GROUP = "Sletchy loopback spike"
RULE_NAME = f"{LANE}: no loopback port {PORT_B}"
REMOVE = f"Remove-NetFirewallRule -Group '{GROUP}'"

#: Read-only, through the COM API, which needs no elevation (ADR-0006 finding 4).
READ_SCRIPT = (
    "$out = foreach ($r in (New-Object -ComObject HNetCfg.FwPolicy2).Rules) "
    f"{{ if ($r.Grouping -eq '{GROUP}') {{ [pscustomobject]@{{ "
    "name = $r.Name; direction = $r.Direction; action = $r.Action; "
    "protocol = $r.Protocol; remote = $r.RemoteAddresses; ports = $r.RemotePorts; "
    "package = $r.LocalAppPackageId; enabled = $r.Enabled "
    "} } }; ConvertTo-Json -Compress -InputObject @($out)"
)
OUTBOUND, BLOCK, TCP = 2, 0, 6


def refuse_if_elevated() -> None:
    if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        sys.exit("refusing to run elevated: the result would not describe how Sletchy runs")


def lane_sid() -> str:
    from sletchy.cli import panic as panic_mod

    sid = panic_mod._call_derive_sid(LANE)
    if not panic_mod.APPCONTAINER_SID.fullmatch(sid):
        sys.exit(f"Windows gave {LANE} the SID {sid!r}, which is not an AppContainer SID")
    return sid


def add_line(sid: str) -> str:
    return (
        f"New-NetFirewallRule -DisplayName '{RULE_NAME}' -Group '{GROUP}' "
        "-Direction Outbound -Action Block -Protocol TCP -Profile Any "
        f"-RemoteAddress 127.0.0.1 -RemotePort {PORT_B} -Package '{sid}' -Enabled True"
    )


def phase(sid: str) -> str:
    """'no rule', 'with the rule', or why the spike group is neither. Read-only."""
    from sletchy.cli import panic as panic_mod

    result = panic_mod._powershell(READ_SCRIPT, timeout=60)
    if result.returncode != 0:
        sys.exit(f"could not read the firewall (exit {result.returncode})")
    raw = json.loads(result.stdout or "[]")
    found = [r for r in (raw if isinstance(raw, list) else [raw]) if isinstance(r, dict)]
    if not found:
        return "no rule"
    if len(found) > 1:
        return f"{len(found)} rules in group '{GROUP}', where the spike adds one"
    rule = found[0]
    expected = {
        "direction": OUTBOUND,
        "action": BLOCK,
        "protocol": TCP,
        "ports": str(PORT_B),
        "package": sid,
        "enabled": True,
    }
    wrong = [k for k, v in expected.items() if rule.get(k) != v]
    if not str(rule.get("remote") or "").startswith("127.0.0.1"):
        wrong.append("remote")
    return "with the rule" if not wrong else f"the spike rule differs: {', '.join(wrong)}"


class Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args: object) -> None:
        return


def listen(port: int) -> http.server.ThreadingHTTPServer:
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Quiet)
    except OSError as exc:
        sys.exit(f"cannot listen on 127.0.0.1:{port} ({exc.strerror}); nothing was measured")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def launch_in_lane(
    win32: ModuleType, command: list[str], env: dict[str, str], capture: Path
) -> int | None:
    """Run `command` contained in `LANE`, with no capability, as `winjob` does. Leaves nothing."""
    lane = win32.Lane(LANE)
    if not lane.take():
        sys.exit(f"{LANE} is in use: let any running sandbox finish, then run this again")
    profile = job = token = None
    try:
        profile = win32.AppContainerProfile(LANE, win32.new_context_id())
        job = win32.JobObject()
        job.apply(memory_mb=512, cpu_percent=50, max_processes=4)
        token = win32.restricted_token()
        with capture.open("wb") as sink:
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
    except win32.ProfileExists:
        sys.exit(f"{LANE} has a container profile left behind; nothing was measured")
    finally:
        if job is not None:
            job.terminate()
            job.close()
        if token is not None:
            win32.close_handle(token)
        if profile is not None:
            profile.close()
        lane.release()


def main() -> int:
    if sys.platform != "win32":
        sys.exit("windows only")
    refuse_if_elevated()
    sid = lane_sid()
    now = phase(sid)
    print(f"{LANE} is {sid}")
    print(f"The spike's rule: {now}")
    if now not in ("no rule", "with the rule"):
        print(f"Stopping. To remove the group, in an administrator PowerShell:\n  {REMOVE}")
        return 1
    if "--plan" in sys.argv:
        print("\nTo add the spike's one rule, in an administrator PowerShell:")
        print(f"  {add_line(sid)}")
        print(f"To remove it again:\n  {REMOVE}")
        print("\n--plan: nothing was sent, created or changed.")
        return 0
    if not CURL.is_file():
        sys.exit(f"no curl at {CURL}")

    from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
    from sletchy.kernel.ledger import InMemoryKeySource, Ledger
    from sletchy.kernel.paths import ENV_HOME, ledger_dir
    from sletchy.warden.isolation import SandboxRecorder, WinJobSandbox
    from sletchy.warden.isolation import _win32 as win32

    curl = [str(CURL), "-sS", "--max-time", "5"]
    results: dict[str, tuple[int | None, float]] = {}
    server_a = listen(0)
    server_b = listen(PORT_B)
    url_a = f"http://127.0.0.1:{server_a.server_address[1]}/"
    url_b = f"http://127.0.0.1:{PORT_B}/"

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        os.environ[ENV_HOME] = str(root / "home")
        os.environ["SLETCHY_ALLOW_INMEMORY_KEY"] = "1"
        workspace = root / "workspace"
        workspace.mkdir()
        outside = root / "outside.txt"
        outside.write_text("denied", encoding="utf-8")
        capture = root / "lane.out"

        ledger = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
        recorder = SandboxRecorder(ledger=ledger, actor_id="loopback_spike")
        profile = IsolationProfile.model_validate({"backend": IsolationBackend.WINJOB})
        env = WinJobSandbox(workspace, profile, recorder=recorder)._environment([str(CURL)], None)

        def contained(tag: str, command: list[str]) -> None:
            start = time.monotonic()
            results[tag] = (launch_in_lane(win32, command, env, capture), time.monotonic() - start)

        def uncontained(tag: str, command: list[str]) -> None:
            start = time.monotonic()
            done = subprocess.run(command, capture_output=True, timeout=20, check=False)  # noqa: S603
            results[tag] = (done.returncode, time.monotonic() - start)

        contained("C1", [str(CURL), "--version"])
        contained("C3", [os.environ["COMSPEC"], "/c", "type", str(outside)])
        contained("LA", [*curl, url_a])
        uncontained("BU", [*curl, url_b])
        contained("LB", [*curl, url_b])
        ledger.close()
    server_a.shutdown()
    server_b.shutdown()

    print(f"\n--- {now} " + "-" * 60)
    for tag, (code, seconds) in results.items():
        print(f"{tag:3} exit={code!s:>5}  {seconds:5.1f}s")
    print("-" * 72)
    print(f"The spike's rule afterwards: {phase(sid)}")

    controls = (
        results["C1"][0] == CURL_OK
        and results["C3"][0] not in (0, None)
        and results["LA"][0] == CURL_OK
        and results["BU"][0] == CURL_OK
    )
    if not controls:
        print("\nCONTROLS FAILED: C1 and LA must run, C3 must fail and BU must reach B.")
        print("Nothing below is a finding. Record the table as it is.")
        return 1
    code, seconds = results["LB"]
    refused = code == CURL_COULD_NOT_CONNECT and seconds < QUICK
    if now == "no rule":
        print(
            "\nLB: REACHED. Loopback is open to the lane, as finding 1 says."
            if code == CURL_OK
            else "\nLB: NOT reached with no rule. Something else refuses it: record the table."
        )
        print(f"\nNext, in an administrator PowerShell:\n  {add_line(sid)}\nthen run this again.")
    else:
        if refused:
            print(
                "\nLB: REFUSED at once. The rule BINDS on loopback, and LA shows the rest stays open."
            )
        elif code == CURL_TIMEOUT:
            print(
                "\nLB: dropped silently while BU reached the same port: the rule BINDS on loopback."
            )
        elif code == CURL_OK:
            print("\nLB: REACHED. The rule does NOT bind on loopback.")
        else:
            print("\nLB: neither reached nor refused at once: inconclusive. Record the table.")
        print(f"\nNow remove it, in an administrator PowerShell:\n  {REMOVE}\nthen run this again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
