#!/usr/bin/env python3
"""SPIKE probe: does an AppContainer actually deny the network? (#71, phase 1)

Throwaway, like `appcontainer_probe.py` before it. It exists to produce findings,
not to become product code.

## What phase 1 answers

Only this: **can a process launched by `winjob` open a TCP connection to a listener
running on this machine?** Nothing here touches the firewall, and nothing here runs
elevated. Phases 2 and 3 - creating a rule scoped to the container SID and measuring
whether it binds - are a separate, elevated run that has to be asked for.

## Why three measurements and not one

A single "the contained curl failed to connect" proves almost nothing. It is equally
consistent with the binary never starting, the listener never listening, or the
environment being too stripped for winsock to initialise. So:

- **C1** - `curl --version` inside the container. Proves the binary runs *contained*.
- **C2** - the real request, **un**contained. Proves the listener is reachable.
- **M1** - the real request, contained. The measurement.

M1 only means something when C1 and C2 both pass. This is the positive-control rule
from ADR-0005 §4, which cost three probe runs there and one containment assertion in
the `winjob` work.

## Safety

- **Loopback only.** Binding a non-loopback address can raise a Windows Firewall
  notification on the operator's desktop; that belongs in a phase that is asked for.
- **Refuses to run elevated** - an elevated result would not describe how Sletchy runs.
- Its ledger and workspace live in a temp directory, never the real `var/`.
- LAW 0 section 6: the only endpoint contacted is a listener this script starts.
"""

from __future__ import annotations

import ctypes
import http.server
import socket
import sys
import tempfile
import threading
from contextlib import closing
from pathlib import Path

CURL = Path(r"C:\Windows\System32\curl.exe")

#: curl's own exit codes, the three we can distinguish here.
CURL_OK = 0
CURL_COULD_NOT_CONNECT = 7
CURL_TIMEOUT = 28


def refuse_if_elevated() -> None:
    if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        sys.exit("refusing to run elevated: the result would not describe how Sletchy runs")


class _Quiet(http.server.BaseHTTPRequestHandler):
    """Answers anything with 204, and does not log to stderr."""

    def do_GET(self) -> None:
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_: object) -> None:
        return


def free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> int:
    if sys.platform != "win32":
        sys.exit("windows only")
    refuse_if_elevated()

    from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
    from sletchy.kernel.ledger import InMemoryKeySource, Ledger
    from sletchy.kernel.paths import ENV_HOME, ledger_dir
    from sletchy.warden.isolation import SandboxRecorder, SubprocSandbox, WinJobSandbox

    if not CURL.is_file():
        sys.exit(f"no curl at {CURL}; this build cannot be probed this way")

    port = free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"
    print(f"listener: {url}\n")

    request = [str(CURL), "-s", "--max-time", "3", url]
    version = [str(CURL), "--version"]

    # `ignore_cleanup_errors`: the ledger holds its append handle open for the life of
    # the object (the #29 batching change), so the temp tree cannot always be unlinked
    # on the way out. Irrelevant to a throwaway chain; it would matter to a caller that
    # expected `Ledger` to be closeable.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        import os

        os.environ[ENV_HOME] = str(root / "home")
        # Set deliberately, as the refusal message instructs. A throwaway chain in a
        # temp directory has nothing to protect; the keyring is for the real ledger.
        os.environ["SLETCHY_ALLOW_INMEMORY_KEY"] = "1"
        workspace = root / "workspace"
        workspace.mkdir()

        ledger = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
        recorder = SandboxRecorder(ledger=ledger, actor_id="egress_spike")
        profile = IsolationProfile.model_validate({"backend": IsolationBackend.WINJOB})

        contained = WinJobSandbox(workspace, profile, recorder=recorder)
        uncontained = SubprocSandbox(workspace, profile, recorder=recorder)

        # C3's target: a file outside the workspace, which the container must not read.
        # Without this, "the contained process reached the listener" is indistinguishable
        # from "the container was never applied".
        outside = root / "outside.txt"
        outside.write_text("denied", encoding="utf-8")
        read_outside = [os.environ["COMSPEC"], "/c", "type", str(outside)]

        try:
            c1 = contained.run(version, timeout=15)
            c2 = uncontained.run(request, timeout=15)
            c3 = contained.run(read_outside, timeout=15)
            m1 = contained.run(request, timeout=15)
        finally:
            server.shutdown()

    def line(tag: str, what: str, result: object) -> None:
        code = getattr(result, "exit_code", None)
        killed = getattr(result, "timed_out", False)
        print(f"{tag:4} {what:52} exit={code!s:>6}  timed_out={killed}")

    print("--- results " + "-" * 60)
    line("C1", "curl --version, CONTAINED (control: binary runs)", c1)
    line("C2", "curl to listener, UNCONTAINED (control: reachable)", c2)
    line("C3", "read a file outside workspace, CONTAINED (must FAIL)", c3)
    line("M1", "curl to listener, CONTAINED (the measurement)", m1)
    print("-" * 72)

    controls_ok = c1.exit_code == CURL_OK and c2.exit_code == CURL_OK and c3.exit_code != 0
    if not controls_ok:
        print("\nCONTROLS FAILED - M1 means nothing. Do not record a finding from this run.")
        if c1.exit_code != CURL_OK:
            print(f"  C1: curl did not run inside the container. stdout: {c1.stdout[:200]!r}")
        if c2.exit_code != CURL_OK:
            print(f"  C2: the listener was not reachable uncontained. stdout: {c2.stdout[:200]!r}")
        if c3.exit_code == 0:
            print("  C3: the container read a file outside its workspace - it was NOT applied.")
        return 1

    print("\nControls passed, so M1 is a real measurement.")
    if m1.exit_code == CURL_OK:
        print("FINDING: the contained process REACHED the loopback listener.")
    elif m1.exit_code in (CURL_COULD_NOT_CONNECT, CURL_TIMEOUT):
        print(f"FINDING: the contained process was DENIED (curl exit {m1.exit_code}).")
    else:
        print(f"FINDING: inconclusive - curl exit {m1.exit_code}, stdout {m1.stdout[:200]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
