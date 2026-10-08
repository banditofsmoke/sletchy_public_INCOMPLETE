#!/usr/bin/env python3
"""SPIKE probe: can a server inside a Sletchy sandbox be reached on loopback? (#175)

Throwaway, like the probes before it: it produces a finding, not product code. Step 2
of ADR-0017 runs the model server inside a `winjob` sandbox, so the model cannot touch
the operator's files or the network, and Sletchy asks it through the local door. That
only works if a contained process can listen on `127.0.0.1` and an uncontained one can
connect to it. Outward, a container reaches loopback (ADR-0006 finding 1). Inward is
unmeasured.

**Nothing new is installed and nothing leaves the machine.** The server binds
`127.0.0.1` only, for a few seconds, which raises no firewall prompt: Windows asks only
for listeners on other interfaces. The server runs under a copy of this Python inside
the workspace, as the GPU probe's did (ADR-0015).

    uv run python scripts/spike/loopback_server_probe.py           # run the rows
    uv run python scripts/spike/loopback_server_probe.py --plan    # say what; run nothing

| | What | Control |
|---|---|---|
| C3 | read a file outside the workspace, contained | must be refused |
| S0 | a loopback server, **un**contained; a client here connects | must answer |
| S1 | the same server, contained; a client here connects | the measurement, in a process that must itself be refused the file outside |
"""

from __future__ import annotations

import ctypes
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

#: Run by the copied Python, inside or outside the sandbox: the containment check,
#: then one request served on 127.0.0.1, or a timeout.
SERVER_SCRIPT = r"""
import socket, sys
try:
    open(sys.argv[2], encoding="utf-8").read()
    print("outside file: READ", flush=True)
except OSError as exc:
    print("outside file: refused,", type(exc).__name__, flush=True)
try:
    srv = socket.socket()
    srv.bind(("127.0.0.1", int(sys.argv[1])))
    srv.listen(1)
except OSError as exc:
    print("listen: FAILED", type(exc).__name__, exc.errno, flush=True)
    sys.exit(20)
print("listening", flush=True)
srv.settimeout(15)
try:
    conn, _ = srv.accept()
except OSError as exc:
    print("accept: nothing came,", type(exc).__name__, flush=True)
    sys.exit(21)
conn.settimeout(5)
conn.recv(1024)
conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nserved")
conn.close()
print("served one request", flush=True)
"""

TOP_FILES = ("python.exe", "python3*.dll", "vcruntime*.dll")
NOT_IN_LIB = (
    "site-packages", "test", "__pycache__", "venv", "idlelib", "tkinter", "turtledemo",
    "ensurepip", "pydoc_data",
)  # fmt: skip


def refuse_if_elevated() -> None:
    if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        sys.exit("refusing to run elevated: the result would not describe how Sletchy runs")


def copy_python(into: Path) -> Path:
    """Enough of this interpreter to open a socket, inside the workspace."""
    base = Path(sys.base_prefix)
    (into / "DLLs").mkdir(parents=True)
    for pattern in TOP_FILES:
        for found in base.glob(pattern):
            shutil.copy2(found, into / found.name)
    for pattern in ("_socket.pyd", "select.pyd"):
        for found in (base / "DLLs").glob(pattern):
            shutil.copy2(found, into / "DLLs" / found.name)
    shutil.copytree(base / "Lib", into / "Lib", ignore=shutil.ignore_patterns(*NOT_IN_LIB))
    return into / "python.exe"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def connect(port: int, seconds: float) -> str:
    """A client here: retry until the server listens, then one request."""
    deadline = time.monotonic() + seconds
    last = "never tried"
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                return "answered: " + data.decode("latin-1").splitlines()[-1]
        except OSError as exc:
            last = f"{type(exc).__name__} {getattr(exc, 'winerror', None) or exc.errno}"
            time.sleep(0.3)
    return f"no answer ({last})"


def main() -> int:
    if sys.platform != "win32":
        sys.exit("windows only")
    refuse_if_elevated()
    print("This starts a server on 127.0.0.1 for a few seconds, in and out of a sandbox,")
    print("and connects to it from here. Nothing leaves the machine.")
    if "--plan" in sys.argv:
        print("\n--plan: nothing was run.")
        return 0

    from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
    from sletchy.kernel.ledger import InMemoryKeySource, Ledger
    from sletchy.kernel.paths import ENV_HOME, ledger_dir
    from sletchy.warden.isolation import SandboxRecorder, SubprocSandbox, WinJobSandbox

    rows: dict[str, tuple[int | None, str, str]] = {}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        os.environ[ENV_HOME] = str(root / "home")
        os.environ["SLETCHY_ALLOW_INMEMORY_KEY"] = "1"
        workspace = root / "workspace"
        workspace.mkdir()
        outside = root / "outside.txt"
        outside.write_text("denied", encoding="utf-8")
        python = copy_python(workspace / "python")
        script = workspace / "server.py"
        script.write_text(SERVER_SCRIPT, encoding="utf-8")

        ledger = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
        recorder = SandboxRecorder(ledger=ledger, actor_id="loopback_spike")
        profile = IsolationProfile.model_validate({"backend": IsolationBackend.WINJOB})
        contained = WinJobSandbox(workspace, profile, recorder=recorder)
        uncontained = SubprocSandbox(workspace, profile, recorder=recorder)

        c3 = contained.run([os.environ["COMSPEC"], "/c", "type", str(outside)], timeout=20)
        rows["C3"] = (c3.exit_code, (c3.stdout or "") + (c3.stderr or ""), "")

        for tag, sandbox in (("S0", uncontained), ("S1", contained)):
            port = free_port()
            box: dict[str, object] = {}

            def serve(sb: object = sandbox, p: int = port, out: dict[str, object] = box) -> None:
                out["result"] = sb.run(  # type: ignore[attr-defined]
                    [str(python), "-I", "-S", "-B", str(script), str(p), str(outside)],
                    timeout=30,
                )

            thread = threading.Thread(target=serve)
            thread.start()
            client = connect(port, 12)
            thread.join(40)
            result = box.get("result")
            code = getattr(result, "exit_code", None)
            said = (getattr(result, "stdout", "") or "") + (getattr(result, "stderr", "") or "")
            rows[tag] = (code, said, client)
        ledger.close()

    print()
    for tag, (code, said, client) in rows.items():
        print(f"{tag:3} exit={code!s:>5}")
        for line in said.strip().splitlines()[:8]:
            print(f"      server: {line[:100]}")
        if client:
            print(f"      client: {client}")

    print("\n--- what this run shows")
    if rows["C3"][0] == 0:
        print("  C3 FAILED: the file outside was read, so the container was not applied.")
        return 1
    if not rows["S0"][2].startswith("answered"):
        print("  S0 FAILED: the server did not answer outside the sandbox; S1 means nothing.")
        return 1
    _, s1_said, s1_client = rows["S1"]
    if "outside file: refused" not in s1_said:
        print("  S1's server process was not shown contained; S1 means nothing.")
        return 1
    verdict = "REACHED" if s1_client.startswith("answered") else "NOT reached"
    print(f"  A server inside a sandbox, from outside it on loopback: {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
