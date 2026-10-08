#!/usr/bin/env python3
"""SPIKE probe: can a program inside a Sletchy sandbox use the GPU? (#168)

Throwaway, like the egress probes before it: it produces findings for an ADR, not
product code. Training inside Sletchy (the Forge, #55) assumes a contained process can
reach the GPU. Nobody has measured that, and if it cannot, the training design changes
before a line of it is written. So it goes first, the same shape as #12 and #71.

**Nothing new is installed.** It uses only what the NVIDIA driver already put in
System32: `nvidia-smi.exe` (the management library) and `nvcuda.dll` (CUDA itself),
called through `ctypes`. Nothing leaves the machine, nothing is elevated, and the only
host change is the sandbox's own container profile, made and removed by `winjob` as
every contained run does.

    uv run python scripts/spike/gpu_probe.py           # run every row
    uv run python scripts/spike/gpu_probe.py --plan    # say what it would run; run nothing

## The rows

| | What | Expected if a sandbox can use the GPU |
|---|---|---|
| C3 | read a file outside the workspace, contained | refused (control: the container was applied) |
| N0 | `nvidia-smi -L`, **un**contained | lists the GPU (control: the tool works here) |
| N1 | the same, contained | lists the GPU |
| K0 | CUDA: init, count, name, a context, 64 MB allocated and freed, **un**contained | every call 0 (control) |
| K1 | the same, contained, and the same process refused a file outside | every call 0, and refused |

`nvidia-smi` (the management library) and CUDA reach the driver by different paths, so
each gets its own pair. Both run under a copy of this Python inside the workspace: a
container cannot read the interpreter where it is installed, and granting it that
folder would change a folder outside Sletchy. The copy is deleted with the workspace.

`nvidia-smi` cannot start without `ProgramFiles` in its environment, which the sandbox's
allowlist does not pass (found by the first run: it failed outside the sandbox too). Its
rows set that one variable for it; nothing else is added.

K1 tries to read a file outside the workspace **in the same process** that used the
GPU, so the CUDA result cannot come from a process the container did not hold.

The GPU work is the smallest that proves use: one 64 MB allocation, freed at once.
"""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
NVIDIA_SMI = SYSTEM32 / "nvidia-smi.exe"
NVCUDA = SYSTEM32 / "nvcuda.dll"
PROGRAM_FILES = os.environ.get("ProgramFiles", "C:\\Program Files")
UUID = re.compile(r"GPU-[0-9a-fA-F-]{36}")

#: Run inside the sandbox by the copied Python. Every binding gets its argtypes and
#: restype (L004), and every call's result is printed, so a refusal names its call.
CUDA_SCRIPT = r"""
import ctypes, sys
try:
    open(sys.argv[1], encoding="utf-8").read()
    print("outside file: READ")
except OSError as exc:
    print("outside file: refused,", type(exc).__name__)
c = ctypes.c_int
p = ctypes.POINTER
try:
    cuda = ctypes.WinDLL("nvcuda.dll")
except OSError as exc:
    print("load nvcuda.dll: FAILED", exc)
    sys.exit(20)
def bind(name, *args):
    fn = getattr(cuda, name)
    fn.argtypes = list(args)
    fn.restype = c
    return fn
cuInit = bind("cuInit", ctypes.c_uint)
cuGetErrorName = bind("cuGetErrorName", c, p(ctypes.c_char_p))
cuDeviceGetCount = bind("cuDeviceGetCount", p(c))
cuDeviceGet = bind("cuDeviceGet", p(c), c)
cuDeviceGetName = bind("cuDeviceGetName", ctypes.c_char_p, c, c)
cuDevicePrimaryCtxRetain = bind("cuDevicePrimaryCtxRetain", p(ctypes.c_void_p), c)
cuDevicePrimaryCtxRelease = bind("cuDevicePrimaryCtxRelease_v2", c)
cuCtxSetCurrent = bind("cuCtxSetCurrent", ctypes.c_void_p)
cuMemAlloc = bind("cuMemAlloc_v2", p(ctypes.c_uint64), ctypes.c_size_t)
cuMemFree = bind("cuMemFree_v2", ctypes.c_uint64)
def say(step, code):
    name = ctypes.c_char_p()
    if code:
        cuGetErrorName(code, ctypes.byref(name))
    print(f"{step}: {code} {(name.value or b'').decode()}".rstrip())
    if code:
        sys.exit(10)
say("cuInit", cuInit(0))
n = c()
say("cuDeviceGetCount", cuDeviceGetCount(ctypes.byref(n)))
print("devices:", n.value)
dev = c()
say("cuDeviceGet", cuDeviceGet(ctypes.byref(dev), 0))
buf = ctypes.create_string_buffer(128)
say("cuDeviceGetName", cuDeviceGetName(buf, 128, dev))
print("name:", buf.value.decode())
ctx = ctypes.c_void_p()
say("cuDevicePrimaryCtxRetain", cuDevicePrimaryCtxRetain(ctypes.byref(ctx), dev))
say("cuCtxSetCurrent", cuCtxSetCurrent(ctx))
ptr = ctypes.c_uint64()
say("cuMemAlloc 64 MB", cuMemAlloc(ctypes.byref(ptr), 64 * 1024 * 1024))
say("cuMemFree", cuMemFree(ptr))
say("cuDevicePrimaryCtxRelease", cuDevicePrimaryCtxRelease(dev))
print("CUDA: every call succeeded")
"""

#: Run by the copied Python: `nvidia-smi -L`, with the one variable it needs to start.
NVML_SCRIPT = r"""
import os, subprocess, sys
env = dict(os.environ, ProgramFiles=sys.argv[2])
result = subprocess.run([sys.argv[1], "-L"], env=env, capture_output=True, text=True)
print((result.stdout + result.stderr).strip())
sys.exit(result.returncode)
"""

#: What the CUDA rows need from the interpreter: itself, its runtime, `ctypes`, and the
#: standard library without its packages and tests. About 30 MB, not the whole folder.
TOP_FILES = ("python.exe", "python3*.dll", "vcruntime*.dll")
CTYPES_FILES = ("_ctypes.pyd", "libffi-*.dll")
NOT_IN_LIB = (
    "site-packages",
    "test",
    "__pycache__",
    "venv",
    "idlelib",
    "tkinter",
    "turtledemo",
    "ensurepip",
    "pydoc_data",
)


def refuse_if_elevated() -> None:
    if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        sys.exit("refusing to run elevated: the result would not describe how Sletchy runs")


def copy_python(into: Path) -> Path:
    """Enough of this interpreter to run `ctypes`, inside the workspace. Returns python.exe."""
    base = Path(sys.base_prefix)
    (into / "DLLs").mkdir(parents=True)
    for pattern in TOP_FILES:
        for found in base.glob(pattern):
            shutil.copy2(found, into / found.name)
    for pattern in CTYPES_FILES:
        for found in (base / "DLLs").glob(pattern):
            shutil.copy2(found, into / "DLLs" / found.name)
    shutil.copytree(base / "Lib", into / "Lib", ignore=shutil.ignore_patterns(*NOT_IN_LIB))
    return into / "python.exe"


def main() -> int:
    if sys.platform != "win32":
        sys.exit("windows only")
    refuse_if_elevated()
    for needed in (NVIDIA_SMI, NVCUDA):
        if not needed.is_file():
            sys.exit(f"not found: {needed.name}. The NVIDIA driver puts it in System32.")
    print(
        "This runs nvidia-smi and nine CUDA calls (one 64 MB allocation), in and out of a sandbox."
    )
    print("Nothing is installed or sent anywhere, and nothing needs an administrator.")
    if "--plan" in sys.argv:
        print("\n--plan: nothing was run.")
        return 0

    from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
    from sletchy.kernel.ledger import InMemoryKeySource, Ledger
    from sletchy.kernel.paths import ENV_HOME, ledger_dir
    from sletchy.warden.isolation import SandboxRecorder, SubprocSandbox, WinJobSandbox

    results: dict[str, tuple[int | None, float, str]] = {}

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        os.environ[ENV_HOME] = str(root / "home")
        os.environ["SLETCHY_ALLOW_INMEMORY_KEY"] = "1"
        workspace = root / "workspace"
        workspace.mkdir()
        outside = root / "outside.txt"
        outside.write_text("denied", encoding="utf-8")
        python = copy_python(workspace / "python")
        script = workspace / "cuda_probe.py"
        script.write_text(CUDA_SCRIPT, encoding="utf-8")
        nvml = workspace / "nvml_probe.py"
        nvml.write_text(NVML_SCRIPT, encoding="utf-8")

        ledger = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
        recorder = SandboxRecorder(ledger=ledger, actor_id="gpu_spike")
        profile = IsolationProfile.model_validate({"backend": IsolationBackend.WINJOB})
        contained = WinJobSandbox(workspace, profile, recorder=recorder)
        uncontained = SubprocSandbox(workspace, profile, recorder=recorder)

        def run(tag: str, sandbox: object, command: list[str]) -> None:
            start = time.monotonic()
            result = sandbox.run(command, timeout=60)  # type: ignore[attr-defined]
            text = ((result.stdout or "") + (result.stderr or "")).strip()
            results[tag] = (result.exit_code, time.monotonic() - start, text)

        cuda = [str(python), "-I", "-S", "-B", str(script), str(outside)]
        smi = [str(python), "-I", "-S", "-B", str(nvml), str(NVIDIA_SMI), PROGRAM_FILES]
        run("C3", contained, [os.environ["COMSPEC"], "/c", "type", str(outside)])
        run("N0", uncontained, smi)
        run("N1", contained, smi)
        run("K0", uncontained, cuda)
        run("K1", contained, cuda)
        ledger.close()

    print()
    for tag, (code, seconds, text) in results.items():
        print(f"{tag:3} exit={code!s:>5}  {seconds:5.1f}s")
        for line in text.splitlines()[:14]:
            # A GPU's UUID names this one card; it stays off any record (writing
            # conventions, section 0).
            print(f"      {UUID.sub('GPU-<uuid>', line)[:110]}")

    def ok(tag: str) -> bool:
        return results[tag][0] == 0

    print("\n--- what this run shows")
    if ok("C3"):
        print("  C3 FAILED: the file outside was read, so the container was not applied.")
        print("  Nothing below means anything. Record that, not a result.")
        return 1
    print("  C3: the container was applied (a file outside was refused).")
    if ok("N0"):
        print(f"  nvidia-smi in a sandbox: {'sees the GPU' if ok('N1') else 'REFUSED'}")
    else:
        print("  nvidia-smi: its control FAILED outside the sandbox; N1 means nothing.")
    k1 = results["K1"][2]
    if not ok("K0"):
        print("  CUDA: its control FAILED outside the sandbox; K1 means nothing.")
    elif "outside file: refused" not in k1:
        print("  CUDA: K1's own process was not shown contained; K1 means nothing.")
    else:
        print(f"  CUDA in a sandbox:       {'works' if ok('K1') else 'REFUSED'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
