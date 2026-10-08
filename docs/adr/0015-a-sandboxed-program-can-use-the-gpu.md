# ADR-0015 - A program in a `winjob` sandbox can use the GPU

**Status:** Accepted · 2026-10-05 · closes #168
**Measured on:** Windows 10 Pro, build **10.0.19045**, AMD64, Python 3.13.3,
**non-elevated**; NVIDIA GeForce RTX 5050 (8 GB), driver **617.14**

## Context

Training inside Sletchy (#55) assumes a contained process can reach the GPU: the model
is fine-tuned by a program `winjob` launched, on the operator's own card, with every
step on the ledger. Nobody had measured that. If a container cannot reach the GPU, the
training design changes before a line of it is written, so this was measured first:
the same shape as #12 ([ADR-0005](0005-appcontainer-findings.md)) and #71
([ADR-0006](0006-egress-binding-findings.md)).

**Nothing was installed.** The probe, `scripts/spike/gpu_probe.py`, uses only what the
NVIDIA driver already put in System32: `nvidia-smi.exe` (the management library, NVML)
and `nvcuda.dll` (CUDA), called through `ctypes`. Nothing left the machine and nothing
was elevated.

## Method

| | What | Control |
|---|---|---|
| C3 | read a file outside the workspace, contained | must be refused: the container was applied |
| N0 | `nvidia-smi -L`, uncontained | must list the GPU: the tool works here |
| N1 | the same, contained | the measurement |
| K0 | CUDA: init, device count and name, the primary context, 64 MB allocated and freed, uncontained, after reading the file outside | every call must return 0 |
| K1 | the same, contained | the measurement, **in a process that must itself be refused the file outside** |

The rows that need Python run a copy of the interpreter inside the workspace (about
30 MB: the executable, its runtime, `ctypes` and the standard library). A container
cannot read the interpreter where it is installed, and granting it that folder would
change a folder outside Sletchy.

## Findings

### 1. CUDA works inside the sandbox

Two runs, identical:

| | Exit | Time | Said |
|---|---|---|---|
| C3 | 1 | 1.7 s | `Access is denied.` |
| K0 | 0 | 0.5 to 0.7 s | `outside file: READ`; every CUDA call `0`; one device, the RTX 5050 |
| K1 | **0** | **2.0 s** | **`outside file: refused, PermissionError`**; every CUDA call `0`, the 64 MB allocation included |

K1 is the finding. The process that initialised CUDA, made a context, and allocated and
freed 64 MB of the card's memory is the same process the container refused a file
outside its workspace. So the result cannot come from a process the container did not
hold. A Job Object, a restricted token and a zero-capability AppContainer together do
not keep a program off the GPU.

### 2. The management library works too, once it can find its folder

The first run's N0 failed **outside** the sandbox (`Failed to initialize NVML: Unknown
Error`, exit 255), so its N1 meant nothing (L001). By elimination, unelevated:
`nvidia-smi` starts with only `ProgramFiles` in its environment and fails with every
other single variable, `SystemRoot` and `PATH` included. The sandbox's environment
allowlist does not pass `ProgramFiles`. With that one variable set by the probe, N0 and
N1 both list the GPU, in both runs.

So a training stack that asks NVML for memory or utilisation needs `ProgramFiles` in its
environment, or it fails in a way that looks like a missing GPU.

### 3. Python warns, and carries on

Every contained Python printed `Failed to find real location of ...python.exe` before
running. The interpreter could not resolve its own path inside the container; the
rows ran normally. Recorded so that the line is not later mistaken for a failure.

### 4. The host was unchanged

Before and after both runs: no `Sletchy` container profile, no interpreter copy left in
the temporary folder, and the card's memory back to its idle level (275 MiB before,
268 MiB after).

## Decision

- **Training can be designed around `winjob`.** Its job limits are raised for a training
  run's own profile, and its network stays off. Whether and when to build it is a
  separate decision, recorded in the ADR that follows this one
- **`winjob` does not confine the GPU, and says so.** It is written as a residual gap,
  not fixed here: no user-mode control Sletchy has (LAW 0 §1) limits a process's GPU
  compute or memory

## Consequences

- **Any contained program can use the GPU**, not only a training run: compute, and the
  card's memory up to what is free. A hostile one could mine on it, starve the display
  of memory, or exercise a driver bug. On the operator's machine the graphics-driver
  service has been failing in a loop (STATUS), which makes the last of those more than
  theoretical. COVERAGE records it
- A training run's environment must include `ProgramFiles`, or NVML fails (finding 2)
- The job's memory cap (2048 MB by default) limits the host's memory, not the card's.
  Nothing here limits how much of the card a run takes

## What this does not answer

- **Whether a real training run fits:** the training stack is not installed, and one
  64 MB allocation is not a training step
- **Load and stability:** seconds of light work, not hours at full load. Whether the
  driver holds under a long run is unmeasured, and the operator's driver is not healthy
- **Isolation of the card's memory** between a contained process and others: not
  claimed, not measured
- **DirectML, Direct3D and Vulkan:** only CUDA and NVML were exercised
- Another driver, card or Windows build

## Reproducing

```
uv run python scripts/spike/gpu_probe.py --plan    # runs nothing
uv run python scripts/spike/gpu_probe.py
```

The output masks the card's unique ID.
