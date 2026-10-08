# ADR-0005 - AppContainer findings on Windows 10 Pro 19045

**Status:** Accepted · 2026-08-13 · closes #12
**Measured on:** Windows 10 Pro, build **10.0.19045**, AMD64, Python 3.13.3, **non-elevated**

## Context

[ADR-0002](0002-pluggable-isolation-backends.md) makes `winjob` the default isolation
backend, and the entire anti-lock-in argument rests on it being genuinely strong with
**nothing installed** - no Docker, no WSL, no cluster. That claim was undocumented and
untested.

POSIX rlimits and run-as-user, the usual process-sandbox tools, are a best-effort no-op
on Windows. `winjob` exists to close exactly that gap, so
if AppContainer does not behave as documented here, the isolation design changes.

**This had to run on the real host.** Docker cannot answer it: Linux containers have no
AppContainer at all, and Windows containers have their own separate isolation. Only this
machine could be measured.

## Findings

### 1. Every required API exists - no gaps

All 13 entry points the `winjob` backend needs are present:

| Library | Functions |
|---|---|
| `userenv` | `CreateAppContainerProfile`, `DeleteAppContainerProfile`, `DeriveAppContainerSidFromAppContainerName`, `GetAppContainerFolderPath` |
| `kernel32` | `CreateJobObjectW`, `SetInformationJobObject`, `AssignProcessToJobObject`, `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `CreateProcessW`, `TerminateJobObject` |
| `advapi32` | `CreateRestrictedToken`, `CreateProcessAsUserW` |

### 2. The profile lifecycle is clean and fully reversible

- `CreateAppContainerProfile` → `HRESULT 0x00000000`, returns a valid SID.
- The profile lives under **`%LOCALAPPDATA%\Packages\<name>\AC`** - the *user's* own
  area, not a system location. No elevation needed at any point.
- `DeleteAppContainerProfile` → `0x00000000`, and the folder is gone.

Verified across **five** probe runs: 117 AppContainer profiles before, 117 after, zero
`SletchySpike*` residue on the filesystem, and no `HKCU\...\AppContainer\Mappings` key
left behind.

One run **crashed mid-probe** (a `FreeSid` lookup in the wrong DLL) and cleanup still
completed, because the delete sits first in the same `finally`. That was an accident, and
it is the most useful single data point here: the reversibility rail holds when the code
around it fails.

### 3. AppContainer with **zero capabilities** does deny filesystem access

| Probe | Result | Meaning |
|---|---|---|
| `cmd /c exit 42` | **42** | The container launches and runs a real interpreter |
| read a file in `%TEMP%` (outside) | **denied** | Containment is real |
| read a file the parent placed in the AC folder | **allowed** | A workspace can be handed in |
| write a file in the AC folder | **allowed** | The container has a usable scratch area |
| read back its own file | **allowed** | Round-trip works |

**Verdict: CONTAINED.** A process launched with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`
and **no** capabilities granted cannot read the user's files, while retaining full use of
its own folder.

That last column matters for the design beyond a pass/fail: **the parent can place a
workspace into the AC folder and the container can use it.** Handing a sandboxed agent a
working directory does not require granting a capability.

### 4. The container cannot open the `NUL` device

Found the hard way, and worth recording because it invalidated three earlier runs.

Every probe was initially written as `cmd /c type <file> >nul 2>&1`. The container **cannot
open `NUL`**, so every probe returned exit 1 - including the ones that should have
succeeded. The first reading was "AppContainer denies everything, even its own folder",
which was wrong: the test was measuring its own output redirection, not file access.

The control probe is what caught it. `cmd /c exit 42` returned **42**, proving the
container ran fine, which made "even its own folder is denied" implausible enough to chase.
**Without a positive control, the earlier outside-denial would have been reported as a
successful containment result for entirely the wrong reason.**

Two lessons carried into the Wave 2 conformance suite:

- Every isolation probe needs a **positive control** that must succeed. A suite of
  should-fail assertions passes trivially when nothing runs at all.
- Probe commands must not use I/O the sandbox might itself deny. Assert on exit codes from
  the simplest possible command.

## Decision

**`winjob` proceeds as designed, and may now be described as providing real, kernel-enforced
filesystem containment on this build** - with the specific claims above, not a general one.

Confirmed for the Wave 2 build (#13, 2.4):

- Profile create/delete is safe, reversible, and needs no elevation → a per-execution
  ephemeral profile is viable, matching the "ephemerality *is* isolation" principle.
- Filesystem denial is real with zero capabilities → L4 in `isolation.md` is achievable.
- A parent-provided workspace works → no capability grant needed to give an agent a
  working directory.

## Still unverified

Named rather than implied ([LAW 10](../LAW/laws.md#law-10)). These stay as residual gaps
in `COVERAGE.md`.

> **Partly answered since.** Building `winjob` (#31) measured three of these: the Job
> Object + restricted token + AppContainer combination composes with none voiding
> another; job limits apply to a contained child; and filesystem denial holds across
> volumes, not just the one `%TEMP%` file probed here. **Network and registry denial are
> still unprobed**, and the memory ceiling is still set-but-unobserved. The list below is
> left as written - it is the record of what was known on 2026-08-13.

- **Network denial.** Not probed. The design assumes an AppContainer without the
  `internetClient` capability cannot open a socket, and that the firewall app rule binds
  correctly to a contained process. **Both are still assumptions.**
- **Registry denial.** Not probed.
- **Job Object + restricted token + AppContainer combined.** Each verified alone or
  assumed; the combination is what `winjob` actually ships, and one may void another.
- **Resource limits.** `JOB_OBJECT_LIMIT_*` behaviour under an AppContainer'd child is
  untested.
- **Build specificity.** Everything here is 10.0.19045. A different Windows build may
  differ, and the probe records the build it ran on for exactly that reason.

## Consequences

- `docs/LAW/isolation.md` updates its residual-gap row: filesystem containment moves from
  unverified to **verified with evidence**; network and registry stay unverified.
- The AppContainer row in `COVERAGE.md` splits into what is measured and what is not.
- The probe (`scripts/spike/appcontainer_probe.py`) stays in the repo until #13 lands,
  then is deleted. It is a measuring instrument, not a component - no production code may
  import it.

## Reproducing

```bash
python scripts/spike/appcontainer_probe.py --phase 0   # inspect only, writes nothing
python scripts/spike/appcontainer_probe.py --phase 1   # create + delete a profile
python scripts/spike/appcontainer_probe.py --phase 2   # enforcement probes
```

The probe refuses to run elevated, creates only `SletchySpike-*` profiles, deletes them in
a `finally`, and reports residue as a failure.
