# Isolation - the six layers, remapped to one Windows host

Agent platforms usually get their six defense-in-depth layers from Kubernetes. There is no
cluster here, and per [LAW 0](00-do-no-harm.md) there is no kernel driver either. This
document maps each layer onto a mechanism that is **kernel-enforced but user-mode-driven**
on Windows, and states honestly where the mapping is weaker.

Read [principles.md](principles.md) §3 and §4 first.

---

## The isolation ladder

Isolation is an interface, not a vendor. `warden/isolation/` defines `IsolationBackend`
and ships several implementations. Sletchy degrades honestly rather than demanding a
dependency.

| Backend | Substrate | Requires | Strength |
|---|---|---|---|
| `inproc` | Same process | - | **None.** Test-only; refuses to load outside a test run. |
| `subproc` | Child process, env-whitelisted, hard timeout | - | Weak |
| **`winjob`** | Job Object + restricted token + AppContainer + firewall app rule | Windows | **Strong for filesystem, resources, and process tree** (all measured - [ADR-0005](../adr/0005-appcontainer-findings.md) and the `winjob` suite); **network still unverified** - default here |
| **`container`** | Rootless Podman, `--network=none`, read-only image pinned by digest, the workspace the only mount | Linux only ([ADR-0014](../adr/0014-the-container-backend-runs-on-linux-only.md)) | **Proven on CI's Linux runner** against the shared conformance suite; never available on Windows, where it would need a virtual machine. Network denial not claimed |
| `container` | OCI: netns, read-only rootfs, cgroups, seccomp | Docker **or** Podman | Strong by design, **not built** |
| `vm` | Hyper-V isolated container | Hyper-V | Strongest (future) |

**Policy declares a minimum.** e.g. "any capability with egress requires ≥ `winjob`";
"training requires ≥ `winjob`"; "`inproc` is forbidden outside tests". If the minimum is
unavailable, **the capability does not run** - it never silently downgrades. That rule is
the difference between a ladder and a loophole.

`container` targets the OCI surface both Docker and Podman implement. A CI job runs the
container backend against **Podman** specifically to prove Docker is never load-bearing.
That is the anti-lock-in guarantee, tested rather than promised.

---

## The six layers on Windows

### L1 - Network

*On Kubernetes: Kubernetes `NetworkPolicy`, deny-all default, egress allowlist.*

**Here:** two independent mechanisms.

1. **Windows Firewall rules** (`sletchy install-rules`, #33,
   [ADR-0013](../adr/0013-sandbox-lanes-so-a-firewall-rule-can-name-the-container.md)):
   one outbound block rule per sandbox lane, naming the lane's container SID, covering
   every address but this machine's. Under them, the container itself already refuses
   other machines over TCP ([ADR-0006](../adr/0006-egress-binding-findings.md) finding 5).
   Measured by hand with the operator: with the container's own lock opened, a rule
   refuses the lane it names over TCP and IPv4, and nothing refuses a container no rule
   names (ADR-0006 finding 8). Both locks drop UDP too, named in Windows' drop log
   (finding 9). IPv6 is not measured (#173).
2. **The Warden egress proxy** (`warden/egress/`, #32) - the only reachable network
   path. One per run, on loopback, behind a password made for that run. Per-request
   allowlist on host, port, method and size, an address floor no allowlist lowers, the
   checked address connected and never a second lookup, and every attempt and verdict
   appended to the ledger before anything connects.

3. **The local model door** (`warden/egress/local.py`,
   [ADR-0017](../adr/0017-a-model-before-training-through-one-local-door.md)) - for
   Sletchy's own Mind, not a sandbox: `127.0.0.1` and one port, a fixed list of questions
   per engine (never one that makes the server fetch, write or delete), the
   `mind_local_models` switch, and every request recorded before it connects. The proxy's
   floor, which refuses this machine, is unchanged.

L1 makes the proxy non-bypassable; the proxy makes L1 granular.

All rules live in a single named group (`Sletchy`) and are removed wholesale by
`sletchy stop` run as administrator, and by uninstall ([LAW 0 §2](00-do-no-harm.md)).

**Weaker than K8s at:** per-pod CIDR policy and cross-namespace ingress rules - concepts
with no single-host equivalent. In exchange, we get per-*binary* granularity, which K8s
does not have.

### L2 - Container / process

*On Kubernetes: Pod `securityContext` - read-only rootfs, run-as-non-root, no privilege
escalation, resource quotas.*

**Here:** the `winjob` backend, applied **before** the process runs. **Built and
measured** - every row marked *measured* has a passing adversarial test, and the
unmarked rows say so rather than being implied:

| Control | Mechanism | Status |
|---|---|---|
| Memory ceiling | `JOB_OBJECT_LIMIT_JOB_MEMORY` | Set before launch; the *kill* is unobserved |
| CPU ceiling | `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`, hard cap | Set before launch |
| Wall-clock kill | our watchdog, then `TerminateJobObject` | **Measured** |
| Whole-tree kill | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | **Measured** - a detached grandchild dies with the job |
| No child breakout | `JOB_OBJECT_LIMIT_BREAKAWAY_OK` **not** set | **Measured** - the grandchild is inside the job |
| Privilege stripping | `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` | **Measured** to combine with AppContainer |
| Deny-by-default filesystem | **AppContainer** with no capabilities granted | **Measured** across volumes |
| Deny-by-default **network** | same profile | **Measured: loopback is allowed, other machines are refused.** A zero-capability container reached a loopback listener in the same run it was denied a file outside its workspace, and was refused a TCP connection to an unrouted address at once, where the same connection outside it timed out ([ADR-0006](../adr/0006-egress-binding-findings.md) findings 1 and 5). Loopback being open is what the proxy needs, and it is open inward too: a server inside the container is reached from outside it (finding 10). UDP is dropped too (finding 9). IPv6 is unmeasured (#173) and loopback reaches every local service, so `winjob` still claims no network confinement. The firewall rule (#33), measured to bind over TCP and UDP (findings 8 and 9), is the second lock |
| Deny-by-default registry | same profile | **Not measured.** See residual gaps |
| No UI/desktop access | Separate window station where applicable | Not built |
| GPU | none | **Measured: not confined.** A contained process initialised CUDA and allocated 64 MB of the card's memory while the same process was refused a file outside its workspace ([ADR-0015](../adr/0015-a-sandboxed-program-can-use-the-gpu.md)). No user-mode control limits a process's GPU compute or memory |

Limits are applied at creation, never after launch - applying them afterwards is a race,
and a race in a security boundary is a vulnerability. The job is attached by
`PROC_THREAD_ATTRIBUTE_JOB_LIST` in the same call that creates the process, so there is
no interval at all, not merely a short one. `AssignProcessToJobObject` is deliberately
never bound in the Warden, and a test enforces that.

**The container must be handed its workspace.** An AppContainer is denied a directory
the parent created for it until one ACE names its per-execution SID. `winjob` adds that
ACE, journals it *before* adding it, and removes it when the run ends - everything
outside the workspace stays denied.

**Equal to or better than Kubernetes at:** process-tree containment.
**Weaker at:** filesystem *image* immutability - there is no read-only rootfs equivalent,
so L4 carries more weight here.

### L3 - Tool and capability access control

*On Kubernetes: card-declared MCP servers ∩ deployment policy, JWT-scoped per execution.*

**Here:** unchanged in spirit and fully applicable. Tools are declared per agent,
intersected with policy, and issued as **short-lived signed capabilities bound to one
execution context**. Checked at the moment of use. A tool not in the intersection does
not appear in the registry the agent sees - it is not merely refused, it is invisible.

Decoy tools from `soc/honeypot/` *are* visible. Calling one is a high-confidence signal.

### L4 - Filesystem guard

*On Kubernetes: path-traversal prevention, quotas, per-mount ro/rw.*

**Here:** carries extra weight because L2 has no read-only rootfs.

- Canonicalise, then confine: resolve symlinks and junctions **before** the check, and
  re-verify the resolved path is under the root.
- Reject `..` traversal, absolute paths, UNC paths (`\\?\`, `\\server\share`), drive
  letters, ADS (`file.txt:stream`), and Windows device names (`CON`, `NUL`, `COM1`,
  `LPT1`, …), which are a Windows-specific trap a POSIX design never has to face.
- Quota checked before write, not after.
- Per-mount ro/rw, enforced by both the guard and the AppContainer profile ACLs.

Symlink-swap TOCTOU is a **known residual gap** - see `tests/adversarial/COVERAGE.md`.

### L5 - Secrets

*On Kubernetes: provisioner injects, code never sees raw values, scoped, rotated.*

**Here:** Windows Credential Manager via the keyring API - the same approach
ElectronAPP1 got right with keytar.

- Config holds `secret_ref`s. Never values.
- Resolved at use time, held for the shortest possible window, never logged, never in
  a ledger payload (only its ref and a hash).
- **Fail closed** on a missing secret. Never a silent fallback default - this is the
  direct fix for the `os.environ.get("GROQ_API_KEY", "gsk_live…")` pattern found in old <!-- secret-scan: allow -->
  Sletchy, which silently worked with a baked-in key.
- Sandboxed children get an **env allowlist**, never the parent environment. Explicitly
  stripped: cloud credentials, DB URLs, `LD_PRELOAD`-equivalents, Python import hooks,
  and `BASH_FUNC_*`-style function exports.

### L6 - Process sandbox for shell-using capabilities

*On Kubernetes: blocked-command list, env allowlist, cwd validation, timeout, output cap.*

**Here:** as designed, plus Windows specifics.

- **Allowlist**, not blocklist. A blocklist of dangerous commands is unwinnable.
- Reject path-bearing executables, empty argv, and shell interpreters (`cmd`, `powershell`,
  `pwsh`, `wsl`, `bash`) unless explicitly granted - a granted shell is an allowlisted
  *script*, never a free prompt.
- Reject `powershell -EncodedCommand`, `-ExecutionPolicy Bypass`, and `rundll32` /
  `regsvr32` / `mshta` style living-off-the-land launchers.
- cwd validated and confined. Timeout and output cap enforced by the job object.
- A denied command **never spawns**. Denial is decided before `CreateProcess`, and emits
  a `sandbox.blocked` ledger event.

---

## Threat → layer

| Threat | Caught by |
|---|---|
| Tool exfiltrates a secret over HTTP | L1 firewall (no direct net) + L1 proxy allowlist + L5 (never in env) |
| Agent reads outside its workspace | L4 canonicalise-then-confine + L2 AppContainer ACLs |
| Agent calls a tool it was not granted | L3 (not in its registry at all) |
| Agent calls a decoy tool | `soc/honeypot/` → high-confidence signal → freeze + revoke |
| Compromised dependency phones home at import | L1 (no direct net) + L4 quarantine profiling |
| Runaway process eats the host's RAM | L2 job memory limit + Sletchy's own free-memory floor |
| Process spawns a detached child to escape | L2 (no breakaway, kill-on-close) |
| Shell capability used to run an arbitrary payload | L6 allowlist + no path-bearing exe + no free-form shell |
| Prompt injection tells the agent to widen its own access | L3 capabilities are signed by the Kernel, not requestable by the agent; [LAW 7](laws.md#law-7) gates widening on a human |
| Ledger tampering to hide activity | Hash chain + startup verification + refuse-to-run |

---

## Residual gaps

Written down because [LAW 10](laws.md#law-10) requires it. These are **not** covered:

- **Every loopback service is reachable from a sandbox**, not only its proxy: loopback
  is open to a container, and the rules leave it open so the proxy can be reached.
  A sandbox still needs that service's own password.
- **Symlink/junction TOCTOU** - static escape cases are covered; the swap race is not.
- **TLS-terminated but not deeply inspected traffic** - we log metadata and size, not
  payload semantics.
- **AppContainer network and registry denial on Windows 10 Pro 19045** - filesystem
  containment is **measured** ([ADR-0005](../adr/0005-appcontainer-findings.md)) and the
  combination of Job Object + restricted token + AppContainer is now measured too: they
  compose, and none of the three voids another. **Network and registry denial remain
  unprobed**, so `winjob` does not claim `confines_network`, and no code should read its
  filesystem strength as covering either.
- **The memory ceiling is set but its enforcement is unobserved** - `JOB_OBJECT_LIMIT_JOB_MEMORY`
  is applied before launch, and the probe interpreter available inside a container cannot
  allocate enough to trip it. "The limit is set" is not "the limit kills".
- **A workspace ACE can survive a hard kill** - it is journalled before it is granted and
  `sletchy stop` reverts it, but between the kill and Stop everything it is still there. The
  SID belongs to a deleted per-execution profile, so it grants nobody anything; it is
  residue, not an opening.
- **Side channels** - timing, cache, and resource-contention channels between sandboxed
  processes on a shared host. Out of scope; documented so it is not implied-covered.
- **A malicious model file** loaded by a local runtime (pickle-style deserialisation).
  Handled today only by treating model files as untrusted input under L4; needs its own
  gate.

---

Related: [LAW 0](00-do-no-harm.md) · [principles.md](principles.md) ·
[architecture.md](architecture.md) · [ADR-0002](../adr/0002-pluggable-isolation-backends.md)
