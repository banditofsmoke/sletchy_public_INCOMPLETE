# ADR-0002 - Isolation is an interface, not a vendor

**Status:** Accepted · 2026-08-13

## Context

Sletchy must be **plug-and-play**: handed to a non-technical user, it works. It must
also enforce real isolation, because agents are untrusted ([LAW 4](../LAW/laws.md#law-4)).

Docker gives strong isolation but is a heavy prerequisite and a lock-in the operator
explicitly objected to. Kubernetes, the usual answer for agent platforms, is not available
on one PC at all. Requiring either would break plug-and-play; requiring neither would mean no real
isolation.

## Decision

`warden/isolation/` defines an **`IsolationBackend` interface** with multiple
implementations, selected by policy:

| Backend | Requires | Strength |
|---|---|---|
| `inproc` | - | None. Test-only; refuses to load outside a test run. |
| `subproc` | - | Weak |
| **`winjob`** | Windows | **Strong for filesystem, resources and process tree**, as measured in ADR-0005; **not a network control** (ADR-0006). Job Object + restricted token + AppContainer; the firewall app rule is #33, not built. **Default.** |
| `container` | Docker **or** Podman | Strong |
| `vm` | Hyper-V | Strongest (future) |

Three rules make this a ladder rather than a loophole:

1. **Policy declares a minimum per capability.** "Egress requires ≥ `winjob`." "Training
   requires ≥ `winjob`." "`inproc` is forbidden outside tests."
2. **If the minimum is unavailable, the capability does not run.** It never silently
   downgrades. A downgrade-on-missing-dependency is how isolation quietly becomes
   decorative.
3. **The container backend targets the OCI surface**, not Docker's. CI runs it against
   **Podman** specifically, so "Docker is not required" is a tested claim rather than a
   promise.

## Reasoning

`winjob` being the default is what makes the whole thing work: on a stock Windows
machine, with zero prerequisites installed, Sletchy still gets kernel-enforced process
containment, privilege stripping, deny-by-default filesystem access, and per-binary
network denial. Plug-and-play and real isolation stop being in tension.

Docker then becomes what it should be - an optional accelerator for someone who already
has it, offering a different (not strictly greater) set of guarantees.

Process isolation is usually treated as the weak fallback for environments without a
cluster, built on POSIX rlimits and run-as-user, which do nothing on Windows. The `winjob`
backend exists to make that fallback genuinely strong on the one OS Sletchy targets.

## Consequences

**Good**
- No prerequisite for the default path.
- No vendor lock-in, and it is tested rather than asserted.
- A clean upgrade path to `vm` without touching any caller.
- Backends are independently testable against one shared conformance suite.

**Costs**
- Backends have genuinely different security properties. The conformance suite must
  assert *behaviour* (this write is refused, this connection is refused), not
  implementation, and each backend needs its own honest residual-gap list.
- `winjob` is Windows-only. A future Linux/macOS port needs a peer backend
  (`linuxns`, `sandbox-exec`). The interface is designed for that; the work is not free.
- More surface than picking one substrate. Accepted: the alternative is either a
  prerequisite that breaks plug-and-play, or no isolation at all.

## Alternatives rejected

- **Docker-only** - breaks plug-and-play, and is the lock-in the operator objected to.
- **No isolation, policy-only** - policy without enforcement is a suggestion.
- **WSL2-only** - rejected by the operator; also a Linux-subsystem prerequisite for a
  non-technical user.
