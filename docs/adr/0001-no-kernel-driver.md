# ADR-0001 - No kernel-mode code in v1

**Status:** Accepted · 2026-08-13
**Supersedes:** nothing · **Superseded by:** nothing

## Context

The stated ambition was a C++ component doing "kernel-level management" for total
visibility and control over processes and network - the granular control a SOC/NOC
needs.

The constraint, stated by the operator: *"I want to seal it, and make sure it doesn't
break my PC. I only have one PC. If I crash it I'm unemployed."*

These two things are in direct tension, and the tension has to be resolved explicitly
rather than deferred.

## Decision

**Sletchy ships no kernel-mode code in v1.** No filesystem minifilter, no WFP callout
driver, no NDIS filter, no bootstart service.

Isolation and observation are achieved through **documented user-mode Windows APIs whose
enforcement happens in the kernel**: Job Objects, restricted tokens, AppContainer,
Windows Firewall via `INetFwPolicy2`, and ETW as a read-only event source.

**C++ is not abandoned - it is relocated.** `warden/` is designed as a process boundary
from day one so its supervisor and egress proxy can be reimplemented as a native binary
once the contracts are stable. Native, user-mode, replaceable, and unable to bring the
machine down.

## Reasoning

The risk asymmetry is not close:

| | User mode | Kernel mode |
|---|---|---|
| Null deref | Process restarts | **BSOD** |
| Bad early-boot state | Nothing | **Boot loop / unbootable** |
| Recovery | Kill the process | Safe Mode, or reinstall Windows |
| To load unsigned code | Nothing | **Test Signing Mode** |
| To load signed code | Nothing | EV cert + WHQL attestation |

The decisive point is Test Signing Mode: loading our own unsigned "security" driver
requires **disabling Windows security features**. We would weaken the machine's real
defenses in order to install our aspirational one. That is a net loss on day one, before
a single line of the driver is even wrong.

The second point is that user mode is not actually a compromise here. AppContainer is the
same sandbox Microsoft ships to contain Edge. Job Objects are the same primitive that
contains Windows containers. We are not hand-rolling a weaker version of the kernel's
protections - we are calling the kernel's protections through their supported interface.

## Consequences

**Good**
- No failure mode in Sletchy can render the host unbootable.
- No EV certificate, no WHQL, no signing infrastructure, no per-Windows-build driver
  maintenance.
- Every host change stays reversible, which [LAW 0](../LAW/00-do-no-harm.md) requires.
- Ships far sooner.

**Costs, accepted**
- No arbitrary syscall interception. We observe what ETW exposes and control what we
  ourselves launch - not what an unrelated process on the host does. **Sletchy secures
  the bubble, not the whole machine.** That scope must stay explicit and must not be
  quietly oversold.
- No inline packet inspection below the proxy. We see what crosses our membrane.
- ETW consumption for some providers wants elevation; those sensors are optional and
  degrade to "unavailable" rather than requiring a permanently elevated Sletchy.

**Follow-up**
- Verify AppContainer behaviour empirically on Windows 10 Pro 19045 before `winjob` is
  described as strong. Tracked as a spike, not assumed. (`docs/LAW/isolation.md`,
  residual gaps.)

## Alternatives rejected

- **Write the driver anyway.** Rejected: one PC, no second machine, Test Signing Mode
  requirement.
- **Require WSL2 for Linux namespaces.** Rejected by the operator, and it would make a
  "plug-and-play bubble for a non-technical user" depend on a Linux subsystem install.
- **Require Docker.** Rejected as vendor lock-in. Docker becomes an *optional*
  accelerator - see [ADR-0002](0002-pluggable-isolation-backends.md).

## Revisiting

This ADR may be superseded only by an ADR that: names the specific capability that
genuinely requires kernel mode; shows it cannot be obtained from ETW plus user-mode APIs;
and proposes a development path on hardware that is **not** the operator's only machine.
The bar is deliberately very high.
