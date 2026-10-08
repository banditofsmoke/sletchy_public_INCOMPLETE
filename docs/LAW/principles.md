# Sletchy - Design Principles

Nine principles. They govern every design decision in this repo. When a choice is
unclear, come back here.

[LAW 0 - Do no harm](00-do-no-harm.md) sits above all nine of these.

---

## 1. The ledger is the truth

**Every decision, call, and boundary crossing produces a ledger event before it takes
effect.** The ledger is append-only and hash-chained: each entry commits to the hash of
its predecessor, so any edit to history invalidates every entry after it.

If an action is not in the ledger, it did not happen - and code that can act without
writing to the ledger is a bug, not a shortcut.

This is Sletchy's spine. It is the ledger rather than a discovery protocol such as A2A,
because the product *is* a SOC/NOC, and a SOC without an immutable log is
theatre. A2A survives as an optional host adapter, not as the organising principle.

Consequences: no side-channel logging, no "quick debug path" that skips the ledger, no
in-memory-only decisions. The ledger is verified on startup; a ledger that does not
verify means Sletchy refuses to run ([LAW 0 §7](00-do-no-harm.md)).

## 2. Nothing is trusted - including our own imports

Agents are not trusted. Tools are not trusted. Models are not trusted. Prompts are not
trusted. **Third-party packages are not trusted.** Sletchy itself is not trusted.

Trust is not a property anything has; it is a budget something spends. Every actor
carries a **trust score** and a set of **capabilities**, and capabilities are checked at
the moment of use, never cached into an assumption.

Specifically on imports - this is a first-class surface, not a footnote:

- Every dependency is pinned by version **and hash**, in a lockfile, reviewed on change.
- New dependencies enter through a **vetting gate**: license, known CVEs, maintainer
  and release-cadence signal, transitive footprint, and a diff review of what changed.
- A new dependency's first runs happen in the **tightest sandbox available**, profiled
  for what it actually touches, before it is allowed a wider capability set.
- Install traffic goes through one controlled index path - never an unpinned, unbounded
  reach into the public internet at install time.

## 3. Declare → tighten → enforce

A component **declares** what it needs - filesystem paths, network destinations,
secrets, tools, resources - in a typed profile. Policy may only make that declaration
**stricter**. A separate enforcer applies the intersection.

**Policy can tighten. Policy can never loosen.** A merge that would widen a declared
bound is rejected, loudly, and the component refuses to start.

The declarer, the policy, and the enforcer are three different components. A component
that enforces its own limits is enforcing nothing.

## 4. Deny by default, at every layer

The default answer to every question - may I reach this host, read this path, call this
tool, use this secret, start this process - is **no**. Access exists only where
something explicitly granted it.

Defense in depth means **independent** layers, each sufficient against some threats and
insufficient against others. The defense is the composition, not any single layer. Every
layer must be documented with an explicit threat→layer table **and an honest list of
what it does not catch**. Residual gaps are written down, not implied-covered.

## 5. Stream-first, one event vocabulary

Every execution path produces one async stream of typed events. Hosts - CLI, HTTP/SSE,
WebSocket, MCP, desktop IPC - are **pure translation** over that stream: no state, no
side effects, no host-specific emission scattered through the runtime.

Non-streaming calls are a thin wrapper that consumes the stream and returns the final
value. Never the reverse.

Adding a new event type is a major decision - it changes the contract every host must
implement. Extend an existing event's payload first.

## 6. Configuration-driven, Pydantic as the only schema

Everything Sletchy runs is defined by **Pydantic models**: agents, tools, isolation
profiles, endpoints, policies, flags. Every derived artifact - JSON Schema, OpenAPI,
CLI arguments, UI forms, tool descriptors - is **generated** from those models.

Hand-authored parallel schemas are forbidden. They drift, and drift in a security
boundary is a vulnerability.

## 7. Human-in-the-loop is first-class

Pausing to ask is part of the protocol, not a bolt-on. An interrupt is a standard event
that every host renders consistently.

Anything irreversible or outward-facing stops for a human: spending money, deploying a
contract, sending a message, publishing anything, widening a capability, exposing a
listener beyond loopback. If a feature cannot be expressed as a pause-and-ask, the
feature changes - not the protocol.

## 8. Everything is a flag, and flags default off

Every capability is individually switchable at runtime through one flags registry. Any
flag touching network, filesystem outside `var/`, microphone, camera, screen, wallet, or
training **defaults to off**.

Flags are ledger-logged on flip, with who/when/why. The flag registry is itself typed
config, generated into the UI - there is no such thing as an undocumented flag.

This is what makes Sletchy plug-and-play: a non-technical user receives a copy where
everything dangerous is already off, and the system is useful before anything is turned
on.

## 9. Build new; scraps are reference, never dependency

`Scraps and Parts/` is **read-only archaeology**. We read it, learn from it, and
re-implement. We never import from it, never copy a file wholesale, and never write to
it.

Every salvaged idea is recorded in [`docs/salvage/INVENTORY.md`](../salvage/INVENTORY.md)
with a verdict and a destination, so provenance is traceable and nothing good is lost.
Code that arrives without passing through the laws is not salvage - it is debt.

---

## Precedence when principles conflict

1. **[LAW 0 - Do no harm](00-do-no-harm.md)** beats everything. Always.
2. **#2 Nothing is trusted** and **#4 Deny by default** beat convenience, performance,
   and elegance. An easier implementation that widens a boundary is rejected.
3. **#1 The ledger** beats #5. If a stream shape would let an action escape the ledger,
   the stream shape changes.
4. **#3 Declare→tighten** beats #6. A config convenience that allows loosening is
   rejected.
5. **#5 Stream-first** beats #6 for runtime concerns.
6. **#8 Flags default off** is not overridable for convenience, including in dev. Dev
   defaults live in a separate profile that is never shipped.

---

## The three human questions

The laws decide whether a feature is **safe**. They say nothing about whether it is
**worth building**. These three do, and they are mine:

1. **Does it save the user time?**
2. **Does it help the user make money?**
3. **Does it help the user connect with people?** In my original words, *"does it
   help the user get laid?"*

Every feature answers yes to at least one, and its issue says which. Three rules keep
the questions honest:

- **Safety is not a fourth question; it is the floor.** A feature that fails LAW 0 or
  any law is not weighed against these three. A yes here never buys an exception there.
- **Helping is never a reason to default on.** A feature that would help everyone is
  still off until each user turns it on ([LAW 8](laws.md#law-8)).
- **Security work answers them indirectly, and says so.** Nobody saves time with a tool
  they cannot trust; the Warden and the ledger exist so the rest can be used at all.
  Write that in the issue instead of stretching a feature to fit a question.

---

## Explicitly not in scope for v1

| Excluded | Why |
|---|---|
| Kernel-mode drivers | [LAW 0 §1](00-do-no-harm.md). Risk to the one host machine. |
| Kubernetes, Helm, cluster ops | No cluster. One PC. Revisit at public release. |
| Multi-tenancy | Single user by design. Do not pay multi-tenant complexity for one tenant - but also never *rely* on single-tenancy for a security property. |
| A2A as the spine | Kept as an optional host adapter. The ledger is the spine. |
| A framework as the spine (LangChain, LangGraph) | A dependency behind an adapter, never a law. The harness owns the event contract ([LAW 4](laws.md#law-4)). |
| Hosted observability (Langfuse et al.) | Telemetry leaving the bubble contradicts the product. Local traces, local dashboards. |
| Any public listener | Nothing binds beyond loopback without an explicit flag and a warning. |
| Convex / managed data planes | Local-first. No operational data leaves the machine. |

---

Related: [LAW 0](00-do-no-harm.md) · [architecture.md](architecture.md) ·
[isolation.md](isolation.md) · [laws.md](laws.md)
