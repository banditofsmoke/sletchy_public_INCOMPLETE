# ADR-0004 - Single-tenant and local-first, without relying on either

**Status:** Accepted · 2026-08-13

## Context

The usual default for an agent platform is multi-tenant from day one: tenant isolation
as a hard requirement, every component designed as if two adversarial tenants shared it,
on Postgres, Redis, ClickHouse, MinIO, and a hosted trace backend.

Sletchy is for one person, on one PC, and is explicitly private: *"this is just for me...
BUT, I am aware of its power."* The eventual goal is a stable public release.

## Decision

Sletchy is **single-tenant and local-first**:

- One user, one bubble. No tenant grain, no org grain, no RLS, no tenant-scoped tokens.
- Storage is embedded: SQLite plus content-addressed files under `var/`. No database
  daemon, no object store, no message broker.
- No telemetry leaves the machine. Traces and dashboards are local, read from the ledger.

**With one hard caveat: no security property may depend on single-tenancy.**

Isolation exists because agents and dependencies are adversarial, not because users might
be. Every boundary - capability checks, egress mediation, filesystem confinement, process
sandboxing - is enforced exactly as if a hostile peer were present, because in the threat
model there is one: the agent itself.

## Reasoning

**Why drop multi-tenancy.** Tenant-grain plumbing through every table, token, and API is
substantial permanent complexity. Paying it for a single user buys nothing today and slows
everything down. Data isolation between users is trivially satisfied by there being one
user and one machine.

**Why the caveat matters more than the decision.** The failure mode is subtle: teams drop
multi-tenancy and, without noticing, start *relying* on it - "only one user, so a tool can
read the workspace freely", "no other tenant, so an unscoped capability is fine". Every
one of those is a real vulnerability, because the adversary in Sletchy's model is a
compromised agent or a malicious dependency running *as* the user. Single-tenancy provides
no defense against that whatsoever.

So: keep the enforcement, drop the bookkeeping.

**Why local-first.** A private security bubble that ships its operational data to hosted
services is self-contradicting. It also makes the plug-and-play goal achievable - no
accounts, no daemons, no network required to be useful. The rule that follows:
add infrastructure only when a feature requires it.

## Consequences

**Good**
- Dramatically less plumbing; faster to build and to reason about.
- Genuinely plug-and-play: install and run, no services, no signup.
- Works fully offline with local models.
- Nothing to leak, because nothing leaves.

**Costs**
- SQLite has real concurrency limits. Mitigated by WAL mode, a single writer per store,
  and append-only patterns - which the ledger wants anyway. Notably, the old Sletchy's
  "rewrite the whole CSV on every write" memory is exactly the pathology to avoid.
- No horizontal scale. Correct for one user; a real constraint on the public-release path.
- Local dashboards mean building modest visualisation instead of adopting a mature hosted
  one. Accepted - it is a core product surface here, not incidental ops tooling.

## The path to a public release

The operator wants to share this one day. That is a **different product** and needs its
own ADR, not a quiet expansion of this one. What makes the transition tractable:

- The **capability** and **policy** models are already actor-scoped. `actor` widening to
  include a tenant identity is additive.
- The **ledger** already records `actor` on every entry.
- The **isolation ladder** ([ADR-0002](0002-pluggable-isolation-backends.md)) already
  supports stronger backends without touching callers.

What would genuinely have to be built: tenant grain in storage, an identity and authn
system, key management per tenant, and a hosted deployment story. **None of that should
be pre-built now** - speculative multi-tenancy that never meets a second real user is
waste, and worse, it is untested waste that provides false confidence.

The honest position: Sletchy v1 is a personal tool that is *architecturally capable* of
growing up, and is not pretending to be grown up yet.
