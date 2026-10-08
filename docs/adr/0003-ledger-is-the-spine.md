# ADR-0003 - The ledger is the spine, and it is built first

**Status:** Accepted · 2026-08-13

## Context

Agent platforms commonly make the **A2A protocol** the organising principle: every agent publishes
a card, discovery and invocation happen over A2A, and the platform is "A2A-native".

Sletchy's stated requirement is different: *"a self-contained SOC and NOC, monitoring any
and all interactions, everything is logged and audited... NOTHING IS TRUSTED."*

There is also a build-order question. Wave 1 could reasonably be the chat loop (fast,
visible, satisfying) or the audit spine (slow, invisible, foundational).

## Decision

**The hash-chained ledger is Sletchy's spine.** A2A is demoted to an optional host
adapter alongside CLI, SSE, WebSocket, MCP, and desktop IPC.

**The Kernel - ledger, policy, capabilities, contracts - is Wave 1.** Nothing else is
built until it exists and verifies.

Concretely: every decision, tool call, model call, egress attempt, flag flip, and
capability grant appends to the ledger **before** it takes effect. The ledger is
append-only and hash-chained; it is verified on startup; a chain that fails verification
halts Sletchy; Sletchy never repairs it.

## Reasoning

**Why not A2A as the spine.** A2A solves discovery and interop across a *fleet* of
agents. Sletchy is one bubble, one user. The problem A2A solves is not the problem
Sletchy has, and adopting it as the organising principle would shape the entire codebase
around a need that does not exist yet. It stays available as a host adapter for the day
two bubbles talk to each other.

**Why the ledger instead.** "Nothing is trusted" is only a real property if there is an
artifact that proves what happened. A SOC without an immutable log is theatre. Making the
ledger the spine means the security property is structural - code physically cannot act
without leaving a record - rather than a discipline that erodes under deadline.

**Why first, not later.** Retrofitting an audit spine is the classic failure. Once a chat
loop exists that works without the ledger, every subsequent feature is written against
the ledger-free path, and the ledger becomes an optional decorator that a hurried change
skips. Building it first inverts the default: the only way to do anything is through the
ledger, so the security property holds by construction.

This costs visible progress in Wave 1. That cost is accepted and stated plainly.

## Consequences

**Good**
- The audit property is structural, not aspirational.
- The SOC needs no separate collection pipeline - it reads the ledger. One source of
  truth means the security view and the audit view cannot disagree.
- Replay, forensics, and the memory rollups all come from the same substrate.
- Tamper-evidence is a mathematical property, not a policy.

**Costs**
- Wave 1 produces nothing you can talk to. Deliberate.
- Every write path pays a hashing and append cost. Mitigated by content-addressing
  payloads out of the chain and keeping chain entries small.
- Startup verification cost grows with the chain. Mitigated by sealed segments - each
  segment ends with a terminal entry committing to its whole hash, so only the active
  segment needs full verification.
- Refusing to run on a corrupt chain is a real availability risk. Accepted: a quietly
  repaired audit log is worse than no audit log ([LAW 0 §7](../LAW/00-do-no-harm.md)).

## Implementation notes

- Chain entry: `{ seq, ts_wall, ts_mono, plane, actor, action, subject, verdict,
  payload_hash, prev_hash, sig }`. Small and fixed-shape.
- Bodies (prompts, responses, artifacts) are content-addressed into a side store. This
  keeps the chain fast **and** lets a sensitive body be deleted without breaking
  verification - the hash still commits, the body is simply gone.
- Signing key in the OS keychain, never in the process's writable memory beyond a
  signing call.
- Both wall-clock and monotonic timestamps: wall for humans, monotonic for ordering that
  survives clock changes.

## Alternatives rejected

- **A2A-native** - solves a fleet problem Sletchy does not have.
  Retained as an optional adapter.
- **Chat loop first, ledger later** - the retrofit failure mode described above.
- **Plain append-only log, no hash chain** - gives auditability but not tamper-evidence,
  and tamper-evidence is the whole claim.
