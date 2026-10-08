# `kernel/` - the trust root

**This package is the thing everything else is allowed to assume. Treat every change as
a security change.**

Read [`docs/LAW/laws.md`](../../../docs/LAW/laws.md) and
[ADR-0003](../../../docs/adr/0003-ledger-is-the-spine.md) first.

## Rules specific to this package

- **`kernel` imports nothing from `sletchy`.** Not `warden`, not `soc`, not `mind`. Ever.
  Enforced by the import-linter test. If the Kernel needs something from another plane,
  the design is wrong.
- **Small, boring, and heavily tested.** This package should change rarely. A PR that
  grows it needs to justify why the logic cannot live one layer up.
- **No convenience APIs that skip a check.** Every "just for testing" bypass eventually
  ships. If tests need a shortcut, give them a fixture, not a code path.
- **Deny on every ambiguity.** Unparseable policy, unverifiable signature, missing
  secret, expired capability, tie in the rules: all deny, all log, all raise.

## The ledger

- Append-only, hash-chained, signed. Entry commits to `prev_hash`.
- **Verified on startup. A chain that does not verify halts Sletchy.**
- **Never self-repair.** No "fix the chain" function exists, and none may be added. A
  quietly repaired audit log is worse than no audit log.
- Bodies are content-addressed into a side store - the chain stays small, and a sensitive
  body can be deleted without breaking verification.
- Both wall-clock and monotonic timestamps. Monotonic is the ordering authority.
- Signing key from the OS keychain; never held in writable memory beyond a signing call.

## Policy and capabilities

- **Tighten-only merge.** A merge producing a wider bound than the declaration is
  rejected and the caller refuses to start. There is no flag to allow it.
- Capabilities are short-lived, scoped, signed, and bound to one execution context.
  Checked at the moment of use - never cached into an assumption.
- A capability names exactly one action on exactly one subject class. If it needs an
  "and", it is two capabilities.
- **Agents cannot request capabilities.** The Kernel issues them from policy. Anything
  else is prompt injection with extra steps.

## Secrets

- Refs in config, values from the OS keychain, resolved at use time.
- **Fail closed.** No fallback defaults, ever. See
  [`docs/salvage/CREDENTIALS-TO-ROTATE.md`](../../../docs/salvage/CREDENTIALS-TO-ROTATE.md)
  for why this rule has teeth.
- Never logged. Never in a ledger payload - only the ref and a hash.

## Flags

- One typed registry. Dangerous flags default off ([LAW 8](../../../docs/LAW/laws.md#law-8)).
- Flips are ledger-logged with who, when, why.
- The UI flag panel is **generated** from this registry. No hand-written flag lists.

## Testing

Every change here needs an adversarial test, not just a unit test. The question is not
"does it work" but "what defeats it" - and the answer goes in
`tests/adversarial/COVERAGE.md` whether or not it is fixed.
