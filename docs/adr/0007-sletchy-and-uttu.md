# ADR-0007 - Sletchy is mine; Uttu is the public one

**Status:** Accepted · 2026-10-02. The name is my working choice, *"for now"*; the
relationship below is the decision.

## Context

Sletchy started three years ago as one Python script, my first chatbot. Since
2026-08-13 it has been rebuilt from nothing as a sealed personal enclave
([ADR-0003](0003-ledger-is-the-spine.md), [ADR-0004](0004-single-tenant-local-first.md)).

ADR-0004 left one door open on purpose: a public release *"is a different product and
needs its own ADR, not a quiet expansion of this one."* This is the first half of that
ADR - what the public thing is called, and how it relates to the private one. **What it
ships is decided later, one ADR per feature**: the network (#56), the board (#61), comms
(#63), the verified network and marketplace (#65), the legal register (#66).

Two pulls have to be reconciled, and both are mine:

- **Sletchy is personal.** It learns one person, holds that person's ledger and memory,
  and is aligned to them. Publishing the code must not change that.
- **The oldest idea in the archive points the other way.** The Global Defense Network
  (INVENTORY §2) was many nodes, not one: *"a network that's
  friendly and helps AI agents and humans flourish, while keeping Sletchy always aligned
  to me."*

## Decision

- **Sletchy stays mine.** One operator, one machine, aligned to me. My data is never
  published.
- **Uttu is the name of the public, open-source release.** Uttu is the Sumerian goddess
  of weaving, and weaving is the shape: many separate threads, each whole on its own,
  made into one cloth only where they choose to cross.
- **One codebase until release.** The package, the CLI and the repo keep the name
  `sletchy` until the release ADR. A rename is mechanical and is done once, at the end,
  not drip-fed through the codebase now.
- **What is Sletchy's never ships.** The operator's ledger, memory, user model, keys,
  flags and policy live under `var/` and the OS keychain, and both are outside git. Uttu
  ships code and defaults. It never ships anyone's state.

## What "grows and flourishes" means

On Uttu once it is ready, in my words: *"its own creation, that will understand I created it,
BUT, I want to see it grow, and flourish."*

That sentence has a safe reading and an unsafe one, and the difference is the whole design.

**The reading meant, and the one built.** Uttu grows because people choose to install it
and choose, feature by feature, to opt in. The project grows, the community grows, and
the shared board ([#61](https://github.com/Sletch/sletchy/issues/61)) gets more useful as
more people choose to publish to it.

**Permanently out.** An instance that:

- acts on its own initiative beyond its operator's goals ([#62](https://github.com/Sletch/sletchy/issues/62))
- takes an instruction from another instance, or from anything it reads on the network
  ([#56](https://github.com/Sletch/sletchy/issues/56), #61)
- spreads, installs, or replicates itself
- acts in concert with other instances on one message

A network of agents that one message can steer is a weapon, whatever it was built to
defend. #61 already says the shield is *"every bubble independently tightening on shared
evidence"*; this ADR makes that the identity of the public product, not one rule inside it.

**Every Uttu answers only to the person who runs it.** That is the alignment Sletchy has
to me, given to every user.

## The three human questions

LAW 0 and the laws decide whether a feature is safe. They do not decide whether it is
worth building. My three questions do, and they apply to Sletchy and Uttu alike - see
[principles.md](../LAW/principles.md#the-three-human-questions).

## Consequences

**Good**

- The private bubble and the public product can no longer be confused, in the code or in
  conversation. A request that would put my data into Uttu now has a name to refuse
  against.
- The network ideas filed in August (#56-#66) have a home that is not "Sletchy, but
  multi-tenant" - which is exactly the quiet expansion ADR-0004 warned against.

**Costs**

- Two names to explain until the rename lands.
- **"Uttu" is not cleared.** Other projects or trademarks may use it. Search before the
  release, not after - the name is held loosely for that reason.

## Not decided here

- The licence. *(Decided since: Apache-2.0 for Uttu, [ADR-0010](0010-uttu-is-apache-2-licensed.md).)*
- Whether Sletchy, after release, is Uttu plus my configuration, or stays a separate
  repo that Uttu is published from.
- What Uttu ships. Each networked feature gets its own ADR, and each must pass the
  three questions, LAW 0, and the constraints already written in #56 and #61.
