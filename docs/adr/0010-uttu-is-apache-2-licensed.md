# ADR-0010 - Uttu is licensed Apache-2.0

**Status:** Accepted · 2026-10-03. I decided it. Settles the first item
[ADR-0007](0007-sletchy-and-uttu.md) left open: "The licence."

## Context

[ADR-0007](0007-sletchy-and-uttu.md) split the work in two: **Sletchy** is my own,
private bubble, and **Uttu** is the name of the public, open-source release. It left the
licence open, and `workload/STATUS.md` carried a recommendation, Apache-2.0, as an open
question until I decided.

Nothing is public yet. There is no Uttu repository, no download, and no release date
(#133 is the installer, still to be built).

## Decision

**Uttu is released under the Apache License, Version 2.0.**

**Sletchy itself stays private and carries no licence.** It is mine, and nobody else
receives it.

**The licence files arrive with the first public code, in the same change:** `LICENSE`, the
Apache-2.0 text unmodified, and `NOTICE`, naming me as the copyright holder. They are
not added to this private repository now, so this repository never claims a licence it was
not published under.

## Reasoning

What Apache-2.0 does for Uttu, in plain words:

- **Anyone may use, change and redistribute it, including commercially.** An open project
  that people may not build on is not open
- **Every copy keeps the licence and the `NOTICE` file**, so my name travels with the
  code, and every change made to a file must say it was changed
- **It grants a patent licence explicitly**, and ends it for anyone who sues over patents in
  the work. MIT says nothing about patents
- **It grants no rights to the name** (section 6). "Uttu" stays mine to protect separately,
  so a fork cannot present itself as Uttu

## Consequences

- The agency site may now say Uttu will be open source under Apache-2.0. It still says
  "will be": nothing is released
- Every dependency Uttu ships must have a licence compatible with Apache-2.0. The vetting
  gate (LAW 4, #34) checks this before anything is bundled
- Contributions to Uttu, if they are ever taken, come in under the same licence (section 5)
- **Uttu's public repository starts from a fresh history.** This repository's commits,
  issues, pull requests and their edit histories stay private: they are the working
  record of a private project, and an edited body on GitHub keeps its earlier text.
  Everything posted here is still written for a public reader
  ([writing conventions, section 0](../LAW/writing-conventions.md)), so that what crosses
  over can be read as it is

## Alternatives rejected

- **MIT** - shorter, but no patent grant and no `NOTICE` requirement
- **GPL-3.0 or AGPL-3.0** - forces everything built on Uttu to be open too. I chose
  permissive
- **No licence** - "all rights reserved" by default, which would make Uttu public but not
  open source
