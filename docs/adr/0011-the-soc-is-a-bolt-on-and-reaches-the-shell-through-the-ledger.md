# ADR-0011 - The SOC is a bolt-on, and reaches the Shell only through the ledger

**Status:** Accepted · 2026-10-03. My direction, settles #84.

## Context

Two places stated the rule for the Shell (the CLI and the window) and disagreed:

- `docs/LAW/architecture.md`, the planes table: the Shell *"Talks to Mind + SOC"*
- `tests/unit/test_import_layers.py`: the CLI may **not** import `sletchy.soc`
- `import-linter` did not mention the CLI at all

#80 hit it first: the self-check belonged in the SOC, the AST test refused it, and it moved
to `cli/selfcheck.py`. The live NOC (Wave 4) would hit it again.

My direction, 2026-10-03: the SOC is to be **a bolt-on that analyses the system and all its
processes**, reaching the window through the ledger, unless that is not safe.

## Decision

**1. The Shell never imports the SOC.** What the SOC concludes, it writes to the ledger as
a finding (an entry with `plane=SOC`), and the window shows findings as it shows every
other entry. The AST test already said this; the architecture table now says it, and
`import-linter` enforces it too, so the two checks cannot drift (#84's contract).

**2. The SOC is a bolt-on.** Nothing imports `sletchy.soc`: every other plane's forbidden
list already names it, and both checks enforce that. Sletchy runs whole without it, and
removing it changes no other plane.

**3. The SOC observes, records and tightens. It never grants.** It reads the ledger and
read-only operating-system telemetry: ETW, the firewall inventory through COM
(ADR-0006 finding 4), Job Object accounting. It writes findings. It may make Sletchy
more restrictive, such as lowering a trust score that gates capabilities (#37). It never
widens anything, the rule threat feeds already follow (#51).

**4. Raw telemetry never goes on the ledger; only findings do,** rate-limited and
de-duplicated. An append is an fsync (29 ms measured) and the ledger stops at 1 GB
(#101). A sensor that recorded every process event would fill it, and a full ledger
stops everything (`LedgerFull`), so a busy machine, or anyone able to start processes,
could switch Sletchy off through its own watcher. When the live NOC needs telemetry, it
goes to a bounded, overwritten store under `var/soc/`. The Shell reads that store as
data validated by a Kernel contract, never as code. It is designed here and built with
the NOC (#37).

**5. "All its processes" means Sletchy's own, by default.** Sletchy's processes are the ones
in its Job Objects, plus its own decisions. Watching every process on the machine is a
separate dangerous flag, off by default (LAW 0 section 4, LAW 8), because a record of
everything the operator runs is itself sensitive: a stolen ledger would become a full
activity log. Command lines are masked with the secret scanner's shapes (#86) before
anything is recorded, because secrets travel in arguments.

## Why the ledger is the safe route

Thinking as the attacker:

- **The SOC is the plane that reads hostile input**: process names and command lines
  chosen by whatever is running, traffic an attacker sends a honeypot (#38), threat feeds
  (#51). A parsing bug there is the likeliest compromise in the system. If the Shell
  imported the SOC, that bug would run inside the window's process, next to the switches.
  Through the ledger, the Shell reads signed, schema-validated entries: the most
  hardened interface Sletchy has (#94-#105, #116, #130), which already renders untrusted
  text safely (#96)
- **A compromised SOC can do less this way.** It can write false findings and tighten
  trust: a denial of service. It cannot grant anything, and it cannot reach the window's
  memory
- **A noisy SOC cannot stop Sletchy**, because only findings reach the ledger (decision 4)

## Alternatives rejected

- **The Shell imports the SOC.** It puts the hostile-input parser inside the window
- **The SOC pushes to the Shell over a socket.** That is a listener, which nothing in Sletchy
  has yet (#59), and a second, unsigned channel beside the ledger (LAW 1)

## Consequences

- `docs/LAW/architecture.md`: the Shell row, the diagram, and the egress sequence, which
  showed the Warden calling the SOC directly; the Warden writes the ledger and the SOC
  reads it
- `pyproject.toml`: an `import-linter` contract for `sletchy.cli`, identical to the AST
  test's list, and a drift test holding them equal
- The Shell may reach the Warden only through its supervisor, which #69 builds. That
  change to the CLI's list is made with #52, which needs it, and not before

## Known gaps

- **Planes in one process share the Kernel's signing key.** An entry's `plane` says which
  plane claims to have written it, not which did. Proving it would need the SOC in its own
  process with its own key
- The bounded telemetry store in decision 4 is designed, not built
