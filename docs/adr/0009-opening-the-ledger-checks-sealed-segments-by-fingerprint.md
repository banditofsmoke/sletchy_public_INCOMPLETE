# ADR-0009 - Opening the ledger checks sealed segments by their fingerprint

**Status:** Accepted · 2026-10-03. I decided it on #116. Changes the segment size in
[LAW 0 §5](../LAW/00-do-no-harm.md) from 500 MB to 4 MB.

## Context

Every `sletchy` command, and every request from the window's Kernel bridge, opens the
ledger, and `Ledger.open()` verifies before it returns. Until this ADR it verified **every
entry**, then parsed every entry again to find the last one, and most callers then called
`verify()` a third time to count entries.

Measured on this machine (Windows 10 Pro 10.0.19045), in temporary ledgers:

| Ledger | Open, before | Open, after |
|---|---|---|
| 1,000 entries | 0.10 s | - |
| 40,000 entries, 19 MB | 4.55 s | - |
| 119,017 entries, 52 MB, about a year of ordinary use | **15.2 s** | **0.28 s** |
| 462,064 entries, 201 MB, a 7 MB active segment left unsealed | **65 s** | **2.4 s** |

The cost was linear, about 0.11 ms per entry, on every click. [ADR-0003](0003-ledger-is-the-spine.md)
had already named the mitigation, *"only the active segment needs full verification"*,
because each sealed segment ends in a signed entry committing to its whole hash. That had
not been built, and segments rotated at 500 MB (about a million entries), so even built it
would not have bounded the active one.

## Decision

1. **An ordinary open checks a sealed segment by its fingerprint.** It reads the file once,
   as bytes, and requires:
   - the SHA-256 of everything before the seal's line to equal the hash the seal signed
   - the segment's first entry to link to the previous segment's seal (`seq`, `prev_hash`,
     signature)
   - the seal to link to the entry before it, and its own signature to verify
2. **The active segment is checked entry by entry**, as before.
3. **Segments rotate at 4 MB**, about 8,500 entries, so the active segment, the part still
   parsed in full, stays small.
4. **A seal checks its segment entry by entry before committing to it.** An ordinary open
   trusts a sealed segment's fingerprint, so a seal must never sign bytes that changed while
   the segment was active.
5. **Rotation happens before the next entry, not after the last one.** A problem the seal
   finds then refuses the new entry, rather than reporting failure for an entry already on
   disk (#104's lesson).
6. **`sletchy ledger verify` still checks every entry**, every signature. It is `verify()`;
   only `Ledger.open()` uses the fingerprint path.
7. **Nothing verifies twice.** `status`, the self-check and the window take the count the
   open already established (`Ledger.length`).

## Reasoning

**Why this is as strong as checking every entry, against anyone without the key.** Changing,
removing or reordering any byte inside a sealed segment changes its SHA-256, and the hash it
must match is inside an entry signed with the key. Deleting or reordering whole segments
breaks the link from one segment's seal to the next segment's first entry. Cutting entries
off the end is the keychain mark's job (#99). The only thing an ordinary open no longer
re-checks is each signature *inside* a sealed segment. Those bytes are covered by the signed
fingerprint, and the seal checked them when it was written.

**Why 4 MB.** The active segment is the part that still costs 0.11 ms per entry. At 4 MB it
is at most about 0.9 s; at 500 MB it was minutes. Sealed segments cost their bytes at about
200 MB/s (SHA-256 plus the read, measured here), which is now the cost that grows with the
ledger.

**Why not cache which segments were verified.** A note under `var/` that says "segment 3
verified" can be written by anything that can write `var/`, which is exactly the attacker the
ledger guards against. Out, permanently (#116).

## Consequences

**Good**
- A year of ordinary use opens in about 0.3 s instead of 15 s; 200 MB in 2.4 s instead of 65 s.
- The window stops getting slower with every click Sletchy records.
- Rotation is no longer theoretical. At 500 MB no real ledger had ever sealed a segment; at
  4 MB the seal path runs about every 8,500 entries, and is tested.

**Costs, stated**
- **Opening still grows with the ledger**, through hashing: about 6 s at #101's 1 GB ceiling,
  extrapolated from the 200 MB/s measured. The long-running Kernel (#59) is the fix: check
  once at start, then only what is new.
- **A seal costs a full check of its segment**, about 0.9 s once per 8,500 entries, inside
  the append that triggers it.
- **More files.** 250 segments at 1 GB. Each is read once per open; nothing else lists them.
- **Segments sealed before this ADR were not checked when they were sealed.** None exists in
  practice: no real ledger reached 500 MB.

## Alternatives rejected

- **Keep verifying everything on every open.** Measured above; it fails the window.
- **Smaller segments alone.** Bounds the active segment but still re-parses every sealed one.
- **A cache of verified segments under `var/`.** Forgeable by the attacker the ledger is for.
- **A long-running Kernel now (#59).** The biggest win, but it is the first thing that would
  run continuously, so it waits for #62 as [BOARD.md](../../workload/BOARD.md) says.
