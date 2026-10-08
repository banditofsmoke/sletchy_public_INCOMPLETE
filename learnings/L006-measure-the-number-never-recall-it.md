# L006 - Measure every number before writing it down

**2026-08-16 and again 2026-08-28, writing the README and auditing it.**

## What happened

Twice.

**First:** writing the README's status section, I stated the suite as *67 `law_zero`, 248
adversarial*. Both were from memory of an earlier session. Measured, they were **70 and
236**. Nobody would have caught it - the numbers are plausible, they move every PR, and no
test asserts them.

**Second:** the same README then disagreed with itself. Section 12 said *48 residual gaps
against 169 attack→test rows*; section 13.9, written in a later PR, said *47 against 160*.
Both were confidently phrased. One of them had to be wrong, and a reader had no way to tell
which.

A related near-miss: a commit message claimed a *"440 passed"* baseline. A clean worktree of
`main` collected **417**. The claim had been carried forward from a branch that had extra
tests on it.

## Why it happened

Numbers in prose have no owner. Code has tests, but a sentence saying "476 tests pass" is
verified by nothing, decays every merge, and reads as authoritative precisely because it is
specific. Recalling one feels like remembering; it is really guessing with false precision.

## The rule

**Run the command. Paste the output. Every time, including when you are sure.**

```bash
uv run pytest                  # not -q; addopts already sets it, and -qq hides the summary
uv run pytest -m law_zero
uv run pytest -m adversarial
```

- **A number you did not measure this session does not go in a document.** If measuring is
  impractical, write the shape ("a few hundred") rather than a false specific
- **Grep for the old number before writing a new one.** The README contradiction survived
  because the second author never looked for the first mention
- **Commit `Verified:` lines carry measured numbers only** - that is the whole point of the
  convention in `writing-conventions.md`
- A count that appears in more than one place should ideally appear in **one** place, with
  the others linking to it

Counting rows in `COVERAGE.md` has its own trap worth knowing: the residual-gap table's
header is `| Gap |`, not `| Attack |`, so a naive row count includes the header and reports
one gap too many. **Verify the counter, not just the count.**
