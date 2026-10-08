# L015 - The gate measures one tree, so hold it still, and keep every step's output

**2026-10-04, the day #146's first sensor landed.**

## What happened

The gate (the full suite, then `law_zero`, then `adversarial`, then lint, types, imports and
the secret scan) takes about eight minutes on this machine. Three times that day, what it
reported could not be trusted:

- **Files changed while it ran, twice.** Once a new, unfinished module was written into
  `src/` during the run; format and mypy then failed on code that was never meant to be in
  that branch. Once three files were fixed during the `adversarial` step; that run measured a
  tree that existed for no single commit. Both runs had to be thrown away and repeated.
- **One step's output overwrote the next.** The gate script wrote every step to the same
  temporary file and kept only its last lines. A failure in the full suite was reduced to
  "1 failed" with its name lost, because the `law_zero` step had already replaced the file.
  The failure turned out to be a real race in the ledger (#149), and it had to wait for a
  second occurrence to be named.

## Why it happened

Waiting for a long run feels like idle time, and the worktree was the nearest place to
use it. A test run is a measurement, and a measurement of something that moves while it is
measured describes nothing. The shared output file was a script written for passing runs:
on a pass, nothing is lost by overwriting.

## The rule

- **Commit, then start the gate, then touch nothing in that worktree until it ends.** Write
  the next thing in the scratchpad, or work on GitHub, and move it in afterwards.
- **Each gate step keeps its own output file**, and the summary prints the names of any
  failures, so a failure is named the first time it happens.
- **A failure the change could not have caused is filed, not re-run until it passes.** Then
  the gate is run again in full, and the PR says which run its numbers come from.
