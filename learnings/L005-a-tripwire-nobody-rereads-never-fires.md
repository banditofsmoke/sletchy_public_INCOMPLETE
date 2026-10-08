# L005 - A condition written where nobody looks is not a tripwire

**2026-08-28, auditing the docs after Wave 2's first half landed.**

## What happened

Two claims in the repo carried conditions attached to them:

- `COVERAGE.md`: the firewall step is *"unverified until the Wave 2 sandbox bed exists"*
- `panic.py`: `processes_terminated` is zero because *"there is nothing Sletchy launches yet"*

**Both conditions had already fired.** `winjob` merged on 2026-08-14; it *is* the sandbox
bed, and it launches plenty. The comments stayed as written for two weeks, through three
subsequent PRs, and were read as current by anyone who opened those files - including me.

The `panic.py` one was the worse of the two, because it under-claimed. A reader would
conclude panic had an unimplemented feature, when what it actually has is an **untested
assumption**: the job object's `KILL_ON_JOB_CLOSE` kills the tree when the launcher dies,
so panic has nothing to terminate. That is a much more interesting statement, and it had
been sitting there disguised as a to-do.

## Why it happened

A condition is only a tripwire if someone re-reads it **at the moment it fires**. These were
written inside a code comment and inside a table row nobody had cause to revisit. The event
that satisfied them happened in a different file, in a different PR, weeks later.

The parent company `CLAUDE.md` records the same failure on the ESL product: issue #11 was
closed with correct reopen criteria written **in the closing comment of a closed issue**,
which nobody re-reads. The criteria fired unnoticed. This is that, in a different repo.

## The rule

**When you write a condition, decide who will be standing there when it fires.** If the
answer is nobody, it is not a tripwire - it is a note.

- **Name the thing that will satisfy it**, not the milestone: *"closes when `winjob` lands
  (#31)"* beats *"when the Wave 2 sandbox bed exists"*, because the first is greppable
- **Put a `Refs #N` in the issue that will satisfy it**, so closing that issue surfaces this
- **Re-read every conditional claim whenever a wave item lands**, not on a schedule. The
  audit that caught these was triggered by a status question, not by a process
- When a condition has fired, **the rewrite is the deliverable** - say what is true now and
  why, rather than deleting the row

Corollary: prefer a claim with no condition. *"This is not tested"* stays true until
somebody tests it. *"This is not tested until X"* rots the moment X happens.
