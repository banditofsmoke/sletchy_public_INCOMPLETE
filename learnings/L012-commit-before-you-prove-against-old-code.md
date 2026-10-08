# L012 - Commit before you prove a test against the old code

**2026-10-03, proving the #115 fix's test against `origin/main`.**

## What happened

Every fix in the second thread is proven the same way: swap the old source file back in,
run the new tests, see them fail, restore the new file. For #115 the fix to
`kernel/ledger/chain.py` was written but **not yet committed** when the old file was
swapped in:

```
git show origin/main:src/sletchy/kernel/ledger/chain.py > src/sletchy/kernel/ledger/chain.py
uv run pytest ...                      # the new tests fail, as they should
git checkout -- src/sletchy/kernel/ledger/chain.py
```

`git checkout --` restores the file **from the index**, which still held `main`'s version.
The fix was gone. It was rewritten from the conversation, re-tested and re-measured. Nothing
reached `main`, and the only cost was the rework. But the same three lines, run on a fix
nobody could reconstruct, would have lost it silently.

## Why it happened

"Restore the file" sounds like undoing the swap. It is not: git restores what it
last recorded, and the fix had never been recorded. The swap overwrote the only copy.

## The rule

- **Commit a work-in-progress before swapping any old file in.** `git commit -m "wip: ..."`
  on the branch (never on `main`), then swap, run, and restore with
  `git checkout HEAD -- <path>`, which restores the committed fix. The WIP commits squash
  away when the PR merges.
- **Restore from `HEAD`, never from the index, after a proof run,** and check
  `git status --short` shows nothing changed before going on.
- A proof against old code also needs the old code to *import*. When a test names
  something the old code lacks, add the smallest stub that lets it load, say so in the PR,
  and make sure the stub cannot make a test pass (an empty `unreadable()`, an ignored
  `lock_wait`).
