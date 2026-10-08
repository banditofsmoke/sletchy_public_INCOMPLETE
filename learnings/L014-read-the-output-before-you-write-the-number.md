# L014 - Read the output before you write the number, and never pipe away an exit code

**2026-10-03, the evening Wave 2's middle landed (#136 to #145).**

## What happened

Three times in one evening a check ran and its result was written down without being read.

- A commit said **"195 passed"** for a run that passed 145. Another said **"39 passed"** for
  17. In both, the commit was chained onto the test command with the count typed in advance,
  so the message was finished before the run was. Both were caught, and the PR bodies and
  squash messages carry the measured numbers, but the branch history holds the wrong ones.
- `scripts/public_check.py` was run on a PR body as `... | tail -3`. The pipe's exit status is
  `tail`'s, which is 0, so a body the check had refused was posted. CI's own copy of the check
  then failed the PR, which proved the CI step works, and the body was fixed. Locally, the
  refusal was never seen.
- A rebase conflict was resolved by a script whose guard refused to write the file. The next
  command in the chain staged the file anyway, with its conflict markers, and the rebase
  continued. It was caught on the next look, before anything was pushed.

**It happened again the next day, with the rule already written.** A rebase was run as
`git rebase origin/main 2>&1 | tail -1 && ...`. It stopped on a conflict; `tail` reported
success, so the chain went on, and a commit landed in the middle of the unfinished rebase
with conflict markers in `COVERAGE.md`. It was caught on the next look, resolved by hand
and nothing was pushed, but the rule had been known for a day and was not followed. Writing
a rule down does not make the hand follow it; reading each exit code by itself
(`cmd; echo "exit $?"`) is the habit, and from then on every step reported its own.

## Why it happened

Each was a chain of commands written as if the first would succeed. A chain runs the next
step whatever the last one said, unless something makes it stop. The number in a message
is a claim about a run, and a claim written before the run is a guess (L006).

## The rule

- **Never type a count into a commit before the command that produces it has finished and
  been read.** Run the check, read it, then write the message.
- **Never pipe a check whose exit code matters.** Read the exit code directly
  (`cmd; echo "exit $?"`), or use `${PIPESTATUS[0]}`. A pipe reports its last command.
- **After any guard refuses, stop the chain.** Join steps with `&&`, never `;` or a newline,
  when a later step must not run on an earlier failure.
