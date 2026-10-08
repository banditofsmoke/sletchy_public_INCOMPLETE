# L007 - CI runs a platform your probes were never tried on

**2026-08-14, PR #45 (the `winjob` backend).**

## What happened

The shared conformance suite was rewritten to use platform shell probes instead of
`sys.executable`, because Python is not available inside an AppContainer. On Windows this
worked. The ubuntu CI lane went red.

The POSIX branch of the probes called `cat` and `sleep` **by bare name**. Sandboxed children
are given `PATH=""` deliberately - an inherited PATH is how a contained process finds an
interpreter it was never meant to reach. So every POSIX probe exited **127, command not
found**.

The suite reported that as *"subproc cannot read its own workspace"*: a containment
assertion, passing, for a reason that had nothing to do with containment. On the wrong day
that reads as a stronger sandbox than we have.

## Why it happened

The empty-PATH decision was made in the Windows backend, where probes are `cmd` builtins and
need no PATH. The POSIX branch inherited the constraint without inheriting the workaround,
and it is a branch that never runs on the development machine - it exists only in CI.

**A code path you cannot run locally is a code path you are guessing about.**

## The rule

- **Resolve every probe binary to an absolute path on the host, before the sandbox starts.**
  `_posix_bin()` exists for this: it finds the real `cat` and `sleep` in the parent, where
  PATH still works, and passes the absolute path in
- **Add a guard test that asserts the property**, not just a fix. This repo has one:
  every probe binary must be an absolute path that exists. It fails on the machine that
  writes the probe, not two lanes later
- **Exit 127 is never a containment result.** Neither is 126, nor "the file was not found".
  Treat "the thing did not run" as a distinct outcome from "the thing was denied" -
  [L001](L001-a-probe-needs-a-positive-control.md) again
- Where a branch only executes in CI, say so in a comment, and note what does and does not
  type-check there. `mypy platform = "win32"` makes every POSIX branch unreachable to the
  checker, which is recorded as a residual gap rather than left to be discovered
