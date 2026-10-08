# L003 - A stuck GUI dialog is a live process, and it will satisfy a liveness check

**2026-08-14, building the `winjob` backend (#31 / PR #45).**

## What happened

The tree-kill test needed a detached grandchild: a process that breaks away from its
parent, so that killing the job proves the *whole tree* dies rather than just the process
being waited on. The probe used `start` with an empty title argument:

```
cmd /c start "" cmd /c <spin>
```

`list2cmdline` escaped the empty string to `\"\"`. `start` then read `\\` as a program name
and **Windows popped a modal error dialog on the operator's desktop** - *"Windows cannot
find '\\'."*

The test passed.

It passed because **that dialog was a live process inside the job.** The assertion was
"something in the job is alive, then after the kill nothing is" - and a stuck message box
satisfies the first half perfectly. The containment claim was measuring a GUI error, not a
detached grandchild.

The operator saw the dialog on screen and reported it. Nothing in the suite would have.

## Why it happened

Three failures stacked, and all three are ordinary:

1. **Argument escaping.** There is no shell to unescape `""`, so the quoting that works when
   typed by hand becomes a literal argument
2. **Liveness is a weak predicate.** "A process exists" is satisfied by any process,
   including one that is doing nothing and will never do anything
3. **A GUI dialog is not obviously a process** to the person writing the assertion

## The rule

**Assert on work performed, not on existence.** A process that cannot make progress must
not be able to satisfy a liveness check.

Concretely, in this repo: `JobObject.cpu_time_ns()` exists because of this. The tree-kill
control now requires the child to have **accrued CPU time**, which a blocked message box
cannot fake. Existence alone is never the assertion.

And two supporting rules:

- **Never pass a pre-quoted string as an argv element.** Pass the arguments separately, or
  omit them. If an argument is optional, leave it out rather than passing empty
- **A dialog on the operator's desktop is a test failure**, whatever the exit code says.
  This machine is the operator's only computer; the suite must never put anything modal on
  it

This is the third time [L001](L001-a-probe-needs-a-positive-control.md)'s theme has bitten:
the test was green for a reason that had nothing to do with the control.
