# L001 - Every isolation probe needs a positive control that must succeed

**2026-08-13, the AppContainer spike ([ADR-0005](../docs/adr/0005-appcontainer-findings.md) §4).**

## What happened

The spike ran a set of probes inside an AppContainer, each asserting that something was
**denied**: reading a file outside the workspace, reading across volumes, touching a
protected directory. Every assertion passed. The container looked excellent.

It was not excellent. The probe could not open its own output stream, so the child process
died before running any of the operations being tested. **Every "denied" was really "never
attempted."**

This happened across three runs before it was caught.

## Why it happened

A suite made entirely of should-fail assertions has a degenerate solution: *nothing runs*.
Total failure is indistinguishable from total containment, and the test output looks
identical - in fact it looks better, because there are no partial results to explain.

The bug is structural, not careless. Any suite shaped this way has the same hole.

## The rule

**Every isolation probe set must contain at least one assertion that must SUCCEED**, run
through the same machinery, in the same container, in the same session.

- Contained + should-be-denied → the measurement
- Contained + should-be-allowed → proves the child ran at all
- Uncontained + should-be-allowed → proves the target was reachable at all

If the positive control fails, **discard the whole run**. Do not report the denials; they
mean nothing.

This has now paid for itself three separate times: the original spike, the `winjob`
tree-kill test ([L003](L003-a-blocked-dialog-is-a-live-process.md)), and the egress spike,
where control C3 was the only thing separating *"the container permits sockets"* from
*"the container was never applied"* ([ADR-0006](../docs/adr/0006-egress-binding-findings.md) §1).
