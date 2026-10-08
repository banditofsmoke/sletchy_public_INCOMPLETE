# L013 - A guard every test must remember is a guard one test will forget

**2026-10-03, looking at LAW 0 again before any work that needs an administrator.**

## What happened

The test suite runs on my only computer, many times a day. Its safety was a habit:
each test file redirected `SLETCHY_HOME`, each panic test stubbed the firewall step, each
test chose an in-memory key. Twenty test files each carried their own `SLETCHY_HOME` line.
Nothing guarded a file that forgot. `paths.home()` falls back to `var/` beside the
working directory, so in the main checkout a forgetful test would have written to my
own ledger and flags.

The LAW 0 scans had the same shape of hole. They read `src/` only, so the window's Rust
and TypeScript, the scripts and the launcher were never looked at, and they matched
case-sensitively: `-Verb RunAs` passed a check for `runas`. Of four host changes planted on
a branch, the old tests caught one; the new scan catches all four.

Nothing harmful had happened. Both holes were found by reading the law clause by clause
against its tests, not by an incident.

## Why it happened

A rule enforced by every caller is enforced by the most careless caller. Each test was
right on its own, and the guarantee was the sum of all of them remembering. A scan written
when the repo was one language kept scanning one language after a second and third arrived.

## The rule

- **Put a guard where no test can skip it.** For the suite that is `tests/conftest.py`,
  which runs before collection. Tests may still set their own values; the default is safe.
- **A safety scan covers every language the product ships**, and its positive control
  proves each kind of file was read. When a new language arrives, the control fails until
  the scan reads it.
- **A refusal that the code under test catches still fails the run.** A broad `except`
  must not be able to hide an attempt to change the machine.
- **The test of a safety net must not need the net.** Every probe in
  `tests/adversarial/test_host_shield.py` is harmless if its guard is missing: a help screen,
  a closed socket, a read of an entry that does not exist.
