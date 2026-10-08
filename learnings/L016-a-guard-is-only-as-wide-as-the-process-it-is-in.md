# L016 - A guard is only as wide as the process it is in, and luck is not a guard

**2026-10-04, the first gate after I installed the eight `Sletchy` firewall rules (#33).**

## What happened

The rules went onto my machine as administrator, exactly as designed. The next full
gate failed two tests, and the reason was on my machine, not in the change being tested:

- `test_abuser_flood.py::test_switching_off_and_panic_still_work_on_a_full_ledger` ran a
  real `panic()` without stubbing its firewall step. Panic counted eight rules and reached
  for `Remove-NetFirewallRule -Group 'Sletchy'`. **The host shield refused it** before it
  started, which is what the shield is for
- `tests/e2e/test_bridge_process.py` runs the Kernel as its own process and presses Stop
  everything. That process was outside the shield. **It ran `Remove-NetFirewallRule`
  against the real firewall.** Windows answered *Access is denied*, only because the suite
  refuses to run elevated. The rules were checked afterwards: all eight intact

The gap was already written down. COVERAGE said *"a child process a test starts is
outside the in-process host shield"*. A known gap stays a gap until something walks
through it.

## Why it happened

Two guards each had an edge nobody tested against:

- **The firewall stub was a habit, not a guard.** Each panic test file carried its own,
  and a static check required it in files named `*panic*`. The flood test calls panic
  and is not named that. It was safe only while the host had no Sletchy rules, so its
  safety was a fact about the machine, not the test
- **The shield patched one interpreter.** `subprocess.Popen` and `socket` were guarded in
  the pytest process. A second Python started fresh, with none of it

Both had held for weeks because nothing on the host gave them a reason to fail. The first
real rule set was that reason.

## The rule

- **A guard covers every process the tests start, or it says which ones it does not.**
  Every Python a test starts now installs the shield through `tests/shield_site/` on
  `PYTHONPATH`, and its refusals fail the run like the parent's. Processes started with
  `-I` or the Kernel's stripped environment are not covered, and are contained by their
  own means
- **A default that every test gets beats a stub that every test must remember** (L013
  again). Panic's firewall step answers as a host with no Sletchy rules in every test,
  from `tests/conftest.py`
- **When the operator's machine changes state, run the gate before anything else.** The
  first host change Sletchy made for real was also the first time these tests met it
- **A test whose safety depends on what is installed on the host is not safe.** If
  installing Sletchy's own rules can change what a test does, the test was reaching the
  host
