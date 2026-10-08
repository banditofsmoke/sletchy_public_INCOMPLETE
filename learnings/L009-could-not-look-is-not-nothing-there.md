# L009 - "Could not look" is not "nothing there"

**2026-10-02, a LAW 0 audit of `sletchy panic` (#78).**

## What happened

`panic`'s firewall step ran:

```
netsh advfirewall firewall delete rule group=Sletchy
```

Run by hand on this box, unelevated, with a rule-count snapshot either side:

```
before: total=2819 sletchy_group=0
'group' is not a valid argument for this command.
netsh exit: 1
after:  total=2819 sletchy_group=0
```

`netsh` does not accept `group=` on `delete rule`. **The step had failed on every run since
Wave 1**, and the code read every non-zero exit as *"nothing to remove"*, so every run
reported a clean firewall.

The only test that touched the step asserted that the text `group=` appeared in
`panic.py`. It did - in the command that could not run. **The test passed because of the
bug.**

The same audit found three more of the same shape in the same file: a failed `icacls`
revoke, a failed profile delete, and `clear_runtime` each reported success while deleting
the journal entry that was the only record of a change still on the host.

## Why it happened

Three things, each reasonable alone:

1. **The benign failure was made the default branch.** `netsh` does exit non-zero when no
   rule matches, so "non-zero means nothing to delete" was true for one case and silently
   swallowed every other
2. **The guard tested text, not effect.** A structural test can prove a command *says*
   group; only running it proves a command *does* anything
3. **Every behavioural test stubbed the step - correctly.** LAW 0 §6 forbids tests touching
   the real firewall. With all of them stubbed and the one unstubbed test reading source,
   **nothing in the suite ever ran the command**. The coverage report said so: 50% on
   `panic.py`, the lowest file in the repo, on the command LAW 0 calls first-class

This is L001 and L007 meeting: a should-succeed path with no positive control, on a step
CI never actually executed.

## The rule

**A step that changes the host proves the change by re-reading the host, and "I could not
look" is an error, never a zero.**

- Count before, act, count again. Report the difference as the result and anything left
  as an error. An exit code is a claim; a recount is evidence
- A query that fails, times out, or returns something unparseable raises. It is never
  folded into the empty answer
- When a mutating step must be stubbed in tests (LAW 0 §6), split off its **read-only
  half** and run that for real as a positive control. Here that is
  `test_the_firewall_count_really_runs_on_windows`. It changes nothing and needs no
  elevation, and it would have failed on the first CI run of the old code
- A test that asserts a substring of a command line is documentation, not evidence. If
  one exists, it needs a sibling that runs something
- A record of an unfinished undo is deleted only after the undo is proven. Forgetting
  first turns one failure into a permanent, invisible one

## It happened again, 2026-10-03

The user stories found the same shape three more times, each already shipped:

- **One unreadable journal line** was skipped by panic, which reported `clean`, and by the
  self-check, which said *"no unfinished changes"* (#103, fixed in #121)
- **A ledger that did not exist** was reported as `0 entries, chain verified` by a read command
  run from another folder, which also created the empty ledger it then verified (#102, #123)
- **A deleted ledger** still reads as verified, because nothing outside it records how long it
  was (#99, decided, being built)

Each is the rule above, applied to a read instead of a host change: **absent, unreadable and
empty are three different answers**, and only the last one is zero.

