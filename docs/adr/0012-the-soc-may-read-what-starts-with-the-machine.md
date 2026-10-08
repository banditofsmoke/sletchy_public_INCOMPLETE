# ADR-0012 - The SOC may read what starts with the machine

**Status:** Accepted · 2026-10-04. I decided it, for #146.

## Context

The LAW 0 scan of shipped code refuses some text anywhere it appears, read or write,
because writing there changes the machine:

- the registry's startup keys (`...\CurrentVersion\Run`): a program put there starts
  at every logon
- the elevated run level of a scheduled task, and the tool that creates tasks
- the registry module, and the service control manager's rights

That strictness is deliberate (L013): a scan that tries to tell reads from writes by
reading code can be talked out of it, and building a refused name in pieces to slip
past it would defeat the point.

But the SOC exists to watch the machine it runs on, and the machine on which it was
being built had two things set to start by themselves that nobody had explained: an
automatic service, running as the most powerful account, whose program had been
removed with the product that installed it; and a scheduled task starting a monitoring
tool with administrator rights at every logon. A sensor that may not read where
startup is configured cannot name either.

In my words, 2026-10-04: *"let it read start up entries, thats the whole point is to monitor
not only whats going on IN Sletchy, but to help monitor the system its on."*

## Decision

1. **One shipped file may name one catalogue entry**:
   `src/sletchy/soc/sensors/_startup.py` may name the registry's startup keys
   ("start at boot"). The exemption is a table in `tests/adversarial/test_law_zero.py`
   (`READ_ONLY_SENSORS`), pinned by a test, so widening it is a reviewed change.
2. **The exemption holds only while the file can only read**, proven by its own tests:
   - every Windows call it binds is a read (`RegOpenKeyExW`, `RegEnumValueW`,
     `RegEnumKeyExW`, `RegQueryValueExW`, `RegCloseKey`, `WinVerifyTrust`)
   - every key it opens is opened with `KEY_READ`
   - its Task Scheduler query names no call that changes a task
   - its signature check never goes online
3. **Every other catalogue entry still applies to that file**, and a control proves
   the exemption is not empty: without it, the file trips exactly the one rule.
4. **Nothing else was loosened.** The registry module is not imported; the reader uses
   the documented read calls. The service list is read from each service's own registry
   key, not through the service control manager. A task's elevated run level is
   recognised as "not least privilege", so no command names it: the runtime host
   shield, which refuses that word in any command a test starts, needed no exception.
5. **Reading the machine's startup needs `soc_watch_machine`**, like the System log
   (ADR-0011 decision 5).

## Consequences

- `sletchy-soc startup` reads four places: the startup keys, the Startup folders,
  automatic services, and scheduled tasks that run at boot or logon. On the machine it
  was built on: 140 entries, none unreadable, in 1.6 s, and exactly the two findings
  above
- A program started from a user-writable folder is a finding only when no publisher
  Windows trusts has signed it. Chat, music and sync programs install for one user and
  are signed; naming them every day would teach the operator to ignore the finding
- **Persistence the sensor does not read** is written down in
  `tests/adversarial/COVERAGE.md`, not implied covered
