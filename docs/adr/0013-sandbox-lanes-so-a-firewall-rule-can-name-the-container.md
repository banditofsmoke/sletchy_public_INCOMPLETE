# ADR-0013 - Sandbox lanes, so a firewall rule can name the container

**Status:** Accepted · 2026-10-04 · refs #33, #71 · builds on [ADR-0005](0005-appcontainer-findings.md), [ADR-0006](0006-egress-binding-findings.md)

## Context

#33 asks for a Windows Firewall rule that keeps a sandboxed program off the network
directly, so the proxy (#32) is the only way out. A rule names an AppContainer by its
SID (`-Package`), and Windows derives that SID from the container's name: SHA-256 of
the lowercased name, measured on 10.0.19045 and held equal to Windows by
`test_the_derivation_is_the_one_windows_uses`.

Until now `winjob` named every container for its run (`Sletchy-s` and 16 random hex
digits). So no SID existed before a run, and a rule written once could cover none of
them. Adding a rule per run would need elevation per run, which LAW 0 §3 forbids.

The firewall cannot name "every Sletchy container" either. A rule naming
`ALL APPLICATION PACKAGES` would reach every Store app on the machine.

ADR-0006 finding 5 changed what is at stake: the container already refuses TCP to
other machines with no rule. The rule is the second lock there, and the only one for
UDP and IPv6 until those are measured. *(2026-10-05: finding 9 measured UDP. The
container drops it too, so the rule is the second lock for UDP as well; IPv6 is still
unmeasured, #173.)*

## Decision

1. **Eight fixed lanes.** A sandbox's container is named `Sletchy-lane0` to
   `Sletchy-lane7` (`SANDBOX_LANES`, in the Kernel, because the Warden claims lanes
   and `sletchy panic` and `sletchy install-rules` name them). Their SIDs are known
   before any run, so eight rules written once cover every run.
2. **One run per lane, held by a named mutex** in the logon session's namespace
   (`Local\Sletchy-laneN`), not a file:
   - it is the same mutex for every Sletchy on the session, whichever `var/` it uses,
     so two test suites side by side never draw the same lane
   - Windows releases a mutex whose holder dies, so a crash cannot leave a lane held
   - a thread may take a mutex it already holds, so the process also keeps a set of
     the lanes it holds, and a second take of one is "in use"
   - a contained process has its own object namespace, so it cannot touch a lane
3. **A lane whose profile is still on the machine is skipped, never reused.** It was
   left by a run that never reached its `finally`, and whatever was granted to its SID
   may still be granted. The grant is revoked before the profile is deleted, so a
   failed revoke leaves the profile too, and the lane stays marked. `sletchy panic`
   clears it.
4. **With no lane free, the run is refused** and the refusal recorded. It never gets a
   container outside the lanes, which the rules would not name.
5. **Panic reverts a lane's record only while it holds that lane.** A dead run's record
   can name a lane a live run holds now; that run's profile and grant are not the
   record's to undo. Records written before lanes (`Sletchy-<context_id>`) still
   revert as before. The forgery checks of #94 are unchanged: the SID must be the one
   Windows derives from the record's profile name.
6. **The rules** (`sletchy install-rules`): one per lane, in the `Sletchy` group only.
   Each **blocks** outbound traffic, every protocol, every network profile, to every
   address except this machine's own (`127.0.0.0/8`, `::1`), for that lane's SID. It
   allows nothing and opens nothing. Loopback is left out on purpose: the proxy
   listens there.
7. **The one elevated step never elevates itself.** Unelevated it prints the plan and
   says how to run it from an administrator PowerShell. Elevated, it prints the plan
   in words and as the exact commands, waits for `yes`, records on the ledger, adds
   the rules, and **reads them back**: the result recorded is what the firewall holds,
   checked rule by rule, and the address coverage compared as ranges, not as text.
   `--check` does the read-back with no administrator; `--remove` takes the group away.
8. **Panic does not ask for elevation either** (the question COVERAGE left to #33). An
   unelevated panic reports the rules it could not remove. They only restrict
   Sletchy's own sandboxes, so leaving them is never the unsafe direction; removing
   them is `sletchy install-rules --remove`, or panic, as administrator.

## Consequences

- `winjob` still does **not** claim `confines_network`. The rules are installable;
  whether Windows honours a rule naming a non-packaged container's SID is measured by
  the probe's second round, by the operator, not by any test (LAW 0 §6)
- At most eight sandboxes run at once on one logon session. A ninth is refused
- A lane left behind is out of use until panic clears it. Eight left behind and no
  sandbox runs: failing closed, and said in the refusal
- Anything running as the operator can hold all eight mutexes, and so stop every
  sandbox run. It cannot remove the rules without elevation
- A run's SID now comes back on later runs. What made a random name safe, a SID no
  later run could hold, is replaced by decision 3: a lane with anything left behind is
  never handed out
- Every product container is created by `winjob`, under a lane. The spike scripts and
  one test create containers by other names; the rules do not cover those and do not
  need to

## What this does not answer

- ~~**Whether the rules bind.**~~ They do, for TCP over IPv4: with the container's own
  lock opened, a lane is refused at once and a container no rule names is not
  ([ADR-0006](0006-egress-binding-findings.md) finding 8)
- ~~**UDP from inside the container, with or without the rules.**~~ Both drop it
  (ADR-0006 finding 9, read from Windows' drop log)
- **IPv6 from inside the container.** The operator's machine has no IPv6 route (#173)
- **A rule removed by an administrator.** The SOC could notice; nothing does yet
