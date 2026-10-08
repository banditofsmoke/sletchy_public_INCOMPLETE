# L008 - Never generalise one measured dimension to another

**2026-08-28, phase 1 of the egress spike ([ADR-0006](../docs/adr/0006-egress-binding-findings.md), #71).**

## What happened

`winjob` runs its children in an AppContainer with **zero capabilities**. Filesystem denial
was measured thoroughly in [ADR-0005](../docs/adr/0005-appcontainer-findings.md): denied
across volumes, denied for a directory the parent created seconds earlier, denied until an
explicit per-execution ACE is granted. It is a genuinely strong control.

The natural inference - *a container with no capabilities denies the network too* - is
false. Measured:

```
C3  read file outside workspace, CONTAINED (must FAIL)    exit=1
M1  curl to a loopback listener, CONTAINED                exit=0
```

**Same execution. Same container. File denied, socket allowed.**

The only reason this was caught rather than shipped as a claim is that `confines_network`
was left `False` with a test enforcing it, on the grounds that it had not been measured.

## Why it happened

"Sandbox" is a single word for a bundle of unrelated mechanisms. AppContainer capabilities
gate different subsystems through different enforcement paths, and the absence of a
capability does not uniformly mean denial - `internetClient`, `privateNetworkClientServer`
and loopback are three separate questions with three separate answers, none of which follow
from the filesystem result.

The failure mode is linguistic as much as technical. Once a control is described as
"strong", the adjective travels to dimensions nobody tested.

## The rule

**A capability model has one row per dimension, and every row is measured separately or
marked unmeasured.** Never one adjective for the whole thing.

- `Capabilities` in this repo is a set of independent booleans on purpose:
  `confines_filesystem`, `confines_network`, `enforces_resource_limits`,
  `kills_process_tree`, `strips_environment`. **Resist any urge to collapse them**
- **A backend claims a dimension only when a passing test measures that dimension.**
  `test_winjob_containment.py` asserts `winjob` does *not* claim `confines_network` - a test
  whose whole job is to stop an unmeasured claim appearing later
- In prose: *"strong for filesystem, resources, and process tree"*. **Never "strong"**
- When a control turns out not to cover a dimension, ask what *does*. Here the answer is the
  firewall rule, which promotes it from a second layer to the entire guarantee - a design
  consequence that would have been missed if the assumption had held

The corollary is the good news, and it is worth stating because the finding reads alarming
on its own: **loopback reachability is required for the proxy design to work.** A contained
process that could not reach loopback could never reach the mediating proxy. Measuring a
dimension tells you what the design needs, not only what it is missing.
