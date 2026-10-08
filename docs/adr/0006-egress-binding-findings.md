# ADR-0006 - Egress binding findings on Windows 10 Pro 19045

**Status:** Accepted · 2026-08-28, reopened 2026-10-04, closed 2026-10-05 · closes #71 ·
finding 11 added 2026-10-07 (#184)
**Measured on:** Windows 10 Pro, build **10.0.19045**, AMD64, Python 3.13.3, **non-elevated**

> **Phase 1, and phases 2-3 so far.** On 2026-10-04 the operator ran the phase 2-3
> probe's first round (#153), which answered the question phase 1 could not: **the
> container refuses connections to other machines** (finding 5). Later that day the rules
> were installed and both rounds ran, and the table did not change; nothing in it could
> see a rule (finding 7). Then the probe opened the container's own lock: **a rule
> refuses the lane it names, and nothing refuses the container no rule names. The rules
> bind, for TCP over IPv4** (finding 8). On 2026-10-05 Windows' own drop log named the
> filter behind every refusal: **both locks drop UDP as well, and with no rules the lane
> goes out** (finding 9). IPv6 is unmeasured: this machine has no IPv6 route (#173).
> Inward, a server inside the container is reached from outside it on loopback
> (finding 10, #175).

## Context

The egress design is one sentence: *"the proxy is the only way out, and the firewall makes
it non-bypassable."* Both halves were assumptions.

[ADR-0005](0005-appcontainer-findings.md) measured AppContainer's **filesystem** denial and
deliberately left network and registry unmeasured. `winjob` therefore does not claim
`confines_network`, and `test_winjob_containment.py` enforces that it never quietly starts
claiming it. This ADR begins closing that gap, starting with the half that needs no host
change at all.

## Method

One measurement, three controls. The controls are the point: a single *"the contained
process failed to connect"* is equally consistent with the binary never starting, the
listener never listening, or the environment being too stripped for winsock. All four runs
use the shipped `WinJobSandbox`, not a bespoke probe.

| | What | Why it exists |
|---|---|---|
| C1 | `curl --version`, contained | The binary runs *inside* the container |
| C2 | request to the listener, **un**contained | The listener is reachable at all |
| C3 | read a file outside the workspace, contained | **The container was actually applied** |
| M1 | request to the listener, contained | The measurement |

C3 is the one that took a second pass to add, and it is the one that makes the result
mean anything. Without it, *"the contained process reached the listener"* cannot be told
apart from *"the AppContainer was never in effect"*.

Endpoint: an HTTP listener this repo starts on `127.0.0.1`, ephemeral port. Nothing
external is contacted ([LAW 0 §6](../LAW/00-do-no-harm.md)). Probe:
[`scripts/spike/egress_probe.py`](../../scripts/spike/egress_probe.py).

## Findings

### 1. An AppContainer with zero capabilities does not deny loopback TCP

```
C1  curl --version, CONTAINED (control: binary runs)      exit=0
C2  curl to listener, UNCONTAINED (control: reachable)    exit=0
C3  read file outside workspace, CONTAINED (must FAIL)    exit=1
M1  curl to listener, CONTAINED (the measurement)         exit=0
```

Reproduced across three consecutive runs.

**In the same contained execution, the process was denied a file outside its workspace and
allowed a TCP connection to loopback.** The container was demonstrably in effect. It simply
does not confine this.

### 2. That is a requirement of the proxy design, not a hole in it

Worth stating plainly, because the instinct on reading finding 1 is that something is
broken.

A mediating proxy listens on loopback. **If a contained process could not reach loopback,
sandboxed traffic could never reach the chokepoint**, and #32 would be unbuildable as
designed. Phase 1 says the chokepoint is reachable.

The hole would be a contained process reaching a **non-loopback** address without passing
through the proxy. That is phase 1b, and it is not measured.

### 3. The capability is not the control, so the firewall must be

`confines_network=False` was the right call, and finding 1 sharpens why. It is not a
hedge pending confirmation - **an AppContainer without the network capability demonstrably
permits a socket**, so nothing about the container can be relied on for egress.

Every remaining guarantee therefore rests on the firewall app rule binding to the container
SID. **That makes phase 3 load-bearing rather than corroborating**, and it is the item that
can still invalidate #32.

> **Narrowed by finding 5 (2026-10-04).** This was written from a loopback measurement
> only. For a TCP connection to another machine, the container *is* a control: it was
> refused with no rule at all. The firewall rule becomes the second lock, not the only
> one, for that case. Loopback, UDP and IPv6 are unchanged by finding 5.

### 5. The same container is refused a TCP connection to another machine

The probe's first round, run twice by the operator on 2026-10-04 with no rule in place:

| | What | Run 1 | Run 2 |
|---|---|---|---|
| C1 | `curl --version`, contained (control: curl runs) | exit 0, 0.6 s | exit 0, 0.4 s |
| C3 | read a file outside the workspace, contained (control: applied) | exit 1, 0.4 s | exit 1, 0.3 s |
| U0 | connect to `192.0.2.1`, **un**contained | exit 28 (timed out), 5.1 s | exit 28, 5.1 s |
| M0 | the same, **contained**, no rule | **exit 7 (refused), 0.4 s** | **exit 7, 0.4 s** |

`192.0.2.1` is reserved for documentation and never routed. Outside the container,
nothing on the machine refused the connection: it waited the full five seconds for an
answer that never came. Inside it, the same connection was refused at once. Both
controls passed, so curl ran, and the container was applied.

Together with finding 1: **an AppContainer with no capabilities reaches loopback and is
refused other machines.** That is the shape the egress design needs. A contained program
can reach the proxy on loopback, and cannot go around it to the internet over TCP.

What finding 5 does not show:
- **The mechanism.** It is consistent with Windows' AppContainer network isolation: a
  container without the `internetClient` capability. That was not observed directly.
  *(Observed in finding 8: the refusal is `WSAEACCES`, and `internetClient` alone lifts
  it.)*
- **UDP, IPv6, or any address but one.** One IPv4 address over TCP was measured
- **What a rule adds.** The probe's second round (M1) needs the rule added in an
  administrator PowerShell before Enter is pressed. In both runs it was not, so the probe
  measured nothing further. The rule group held 0 rules before and after both runs

### 6. On another Windows, a container could not reach loopback at all

Found by CI on 2026-10-04, in the first run of #32's end-to-end test: on GitHub's
**Windows Server 2025** runner, a contained `curl` given the proxy's loopback address
timed out after 10 seconds. It was not refused: nothing answered. On this machine,
10.0.19045, the same test passed, which is finding 1 again.

So finding 1 is a fact about a build, or a configuration, not about AppContainer. Where
loopback is closed to a container, the proxy cannot be reached either, and a sandbox
has no way out at all: the safe direction, but not the design. The end-to-end test now
measures loopback first, with no proxy, and says so when it is closed. Which setting
closes it on the runner is not known.

### 7. With the rules installed, the table did not change, and could not have

The operator, 2026-10-04: the probe with no rules, `sletchy install-rules` in an
administrator PowerShell (all eight installed and read back as planned), then the probe
again, unelevated.

| | What | No rules | With the rules |
|---|---|---|---|
| C1 | `curl --version`, contained | exit 0, 0.5 s | exit 0, 0.4 s |
| C3 | a file outside the workspace, contained | exit 1, 0.3 s | exit 1, 0.4 s |
| L | the loopback listener, contained | exit 0, 0.3 s | exit 0, 0.4 s |
| TU | TCP to `192.0.2.1`, **un**contained | exit 28, 5.1 s | exit 28, 5.1 s |
| T | the same, contained | exit 7, 0.3 s | exit 7, 0.3 s |
| DU | UDP (TFTP) to `192.0.2.1`, **un**contained | exit 28, 5.1 s | exit 28, 5.1 s |
| D | the same, contained | exit 28, 5.4 s | exit 28, 5.4 s |
| 6U | TCP to `[2001:db8::1]`, **un**contained | exit 7, 0.1 s | exit 7, 0.1 s |
| 6 | the same, contained | exit 7, 0.4 s | exit 7, 0.3 s |

**Loopback stayed open with the rules installed**, which the proxy needs: the rules'
exclusion of `127.0.0.0/8` works as written. Beyond that, the table says nothing about
the rules, for a reason on each row:

- **TCP**: the container refuses before any rule is consulted (finding 5). A second lock
  cannot be seen while the first one holds
- **UDP**: the target never answers, so a datagram dropped and one sent and unanswered
  both time out. The probe printed *"went out and timed out: NOT stopped"*. It could not
  know that, and no longer says it
- **IPv6**: this machine has no IPv6 route (`Get-NetConnectionProfile`: IPv6
  `NoTraffic`), so even the uncontained control failed at once, and nothing reached the
  firewall

Checked read-only the same day, so "Windows is not enforcing the rules" is not the
explanation either:

- Windows Defender Firewall is on for the Private and Public profiles, both of them
  active; no interface is excluded; local rules are honoured (`LocalPolicyModifyState` 0)
- Avira Security is registered with Security Center as a firewall, but not with Windows
  Firewall as a product that takes over its rules (`HNetCfg.FwProducts`: none), so
  Windows still enforces its own
- The `Sletchy` group is enabled, and `netsh` reads each rule as Out, Block, every
  profile, the planned addresses
- WFP's own filter list needs elevation to read, so which filter refused row T is not
  known

**The instrument for the question that is left: open the first lock.** The probe now
gives the `internetClient` capability to two containers of its own: a lane, whose SID a
rule names, and a control under a fresh name that no rule names. With the rules
installed, the lane refused at once while the control times out is the rule binding.
Measured before it was trusted: a child launched that way carries `S-1-15-3-1` in its
token, and one launched as `winjob` launches carries no capability. That round needs no
elevation, because the rules are already installed.

### 8. With the container's own lock opened, the rule refuses the lane

The operator, 2026-10-04, unelevated, with the eight rules installed, running the probe as
#164 left it. Every control passed: curl ran in both kinds of container (C1, C4), the
container was applied (C3), the address never answers (TU timed out), and loopback was
reached (L). The rules read as installed before and after the run.

| | What | Exit | Time | curl's own words |
|---|---|---|---|---|
| T | TCP to `192.0.2.1`, a lane, no capability | 7 | 0.3 s | `connect ... failed: Bad access` |
| OT | the same, with `internetClient`, a name no rule names | 28 | 5.1 s | `Connection timed out after 5010 milliseconds` |
| RT | the same, with `internetClient`, **a lane** | **7** | **0.1 s** | **`connect ... failed: Bad access`** |
| D, OD, RD | UDP (TFTP) to `192.0.2.1`, each kind of container | 28 | 5.1 to 5.3 s | `Connected`, then `Operation timed out`; no error |
| 6U, 6 | TCP to `[2001:db8::1]`, outside and inside | 7 | 0.1 to 0.3 s | `Network unreachable`, outside the container too |

**The rule binds, for TCP over IPv4.** OT and RT differ only in the container's name: the
same launcher, capability, job, token and command. The one a rule names was refused in a
tenth of a second; the other's attempt went out and waited the full five. A Windows
Firewall rule scoped with `-Package` to a container SID applies to a Win32 process
launched into that container, which is what ADR-0013's lanes assumed.

**Finding 5's mechanism is observed too.** Row T's refusal is `Bad access`, curl's text
for `WSAEACCES`, the error a connection blocked by the Windows Filtering Platform
returns. Granting `internetClient` and nothing else let the same connection go out (OT).
So the container's own lock is Windows' network isolation of a container without that
capability, as finding 5 supposed.

What finding 8 does not show:

- **UDP.** No row printed an error, including D, where the container's own lock was
  closed. Either a blocked datagram is dropped silently while the send reports success,
  or nothing blocks UDP; an address that never answers cannot tell those apart. The
  rules carry no protocol condition, so the filter that refused RT is the one a datagram
  would meet. That is an inference, not a measurement (L008)
- **IPv6.** This machine has no IPv6 route
- **The new rows with no rules installed**, which would show RT going out like OT. OT
  already shows that the capability opens the lock. What that round would add is ruling
  out something other than the rule treating a lane's name differently, and nothing is
  known to

### 9. Windows' drop log: both locks drop UDP too, and the rule is what refuses the lane

On 2026-10-05 the operator ran the probe twice more, unelevated, between administrator
steps that only read or that `sletchy install-rules` makes: whether Windows buffers network
events (`netsh wfp show options optionsfor=netevents`: `on`); `install-rules --remove`;
the probe's round with no rules; the events for `192.0.2.1` (`netsh wfp show netevents
remoteaddr=192.0.2.1`); the rules added back; the probe's round with them; the events
again; and the filters that match `192.0.2.1` (`netsh wfp show filters`). The probe
printed what it printed before. The drop log said what the probe could not:

| Round | Row | Protocol | Dropped by |
|---|---|---|---|
| no rules | T (a lane, no capability) | TCP | `Block Outbound Default Rule` |
| no rules | D (the same) | UDP, 3 datagrams | `Block Outbound Default Rule` |
| no rules | RT, RD, OT, OD, TU, DU | | no drop recorded; RT timed out like OT (28, 5.1 s) |
| with rules | T; D | TCP; UDP, 3 datagrams | `Block Outbound Default Rule` |
| with rules | **RT** | **TCP** | **`Sletchy-lane0: no direct network`** |
| with rules | **RD** | **UDP, 3 datagrams** | **`Sletchy-lane0: no direct network`** |
| with rules | OT, OD, TU, DU | | no drop recorded |

Each event was matched to its row by time and local port: T's ports, 64155 and 64195, are
the ones curl printed, and RT's is 64205. Every drop names lane0, the lane both rounds took,
and every one is at the ALE connect layer for IPv4. The three datagrams per row are curl's
TFTP retries, two seconds apart. `Block Outbound Default Rule` belongs to the firewall's
service-hardening provider (`FWPM_PROVIDER_MPSSVC_WSH`): it is Windows' default block for a
container without a network capability, the lock finding 5 found. The lane's rule belongs
to the Windows Firewall provider (`FWPM_PROVIDER_MPSSVC_WF`).

- **UDP is refused, by both locks, silently.** A dropped datagram returns no error to the
  program that sent it, which is why findings 7 and 8 read UDP as silence. The rule
  carries no protocol condition, and the drop log now shows what finding 8 could only
  infer (L017)
- **The rule is what refuses RT.** With no rules, RT went out like OT and nothing dropped
  it; with the rules, the lane's own rule did. The no-rules round finding 8 lacked is run
- **Removal works on a real host.** `install-rules --remove` took 8 rules and `--check`
  read none; `install-rules` put 8 back, read back exactly as planned
- **The self-check saw the gap.** With the rules off, its network line failed: `85 / 100`,
  with a ceiling of 100 (#169)

Not shown: **IPv6**. This machine has no IPv6 route, so an IPv6 attempt fails with
`Network unreachable` before any filter, inside the container and out, and the drop log
holds nothing for it (#173). **The registry**, untouched.

### 10. A server inside the container is reached from outside it, on loopback

Finding 1 measured loopback outward: a contained program reaches a listener here. Running
a model server inside a sandbox (#175) needs the other direction, which was unmeasured.
`scripts/spike/loopback_server_probe.py` ran a small server, under a copy of the
interpreter inside the workspace (the method of ADR-0015), and connected to it from the
probe's own uncontained process. Twice, on 2026-10-05, unelevated, identical:

| | What | Exit | Said |
|---|---|---|---|
| C3 | a file outside the workspace, contained | 1 | `Access is denied.` |
| S0 | the server, uncontained; a client here | 0 | `outside file: READ`; listening; the client was `answered` |
| S1 | the same server, **contained** | **0** | **`outside file: refused, PermissionError`**; listening; the client was **`answered`** |

The server that answered in S1 is the process the container refused a file outside its
workspace, so it was held when it listened and served. A zero-capability container may
bind `127.0.0.1`, accept a connection from an ordinary process on this machine, and
answer it. No firewall prompt appeared: the listener was loopback only. No container
profile and no interpreter copy were left.

- **For step 2 (#175): a model server can run inside a sandbox and be asked through the
  local door as it is.** What remains is placing the server's program and the model
  files under `var/`, where a container can be given them
- **It is also a gap.** Any contained program can listen on loopback, and anything on this
  machine can connect to it: another sandbox, or any program the operator runs. A
  hostile contained program could offer a service there. COVERAGE records it beside
  finding 1, its outward twin

### 11. A rule naming a lane does not refuse it a loopback port

Loopback is open to a sandbox (finding 1), and on it is the model server, which asks no
password and can be told to download or delete a model (COVERAGE). If a rule could
refuse one lane one loopback port and leave the others, a sandbox could be narrowed to
its proxy. `scripts/spike/loopback_rule_probe.py` asked, on 2026-10-07, unelevated,
against two listeners of its own on `127.0.0.1`: A on a random port, B on 47613. Three
phases; the operator added and removed the one rule as administrator:

```text
New-NetFirewallRule -DisplayName 'Sletchy-lane0: no loopback port 47613'
  -Group 'Sletchy loopback spike' -Direction Outbound -Action Block -Protocol TCP
  -Profile Any -RemoteAddress 127.0.0.1 -RemotePort 47613 -Package '<lane0 SID>'
```

| | What | No rule | **With the rule** | Removed |
|---|---|---|---|---|
| C1 | `curl --version`, contained in lane 0 | 0 | 0 | 0 |
| C3 | a file outside the workspace, contained | 1 | 1 | 1 |
| LA | contained, to A | 0 | 0 | 0 |
| BU | **un**contained, to B | 0 | 0 | 0 |
| LB | contained, to B: the measurement | 0 | **0** | 0 |

Every attempt took 0.1 s. The probe read the rule back before and after phase 2's rows,
through the firewall's own API, exactly as written: outbound, block, TCP, `127.0.0.1`,
port 47613, lane 0's SID, switched on. C3 shows the container was applied in every
phase, and the rows ran in lane 0, whose SID the rule names. Finding 8 measured that
rules naming a lane bind, for addresses on other machines. On loopback the same kind of
rule changed nothing. After phase 3, `sletchy install-rules --check` read Sletchy's
eight rules back exactly as planned; the spike's group was gone.

- **The Windows Firewall cannot narrow a sandbox's loopback.** A sandbox reaches its
  proxy, the model server and every other local service, and no rule written the way
  ours are changes that. COVERAGE's two loopback rows say so, measured
- **What could close it is not a firewall rule:** the model server inside its own
  sandbox (ADR-0017 step 2), which stops a download but not a delete, or filtering below
  the firewall, which is a different kind of host change and unmeasured. A door with a
  password in front of the server does not help: the server would still listen on
  loopback, where a sandbox reaches it directly. Which, if any, is the operator's
  decision. **Decided 2026-10-07 (#184): accepted as written.** Step 2 closes the
  download half; a filter below the firewall is filed for later, only if needed (#188)
- **What this did not ask:** UDP, `::1`, other ports, and inbound to a contained server
  (finding 10)

### 4. Reading the firewall inventory does not need elevation; the PowerShell cmdlet does

`Get-NetFirewallRule` fails with *Access is denied* unelevated. `netsh advfirewall firewall
show rule name=all` returns the full inventory (2614 rules) unelevated.

Small, but it decides how `panic` and any future SOC sensor verify their own firewall state
without demanding rights they should not hold. **Read via `netsh`; reserve elevation for
writes.**

## Host state

| | Before | After |
|---|---|---|
| AppContainer profiles | 115 | 115 |
| `Sletchy-*` profiles | 0 | 0 |
| Firewall rules | 2614 | 2614 |
| Stray `cmd.exe` | 0 | 0 |

Nothing was written to the host in phase 1. The profile count differs from ADR-0005's 117
because ordinary app installs and updates move it; the number that matters is that
`Sletchy-*` is zero at both ends.

## Consequences

- `winjob`'s `confines_network` **stays False**, now for a measured reason rather than an
  unmeasured one. The test that enforces it stands.
- [`docs/LAW/isolation.md`](../LAW/isolation.md) L2 no longer says network denial is
  unmeasured. It says loopback is measured and **not** denied.
- `COVERAGE.md` gains a residual gap for finding 1 and keeps its Planned rows for the
  firewall question.
- **#32 may proceed on the loopback assumption** - the proxy can be reached. It may not
  claim non-bypassability until phase 3.
- #33 inherits finding 3: the firewall rule is the whole control, not a second layer.
- **2026-10-04, after finding 5:**
  - for TCP to other machines over IPv4, the container is already a control, measured.
    #33's rule is a second lock there, and the whole control for UDP and IPv6 until those
    are measured
  - `winjob` still does not claim `confines_network`: loopback is open by design, and UDP
    and IPv6 are unmeasured
  - a real `winjob` run gets a random container name, so #33's rule cannot name its SID in
    advance as the probe's fixed name did. That is #33's first design question
- **2026-10-04, after finding 7:** the rules are installed and loopback still reaches the
  proxy. Whether they bind is still unmeasured, and `winjob` still claims no
  `confines_network`. The probe's next round opens the container's own lock so that the
  rule is the only thing left to refuse
- **2026-10-04, after finding 8:** the rules bind, for TCP over IPv4, measured. `winjob`
  still claims no `confines_network`: UDP and IPv6 are unmeasured, and loopback is open
  by design. #33's definition of done is met except that claim, which waits on #71
- **2026-10-05, after finding 9:** over IPv4, a contained program is refused TCP and UDP to
  other machines by two locks, each named in Windows' own drop log. `winjob` still claims
  no `confines_network` ("outbound connections are refused unless explicitly allowed"),
  for two reasons now, not three: loopback is open to every service on this machine, not
  only the proxy, by design (COVERAGE); and IPv6 is unmeasured here (#173). #71 and #33
  close; the claim is decided and written down, not left waiting on them

## What this does not answer

- ~~**Non-loopback egress from inside the container.**~~ Answered for TCP over IPv4 by
  finding 5, with no listener: an unrouted documentation address needed none, so no
  firewall notification could appear.
- ~~**Whether a firewall rule scoped to the container SID binds.**~~ Answered for TCP
  over IPv4 by finding 8.
- ~~**Non-loopback UDP from inside the container.**~~ Answered by finding 9: both locks
  drop it, named in Windows' drop log, read by the operator as administrator.
- **IPv6 from inside the container.** Not measured: this machine has no IPv6 route, so no
  attempt reaches a filter. It needs a machine with one (#173).
- ~~**`internetClient` specifically.**~~ Exercised by the operator's probe against a
  documentation address (finding 8): it lifts the container's refusal. Tests still never
  do, under LAW 0 §6.
- **Registry denial.** Untouched, still unmeasured, still unclaimed.
- Anything about a build other than 10.0.19045.
