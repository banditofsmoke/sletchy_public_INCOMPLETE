# LAW 0 - Do no harm to the host machine

**This law outranks every other law, principle, feature, and deadline in this repo.**
When any other law, any performance goal, or any interesting idea conflicts with this
one, this one wins and the other thing does not get built.

## Why this law exists

Sletchy runs on one machine. There is no second machine. If Sletchy bricks the host,
the cost is not "a rebuild weekend" - it is the operator's livelihood. Every design
decision in this repo is made by someone who can afford to lose a container and cannot
afford to lose a laptop.

A security system that endangers the thing it protects has failed at its only job.

---

## 1. No kernel-mode code. Ever, in v1.

**Sletchy ships no kernel driver, no filesystem minifilter, no WFP callout driver, no
NDIS filter, no bootstart service.**

Reasoning - this is not caution, it is arithmetic:

| Risk | User mode | Kernel mode |
|---|---|---|
| Null deref | Process crashes, gets restarted | **BSOD** |
| Bad early-boot state | Nothing | **Boot loop, possibly unbootable** |
| Recovery | Kill the process | Safe Mode, or a Windows reinstall |
| To load unsigned code | Nothing required | **Test Signing Mode - which disables the very protections we are building** |
| To load signed code | Nothing required | EV certificate + WHQL attestation |

Enabling Test Signing Mode to load our own "security" driver would disable Windows
security features in order to install a security feature. That is a net loss on day one.

### What we do instead - kernel-enforced isolation from user mode

The goal behind "kernel-level control" is total, granular visibility and control over
processes and network. Windows exposes that through **documented user-mode APIs whose
enforcement happens in the kernel**. We get the enforcement without shipping the risk.

| Goal | Mechanism | Enforced by | Risk to host |
|---|---|---|---|
| Cap CPU/memory/handles; kill a whole process tree atomically | **Job Objects** (`CreateJobObject`, `JOB_OBJECT_LIMIT_*`) | Kernel | None |
| Strip privileges from a child process | **Restricted tokens** (`CreateRestrictedToken`) | Kernel | None |
| Deny filesystem, registry, and network by default | **AppContainer** (`CreateAppContainerProfile`) - the same sandbox Edge and UWP use | Kernel | None |
| Block a specific binary's network access | **Windows Firewall app rules** (`INetFwPolicy2` COM API) | Kernel (WFP) | None - and fully reversible |
| Observe process/network/file events | **ETW** consumers (`Microsoft-Windows-Kernel-Process`, `-Network`) | Kernel emits, we read | None - read-only |
| Deny writes outside a root | Path canonicalisation + ACLs + AppContainer profile | Kernel | None |

This ladder is *stronger* than most hand-rolled drivers, because it is the same code
path Microsoft ships to sandbox its own browser - and it cannot take the machine down.

**Where C++ belongs.** `warden/` is designed as a process boundary from day one
precisely so its supervisor and egress proxy can be rewritten as a native binary once
the contracts are stable. Native, user-mode, and replaceable. That is the C++ ambition,
honoured safely. See [ADR-0001](../adr/0001-no-kernel-driver.md).

---

## 2. Reversibility is a hard requirement

**Every change Sletchy makes to the host must be undoable by one documented command.**

If a feature cannot state its own undo, the feature is not finished.

- All firewall rules are created in a single named group (`Sletchy`) and are removed
  wholesale by `sletchy stop` run as administrator, and by uninstall.
- All Sletchy state lives under **one** directory (`var/`) and **one** registry key.
  Uninstall is: stop, remove rules, delete both. Nothing else is touched.
- No modification of system-wide network config: no route table edits, no global proxy,
  no LSP/Winsock providers, no `hosts` file edits, no DNS server changes, no
  certificate-store installs without an explicit interactive prompt.
- No global environment variables. No `PATH` edits.
- **No auto-start at boot** unless explicitly opted in, and even then it starts
  *disarmed* (see §4).

### `sletchy stop` (Stop everything)

A single command, working even when the daemon is wedged, that:

1. Terminates every Sletchy job object and every child process.
2. Removes every firewall rule in the `Sletchy` group, when run as administrator. Run
   as a normal user it keeps them, counts them and says so (#179): they only restrict
   Sletchy's own sandboxes, so keeping them is never the unsafe direction.
3. Releases every listening socket, including all honeypot listeners.
4. Disarms every flag back to its default.
5. Writes a final sealed ledger entry recording that it ran, and why.

It is tested in CI as a **first-class feature**, not a nice-to-have. A stop button
that has never been pressed is a rumour, not a feature.

Its old name, `sletchy stop`, still works and is listed nowhere. The operator renamed
it on 2026-10-05: the control you reach for when something is wrong should not read as
an alarm. Older records, decisions and pull requests say `panic` and are left as written.

---

## 3. Least privilege for Sletchy itself

Sletchy is not trusted either. It is inside its own threat model.

- **Sletchy runs as a normal user.** Not Administrator, not SYSTEM, not a service
  account with `SeDebugPrivilege`.
- Exactly **one** operation may prompt for elevation: initial firewall-rule
  installation. It is a separate, auditable, one-shot step (`sletchy install-rules`),
  never inline in normal operation, and it prints exactly what it will do first.
- Sletchy never grants itself a capability it would deny to an agent.
- The ledger's signing key is bound to the OS keychain and is never held in the
  process's own writable memory longer than a signing call.

---

## 4. Default-off, default-disarmed, default-loopback

Every capability that touches the network, the filesystem outside `var/`, the
microphone, the camera, the screen, a wallet, or a training run is **off by default**
and requires an explicit flag flip.

Specifically, and non-negotiably:

- **The honeypot binds to loopback only by default.** Exposing a deception surface to a
  LAN or WAN interface requires a separate, explicit, logged flag and prints a warning
  naming the interface. A honeypot reachable from the internet is not a defense, it is
  an invitation and possibly a legal problem.
- **Camera and microphone are off** until flipped, per session, and both emit a ledger
  event and a visible indicator whenever active.
- **Contract deployment to any live network is off**, requires human confirmation, and
  mainnet requires a second confirmation naming the chain and the value at risk. See
  [LAW 7](laws.md#law-7).
- **Training runs are off** and resource-capped, because a runaway training job can
  thermally throttle or OOM the host.

---

## 5. Resource ceilings on everything Sletchy starts

An out-of-memory host is a broken host. Every Sletchy-launched process is created
**inside a Job Object with hard limits already applied** - never launched first and
limited afterwards, which is a race.

| Limit | Default | Enforced by |
|---|---|---|
| Memory per job | 2 GB | `JOB_OBJECT_LIMIT_JOB_MEMORY` |
| CPU | 50% of one core, tunable | `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` |
| Wall clock | 300 s | `JOB_OBJECT_LIMIT_JOB_TIME` + our own watchdog |
| Process tree | Dies with the job | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` |
| Disk under `var/` | 5 GB, checked before write | Warden fsguard |
| Ledger size | Rotates + seals at 4 MB, so an ordinary open parses at most one small segment ([ADR-0009](../adr/0009-opening-the-ledger-checks-sealed-segments-by-fingerprint.md)) | Kernel ledger |
| Ledger total | 1 GB, and never written below 2 GB free on its drive; switching things off keeps a 16 MB reserve past 1 GB, never past the floor (#101) | Kernel ledger |
| Payloads | 32 MB each and 3 GB in total, never written below 2 GB free on their drive. A launch whose command line cannot be kept does not run | Kernel payload store |

Sletchy additionally refuses to start a training or vision workload when host free
memory is below a floor, or when battery is below a floor and unplugged.

---

## 6. The host is never the test target

Adversarial tests - egress-bypass attempts, path traversal, honeypot triggering,
sandbox escape - run against **Sletchy's own sandboxed surfaces**, never against the
host's real services, and never against any third party.

- No scanning, probing, or traffic generation aimed at any address outside the local
  bubble.
- No test may disable, degrade, or reconfigure the host's Defender, firewall defaults,
  or update service.
- Red-team fixtures are inert artifacts (a fake token, a malformed path, a decoy
  binary) - never live malware samples.

---

## 7. Fail closed, but never fail destructive

Two failure modes, and they are different:

- **Fail closed** - when a policy decision cannot be made with confidence, *deny*. A
  missing secret, an unverifiable signature, an unparseable policy, a ledger that will
  not verify: all deny, all log, all refuse to proceed.
- **Never fail destructive** - a failure never deletes user data, never mass-kills
  unrelated host processes, never mutates host config to "recover", and never
  auto-remediates outside `var/`. Sletchy stops and says what happened. Stopping is
  always available; undoing is not.

When the ledger cannot be verified, Sletchy **refuses to run** and says so. It does not
"repair" the ledger. A quietly repaired audit log is worse than no audit log.

---

## Enforcement

- Every PR that touches `warden/`, `soc/honeypot/`, `kernel/secrets/`, or `vault/deploy/`
  must state its blast radius and its undo in the PR body. No statement, no merge.
- `tests/adversarial/test_law_zero.py` asserts the mechanical parts of this law:
  no elevation required at runtime, no writes outside `var/`, honeypot loopback-bound
  by default, Stop everything fully reverts, every launched process carries job limits.
- **Everything Sletchy ships is scanned, not only its Python**: the window's Rust and
  TypeScript, the scripts, the launcher and the git hook, against one catalogue of the
  host changes this law forbids (`tests/hostshield.py`). Each entry names its clause and
  is proven to catch its own example.
- **The test suite cannot harm this machine either.** `tests/conftest.py` surrounds every
  run: it refuses to run elevated, sends every test to a throwaway `SLETCHY_HOME`, makes
  the real keychain unreachable, refuses any command that changes the host and any
  connection off this machine before it starts, and fails the run if the real `var/`
  changed. `tests/adversarial/test_host_shield.py` proves each guard bites, with probes
  that are harmless even if a guard were missing.
- Introducing a kernel-mode component, an auto-start default, or a non-reversible host
  change requires an **ADR that supersedes this law**, argued explicitly. There is
  currently no such ADR, and the bar is deliberately very high.

---

*This law is Sletchy's first commit and its last line of defense. Everything else in
this repo is negotiable. This is not.*
