# Wave 1 backlog - the Kernel

Ready to open as GitHub issues. Order matters: 1.1 blocks everything, 1.2 blocks 1.4–1.7.

Labels: `wave-1` · `kernel` · `security` · `law-0` · `spike`

Every PR answers [the checklist](../LAW/laws.md#pr-checklist).

---

### #1 - `kernel/contracts/`: the Pydantic foundation
`wave-1` `kernel`

Base models every other plane builds on. **No plane may define its own version of these.**

`LedgerEntry` · `Actor` · `Action` · `Subject` · `Verdict` · `Capability` ·
`IsolationProfile` · `Flag` · `SecretRef` · `PolicyRule` · `AgentEvent` + the 11 event types

**Done when:** models round-trip; JSON Schema generates from them; a golden-file test
catches unreviewed schema changes; no hand-written parallel schema exists anywhere.

**Notes:** The event vocabulary adds `POLICY` (a security decision, carrying its ledger
seq) to the base ten - see `docs/LAW/architecture.md` §5.

---

### #2 - `kernel/ledger/`: hash chain, sign, append, verify
`wave-1` `kernel` `security` - **blocks #4 #5 #6 #7**

Append-only, hash-chained, signed. Entry commits to `prev_hash`. Verified on startup;
a chain that fails verification **halts Sletchy**.

**Explicitly out of scope, permanently: any repair function.** None exists, none may be
added. A quietly repaired audit log is worse than no audit log.

**Done when:** mutating / truncating / reordering any entry fails verification; a wrong
signing key is rejected; startup halts on a corrupt chain; signing key comes from the OS
keychain and is not held in writable memory beyond a signing call; both wall and monotonic
timestamps recorded, monotonic authoritative for ordering.

**Salvage:** HMAC-SHA256 sign/verify pattern from GDN `src/security/integrity.py`, with
its per-node-ephemeral-key flaw (identified in GDN's own `AUDIT_REPORT.md`) corrected.

---

### #3 - `kernel/ledger/store`: content-addressed payloads
`wave-1` `kernel`

Bodies (prompts, responses, artifacts) live outside the chain, addressed by hash. Keeps
the chain small and lets a sensitive body be deleted without breaking verification.

**Done when:** deleting a payload leaves the chain verifying; dedup works; a size cap and
GC policy exist.

---

### #4 - `kernel/policy/`: rules, tighten-only merge, deny by default
`wave-1` `kernel` `security` - depends on #2

**Done when:** a merge producing a wider bound than the declaration is **rejected** (no
override flag exists); an empty policy denies everything; an unparseable policy denies
everything *and raises*; ties go to deny; every verdict hits the ledger.

---

### #5 - `kernel/capability/`: scoped, signed, short-lived grants
`wave-1` `kernel` `security` - depends on #2 #4

One capability = one action on one subject class. If it needs an "and", it is two.

**Done when:** expired, forged, and wrong-context capabilities are all rejected; an agent
cannot self-grant (the Kernel issues from policy, agents never request); grants are
checked at use time, never cached into an assumption.

---

### #6 - `kernel/secrets/`: OS keychain, fail closed
`wave-1` `kernel` `security` - depends on #2

Refs in config, values from Windows Credential Manager, resolved at use time.

**Done when:** a missing secret **raises** - there is no fallback-default code path; a
secret value can never reach a log or a ledger payload (only its ref and a hash); an env
allowlist is applied to any child process.

**Why this one has teeth:** the exact pattern `os.environ.get("GROQ_API_KEY", "gsk_live…")` <!-- secret-scan: allow -->
in the old Sletchy config is how a live key spread to eight files across three projects.
See `docs/salvage/CREDENTIALS-TO-ROTATE.md`.

---

### #7 - `kernel/flags/`: typed registry, dangerous flags off
`wave-1` `kernel` `law-0` - depends on #2

**Done when:** a fresh install has every network / filesystem-outside-`var` / mic / camera
/ screen / wallet / training flag **off**; flips are ledger-logged with who, when, why;
the UI flag panel is generated from the registry; dev defaults live in a separate profile
that never ships.

---

### #8 - `apps/cli`: `sletchy panic` and friends
`wave-1` `law-0` - depends on #2 #7

`sletchy ledger verify` · `sletchy flags [list|set]` · `sletchy status` ·
**`sletchy panic`**

**`panic` must work when the daemon is wedged.** It terminates every job object and child
process, removes every firewall rule in the `Sletchy` group, releases every listener
including honeypots, disarms every flag, and writes a final sealed ledger entry recording
that it ran and why.

**Done when:** panic is tested from a deliberately wedged state and leaves **zero
residue** - no rules, no processes, no listeners.

---

### #9 - `tests/adversarial/test_law_zero.py`
`wave-1` `law-0` `security` - depends on #8

Mechanically assert LAW 0: no runtime elevation required · no writes outside `var/` ·
every dangerous flag off on a fresh install · panic fully reverts · every launched process
carries job limits *applied before it starts*.

**Done when:** these pass in CI, and `tests/adversarial/COVERAGE.md` rows move from
Planned to Coverage.

---

### #10 - `tests/unit/test_import_layers.py`: plane dependency enforcement
`wave-1` `security`

`kernel` imports nothing from `sletchy`. `warden` and `soc` import only `kernel`.
`mind` / `senses` / `forge` / `vault` import `kernel` + `warden`. `apps` never imports
`warden` directly.

**Done when:** an upward or sideways import fails the build.

---

### #11 - Project setup: `uv`, ruff, mypy, pre-commit, CI
`wave-1`

Python 3.13 · `uv` · ruff · mypy strict on `kernel/` · pytest.

**Pre-commit must include a secret scan** - the pattern that leaked six keys must not be
able to re-enter this repo. Same sweep runs in CI.

**Done when:** `uv sync && uv run pytest` is green from a clean clone; the secret-scan
hook rejects a test commit containing a fake `gsk_`-shaped string.

---

## Wave 2 - first two, so the risk is visible early

### #12 - **SPIKE**: AppContainer on Windows 10 Pro 19045
`wave-2` `spike` `security` - **blocks the `winjob` backend**

Empirically verify on *this exact build*: profile creation/deletion, capability grants,
FS/registry denial by default, interaction with Job Objects and restricted tokens, and
whether firewall app rules bind correctly to an AppContainer'd process.

**Done when:** a written findings doc says what works, what does not, and what `winjob`
can honestly claim. **Until then, `winjob` is not described as "strong" anywhere** -
`docs/LAW/isolation.md` lists this as an open residual gap.

**This is a spike, not an assumption.** If AppContainer does not behave as documented on
19045, the isolation design changes and we find out now rather than in Wave 4.

---

### #13 - `IsolationBackend` interface + conformance suite
`wave-2` `security` - depends on #5

One interface, one shared suite asserting **behaviour** ("this write is refused", "this
connection is refused"), never implementation.

**Done when:** `inproc` and `subproc` both pass with correctly different results;
`inproc` **refuses to load outside a test run** (enforced in code, not a comment); a
capability whose minimum backend is unavailable **does not run** and does not downgrade.
