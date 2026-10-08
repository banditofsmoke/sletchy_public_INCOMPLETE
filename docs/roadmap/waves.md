# Roadmap - the waves

Sletchy is built in waves. Each wave is a vertical slice that leaves the system working,
tested, and honest about what it does not yet do. **A wave is not done until its
adversarial tests pass and its residual gaps are written down** ([LAW 10](../LAW/laws.md#law-10)).

Every wave ships through issues → branch → PR → review against
[the PR checklist](../LAW/laws.md#pr-checklist) → merge. No direct commits to `main`.

---

## Wave 0 - Ground (this session)

Foundations, no runtime.

- [x] Survey and dissect `Scraps and Parts/` → salvage inventory
- [x] Credential sweep → rotation list
- [x] [LAW 0 - Do no harm](../LAW/00-do-no-harm.md)
- [x] [Principles](../LAW/principles.md), [Laws](../LAW/laws.md), [Architecture](../LAW/architecture.md), [Isolation](../LAW/isolation.md)
- [x] ADRs 0001–0004
- [x] Repo scaffold, `CLAUDE.md` files, `.gitignore`
- [x] Git init, first commit, private remote
- [x] Issue backlog opened

---

## Wave 1 - The Kernel - **COMPLETE**

**Goal: nothing can happen off-ledger.** No chat, nothing to talk to. Deliberate - see
[ADR-0003](../adr/0003-ledger-is-the-spine.md).

| # | Work | Done when |
|---|---|---|
| 1.1 | ✅ `kernel/contracts/` - Pydantic base: `Event`, `Actor`, `Capability`, `Verdict`, `IsolationProfile`, `Flag` | Schemas generate; round-trip tested |
| 1.2 | ✅ `kernel/ledger/` - hash chain, sign, append, verify, seal, rotate | Tamper of any entry is detected; startup verify halts on corruption |
| 1.3 | ✅ `kernel/ledger/store` - content-addressed payload store | Body deletable without breaking chain verification |
| 1.4 | ✅ `kernel/policy/` - rule eval, tighten-only merge, deny-on-tie, deny-on-unparseable | A widening merge is rejected; empty policy denies everything |
| 1.5 | ✅ `kernel/capability/` - scoped, signed, short-lived, context-bound grants | Expired/forged/wrong-context capability rejected |
| 1.6 | ✅ `kernel/secrets/` - OS keychain refs, fail-closed | Missing secret raises; never a fallback default |
| 1.7 | ✅ `kernel/flags/` - typed registry, defaults off, ledger-logged flips | Fresh install has every dangerous flag off |
| 1.8 | ✅ `src/sletchy/cli` - `sletchy ledger verify`, `sletchy flags`, **`sletchy panic`** | Panic works with the daemon wedged |
| 1.9 | ✅ `tests/adversarial/test_law_zero.py` + `COVERAGE.md` | Law 0 mechanically asserted |

**Exit criteria - all met.** Ledger verifies and refuses to repair · policy denies by
default and can only tighten · capabilities cannot be self-granted · secrets fail closed ·
every dangerous flag is off on a fresh install · `sletchy stop` reverts from a wedged state ·
import-linter and AST checks enforce plane dependencies, proven against deliberate
violations.

**Delivered:** 372 tests (51 `law_zero`, ~140 adversarial), 13 PRs, ~110 attacks in
`COVERAGE.md` with 25 residual gaps named. Three CI-only bugs found and fixed along the
way - see the PR bodies for #22, #24, #26.

---

## Wave 2 - The Warden - **COMPLETE**

**Goal: nothing reaches the outside world except through one mediated, logged chokepoint.**

**Complete 2026-10-07**, with what it does not hold measured and written in COVERAGE.
`winjob` still does not claim `confines_network`, and a test enforces that.

**Start 2.5 with the measurement, not the proxy.** Whether a Windows Firewall app rule
actually binds to an AppContainer process is the assumption the entire egress design rests
on, and it is unverified. That makes it the item that could invalidate a design decision,
so it goes first - the same shape as 2.3, and for the same reason.

| # | Work | Issue | Notes |
|---|---|---|---|
| 2.1 | ✅ `IsolationBackend` interface + conformance suite | #13 | Suite asserts behaviour, not implementation |
| 2.2 | ✅ `inproc` + `subproc` backends | #13 | `inproc` refuses to load outside tests |
| 2.3 | ✅ **Spike: AppContainer on Windows 10 Pro 19045** | #12 | Empirical. Gated 2.4. [ADR-0005](../adr/0005-appcontainer-findings.md) |
| 2.4 | ✅ `winjob` backend - Job Object, restricted token, AppContainer | #31 | The default backend. Filesystem, resources, and process-tree containment measured; **the firewall app rule and network denial are deliberately not in it** - unmeasured, so 2.5 carries them |
| 2.10 | ✅ Sandbox launches on the ledger - recorder, four actions, refusal path | #46 | Numbered last, landed early. 2.1–2.4 built a launcher that acted off-ledger, which LAW 1 forbids; this closed it before more was built on top |
| 2.5 | ✅ `warden/egress/` - mediating proxy, allowlist, ledger every attempt | #32, #33, #71 | Phase 1 and the probe's first round measured ([ADR-0006](../adr/0006-egress-binding-findings.md) findings 1 and 5): the container reaches loopback, which the proxy **needs**, and is refused TCP to other machines. The rules are built (#159, [ADR-0013](../adr/0013-sandbox-lanes-so-a-firewall-rule-can-name-the-container.md)): eight sandbox lanes, one rule each, so rules written once name every run's container. They are installed on the operator's machine (2026-10-04) and **bind, for TCP over IPv4** (finding 8): with the container's own lock opened, a lane is refused and a container no rule names is not. Both locks drop UDP too, named in Windows' drop log (finding 9). IPv6 is unmeasured (#173). The proxy is built (#160): one gate decides and records every connection, and a sandbox gets a door on loopback for its run. A rule cannot narrow loopback (finding 11); I accepted that as written (#184) |
| 2.6 | ✅ `warden/fsguard/` - canonicalise-then-confine, quotas, Windows traps (ADS, device names, UNC) | #68 | Every trap a test (#143) |
| 2.7 | ✅ `warden/supervisor/` - allowlist launch, no shells, no living-off-the-land programs, every decision recorded first | #69 | A denied command never spawns (#144). Closed the `select()`-refusal gap. `sletchy sandbox run` (#52, #145) reaches it from a terminal |
| 2.8 | ✅ `container` backend + **Podman CI job** | #70 | Linux only, never on Windows ([ADR-0014](../adr/0014-the-container-backend-runs-on-linux-only.md)); proven by the conformance suite on CI's Ubuntu runner with rootless Podman (#162) |
| 2.9 | ✅ `warden/supply/` - hash-pinned lockfile, license/CVE gate, quarantine profiling | #34 | Actions and hooks pinned to commits, locked installs, licences, a written reason per dependency (#147, #150, #152); every shipped package imported in quarantine, and OSV asked about every lockfile in CI (#161) |

**Operator surface, alongside the above.** The Warden now writes to the ledger and launches
contained processes, and neither is reachable without writing Python: `sletchy ledger show`
(#50) and `sletchy sandbox run` (#52). Small, and the first point at which Wave 2 is
visible from a terminal.

**Exit:** a hostile process launched by Sletchy cannot reach the network, escape its
directory, keep a child alive, or read the parent environment.

**Where the exit stands (2026-10-07).** Three of the four hold in `winjob`, each by a test:
it cannot escape its directory (the conformance suite and fsguard, #143), keep a child
alive (`test_a_detached_grandchild_is_inside_the_job_and_dies_with_it`), or read the
parent environment (`test_environment_stripping_matches_the_claim`). The network holds in
part. Over IPv4, other machines are refused TCP and UDP, by the container and by the rules
(ADR-0006 findings 5, 8 and 9). IPv6 is unmeasured, because this machine has no IPv6 route
(#173). Loopback is open both ways: the proxy needs it (finding 1), and it also reaches
every local service, the model server included (COVERAGE), and a firewall rule cannot
narrow it: measured on 2026-10-07, a rule naming a lane and one loopback port changed
nothing (ADR-0006 finding 11, #184). So `winjob` still claims no `confines_network`.

**I accepted the loopback gap as written on 2026-10-07 (#184), and that closes the wave.**
A sandbox runs only when I start one, and the model server only while I run it. The model
server in its own sandbox (ADR-0017 step 2) closes the download half, once my own
llama.cpp build runs in a lane. A filter below the firewall might close both, but it is a
deeper change to Windows than the one audited elevation LAW 0 allows for firewall rules,
so it is filed for later, only if needed (#188).

**`egress_enabled` stays unwired, on purpose (2026-10-07).** Wiring it would let a
sandboxed program reach other machines through the proxy, so it can only widen what a
program reaches. Nothing Sletchy runs needs the Internet before Wave 3's tools, and it
needs a decision first: which hosts a program may ask for, and who adds one. Until then
the window shows the switch as not connected yet, and it changes nothing. The proxy, its
gate and the supervisor are built and tested (#160, #144); the hand-over waits for the
first tool that needs it.

---

## Wave 3 - The Mind (first light) - **IN PROGRESS**

**Goal: talk to Sletchy - through the ledger, through the Warden.** The first wave with
something to show.

| # | Work | Salvaged from |
|---|---|---|
| 3.1 | `mind/harness/` - executor, event stream, 11 event types incl. `POLICY`. **Started 2026-10-07** ([ADR-0018](../adr/0018-the-harness-one-stream-per-turn-every-event-on-the-record.md)): a conversation with the local model, one stream per turn, every event on the record before it is shown, and the terminal host (`sletchy chat`, #190), then the window's Talk plate (#191). Left for later: words as they arrive, `INTERRUPT` with tools (3.6), and hosts that listen (#62, #59) | New |
| 3.2 | Hosts: CLI, SSE, WebSocket | TalkyTime (WS text+audio) |
| 3.3 | `mind/router/` - Provider/Endpoint/Catalog/Binding; **endpoint toggle** | project42 |
| 3.4 | Adapters: Ollama, llama.cpp, Groq, Gemini, HF, OpenAI-compatible. **Ollama started, 2026-10-05** ([ADR-0017](../adr/0017-a-model-before-training-through-one-local-door.md)): `sletchy ask`, through one local door, with the card budget and the context meter | alpha, Bravo, ElectronAPP1 |
| 3.5 | `mind/router/limits.py` - RPM/RPD/TPM/TPD + wait computation | Sletchy `RateLimiter` (+ its Groq table as seed data) |
| 3.6 | `mind/tools/` - registry, every call capability-checked | |
| 3.7 | `mind/agents/` - config-driven agent factory | sletchy `agents/`, COBOL `agents.py` |
| 3.8 | `mind/memory/` - **the recall store**, pulled forward from 5.1 and 5.4 by [ADR-0019](../adr/0019-recall-comes-into-wave-3.md): chunks at three sizes, found by words (FTS5, BM25) and by meaning (vectors), merged by rank (#194) | Rebuilt; ElectronAPP1's multi-granular instinct |
| 3.9 | `mind/memory/gate.py` - **the evidence gate**: only what answers reaches the model, or "not in my memory" (#195). A trained judge is #196 | New |
| 3.10 | `mind/harness/context.py` - **a context plan on the record**: every piece of a question's context with its source and trust, and what was left out (#193) | New |

**Exit:** a real conversation, every token and tool call in the ledger, a question about an
earlier conversation answered from the record with its entries, or answered "not in my
memory" ([ADR-0019](../adr/0019-recall-comes-into-wave-3.md)), model endpoint
switchable at runtime, offline-capable via Ollama.

---

## Wave 4 - The SOC/NOC

**Goal: see everything, and catch something.**

| # | Work | Salvaged from |
|---|---|---|
| 4.1 | `soc/sensors/` - ledger + ETW normalisation | |
| 4.2 | `soc/detect/rules/` - denied-egress bursts, first-contact hosts, escalation attempts, injection markers | GDN `ai_monitor` |
| 4.3 | `soc/detect/trust.py` - trust 0–100 gating capabilities | **GDN `AIAgent.trust_score`** |
| 4.4 | `soc/honeypot/` - decoy creds, decoy tools, tarpit; **loopback-only default** | New |
| 4.5 | `soc/noc/` - live dashboard | ElectronAPP1 shell |
| 4.6 | Auto-response: honeypot touch → freeze actor, revoke capabilities, snapshot, alert | |

**Exit:** a deliberately hostile test agent is detected, frozen, and fully reconstructable
from the ledger alone.

---

## Wave 5 - Memory and the learning loop

**Goal: Sletchy evolves to its user, auditably.**

| # | Work | Salvaged from |
|---|---|---|
| 5.1 | `mind/memory/` - episodic, append-only, content-addressed. **The store comes first, in 3.8** | Sletchy `MemoryManager` (fixing full-CSV-rewrite + duplicate method) |
| 5.2 | Rollups: hourly → daily → weekly → monthly, each a ledger artifact | Its `summarize_recent()` instinct |
| 5.3 | The user model - goals, style, standing preferences, fully traceable | New |
| 5.4 | `mind/rag/` - `Strategy` protocol; BM25 + multi-granular ingestion first. **BM25 and multi-granular chunking come first, in 3.8**; the `Strategy` catalog stays here | ElectronAPP1 |
| 5.5 | The 21 RAG strategies as flag-gated, benchmarkable implementations | `RAGs/` catalog |
| 5.6 | `mind/graph/` - **temporal** KG: entities, relations, communities, validity intervals | TalkyTime (Graphiti) + ElectronAPP1 GraphRAG-lite |

**Exit:** you can read exactly what Sletchy concluded about you, when, and from which
interactions - and delete any of it.

---

## Wave 6 - The Shell

**Goal: the encapsulated bubble a non-technical person can actually use.**

- **Tauri v2 desktop, not Electron** ([ADR-0008](../adr/0008-desktop-shell.md)): the window
  starts `sletchy bridge` as a job-confined child and speaks JSON over its pipes. Nothing
  listens. **Pulled forward on 2026-10-02 as a host over what already exists** - status,
  flags, ledger, Stop everything, setup, the self-check - with Simple, Custom and Raw modes
- OS keychain: already the Kernel's, through `keyring`; the shell never touches a key
- The NOC view and the conversation still wait for Waves 3 and 4. The flag panel is
  generated from the typed registry
- First-run: everything dangerous off, useful immediately, one screen explaining what is
  and is not on

**Exit:** installs and runs with no prerequisites; a stranger can use it without reading
anything.

---

## Wave 7 - The Senses *(all flag-gated off)*

- `senses/voice/` - wake word, STT, TTS, sentence chunking, barge-in as `INTERRUPT`
  *(project42, TalkyTime, OARC)*
- `senses/vision/` - YOLO + Depth-Anything-V2, debounced tracking *(Yolo Vision Stuffs)*
- `senses/affect/` - **the emotional classifier lands here via its own PR**, treated as an
  untrusted third-party model with its own capability profile *(a friend's model)*

---

## Wave 8 - The Forge

**A first slice is pulled forward, before Wave 3** ([ADR-0016](../adr/0016-a-first-training-slice-before-wave-3.md),
2026-10-05): one fine-tune of a small model with Unsloth, inside `winjob`, network off,
every step on the ledger. It depends on Waves 1 and 2 only, and a sandboxed program was
measured to use the GPU ([ADR-0015](../adr/0015-a-sandboxed-program-can-use-the-gpu.md)).
Its order: the host's graphics driver repaired, #71's UDP round, the training stack
through the supply gate (#170), the weights, then the runner (#55). The rest of the Forge
stays here.

- `forge/datasets/` - build, clean, Kaggle loaders, provenance tracking
- `forge/bench/` - any endpoint × any eval set → ledger-recorded results.
  **Seeded by the COBOL mainframe leaderboard as the first regression baseline.**
- `forge/train/` - Unsloth as a pinned dependency, capped and flag-gated
- `forge/eval/` - scoring, using the salvaged agent-output fixtures

**Exit:** train a small model on your own data, benchmark it against the leaderboard
baseline, with the whole run reconstructable from the ledger.

---

## Wave 9 - The Vault

- `vault/contracts/` - on OpenZeppelin as a versioned dependency, never a fork
- `vault/audit/` - Slither + Mythril adapters, findings into the ledger
- `vault/backtest/` - forked-chain simulation
- `vault/deploy/` - **testnet by default. Mainnet requires a second human confirmation
  naming the chain and the value at risk** ([LAW 7](../LAW/laws.md#law-7))
- The scraped Solidity corpus from original Sletchy becomes the first
  `forge/datasets/` input - which is how "train my own models on contract data" starts

---

## Later, explicitly not now

Every item here is filed, so the design constraints are captured while the reasoning is
fresh. **Filed is not scheduled.** None of these starts before Wave 4, and most are post-v1.

Bubble-to-bubble federation (#56) and the signed board that travels on it (#61) · what an
agent may do with no goal from its operator (#62) · in-house comms (#63) · borrowed and
shared GPU (#64) · the verified-network question (#65) · a legal conformance register (#66)
· a distributed chain (#58) and self-verified chain state (#57) · whether Sletchy runs on a
hardened OS or is one (#60) · multi-tenancy and a public release
([ADR-0004](../adr/0004-single-tenant-local-first.md)) · the `vm` isolation backend · a
native C++ Warden ([ADR-0001](../adr/0001-no-kernel-driver.md)) · Linux/macOS isolation
backends.

---

## The one rule about this roadmap

Waves are sequential because each one's guarantees depend on the previous one's. The
temptation will be to jump to Wave 3 or Wave 7 for something visible. **Wave 1 first.**
The reason is written down in [ADR-0003](../adr/0003-ledger-is-the-spine.md), so that
future-you arguing to skip it has to argue with past-you who already thought about it.
