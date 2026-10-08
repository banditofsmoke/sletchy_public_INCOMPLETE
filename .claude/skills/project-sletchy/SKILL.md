---
name: project-sletchy
description: >-
  Build, extend, and reason about Sletchy - the sealed personal enclave in this repo (private network+compute bubble with a self-contained SOC/NOC and a local-first assistant). Use when the user wants to work on Sletchy at all: implementing a wave item, opening or working an issue, writing a PR, adding a plane (kernel/warden/soc/mind/senses/forge/vault), touching isolation or the ledger, salvaging from Scraps and Parts, or asking "what's the state" / "what's next". Enforces LAW 0 (do no harm to the one host machine), the ledger-first architecture, and the writing conventions. Not for the ESL business, the agency site, or the Marketing OS - those are separate concerns in the parent folder.
---

# project-sletchy

You are building **Sletchy**: a sealed personal enclave - a private network-and-compute
bubble with a self-contained SOC/NOC, running a local-first assistant that learns from its
user and gates everything inside itself, including its own behaviour.

Repo: `https://github.com/banditofsmoke/sletchy_public_INCOMPLETE`, a public snapshot; development happens in a private repository.

**This is my learning project, not a revenue one.** Optimise for me understanding what
was built, not for speed. Explain trade-offs; I engage with them and push back well.
Do not let the ESL revenue push in the parent folder bleed into this repo.

---

## Read these before doing anything

In this order, every session. Do not work from memory of a filename.

1. **`docs/LAW/00-do-no-harm.md`** - LAW 0. Outranks everything, always.
2. `docs/LAW/laws.md` - the 11 checkable laws and the PR checklist.
3. `docs/LAW/writing-conventions.md` - commit, PR, and issue shape.
4. **`workload/STATUS.md`** - where the build is and what the next action is.
   `workload/BOARD.md` is the full queue in order.
5. **`learnings/README.md`** - the mistakes already made here, and the rules they bought.
   Read before writing any probe or any test that asserts a denial.
6. `docs/roadmap/waves.md` - the wave plan behind the board.
7. `CLAUDE.md` - current wave and any standing constraint.

Then whichever of these the task touches: `docs/LAW/architecture.md` (the planes),
`docs/LAW/isolation.md`, `docs/adr/`, `tests/adversarial/COVERAGE.md`.

---

## The one rule that outranks the rest

**LAW 0 - do no harm to the host machine.** Sletchy runs on my *only* computer. If it
bricks the host, the cost is my livelihood, not a rebuild weekend.

- **No kernel drivers, no Test Signing Mode, no bootstart services.** ADR-0001. Isolation
  comes from user-mode Windows APIs the kernel enforces: Job Objects, restricted tokens,
  AppContainer, Windows Firewall via `INetFwPolicy2`, ETW read-only.
- **All state under `SLETCHY_HOME`** (default `var/`). Nothing else on the host is written.
- **Every host change is reversible**, and its undo ships in the *same PR*, wired into
  `sletchy stop`.
- **Runs as a normal user.** One auditable elevation, for firewall rules only.
- Resource ceilings applied **before** a process starts, never after.
- Honeypot binds **loopback only** by default.

If a change could plausibly destabilise Windows, **say so before building it, not after.**

### The shape that works for anything touching the host

Proven by the AppContainer spike (ADR-0005), and I was comfortable with it:

1. **Phase it, safest first.** Inspect (no writes) → create-and-delete → the real test.
2. **Snapshot before and after**, and show me the diff. "117 profiles before, 117 after."
3. **Cleanup in a `finally`**, first in the block. One spike run crashed mid-probe and
   cleanup still completed - that is the rail working.
4. **Refuse to run elevated.** An elevated result does not describe how Sletchy runs.

---

## Architecture in one screen

Seven planes, depending **downward only** (enforced by import-linter *and* AST checks):

```
mind | senses | forge | vault     the capabilities
warden | soc                      enforcement and observation
kernel                            the trust root
```

Two structural rules:

1. **Nothing reaches the outside world except through the Warden.** A raw
   `httpx`/`socket`/`requests` import outside `warden/egress/` fails the build.
2. **Everything writes to the Kernel's ledger.** The SOC *reads* the ledger; it is not a
   parallel logging system.

`kernel` imports nothing from `sletchy`. `warden` and `soc` are siblings, not a stack.

---

## The invariants that are enforced structurally

These are not style. Each is a control, and each has a test asserting it stays true. If a
change would weaken one, stop and raise it.

| Invariant | How it is enforced |
|---|---|
| The ledger has **no repair function** | A test walks `dir(Ledger)` and fails on any `repair`/`rebuild`/`truncate`/`reset`/`recover`/`prune` method |
| An agent **cannot self-grant** a capability | `CapabilityIssuer`'s only public method is `issue()`, and its constructor requires a `PolicyGate` |
| Secrets **fail closed** | `SecretResolver.resolve()` has no `default=` parameter; a test asserts the exact parameter set |
| Policy **can only tighten** | `merge_profiles()` verifies its own output against both inputs; there is no `loosen`/`widen` anywhere |
| Dangerous flags are **off on a fresh install** | A test enumerates the *whole* registry, not a sample |
| `select()` **never downgrades** isolation | No `allow_downgrade`/`fallback`/`best_effort`; a test asserts the parameter set |
| `sletchy stop` **reverts from a wedged state** | Tested against a deliberately corrupted ledger |

**Adding an escape hatch to any of these is a security regression, however it is framed.**

---

## How to work

Everything ships through **issue → branch → PR → merge**. No direct commits to `main`
(a `pre-push` hook refuses; GitHub branch protection needs Pro, which I do not have).

- Branches: `wave2/egress-proxy`, `fix/ledger-throughput`, `spike/appcontainer`.
- Issues use the forms in `.github/ISSUE_TEMPLATE/`: build task, bug, spike. The three
  build-task fields people skip and shouldn't: **scope** (especially *permanently*
  excluded behaviour), **laws in play with how each is enforced in code**, and **known
  gaps stated before work starts**.
- PR titles are `type(scope): imperative subject`, at most 72 characters. Bodies use
  `.github/pull_request_template.md`'s headings in order (Summary, Changes, Tests, Risk,
  Not in scope), at most **one** extra section for a judgement call. CI runs
  `scripts/pr_check.py` on both; run it before posting.
- Commits: `type(scope): subject`, body ≤ 25 lines, **ASCII only**, bullets for changes and
  prose for reasoning, and **always a `Verified:` line with real numbers**.
- **No `Co-Authored-By` trailer.** I asked for this explicitly.
- `Closes #N` only for a full fix; `Refs #N` for a deliberate partial, and say what is left.

### Verify before claiming

```bash
uv run pytest                 # everything
uv run pytest -m "not slow"   # fast loop
uv run pytest -m law_zero     # the host-safety subset
uv run ruff check . && uv run ruff format --check .
uv run mypy                   # strict on kernel/
uv run lint-imports           # plane layering
python scripts/secret_scan.py
```

State CI honestly. If a job is a placeholder, say so in the PR.

---

## Honesty rules - these are the point of the project

- **Document what a control does *not* catch.** Residual gaps go in
  `tests/adversarial/COVERAGE.md`, visibly. "Probably fine" is not a coverage claim.
- **A row moves to Coverage only when a test passes**, never when a control is written.
- **A gap is recorded before it is fixed**, not after.
- **Never describe something as strong beyond what was measured.** `winjob`'s *filesystem*
  containment is measured (ADR-0005); its network and registry denial are **not**. Say
  "strong for filesystem", never "strong".
- **Every isolation probe needs a positive control that must succeed.** A suite of
  should-fail assertions passes trivially when nothing runs. This cost three probe runs in
  ADR-0005 §4 - the probe could not open its own output stream and read as "denies
  everything".
- If a test fails, say so with the output. Do not report completion on a partial pass.

---

## `Scraps and Parts/` is READ-ONLY

Absolutely. ~19 archived projects, the archaeology this repo mines. Read it, learn, then
**rebuild from scratch** under the laws. Never import, never copy a file, never write to
it. It holds six old API keys (all six dead since 2026-10-08) and ~3.5 GB of venvs; it is gitignored in full. Every
salvaged idea gets a row in `docs/salvage/INVENTORY.md` with a verdict (REBUILD / PATTERN
/ DATA / REFERENCE / DROP) and a destination.

## Sletchy stands on its own

Sletchy's laws are its own: **LAW 0, then LAWs 1-10.** No outside design doc wins by
default, and none is referenced anywhere in this repo; `tests/unit/test_repo_hygiene.py`
fails the build if one appears. Sletchy is my own bubble; the public release will be
called **Uttu** ([ADR-0007](../../../docs/adr/0007-sletchy-and-uttu.md)).

---

## Where the build is

**`workload/STATUS.md`.** Read it - do not read a summary of it here.

This section used to carry its own copy of the counts, the closed issues and the next item.
It went stale within three PRs and was believed anyway, which is
[L005](../../../learnings/L005-a-tripwire-nobody-rereads-never-fires.md) and
[L006](../../../learnings/L006-measure-the-number-never-recall-it.md) in one place. A second
copy of a fact is a second thing to get wrong.

- `workload/STATUS.md` - where the build is, what was verified on this box and when, and
  the single next action
- `workload/BOARD.md` - every open issue in the order worth doing, and why that order
- `docs/roadmap/waves.md` - the wave plan the board is derived from

---

## Session flow

1. **Orient.** Read the LAW docs and `waves.md`. Run `gh issue list` and `git log --oneline -5`.
   Do not guess the state.
2. **Pick one issue.** If I did not name one, propose the single best next item in one
   line - the one that could invalidate a design decision goes first - then do it.
3. **Branch, build, test, PR.** Follow the conventions above. Verify with real numbers.
4. **Record what you did not cover.** Update `COVERAGE.md` in the same PR.
5. **File what you found.** Something out of scope discovered while working becomes its own
   issue, not a smuggled change in an unrelated PR.
6. **Update `workload/STATUS.md`** - it is the next session's starting point, and a stale
   one is worse than none.
7. **Write a learning if something went wrong.** One file in `learnings/`, and only if it
   *already happened*. The bar is a mistake that cost something, not a risk that might.

If I say "keep going" or "as you see fit", take the next wave item and run the full
loop. I trust the process; keep earning it by being honest about gaps.
