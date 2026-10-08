# Sletchy - working rules

**Invoke `/project-sletchy`** to load the full working skill for this repo
(`.claude/skills/project-sletchy/SKILL.md`).

Codename **Sletchy**. Placeholder repo name: `unnamed project evelution v0.0.001`.

A sealed personal enclave: a private network-and-compute bubble with a SOC/NOC at its
centre, running a local-first assistant that learns from its user and gates everything
that happens inside itself - including its own behaviour.

**Private. Single-user. One machine.**

---

## Read before doing anything

In this order, every session:

1. **[`docs/LAW/00-do-no-harm.md`](docs/LAW/00-do-no-harm.md)** - outranks everything.
2. [`docs/LAW/laws.md`](docs/LAW/laws.md) - the checkable rules.
3. [`docs/LAW/principles.md`](docs/LAW/principles.md) - the reasoning.
4. [`docs/LAW/architecture.md`](docs/LAW/architecture.md) - the planes.
5. **[`workload/STATUS.md`](workload/STATUS.md)** - where the build actually is, and the
   next action. [`workload/BOARD.md`](workload/BOARD.md) is the queue behind it.
6. **[`learnings/`](learnings/README.md)** - rules earned from things that already went
   wrong here. Half of them are one theme: **a test that passes for the wrong reason is
   worse than no test**, because it turns an unknown into a false certainty.
7. [`docs/roadmap/waves.md`](docs/roadmap/waves.md) - the wave plan behind the board.

Also relevant: [`docs/LAW/isolation.md`](docs/LAW/isolation.md), [`docs/adr/`](docs/adr/).

**Sletchy is my own bubble. The public release will be called Uttu**
([ADR-0007](docs/adr/0007-sletchy-and-uttu.md)). Sletchy's laws are its own: LAW 0, then
LAWs 1-10. No outside design doc wins by default, and none is referenced.

I am the operator, and the author of every commit here: call me by that first name. The
Windows account on this PC carries another name because the machine was bought second hand:
that is the account, not me, and it is never renamed (renaming a Windows profile breaks
installed software, and this is my only computer).

---

## The five things that get broken most often

1. **`Scraps and Parts/` is read-only. Never write to it. Never import from it.**
   It is archaeology. Read it, learn, then rebuild from scratch under the laws.
   Every salvaged idea is logged in
   `docs/salvage/INVENTORY.md` with a verdict and a
   destination. It is gitignored in full - 3.5 GB of venvs, `node_modules`, model blobs,
   and six old API keys, all six dead since 2026-10-08.

2. **Nothing happens off-ledger.** Every decision, tool call, model call, egress attempt,
   flag flip, and capability grant appends to the ledger *before* it takes effect. A code
   path that can act without a ledger append is a bug, not an optimisation.

3. **Deny by default.** If the policy file were empty, every feature should do nothing.

4. **Flags default off.** On a fresh install with no configuration, anything touching
   network, filesystem outside `var/`, microphone, camera, screen, wallet, or training is
   inert.

5. **Nothing is trusted - including imports.** Dependencies are pinned by version *and*
   hash, pass the vetting gate, and are profiled in quarantine before widening.

---

## Host safety - non-negotiable

This runs on the operator's **only** computer. See
[LAW 0](docs/LAW/00-do-no-harm.md).

- **No kernel drivers. No Test Signing Mode. No bootstart services.** Ever, in v1.
  Isolation comes from user-mode APIs the kernel enforces: Job Objects, restricted
  tokens, AppContainer, Windows Firewall via `INetFwPolicy2`, ETW read-only.
- **All state under `var/`.** Sletchy writes nowhere else on the host.
- **Every host change is reversible**, and `sletchy stop` reverts all of it.
- **Runs as a normal user.** One auditable elevation, for firewall rules only.
- Resource ceilings applied **before** a process starts, never after.
- Honeypot binds **loopback only** by default.

If a change could plausibly destabilise Windows, stop and say so. Do not build it and
mention the risk afterwards.

---

## Spec before code

Confirm scope before large changes. The waves in
[`docs/roadmap/waves.md`](docs/roadmap/waves.md) are sequential on purpose - each wave's
guarantees depend on the previous one's. **Do not jump ahead to something visible.**
The reasoning is in [ADR-0003](docs/adr/0003-ledger-is-the-spine.md).

Current wave: **Wave 3 - the Mind**, starting with the harness (#35), then recall: memory,
an evidence gate and a context plan, pulled forward from Wave 5
([ADR-0019](docs/adr/0019-recall-comes-into-wave-3.md)). Wave 2 (the Warden)
is complete (2026-10-07), with what it does not hold written in COVERAGE. Wave 1 (the
Kernel) is complete: ledger, payload store, policy, capabilities, secrets, flags, CLI, and
the LAW 0 test suite.

The **AppContainer spike (#12) is closed** - see [ADR-0005](docs/adr/0005-appcontainer-findings.md) -
and the **`winjob` backend (#31) is built**. Measured on 10.0.19045: filesystem denial
across volumes, job limits applied before the process exists, a detached grandchild dying
with the job, and the Job Object + restricted token + AppContainer combination composing
without one voiding another.

**Its network and registry denial are still unverified.** `winjob` does not claim
`confines_network`, and a test enforces that. Describe it as "strong for filesystem,
resources, and process tree" - never as strong generally - until the egress work measures
the rest.

Sandbox launches are now **on the ledger** (#46): every launch, completion, forced stop and refusal
appends before it takes effect, and a backend cannot be constructed without a recorder.

**Wave 2's code is built** (2026-10-04): the egress gate and the sandbox proxy (#32,
#160), sandbox lanes and `sletchy install-rules` (#33, #159,
[ADR-0013](docs/adr/0013-sandbox-lanes-so-a-firewall-rule-can-name-the-container.md)), the
quarantine run and OSV in CI (#34, #161), and the container backend, Linux only (#70, #162,
[ADR-0014](docs/adr/0014-the-container-backend-runs-on-linux-only.md)). An AppContainer
reaches loopback and is refused other machines over TCP on 10.0.19045
([ADR-0006](docs/adr/0006-egress-binding-findings.md) findings 1 and 5); on Windows Server
2025 it cannot reach loopback at all (finding 6).

**The rules bind** (2026-10-04, ADR-0006 finding 8). They are installed on my
machine, and loopback still reaches the proxy. With the container's own lock opened
(`internetClient`), a lane was refused at once while a container no rule names got out.
That is TCP over IPv4. **Both locks drop UDP too** (2026-10-05, finding 9): Windows' own
drop log named the container's default block and the lane's rule for each datagram. My
machine has no IPv6 route (#173), and loopback reaches every local service, so `winjob`
still claims no `confines_network`. `egress_enabled` stays unwired on purpose until
Wave 3's tools need it ([waves.md](docs/roadmap/waves.md)). A firewall rule cannot narrow
a sandbox's loopback (2026-10-07, ADR-0006 finding 11); I accepted that gap as written
(#184), which completed Wave 2.

**Sletchy asks a model on this computer** (2026-10-05,
[ADR-0017](docs/adr/0017-a-model-before-training-through-one-local-door.md)): `sletchy ask`,
through one door to `127.0.0.1` and one port (`warden/egress/local.py`), never a request
that makes the server fetch, write or delete; every question and answer on the ledger;
my card budget (a model takes at most 70% of the card, so its context fits) and a
context meter. Ollama is asked, never embedded: my own llama.cpp build replaces it
when I have studied it. Training waits behind this. `sletchy chat` and the window's Talk
plate hold a conversation
through the harness ([ADR-0018](docs/adr/0018-the-harness-one-stream-per-turn-every-event-on-the-record.md)):
one stream of events per turn, each on the record before it is shown.

**A first training slice comes before Wave 3** (2026-10-05,
[ADR-0016](docs/adr/0016-a-first-training-slice-before-wave-3.md)). A program in a `winjob`
sandbox was measured to use the GPU ([ADR-0015](docs/adr/0015-a-sandboxed-program-can-use-the-gpu.md)),
which is also a gap: `winjob` does not confine the GPU. Its first two steps are done
(2026-10-05): the graphics driver was reinstalled and its crash loop stopped, and #71
measured UDP. Next is the training stack (#170), each dependency approved by me in its
own PR.

---

## Git workflow

Everything ships through **issue → branch → PR → review → merge**. No direct commits to
`main`.

- Branch naming: `wave1/ledger-hash-chain`, `fix/egress-allowlist-bypass`
- **Follow [`docs/LAW/writing-conventions.md`](docs/LAW/writing-conventions.md)** for every
  commit, PR, and issue. Commits are `type(scope): subject`, body <= 25 lines, bullets for
  changes and prose for reasoning, ASCII-only, and **always a `Verified:` line with real
  numbers**. A PR's title is `type(scope): imperative subject`, at most 72 characters, and
  its body uses `.github/pull_request_template.md`'s headings in order; CI checks both
  (`scripts/pr_check.py`).
- Issues use the three forms in `.github/ISSUE_TEMPLATE/`: build task, bug, spike.
- `Closes #N` only for a full fix; `Refs #N` for a deliberate partial, and say what is left.
- Never `--no-verify`. Never bypass signing. If a hook fails, fix the cause.
- Commit or push only when asked.

---

## Style

- Python 3.13, `uv` for env and deps, Pydantic for every schema.
- Type hints everywhere. Pydantic models are the source of truth - **never hand-write a
  parallel JSON Schema, OpenAPI spec, or UI form.** Generate them.
- Match the surrounding code's idiom, naming, and comment density.
- Tests live beside the risk: `tests/unit/` per module, `tests/adversarial/` for the
  attack→test matrix, `tests/e2e/` for full-bubble scenarios.
- Plane dependencies are enforced by an import-linter test. `kernel` imports nothing from
  Sletchy; `warden` and `soc` import only `kernel`, and nothing imports `soc`; the Shell
  (`cli`) imports `kernel`, `mind` and the Warden's supervisor only, and reads the SOC
  through the ledger (ADR-0011);
  everything else imports `kernel` +
  `warden`. Upward or sideways imports fail the build.

---

## Honesty rules

- **Document what a control does not catch.** Residual gaps go in
  `tests/adversarial/COVERAGE.md`, visibly. "Probably fine" is not a coverage claim.
- Do not describe a control as working until its adversarial test passes. If a test
  fails, say so with the output.

---

## Secrets

- OS keychain only. Config holds `secret_ref`s, never values.
- **Fail closed** on a missing secret. Never a fallback default - that exact pattern
  (`os.environ.get("GROQ_API_KEY", "gsk_live…")`) is why six keys leaked across the old <!-- secret-scan: allow -->
  projects. See `docs/salvage/CREDENTIALS-TO-ROTATE.md`.
- A pre-commit secret scan and the same sweep in CI block regressions.

---

## Related

The parent folder is the company working space, with its own
`CLAUDE.md` and `source of truth.md` (ESL product, agency site, marketing OS). **Sletchy
is a separate concern** - it is not part of the ESL revenue push and does not share its
constraints. Do not let one bleed into the other.
