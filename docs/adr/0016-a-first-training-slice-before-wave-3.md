# ADR-0016 - A first training slice comes before Wave 3

**Status:** Accepted · 2026-10-05. Moves a slice of Wave 8 (#55) ahead of Waves 3 to 7
in [waves.md](../roadmap/waves.md), as [ADR-0008](0008-desktop-shell.md) did for the
Shell. *Order changed the same day by [ADR-0017](0017-a-model-before-training-through-one-local-door.md):
a model is asked before one is trained. Steps 1 and 2 below are done; 3 to 5 wait.*

## Context

Training Sletchy's own model is one of the founding goals of this project, and the
operator wants to start on it now. The roadmap puts it in Wave 8, the Forge, behind the
Mind, the SOC, memory, the Shell and the Senses. Waves are sequential because each one's
guarantees depend on the last ([ADR-0003](0003-ledger-is-the-spine.md)), and the
temptation to build something visible early is the failure that rule was written to
stop.

So the question is not "is training more exciting than Wave 3" but **which guarantees a
first fine-tune actually depends on**:

| A first fine-tune needs | Which wave | State |
|---|---|---|
| Every step recorded before it takes effect | 1, the ledger | Done |
| A process that cannot take the machine down or reach out | 2, `winjob` | Done for filesystem, resources and process tree; network over TCP measured (ADR-0006); UDP unmeasured (#71) |
| Its dependencies vetted before they run | 2, the supply gate (#34) | Done |
| The GPU, from inside that process | 2, measured by #168 | **Works** ([ADR-0015](0015-a-sandboxed-program-can-use-the-gpu.md)) |
| A conversation, a router, tools | 3, the Mind | Not needed: nothing talks to the model |
| Detection, the NOC | 4, the SOC | Not needed for one deliberate run |
| What Sletchy learned about its user | 5, memory | Not needed, and deliberately excluded: the data is one the operator names |
| A window, voice, vision | 6, 7 | Not needed |

A first slice depends on Waves 1 and 2 only, and jumps no guarantee. That is the test
ADR-0008 applied, and it passes here for the same reason. **The operator decided on
2026-10-05 to pull it forward if #168 showed a sandbox could use the GPU; it did.**

## Decision

1. **One slice of #55 is built before Wave 3.** Waves 3 to 7 keep their order, and
   nothing else in Wave 8 moves.
2. **The slice is one run:** fine-tune one small open-weight model (about 1 to 4 billion
   parameters, 4-bit, on one 8 GB card) with Unsloth, on a dataset the operator names,
   inside `winjob`, with no network, every step on the ledger. Its output is an adapter,
   stored by content like any other payload.
3. **It is built in this order, each step its own issue and PR, and none starts before
   the one above it has landed:**
   1. **The host first, and the operator's to do.** The graphics-driver service stops
      failing in a loop (a clean driver reinstall), and there is disk for the weights
      and the checkpoints. A training run holds the card at full load for hours; on
      this machine's driver that is a LAW 0 risk, and nothing in Sletchy can repair it
   2. **#71's UDP measurement.** A training run is the first time Sletchy runs gigabytes
      of code it did not write. That code must meet a network lock measured for every
      protocol it could use, not only TCP
   3. **The training stack through the supply gate (#34, #170),** in a `forge` dependency
      group that the Kernel never installs: each package with a written reason, its
      licence checked, OSV asked, and imported in quarantine. **Each new dependency is
      approved by the operator in its own PR**: today's rule is no new dependencies, and
      this ADR does not lift it
   4. **The weights,** fetched by the operator outside Sletchy, checked against a hash
      recorded in the repository, and loaded as safetensors only, never pickle (#83). A
      sandbox is given no network to fetch them
   5. **The runner, `forge/train`,** to #55's contract: `forge_training` (already
      dangerous, off) gates it; it refuses to start under its floors (free card memory,
      free disk, battery); it runs under a training profile with raised memory, process
      and wall-clock caps, and `ProgramFiles` in its environment (ADR-0015 finding 2);
      the run is on the ledger before it starts and after it ends (dataset and model
      digests, every setting, the resolved versions, why it stopped); `sletchy panic`
      kills it like any sandbox run
4. **Out of the slice:** serving or talking to the model (Wave 3); measuring it against
   a baseline (#41); training on the ledger or on conversations, which #55 rules out by
   default (Wave 5); more than one card; any schedule.

## Consequences

- **The GPU is not confined** (ADR-0015). A training run, and anything else in a
  sandbox, can use the whole card. The floors check free card memory before a run
  starts; nothing limits it during one
- **The training stack must be readable inside the container.** ADR-0015 copied a
  30 MB interpreter into the workspace; a training stack is gigabytes and cannot be
  copied per run. One environment under `var/`, granted read-only to the lanes and
  revoked by panic, is the likely shape. It is decided in step 5, with a test that panic
  takes the grant away
- **Native Windows only.** WSL is a virtual machine, which ADR-0014 keeps off this
  machine. Whether Unsloth's stack runs natively on this card is measured in step 3,
  not assumed
- Wave 2's other open items (#32's gate handed to the supervisor, #146's last piece)
  do not block the slice. #71's UDP round does, at step 2

## What this does not decide

- The base model and the dataset: the operator's, at the run
- Whether the slice's output ever becomes open weights for Uttu (#83)
- Anything about Waves 3 to 7, which proceed as written once the slice has landed
