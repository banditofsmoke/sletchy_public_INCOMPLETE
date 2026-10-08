# Board - everything open, in the order worth doing

Updated **2026-10-07**. [STATUS.md](STATUS.md) is the session-start read; this is the queue behind
it. **37 issues open** on 2026-10-07, once #184 closed. Every open issue has an Abuse cases
section.

Waves are sequential on purpose ([ADR-0003](../docs/adr/0003-ledger-is-the-spine.md)), so
most of this order is not a judgement call. **Only the first five are load-bearing** - the
rest follows from the wave it sits in.

**Two threads work this board at once** since 2026-10-03, each in its own worktree:

- the **main thread** takes the window (`apps/desktop/`), the docs, STATUS and this board
- the **second thread** takes user stories and the tests that hold them (`docs/stories/`,
  `tests/`), and files every bug it finds as an issue

Neither does elevated work.

## Done - Wave 2, complete 2026-10-07

I accepted the loopback gap as written (#184); a filter below the firewall is filed for later,
only if needed (#188). What it does not hold is in COVERAGE.

| | Item | State | Next action |
|---|---|---|---|
| 1 | **[#33](https://github.com/Sletch/sletchy/issues/33)** - firewall app rules | **Closed 2026-10-05.** Built in #159 ([ADR-0013](../docs/adr/0013-sandbox-lanes-so-a-firewall-rule-can-name-the-container.md)); reported by the self-check (#169) | Measured to bind for TCP and UDP over IPv4, and removed and put back on my machine (ADR-0006 findings 8 and 9). `confines_network` decided: not claimed, for IPv6 (#173) and loopback |
| 2 | **[#32](https://github.com/Sletch/sletchy/issues/32)** - the mediating proxy | **Built in #160**: gate, proxy, client, wired into `winjob` | `egress_enabled` stays unwired on purpose until Wave 3's tools need it, and a host list is decided ([waves.md](../docs/roadmap/waves.md), 2026-10-07) |
| 3 | **[#71](https://github.com/Sletch/sletchy/issues/71)** - does the network stay shut | **Closed 2026-10-05.** Findings 5, 7, 8 and 9: over IPv4 both locks drop TCP and UDP, each named in Windows' drop log | IPv6 needs a machine with an IPv6 route: [#173](https://github.com/Sletch/sletchy/issues/173), `later` |
| 4 | **[#146](https://github.com/Sletch/sletchy/issues/146)'s last piece** - command lines of running processes | `processes`, `network`, `events` and `startup` landed (#151, #156, #157) | Read them, masked with the secret shapes |
| 5 | **[#34](https://github.com/Sletch/sletchy/issues/34)** - supply chain | **Done in #161**: the quarantine run, and OSV asked about every lockfile in CI | Written down, not built: vetting decisions as ledger entries |

## Done - the rest of Wave 2

| | Item | Notes |
|---|---|---|
| 6 | [#70](https://github.com/Sletch/sletchy/issues/70) - container backend | **Done in #162**: Linux only, never on Windows ([ADR-0014](../docs/adr/0014-the-container-backend-runs-on-linux-only.md)); proven on CI's Ubuntu runner with rootless Podman |

Landed in Wave 2 on 2026-10-03 and 2026-10-04, and off this board: #149 (#155), #84 ([ADR-0011](../docs/adr/0011-the-soc-is-a-bolt-on-and-reaches-the-shell-through-the-ledger.md)),
#86 (`ledger show --payload`), #68 (fsguard), #69 (the supervisor), #52 (`sandbox run`).

## The first model (Wave 3, started)

Sletchy asks a model before it trains one
([ADR-0017](../docs/adr/0017-a-model-before-training-through-one-local-door.md)).

| | Item | Notes |
|---|---|---|
| M1 | `sletchy models` and `sletchy ask` | **Built 2026-10-05**: one local door, the card budget, the context meter. My first real question is next |
| M2 | [#175](https://github.com/Sletch/sletchy/issues/175) - a server inside a sandbox, reached on loopback | **Measured 2026-10-05**: reached (ADR-0006 finding 10) |
| M3 | My own llama.cpp build | Mine to study first. Then the door's `llama.cpp` engine, and the server inside a lane, which closes the download half of the loopback gap (#184) |

## The first training slice (Wave 8, pulled forward, waiting behind the model)

A sandboxed program can use the GPU ([ADR-0015](../docs/adr/0015-a-sandboxed-program-can-use-the-gpu.md)),
and a first fine-tune depends on Waves 1 and 2 only, so one slice comes before Wave 3
([ADR-0016](../docs/adr/0016-a-first-training-slice-before-wave-3.md)). In this order:

| | Item | Notes |
|---|---|---|
| T1 | The graphics driver | **Done 2026-10-05**: reinstalled by me; no failure since 17:58 on the 4th |
| T2 | #71's UDP round | **Done 2026-10-05**: both locks drop UDP (ADR-0006 finding 9) |
| T3 | [#170](https://github.com/Sletch/sletchy/issues/170) - the training stack through the supply gate | A `forge` group the Kernel never installs; each dependency approved by me in its PR |
| T4 | [#83](https://github.com/Sletch/sletchy/issues/83) - the weights | Fetched by me, checked by hash, safetensors only |
| T5 | [#55](https://github.com/Sletch/sletchy/issues/55) - the runner | `forge_training` off by default, floors, a training profile, the run on the ledger, Stop everything ends it |

## Recall (Wave 5, pulled forward into Wave 3)

Sletchy forgets the oldest turns of a conversation, and everything between conversations.
I want it to remember and look things up before the router, the tools and the agents are
built on it ([ADR-0019](../docs/adr/0019-recall-comes-into-wave-3.md)). In this order:

| | Item | Notes |
|---|---|---|
| R1 | [#194](https://github.com/Sletch/sletchy/issues/194) - the recall store | **Built in #199**: chunks at three sizes, words and vectors, standard library only, behind `mind_memory`, and `sletchy memory`. Conversations are kept as they are answered since #200 |
| R2 | [#195](https://github.com/Sletch/sletchy/issues/195) - the evidence gate | **Built in #200**: the chat model judges every candidate; thresholds in code; "not in my memory". Measured by `sletchy memory measure` on a seed set (#201); the first judge's numbers wait for my own run, on my machine |
| R3 | [#193](https://github.com/Sletch/sletchy/issues/193) - the context plan | **Recalled passages built in #200**: quoted with their source, the plan recorded before the question. Left: a time budget per turn |
| R4 | [#197](https://github.com/Sletch/sletchy/issues/197) - Gemma 4 E2B and EmbeddingGemma | Spike: fit, speed and embeddings on my card. I pull them by hand |
| R5 | [#196](https://github.com/Sletch/sletchy/issues/196) - my own decision model | Spike: train a judge on my card once the training stack (#170) is in |
| R6 | [#202](https://github.com/Sletch/sletchy/issues/202) - load a model first, and choose the context | **Built in #203**: Load model and its status, the context measured on the card, 30 minutes kept, Unload |
| R7 | [#204](https://github.com/Sletch/sletchy/issues/204) - keep embedding models out of the chat picker | **Built in #206**: `POST /api/show` at the door, the model listed and greyed, refused a load, a failed load on the record |
| R8 | [#205](https://github.com/Sletch/sletchy/issues/205) - a stored refusal outranks the fact, and the judge keeps it | **Built in #206**: non-answers not kept, refusals and bare questions set aside before the judge, an unreadable judge said |
| R9 | [#207](https://github.com/banditofsmoke/sletchy/issues/207) - sections in the model list, and a bar while it waits | **Built in #213**: talk, memory search, Ollama's own names, too big; each name once; a bar against last time's load or answer |
| R10 | [#208](https://github.com/banditofsmoke/sletchy/issues/208) - a model mixes up whose name is whose | **Framing built in #213**: every model is told a Question is mine and an Answer is a model's. Left: store each turn with who spoke and which model |
| R11 | [#212](https://github.com/banditofsmoke/sletchy/issues/212) - search memory by meaning in the window | Choose memory's embedding model from the list; give what memory holds its vectors once. After #197 |
| R12 | [#211](https://github.com/banditofsmoke/sletchy/issues/211) - memory by time | Dates on every chunk and in every passage, time words in a question; then days, months and years behind `mind_memory_rollups` |

## The window (Wave 6, pulled forward)

I asked for a window first, so it was built ahead of its wave
([ADR-0008](../docs/adr/0008-desktop-shell.md)). It talks only to the Kernel that exists
today, so it jumps no guarantee; it adds no capability.

| | Item | Notes |
|---|---|---|
| 7 | [#91](https://github.com/Sletch/sletchy/issues/91) - the Uttu network simulator | **Waits until #32, #33 and #71 phases 2-3 land** (decided 2026-10-03, on the issue). Seeded, local-only: 500 users, hobby channels, private messages, a stress dial, a scammer scenario. Nothing leaves the machine |
| 8 | [#60](https://github.com/Sletch/sletchy/issues/60) the OS question · [#63](https://github.com/Sletch/sletchy/issues/63) comms · [#65](https://github.com/Sletch/sletchy/issues/65) the verified-network boundary | Spikes and decisions, not builds |
| 8a | [#209](https://github.com/banditofsmoke/sletchy/issues/209) - the window can open behind other windows after a build | Windows keeps the front for the program I am using; measure `set_focus`, else flash the taskbar |
| 8b | [#210](https://github.com/banditofsmoke/sletchy/issues/210) - an installer for a first small release | Per user, no administrator, nothing system-wide, signed or not shipped. An ADR first; the release is Uttu |

## Now - Wave 3, the first thing to talk to

| | Item | Notes |
|---|---|---|
| 9 | [#35](https://github.com/Sletch/sletchy/issues/35) - the harness | Stream-first executor, 11 event types. Foundation for the rest. **Built #190 and #191** (ADR-0018): a conversation in the terminal and in the window. Left: words as they arrive, `INTERRUPT` with tools, hosts that listen |
| 10 | [#36](https://github.com/Sletch/sletchy/issues/36) - the router | Provider, endpoint, catalog, binding |
| 11 | [#54](https://github.com/Sletch/sletchy/issues/54) - refuse a model that will not fit VRAM | `law-0`. **The refusal before the loader** - deny-by-default applies to our own convenience too |
| 12 | [#53](https://github.com/Sletch/sletchy/issues/53) - llama.cpp and Ollama adapters | The default model becomes local and offline |
| 13 | [#62](https://github.com/Sletch/sletchy/issues/62) - what an agent may do with no goal | **Before #59, not after.** A long-running Sletchy with nothing to do is exactly what this governs |
| 14 | [#59](https://github.com/Sletch/sletchy/issues/59) - a long-running `sletchy` | The first time anything listens |

## After - Wave 4 and the cross-cutting one

| | Item | Notes |
|---|---|---|
| 15 | [#66](https://github.com/Sletch/sletchy/issues/66) - legal conformance register | Cheap, and it belongs **before** the honeypot and any feed. Also where "no hack-back, ever" is permanently recorded |
| 16 | [#37](https://github.com/Sletch/sletchy/issues/37) - trust scoring that gates capabilities | Everything else in Wave 4 depends on it |
| 17 | [#38](https://github.com/Sletch/sletchy/issues/38) - honeypot | Loopback-only by default. Closes a Planned COVERAGE row |
| 18 | [#51](https://github.com/Sletch/sletchy/issues/51) - threat feeds | Phase 1 only: a research baseline. More suspicious, never more permissive |

## Later - Waves 5, 8, 9

| | Item |
|---|---|
| 19-20 | [#39](https://github.com/Sletch/sletchy/issues/39) memory · [#40](https://github.com/Sletch/sletchy/issues/40) RAG catalog |
| 21-25 | [#41](https://github.com/Sletch/sletchy/issues/41) bench · [#81](https://github.com/Sletch/sletchy/issues/81) the Workshop · [#82](https://github.com/Sletch/sletchy/issues/82) datasets · [#83](https://github.com/Sletch/sletchy/issues/83) models · [#55](https://github.com/Sletch/sletchy/issues/55) Unsloth fine-tuning |
| 26 | [#64](https://github.com/Sletch/sletchy/issues/64) borrowed GPU |
| 27-29 | [#42](https://github.com/Sletch/sletchy/issues/42) contracts · [#57](https://github.com/Sletch/sletchy/issues/57) self-verified chain state · [#58](https://github.com/Sletch/sletchy/issues/58) distributed chain ADR |

## Filed, deliberately not scheduled

[#56](https://github.com/Sletch/sletchy/issues/56) federation,
[#61](https://github.com/Sletch/sletchy/issues/61) the signed board,
[#89](https://github.com/Sletch/sletchy/issues/89) Uttu Commons,
[#90](https://github.com/Sletch/sletchy/issues/90) Uttu Connect,
[#114](https://github.com/Sletch/sletchy/issues/114) llama.cpp or vLLM once training starts,
[#188](https://github.com/Sletch/sletchy/issues/188) a filter below the firewall for a sandbox's loopback, only if needed,
[#133](https://github.com/Sletch/sletchy/issues/133) an installer for Windows and Ubuntu, for Uttu's release, and
[#127](https://github.com/Sletch/sletchy/issues/127) anchoring the ledger in a chain, holding no
value, ever, which I mean to be Sletchy's own chain code, years from now.

These exist to **hold their design constraints while the reasoning is fresh**, not to
schedule work. Every one of them is networked or multi-tenant, which is the opposite of
[ADR-0004](../docs/adr/0004-single-tenant-local-first.md), and none of them may ever join
anyone to anything automatically ([ADR-0007](../docs/adr/0007-sletchy-and-uttu.md)).
**Filed is not scheduled.**

## How this order was chosen

1. **The thing that can invalidate a design decision goes first.** That is why a spike
   outranks the feature it gates, and why #71 sits above #32 despite being smaller
2. **Waves are sequential**, so within a wave the order is dependency, and across waves
   there is no choice to make
3. **Small unblocked items that make later work observable** get pulled forward - #86
   makes every later ledger entry readable in full
4. **A refusal path is built before the thing it refuses** (#54 before #53), because
   deny-by-default is not a feature you retrofit
