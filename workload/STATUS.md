# STATUS - read this first

Last updated **2026-10-08**. The queue behind this is [BOARD.md](BOARD.md), refreshed the same
day.

## Where we are

`main` at `e077a63`, plus #116, when this section was written. Landed 2026-10-02/03, all CI green:

| PR | What |
|---|---|
| #75 | No em dashes anywhere, and a hygiene test that keeps it so |
| #77 | Sletchy stands on its own; [ADR-0007](../docs/adr/0007-sletchy-and-uttu.md): Sletchy is mine, **Uttu** is the public name; the three human questions |
| #79 | **`sletchy panic` proves each undo** - its firewall step had never worked ([L009](../learnings/L009-could-not-look-is-not-nothing-there.md)) |
| #85 | `sletchy bridge` (stdio, no socket), `sletchy selfcheck`, `sletchy ledger show` |
| #88 | **The desktop window** ([ADR-0008](../docs/adr/0008-desktop-shell.md)): Tauri v2, the Kernel started suspended in a Job Object |
| #92 | **The Orrery Vault**: steampunk and full width, the vault-door opening (its tests found the door never let you in), the live NOC, `Flag.serves` |
| #107 | **`Open-Sletchy.cmd`**: double-click to open Sletchy, with no installer. Plus [WHAT-A-CLICK-CAN-DO.md](../apps/desktop/WHAT-A-CLICK-CAN-DO.md), the map of every request the window can send, kept complete by a test ([L010](../learnings/L010-test-a-launcher-before-you-launch-it.md)) |
| #108 | The sandbox residue tests check the profiles a run made, not every app on the machine |

### The hardening lane (second thread)

User stories for five people - Simple, Custom, Raw, Clumsy, Abuser - drove the CLI and the
window's bridge the way a confused, careless or hostile person would (#106). Every defect they
found was filed, decided and fixed, each proven failing against the old code first. **The
lane is finished:** all 155 acceptance criteria are held by a named test, and none is a GAP.

| PR | Issue | What a person could do before |
|---|---|---|
| #109, #120 | #94 | **Aim Stop everything at the home folder and another app's container** with one forged journal line. Panic now acts only on its own profile name, the SID Windows derives from it, and paths the Warden's grant guard accepts. The guard moved into the Kernel so both share one copy ([L011](../learnings/L011-a-copy-of-a-guard-is-not-the-guard.md)) |
| #113 | #96 | Print a fake ledger entry, or terminal escape codes, through a reason; crash `ledger show` with one emoji; turn a dangerous switch on with an invisible reason |
| #117 | #112 | (a flaky test) Batching is proven by counting fsyncs, not timing a shared runner |
| #118 | #115 | Make every action slower than the last: one flip took 741 ms at 40,000 entries, now 29 ms flat |
| #119 | #97 | Get a Python traceback from a damaged `var/`; now one sentence and an exit code |
| #121 | #103 | Hide a change from panic behind one unreadable journal line |
| #122 | #104 | Leave the camera on under a ledger entry saying off, when the file write failed |
| #123 | #102 | Start a second, empty Sletchy just by running `status` in another folder |
| #124 | #95 | Fork the ledger beyond repair by writing from two processes at once |
| #125 | #100 | Turn a dangerous switch on by editing `flags.json`, with no record |
| #126 | #98 | Lose a crash's cut-off last line in a generic error, a traceback, or a silent corruption |
| #129 | #101 | Fill the disk with a loop of appends. Now 1 GB, never below 2 GB free (my numbers), and switching off keeps a reserve |
| #130 | #99 | Delete or shorten the ledger and have it called verified. A high-water mark now lives in the keychain beside the signing key |
| #131 | #105 | (tests) The last seven story criteria, two of them against a real Kernel process: killed mid-life, and flooded with hostile lines |
| #132 | #116 | Wait 15 s for every click on a year-sized ledger. An ordinary open now checks sealed segments by fingerprint: 0.28 s at 52 MB, 2.4 s at 201 MB ([ADR-0009](../docs/adr/0009-opening-the-ledger-checks-sealed-segments-by-fingerprint.md)) |

### Wave 2's middle (2026-10-03 evening)

I asked for the open issues to be worked down in order, every issue and PR left written
for a public reader, and LAW 0 made stronger by tests before any of it. In order, all CI green:

| PR | Issue | What |
|---|---|---|
| #136 | #135 | **The suite cannot touch the machine.** `tests/conftest.py` refuses an elevated run, points `SLETCHY_HOME` at a temporary folder, makes the real keychain unreachable, and refuses host-changing programs, network calls off the machine, and anything opened on the desktop; an unexpected refusal fails the run. The LAW 0 scan now reads every language shipped ([L013](../learnings/L013-a-guard-every-test-must-remember-will-be-forgotten.md)) |
| #138 | #137 | The payload store has the ledger's ceiling and floor: 3 GB, never below 2 GB free |
| #140 | #139 | **Written for a public reader** ([writing-conventions §0](../docs/LAW/writing-conventions.md)): every issue and PR states its abuse cases; `scripts/public_check.py` refuses machine-specific names, and CI runs it on every PR. 76 old texts swept |
| #141 | #84 | [ADR-0011](../docs/adr/0011-the-soc-is-a-bolt-on-and-reaches-the-shell-through-the-ledger.md): the SOC is a bolt-on that nothing imports, and the Shell reads it through the ledger |
| #142 | #86 | `sletchy ledger show --payload`: the body rehashed against its entry, and every known secret shape masked |
| #143 | #68 | **fsguard**: canonicalise, then confine; every Windows path trap a test |
| #144 | #69 | **The supervisor**: a refused command never becomes a process, and every decision is recorded first |
| #145 | #52 | **`sletchy sandbox run`**: the Warden from a terminal, through the supervisor only |
| #147 | #34 | Phase 1 of supply chain: CI's actions and hooks pinned to commits, installs only from the lock, shipped licences checked |

### 2026-10-04

I asked for the six things left from the night before. All CI green:

| PR | Issue | What |
|---|---|---|
| #148 | - | STATUS, BOARD and L014 for the night before. Its first CI run failed before any test ran: GitHub had no server for the download step. The re-run passed |
| #150 | #34 | **Every GitHub Action on Node 24.** GitHub's warning sat on every job after #147: four actions targeted Node 20, which it is retiring. Each pin now names its exact release |
| #151 | #146 | **`sletchy-soc processes` and `sletchy-soc network`**: the SOC's first sensor. Read-only Windows queries, unelevated; what is wrong becomes a finding on the record, once a day each, at most 10 a run. `soc_watch_machine` is the first switch that really does something |
| #152 | #34 | **A written reason for every shipped dependency** (`docs/supply/DEPENDENCIES.md`), 16 rows held to `uv.lock` by a test |
| #153 | #71 | **The probe for #71 phases 2-3**, ready for the run with me at the keyboard. I chose option B |
| #155 | #149 | **Opening the ledger while another process appends never calls it broken.** The end comes from the same read as the check; a half-written last line is read again under the lock |
| #156 | #146 | **`sletchy-soc events`**: the System log's crash loops and unexpected shutdowns. On its first real run it named the graphics-driver loop, back again that day |
| #157 | #146 | **`sletchy-soc startup`**: everything set to start with the machine, read-only, by my decision ([ADR-0012](../docs/adr/0012-the-soc-may-read-what-starts-with-the-machine.md)). On the real machine: 140 entries, exactly the two problems found by hand |
| #158 | #71 | ADR-0006 finding 5, and these docs for the afternoon |
| #159 | #33 | **The firewall rules, and the lanes that let a rule name a sandbox** ([ADR-0013](../docs/adr/0013-sandbox-lanes-so-a-firewall-rule-can-name-the-container.md)). A sandbox now runs under one of eight fixed container names, so eight rules written once cover every run. `sletchy install-rules` shows them, waits for yes, records, adds, and reads them back; it never asks Windows for administrator rights itself. The probe measures UDP and IPv6 now too |
| #160 | #32 | **The proxy: the only way out** (`warden/egress/`). One gate decides every connection (name, port, method, size, then an address floor no allowlist lowers: this machine, private networks, cloud metadata) and records it before anything connects. A sandbox whose profile allows a host gets a proxy on loopback for its run, behind a password made for that run; a real contained `curl` is shown reaching it and nothing past it. Redirects are never followed; answers and uploads stop at their limits |
| #161 | #34 | **What a dependency does, and what is known against it.** Every shipped package is imported once in quarantine, a fresh Python with an audit hook that refuses and records any connection, program start or write outside its folder: all clean, on Windows and Linux. CI asks OSV about all 606 locked packages on every run. Its first answer: three advisories, all in the Linux-only GTK crates under Tauri, which the Windows window never builds; accepted with that reason until 2027-01-04 (`docs/supply/VULNERABILITIES.md`) |
| #162 | #70 | **The container backend, on Linux only** ([ADR-0014](../docs/adr/0014-the-container-backend-runs-on-linux-only.md)). Rootless Podman, no network, a read-only image pinned by digest, only the workspace mounted, journalled first and swept by panic. Never available on Windows, where a container needs a virtual machine: this machine's ladder is unchanged. Proven on CI's Ubuntu runner against the same conformance suite as every backend |

Also that day: an Abuse cases section on every open issue (38 had none), and **#149** filed: opening the ledger while another
process appends can report a healthy chain as broken. It failed 2 of 8 full runs that day, and was fixed the same day (#155).

**I ran #71's probe twice** ([ADR-0006](../docs/adr/0006-egress-binding-findings.md) finding 5): with no
firewall rule, the sandbox refused a TCP connection to another machine at once, where the same connection outside it
timed out. With phase 1, the container reaches loopback and nothing beyond it, which is the shape the egress design
needs. The rule round was not run; it is now a second lock, not the whole control.

The window was rebuilt on my machine that day, from `main` at `b910208`.

**I closed the two database servers to the network** that evening, in an administrator
PowerShell, from commands first tested on copies of their configuration files. Both now start
only when asked rather than with Windows, both listen on this machine only, and the two
firewall rules that had opened one of them to every network, public ones included, are switched
off rather than deleted. Each configuration file has a `.before-sletchy` copy beside it. The
ports did not change, so the tools that use them still connect from this machine. Verified
read-only afterwards: both stopped, both set to start by hand, nothing listening on their ports.

### 2026-10-05

I asked for the base to be strengthened, the tracker cleaned up, and a way toward
training Sletchy's own model. All CI green:

| PR | Issue | What |
|---|---|---|
| #165 | #71 | **The rules bind, for TCP over IPv4** ([ADR-0006](../docs/adr/0006-egress-binding-findings.md) finding 8) |
| #167 | #166 | **PR and issue templates that fit their reader, checked in CI.** A PR body scales with the change (Summary, Changes, Tests, Risk, Not in scope); titles are `type(scope): imperative`, at most 72 characters; issues have three forms (build task, bug, spike). `scripts/pr_check.py` holds every PR to it, in a CI job of its own. All 79 earlier PR titles were corrected to pass it, and the bodies of #159 to #165 reshaped, every claim kept |
| #169 | #33 | **The self-check reads the firewall rules.** Any rule missing or changed fails the network line; the window shows it as needing attention |
| #171 | #168 | **A sandboxed program can use the GPU** ([ADR-0015](../docs/adr/0015-a-sandboxed-program-can-use-the-gpu.md)): CUDA initialised and allocated 64 MB in a process the container refused a file outside its workspace. Also a gap: `winjob` does not confine the GPU |
| #172 | #55 | **A first training slice comes before Wave 3** ([ADR-0016](../docs/adr/0016-a-first-training-slice-before-wave-3.md)) |
| #174 | #71, #33 | **Both locks drop UDP too** ([ADR-0006](../docs/adr/0006-egress-binding-findings.md) finding 9, [L017](../learnings/L017-when-a-refusal-is-silent-read-the-refusers-record.md)). My sitting: the rules removed and put back, the probe with and without them, and Windows' drop log read as administrator. It named the container's default block for every dropped datagram and the lane's own rule once the container's lock was opened; with no rules the lane went out. Removal is verified on a real host, and the self-check failed its network line while the rules were off. #71 and #33 close; IPv6 is #173 |
| #176 | #53, #54 | **Sletchy asks a model on this computer** ([ADR-0017](../docs/adr/0017-a-model-before-training-through-one-local-door.md)). `sletchy models` and `sletchy ask`, through one door to `127.0.0.1` and one port, never a request that makes the server fetch, write or delete. Every question and answer on the ledger. My card budget: a model may take at most 60% of the card, so its context fits, and every answer reports how much of the context it used and says so if it ran out. Ollama is asked, never embedded; my own llama.cpp build replaces it later |
| #177 | #175 | **A server inside a sandbox is reached on loopback** ([ADR-0006](../docs/adr/0006-egress-binding-findings.md) finding 10): measured twice, in a process the container refused a file outside its workspace. Step 2 of ADR-0017 can run a model server inside a lane and ask it through the local door. Also a gap: any contained program can listen on loopback |
| #178 | - | **The window in the README**: nine screens I took, the Simple view first |

I also reinstalled the graphics driver that day. `NVIDIA LocalSystem Container` had
failed 1,493, 3,285 and 2,388 times on 2 to 4 October; read read-only from the System log
afterwards, it had not failed since 17:58 on the 4th.

### 2026-10-06

I asked for Stop everything to be safe to press again, for the word panic to go, and to
ask a model from the window, not a terminal.
All CI green:

| PR | Issue | What |
|---|---|---|
| #180 | #179 | **Stop everything no longer warns on every press.** Run as a normal user it keeps Sletchy's firewall rules, counts them and says why: they only stop Sletchy's own sandboxes reaching other computers. A count it cannot take is still an error |
| #181 | - | **`sletchy stop`, not `sletchy panic`**: the terminal, the Raw console (`stop.plan`, `stop.run`), the record and the docs. The old name still works and is listed nowhere; code names and history keep it |
| #182 | - | **Talk to a model, in the window** ([ADR-0017](../docs/adr/0017-a-model-before-training-through-one-local-door.md) decision 10): pick a model that fits the card, ask, read the answer and the context meter. A question gets a ticket and runs on a worker thread, so Stop everything never waits on a model. The card budget is 70%, so ornith:9b fits |

### 2026-10-07

I had the Talk plate tried against my own Ollama before rebuilding the window, and it
found one thing to say. Then the loopback question it led to, the repo put in my own voice,
Wave 2 closed, and Wave 3's first piece. All CI green:

| PR | Issue | What |
|---|---|---|
| #183 | - | **The Talk plate says the first question loads the model.** Live, ornith:9b took 173 s for its first answer and 5.4 s for the next, while Stop everything's plan answered in 2.95 s ([ADR-0017](../docs/adr/0017-a-model-before-training-through-one-local-door.md) consequences) |
| #185 | #184 | **Wave 2's exit, written down.** A sandbox can ask the model server to download or delete a model around the door, because Ollama asks no password on loopback (COVERAGE; never tried against the real server). `egress_enabled` stays unwired on purpose ([waves.md](../docs/roadmap/waves.md)). Then the probe (`scripts/spike/loopback_rule_probe.py`): with my one rule in place, the lane still reached the port it named, so a firewall rule cannot narrow loopback (ADR-0006 finding 11) |
| #186 | - | **In my own voice.** My name no longer appears in the third person anywhere: every file, and every issue, PR and comment on GitHub (54 edited). My notes read as mine; "the operator" stays the role. A hygiene test and `public_check.py` hold it ([writing-conventions](../docs/LAW/writing-conventions.md) section 0.2). Also: the window's end-to-end test waited for a refused question by a count of checks, which ran out on a busy machine; it now waits by time |
| #189 | #184 | **Wave 2 complete.** I accepted the loopback gap as written: a sandbox runs only when I start one, and the model server only while I run it. ADR-0017 step 2 closes the download half; a filter below the firewall is filed for later, only if needed (#188). Next: Wave 3.1, the harness |
| #190 | #35 | **The harness: a conversation, one stream per turn** ([ADR-0018](../docs/adr/0018-the-harness-one-stream-per-turn-every-event-on-the-record.md)). `sletchy chat` sends each question with the conversation so far; every event is on the record before it is shown and cites its entry, and a refusal appears inline with its entry number. Nothing a model writes can look like Sletchy speaking |
| #191 | #35 | **The window holds a conversation.** Talk to a model asks through the harness: each question goes with the conversation so far, the plate shows every turn with its record entries, and **New conversation** starts again. The window is the second host of the same stream |
| #192 | - | **The window builds from a double-click.** My first double-click build stopped at "'npm' is not recognized": Explorer spells the search path `Path`, and the build's helper only knew `PATH`, so it handed the build Rust's folder alone. Every spelling is kept now ([L018](../learnings/L018-a-double-click-is-not-a-terminal.md)) |
| #198 | #194, #195, #193 | **Recall comes into Wave 3** ([ADR-0019](../docs/adr/0019-recall-comes-into-wave-3.md)). Sletchy forgets the oldest turns of a conversation and everything between conversations; memory, an evidence gate and a context plan now come before the router. The ADR also goes through what a harness controls against what Sletchy has. A hosted judge is out permanently; Gemma 4 E2B fits the card budget by listed size (#197); my own decision model is a spike (#196) |
| #199 | #194 | **The recall store.** `sletchy memory add NAME < file`, `search`, `list`, `forget`: chunks at three sizes, found by words (FTS5, BM25) and by meaning (an embedding model through the door's new `POST /api/embed`), merged by rank, standard library only, behind `mind_memory`. Every add, search and forget is on the record first |
| #200 | #195, #193 | **Sletchy remembers across conversations.** With Memory on, each question is searched for in memory, the chat model judges every passage, and only those that help go before the question, quoted with their source; the plan is recorded first, and every answered turn is kept. In `sletchy chat`, `sletchy memory ask` ("not in my memory" when nothing answers) and the window's Talk plate |
| #201 | #195 | **A judge is measured, not believed.** `sletchy memory measure MODEL < set.jsonl` scores a model as the gate's judge: precision, recall, answerable and time. A seed set of twelve questions, five of them with a passage about the right thing that still does not answer ([docs/measure](../docs/measure/README.md)) |
| #203 | #202 | **Load a model first, with a context I choose.** **Load model** puts it on the card with no question and says what the server holds: the context, how much is on the card, how long it took. 4,096, 8,192, 16,384 or 32,768 tokens; more than 4 GiB past the card is unloaded and refused. Kept 30 minutes, not 5; **Unload** frees the card. `sletchy load`, `sletchy unload`, `--context` |
| #206 | #204, #205 | **Memory keeps no non-answers, and the window never offers a model that cannot talk.** A turn whose answer says it does not know keeps my words alone, or nothing; a refusal or a question alone that a search finds is set aside before the judge; a judge too small to be read is said in the answer. The door asks what a model can do (`POST /api/show`): an embedding model is listed, greyed, and refused a load; a failed load ends on the record |
| #213 | #207, #208 | **The model list in sections, a bar while it waits, and who said what.** Models to talk to, for memory search, Ollama's own names, too big; each name once. A load or an answer shows a bar against last time. Every model is told a passage's Question is mine and its Answer a model's |
| #215 | #214 | **Ready to be read in public.** No local paths or account name in the tree; the six old archive keys checked against their providers on 2026-10-08, the one that still answered revoked, and every line now says they are dead; the README opens with the status and no licence yet; SECURITY.md says how to report privately. A scan of all 1273 file versions in history found no secret |

## How I run it

Double-click **`Open-Sletchy.cmd`** in the repo root. To see what it would do first, run
`Open-Sletchy.cmd --check` in a command prompt: it starts nothing. Every button's outcome is in
`apps/desktop/WHAT-A-CLICK-CAN-DO.md`. There is deliberately **no installer** yet: one writes
outside the folder, and an unsigned one trains people to click past SmartScreen. That comes with
Uttu's public release.

**To see what is running on the machine:** `uv run sletchy-soc processes`, `network`, `events` and `startup`. They
look only at Sletchy's own processes until the dangerous switch is on:
`uv run sletchy flags set soc_watch_machine on --reason "..."`. What they find is on the record:
`uv run sletchy ledger show --action soc`. `--dry-run` looks without recording.

**The repo root checkout is not updated automatically.** On 2026-10-03 it was still at
`e085244` while `main` had moved on, so the window ran without that day's fixes. Pull before
showing it to anyone.

## Two threads

Since 2026-10-03 a second Claude session works this repo in its own worktree. It runs from
`SECOND-THREAD-PROMPT.md`, which I hold.

- **Main thread:** the window (`apps/desktop/`), docs, this file, BOARD
- **Second thread:** user stories and the tests that hold them, plus fixes for the bugs those
  tests find. On 2026-10-03 I also asked it to bring these docs up to date

Both obey the same laws, merge only on four green CI checks, and do no elevated work.

**One shared-machine hazard has already shown itself.** Two suites on one PC share the user's
AppContainer profiles, and one residue test flaked (#108 fixed it). Before trusting a red test
on this machine, ask whether the other thread was running at the same moment.

A third session, started 2026-10-03, renames the agency site's Sletchy entry to **Uttu**, from
measured numbers and with **no download**: Uttu is not ready for release.

## The next action

**Wave 2 is complete (2026-10-07).** Sletchy asks a model on this computer
([ADR-0017](../docs/adr/0017-a-model-before-training-through-one-local-door.md)); training
waits behind it ([ADR-0016](../docs/adr/0016-a-first-training-slice-before-wave-3.md)).
In order:

1. **Test #206 from the window.** My first questions from the window worked on
   2026-10-08 (below). First forget the conversations that kept a refusal
   (`sletchy memory list` shows them, `sletchy memory forget` takes one), rebuild the
   window, check the embedding model is greyed, load ornith:9b and ask my name in a new
   conversation. Step 2's measurement is done (#175). Next, my own llama.cpp build. The
   training stack (#170) waits
2. **Wave 3.1, the harness** (#35): built, in the terminal (#190) and the window (#191),
   ADR-0018. Left on #35: words as they arrive, `INTERRUPT` with tools, hosts that listen.
   **Recall is built** ([ADR-0019](../docs/adr/0019-recall-comes-into-wave-3.md)): the store (#199), the
   evidence gate and the context plan (#200). The judge is measured by `sletchy memory measure` (#201); its first
   numbers are my own run. Left: a time budget per turn (#193), Gemma 4 E2B and EmbeddingGemma on my card (#197), my own judge (#196). Then the router (#36). The loopback gap is accepted as written (#184); a filter below the firewall
   is filed for later, only if needed (#188). `egress_enabled` stays unwired on purpose until Wave 3's tools need it
   ([waves.md](../docs/roadmap/waves.md))
3. **#146's last piece**: command lines of running processes, masked with the secret shapes
4. Smaller, written down rather than built: vetting decisions as ledger entries (#34), and a
   quarantine for the window's npm packages and crates. **#91**, the Uttu network simulator,
   was waiting on #71's rounds, which have landed

**The first real keychain mark.** Since #130, every append also writes one generic credential,
`sletchy` / `ledger-high-water-<id>`, beside the signing key. No test touches the real keychain,
so the first real write happens the first time my own Sletchy appends after I pull. To
look: Credential Manager, Windows Credentials, Generic Credentials.

## Open questions for me

- ~~**#71's last rounds and the rules**~~ Done 2026-10-05: both locks drop TCP and UDP over
  IPv4 (ADR-0006 finding 9). IPv6 waits for a machine with an IPv6 route (#173)
- The six old API keys get rotated last (your call)
- **Open source, or a product?** (My words, 2026-10-04: *"I just dont wanna give away something
  that MIGHT earn me a chance for coin"*.) Nothing is public, and ADR-0010's licence ships only
  with the first public code, so the choice is still open and costs nothing to hold. The options
  on the table: keep it private and sell what it finds (a machine health and exposure check, as
  a service); open core (the trust-building parts open, the polished parts paid); or open as
  planned. Undecided; nothing is published until it is

**Found on my machine on 2026-10-04, read-only, each mine to act on:**

- ~~**Two database servers listen on every network interface**~~ **Closed by me the same
  evening**: both start only when asked, and listen on this machine only (above)
- **A GPU monitoring tool starts at every logon with administrator rights**, through a
  scheduled task named `GPU-Z`, and the security product stops it each time. The file is
  genuine (signed by its publisher). Removing the task in Task Scheduler and deleting its folder
  under Program Files ends it
- **What an uninstalled security product left behind**: a service, `AviraFallbackUpdater`, still
  set to start automatically as LocalSystem, pointing at a program that is no longer there; and
  five stale firewall-product entries in Windows Security. `sletchy-soc startup` names the
  service. Removing it is `sc.exe delete AviraFallbackUpdater` in an administrator PowerShell
- ~~**The graphics-driver service is crash-looping again**~~ **Repaired by me on
  2026-10-05**, by reinstalling the driver: `NVIDIA LocalSystem Container` had not failed
  since 17:58 on the 4th when the System log was read that afternoon. Its history is below.
  `sletchy-soc events` names it if it comes back

**The machine froze at about 23:03 on 2026-10-03, during a test run**, and was switched off at
the button. Windows logged no crash report (`BugcheckCode` 0) and an earlier unexpected shutdown
on 2026-09-29. What the logs showed, read-only, unelevated:

- **a graphics-driver service had failed about 3,000 times a day for 8 days** (3,285 on
  2026-10-03, measured by `sletchy-soc events` the next day), with nothing telling anyone. Updating or reinstalling the driver is mine to do. #146
  is the sensor that would have named it
- three security products scanning in real time at once, which multiplies the cost of every
  program started, test runs included
- no residue: no Sletchy AppContainer profiles, no Sletchy firewall rules; `git fsck` clean

Whether the test load contributed is not known. My call, 2026-10-03: the gate still runs the
full suite, then `law_zero`, then `adversarial`, every time.

Decided and built 2026-10-03, recorded on each issue: #94, #95, #98, #99, #100, #101, #102,
#103, #104, #116.

**The licence is decided: Apache-2.0 for Uttu** ([ADR-0010](../docs/adr/0010-uttu-is-apache-2-licensed.md)).
Sletchy stays private and carries none. `LICENSE` and `NOTICE` arrive with the first public
code, in the same change, and not before.

## Filed for later, not scheduled

- **#133**: a safe, tested installer for Windows and Ubuntu, for Uttu's release. Today there is
  deliberately none, and the window is tied to the folder it was built in
- **#114**: llama.cpp, vLLM, or both, once the Forge starts training. vLLM has no official
  Windows support (reported, not yet checked here)
- **#127**: anchoring the ledger's fingerprint in a blockchain, holding no value, ever. My
  long-term aim is Sletchy's own chain code (#57, #58); years away

## Verified on this box, 2026-10-08: the window, by my own click

- `Open-Sletchy.cmd` built the window from a double-click in a minute or two, after #192
- **Local AI models** and **Memory** both switched on from the window, and recall worked:
  a fact told in one conversation was answered in a new one, with the passage it came from
- What I found: the first answer waits minutes while the model loads, Ollama unloads it
  after five quiet minutes, and 4,096 tokens of context held two messages at about a fifth
  of it. #202 is the answer to all three
- My models live on the SSD, so the load time is not a slow disk; #202 measures it
- **Load model worked** (#203): gemma3:1b in 7.4 s and ornith:9b in 8.4 s, both 100% on
  the card at 16,384 tokens
- The two switches were still on after a rebuild because I turned them on at 10:55 that
  morning (ledger entries 5 and 7), and `var/flags.json` keeps them. Not on by default
- Asking my name then failed, read from my own record (#205): a 1B judge could not be
  read, its refusal was kept as memory, and the next judge kept the refusal over the
  fact. An embedding model was offered and picked, and its failed load left no outcome
  on the record (#204). #206 is the answer to both
- After #206, the evening: nomic-embed-text listed greyed, the refusals forgotten by hand,
  and ornith:9b answered my name from memory, but only on the third try: twice it said
  its own name, reading an earlier answer about itself as mine (#208). Loads took 54.8 s
  (ornith:9b) and 33.8 s, then 6.6 s (gemma3:4b). Ollama wrote a second listing and a
  `llamacpp:` name for gemma3:1b and gemma3:4b the moment each first loaded, so the list
  showed them twice (#207)

## Verified on this box, 2026-10-05

Windows 10 Pro 10.0.19045, unelevated, on this change's branch at `main` `8080f2b` with #171
squashed onto it, with the eight `Sletchy` rules installed:

- `uv run pytest`: **1531 passed, 24 skipped**; `-m law_zero`: **532**; `-m adversarial`: **1051**.
  The skips are what this machine cannot run: Linux-only packages and the container backend,
  both measured on CI. CI's Podman lane: **74 passed**, the container rung included
  The Windows-only tests skip on Linux CI
- ruff, ruff format and mypy (151 files) clean; `lint-imports` 3 contracts kept; secret
  scan clean (284 files)
- `scripts/known_vulnerabilities.py`, once by hand: 606 packages asked of OSV; 3 advisories,
  all on Tauri's Linux-only GTK path, accepted until 2027-01-04
- `sletchy install-rules --plan` and `--check`, unelevated, on this machine: eight rules
  shown in full. I then installed them as administrator, and `--check` reads all eight
  back as planned, before and after every gate since (L016); last read after this change's
  gate. `sletchy selfcheck` reads the same eight in 0.9 s (#169)
- `scripts/spike/gpu_probe.py`, twice: CUDA initialised and allocated 64 MB inside a sandbox,
  in a process the container refused a file outside its workspace (ADR-0015). No profile or
  interpreter copy left afterwards
- `scripts/pr_check.py --github`: every PR title on GitHub in the agreed shape (79 checked,
  72 corrected that day)
- `sletchy-soc`, on the whole machine through its library, nothing recorded:
  - `processes` and `network`: **219** processes, **147** whose path an ordinary user cannot
    read, **20** listening ports, **3** findings, in 0.05 s
  - `events`: **24,350** System log entries from 10 days in 4.0 s; the graphics-driver loop and
    two unexpected shutdowns
  - `startup`: **140** entries, none unreadable, in 1.6 s; the two findings found by hand
- The window, rebuilt that day from `b910208`: a release build in 5 min 23 s
- User stories: **155** criteria, **155** held by a named test, **0** marked GAP (unchanged)
- **Talk to a model, live, on 2026-10-07** at `99bd77d`, against my running Ollama: the
  window's requests sent to the Kernel in-process, on a throwaway home and an in-memory
  key, so my record and keychain were untouched. 15 models listed, 3 over the
  70% budget; ornith:9b answered in **173 s** cold and **5.4 s** warm, fully on the card
  (4.96 GiB); Stop everything's plan answered in **2.95 s** while it thought; only
  `/api/tags` and `/api/chat` were sent
- The ledger, measured in temporary ledgers on 2026-10-03 at `e077a63`, not re-run since: one
  append is **29 ms**; opening takes **0.28 s at 52 MB** and **2.4 s at 201 MB**

## Standing constraints that do not change

- **LAW 0 outranks everything.** This is my only computer, and my income
- **Nothing appears on my screen unannounced** ([L010](../learnings/L010-test-a-launcher-before-you-launch-it.md)). Launchers get a dry-run mode and a test first
- No kernel drivers, no Test Signing Mode, no bootstart services. One auditable elevation
- `winjob` is *"strong for filesystem, resources, and process tree"* - never "strong"
- `Scraps and Parts/` is read-only. Nothing auto-joins any network, ever (ADR-0007)
