# ADR-0019 - Recall comes into Wave 3: memory, an evidence gate, and a context on the record

**Status:** Accepted · 2026-10-08. Moves a slice of Wave 5 (5.1 and 5.4, #39 and #40)
into Wave 3, as [ADR-0016](0016-a-first-training-slice-before-wave-3.md) moved a slice of
Wave 8. Opens #193, #194, #195 and the spikes #196 and #197.

## Context

Sletchy holds a conversation now ([ADR-0018](0018-the-harness-one-stream-per-turn-every-event-on-the-record.md)),
and forgets it twice. Inside one conversation, the oldest turns are left out when the
context fills, and from then on the model never sees them again, although every word is on
the ledger. Between conversations it remembers nothing at all. I want Sletchy to remember
and to look things up before anything else is built on it: the router, the tools and the
agents all ask a model, and each of them is worse with a model that cannot see what was
already said.

Memory and retrieval sit in Wave 5. Waves are sequential because each one's guarantees
depend on the last ([ADR-0003](0003-ledger-is-the-spine.md)), so the question is the one
ADR-0016 asked: **which guarantees does recall actually depend on?**

| Recall needs | Which wave | State |
|---|---|---|
| Every question and answer recorded, word for word | 1 and 3.1 | Done (#190, #191) |
| Text stored by content, deletable without breaking the chain | 1, the payload store | Done |
| A model on this machine, reached through one door, nothing leaving | ADR-0017 | Done for questions; an embedding is one more question of the same kind |
| Recalled text treated as data, never as an instruction | 3.1 | Partly: answers are inert and roles are checked, but nothing yet labels where a piece of context came from (#193) |
| A planted document caught by its markers | 4.2, the SOC | Not built. So recall reads my conversations and documents I add by hand, nothing fetched (decision 4) |
| Conclusions about me, traceable and deletable | 5.3 | Not needed: recall finds what was said and never concludes anything |
| A trained judge | 8, the Forge | Not needed first: the gate starts with the chat model as its judge (decision 3) |

Nothing recall needs is missing except the label on recalled text, and that is part of
this slice. The SOC's markers would add a layer, not a foundation.

## What a harness controls, and where Sletchy stands

A model call is not an agent. What surrounds it decides what it sees, what it may do,
what is kept, when it stops and how anyone knows it worked. I went through those controls
one by one against what Sletchy has:

| The control | Sletchy today | What is missing, and where |
|---|---|---|
| A durable record, separate from what the model sees | The ledger and payload store; the context is chosen per turn | Recall, so the record can come back into view (#194) |
| What enters the context, and from where | The conversation so far, oldest left out by estimate | A plan per question naming every piece, its source and trust, recorded before sending (#193) |
| Text from elsewhere carries its source | Answers are inert; roles are user and model only | Recalled and document text quoted as passages with their source, never as a role (#193) |
| Only evidence that answers reaches the model | Nothing between search and model, because there is no search | The evidence gate, and "not in my memory" when nothing passes (#195) |
| Stopping is not finishing | `COMPLETE` says answered or refused | Outcomes for out of room, out of time, not in memory (#193) |
| Budgets bound autonomy | The card budget and the context size | A time budget per turn now; tool budgets with the tools (3.6) |
| Rules enforced by mechanism, not by prose | Import contracts, hygiene tests, the door's fixed list | Unchanged: every new rule here gets a test |
| The control plane outside the sandbox | The harness runs in the Kernel's process; code runs in `winjob` | Unchanged |
| Credentials never inside untrusted execution | The keychain, secret references, nothing in a sandbox | Unchanged |
| Failed tools as observations, retries only when safe | No tools yet | With the tools (3.6): typed failures, and an id on every side effect |
| Judging an answer is separate from writing it | Not yet | The gate is the first judge; a trained one is #196 |
| Each piece of the harness is a hypothesis to measure | The gate runs three times on every change | A measurement script for every judge (#195); numbers before adjectives |

## Decision

1. **Wave 3 gains three items.** 3.8, the recall store (#194); 3.9, the evidence gate
   (#195); 3.10, a context plan on the record (#193). Wave 3's exit gains a sentence: a
   question about something said in an earlier conversation is answered from the record,
   with the entries it came from, or answered "not in my memory".
2. **Chunking is structural and stored three ways.** A document splits by its headings,
   then paragraphs, then sentences; a conversation turn is its own unit. Sentence windows
   are matched, paragraphs are read, sections hold the context, and every chunk carries
   its header path and is stored once, by the hash of its content. Each is found by its
   words (SQLite's FTS5 with BM25) and by its meaning (a vector from a local embedding
   model, searched first by a 256-bit code and then rescored exactly), and the two lists
   are merged by rank. **No new dependency:** Python's standard library does all of it,
   measured fast enough on my machine (#194).
3. **Between search and the model sits a judge, and thresholds live in code.** The judge
   scores every candidate against the question, and whether what passed is enough to
   answer. The first judge is the chat model on this computer, asked for numbers. A
   decision model trained on my own card replaces it if it measures better (#196).
   **A hosted judge is out permanently**: every passage judged would leave the machine.
4. **Recall reads only what I put there.** My conversations, through the harness, and
   documents I add by hand. Nothing fetched, until the SOC can mark a planted document
   (4.2). Every chunk keeps its source; a conversation chunk cites the answer entry it
   came from.
5. **A new switch, `mind_memory`**, ELEVATED and off on a fresh install, read on every
   call. Rollups and a model of me stay behind `mind_memory_rollups`, in Wave 5.
6. **The door gains one request, `POST /api/embed`.** It is a question for a model like
   `/api/chat`: it never makes the server fetch, write or delete. ADR-0017's list is
   otherwise unchanged.
7. **Models.** By the sizes Ollama lists, Gemma 4 E2B (4.6 GB) fits the card budget of
   5.57 GiB and E4B (6.1 GB and up) does not. EmbeddingGemma (622 MB) is the first
   embedding model to try. Both are measured before either is named a default (#197),
   and I pull them by hand; the door never downloads.

## Consequences

- **Wave 4 starts later.** The SOC waits behind three more items. The trade is deliberate:
  a SOC watching a Mind that forgets is watching less than it will
- **Recall is a new place for an instruction to hide.** A stored passage can say anything.
  The label (#193) and the gate (#195) narrow it; COVERAGE.md gets the row, and the SOC's
  markers are the layer still missing
- **The store is derived, the ledger is not.** Everything in the store can be rebuilt
  from the record and the documents, so deleting the store loses nothing that matters,
  and `sletchy stop` need not touch it
- **The first judge costs a model call per question.** #195 measures it, and #196 is how
  it gets cheaper
- **Nothing here trains.** The decision model waits for the training stack (#170), whose
  dependencies I approve one PR at a time (ADR-0016)
- **No vector database, until the store is measured too slow** (asked 2026-10-08, about
  Qdrant). A vector database earns its place at millions of vectors, and costs a server
  listening on a port or a new dependency. The store searches 100,000 chunks in about 60
  ms in Python's standard library, and the wait I saw was the model loading and the judge's
  call, not search (#202). The day a search on my own memory is slow enough to notice is
  the day to look again, starting from that measurement
- **A non-answer is not memory** (#205, read from my own record on 2026-10-08). Recall had
  answered my name once. Then a 1B model could not write the judgement, so nothing was
  kept and it answered alone: "no access to your personal information". That refusal was
  kept as memory, and on the next question a search found it, my bare question and a
  piece of it ahead of the fact, and the judge kept the refusal at 0.95 and turned the
  fact away at 0.35. Now a turn whose answer says it does not know keeps my words alone,
  or nothing; a refusal or a question alone that a search finds is set aside before any
  judge reads it, on the plan's record; and a judge that cannot be read is said in the
  answer, not passed over. Told by phrase, in English: COVERAGE says what that misses
