# ADR-0017 - Sletchy asks a local model before it trains one, through one local door

**Status:** Accepted · 2026-10-05. Changes [ADR-0016](0016-a-first-training-slice-before-wave-3.md)'s
order: a model is asked before one is trained. Starts Wave 3's 3.4 for one engine.
Amended 2026-10-06: the share is 70% (decision 5), and the window asks too (decision 10).
Amended 2026-10-08: the door asks one more question, `POST /api/embed`, text into
vectors for the recall store ([ADR-0019](0019-recall-comes-into-wave-3.md) decision 6).
Amended 2026-10-08 again (#202): the context is chosen and measured, not fixed (decision 5),
loading is its own step, and the door reads what is loaded (`GET /api/ps`).
Amended 2026-10-08 a third time (#204): the door asks what one model can do
(`POST /api/show`, a read), so a model the server says cannot hold a conversation, such
as an embedding model, is never loaded or offered to talk to; and a load that fails ends
on the record (`mind.model.loaded`, denied), where before only its start was.

## Context

On 2026-10-05 I chose to run a model inside Sletchy before training one: the training
slice's first two steps had landed that day (the graphics driver repaired, UDP measured),
and asking a model is minutes on the card where training is hours. My constraints, in my
words and in order:

- **Sletchy, and Uttu after it, is to stand alone one day**, with its own inference
  engine: my own build of llama.cpp, once I have studied it. *"For now, while we build,
  we do what we can, with what we have."* What I have is Ollama
- **Ollama is not embedded.** Its code is not imported, copied or shipped
- **vLLM is not used on this machine.** It has no official Windows support; the ways to
  run it here are WSL2 or Docker, both a Linux virtual machine, which ADR-0014 keeps off
  this machine, or an unofficial build. Its speed is for many users sharing a server, and
  it reserves most of the card and cannot spill a model into system memory. #114 keeps
  it for Linux
- **A model that fills the card leaves no room to answer.** My experience with Ollama on
  an 8 GB card: a 6 GB model, a context that grows, and an answer that never comes, with
  nothing saying why. I asked for a limit on the model's share of the card, and for the
  context to be visible

The machine: one 8 GB card (8151 MiB, ADR-0015), 20 GB of memory, a four-core processor
from 2015. Fast where the model fits the card, slow anywhere it spills.

The gate (`warden/egress/gate.py`) refuses this machine by a floor no allowlist lowers,
and must keep doing so: a service on this machine is the first thing a confused deputy is
aimed at. A model server is exactly such a service.

## Decision

1. **A model is asked before one is trained.** ADR-0016's remaining steps (the training
   stack #170, the weights #83, the runner #55) wait behind this one.

2. **Sletchy is a client of a model server on this machine, never its host.** It speaks
   HTTP to one port on `127.0.0.1`. The server is outside Sletchy, unmodified and
   unimported. **Changing it is an engine name and a port**: Ollama today; the
   operator's own llama.cpp build, which speaks a different API, behind the same door
   later; at that point Uttu stands alone.

3. **One door, `warden/egress/local.py`, separate from the gate.** The floor stays whole.
   The door reaches `127.0.0.1` and the operator's port, and no other address: it takes
   no host, name or URL at all. For each engine it asks a fixed list of questions,
   matched whole: list the models, ask one, and since ADR-0019 turn text into vectors.
   **Never a request that makes the server
   fetch, write or delete** (Ollama's `pull`, `push`, `create`, `copy`, `delete`): a
   local server that downloads on request would be a way round the gate. Every request
   is recorded before it connects; sizes and time are limited while the bytes pass.
   `mind_local_models`, off on a fresh install, is read on every request.

4. **Every question and answer is on the ledger**, `mind.model.ask` before and
   `mind.model.answer` after, with both texts in the payload store (LAW 1). A
   conversation can be read back word for word and checked against the chain.

5. **The card budget (the operator's design).** A model may take at most **70% of the
   card**, by the size the server reports (5.57 GiB of its 7.96 GiB), and is refused before it is
   asked otherwise; the rest is the context's. It was 60% (4.78 GiB) until 2026-10-06, when
   the operator raised it to ask ornith:9b (5.6 GB, about 65.5% of the card). Every question asks for the same context,
   **4096 tokens**, so the server never picks one that does not fit. #54 later replaces
   the card's measured size with free memory measured at the time.

   *Amended 2026-10-08 (#202).* 4,096 tokens held two messages at about a fifth of it, so
   the context is now the operator's choice of 4,096, 8,192, 16,384 or 32,768, and one
   conversation keeps one, so the server never reloads to change it. Fit is measured
   rather than assumed: after a model is loaded, the server's own report (`/api/ps`) says
   how much of it is on the card. Past the card it runs slower, from system memory, and
   the window says so; more than 4 GiB past it (`MAX_SPILL_BYTES`, for this machine's
   19.9 GB) and it is unloaded at once and refused, because system memory filling is the
   machine that stops answering this decision was written to prevent. Loading is its own
   step with its own status, and the server keeps a model 30 minutes after its last
   request instead of five.

6. **The context meter.** Every answer says how many tokens of its context it used, and
   if it stopped because it ran out of room, it says that in a sentence.

7. **The answer is untrusted text.** Nothing acts on it. The terminal shows it inert:
   every control character but a newline and a tab becomes `?`.

8. **Sletchy never starts a model server.** If none answers, it says so and stops.

9. **Step 2, the model server inside a sandbox, is measured before it is built.** The
   GPU works inside one (ADR-0015). Still unmeasured: whether a server listening inside
   a container can be reached from outside it on loopback (#175), and how the model
   files and the server's own program are placed under `var/`, where a container can be
   given them, without granting a folder outside it. It is built with the operator's
   llama.cpp, not Ollama: a program Sletchy runs inside its own sandbox is one the
   operator has studied (LAW 4), and one Sletchy can place. Measured 2026-10-05 (#175,
   ADR-0006 finding 10): a server inside a container is reached from outside it.

10. **The window asks too (2026-10-06), and never waits on a model.** Talk to a model
    sends three requests: `models.list`, `model.ask` and `model.answer`, through the same
    door, budget and record as `sletchy ask`, as `operator-desktop`. The window's shell
    sends one request at a time and waits for each answer, so a question answered inline
    would hold up every other request for as long as the model thinks, **Stop everything
    included**. So `model.ask` starts the question on a worker thread inside the Kernel and
    answers at once with a ticket, and the window asks `model.answer` once a second. The
    worker has its own ledger handle; the ledger's lock excludes other handles in the same
    process (#124). One question at a time. Stop everything turns the switch off; a
    question already sent finishes, and its answer is recorded.

## Consequences

- **The Mind exists.** `src/sletchy/mind/local.py` is its first module, and
  `sletchy models` and `sletchy ask` its first commands. `mind_local_models` becomes the
  second switch that does something
- **Of the operator's models, by the sizes Ollama lists** (1000-based, so 5.1 GB is
  4.75 GiB): at 70%, gemma3:1b, glm-ocr, rnj-1 and ornith:9b fit. deepseek-ocr (6.7 GB),
  gemma4:12b (7.6 GB) and qwen3-coder:30b (18 GB) are refused, with the reason. The share
  is the operator's decision, in one constant and one test
- **A model's first question is slow; the rest are not.** Measured on 2026-10-07 on the
  operator's machine, at `99bd77d`, with the operator's yes: the window's requests sent
  to the Kernel in-process, against the operator's running Ollama, on a throwaway home
  and key. ornith:9b took **173 s** for its first answer, loading 4.96 GiB onto the card,
  and **5.4 s** for the next. While it thought, Stop everything's plan answered in
  **2.95 s** and a switch flip in **0.05 s**. The door sent `/api/tags` and `/api/chat`
  only. The plate says the first question loads the model
- **Whatever answers on the port is trusted with the conversation.** Sletchy does not
  authenticate the server: another program listening on that port would be asked
  instead, and would see the question. The server keeps its own logs, outside the
  ledger. Both are written in COVERAGE
- **The model server is not contained.** It runs as the operator, with the operator's
  rights, as it did before Sletchy. Step 2 is what changes that
- **A sandbox can ask the model server directly, around the door** (2026-10-07). The
  door refuses `pull`, `delete` and the rest for Sletchy's own requests, but a contained
  program reaches loopback without it (ADR-0006 finding 1), and Ollama asks no password.
  Inferred, never tried against the operator's server, because what it would prove is a
  download. Step 2 would stop the download, not the delete. Loopback filtering per port
  would stop both, and the Windows Firewall cannot do it (ADR-0006 finding 11). Written in
  COVERAGE

## What this does not decide

- Streaming answers, conversations longer than one question, and the harness (3.1)
- Hosted models: `egress_hosted_models` stays off and unread
- The context size beyond 4096 tokens, which waits for #54's measured memory
- Whether Uttu ships an engine binary, or asks the user to build one
