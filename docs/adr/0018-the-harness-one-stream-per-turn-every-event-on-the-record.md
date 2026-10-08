# ADR-0018 - The harness: one stream per turn, every event on the record before it is shown

**Status:** Accepted · 2026-10-07. Starts Wave 3's 3.1 (#35) for a conversation with a
model on this machine, through ADR-0017's door. The terminal host landed in #190, and the
window's Talk plate, the second host of decision 5, in #191. Amended 2026-10-08 by
[ADR-0019](0019-recall-comes-into-wave-3.md): with recall, a turn first records a context
plan (`mind.context.plan`), `STATUS` says how many passages went (`recalled`, `plan_seq`),
and `COMPLETE` gains the outcome `not_in_memory`. No event type was added (LAW 5).

## Context

Wave 3's goal is to talk to Sletchy. `sletchy ask` and the window's Talk plate answer one
question at a time, and nothing remembers the question before it. LAW 5 says every
execution is one typed stream of events, and every host only translates it; the event
vocabulary has existed since #1 (`AgentEventType`, eleven members, `POLICY` the one
Sletchy added) and nothing produced it.

#35 named the problem this has to solve first. LAW 1 puts every event on the record
before it reaches a host, and a record entry costs about 29 ms. A model writes tens of
words a second, so one entry per word would make the record slower than the model, and
the record would be mostly fragments.

## Decision

1. **One stream per turn.** `Conversation.turn(question)` is an async iterator of
   `AgentEvent`s: the question asked, the answer, the end. A call that wants the result
   rather than the stream consumes it (`Conversation.play`), never the reverse (LAW 5).
2. **Every event cites the record entry that holds what it reports, and is yielded only
   after that entry is appended.** Not only `POLICY`: every event the harness yields
   carries `ledger_seq`. The question's `mind.model.ask` entry is cited by the `STATUS`
   event that says it was asked; the answer's `mind.model.answer` entry by the `CONTENT`
   that carries it and the `COMPLETE` that ends the turn; a refusal's entry by its
   `POLICY` event. A turn that fails without a refusal (no model server, an answer that
   cannot be read) is first recorded as `mind.conversation.error`, and its `ERROR` event
   cites that.
3. **Recorded per answer, not per word.** The answer arrives whole, as `sletchy ask`'s
   does, and is one entry and one `CONTENT` event. Showing words as they arrive would
   show text that is not yet on the record, which decision 2 forbids, so it waits for
   its own decision: what is shown before it is recorded, and how a screen says so.
4. **Earlier turns go with each question, within the context.** The conversation sends
   its earlier questions and answers, oldest left out first when they would leave less
   than a quarter of the context (`CONTEXT_TOKENS`) for the answer. Until a tokenizer is
   built, the size is estimated at three characters a token, which overstates it for
   English, so the estimate errs towards leaving a turn out. How many earlier turns were
   sent, and how many left out, is in the question's entry and its `STATUS` event; the
   meter still shows the server's own count afterwards.
5. **Hosts are pure translation.** A host turns one event into output and writes it. It
   holds no state and does nothing else, so two hosts showing one stream show the same
   truth. The terminal host is first (`sletchy chat`); the window is the second, on the
   same stream. Every line of a model's answer is indented under a marker, and nothing
   but Sletchy's own events starts a line with `[sletchy]`, so an answer cannot pass
   itself off as a refusal or a record entry. The answer is shown inert, as before.
6. **No hosts that listen yet.** The web hosts #35 lists (SSE, WebSocket) open a port.
   Nothing in Sletchy listens until #62 (what an agent may do with no goal) and #59 (a
   long-running Sletchy) decide how.
7. **Backpressure is the iterator's.** A host pulls the next event when it has written
   the last one, so a slow host slows the conversation instead of queueing events behind
   it. A bounded queue is needed only once words stream (decision 3).

## Consequences

- **A conversation can be read back from the record, in order.** Each question's entry
  says which turn of which conversation it is, so `sletchy ledger show --action mind.model`
  shows the turns in sequence, with both texts in the payload store
- **A conversation lives in memory for one session.** Every word is on the record, but
  picking a conversation up again from it is Wave 5's memory, not this
- **`INTERRUPT`, `TOOL_CALL`, `TOOL_RESULT`, `PLAN` and `ARTIFACT` are not produced yet.**
  They come with tools (3.6). `REASONING`, a model's thinking where the server separates
  it, is not shown yet either
- **The estimate in decision 4 is a guess,** written in COVERAGE until a tokenizer
  replaces it. The server's own count, shown by the meter, is the measurement

## What this does not decide

- Words as they arrive, and what a screen shows before the record has it
- Which hosts may listen, and on what (#62, #59)
- The router (3.3): this asks the one local model ADR-0017 allows
