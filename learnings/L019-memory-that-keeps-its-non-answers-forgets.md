# L019 - Memory that keeps its own non-answers teaches itself not to know

**2026-10-08: asked my name, two models said they had no access to it, from a memory that
held it.**

## What happened

With **Memory** on, I told Sletchy my name, and in a new conversation it answered it
correctly from memory. Later the same day I asked again, first of gemma3:1b, then of
ornith:9b. Both said they had no access to my personal information. My first written
guesses at the cause were that the window searches by words only, that nothing said
before Memory was on was stored, and that an empty search fell through to the model.
The record said otherwise, and showed the guesses were mostly wrong.

## Why it happened

Read entry by entry from my own ledger and store:

1. gemma3:1b, the chat model, was also the judge. It could not write the judgement, so
   nothing passed, and it answered alone: "I do not have access to your Personally
   Identifiable Information ... That includes your name."
2. That turn was kept as memory, the refusal with it.
3. Asked again, a search by words found four passages: the refusal, my bare question
   from another turn, a later line of the refusal, and the fact, last. A refusal repeats
   the question's words, so it matches the question better than the fact does.
4. ornith:9b judged them. It kept the refusal at 0.95 and my bare question at 0.95, and
   turned the fact away at 0.35. ornith read the refusal and repeated it, and that
   answer was kept too.

Each piece was correct alone: keep every answered turn, rank by shared words, ask the
model to judge. Together they let a non-answer outrank the answer, and grow.

## The rule

- **Memory keeps evidence, not everything said.** A model's "I don't know" is not a
  fact about me. Keep my words from that turn, and nothing when my words were only
  questions (`mind/memory/evidence.py`)
- **What a search finds is not yet evidence.** Set aside what cannot answer (a refusal,
  a question alone) before the judge reads anything, and put what was set aside, and
  why, on the record
- **A step that fails quietly must say so.** A judge that could not be read turned
  recall off without a word; now the answer says memory was not checked
- **Read the record of a failure before guessing at it.** The ledger and the store held
  every step, and two of my three first guesses were wrong
