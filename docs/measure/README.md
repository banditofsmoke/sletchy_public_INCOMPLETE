# Measuring a judge

The evidence gate ([ADR-0019](../adr/0019-recall-comes-into-wave-3.md), #195) asks a judge
which recalled passages help answer a question. A judge is a guess until it is measured,
and these sets are how it is measured:

```bash
sletchy memory measure gemma3:1b < docs/measure/judge-seed.jsonl
```

It needs **Local AI models** on, and asks the model once per question, every call on the
record. It prints precision (of the passages kept, how many help), recall (of the
passages that help, how many were kept), how often "answerable" was right, and the time.

## `judge-seed.jsonl`

Twelve questions about an ordinary house, written to start with, and two from my own
memory's mistakes. Of the twelve, seven are answered by one passage; the other five have
a passage about the right thing that still does not answer: "the wifi network is called
Orchard" for "what is the wifi password?". A word or meaning search ranks that passage
first. A good judge keeps nothing.

The last two are the traps my own memory fell into (#205): a model's refusal ("I don't
have access to personal information") and the question asked again, beside the fact or
with nothing. Both share the question's words better than the fact does. Recall now sets
them aside before any judge reads them, so these rows measure the judge alone: on my
record a judge kept the refusal at 0.95 and turned the fact away at 0.35.

It is a seed, not a benchmark: fourteen rows measure very little, and they are not my
data. The set that matters is one built from my own conversations, labelled by me, and
#196 trains on the same kind of rows. Results describe the set they came from, and say
which set that was.
