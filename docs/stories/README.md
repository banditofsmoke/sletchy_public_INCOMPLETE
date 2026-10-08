# User stories

Five kinds of person meet Sletchy. Each file says what they want, and for every
acceptance criterion it names the test that proves Sletchy does it - or says `GAP #N`
and names the issue, when nothing proves it yet.

**These describe what Sletchy does today**, through the two surfaces a person can reach:
the `sletchy` command, and the `sletchy bridge` JSON-lines channel the desktop window
speaks to the Kernel. The window's three views are three ways of calling the same eight
bridge methods; nothing in them adds a capability the bridge does not have.

| Persona | Who | File |
|---|---|---|
| **Simple** | Someone who has never opened a terminal, in the window's Simple view | [simple.md](simple.md) |
| **Custom** | A techie who wants the detail, in the Custom view | [custom.md](custom.md) |
| **Raw** | A developer, in the Raw view and at the terminal | [raw.md](raw.md) |
| **Clumsy** | Double-runs commands, kills windows mid-operation, types nonsense, runs things from the wrong folder | [clumsy.md](clumsy.md) |
| **Abuser** | Tries to use Sletchy for harm: switches on without consent, forged requests, a tampered or flooded ledger, escaping `var/` | [abuser.md](abuser.md) |

The Abuser story is the one the others rest on. My standing instruction:
*always assume somewhere on the network someone will try to use Sletchy for evil, and
default-cut them out.* Every other persona is also a way in for that person.

## How to read a criterion

```
| A1.1 | No route through the bridge turns a dangerous switch on without both proofs | `tests/adversarial/test_bridge_abuse.py::test_no_route_turns_a_dangerous_flag_on_without_both_proofs` |
```

- **A test id** means the criterion is held: that test exists, by that name, in that
  file, and the suite runs it. Run one with `uv run pytest "<id>"`.
- **`GAP #N`** means nothing holds it yet, and issue #N is where that is tracked. Gaps
  are written down rather than implied-covered ([LAW 10](../LAW/laws.md#law-10)).
  Defects found while writing these stories are #94 to #104; #105 tracks criteria that
  Sletchy is believed to meet but that no test proves.

## Kept honest by a test

[`tests/unit/test_stories.py`](../../tests/unit/test_stories.py) reads every file here
and fails the build when:

- a story cites a test that does not exist, by that name, in that file. It reads the test
  files with `ast` rather than grepping, so a name in a docstring is not a test;
- a `GAP` names no issue;
- a story has no "As a ..., I want ..., so that ..." line, or no criteria;
- a file yields no criteria at all - a checker that parses nothing passes everything
  ([L001](../../learnings/L001-a-probe-needs-a-positive-control.md)).

Its positive controls prove it catches an invented name, a real name in the wrong file,
an abbreviated id, and a numberless `GAP`.

## Adding a story

Give it the next id in its file (`## S7. ...`), one "As a ..., I want ..., so that ..."
line, and a criteria table. Cite the full node id - `tests/<path>.py::<test>` - never the
`...::test_x` shorthand `COVERAGE.md` uses. A criterion nothing proves gets a `GAP #N`
with a real issue, filed first.
