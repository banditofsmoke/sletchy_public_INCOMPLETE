<!--
Title: type(scope): imperative summary, at most 72 characters.
  feat(warden/egress): add the egress gate and the sandbox proxy
Body: these headings, in this order. At most one extra section, between Changes and
Tests, for a decision a reviewer should challenge, under a specific heading.
The size follows the change: a docs-only change answers Risk in one line.
CI checks the shape (scripts/pr_check.py) and the text (scripts/public_check.py).
Conventions: docs/LAW/writing-conventions.md, section 2.
-->

Closes #

## Summary
<!-- 2-4 sentences: what was wrong or missing, what this does about it, and why this
     way. If the issue's suggested approach was not followed, say so and why. -->

## Changes
<!-- One bullet per file or symbol, with the reason. -->
-

## Tests
<!-- Each new or changed test. One that passes with and without the change is a guard,
     not coverage: say so in the last column. With no new test, say why in one line. -->
| Test | What it proves | Fails without the change |
|---|---|---|
|  |  |  |

```text
pytest           ___ passed, ___ skipped
-m law_zero      ___ passed
-m adversarial   ___ passed
ruff, format     clean
mypy             clean, ___ files
lint-imports     ___ contracts kept
secret scan      clean, ___ files
```

## Risk
<!-- The PR checklist (docs/LAW/laws.md), one line each. Then who would misuse what
     this touches, and what stops them. Gaps become COVERAGE.md residual-gap rows. -->
| Check | Answer |
|---|---|
| Blast radius |  |
| Undo |  |
| Ledger |  |
| Default |  |
| Deny path |  |
| Gaps |  |
| Salvage |  |

| Who | What they try | What stops it | Proven by |
|---|---|---|---|
|  |  |  |  |

## Not in scope
<!-- What this deliberately leaves, and the issue that tracks it. -->
-

## How to check by hand
<!-- Optional. Delete this section if there is nothing a reviewer can usefully run. -->
1.
