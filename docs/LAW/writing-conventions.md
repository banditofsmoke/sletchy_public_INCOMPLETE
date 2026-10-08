# Writing conventions - commits, PRs, issues

One skeleton per artifact type, so nothing posted here has to be improvised.

---

## Why this exists

The failure mode is not bad content, it is bad *shape*: bodies two to three times
the useful length, reasoning buried in prose that should be bullets, and - the
expensive one - **verification that was actually performed never making it into the
artifact**. The evidence exists; it just never gets written down, so a reviewer has
to take the work on trust.

Two more failure modes, which I named on 2026-10-03: **issues and PRs written as the
bare minimum**, with no scope and no thought about misuse, and **private material in a
tracker that may one day be read by anyone**. Sections 0 and 0.1 answer them.

A third, named on 2026-10-05: **the same seven sections at every size**, so a docs-only
change carried empty tables and "Ledger - none"; **titles written as sentences**, past a
length limit nothing checked; and **one issue form** for bugs, spikes and parked ideas.
The PR body now scales with the change, CI checks the title and the headings
(`scripts/pr_check.py`), and issues have three forms.

---

## 0. Written for a public reader

**Every issue, PR, commit and comment is written as if the repository were public**,
even while it is private. Sletchy stays private, but Uttu will not (ADR-0010), and a
tracker is the first thing anyone studying a project reads. It is reconnaissance for an
attacker as much as context for a contributor.

Never in a title, body, commit or comment:

- **this machine**: account names, home-folder paths, the folders the checkout lives in
- **personal circumstances**: what the maintainer can afford to lose, how many machines
  they own, anything about their income or their life. Say "the operator's machine"
- **people other than the maintainer**, by name, unless they asked to be credited
- **the private archive**, or where credentials once leaked. "Old keys were rotated" is
  enough; where they were is a map
- **secrets of any shape**, whole or in part
- **internal session talk**: which thread or session did what. Say what changed
- **words written in heat**. They are read forever by people who were not there

`python scripts/public_check.py <file>` checks a body before it is posted, and
`--github` checks everything already posted. On a developer machine it also finds this
machine's own account name and folders, read at run time so they are never written in
the repository. CI runs it on every PR's title and body.

**Fixing what is already posted:** edit the body or comment, replacing the private
text with a neutral phrase that keeps the sentence true. This is the one case where a
comment is edited rather than corrected (section 5). **An edit is not an erasure**: GitHub
keeps every earlier version in the edit history, visible to anyone who can see the
issue, and only the repository owner can delete a version, one at a time, in the web
page. That is why Uttu's public repository starts from a fresh history (ADR-0010).

---

## 0.1 Every issue and PR names how it could be abused

Thinking like the attacker is part of the work, not a review step after it. Every issue
and every PR has an **Abuse cases** section:

- **who** would misuse it: a careless test, a confused user, a hostile page in the
  window, a script at the terminal, a compromised dependency, a contributor
- **what** they would try: exploit it, use it to harm the host or someone else, or
  infect it - slip code in through a dependency, a build step, a workflow, a fetched file
- **what stops each one**, and **the test that proves it**
- **what nothing stops yet**, which becomes a residual-gap row in `COVERAGE.md`

A table works best: Who, What they try, What stops it, Proven by. "Not applicable" is
an answer only for a change that touches no code and no workflow, and it says why.

---

## 0.2 In my own voice

**This repository is mine, and it reads as mine.** My own notes, decisions and findings
are in the first person: *I*, *my machine*, *my decision*. My name never appears in the
third person, in a file, a commit, an issue, a PR or a comment. *The operator* is the
role, whoever runs Sletchy or Uttu, as user stories, tests, ADRs and the product's own
text say it. A copyright notice (`LICENSE`, `NOTICE`) is the one place a name belongs.

`tests/unit/test_repo_hygiene.py` holds every tracked file to it, and
`scripts/public_check.py` every issue and PR.

---

## 1. Commit message

```
<type>(<scope>): <imperative subject, <=72 chars>

<Why paragraph - 2-4 lines. The defect and its consequence, in plain prose.
State what the reader would otherwise assume, and why it is wrong.>

- <change 1: name the file/symbol and the reason, not just the action>
- <change 2>

<Optional: one paragraph for a decision that needs defending, or a NOT-done.>

Verified: <concrete numbers - suite counts, lint, what you ran locally>.

<Closes #N. | Refs #N - what is left>
```

The subject line is the PR's title, because a PR is squash-merged with its title as the
subject (section 2 gives the rules, and CI checks them).

**Types:** `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `ci`, `chore`, `spike`.

**Areas:** `kernel`, `warden`, `soc`, `mind`, `senses`, `forge`, `vault`, `cli`, `desktop`,
`docs`, `adr`, `deps`, `ci`, `tests`.

A scope is an area, or an area and its module: `kernel/ledger`, `warden/egress`,
`warden/supply`. Comma-join when a change genuinely spans two (`kernel,cli`).

**Rules**

- **Bullets carry the changes; prose carries the reasoning.** If a paragraph is
  listing things, it should be bullets.
- **Always a `Verified:` line** when anything executable changed. Numbers, not
  adjectives - `93 passed, ruff clean, mypy clean on 22 files`, never "tested
  thoroughly".
- **Body <= 25 lines.** If it needs more, the extra belongs in the PR body or a doc.
- `Closes #N.` only for a full fix. `Refs #N` for a deliberate partial, and say what
  is left.
- **No `Co-Authored-By` trailer.**
- **ASCII-only in commit bodies.** Arrows and box-drawing characters belong in docs,
  not in `git log`.
- **No em dashes anywhere** - not in commits, docs, code, or comments. Write ` - `
  instead. `tests/unit/test_repo_hygiene.py` fails the build on one, so this rule is
  checked rather than remembered.

---

## 2. Pull requests

### Title

`type(scope): subject`, at most **72 characters**. It becomes the commit subject on
`main`, so it is written for someone reading `git log` in a year.

- **The subject starts with an imperative verb, in lower case**: *add*, *fix*, *record*,
  *refuse*. Not a noun phrase, and never a sentence about the code
- **Name the change, not the story.** The story belongs in the Summary
- No full stop at the end, no em dash

| Not this | This |
|---|---|
| `feat(egress): the gate, the sandbox proxy and the client - the only way out` | `feat(warden/egress): add the egress gate, sandbox proxy and client` |
| `docs(egress): the rules bind, for TCP over IPv4 - ADR-0006 finding 8` | `docs(adr): record that lane rules bind for TCP over IPv4` |
| `docs: Uttu is licensed Apache-2.0 (ADR-0010)` | `docs(adr): license Uttu under Apache-2.0` |

### Body

The headings come from `.github/pull_request_template.md`, in its order:

```markdown
Closes #N                 <- or "Refs #N: what is left", or "No issue: <reason>"
## Summary
## Changes
## <at most one extra: the decision a reviewer should challenge>
## Tests
## Risk
## Not in scope
## How to check by hand   <- optional, last
```

**Rules**

- **The size follows the change.** A reviewer reads the Summary and the Tests and knows
  what merged and how it was proven. Most bodies fit in 400 words. A docs-only change
  answers Risk in one line and leaves out the empty tables
- **Summary**: two to four sentences: what was wrong or missing, what this does, and why
  this way. If the issue's suggested approach was not followed, say so and why
- **Changes**: one bullet per file or symbol, with the reason, not just the action
- **Tests**: a row per new or changed test, with a **fails without the change** column. A
  test that passes both ways is a guard; label it, so it is not read as coverage. Then
  the gate's numbers, in the template's block. Numbers, never adjectives
- **Risk**: the [PR checklist](laws.md#pr-checklist) as a table, one line each, then the
  abuse cases (section 0.1). A PR that cannot state its blast radius and its undo does
  not merge
- **Not in scope**: what this deliberately leaves, and the issue that tracks it
- **At most one extra section**, with a specific heading: "Why redacted, not dropped"
  beats "Notes"
- **State CI honestly** when a body is edited after CI ran: "green" can mean no checks,
  checks passing, or checks passing except a placeholder job. Say which. Reproduce a
  failure on clean `main` before calling it someone else's
- **A commit message and a PR body are two artifacts with two readers.** Never paste
  one into the other

**Checked, not remembered.** CI runs `scripts/pr_check.py` on every PR's title and body:
the title's shape, the first line naming an issue, the headings and their order, the
gate's numbers, and no blank left from the template. Before posting, write the title, a
blank line and the body to a file and run:

```bash
python scripts/pr_check.py pr.md
python scripts/public_check.py pr.md
```

## 3. Issues

Three forms in `.github/ISSUE_TEMPLATE/`, and no blank issues:

| Form | For | Label |
|---|---|---|
| **Build task** (`build_task.yml`) | building or changing something | the wave, by hand |
| **Bug** (`bug.yml`) | something that does what it should not | `bug` |
| **Spike** (`spike.yml`) | a question to answer by measuring, before building on it | `spike` |

Titles are `<plane>/<module>: <outcome>`. **Status lives in labels, not titles**: an idea
recorded but not scheduled carries `later`, never "(recorded, not scheduled)".

The three build-task fields that do the most work, and are the easiest to skip:

- **Scope** - especially *permanently* excluded behaviour. "No ledger repair function
  exists and none may be added" belongs in the issue, so a future contributor cannot add
  one helpfully.
- **Laws in play** - and *how they are enforced in code*. "LAW 8" is not an answer;
  "a DANGEROUS flag defaulting on raises at construction" is.
- **Known gaps** - written *before* the work starts (LAW 10). These become residual-gap
  rows in `tests/adversarial/COVERAGE.md`.

## 4. Issue ↔ PR lifecycle

A merge closes only what the PR *names* with a closing keyword.

| Keyword | On merge | Use when |
|---|---|---|
| `Closes #N` / `Fixes #N` / `Resolves #N` | issue **closes** | the PR fully resolves it |
| `Refs #N` / plain `#N` | issue **stays open** | the PR deliberately does part of it |

**An open issue with a merged PR is not a mistake.** It is the tracker correctly
saying there is work left. Using `Closes` on a half-done issue silently shuts it -
that is the failure this rule exists to prevent.

**GitHub reads the keyword anywhere in the body**, including inside a quote, a code
span or a correction note. PR #85 explained in prose why it did *not* close #50 by
quoting the keyword next to the number, and the merge closed #50 anyway. It had to be
reopened by hand. Write a closing keyword only on the real closing line. Anywhere
else, describe it in words ("the closing keyword") and use `Refs #N`.

When you find something out of scope while working an issue, **file it separately**
rather than smuggling it into an unrelated PR. Filing a good issue is how work
becomes visible and ordered.

---

## 5. Fixing what is already posted

**Fix at source, never rewrite the record.**

| Artifact | Editable? | What to do |
|---|---|---|
| **PR body** | Yes - a living document | **Edit it.** It is the first thing a reviewer reads, so a stale claim there does the most damage. Mark the edit inline (*"this section originally said X; that was true when written"*) so the change is visible, not silent. |
| **Issue / PR comment** | Technically yes | **Never edit.** Post a correction as its own comment. A silent edit erases how the reasoning moved. **The one exception is private material** (section 0): edit it out, and know the history keeps it. |
| **PR title** | Yes | **Correct it**, merged or not, to the shape in section 2. The commit subject on `main` keeps the old wording: rewriting `main` would need a force-push. |
| **A PR body in an older shape** | Yes | **Reshape it to the current template** when it is next touched, with a first line saying so. Every claim and number stays; nothing is added that was not true at merge. |
| **Commit on a pushed branch** | Only by force-push | **Leave it.** Content accuracy matters; shape is fixed going forward, not retroactively. |

---

## 6. Before posting - the checklist

1. Does the commit have a `Verified:` line with real numbers?
2. Is the title `type(scope): imperative subject`, at most 72 characters?
3. Does the body's first line name the issue, with `Closes` only for a full fix?
4. Does `## Tests` carry the fails-without column and the gate's numbers, and say what
   CI actually did if CI has run?
5. Does `## Risk` state the blast radius, the undo and the abuse cases?
6. Is the judgement call in its own named section - at most one?
7. ASCII-only commit body, no `Co-Authored-By`, <= 25 lines?
8. Do `python scripts/pr_check.py` and `python scripts/public_check.py` pass on the
   title and body?
9. Is it in my own voice, with my name nowhere in the third person (section 0.2)?

## 7. A `gh` gotcha

`gh pr edit --body-file` can fail with a *Projects (classic) is being deprecated*
GraphQL error. Use the REST API instead:

```bash
gh api -X PATCH repos/Sletch/sletchy/pulls/<n> --input body.json
```

where `body.json` is `{"body": "..."}`. On Windows, write that file to the scratchpad
rather than `/tmp` - Git Bash and native Python disagree about where `/tmp` is.
