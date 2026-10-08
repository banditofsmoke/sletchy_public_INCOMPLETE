# Learnings

Rules earned from something that actually went wrong here, or nearly did. Each one cost
something to learn; writing it down is how it only costs that once.

**Read this folder before starting work on a new issue.** [`docs/LAW/`](../docs/LAW/) is the
binding law and [`tests/adversarial/COVERAGE.md`](../tests/adversarial/COVERAGE.md) is the
record of what is not caught. This folder is the record of *why* several of their clauses
exist - the mistakes behind the rules.

Half of these are variations on one theme: **a security test that passes for the wrong
reason is worse than no test at all**, because it converts an unknown into a false
certainty. That theme is why this project measures rather than assumes.

| # | Learning | Cost if ignored |
|---|---|---|
| [L001](L001-a-probe-needs-a-positive-control.md) | Every isolation probe needs a control that must succeed | A suite of should-fail assertions passing because nothing ran |
| [L002](L002-never-probe-with-io-the-sandbox-denies.md) | A probe must not use I/O the sandbox itself denies | Measuring your plumbing and calling it containment |
| [L003](L003-a-blocked-dialog-is-a-live-process.md) | A stuck GUI dialog is a live process, and it will satisfy a liveness check | A tree-kill test that passed by measuring a message box |
| [L004](L004-ctypes-needs-a-restype-on-every-binding.md) | Set `restype` on every ctypes binding, always | A silently truncated 64-bit handle and a nonsense error code |
| [L005](L005-a-tripwire-nobody-rereads-never-fires.md) | A condition written where nobody looks is not a tripwire | Two weeks of docs describing a control that had already changed |
| [L006](L006-measure-the-number-never-recall-it.md) | Measure every number before writing it down | A document that contradicts itself and is believed anyway |
| [L007](L007-ci-runs-a-platform-your-probes-do-not.md) | CI runs a platform your probes were never tried on | A green containment claim that was really a missing binary |
| [L008](L008-the-capability-is-not-the-control.md) | Never generalise one measured dimension to another | Shipping "the sandbox blocks the network" because it blocks files |
| [L009](L009-could-not-look-is-not-nothing-there.md) | "Could not look" is an error, never a zero; prove a host change by re-reading the host | A panic step that failed on every run since Wave 1 and reported clean every time |
| [L010](L010-test-a-launcher-before-you-launch-it.md) | Anything that launches gets a dry-run mode and a test before its first real run; nothing appears on the operator's screen unannounced | A Windows error dialog on the only computer I have, from a launcher run by hand before any test existed |
| [L011](L011-a-copy-of-a-guard-is-not-the-guard.md) | A rule two planes must obey lives where both import it; fixtures are shaped like what production writes | Stop everything aimed at the home folder and another app's container by one forged line, behind tests that used a SID no real record carries |
| [L012](L012-commit-before-you-prove-against-old-code.md) | Commit a work-in-progress before swapping old code in to prove a test; restore from `HEAD` | A finished fix overwritten by the old file it was being proven against |
| [L013](L013-a-guard-every-test-must-remember-will-be-forgotten.md) | Put a guard where no test can skip it; a safety scan covers every language shipped; the test of a safety net must not need the net | A forgetful test writing to the operator's real ledger, and a window whose code no LAW 0 scan ever read |
| [L014](L014-read-the-output-before-you-write-the-number.md) | Never type a count before the run that produces it is read; never pipe a check whose exit code matters; stop the chain when a guard refuses | Two commits claiming counts their runs never produced, a refused PR body posted because `tail` reported success, and a conflict staged with its markers |
| [L015](L015-the-gate-measures-one-tree-so-hold-it-still.md) | Commit, start the gate, touch nothing in that worktree until it ends; each step keeps its own output; a failure the change could not cause is filed, then the gate runs again | Two gate runs thrown away because files changed mid-run, and a real ledger race reduced to "1 failed" |
| [L016](L016-a-guard-is-only-as-wide-as-the-process-it-is-in.md) | A guard covers every process the tests start, or names the ones it does not; a default every test gets beats a stub every test must remember; after the host changes state, run the gate first | The window's end-to-end test running a real `Remove-NetFirewallRule` against the operator's rules, stopped only because the suite runs unelevated |
| [L017](L017-when-a-refusal-is-silent-read-the-refusers-record.md) | A silent refusal cannot be measured from the refused program's side; read the refuser's own record, match it to the probe's rows, and keep a control row with no record | Three probe rounds reading a dropped datagram as "went out" or as unknowable |
| [L018](L018-a-double-click-is-not-a-terminal.md) | Find a Windows environment variable without regard to case and update every spelling; a test standing in for a double-click starts from `Path`; what only a click runs is unproven until it has | The first double-click build of the window failing with "'npm' is not recognized", because Explorer spells it `Path` and the build only knew `PATH` |
| [L019](L019-memory-that-keeps-its-non-answers-forgets.md) | Memory keeps evidence, not everything said: a model's "I don't know" is not a fact, and kept, it outranks the fact it missed; read the record of a failure before guessing at it | My name asked of memory: a refusal kept as memory, then found ahead of the fact and kept by the judge, while my own first guesses at the cause were wrong |

## Adding one

One file per learning, `LNNN-kebab-summary.md`. State **what happened**, **why it happened**
(the mechanism, not the mood), and **the rule** in a form that is checkable.

The bar: it goes in this folder because it **already happened**, not because it might. If it
belongs in the law, add it to [`docs/LAW/laws.md`](../docs/LAW/laws.md) too and cite it here.
If it is a gap in what the code catches, it belongs in `COVERAGE.md` instead - this folder
is for mistakes in *how we work*, not holes in what we built.
