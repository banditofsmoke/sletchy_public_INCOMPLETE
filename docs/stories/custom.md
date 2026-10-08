# Custom - a techie who wants the detail

They use the desktop window's **Custom** view: every switch with its risk, the record
with filters, the meter's evidence, and Stop everything's plan before its run. They know
what a hash chain is and want to check the window is not lying to them. Their view calls
the same bridge methods as Simple, plus `panic.plan` and the filters on `ledger.tail`.

Read [README.md](README.md) for how a criterion is held.

## C1. Every switch, as it really is

As a technical user, I want to see every switch with its name, label, risk and description, so that I can judge each one myself instead of trusting a summary.

| # | Acceptance criterion | Held by |
|---|---|---|
| C1.1 | Every switch has a label a person can read | `tests/unit/test_flag_honesty.py::test_every_flag_has_a_label_a_person_can_read` |
| C1.2 | No two switches share a label, so the window cannot confuse them | `tests/unit/test_flag_honesty.py::test_labels_are_unique` |
| C1.3 | Every switch carries a description | `tests/unit/test_flags.py::test_every_flag_carries_a_description` |
| C1.4 | The list is the whole registry, and no dangerous switch is on by default | `tests/unit/test_bridge.py::test_flags_list_is_the_whole_registry` |
| C1.5 | Status names every dangerous switch that is on | `tests/unit/test_cli.py::test_status_names_any_dangerous_flag_that_is_on` |

## C2. Flipping a safe switch without ceremony

As a technical user, I want safe switches to flip at once and dangerous ones to make me say why, so that friction lands only where it protects me.

| # | Acceptance criterion | Held by |
|---|---|---|
| C2.1 | A safe switch needs no reason | `tests/unit/test_flags.py::test_a_safe_flag_needs_no_reason` |
| C2.2 | Every flip is recorded with who and why | `tests/unit/test_flags.py::test_a_flip_is_recorded_with_who_and_why` |
| C2.3 | A refused flip is not recorded as a flip | `tests/unit/test_flags.py::test_a_refused_flip_is_not_recorded_as_a_flip` |
| C2.4 | A switch that does not exist is named as such | `tests/unit/test_bridge.py::test_an_unknown_flag_is_named_as_such` |

## C3. Reading the record

As a technical user, I want the recent record filtered by action and by refusals, verified before it is shown, so that I can audit what happened without reading every line.

| # | Acceptance criterion | Held by |
|---|---|---|
| C3.1 | Entries come back oldest first, and a tail keeps the newest | `tests/unit/test_ledger_view.py::test_entries_come_back_oldest_first_and_tail_keeps_the_newest` |
| C3.2 | Filtering by action is segment-aware: `warden.sandbox` does not match `warden.sandboxes` | `tests/unit/test_ledger_view.py::test_action_filtering_is_segment_aware` |
| C3.3 | The action and refusal filters compose | `tests/unit/test_ledger_view.py::test_filters_compose` |
| C3.4 | The window's read verifies the chain before returning a single entry | `tests/unit/test_bridge.py::test_ledger_tail_verifies_and_reads` |
| C3.5 | A view never carries hashes or signatures | `tests/unit/test_ledger_view.py::test_a_view_never_carries_hashes_or_signatures` |
| C3.6 | Reading writes nothing | `tests/unit/test_ledger_view.py::test_reading_writes_nothing` |
| C3.7 | A reason typed with accents or in another script is stored as typed, and the chain still verifies | `tests/adversarial/test_abuser_reasons.py::test_printable_text_in_any_script_is_stored_and_shown_as_typed` |

## C4. A plan before Stop everything

As a technical user, I want to see what Stop everything would do before I press it, so that I know the button is honest.

| # | Acceptance criterion | Held by |
|---|---|---|
| C4.1 | The plan changes nothing | `tests/adversarial/test_panic.py::test_dry_run_changes_nothing` |
| C4.2 | The plan reports what would be reverted and touches nothing | `tests/adversarial/test_panic_reverts.py::test_a_dry_run_reports_what_would_be_reverted_and_touches_nothing` |
| C4.3 | The plan counts Sletchy's firewall rules but never removes one | `tests/adversarial/test_panic_reverts.py::test_a_dry_run_counts_but_never_removes` |
| C4.4 | Every error the run collected is in the report | `tests/adversarial/test_panic_reverts.py::test_the_report_shows_every_error_it_collected` |

## C5. The meter's evidence

As a technical user, I want the score's ceiling and every check's status, so that a high score cannot hide an unmeasured claim.

| # | Acceptance criterion | Held by |
|---|---|---|
| C5.1 | The score never exceeds the ceiling | `tests/unit/test_selfcheck.py::test_the_score_never_exceeds_the_ceiling` |
| C5.2 | The meter cannot reach 100 while network containment is unbuilt | `tests/unit/test_selfcheck.py::test_the_meter_cannot_reach_100_while_network_containment_is_unbuilt` |
| C5.3 | An unmeasured Windows build is not assumed safe | `tests/unit/test_selfcheck.py::test_an_unmeasured_windows_build_is_not_assumed_safe` |
| C5.4 | Host changes left behind by a crash are a warning | `tests/unit/test_selfcheck.py::test_leftover_host_changes_are_a_warning` |
| C5.5 | Running Sletchy elevated fails the check | `tests/unit/test_selfcheck.py::test_running_elevated_fails` |
