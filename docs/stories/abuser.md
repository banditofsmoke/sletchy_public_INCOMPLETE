# Abuser - someone trying to use Sletchy for harm

**Assume somewhere on the network, someone will try to use Sletchy for evil, and cut
them out by default.** That is my instruction, and this file is the floor it sets.

The abuser here may be a hostile page rendered in the window, a script that got hold of
the bridge's pipe, a program running as the same Windows user that can write `var/`, or
the operator's own hurried hands. They want to turn a switch on without consent, forge a
request, rewrite or flood the record, or use Sletchy to reach past `var/` into the rest
of the computer. What stops them, and what does not yet, is below.

Read [README.md](README.md) for how a criterion is held. What a control does **not**
catch is recorded in [`tests/adversarial/COVERAGE.md`](../../tests/adversarial/COVERAGE.md).

## A1. Turning a switch on without consent

As an operator, I want no dangerous switch to turn on unless I said why and named it, so that nothing can enable the camera, the network or a deploy behind my back.

| # | Acceptance criterion | Held by |
|---|---|---|
| A1.1 | No route through the bridge turns a dangerous switch on without both a reason and its name typed back | `tests/adversarial/test_bridge_abuse.py::test_no_route_turns_a_dangerous_flag_on_without_both_proofs` |
| A1.2 | Coerced or smuggled parameters, including an `actor_id` naming someone else, are refused and change nothing | `tests/adversarial/test_bridge_abuse.py::test_smuggled_or_coerced_flag_params_are_refused` |
| A1.3 | A refused flip leaves no ledger entry | `tests/adversarial/test_bridge_abuse.py::test_a_refused_flip_leaves_no_ledger_entry` |
| A1.4 | The command line refuses a dangerous flip without a reason | `tests/unit/test_cli.py::test_flags_set_requires_a_reason_for_a_dangerous_flag` |
| A1.5 | A blank reason is not a reason | `tests/unit/test_flags.py::test_a_blank_reason_is_not_a_reason` |
| A1.6 | An invisible reason (a zero-width space, a word joiner, a NUL) is not a reason at the command line | `tests/adversarial/test_abuser_reasons.py::test_an_invisible_reason_does_not_turn_a_dangerous_switch_on` |
| A1.7 | A switch name `flags.json` does not declare is dropped, so a hand-edited file cannot smuggle one in | `tests/unit/test_flags.py::test_an_unknown_name_in_the_state_file_is_ignored` |
| A1.8 | A dangerous switch turned on by editing `flags.json`, with no ledger entry, is detected | `tests/adversarial/test_abuser_flags.py::test_a_dangerous_flag_turned_on_by_hand_reads_as_off_and_is_named`, `tests/adversarial/test_abuser_flags.py::test_status_names_it_and_exits_one`, `tests/adversarial/test_abuser_flags.py::test_the_window_and_the_self_check_name_it` |
| A1.9 | A dangerous switch that defaults to on cannot even be registered | `tests/unit/test_flags.py::test_a_dangerous_flag_defaulting_on_cannot_be_registered` |
| A1.10 | An invisible reason is not a reason from the window either | `tests/adversarial/test_abuser_reasons.py::test_an_invisible_reason_is_refused_from_the_window_too` |

## A2. Forging bridge requests

As an operator, I want the bridge to answer only the requests the window needs, strictly typed, so that whoever holds its pipe cannot make the Kernel do anything else.

| # | Acceptance criterion | Held by |
|---|---|---|
| A2.1 | Only allowlisted methods exist: no private attribute, no `ledger.append`, no `ledger.repair` | `tests/adversarial/test_bridge_abuse.py::test_only_allowlisted_methods_exist` |
| A2.2 | Malformed, mistyped or over-deep requests are refused, never crashed | `tests/adversarial/test_bridge_abuse.py::test_malformed_requests_are_refused_not_crashed` |
| A2.3 | A method that takes no parameters takes nothing | `tests/adversarial/test_bridge_abuse.py::test_a_no_params_method_takes_nothing` |
| A2.4 | The id of a failed request is echoed only when it is valid | `tests/adversarial/test_bridge_abuse.py::test_the_id_of_a_failed_request_is_echoed_only_when_it_is_valid` |
| A2.5 | Stop everything cannot be made to ask, or to accept a confirmation | `tests/unit/test_bridge.py::test_panic_run_takes_no_confirmation` |
| A2.6 | A flood of hostile lines on a real Kernel's pipe is answered line for line, and the Kernel survives it | `tests/e2e/test_bridge_process.py::test_a_flood_of_hostile_lines_is_answered_line_for_line_and_the_kernel_survives` |

## A3. Tampering with the record

As an operator, I want any edit to the record to be detected and never repaired, so that history cannot be rewritten to hide what happened.

| # | Acceptance criterion | Held by |
|---|---|---|
| A3.1 | Editing a field of a past entry breaks its signature | `tests/adversarial/test_ledger_tamper.py::test_mutating_a_field_breaks_the_signature` |
| A3.2 | Flipping a recorded verdict from deny to allow breaks its signature | `tests/adversarial/test_ledger_tamper.py::test_mutating_the_verdict_breaks_the_signature` |
| A3.3 | Deleting an entry from the middle breaks the chain | `tests/adversarial/test_ledger_tamper.py::test_deleting_a_middle_entry_breaks_the_chain` |
| A3.4 | Reordering entries is detected | `tests/adversarial/test_ledger_tamper.py::test_reordering_entries_is_detected` |
| A3.5 | An entry forged without the key breaks the chain | `tests/adversarial/test_ledger_tamper.py::test_appending_a_forged_entry_breaks_the_chain` |
| A3.6 | A second genesis cannot be spliced in to disguise a truncation | `tests/adversarial/test_ledger_tamper.py::test_a_second_genesis_cannot_be_spliced_in` |
| A3.7 | No module offers a repair function | `tests/adversarial/test_law_zero.py::test_no_module_offers_a_ledger_repair_function` |
| A3.8 | Nothing is shown from a chain that does not verify | `tests/unit/test_ledger_view.py::test_cli_show_prints_nothing_from_a_corrupt_chain` |
| A3.9 | A shortened or deleted record is detected | `tests/adversarial/test_ledger_tamper.py::test_truncating_the_tail_is_caught_by_the_keychain_mark`, `tests/adversarial/test_ledger_tamper.py::test_deleting_the_whole_ledger_is_caught_even_by_setup`, `tests/adversarial/test_ledger_tamper.py::test_status_and_setup_refuse_a_ledger_the_keychain_remembers_as_longer` |
| A3.10 | A reason cannot print a fake entry in `ledger show` | `tests/adversarial/test_abuser_reasons.py::test_a_reason_cannot_print_a_second_entry` |
| A3.11 | No control character in a stored field reaches the terminal raw: no escape sequence, carriage return, backspace or right-to-left override | `tests/adversarial/test_abuser_reasons.py::test_no_control_character_reaches_the_terminal_raw` |

## A4. Flooding

As an operator, I want every input Sletchy accepts to have a ceiling, so that nobody can fill my disk or memory through it.

| # | Acceptance criterion | Held by |
|---|---|---|
| A4.1 | A request line over 64 KiB is refused and the stream recovers on the next line | `tests/adversarial/test_bridge_abuse.py::test_an_oversized_line_is_refused_and_the_stream_recovers` |
| A4.2 | One read cannot ask for more than 500 entries, or for nonsense | `tests/adversarial/test_bridge_abuse.py::test_ledger_tail_params_are_bounded` |
| A4.3 | A stored body over the cap is refused before a byte is written | `tests/unit/test_payload_store.py::test_a_refused_payload_leaves_nothing_behind` |
| A4.4 | The meter warns when `var/` grows past the LAW 0 quota | `tests/unit/test_selfcheck.py::test_disk_use_against_the_law_0_quota` |
| A4.5 | The record's total size has a ceiling | `tests/adversarial/test_abuser_flood.py::test_a_flood_stops_at_the_ceiling_and_the_chain_still_verifies`, `tests/adversarial/test_abuser_flood.py::test_nothing_is_written_that_would_leave_the_drive_under_two_gb`, `tests/adversarial/test_abuser_flood.py::test_switching_off_and_panic_still_work_on_a_full_ledger` |

## A5. Reaching past `var/`

As an operator, I want Sletchy to touch nothing on my computer outside its own folder except what it can undo, so that it can never become the tool that damages the machine it protects.

| # | Acceptance criterion | Held by |
|---|---|---|
| A5.1 | A full session writes nothing outside Sletchy's home | `tests/adversarial/test_law_zero.py::test_a_full_session_writes_nothing_outside_sletchy_home` |
| A5.2 | Nothing writes to the registry | `tests/adversarial/test_law_zero.py::test_no_registry_writes` |
| A5.3 | Nothing writes to a hardcoded absolute path | `tests/adversarial/test_law_zero.py::test_nothing_writes_to_a_hardcoded_absolute_path` |
| A5.4 | Nothing asks for elevation at runtime | `tests/adversarial/test_law_zero.py::test_nothing_requests_elevation_at_runtime` |
| A5.5 | Firewall rules are removed only by Sletchy's own group, never by name | `tests/adversarial/test_panic_reverts.py::test_removal_is_by_group_never_by_rule_name` |
| A5.6 | A stored body's address is computed, never chosen by the caller | `tests/unit/test_payload_store.py::test_put_takes_only_content` |
| A5.7 | A forged undo-journal record cannot make Stop everything delete an AppContainer profile that is not Sletchy's | `tests/adversarial/test_abuser_panic.py::test_a_forged_record_naming_another_apps_profile_is_never_deleted` |
| A5.8 | A forged undo-journal record cannot make Stop everything strip a user's, a group's or a well-known SID's permissions | `tests/adversarial/test_abuser_panic.py::test_a_forged_record_naming_the_users_own_sid_never_reaches_icacls` |
| A5.9 | A refused record makes Stop everything report "not clean" with the reason, and the record is kept as evidence | `tests/adversarial/test_abuser_panic.py::test_a_refusal_makes_panic_unclean_and_says_why` |
| A5.10 | A forged record naming another app's container SID, or a path the Warden would never grant, is refused too | `tests/adversarial/test_abuser_panic.py::test_another_apps_container_sid_is_refused_even_under_a_sletchy_name`, `tests/adversarial/test_abuser_panic.py::test_a_granted_path_the_warden_would_refuse_is_never_walked`, `tests/adversarial/test_abuser_panic.py::test_a_sid_that_cannot_be_checked_is_refused_and_kept` |
| A5.11 | An undo-journal line Stop everything cannot read is reported, not silently skipped | `tests/adversarial/test_panic_reverts.py::test_an_unreadable_journal_line_makes_panic_unclean_and_is_kept`, `tests/adversarial/test_panic_reverts.py::test_a_readable_record_still_reverts_beside_an_unreadable_line`, `tests/unit/test_selfcheck.py::test_an_unreadable_undo_line_is_not_nothing_left_behind` |

## A6. Using the test key for real

As an operator, I want the signing key to come only from my keychain and never be replaced, so that nobody can sign a history of their own.

| # | Acceptance criterion | Held by |
|---|---|---|
| A6.1 | The in-memory test key refuses to load outside a test run | `tests/unit/test_ledger_chain.py::test_in_memory_key_source_refuses_outside_a_test_run` |
| A6.2 | A missing key is fatal on the read path, and no key is created there | `tests/unit/test_ledger_chain.py::test_a_missing_keychain_key_raises_and_does_not_create_one` |
| A6.3 | A chain signed with a different key fails | `tests/adversarial/test_ledger_tamper.py::test_a_chain_signed_with_the_wrong_key_fails` |
