# Clumsy - the person who does it wrong

They double-click, run a command twice, close the window halfway through, type the
wrong thing, and run `sletchy` from whatever folder the terminal happened to open in.
None of that is malicious, and none of it may cost them their record or their computer.
The bar for every story here is the same: **wrong input fails closed, says what
happened in a sentence, and leaves nothing half-done.**

Read [README.md](README.md) for how a criterion is held.

## K1. Doing things in the wrong order

As a person who skips the setup step, I want every command to tell me it is not set up yet, so that I am never shown a crash or an empty answer dressed as a real one.

| # | Acceptance criterion | Held by |
|---|---|---|
| K1.1 | Before `init`, `status`, `ledger verify`, `ledger show`, `flags list` and `flags set` each say Sletchy is not set up, exit 1, and write no ledger | `tests/unit/test_clumsy_cli.py::test_before_init_every_command_says_not_set_up_and_creates_nothing` |
| K1.2 | Before setup, the window's status says "not set up" rather than failing | `tests/unit/test_bridge.py::test_status_before_setup_says_so_rather_than_failing` |
| K1.3 | `init` run twice leaves the signing key untouched and says so | `tests/unit/test_clumsy_cli.py::test_init_run_twice_leaves_the_key_alone_and_says_so` |
| K1.4 | `init` over a corrupt record refuses with a sentence and exit 2, and repairs nothing | `tests/unit/test_clumsy_cli.py::test_init_over_a_corrupt_record_exits_two_and_changes_nothing`, `tests/unit/test_clumsy_cli.py::test_init_after_a_torn_last_line_exits_two` |

## K2. Wrong, missing or huge arguments

As a person who mistypes, I want a wrong argument refused before anything happens, so that a typo can never half-run a command.

| # | Acceptance criterion | Held by |
|---|---|---|
| K2.1 | A misspelt switch name is refused and named as unknown | `tests/unit/test_cli.py::test_an_unknown_flag_exits_non_zero` |
| K2.2 | A value other than `on` or `off` is refused | `tests/unit/test_cli.py::test_flags_set_rejects_a_value_that_is_not_on_or_off` |
| K2.3 | `sletchy` with no command does nothing | `tests/unit/test_cli.py::test_a_bare_invocation_is_an_error` |
| K2.4 | A negative, zero or non-numeric `--tail` is refused before the ledger is opened | `tests/unit/test_cli.py::test_ledger_show_refuses_a_tail_that_is_not_a_positive_number` |
| K2.5 | A reason longer than the record holds is cut to 512 characters, and the chain still verifies | `tests/unit/test_clumsy_cli.py::test_a_reason_longer_than_the_record_holds_is_cut_and_still_verifies` |
| K2.6 | A missing argument (`flags set` with no value) is refused and nothing is written | `tests/unit/test_clumsy_cli.py::test_flags_set_with_no_value_is_refused_and_writes_nothing` |

## K3. Doing it twice

As a person who double-clicks, I want running the same thing twice to be as safe as running it once, so that impatience never damages anything.

| # | Acceptance criterion | Held by |
|---|---|---|
| K3.1 | The same flip run twice leaves the switch in the same state, records both, and verifies | `tests/unit/test_clumsy_cli.py::test_the_same_flip_twice_leaves_one_state_records_both_and_verifies` |
| K3.2 | Stop everything run twice is harmless | `tests/adversarial/test_panic.py::test_panic_is_idempotent` |
| K3.3 | Two processes writing to the record at the same moment never fork the chain | `tests/adversarial/test_clumsy_ledger.py::test_processes_writing_at_the_same_moment_never_fork_the_chain`, `tests/adversarial/test_clumsy_ledger.py::test_two_writers_taking_turns_never_fork_the_chain`, `tests/adversarial/test_clumsy_ledger.py::test_a_killed_writer_leaves_no_lock_behind` |

## K4. Closing the window halfway through

As a person who closes things without waiting, I want a half-finished operation to leave either the old state or the new one, so that I never come back to a broken record.

| # | Acceptance criterion | Held by |
|---|---|---|
| K4.1 | Closing the window's pipe ends the Kernel cleanly, exit 0 | `tests/e2e/test_bridge_process.py::test_every_button_in_the_window_end_to_end` |
| K4.2 | A Kernel killed between requests leaves a record that still verifies | `tests/e2e/test_bridge_process.py::test_a_kernel_killed_between_requests_leaves_a_record_that_verifies` |
| K4.3 | A crash while the last entry was being written is reported as what it is | `tests/adversarial/test_clumsy_ledger.py::test_a_cut_off_last_line_is_reported_as_a_write_that_never_finished`, `tests/adversarial/test_clumsy_ledger.py::test_the_operator_is_told_what_happened_and_nothing_is_changed` |
| K4.4 | A stored body whose write was cut off is never readable as content | `tests/unit/test_payload_store.py::test_a_stray_temp_file_is_not_readable_as_content` |
| K4.5 | A switch whose file write fails is not recorded as switched | `tests/unit/test_flag_writes.py::test_a_flip_that_cannot_be_written_is_recorded_as_not_taking_effect`, `tests/unit/test_flag_writes.py::test_a_flip_that_cannot_be_staged_records_nothing`, `tests/adversarial/test_panic.py::test_panic_reports_what_the_ledger_holds_when_the_flag_file_cannot_be_written` |

## K5. A damaged `var/`

As a person who deletes or edits the wrong file, I want Sletchy to fall back to its safe state or refuse, so that a damaged folder never turns something dangerous on.

| # | Acceptance criterion | Held by |
|---|---|---|
| K5.1 | A corrupt `flags.json` falls back to the defaults, where every dangerous switch is off | `tests/unit/test_flags.py::test_a_corrupt_state_file_falls_back_to_defaults` |
| K5.2 | A deleted `flags.json` returns Sletchy to a fresh-install posture | `tests/unit/test_flags.py::test_deleting_the_state_file_returns_to_defaults` |
| K5.3 | A corrupt record halts Sletchy rather than being repaired | `tests/adversarial/test_law_zero.py::test_a_corrupt_ledger_halts_rather_than_being_repaired` |
| K5.4 | Stop everything still works over a corrupt record | `tests/adversarial/test_panic.py::test_panic_survives_a_corrupt_ledger_via_the_cli` |
| K5.5 | A missing `var/run/` is not an error for Stop everything | `tests/adversarial/test_panic.py::test_clear_runtime_on_a_missing_directory_is_not_an_error` |
| K5.6 | A file where a folder belongs, or a read-only file, gives a sentence and an exit code, not a traceback | `tests/unit/test_clumsy_cli.py::test_a_file_where_the_ledger_folder_goes_is_a_sentence_and_exit_one`, `tests/unit/test_clumsy_cli.py::test_a_folder_where_flags_json_goes_is_a_sentence_and_exit_one`, `tests/unit/test_clumsy_cli.py::test_a_read_only_flags_json_is_a_sentence_and_exit_one` |

## K6. The wrong folder

As a person whose terminal opened somewhere unexpected, I want Sletchy to find its own state or tell me it cannot, so that I never act on a second, empty copy.

| # | Acceptance criterion | Held by |
|---|---|---|
| K6.1 | A read command run from another folder does not create a `var/` there | `tests/unit/test_clumsy_cli.py::test_a_command_run_from_another_folder_creates_nothing_there`, `tests/unit/test_bridge.py::test_the_window_in_a_folder_with_no_sletchy_says_so_and_creates_nothing` |
| K6.2 | A read command run from another folder does not report an empty record as verified | `tests/unit/test_clumsy_cli.py::test_a_command_run_from_another_folder_creates_nothing_there` |

## K7. Nonsense on the wire

As a person poking at the Raw view, I want any garbage I send to be refused with a code, so that the window never dies because of what I typed.

| # | Acceptance criterion | Held by |
|---|---|---|
| K7.1 | Malformed requests are refused, never crashed | `tests/adversarial/test_bridge_abuse.py::test_malformed_requests_are_refused_not_crashed` |
| K7.2 | A handler that crashes produces an answer, and the next request still works | `tests/adversarial/test_bridge_abuse.py::test_a_crashing_handler_is_an_answer_not_a_dead_bridge` |
| K7.3 | Garbage on a real Kernel's pipe does not kill it | `tests/e2e/test_bridge_process.py::test_every_button_in_the_window_end_to_end` |
