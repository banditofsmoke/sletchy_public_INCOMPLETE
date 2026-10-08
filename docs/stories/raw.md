# Raw - a developer

They use the window's **Raw** view, which sends any method with any JSON parameters and
shows the answer, and they use the `sletchy` command in scripts. They care about exit
codes, the wire format, and where state lives. Raw is a view, not a back door: every
request goes through the same allowlist and the same strict models as the other views.

Read [README.md](README.md) for how a criterion is held.

## R1. Exit codes a script can rely on

As a developer scripting Sletchy, I want distinct exit codes for success, failure and a corrupt record, so that a script can tell a broken ledger from a typo.

| # | Acceptance criterion | Held by |
|---|---|---|
| R1.1 | `ledger verify` exits 0 and reports the count on a good chain | `tests/unit/test_cli.py::test_verify_reports_the_entry_count` |
| R1.2 | `ledger verify` exits 2 on a corrupt chain and says it was not repaired | `tests/unit/test_cli.py::test_verify_exits_two_on_a_corrupt_chain` |
| R1.3 | `status` exits 2 on a corrupt chain rather than printing a reassuring summary | `tests/unit/test_cli.py::test_status_exits_two_on_a_corrupt_chain` |
| R1.4 | Every command and subcommand is reachable from the parser | `tests/unit/test_cli.py::test_every_command_is_reachable` |
| R1.5 | A damaged `var/` gives a one-line reason and an exit code, never a traceback | `tests/unit/test_clumsy_cli.py::test_a_file_where_the_ledger_folder_goes_is_a_sentence_and_exit_one`, `tests/unit/test_clumsy_cli.py::test_init_keeps_the_exit_code_contract`, `tests/unit/test_clumsy_cli.py::test_a_programming_error_still_raises` |

## R2. The wire

As a developer driving the bridge, I want one JSON request per line in and one ASCII line out, in order, so that I can pipe it and parse it without surprises.

| # | Acceptance criterion | Held by |
|---|---|---|
| R2.1 | Requests are answered in order, and the bridge stops at end of input | `tests/unit/test_bridge.py::test_serve_answers_in_order_and_stops_at_end_of_input` |
| R2.2 | Every response is one ASCII line, whatever the input contained | `tests/adversarial/test_bridge_abuse.py::test_responses_are_one_ascii_line_each_whatever_the_input` |
| R2.3 | Every allowed method has a handler, and nothing else does | `tests/unit/test_bridge.py::test_every_method_has_a_handler_and_nothing_else_does` |
| R2.4 | The window's TypeScript types are generated from the bridge's models and are current | `tests/unit/test_desktop_contracts.py::test_the_typescript_is_current` |
| R2.5 | The shell's Rust allowlist is generated from the same models and is current | `tests/unit/test_desktop_contracts.py::test_the_rust_allowlist_is_current` |
| R2.6 | A stray `print` anywhere in the Kernel cannot corrupt the protocol stream | `tests/adversarial/test_bridge_abuse.py::test_stray_prints_cannot_reach_the_protocol_stream` |
| R2.7 | A real Kernel process on real pipes exits 0 when its input closes | `tests/e2e/test_bridge_process.py::test_every_button_in_the_window_end_to_end` |

## R3. Where state lives

As a developer, I want every byte Sletchy writes to be under one folder I can name, so that uninstall is one delete and a test can never touch my real install.

| # | Acceptance criterion | Held by |
|---|---|---|
| R3.1 | `SLETCHY_HOME` moves everything | `tests/unit/test_cli.py::test_home_is_overridable_so_nothing_assumes_a_fixed_location` |
| R3.2 | Every path Sletchy declares lives under its home | `tests/unit/test_cli.py::test_every_path_lives_under_home` |
| R3.3 | The CLI writes nothing outside its home | `tests/unit/test_cli.py::test_the_cli_writes_nothing_outside_sletchy_home` |
| R3.4 | A command run from another folder neither creates state there nor calls an empty record verified | `tests/unit/test_clumsy_cli.py::test_a_command_run_from_another_folder_creates_nothing_there`, `tests/unit/test_ledger_chain.py::test_open_without_create_never_makes_a_ledger` |

## R4. Reading the record from a terminal

As a developer, I want `sletchy ledger show` to print a verified chain or nothing, and to survive being piped, so that I can keep an audit copy in a file.

| # | Acceptance criterion | Held by |
|---|---|---|
| R4.1 | It prints entries from a verified chain | `tests/unit/test_ledger_view.py::test_cli_show_prints_entries` |
| R4.2 | It prints nothing from a chain that does not verify | `tests/unit/test_ledger_view.py::test_cli_show_prints_nothing_from_a_corrupt_chain` |
| R4.3 | A tail is capped, so one read cannot ask for the whole history | `tests/unit/test_ledger_view.py::test_tail_is_capped` |
| R4.4 | `--tail` accepts only a positive number, and refuses anything else before the ledger is opened | `tests/unit/test_cli.py::test_ledger_show_refuses_a_tail_that_is_not_a_positive_number` |
| R4.5 | Redirected to a file, it never crashes on a character the encoding cannot hold | `tests/adversarial/test_abuser_reasons.py::test_a_reason_the_output_encoding_cannot_hold_does_not_crash_the_reader` |

## R5. The ledger underneath

As a developer, I want the chain's format to be stable and its test key unusable in production, so that what verifies today verifies after an upgrade and a convenience never ships.

| # | Acceptance criterion | Held by |
|---|---|---|
| R5.1 | Appending after a reopen continues the same chain | `tests/unit/test_ledger_chain.py::test_appending_after_reopen_continues_the_chain` |
| R5.2 | The chain crosses a segment boundary on rotation | `tests/unit/test_ledger_chain.py::test_the_chain_crosses_a_segment_boundary` |
| R5.3 | The bytes that are signed are ASCII | `tests/unit/test_ledger_chain.py::test_canonical_bytes_are_ascii` |
| R5.4 | Hashing is stable across calls | `tests/unit/test_ledger_chain.py::test_hashing_is_stable_across_calls` |
| R5.5 | The in-memory test key refuses to load outside a test run | `tests/unit/test_ledger_chain.py::test_in_memory_key_source_refuses_outside_a_test_run` |
