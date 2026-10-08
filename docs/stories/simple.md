# Simple - someone who has never opened a terminal

They use the desktop window's **Simple** view: one column, big switches, plain words.
They do not know what a firewall rule or a ledger is, and they should never need to.
Everything they press reaches the Kernel as one `sletchy bridge` request: `init`,
`status`, `selfcheck`, `flags.list`, `flags.set`, `ledger.tail` or `panic.run`.

Read [README.md](README.md) for how a criterion is held.

## S1. Safe the moment it is installed

As a person who does not know what a firewall is, I want Sletchy to do nothing risky until I ask, so that installing it cannot hurt my only computer.

| # | Acceptance criterion | Held by |
|---|---|---|
| S1.1 | Every dangerous switch is off on a fresh install, checked across the whole registry rather than a sample | `tests/unit/test_flags.py::test_every_dangerous_flag_is_off_on_a_fresh_install` |
| S1.2 | A fresh install with an empty policy grants nothing | `tests/adversarial/test_law_zero.py::test_a_fresh_install_grants_nothing` |
| S1.3 | The window's first status reports a verified record and no dangerous switch on | `tests/unit/test_bridge.py::test_status` |
| S1.4 | A switch that nothing in Sletchy reads yet is marked as such, so the window never presents it as doing something | `tests/unit/test_flag_honesty.py::test_wired_matches_the_source` |

## S2. Setting it up

As a first-time user, I want one Set up button that I cannot break by pressing, so that I can start without reading anything.

| # | Acceptance criterion | Held by |
|---|---|---|
| S2.1 | Before setup, the window is told "not set up" rather than shown an error | `tests/unit/test_bridge.py::test_status_before_setup_says_so_rather_than_failing` |
| S2.2 | Set up creates Sletchy's folder and says what it did | `tests/unit/test_bridge.py::test_init_on_an_in_memory_key_creates_the_home_and_provisions_nothing` |
| S2.3 | Pressing Set up a second time changes nothing and the record still verifies | `tests/unit/test_bridge.py::test_set_up_pressed_twice_changes_nothing_and_the_record_verifies` |
| S2.4 | Set up never replaces an existing signing key, which would make every past entry unverifiable | `tests/unit/test_ledger_chain.py::test_provision_refuses_to_overwrite_an_existing_key` |

## S3. Turning something on, on purpose

As a person who might tap the wrong thing, I want a dangerous switch to ask me what it is for and which switch I meant, so that nothing dangerous turns on by accident.

| # | Acceptance criterion | Held by |
|---|---|---|
| S3.1 | A dangerous switch turns on only with a reason and its exact name typed back | `tests/unit/test_bridge.py::test_a_dangerous_flag_needs_a_reason_and_its_name_typed_back` |
| S3.2 | Turning anything off never asks for anything | `tests/unit/test_bridge.py::test_turning_anything_off_is_never_obstructed` |
| S3.3 | The record says the change came from the window, not the terminal | `tests/unit/test_bridge.py::test_a_safe_flag_flips_and_is_ledgered_as_the_desktop` |
| S3.4 | A switch they turned on is still on after a restart | `tests/unit/test_flags.py::test_a_flip_survives_a_restart` |

## S4. Stop everything

As a person who is frightened something is wrong, I want one button that stops everything without asking me questions, so that I can make it safe before I understand what happened.

| # | Acceptance criterion | Held by |
|---|---|---|
| S4.1 | Stop everything takes no confirmation, and refuses to be given one | `tests/unit/test_bridge.py::test_panic_run_takes_no_confirmation` |
| S4.2 | It returns every switch to its default | `tests/unit/test_bridge.py::test_panic_plan_changes_nothing_and_panic_run_resets` |
| S4.3 | It never deletes their history | `tests/adversarial/test_panic.py::test_panic_does_not_delete_the_ledger` |
| S4.4 | It never deletes stored conversations | `tests/adversarial/test_panic.py::test_panic_does_not_delete_payloads` |
| S4.5 | Pressing it twice is as safe as pressing it once | `tests/adversarial/test_panic.py::test_panic_is_idempotent` |
| S4.6 | It still works from the window when the record is damaged | `tests/unit/test_bridge.py::test_stop_everything_still_works_from_the_window_when_the_record_is_damaged` |
| S4.7 | It never deletes an app profile Sletchy did not create, whatever its undo list says | `tests/adversarial/test_abuser_panic.py::test_a_forged_record_naming_another_apps_profile_is_never_deleted` |
| S4.8 | It never changes the permissions of a person or a group of people on the computer | `tests/adversarial/test_abuser_panic.py::test_only_an_appcontainer_sid_is_ever_handed_to_icacls` |
| S4.9 | It never changes another app's permissions, or walks a folder Sletchy would never have used | `tests/adversarial/test_abuser_panic.py::test_another_apps_container_sid_is_refused_even_under_a_sletchy_name`, `tests/adversarial/test_abuser_panic.py::test_a_granted_path_the_warden_would_refuse_is_never_walked`, `tests/adversarial/test_abuser_panic.py::test_the_warden_and_panic_share_one_guard` |

## S5. A trust meter in plain words

As a person who cannot judge security settings, I want one score and a sentence for each check, so that I know whether to worry without learning the vocabulary.

| # | Acceptance criterion | Held by |
|---|---|---|
| S5.1 | Every sentence the meter shows is plain English with no jargon | `tests/unit/test_selfcheck.py::test_every_plain_sentence_is_plain` |
| S5.2 | It says what it cannot prove, on the same screen as the score | `tests/unit/test_selfcheck.py::test_what_it_cannot_prove_is_part_of_the_answer` |
| S5.3 | A tampered record fails loudly, in plain words | `tests/unit/test_selfcheck.py::test_a_tampered_ledger_fails_loudly_in_plain_words` |
| S5.4 | A dangerous switch left on is a warning that names it | `tests/unit/test_selfcheck.py::test_a_dangerous_switch_on_is_a_warning_that_names_it` |
| S5.5 | Checking changes nothing | `tests/unit/test_selfcheck.py::test_a_self_check_changes_nothing` |

## S6. The window works, end to end

As a person who only ever clicks, I want every button to reach the real Kernel and come back, so that what the window shows is what Sletchy did.

| # | Acceptance criterion | Held by |
|---|---|---|
| S6.1 | Every button in the window, against a real Kernel process on real pipes: setup, status, the meter, a dangerous switch's two proofs, the record, Stop everything, and a clean exit | `tests/e2e/test_bridge_process.py::test_every_button_in_the_window_end_to_end` |
| S6.2 | The meter notices when a dangerous switch goes on | `tests/e2e/test_bridge_process.py::test_every_button_in_the_window_end_to_end` |
| S6.3 | Nothing is written outside Sletchy's folder while they use it | `tests/adversarial/test_law_zero.py::test_a_full_session_writes_nothing_outside_sletchy_home` |
