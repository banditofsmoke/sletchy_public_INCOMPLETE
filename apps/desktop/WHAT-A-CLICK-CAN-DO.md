# What a click can do

The question this page answers: *can I click anything in the Sletchy window without
breaking my computer?*

**The short answer: yes.** Every button, lever, valve and screen in the window ends
in one of **twelve requests** to Sletchy's Kernel, or it only changes how the window
looks. Nothing else can come out of the window: the Rust shell and the Kernel each
refuse anything that is not on this list, and the tests named below check that.

`tests/unit/test_click_map.py` fails the build if a request is missing from this
page, or if this page cites a test that does not exist.

---

## The twelve requests

| Request | The buttons that send it | Reads | Writes | Outside `var/`? | How to undo it | Tests that prove it |
|---|---|---|---|---|---|---|
| `status` | Opening the window, **Refresh**, and after every switch flip | the record (`var/ledger/`), the switches (`var/flags.json`) | nothing | no | nothing to undo | `tests/unit/test_bridge.py::test_status`, `tests/unit/test_bridge.py::test_status_before_setup_says_so_rather_than_failing` |
| `selfcheck` | The trust meter, **Check again** | the record, the switches, the host-change journal, whether Sletchy runs elevated, the Windows build, free disk space, the `Sletchy` firewall rules (read-only, no administrator) | nothing | no | nothing to undo | `tests/unit/test_selfcheck.py::test_a_self_check_changes_nothing`, `tests/unit/test_bridge.py::test_selfcheck_answers_with_a_score_and_its_limits` |
| `flags.list` | Every screen that shows the switches | the switches | nothing | no | nothing to undo | `tests/unit/test_bridge.py::test_flags_list_is_the_whole_registry` |
| `flags.set` | A lever or switch | the switches | one line of `var/flags.json`, and one record entry saying who flipped it and when | no | flip it back, or **Stop everything** resets every switch. **Two switches are read today**: Watch the whole PC, by `sletchy-soc`, and Local AI models, by `sletchy ask` and **Talk to a model**. Any other flip changes that file and nothing else | `tests/unit/test_bridge.py::test_a_safe_flag_flips_and_is_ledgered_as_the_desktop`, `tests/adversarial/test_bridge_abuse.py::test_no_route_turns_a_dangerous_flag_on_without_both_proofs`, `tests/adversarial/test_bridge_abuse.py::test_a_refused_flip_leaves_no_ledger_entry`, `tests/unit/test_bridge.py::test_turning_anything_off_is_never_obstructed`, `tests/unit/test_flag_honesty.py::test_these_switches_are_read_today` |
| `ledger.tail` | The record table and its filters | the record | nothing | no | nothing to undo | `tests/unit/test_ledger_view.py::test_reading_writes_nothing`, `tests/adversarial/test_bridge_abuse.py::test_ledger_tail_params_are_bounded` |
| `ledger.payload` | The **Raw** view's console, by hand (#86) | one record entry and its stored body | nothing | no | nothing to undo | `tests/adversarial/test_payload_view.py::test_no_secret_shape_is_ever_shown`, `tests/adversarial/test_payload_view.py::test_a_body_planted_or_edited_under_its_hash_is_not_shown`, `tests/adversarial/test_payload_view.py::test_the_bridge_bounds_the_sequence_number`, `tests/adversarial/test_payload_view.py::test_reading_a_body_writes_nothing` |
| `stop.plan` | **Show what it would do** | the switches, the journal, and a read-only count of Windows Firewall rules in the group `Sletchy` | nothing | reads only | nothing to undo | `tests/unit/test_bridge.py::test_panic_plan_changes_nothing_and_panic_run_resets`, `tests/adversarial/test_panic_reverts.py::test_a_dry_run_counts_but_never_removes`, `tests/adversarial/test_panic.py::test_dry_run_changes_nothing` |
| `stop.run` | **Stop everything** (the red valve: hold it, a click is not enough) | as above | resets every switch, clears `var/run/`, adds a record entry. It also undoes **only Sletchy's own** host changes: folder permissions and sandbox profiles from its journal, and, run as administrator, firewall rules in the group `Sletchy`. The window runs as a normal user, so it **keeps** those rules, counts them and says so (#179): they only stop Sletchy's own sandboxes reaching other computers. `sletchy install-rules --remove`, as administrator, takes them away | only to undo Sletchy's own changes | it is the undo. It never deletes the record, the payloads or the signing key | `tests/adversarial/test_panic.py::test_panic_does_not_delete_the_ledger`, `tests/adversarial/test_panic.py::test_panic_does_not_delete_payloads`, `tests/adversarial/test_panic.py::test_panic_only_clears_the_runtime_directory`, `tests/adversarial/test_panic_reverts.py::test_removal_is_by_group_never_by_rule_name`, `tests/adversarial/test_panic_reverts.py::test_unelevated_panic_with_rules_kept_is_clean_and_says_why`, `tests/adversarial/test_panic.py::test_panic_is_idempotent` |
| `models.list` | Opening **Talk to a model**, and its **Try again** | the switches; then, only while **Local AI models** is on, the list of models from the model server on `127.0.0.1` (Ollama's port), and what each can do (`/api/show`, asked once per model while the window is open): one that cannot hold a conversation is listed and greyed | one record entry for each request to the model server (`warden.egress.local`), allowed or refused | no: `127.0.0.1` only, and Sletchy never starts a model server | nothing to undo | `tests/unit/test_bridge_models.py::test_switched_off_the_window_is_refused_and_nothing_is_sent`, `tests/unit/test_bridge_models.py::test_the_model_list_marks_what_fits_the_card_budget`, `tests/unit/test_bridge_models.py::test_no_model_server_is_a_sentence_not_a_crash`, `tests/unit/test_local_show.py::test_the_window_lists_an_embedding_model_as_one_that_cannot_talk`, `tests/adversarial/test_local_model_door.py::test_the_door_connects_to_this_machine_and_nowhere_else` |
| `model.ask` | **Ask**, on **Talk to a model** | the switches, then the model list, then the model's answer to the question and the conversation so far (ADR-0018; **New conversation**, or another model, starts again). With **Memory** on, the question is first searched for in memory, the same model judges what was found, and what helps goes before the question as quoted passages with their sources; the answered turn is remembered (ADR-0019). All of it on a worker thread inside the Kernel. It answers at once with a ticket, so a model that thinks for minutes holds up no other request, Stop everything included. One question at a time | the question and the answer as record entries (`mind.model.ask`, `mind.model.answer`), both texts under `var/payloads/`, and the door's entries. With Memory on, also the search, the judgement and the plan (`mind.memory.search`, `.found`, `.judge`, `mind.context.plan`), and the turn added to `var/memory/` (`mind.memory.add`). A model over the card budget, or any request but a question, is refused and recorded, and nothing is sent | no: `127.0.0.1` only. The model server is not contained, and is trusted with the question | nothing to undo: the record keeps the conversation, as it keeps everything. Stop everything turns the switch off; a question already sent finishes and is recorded | `tests/unit/test_bridge_models.py::test_the_window_asks_through_the_door_and_both_texts_are_on_the_record`, `tests/unit/test_bridge_models.py::test_stop_everything_answers_while_a_model_is_still_thinking`, `tests/unit/test_bridge_models.py::test_one_question_at_a_time`, `tests/unit/test_bridge_models.py::test_a_model_over_the_budget_is_refused_with_its_reason_and_never_asked`, `tests/unit/test_bridge_models.py::test_a_malformed_question_is_refused_before_anything_is_sent`, `tests/adversarial/test_local_model_door.py::test_anything_but_a_listed_question_is_refused_before_it_is_sent` |
| `model.load` | **Load model**, on **Talk to a model** | the switches, the model list and the card budget; then the model is put on the card with the chosen context and no question, on a worker thread, answering at once with a ticket. Afterwards it reads what the server holds (`/api/ps`): the size, how much is on the card, the context and when it unloads | record entries before and after (`mind.model.load`, `mind.model.loaded`), and the door's. A model over the budget, or one the server says cannot hold a conversation, is refused before anything is sent; one running more than 4 GiB past the card is unloaded at once and refused; a load that fails ends on the record | no: `127.0.0.1` only. The model stays loaded 30 minutes after its last request | **Unload**, or wait 30 minutes; Stop everything turns the switch off | `tests/unit/test_local_load.py::test_load_is_recorded_then_measured_from_the_server`, `tests/unit/test_local_load.py::test_a_load_that_spills_past_the_bound_is_unloaded_and_refused`, `tests/unit/test_local_load.py::test_a_model_over_the_budget_is_never_loaded`, `tests/unit/test_local_show.py::test_an_embedding_model_is_never_loaded`, `tests/unit/test_local_show.py::test_a_failed_load_ends_on_the_record`, `tests/unit/test_local_load.py::test_the_window_loads_on_a_ticket_and_lists_what_is_loaded` |
| `model.unload` | **Unload**, on **Talk to a model** | the switches | a record entry (`mind.model.unload`), then the server is asked to drop the model now | no: `127.0.0.1` only | **Load model** again | `tests/unit/test_local_load.py::test_unload_takes_the_model_off_the_card`, `tests/unit/test_local_load.py::test_the_window_unloads_at_once` |
| `model.answer` | **Talk to a model**, once a second while a question is out | how that question ended: still thinking, answered, or refused and why. The answer is shown inert: every control character but a newline and a tab is `?` | nothing | no | nothing to undo | `tests/unit/test_bridge_models.py::test_the_answer_reaches_the_window_inert`, `tests/unit/test_bridge_models.py::test_a_long_answer_is_cut_for_the_window_and_says_so`, `tests/unit/test_bridge_models.py::test_an_unknown_or_forgotten_ticket_is_refused` |
| `init` | **Set up Sletchy** (shown only before setup) | whether a signing key exists | creates `var/`, `var/run/`, `var/ledger/`, `var/payloads/`, and **one signing key in Windows Credential Manager** | **yes, that one key**. Secrets live only in the OS keychain (CLAUDE.md, Secrets), and this is the one place Sletchy writes outside `var/` | remove the `sletchy` entry in Credential Manager. Stop everything deliberately keeps it: without the key, the record can no longer be verified | `tests/unit/test_bridge.py::test_init_on_an_in_memory_key_creates_the_home_and_provisions_nothing`, `tests/unit/test_ledger_chain.py::test_provision_refuses_to_overwrite_an_existing_key`, `tests/unit/test_ledger_chain.py::test_a_missing_keychain_key_raises_and_does_not_create_one` |

The **Raw** view's console sends the same twelve requests, by hand. It gets no other
way in: anything else is refused twice, first by the shell
(`apps/desktop/src-tauri/src/bridge.rs::a_method_off_the_allowlist_never_reaches_the_kernel`)
and then by the Kernel (`tests/adversarial/test_bridge_abuse.py::test_only_allowlisted_methods_exist`).
Malformed input gets an error back, never a crash
(`tests/adversarial/test_bridge_abuse.py::test_malformed_requests_are_refused_not_crashed`).

## What the shell itself reads

| Request | Where | Reads | Writes | Tests |
|---|---|---|---|---|
| `bridge_info` | Raw view's connection panel, the NOC, the Orrery's core | the connection's own state; Windows' process table, filtered to Sletchy's own processes; the Kernel's Job Object accounting | nothing | `apps/desktop/src-tauri/src/procs.rs::descendants_walks_the_tree_and_nothing_else`, `apps/desktop/src-tauri/src/job.rs::the_job_counts_what_ran_in_it` |

## Clicks that never reach the Kernel

The **Simple / Custom / Raw** tabs, **Help on/off**, **Sound on/off** and the vault
door change only the window. The first three settings are remembered in the window's
own profile, inside `var/webview/`
(`tests/adversarial/test_desktop_shell.py::test_the_webview_profile_lives_under_var`).

## What no click can do

These are true by construction, and each is checked by a test:

- **Reach the internet, or anything else.** The window's content policy allows its
  own pipe and nothing else
  (`tests/adversarial/test_desktop_shell.py::test_the_csp_allows_nothing_remote`).
- **Read or write a file directly, or run a program.** No Tauri plugin is loaded
  (`tests/adversarial/test_desktop_shell.py::test_no_tauri_plugins_widen_the_window`),
  and the window may call exactly two commands
  (`tests/adversarial/test_desktop_shell.py::test_the_window_is_granted_exactly_two_commands`).
- **Leave Sletchy running after you close it.** The Kernel lives in a Job Object
  that Windows kills when the window goes
  (`apps/desktop/src-tauri/src/job.rs::closing_the_job_kills_what_is_inside_it`).
- **Turn on a dangerous switch by accident.** It needs a reason, and the switch's own
  name typed back, and the Kernel checks both
  (`tests/unit/test_bridge.py::test_a_dangerous_flag_needs_a_reason_and_its_name_typed_back`).

## What this page does not prove

- **No test clicks inside the real window.** The tests drive the screens against a
  preview, the real Kernel over real pipes, and the real Kernel inside its job, but
  the whole chain (a click in WebView2, through Rust, into the Kernel) has only been
  exercised by hand. This is the open "No test clicks inside the real window" row in
  `tests/adversarial/COVERAGE.md`.
- **It covers what Sletchy does today.** When a switch gets wired to a real feature,
  that feature brings its own row here, and its own tests, before it ships. The first,
  **Watch the whole PC** (`soc_watch_machine`, #146), needs no row: flipping it is the
  `flags.set` row above, and what it widens is `sletchy-soc`, which runs from a
  terminal and is never started by a click.
