// What every control does, why you would use it, the worst it can do, and the tests
// that stand behind those words.
//
// My words, 2026-10-02: "too scared to click anything ... if I feel that way as the
// creator, we need to give peace of mind." The answer to fear is evidence, so every
// card names the tests that guard it, and `help.test.ts` fails if a named test does
// not exist in the repository. A card cannot cite a test nobody wrote.
//
// "Worst" means the worst thing that control can do **today**, measured, not the
// worst thing the feature behind it might do one day. Where those differ, both are said.

export interface Guard {
  /** Repository-relative path of the file holding the test. */
  readonly file: string;
  /** The test's name: a Python or Rust function, or a Vitest title. */
  readonly test: string;
}

export interface HelpEntry {
  readonly title: string;
  readonly what: string;
  readonly why: string;
  readonly worst: string;
  readonly guards: readonly Guard[];
}

const py = (file: string, test: string): Guard => ({ file: `tests/${file}`, test });
const rs = (file: string, test: string): Guard => ({ file: `apps/desktop/src-tauri/src/${file}`, test });
const ui = (file: string, test: string): Guard => ({ file: `apps/desktop/src/${file}`, test });

export const HELP = {
  meter: {
    title: "The trust meter",
    what: "A score out of 100, made only from checks Sletchy ran just now. The faint arc and the tick show the best score possible today.",
    why: "To see at a glance whether anything about Sletchy itself needs you.",
    worst: "Nothing - it only reads. Its limit: it runs as you, so something that already controls your Windows account could fake it. That is printed under the checks.",
    guards: [
      py("unit/test_selfcheck.py", "test_the_meter_cannot_reach_100_while_network_containment_is_unbuilt"),
      py("unit/test_selfcheck.py", "test_the_score_never_exceeds_the_ceiling"),
      py("unit/test_selfcheck.py", "test_an_unmeasured_windows_build_is_not_assumed_safe"),
      py("unit/test_selfcheck.py", "test_a_self_check_changes_nothing"),
      ui("components/components.test.tsx", "the meter tells a screen reader its score and its ceiling"),
    ],
  },
  recheck: {
    title: "Check again",
    what: "Runs all seven checks again and redraws the meter.",
    why: "After you change something, or just to be sure.",
    worst: "Nothing. It reads Sletchy's record, switches, journal and firewall rules, and changes none of them.",
    guards: [py("unit/test_selfcheck.py", "test_a_self_check_changes_nothing")],
  },
  switches: {
    title: "Switches",
    what: "Each switch allows Sletchy one thing it is not allowed by default. Every flip is written to Sletchy's record with who did it and when.",
    why: "To allow something on purpose. Everything starts off, and nothing can turn itself on.",
    worst: "Two switches do something today. Watch the whole PC widens what sletchy-soc, run from a terminal, looks at, from Sletchy's own processes to every process and connection. Local AI models lets sletchy ask, from a terminal, put questions to a model server on this computer, one local port only. Every other switch changes one line in var/flags.json and adds one record entry. The \"Not connected yet\" tag goes away only when a test proves something reads that switch.",
    guards: [
      py("unit/test_flag_honesty.py", "test_wired_matches_the_source"),
      py("unit/test_flag_honesty.py", "test_these_switches_are_read_today"),
      py("unit/test_bridge.py", "test_a_safe_flag_flips_and_is_ledgered_as_the_desktop"),
      py("unit/test_bridge.py", "test_turning_anything_off_is_never_obstructed"),
      py("unit/test_flags.py", "test_every_dangerous_flag_is_off_on_a_fresh_install"),
    ],
  },
  dangerous: {
    title: "Dangerous switches",
    what: "Switches for the internet, your files, your camera, microphone or screen, training, or real money. Turning one on asks why, and asks you to type its exact name.",
    why: "Only when you need that capability and accept what it allows.",
    worst: "Once its feature is built: exactly what it names, for example Sletchy using your camera. Today nothing reads it. Turning it back off is never blocked, and Stop everything turns all of them off.",
    guards: [
      py("adversarial/test_bridge_abuse.py", "test_no_route_turns_a_dangerous_flag_on_without_both_proofs"),
      py("adversarial/test_bridge_abuse.py", "test_smuggled_or_coerced_flag_params_are_refused"),
      py("adversarial/test_bridge_abuse.py", "test_a_refused_flip_leaves_no_ledger_entry"),
      ui("components/components.test.tsx", "the dialog will not turn a switch on without a reason and the exact name"),
      ui("App.test.tsx", "a dangerous switch goes through the dialog, then shows on and the status warns"),
    ],
  },
  setup: {
    title: "Set up Sletchy",
    what: "Creates Sletchy's folders under var/ and one signing key in Windows Credential Manager, so its record can be trusted.",
    why: "Sletchy refuses to keep an unsigned record, so nothing else works until this has run once.",
    worst: "One new entry in Windows Credential Manager. It never replaces a key that already exists.",
    guards: [
      py("unit/test_ledger_chain.py", "test_provision_refuses_to_overwrite_an_existing_key"),
      py("unit/test_bridge.py", "test_init_on_an_in_memory_key_creates_the_home_and_provisions_nothing"),
      ui("App.test.tsx", "before setup, the window offers to set Sletchy up, and setting up shows the switches"),
    ],
  },
  talk: {
    title: "Talk to a model",
    what: "Talks with a model on this computer, through Ollama on this machine's own port: each question goes with the conversation so far, and each answer shows how much of the model's context it used. New conversation starts again. The list comes in sections: models to talk to, models for memory search (which turn text into numbers and cannot talk), names Ollama made for its own copies, and models too big for your card budget; only the first and third can be picked. Load model puts one on the card before any question, with the context you choose, and says how much of it fits on the card; a model more than 4 GiB past the card is unloaded and refused. It stays loaded 30 minutes after the last question, and Unload frees the card. Without loading first, the first question loads it, which can take minutes. While a model loads or thinks, a bar fills against how long the same thing took last time; the first time, there is nothing to measure against, and it says so. With Memory on, each question is first looked for in what Sletchy remembers; the model judges what was found, and what helps goes with the question, quoted with where it came from and told apart: what you said, and what a model said back. A model too small to judge leaves memory out, and the answer says so. Every answered turn is remembered, except an answer that says it does not know: only your own words from that turn are kept.",
    why: "To use a model you already have, with every question and answer on Sletchy's record.",
    worst: "It asks only while Local AI models is on, and never reaches past this computer. Whatever answers on that port is trusted with your question, and the model server itself is not contained yet. Stop everything still works while a model thinks; a question already sent finishes, and its answer is recorded.",
    guards: [
      py("unit/test_bridge_models.py", "test_switched_off_the_window_is_refused_and_nothing_is_sent"),
      py("unit/test_bridge_models.py", "test_the_window_asks_through_the_door_and_both_texts_are_on_the_record"),
      py("unit/test_bridge_models.py", "test_a_model_over_the_budget_is_refused_with_its_reason_and_never_asked"),
      py("unit/test_bridge_models.py", "test_the_answer_reaches_the_window_inert"),
      py("unit/test_bridge_models.py", "test_stop_everything_answers_while_a_model_is_still_thinking"),
      py("unit/test_bridge_models.py", "test_the_window_holds_a_conversation"),
      py("unit/test_local_load.py", "test_the_window_loads_on_a_ticket_and_lists_what_is_loaded"),
      py("unit/test_local_load.py", "test_a_load_that_spills_past_the_bound_is_unloaded_and_refused"),
      py("unit/test_bridge_recall.py", "test_with_memory_on_a_new_conversation_remembers_an_old_one"),
      py("unit/test_local_show.py", "test_the_window_lists_an_embedding_model_as_one_that_cannot_talk"),
      py("unit/test_local_show.py", "test_a_failed_load_ends_on_the_record"),
      py("unit/test_memory_evidence.py", "test_the_205_replay_judges_the_fact_and_sets_the_rest_aside"),
      py("unit/test_memory_evidence.py", "test_a_judge_that_cannot_be_read_is_said_not_silent"),
      py("adversarial/test_recall_abuse.py", "test_a_passage_cannot_close_its_label_and_speak_as_me"),
      py("unit/test_harness_stream.py", "test_every_event_is_on_the_record_before_a_host_sees_it"),
      py("adversarial/test_local_model_door.py", "test_the_door_connects_to_this_machine_and_nowhere_else"),
    ],
  },
  stop: {
    title: "Stop everything",
    what: "Turns every switch off, undoes the sandbox changes Sletchy made, and clears its temporary files. Run as administrator, it also removes Sletchy's firewall rules. Hold the button to use it.",
    why: "Whenever anything feels wrong. It is always safe to press, and it never asks you to confirm.",
    worst: "Switches you turned on go back to off. It never deletes Sletchy's record, its stored data or its keys. Run as a normal user, it keeps Sletchy's firewall rules and says how many. They only stop Sletchy's own sandboxes reaching other computers, so keeping them is safe.",
    guards: [
      py("adversarial/test_panic_reverts.py", "test_unelevated_panic_with_rules_kept_is_clean_and_says_why"),
      py("adversarial/test_panic.py", "test_panic_does_not_delete_the_ledger"),
      py("adversarial/test_panic.py", "test_panic_does_not_delete_payloads"),
      py("adversarial/test_panic.py", "test_panic_only_clears_the_runtime_directory"),
      py("adversarial/test_panic_reverts.py", "test_a_count_that_cannot_be_taken_is_an_error_never_a_zero"),
      py("adversarial/test_panic_reverts.py", "test_a_failed_revert_survives_panic_and_the_next_panic_retries"),
      py("unit/test_bridge.py", "test_panic_run_takes_no_confirmation"),
      ui("components/components.test.tsx", "a click is not a hold"),
    ],
  },
  activity: {
    title: "Recent activity",
    what: "The last few things in Sletchy's record, in plain words.",
    why: "To see what changed, and who changed it.",
    worst: "Nothing - it only reads, and only after the whole record has been verified.",
    guards: [
      py("unit/test_ledger_view.py", "test_reading_writes_nothing"),
      ui("lib/lib.test.ts", "names the switch by its label and says who"),
    ],
  },
  modes: {
    title: "Simple, Custom, Raw",
    what: "Three levels of detail on the same Sletchy. Nothing about Sletchy changes when you switch.",
    why: "Simple for everyday use, Custom to see every detail, Raw to see the JSON itself.",
    worst: "Nothing. The choice is remembered on this computer only.",
    guards: [
      ui("App.test.tsx", "switches modes and remembers the choice"),
      ui("lib/lib.test.ts", "ignores a tampered value"),
    ],
  },
  ledger: {
    title: "The ledger",
    what: "Sletchy's record: every flip, setup and stop, each entry signed and chained to the one before, so an edit anywhere is detected.",
    why: "To audit exactly what happened, and when.",
    worst: "Nothing - it only reads. If anything in the record was altered, nothing is shown and you are told.",
    guards: [
      py("unit/test_ledger_view.py", "test_cli_show_prints_nothing_from_a_corrupt_chain"),
      py("unit/test_ledger_view.py", "test_reading_writes_nothing"),
      py("adversarial/test_ledger_tamper.py", "test_mutating_a_field_breaks_the_signature"),
      py("adversarial/test_ledger_tamper.py", "test_deleting_a_middle_entry_breaks_the_chain"),
    ],
  },
  plan: {
    title: "Show what it would do",
    what: "A dry run of Stop everything: it counts what Stop everything would change, and changes nothing.",
    why: "To look before you press.",
    worst: "Nothing. It reads the firewall rule count and the journal; it removes and resets nothing.",
    guards: [
      py("unit/test_bridge.py", "test_panic_plan_changes_nothing_and_panic_run_resets"),
      py("adversarial/test_panic_reverts.py", "test_a_dry_run_counts_but_never_removes"),
    ],
  },
  console: {
    title: "Console",
    what: "Send any request this window is allowed to make, written as JSON, and see the raw answer.",
    why: "For developers and researchers: learning the protocol, testing the refusals.",
    worst: "Exactly what the other buttons can do, no more. A request passes the same two allowlists and the same checks; a dangerous switch still needs a reason and its name.",
    guards: [
      rs("bridge.rs", "a_method_off_the_allowlist_never_reaches_the_kernel"),
      py("adversarial/test_bridge_abuse.py", "test_only_allowlisted_methods_exist"),
      py("adversarial/test_bridge_abuse.py", "test_malformed_requests_are_refused_not_crashed"),
      ui("App.test.tsx", "Raw goes through the same rules: a dangerous switch without proofs is refused"),
    ],
  },
  bridge: {
    title: "Bridge",
    what: "The Kernel process this window started: its program, process id, and the Job Object limits it runs inside.",
    why: "To see that the Kernel is running, contained, and nothing else is.",
    worst: "Nothing - it only reads.",
    guards: [
      rs("job.rs", "a_confined_process_runs_and_is_in_its_job"),
      rs("job.rs", "closing_the_job_kills_what_is_inside_it"),
      rs("job.rs", "an_unconfined_process_is_not_in_the_job"),
    ],
  },
  transcript: {
    title: "Transcript",
    what: "Every request this window made and every answer, newest first.",
    why: "To see exactly what the window asked Sletchy and what it said.",
    worst: "Nothing. It lives in this window's memory only and is gone when the window closes.",
    guards: [ui("App.test.tsx", "Raw goes through the same rules: a dangerous switch without proofs is refused")],
  },
  orrery: {
    title: "Inside the vault",
    what: "Sletchy's architecture, live. The Kernel and its record at the core; the Warden and SOC in the middle ring; the Mind, Senses, Forge and Vault outside; one door in the outer wall. Each switch is a lamp on its ring, each Kernel process orbits the core, and each new record entry flies into the core.",
    why: "To see at a glance what is running, what is switched on, and that everything goes through the one door.",
    worst: "Nothing - it only draws what the other checks report.",
    guards: [
      rs("procs.rs", "roles"),
      ui("components/components.test.tsx", "the orrery puts every switch on a ring and every kernel process at the core"),
    ],
  },
  noc: {
    title: "Everything Sletchy is running",
    what: "Every process Sletchy started - the window, its renderers, the Kernel - with memory, CPU and threads, and the Kernel's Job Object against its ceilings.",
    why: "To see exactly what is running on this computer because of Sletchy, with nothing hidden.",
    worst: "Nothing - it reads Windows' process table and reports only Sletchy's own processes.",
    guards: [
      rs("procs.rs", "descendants_walks_the_tree_and_nothing_else"),
      rs("procs.rs", "the_test_process_finds_itself_and_its_confined_child"),
      rs("job.rs", "the_job_counts_what_ran_in_it"),
    ],
  },
  questions: {
    title: "Does it help you?",
    what: "Three questions every feature has to answer: does it save you time, make you money, or help you connect with people - with safety as the floor beneath them. In the original words, the third was \"does it help the user get laid?\"",
    why: "So every feature earns its place by helping a person, not by existing.",
    worst: "Nothing - it counts switches, and says plainly when nothing is connected yet.",
    guards: [
      py("unit/test_flag_honesty.py", "test_every_flag_says_which_human_question_it_serves"),
      py("unit/test_flag_honesty.py", "test_wired_matches_the_source"),
    ],
  },
  door: {
    title: "The vault door",
    what: "The opening. Each of its four locks is a real start-up check - the Kernel answering from inside its job, the record verifying, the self-check, the switches being read - and a lock seats only when its check passes. A lock that fails stays red, and the door opens anyway so you can see why.",
    why: "So the first thing you see is Sletchy proving itself, not a logo.",
    worst: "A few seconds of your time. Any key or click skips it, \"reduce motion\" in Windows skips it entirely, and nothing can hold it shut for more than six seconds.",
    guards: [
      ui("components/components.test.tsx", "the vault door cannot keep anyone outside: a check that never answers still opens it"),
      ui("components/components.test.tsx", "any key or a click skips the vault door, and it opens exactly once"),
      ui("components/components.test.tsx", "the door opens on its own once every lock has answered, even if one failed"),
    ],
  },
  sound: {
    title: "Sound on or off",
    what: "Mechanical clicks, ratchets and clunks when a lock seats or a switch moves. Made on the spot by the Web Audio engine: there are no sound files.",
    why: "Feedback you can hear: a click means something really happened.",
    worst: "A noise. Sound off makes Sletchy silent - it does not even start the audio engine - and the choice is remembered on this computer, inside Sletchy's own folder.",
    guards: [ui("lib/lib.test.ts", "sound off means silence: muted, nothing even starts the audio engine")],
  },
} as const satisfies Record<string, HelpEntry>;

export type HelpId = keyof typeof HELP;

const KEY = "sletchy.help";

export function loadHelp(): boolean {
  try {
    return window.localStorage.getItem(KEY) === "on";
  } catch {
    return false;
  }
}

export function saveHelp(on: boolean): void {
  try {
    window.localStorage.setItem(KEY, on ? "on" : "off");
  } catch {
    // not remembered; nothing depends on it
  }
}
