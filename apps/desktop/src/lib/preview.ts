// A pretend Kernel, for working on the window in a plain browser.
//
// It exists only when there is no Tauri runtime, it is labelled on screen as sample
// data, and it can reach nothing: no files, no ledger, no network. Its few switches
// are samples, not the real registry (the real list always comes from the Kernel).
// It follows the bridge's rules for the flows the window needs to exercise - a
// dangerous switch needs a reason and its exact name - so the screens behave the
// same way in preview as they do for real.

import type {
  EntryView,
  FlagView,
  FlagsSetParams,
  LedgerPayloadParams,
  LedgerTailParams,
  PanicResult,
  SelfCheck,
  StatusResult,
} from "../generated/contracts";
import { PROTOCOL_VERSION } from "../generated/contracts";

type Mutable<T> = { -readonly [K in keyof T]: T[K] };
type SampleFlag = Mutable<FlagView>;

const SAMPLE_FLAGS: SampleFlag[] = [
  { name: "egress_enabled", label: "Internet access", description: "Allow any outbound network connection through the Warden proxy.", risk: "dangerous", default: false, enabled: false, wired: false, serves: ["time", "connection"] },
  { name: "fs_outside_var", label: "Your files", description: "Allow reads or writes outside var/. Off means Sletchy cannot touch your files.", risk: "dangerous", default: false, enabled: false, wired: false, serves: ["time"] },
  { name: "senses_microphone", label: "Microphone", description: "Allow microphone capture. Emits a ledger event whenever active.", risk: "dangerous", default: false, enabled: false, wired: false, serves: ["time", "connection"] },
  { name: "senses_camera", label: "Camera", description: "Allow camera capture. Emits a ledger event whenever active.", risk: "dangerous", default: false, enabled: false, wired: false, serves: ["connection"] },
  { name: "mind_local_models", label: "Local AI models", description: "Let Sletchy ask a model server on this computer (Ollama today), through one local port. Every question and answer is recorded. Nothing leaves the machine.", risk: "elevated", default: false, enabled: false, wired: true, serves: ["time"] },
  { name: "cli_verbose", label: "Explain every decision", description: "Print policy reasoning alongside every decision.", risk: "safe", default: false, enabled: false, wired: false, serves: ["safety"] },
];

interface PreviewState {
  initialised: boolean;
  flags: SampleFlag[];
  ledger: EntryView[];
  lastQuestion?: { ticket: number; model: string; conversation: string; turn: number; context: number };
  /** A load in progress or done, and what is loaded (#202). */
  lastLoad?: { ticket: number; model: string; context: number };
  loaded?: { model: string; context: number };
}

let state: PreviewState = fresh();

function fresh(): PreviewState {
  return { initialised: true, flags: SAMPLE_FLAGS.map((f) => ({ ...f })), ledger: [] };
}

/** For tests. */
export function resetPreview(initialised = true): void {
  state = fresh();
  state.initialised = initialised;
}

function now(): string {
  return new Date().toISOString().slice(0, 19) + "+00:00";
}

function log(action: string, subject: string, decision: string, reason: string): void {
  state.ledger.push({
    seq: state.ledger.length,
    ts: now(),
    plane: "kernel",
    actor: "operator-desktop",
    action,
    subject,
    decision,
    reason,
    has_payload: false,
  });
}

const ok = (result: unknown) => ({ ok: true, result });
const no = (code: string, message: string) => ({ ok: false, error: { code, message } });

function status(): StatusResult {
  const dangerous = state.flags.filter((f) => f.risk === "dangerous" && f.enabled).map((f) => f.name);
  return {
    protocol: PROTOCOL_VERSION,
    version: "preview",
    home: "(preview - no files)",
    ledger_state: state.initialised ? "ok" : "not_initialised",
    entries: state.initialised ? state.ledger.length : null,
    detail: "preview data",
    flags_on: state.flags.filter((f) => f.enabled).length,
    dangerous_on: dangerous,
  };
}

function selfcheck(): SelfCheck {
  const dangerous = state.flags.filter((f) => f.risk === "dangerous" && f.enabled);
  const checks: SelfCheck["checks"] = [
    state.initialised
      ? { id: "ledger", label: "Sletchy's record", status: "pass", weight: 30, plain: "Sletchy's record of everything it has done is intact.", detail: `${state.ledger.length} entries (preview)` }
      : { id: "ledger", label: "Sletchy's record", status: "fail", weight: 30, plain: "Sletchy has not been set up on this computer yet.", detail: "preview" },
    dangerous.length
      ? { id: "switches", label: "Dangerous switches", status: "warn", weight: 15, plain: `You turned on ${dangerous.length} dangerous switch${dangerous.length > 1 ? "es" : ""}: ${dangerous.map((f) => f.label).join(", ")}.`, detail: "preview" }
      : { id: "switches", label: "Dangerous switches", status: "pass", weight: 15, plain: "Every dangerous switch is off.", detail: "preview" },
    { id: "privilege", label: "Runs as a normal user", status: "pass", weight: 15, plain: "Sletchy is running as a normal user, with no extra power over this computer.", detail: "preview" },
    { id: "files", label: "Keeps programs out of your files", status: "pass", weight: 15, plain: "Programs Sletchy runs cannot reach your files. This was measured on this version of Windows.", detail: "preview" },
    { id: "network", label: "Keeps programs off the internet", status: "unmeasured", weight: 15, plain: "Sletchy's firewall rules are in place, and keep the programs it runs off other computers over TCP and UDP. IPv6 is not measured yet, and they can still reach this computer's own services.", detail: "preview" },
    { id: "leftovers", label: "Nothing left behind", status: "pass", weight: 5, plain: "Sletchy has no unfinished changes on this computer.", detail: "preview" },
    { id: "disk", label: "Stays inside its disk space", status: "pass", weight: 5, plain: "Sletchy is well inside the disk space it is allowed.", detail: "preview" },
  ];
  const earns = { pass: 1, warn: 0.5, fail: 0, unmeasured: 0 } as const;
  return {
    checked_at: new Date().toISOString(),
    score: Math.round(checks.reduce((sum, c) => sum + c.weight * earns[c.status], 0)),
    ceiling: checks.filter((c) => c.status !== "unmeasured").reduce((sum, c) => sum + c.weight, 0),
    checks,
    does_not_prove: [
      "It runs on this computer, as you. Something that already controls your Windows account could fake every check on this page.",
      "It checks Sletchy, not the rest of your computer. It is not an antivirus.",
      "A check that passes now says nothing about a minute from now. Open it again to check again.",
    ],
  };
}

function setFlag(p: FlagsSetParams) {
  if (!state.initialised) return no("not_initialised", "Sletchy has not been set up yet");
  const flag = state.flags.find((f) => f.name === p.name);
  if (!flag) return no("unknown_flag", `unknown flag ${p.name}`);
  if (p.enabled && flag.risk === "dangerous") {
    if ((p.confirm ?? "") !== flag.name) return no("confirmation_required", `turning on '${flag.name}' needs its name typed back exactly`);
    if (!(p.reason ?? "").trim()) return no("reason_required", `turning on '${flag.name}' requires a reason`);
  }
  flag.enabled = p.enabled;
  log("kernel.flag.flip", `flag:${flag.name}`, p.enabled ? "allow" : "deny", `${flag.name} -> ${p.enabled ? "on" : "off"}: ${(p.reason ?? "").trim() || (p.enabled ? "enabled" : "disabled")}`);
  return ok({ ...flag });
}

function panic(dryRun: boolean): PanicResult {
  const on = state.flags.filter((f) => f.enabled !== f.default).length;
  if (!dryRun) {
    state.flags.forEach((f) => (f.enabled = f.default));
    log("kernel.flag.reset", "flag:all", "deny", `all flags reset to defaults (${on} changed): operator pressed Stop everything`);
  }
  return {
    dry_run: dryRun,
    clean: true,
    flags_reset: dryRun ? 0 : on,
    firewall_rules_removed: 0,
    firewall_rules_kept: 0,
    processes_terminated: 0,
    sandbox_changes_reverted: 0,
    runtime_files_cleared: 0,
    ledger_sealed: !dryRun,
    errors: [],
  };
}

export async function previewTransport(method: string, params: object): Promise<unknown> {
  await new Promise((r) => setTimeout(r, 120)); // feel like a real round trip
  switch (method) {
    case "status":
      return ok(status());
    case "selfcheck":
      return ok(selfcheck());
    case "flags.list":
      return state.initialised ? ok({ flags: state.flags.map((f) => ({ ...f })) }) : no("not_initialised", "Sletchy has not been set up yet");
    case "flags.set":
      return setFlag(params as FlagsSetParams);
    case "ledger.tail": {
      const p = params as LedgerTailParams;
      let entries = state.ledger.slice();
      if (p.denied_only) entries = entries.filter((e) => e.decision === "deny");
      if (p.action_prefix) entries = entries.filter((e) => e.action === p.action_prefix || e.action.startsWith(`${p.action_prefix}.`));
      return ok({ verified: state.ledger.length, entries: entries.slice(-(p.limit ?? 50)) });
    }
    case "ledger.payload": {
      // The preview stores no bodies: it answers as the bridge does for an entry without one.
      const p = params as LedgerPayloadParams;
      const entry = state.ledger.find((e) => e.seq === p.seq);
      if (!entry) return no("no_such_entry", `no entry with sequence number ${p.seq}`);
      return ok({ entry, payload: { seq: p.seq, state: "none", body: "", size: 0, truncated: false, masked: [] } });
    }
    case "models.list":
      if (!state.flags.find((f) => f.name === "mind_local_models")?.enabled) return no("switched_off", "Local AI models are switched off");
      return ok({
        card_bytes: 8151 * 1024 ** 2,
        budget_bytes: Math.floor(8151 * 1024 ** 2 * 0.7),
        share: 0.7,
        context_tokens: 4096,
        max_question_chars: 32000,
        // Smallest first, as the Kernel sorts them: an embedding model is often the
        // smallest, and is listed and never offered to talk to (#204).
        models: [
          { name: "sample-embed:latest", size_bytes: 274_000_000, fits: true, can_chat: false },
          { name: "sample-small:1b", size_bytes: 815_000_000, fits: true, can_chat: true },
          { name: "sample-big:30b", size_bytes: 18_000_000_000, fits: false, can_chat: true },
        ],
        context_choices: [4096, 8192, 16384, 32768],
        running: state.loaded
          ? [
              {
                model: state.loaded.model,
                size_bytes: 815_000_000,
                vram_bytes: 815_000_000,
                context_tokens: state.loaded.context,
                expires_at: "(preview)",
              },
            ]
          : [],
      });
    case "model.load": {
      if (!state.flags.find((f) => f.name === "mind_local_models")?.enabled) return no("switched_off", "Local AI models are switched off");
      const asked = params as { model: string; context?: number };
      if (asked.model === "sample-embed:latest")
        return no(
          "model_refused",
          "an embedding model: it turns text into numbers for memory search, and cannot hold a conversation",
        );
      if (asked.model !== "sample-small:1b") return no("model_refused", "the model is over the card budget");
      const ticket = Math.max(state.lastQuestion?.ticket ?? 0, state.lastLoad?.ticket ?? 0) + 1;
      state.lastLoad = { ticket, model: asked.model, context: asked.context ?? 4096 };
      return ok({ ticket });
    }
    case "model.unload":
      state.loaded = undefined;
      return ok({ model: (params as { model: string }).model, unload_seq: 0 });
    case "model.ask": {
      if (!state.flags.find((f) => f.name === "mind_local_models")?.enabled) return no("switched_off", "Local AI models are switched off");
      const asked = params as { model: string; fresh?: boolean; context?: number };
      const previous = state.lastQuestion;
      const context = asked.context ?? 4096;
      // As the Kernel does: the same model and context, not fresh, carries the conversation on.
      const carried =
        previous && !asked.fresh && previous.model === asked.model && previous.context === context ? previous : undefined;
      const ticket = Math.max(previous?.ticket ?? 0, state.lastLoad?.ticket ?? 0) + 1;
      state.lastQuestion = {
        ticket,
        model: asked.model,
        conversation: carried ? carried.conversation : `c-preview${ticket}`,
        turn: carried ? carried.turn + 1 : 1,
        context,
      };
      return ok({ ticket });
    }
    case "model.answer": {
      const ticket = (params as { ticket: number }).ticket;
      const loading = state.lastLoad;
      if (loading && loading.ticket === ticket) {
        state.loaded = { model: loading.model, context: loading.context };
        return ok({
          ticket,
          state: "loaded",
          seconds: 0.1,
          loaded: {
            running: {
              model: loading.model,
              size_bytes: 815_000_000,
              vram_bytes: 815_000_000,
              context_tokens: loading.context,
              expires_at: "(preview)",
            },
            seconds: 0.1,
            load_seconds: 0.1,
            load_seq: 0,
            loaded_seq: 0,
          },
        });
      }
      const asked = state.lastQuestion;
      if (!asked || asked.ticket !== ticket) return no("no_such_question", "no question has that ticket");
      return ok({
        ticket: asked.ticket,
        state: "answered",
        seconds: 0.1,
        answer: {
          model: asked.model,
          text: "(preview: a sample answer. No model was asked, and nothing left this browser.)",
          cut: false,
          seconds: 0.1,
          prompt_tokens: 12,
          answer_tokens: 18,
          context_tokens: asked.context,
          out_of_room: false,
          asked_seq: 0,
          answered_seq: 0,
          conversation: asked.conversation,
          turn: asked.turn,
          earlier_turns: asked.turn - 1,
          left_out: 0,
        },
      });
    }
    case "stop.plan":
      return ok(panic(true));
    case "stop.run":
      return ok(panic(false));
    case "init":
      state.initialised = true;
      return ok({ home: "(preview)", provisioned: true, detail: "preview: nothing was created" });
    default:
      return no("method_not_allowed", `no such method: '${method}'`);
  }
}

let cpu = 0;

/** Sample process data, so the NOC and the Orrery have something to draw in a browser. */
export function previewBridgeInfo(): Record<string, unknown> {
  cpu += 40 + Math.round(Math.random() * 60);
  const mk = (pid: number, ppid: number, name: string, role: string, mb: number, threads: number, inJob: boolean) => ({
    pid,
    ppid,
    name,
    threads,
    cpu_ms: Math.round(cpu * (role === "kernel" ? 0.6 : 0.3)),
    memory_bytes: (mb + Math.random() * 4) * 1024 ** 2,
    private_bytes: mb * 1024 ** 2,
    in_job: inJob,
    role,
  });
  return {
    preview: true,
    note: "Sample data: this window is in a browser and no kernel is running.",
    program: "(preview)",
    running: true,
    pid: 4102,
    confined: true,
    limits: { memory_bytes: 2 * 1024 ** 3, active_processes: 8, kill_on_close: true },
    job: { active_processes: 4, total_processes: 4, cpu_ms: Math.round(cpu * 0.6), peak_memory_bytes: 96 * 1024 ** 2 },
    processes: [
      mk(4000, 1, "sletchy-desktop.exe", "window", 28, 15, false),
      mk(4010, 4000, "msedgewebview2.exe", "webview", 64, 53, false),
      mk(4011, 4010, "msedgewebview2.exe", "webview", 41, 21, false),
      mk(4102, 4000, "sletchy.exe", "kernel", 4, 1, true),
      mk(4103, 4102, "conhost.exe", "kernel", 6, 3, true),
      mk(4104, 4102, "python.exe", "kernel", 5, 2, true),
      mk(4105, 4104, "python.exe", "kernel", 38, 4, true),
    ],
  };
}
