import { describe as group, expect, it } from "vitest";

import { ALL_ERROR_CODES, toOutcome } from "../api";
import type { EntryView, FlagView } from "../generated/contracts";
import { ERROR_CODES } from "../generated/contracts";
import { describe } from "./activity";
import { angleFor, arcPath, band, clamp, headline, START_DEG, SWEEP_DEG } from "./meter";
import { loadMode, saveMode } from "./modes";
import { PLAIN_ERRORS, plainError } from "./plain";
import { relative } from "./time";

group("plain errors", () => {
  it("has a sentence for every code the Kernel and the shell can send", () => {
    for (const code of ALL_ERROR_CODES) expect(plainError(code)).toMatch(/\w{3}/);
    expect(Object.keys(PLAIN_ERRORS).sort()).toEqual([...ALL_ERROR_CODES].sort());
  });

  it("covers every code in the generated contract", () => {
    for (const code of ERROR_CODES) expect(ALL_ERROR_CODES).toContain(code);
  });

  it("never shows a code name to a person", () => {
    for (const sentence of Object.values(PLAIN_ERRORS)) expect(sentence).not.toMatch(/_/);
  });
});

group("meter geometry", () => {
  it("clamps anything out of range, including NaN", () => {
    expect([clamp(-5), clamp(150), clamp(Number.NaN)]).toEqual([0, 100, 0]);
  });

  it("maps 0 and 100 onto the ends of the sweep", () => {
    expect(angleFor(0)).toBe(START_DEG);
    expect(angleFor(100)).toBe(START_DEG + SWEEP_DEG);
  });

  it("draws nothing for zero, a small arc below halfway and a large one past it", () => {
    expect(arcPath(100, 100, 80, 0)).toBe("");
    expect(arcPath(100, 100, 80, 40)).toContain(" 0 0 1 ");
    expect(arcPath(100, 100, 80, 90)).toContain(" 0 1 1 ");
  });

  it("bands against 100, so an unbuilt control still shows", () => {
    expect([band(85), band(70), band(40)]).toEqual(["strong", "fair", "low"]);
  });

  it("puts a failure ahead of a good score", () => {
    expect(headline(85, 85, 1)).toMatch(/attention/);
    expect(headline(85, 85, 0)).toMatch(/fine/);
    expect(headline(60, 85, 0)).toMatch(/look at/);
  });
});

const entry = (over: Partial<EntryView>): EntryView => ({
  seq: 0,
  ts: "2026-10-02T22:00:00+00:00",
  plane: "kernel",
  actor: "operator-desktop",
  action: "kernel.flag.flip",
  subject: "flag:senses_camera",
  decision: "allow",
  reason: "senses_camera -> on: video call",
  has_payload: false,
  ...over,
});

const camera: FlagView = {
  name: "senses_camera",
  label: "Camera",
  description: "d",
  risk: "dangerous",
  default: false,
  enabled: true,
  wired: false,
  serves: ["connection"],
};

group("activity sentences", () => {
  it("names the switch by its label and says who", () => {
    expect(describe(entry({}), [camera])).toBe("You turned on Camera");
    expect(describe(entry({ actor: "operator", reason: "senses_camera -> off: disabled" }), [camera])).toBe(
      "You (in the terminal) turned off Camera",
    );
  });

  it("falls back to the name when the switch is unknown", () => {
    expect(describe(entry({}), [])).toBe("You turned on senses_camera");
  });

  it("explains a reset, and never invents meaning for an unknown action", () => {
    expect(describe(entry({ action: "kernel.flag.reset" }))).toMatch(/Stop everything/);
    expect(describe(entry({ action: "warden.egress.attempt" }))).toBe('Sletchy recorded "warden.egress.attempt"');
  });
});

group("relative time", () => {
  const now = Date.parse("2026-10-02T22:00:00Z");
  it("reads like a person", () => {
    expect(relative("2026-10-02T21:59:58Z", now)).toBe("just now");
    expect(relative("2026-10-02T21:58:00Z", now)).toBe("2 min ago");
    expect(relative("2026-10-02T19:00:00Z", now)).toBe("3 h ago");
    expect(relative("2026-10-01T21:00:00Z", now)).toBe("yesterday");
    expect(relative("not a date", now)).toBe("not a date");
  });
});

group("modes", () => {
  it("defaults to Simple and remembers a choice", () => {
    window.localStorage.clear();
    expect(loadMode()).toBe("simple");
    saveMode("raw");
    expect(loadMode()).toBe("raw");
  });

  it("ignores a tampered value", () => {
    window.localStorage.setItem("sletchy.mode", "admin");
    expect(loadMode()).toBe("simple");
  });
});

group("reading answers defensively", () => {
  it("accepts a success and a known refusal", () => {
    expect(toOutcome({ ok: true, result: 1 })).toEqual({ ok: true, value: 1 });
    expect(toOutcome({ ok: false, error: { code: "unknown_flag", message: "m" } })).toEqual({
      ok: false,
      code: "unknown_flag",
      message: "m",
    });
  });

  it("treats anything else as a shell error, never as success", () => {
    const odd: unknown[] = [
      null,
      "ok",
      3,
      [],
      { ok: "true", result: 1 },
      { ok: true },
      { ok: false, error: { code: "made_up" } },
    ];
    for (const answer of odd) {
      const out = toOutcome(answer);
      expect(out.ok).toBe(false);
      if (!out.ok) expect(out.code).toBe("shell_error");
    }
  });
});

it("sound off means silence: muted, nothing even starts the audio engine", async () => {
  const sound = await import("./sound");
  let engines = 0;
  const real = (globalThis as { AudioContext?: unknown }).AudioContext;
  (globalThis as { AudioContext?: unknown }).AudioContext = function Refuses() {
    engines += 1;
    throw new Error("an engine that refuses to start");
  };
  try {
    sound.setMuted(true);
    sound.click();
    sound.ratchet(6);
    sound.clunk();
    sound.hiss();
    sound.refuse();
    expect(engines).toBe(0);
    expect(window.localStorage.getItem("sletchy.sound")).toBe("off");
    // Positive control: unmuted, the same calls do try to start it (and survive a refusal).
    sound.setMuted(false);
    sound.click();
    expect(engines).toBeGreaterThan(0);
  } finally {
    sound.setMuted(false);
    (globalThis as { AudioContext?: unknown }).AudioContext = real;
  }
});
