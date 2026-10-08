// The three ways to see Sletchy. Remembered per computer; a convenience, not state.

export const MODES = ["simple", "custom", "raw"] as const;
export type Mode = (typeof MODES)[number];

export const MODE_LABELS: Record<Mode, { name: string; hint: string }> = {
  simple: { name: "Simple", hint: "Big switches and plain words" },
  custom: { name: "Custom", hint: "Every switch, the record, the details" },
  raw: { name: "Raw", hint: "The JSON, for developers" },
};

const KEY = "sletchy.mode";

export function loadMode(): Mode {
  try {
    const saved = window.localStorage.getItem(KEY);
    if (saved && (MODES as readonly string[]).includes(saved)) return saved as Mode;
  } catch {
    // storage can be unavailable; the default is fine
  }
  return "simple";
}

export function saveMode(mode: Mode): void {
  try {
    window.localStorage.setItem(KEY, mode);
  } catch {
    // not remembered this time; nothing else depends on it
  }
}
