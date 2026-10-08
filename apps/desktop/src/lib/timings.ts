// How long a load or an answer took last time, so the next wait can show a bar against
// it (#207). The model server says nothing until a load or an answer is done, so this is
// the only measure there is. Kept in the window's own storage as a convenience: lost or
// unavailable, there is only no estimate.

const KEY = "sletchy.talk.timings";

export type Wait = "load" | "answer";

type Timings = Record<Wait, Record<string, number>>;

/** A load is timed per model and context; an answer per model. */
export const waitKey = (wait: Wait, model: string, context: number): string =>
  wait === "load" ? `${model}|${context}` : model;

function read(): Timings {
  const empty: Timings = { load: {}, answer: {} };
  try {
    const saved: unknown = JSON.parse(window.localStorage.getItem(KEY) ?? "null");
    if (!saved || typeof saved !== "object") return empty;
    for (const wait of ["load", "answer"] as const) {
      const held: unknown = (saved as Record<string, unknown>)[wait];
      if (!held || typeof held !== "object") continue;
      for (const [key, seconds] of Object.entries(held)) {
        if (typeof seconds === "number" && Number.isFinite(seconds) && seconds > 0) empty[wait][key] = seconds;
      }
    }
  } catch {
    // unreadable or unavailable: no estimate
  }
  return empty;
}

/** How long this took last time, in seconds, or null if it has not been timed. */
export function lastTime(wait: Wait, key: string): number | null {
  return read()[wait][key] ?? null;
}

export function remember(wait: Wait, key: string, seconds: number): void {
  if (!Number.isFinite(seconds) || seconds <= 0) return;
  const held = read();
  held[wait][key] = seconds;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(held));
  } catch {
    // not remembered this time; nothing else depends on it
  }
}
