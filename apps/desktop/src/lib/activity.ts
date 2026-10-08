// Ledger entries, as sentences. Simple mode shows these; Custom shows the raw rows.

import type { EntryView, FlagView } from "../generated/contracts";

function who(actor: string): string {
  if (actor === "operator-desktop") return "You";
  if (actor === "operator") return "You (in the terminal)";
  return `"${actor}"`;
}

const FLIP = /^([a-z][a-z0-9_-]*) -> (on|off)(?::|$)/;

export function describe(entry: EntryView, flags: readonly FlagView[] = []): string {
  const label = (name: string) => flags.find((f) => f.name === name)?.label ?? name;

  if (entry.action === "kernel.flag.flip") {
    const m = FLIP.exec(entry.reason);
    if (m && m[1] && m[2]) return `${who(entry.actor)} turned ${m[2]} ${label(m[1])}`;
  }
  if (entry.action === "kernel.flag.reset") return "Stop everything turned every switch off";
  if (entry.action.startsWith("kernel.ledger.seal")) return "Sletchy closed a page of its record";
  if (entry.action === "warden.sandbox.launch") return "Sletchy started a program inside its sandbox";
  if (entry.action === "warden.sandbox.complete") return "A sandboxed program finished";
  if (entry.action === "warden.sandbox.kill") return "Sletchy stopped a sandboxed program";
  if (entry.action === "warden.sandbox.refuse") return "Sletchy refused to start a program";
  return `Sletchy recorded "${entry.action}"`;
}
