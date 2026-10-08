// The model list in sections (#207). On my machine on 2026-10-08 it held 19 models in one
// list: the ones I can talk to, two embedding models, two names Ollama made itself, the
// same name twice, and three too big for the card.

import type { ModelView } from "../generated/contracts";

/**
 * A name Ollama gives its own copy of a model: `llamacpp:` and a 64-character digest. It
 * wrote two on 2026-10-08, each the moment a model was first loaded, beside a second
 * listing of the same model's name.
 */
const OLLAMA_COPY = /^llamacpp:[0-9a-f]{64}$/;

export interface ModelSection {
  readonly label: string;
  readonly models: readonly ModelView[];
  /** Whether a model in it may be picked to talk to. */
  readonly pickable: boolean;
}

/**
 * The models in sections, in the server's order within each, each name once: for talking
 * to, for memory search, Ollama's own names, too big for the card. Empty sections are
 * left out.
 */
export function sections(models: readonly ModelView[]): ModelSection[] {
  const seen = new Set<string>();
  const talk: ModelView[] = [];
  const memory: ModelView[] = [];
  const copies: ModelView[] = [];
  const big: ModelView[] = [];
  for (const m of models) {
    if (seen.has(m.name)) continue;
    seen.add(m.name);
    if (m.can_chat === false) memory.push(m);
    else if (!m.fits) big.push(m);
    else if (OLLAMA_COPY.test(m.name)) copies.push(m);
    else talk.push(m);
  }
  const all: ModelSection[] = [
    { label: "For talking to", models: talk, pickable: true },
    { label: "For memory search, not for talking to", models: memory, pickable: false },
    { label: "Ollama's own names for models above", models: copies, pickable: true },
    { label: "Too big to leave room for a conversation", models: big, pickable: false },
  ];
  return all.filter((s) => s.models.length > 0);
}

/** The names that may be picked, best first: the first is picked by default. */
export function offered(models: readonly ModelView[]): string[] {
  return sections(models)
    .filter((s) => s.pickable)
    .flatMap((s) => s.models.map((m) => m.name));
}
