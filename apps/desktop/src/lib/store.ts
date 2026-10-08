// A tiny observable store: the request transcript (Raw mode) and the toasts.
// No library - React's useSyncExternalStore is all it needs.

import { useSyncExternalStore } from "react";

export interface TranscriptEntry {
  readonly id: number;
  readonly at: number;
  readonly method: string;
  readonly params: unknown;
  readonly answer: unknown;
  readonly ms: number;
  readonly ok: boolean;
}

export type ToastTone = "good" | "warn" | "bad" | "info";

export interface Toast {
  readonly id: number;
  readonly tone: ToastTone;
  readonly title: string;
  readonly body?: string;
}

const TRANSCRIPT_KEEP = 200;

let transcript: readonly TranscriptEntry[] = [];
let toasts: readonly Toast[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function record(entry: Omit<TranscriptEntry, "id">): void {
  transcript = [{ ...entry, id: nextId++ }, ...transcript].slice(0, TRANSCRIPT_KEEP);
  emit();
}

export function clearTranscript(): void {
  transcript = [];
  emit();
}

export function toast(tone: ToastTone, title: string, body?: string): number {
  const id = nextId++;
  toasts = [...toasts, body === undefined ? { id, tone, title } : { id, tone, title, body }].slice(-5);
  emit();
  const ttl = tone === "bad" ? 9000 : 5000;
  setTimeout(() => dismiss(id), ttl);
  return id;
}

export function dismiss(id: number): void {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

export function useTranscript(): readonly TranscriptEntry[] {
  return useSyncExternalStore(subscribe, () => transcript);
}

export function useToasts(): readonly Toast[] {
  return useSyncExternalStore(subscribe, () => toasts);
}

/** For tests only. */
export function resetStore(): void {
  transcript = [];
  toasts = [];
  emit();
}
