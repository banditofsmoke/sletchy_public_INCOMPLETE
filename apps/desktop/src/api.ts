// The window's only way to reach Sletchy.
//
// Inside the app, every call is one Tauri command, `bridge_call`, which the Rust
// shell checks against the generated allowlist before writing it to the Kernel's
// stdin (ADR-0008). In a plain browser there is no Kernel, so calls go to the
// labelled preview in `lib/preview.ts` instead - never to anything real.

import { invoke } from "@tauri-apps/api/core";

import type { ErrorCode, MethodName, Methods } from "./generated/contracts";
import { ERROR_CODES } from "./generated/contracts";
import { previewBridgeInfo, previewTransport } from "./lib/preview";
import { record } from "./lib/store";

/** Codes the shell itself can answer with, on top of the Kernel's own. */
export const SHELL_ERROR_CODES = [
  "bridge_unavailable",
  "bridge_timeout",
  "protocol_mismatch",
  "shell_error",
] as const;

export type AnyErrorCode = ErrorCode | (typeof SHELL_ERROR_CODES)[number];

export const ALL_ERROR_CODES: readonly AnyErrorCode[] = [...ERROR_CODES, ...SHELL_ERROR_CODES];

export type Outcome<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code: AnyErrorCode; readonly message: string };

export type Transport = (method: string, params: object) => Promise<unknown>;

export function inApp(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

const appTransport: Transport = (method, params) => invoke("bridge_call", { method, params });

let transport: Transport = inApp() ? appTransport : previewTransport;

/** Tests swap the transport; nothing else should. */
export function setTransport(next: Transport): void {
  transport = next;
}

function isCode(value: unknown): value is AnyErrorCode {
  return typeof value === "string" && (ALL_ERROR_CODES as readonly string[]).includes(value);
}

/** Read an answer defensively: anything not shaped like one is a shell error. */
export function toOutcome<T>(answer: unknown): Outcome<T> {
  if (typeof answer === "object" && answer !== null) {
    const a = answer as Record<string, unknown>;
    if (a.ok === true && "result" in a) {
      return { ok: true, value: a.result as T };
    }
    const err = a.error as Record<string, unknown> | undefined;
    if (a.ok === false && err && isCode(err.code)) {
      return { ok: false, code: err.code, message: String(err.message ?? "") };
    }
  }
  return { ok: false, code: "shell_error", message: "Sletchy sent an answer this window does not recognise." };
}

export async function call<M extends MethodName>(
  method: M,
  params: Methods[M]["params"],
): Promise<Outcome<Methods[M]["result"]>> {
  const started = performance.now();
  let answer: unknown;
  try {
    answer = await transport(method, params as object);
  } catch (err) {
    answer = { ok: false, error: { code: "shell_error", message: String(err) } };
  }
  const outcome = toOutcome<Methods[M]["result"]>(answer);
  record({
    at: Date.now(),
    method,
    params,
    answer,
    ms: Math.round(performance.now() - started),
    ok: outcome.ok,
  });
  return outcome;
}

export async function bridgeInfo(): Promise<Record<string, unknown>> {
  if (!inApp()) return previewBridgeInfo();
  try {
    return (await invoke("bridge_info")) as Record<string, unknown>;
  } catch (err) {
    return { error: String(err) };
  }
}
