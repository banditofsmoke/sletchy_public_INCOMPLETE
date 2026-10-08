// Every refusal, in words a person can act on.
//
// `satisfies Record<AnyErrorCode, string>` makes this exhaustive at compile time: a
// new error code in the Kernel regenerates contracts.ts, and this file then fails to
// type-check until the new code has a sentence. A test checks the same at runtime.

import type { AnyErrorCode } from "../api";

export const PLAIN_ERRORS = {
  bad_request: "Sletchy didn't understand that request.",
  too_large: "That request was too big for Sletchy to accept.",
  method_not_allowed: "That isn't something this window is allowed to ask for.",
  invalid_params: "Some details in that request weren't right, so nothing was changed.",
  not_initialised: "Sletchy isn't set up on this computer yet.",
  ledger_corrupt:
    "Sletchy's record was changed by something other than Sletchy. It has stopped until someone looks at it.",
  no_such_entry: "Sletchy's record has no entry with that number.",
  unknown_flag: "Sletchy doesn't have a switch by that name.",
  reason_required: "Please say why you're turning this on.",
  confirmation_required: "Please type the switch's name exactly, to confirm.",
  switched_off: "Local AI models is switched off. Turn it on in Switches to ask a model.",
  no_model_server: "No model server is answering on this computer. Sletchy never starts one: start Ollama yourself, then ask again.",
  model_refused: "Sletchy did not ask that model.",
  model_unreadable: "The model server answered with something Sletchy could not read.",
  model_busy: "A model is already answering a question. Ask again when it has finished.",
  no_such_question: "Sletchy no longer has that question. Ask it again.",
  internal_error: "Something went wrong inside Sletchy.",
  bridge_unavailable: "This window can't reach Sletchy right now.",
  bridge_timeout: "Sletchy took too long to answer, so it was restarted.",
  protocol_mismatch: "This window and Sletchy are different versions. One of them needs updating.",
  shell_error: "This window had a problem talking to Sletchy.",
} as const satisfies Record<AnyErrorCode, string>;

export function plainError(code: AnyErrorCode): string {
  return PLAIN_ERRORS[code];
}
