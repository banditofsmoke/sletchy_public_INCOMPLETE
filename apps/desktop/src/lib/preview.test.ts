import { beforeEach, expect, it } from "vitest";

import { previewTransport, resetPreview } from "./preview";

// The preview exists only for working on the window in a browser, but it must follow
// the bridge's rules for the flows it lets you exercise, or it would teach the wrong
// thing about how the real one behaves.

beforeEach(() => resetPreview());

type Answer = Record<string, any>;
const ask = (method: string, params: object = {}) => previewTransport(method, params) as Promise<Answer>;

it("refuses a dangerous switch without its name, then without a reason", async () => {
  expect((await ask("flags.set", { name: "senses_camera", enabled: true })).error.code).toBe("confirmation_required");
  expect((await ask("flags.set", { name: "senses_camera", enabled: true, confirm: "senses_camera" })).error.code).toBe(
    "reason_required",
  );
  const on = await ask("flags.set", { name: "senses_camera", enabled: true, confirm: "senses_camera", reason: "call" });
  expect(on.result.enabled).toBe(true);
});

it("never obstructs turning something off", async () => {
  await ask("flags.set", { name: "senses_camera", enabled: true, confirm: "senses_camera", reason: "r" });
  expect((await ask("flags.set", { name: "senses_camera", enabled: false })).result.enabled).toBe(false);
});

it("refuses an unknown method like the bridge does", async () => {
  expect((await ask("evil.exec")).error.code).toBe("method_not_allowed");
});

it("cannot reach 100 while the network check is unmeasured", async () => {
  const sc = (await ask("selfcheck")).result;
  expect(sc.ceiling).toBe(85);
  expect(sc.score).toBeLessThanOrEqual(sc.ceiling);
});

it("stop everything resets switches and is recorded", async () => {
  await ask("flags.set", { name: "senses_camera", enabled: true, confirm: "senses_camera", reason: "r" });
  const run = (await ask("stop.run")).result;
  expect(run.flags_reset).toBe(1);
  const flags = (await ask("flags.list")).result.flags as { enabled: boolean; default: boolean }[];
  expect(flags.every((f) => f.enabled === f.default)).toBe(true);
  const entries = (await ask("ledger.tail", { limit: 10 })).result.entries as { action: string }[];
  expect(entries.at(-1)?.action).toBe("kernel.flag.reset");
});

it("a model is asked only with Local AI models on, and the preview's answer says it is a sample", async () => {
  expect((await ask("model.ask", { model: "sample-small:1b", question: "Hi" })).error.code).toBe("switched_off");
  await ask("flags.set", { name: "mind_local_models", enabled: true, reason: "a question" });
  const listed = (await ask("models.list")).result;
  expect(listed.models.map((m: { fits: boolean }) => m.fits)).toEqual([true, true, false]);
  expect(listed.models.map((m: { can_chat: boolean }) => m.can_chat)).toEqual([false, true, true]);
  const { ticket } = (await ask("model.ask", { model: "sample-small:1b", question: "Hi" })).result;
  const state = (await ask("model.answer", { ticket })).result;
  expect(state.state).toBe("answered");
  expect(state.answer.text).toContain("No model was asked");
  expect(state.answer.turn).toBe(1);

  // As the Kernel does: the same model carries the conversation on, and fresh starts again.
  const again = (await ask("model.ask", { model: "sample-small:1b", question: "Again" })).result;
  expect((await ask("model.answer", { ticket: again.ticket })).result.answer.turn).toBe(2);
  const anew = (await ask("model.ask", { model: "sample-small:1b", question: "New", fresh: true })).result;
  expect((await ask("model.answer", { ticket: anew.ticket })).result.answer.turn).toBe(1);
});

it("a model is loaded on a ticket, listed as loaded, and unloaded (#202)", async () => {
  await ask("flags.set", { name: "mind_local_models", enabled: true, reason: "a question" });
  const { ticket } = (await ask("model.load", { model: "sample-small:1b", context: 16384 })).result;
  const done = (await ask("model.answer", { ticket })).result;
  expect(done.state).toBe("loaded");
  expect(done.loaded.running.context_tokens).toBe(16384);
  expect((await ask("models.list")).result.running.map((r: { model: string }) => r.model)).toEqual(["sample-small:1b"]);
  expect((await ask("model.load", { model: "sample-big:30b" })).error.code).toBe("model_refused");
  const embed = await ask("model.load", { model: "sample-embed:latest" });
  expect(embed.error.message).toMatch(/an embedding model/);
  const listed = (await ask("models.list")).result.models;
  expect(listed.find((m: { name: string }) => m.name === "sample-embed:latest").can_chat).toBe(false);

  // A question then carries the context it was loaded with.
  const asked = (await ask("model.ask", { model: "sample-small:1b", question: "Hi", context: 16384 })).result;
  expect((await ask("model.answer", { ticket: asked.ticket })).result.answer.context_tokens).toBe(16384);

  await ask("model.unload", { model: "sample-small:1b" });
  expect((await ask("models.list")).result.running).toEqual([]);
});

it("before setup, switches are refused and status says so", async () => {
  resetPreview(false);
  expect((await ask("status")).result.ledger_state).toBe("not_initialised");
  expect((await ask("flags.list")).error.code).toBe("not_initialised");
});
