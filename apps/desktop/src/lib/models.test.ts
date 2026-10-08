import { beforeEach, expect, it } from "vitest";

import type { ModelView } from "../generated/contracts";
import { offered, sections } from "./models";
import { lastTime, remember, waitKey } from "./timings";

// The model list in sections, and the times a wait is measured against (#207).

beforeEach(() => window.localStorage.clear());

const COPY = `llamacpp:${"83be9dbf".repeat(8)}`;

/** The shape of my own list on 2026-10-08, smallest first as the Kernel sorts it. */
const MINE: ModelView[] = [
  { name: "nomic-embed-text:latest", size_bytes: 274_000_000, fits: true, can_chat: false },
  { name: "gemma3:1b", size_bytes: 815_000_000, fits: true, can_chat: true },
  { name: COPY, size_bytes: 815_000_000, fits: true, can_chat: null },
  { name: "gemma3:1b", size_bytes: 815_100_000, fits: true, can_chat: true },
  { name: "ornith:9b", size_bytes: 5_626_000_000, fits: true },
  { name: "gemma4:12b", size_bytes: 7_560_000_000, fits: false, can_chat: true },
];

it("the list comes in sections, each name once, the empty ones left out", () => {
  const got = sections(MINE).map((s) => [s.label, s.models.map((m) => m.name), s.pickable]);

  expect(got).toEqual([
    ["For talking to", ["gemma3:1b", "ornith:9b"], true],
    ["For memory search, not for talking to", ["nomic-embed-text:latest"], false],
    ["Ollama's own names for models above", [COPY], true],
    ["Too big to leave room for a conversation", ["gemma4:12b"], false],
  ]);
  expect(sections(MINE.slice(1, 2)).map((s) => s.label)).toEqual(["For talking to"]);
});

it("the first model offered is one that can talk, never the smallest embedding model", () => {
  expect(offered(MINE)).toEqual(["gemma3:1b", "ornith:9b", COPY]);
  expect(offered(MINE.slice(0, 1))).toEqual([]);
});

it("a wait is timed per model, and a load per context too", () => {
  remember("load", waitKey("load", "ornith:9b", 16384), 54.8);
  remember("answer", waitKey("answer", "ornith:9b", 16384), 2.9);

  expect(lastTime("load", waitKey("load", "ornith:9b", 16384))).toBe(54.8);
  expect(lastTime("load", waitKey("load", "ornith:9b", 8192))).toBeNull();
  expect(lastTime("answer", waitKey("answer", "ornith:9b", 8192))).toBe(2.9);
});

it("a time that is not a time is neither kept nor read", () => {
  remember("load", "x", Number.NaN);
  remember("load", "y", -1);
  window.localStorage.setItem("sletchy.talk.timings", JSON.stringify({ load: { z: "fast" }, answer: 3 }));

  expect([lastTime("load", "x"), lastTime("load", "y"), lastTime("load", "z")]).toEqual([null, null, null]);
  window.localStorage.setItem("sletchy.talk.timings", "not json");
  expect(lastTime("answer", "ornith:9b")).toBeNull();
});
