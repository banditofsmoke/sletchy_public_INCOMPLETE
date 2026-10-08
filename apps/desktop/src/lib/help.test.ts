import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect, it } from "vitest";

import { HELP, type Guard } from "./help";

// A help card is a claim, and LAW 10 says a claim needs its test. So every test a
// card cites must exist, under that exact name, in the file it names.

const ROOT = resolve(import.meta.dirname, "../../../..");

function exists(guard: Guard): boolean {
  let source: string;
  try {
    source = readFileSync(resolve(ROOT, guard.file), "utf-8");
  } catch {
    return false;
  }
  if (guard.file.endsWith(".py")) return source.includes(`def ${guard.test}(`);
  if (guard.file.endsWith(".rs")) return source.includes(`fn ${guard.test}(`);
  return source.includes(`"${guard.test}"`);
}

it("the checker can tell a real test from an invented one", () => {
  // Positive control: it must be able to say no.
  expect(exists({ file: "tests/unit/test_selfcheck.py", test: "test_a_self_check_changes_nothing" })).toBe(true);
  expect(exists({ file: "tests/unit/test_selfcheck.py", test: "test_that_was_never_written" })).toBe(false);
  expect(exists({ file: "tests/no/such/file.py", test: "anything" })).toBe(false);
});

it("every test a help card cites exists, by that name, in that file", () => {
  const missing = Object.entries(HELP).flatMap(([id, entry]) =>
    entry.guards.filter((g) => !exists(g)).map((g) => `${id}: ${g.file} :: ${g.test}`),
  );
  expect(missing).toEqual([]);
});

it("every card answers all four questions and cites at least one test", () => {
  for (const [id, entry] of Object.entries(HELP)) {
    for (const field of ["title", "what", "why", "worst"] as const) {
      expect(entry[field].length, `${id}.${field}`).toBeGreaterThan(5);
    }
    expect(entry.guards.length, id).toBeGreaterThan(0);
  }
});
