import { expect, it } from "vitest";

import { firstOnPath } from "./first-on-path.mjs";

// The first double-click build of the window failed with "'npm' is not recognized":
// Explorer had spelled the variable `Path`, and the build's search path came out as
// Rust's folder alone. These tests stand in for that double-click.

const CARGO = "C:\\Users\\me\\.cargo\\bin";
const NODE = "F:\\Tools";

/** The search path a child is given: on Windows, Node passes one spelling of each
 * name, the first in sorted order, so `PATH` wins over `Path`. */
const passed = (env) => {
  const key = Object.keys(env)
    .sort()
    .find((k) => k.toUpperCase() === "PATH");
  return key === undefined ? undefined : env[key];
};

it("keeps npm's folder when Windows spells it Path, as on a double-click", () => {
  const env = firstOnPath({ Path: `${NODE};C:\\Windows` }, CARGO, ";");
  expect(passed(env)).toBe(`${CARGO};${NODE};C:\\Windows`);
  expect(Object.keys(env)).toEqual(["Path"]);
});

it("keeps npm's folder when a terminal spells it PATH", () => {
  expect(passed(firstOnPath({ PATH: NODE }, CARGO, ";"))).toBe(`${CARGO};${NODE}`);
});

it("puts Rust's folder first on every spelling already there", () => {
  const env = firstOnPath({ PATH: NODE, Path: NODE }, CARGO, ";");
  expect([env.PATH, env.Path]).toEqual([`${CARGO};${NODE}`, `${CARGO};${NODE}`]);
});

it("makes PATH only when there is none", () => {
  expect(firstOnPath({ HOME: "x" }, CARGO, ";")).toEqual({ HOME: "x", PATH: CARGO });
});

it("changes a copy, never the process's own environment", () => {
  const env = { Path: NODE };
  firstOnPath(env, CARGO, ";");
  expect(env).toEqual({ Path: NODE });
});
