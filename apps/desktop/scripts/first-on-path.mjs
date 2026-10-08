import { delimiter } from "node:path";

/**
 * A copy of `env` with `folder` first on the search path, for one child process.
 *
 * Windows spells the variable `Path` when Explorer starts a program (a double-click)
 * and `PATH` in most terminals, while a plain object's keys are case-sensitive. Setting
 * `env.PATH` beside an existing `Path` made a second variable holding only `folder`,
 * and Node, which passes a child one spelling of each name, passed that one: the build
 * could no longer find npm. So every spelling already there is updated, and `PATH` is
 * made only when there is none.
 *
 * @param {Record<string, string | undefined>} env
 * @param {string} folder
 * @param {string} [sep]
 * @returns {Record<string, string | undefined>}
 */
export function firstOnPath(env, folder, sep = delimiter) {
  const out = { ...env };
  const keys = Object.keys(out).filter((key) => key.toUpperCase() === "PATH");
  for (const key of keys.length > 0 ? keys : ["PATH"]) {
    out[key] = out[key] ? `${folder}${sep}${out[key]}` : folder;
  }
  return out;
}
