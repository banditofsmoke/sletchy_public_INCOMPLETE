// Runs the Tauri CLI with Rust's toolchain on PATH for this process only.
//
// rustup installs to %USERPROFILE%\.cargo\bin. My PATH deliberately does not
// include it, and Sletchy never edits a PATH (LAW 0 section 2), so the folder is
// prepended here, for this child process and nothing else.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { firstOnPath } from "./first-on-path.mjs";

const cargoBin = join(homedir(), ".cargo", "bin");
const env = existsSync(cargoBin) ? firstOnPath(process.env, cargoBin) : process.env;

const cli = fileURLToPath(new URL("../node_modules/@tauri-apps/cli/tauri.js", import.meta.url));
const result = spawnSync(process.execPath, [cli, ...process.argv.slice(2)], {
  stdio: "inherit",
  env,
});
process.exit(result.status ?? 1);
