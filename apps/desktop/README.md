# Sletchy desktop

The window. It starts the Kernel (`sletchy bridge`) as its own child process, inside a
Windows Job Object, and talks to it over that process's pipes. **Nothing listens** - no
port, no local web server. Why, and what that rules out: [ADR-0008](../../docs/adr/0008-desktop-shell.md).

## Start it with a double-click

Double-click **`Open-Sletchy.cmd`** in the repository root. The first time, it offers to
build the window (a few minutes), then it opens Sletchy. After that it opens straight away.

To see what it would do without starting anything, run `Open-Sletchy.cmd --check` in a
command prompt. It prints what it would do, starts nothing, and never waits for a key.

Nothing is installed: the program runs from this folder, everything Sletchy writes stays
in `var/`, and closing the window stops all of it. The one exception is **Set up Sletchy**,
which keeps one signing key in Windows Credential Manager.

**Is it safe to click everything?** Every button, lever and screen, and exactly what each
one can and cannot do, is in [WHAT-A-CLICK-CAN-DO.md](WHAT-A-CLICK-CAN-DO.md), with the
tests that prove it. `tests/unit/test_click_map.py` fails if that page misses a request or
cites a test that does not exist.

**Why there is no installer yet.** An installer writes outside this folder: into Program
Files or `%LOCALAPPDATA%\Programs`, the Start menu, and an uninstall key in the registry.
That is a host change LAW 0 has not cleared. An unsigned installer would also trip
SmartScreen, and teach people to click through warnings. It comes with Uttu's public
release, with a code-signing certificate and its own ADR.

## Run it for development

From this folder, once:

```bash
npm ci
```

Then:

```bash
npm run tauri dev
```

The first build compiles about 400 Rust crates and takes several minutes; later ones take
seconds. It needs Node and Rust to **build**. The app it produces needs neither.

The app looks for the Kernel at `../../.venv/Scripts/sletchy.exe`, so run `uv sync` in the
repository first. It shares `var/` with the CLI: a switch flipped here is the same switch
`sletchy flags list` shows, and both are in the same ledger.

Rust lives in `%USERPROFILE%\.cargo\bin`, which is deliberately not on PATH. `npm run tauri`
adds it for that one command (`scripts/tauri.mjs`). Nothing edits your PATH.

## Three ways to look

| Mode | For | Shows |
|---|---|---|
| **Simple** | Anyone | The trust meter in plain words, big switches, recent activity, Stop everything |
| **Custom** | People who want detail | Every switch by its real name, the self-check with weights, the ledger with filters, a Stop everything dry run |
| **Raw** | Developers | A console for any allowed request, every request and answer, the Kernel process and its job limits |

Raw is a view, not a back door: every request goes through the same two allowlists and
the same checks.

## Work on the screens in a browser

```bash
npm run preview:browser
```

Serves the window on `http://127.0.0.1:1420` with **sample data and a banner saying so**.
There is no Kernel in a browser, so nothing it shows is yours and nothing it does reaches
your computer.

## Tests

```bash
npm test            # the window (Vitest)
npm run typecheck   # TypeScript
cd src-tauri && cargo test   # the Job Object, the allowlist, and the real Kernel
```

`tests/adversarial/test_desktop_shell.py` (run by `uv run pytest`) pins the security
posture: two granted commands, no plugins, a CSP that allows nothing remote, no npm install
scripts, exact pins, and the WebView profile under `var/`.

## What is generated

`src/generated/contracts.ts` and `src-tauri/src/methods.rs` are written by
`scripts/gen_desktop_contracts.py` from the Kernel's Pydantic models. Do not edit them; a
test fails when they are stale.
