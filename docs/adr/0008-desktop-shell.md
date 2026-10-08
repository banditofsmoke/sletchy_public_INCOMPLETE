# ADR-0008 - The desktop shell: Tauri v2, a stdio bridge, and nothing listens

**Status:** Accepted · 2026-10-02. Replaces the "Electron desktop" line of Wave 6 in
[waves.md](../roadmap/waves.md).

## Context

I want a window: buttons, screens and feedback, in three modes - **Simple** for
someone who has never opened a terminal, **Custom** for people who want every switch,
and **Raw** for developers who want the JSON. It needs a trust meter for Sletchy
itself and switches people can toggle.

Two existing decisions constrain how:

- **[ADR-0003](0003-ledger-is-the-spine.md):** waves are sequential, and the temptation
  to build something visible early is the failure it was written to stop. The Shell is
  Wave 6.
- **Nothing listens** until [#62](https://github.com/Sletch/sletchy/issues/62) and
  [#59](https://github.com/Sletch/sletchy/issues/59) decide what a long-running Sletchy
  may do.

## Decision

1. **Tauri v2** (Rust, with the WebView2 runtime that ships with Windows), not
   Electron.
2. **The window talks to the Kernel through `sletchy bridge`**: a child process it
   starts itself, speaking JSON lines over stdin and stdout. **There is no port.**
3. **The child starts inside a Job Object with LAW 0 §5's ceilings already applied.**
   It is created suspended, assigned to the job, and only then resumed, so not one
   instruction runs outside the limits. If assignment fails, the child is killed
   and the window shows the error. It never runs unconfined.
4. **Two allowlists, enforced by two different components.** Tauri's command manifest
   makes every command deny-by-default, granted only by the window's capability file;
   the Rust side refuses any bridge method not in its list; the bridge refuses any
   method not in `METHODS`. The Rust list is generated from the Python one.
5. **Every type the window uses is generated** from the bridge's Pydantic models
   ([LAW 6](../LAW/laws.md#law-6)), and a test fails when it is stale.
6. **The shell adds no capability.** Every bridge method is something the CLI could
   already do: status, the flags, the ledger, panic, setup, and the self-check.

## Why this is not jumping a wave

ADR-0003 already names "desktop IPC" as a **host adapter** beside the CLI. A host is
pure translation ([LAW 5](../LAW/laws.md#law-5)): it reaches exactly what the CLI
reaches, and the bridge is tested to prove it holds no state between requests. What
Wave 6 *is* - the conversation, the NOC, first-run - still waits for the Mind and the
SOC. When they land, the window gains panes; until then it shows what exists, and
says plainly what does not (every switch reports whether anything reads it yet).

## Reasoning, law by law

| Law | How this design meets it |
|---|---|
| **LAW 0 §1-2** | No kernel code, no service, no auto-start. **WebView2's profile is pointed into `var/webview`**: left to itself it wrote 232 files (11 MB) to `%LOCALAPPDATA%` on the first launch, measured 2026-10-02 and removed. The window is therefore built in code, not in `tauri.conf.json`, and a test fails if a config window reappears. |
| **LAW 0 §5** | The bridge runs in a job with a memory ceiling, an active-process ceiling and kill-on-close, applied before it runs. **One stated departure:** no 300-second wall clock, because the bridge lives exactly as long as the window. Kill-on-close is its bound instead. |
| **LAW 2** | Nothing listens, so there is no request a web page, another user or another machine can send. A localhost server would have needed CSRF and DNS-rebinding defences from day one; this needs none. |
| **LAW 3** | Tauri's capabilities are declare-then-grant, and the enforcer (the Tauri runtime) is not the declarer (the web page). |
| **LAW 4** | No Node runtime ships inside the app. WebView2 is part of Windows. Rust and npm dependencies are pinned by lockfile hashes. The vetting gate itself is #34, not built; until then each dependency is named in the PR that adds it. |
| **LAW 7, LAW 8** | The window cannot turn anything on by itself. A dangerous switch needs a reason (the Kernel's rule) **and** its exact name typed back (the bridge's rule). Turning anything off, and Stop everything, need neither: the safe direction is never obstructed, and panic never asks. |

Two reasons that are not laws but decided it anyway:

- **Size.** A Tauri installer is around 10 MB; an Electron one ships a whole Chromium
  and Node at around 150 MB. Mobile data in South Africa is expensive, and the people
  Uttu is for will notice.
- **No lock-in.** Tauri is MIT/Apache-2.0, WebView2 ships with Windows, and nothing
  here needs Docker, Kubernetes, or an account anywhere.

## Alternatives rejected

- **Electron** - what Wave 6 planned. Ships Chromium and Node, roughly fifteen times
  the size, and its security depends on a list of settings that must each be right.
- **A web page on 127.0.0.1** - the first listener in Sletchy, reachable by any page
  the user visits unless defended against CSRF and DNS rebinding.
- **Tkinter** - no listener and no dependency, but I ruled it out.
- **A terminal UI** - the Raw mode is already that; it is not something a grandmother
  can use.

## Consequences

**Good**

- A window people can use, built on the same Kernel calls the CLI makes.
- `sletchy selfcheck` and `sletchy ledger show` (#50) exist for terminal users too,
  because the bridge needed them first.

**Costs**

- **The window runs from the repo only.** It finds `.venv/Scripts/sletchy.exe` and
  starts it with the repo as its working directory. A release has to bundle the
  Kernel as a sidecar; that is release work, not tonight's.
- Building it needs the Rust toolchain and Node. Running it needs neither.
- **The Kernel is four processes deep on Windows**: uv's launcher, the `conhost.exe`
  Windows gives every console program, the virtualenv's `python.exe` redirector, and
  the interpreter it starts. All four are in the job (measured: a lone `cmd /c exit`
  counts as 2 in a job, itself and its conhost). `panic`'s helpers are console programs
  too, so each brings its own conhost: two at a time. That is 6 of the job's 8.
- `tauri dev` builds the window's files and loads them from disk, so **nothing listens
  even during development**. `npm run preview:browser` does serve them on loopback,
  for UI work only: in a browser there is no Kernel to reach, and the page says so.
- WebView2's version varies per machine, and its bugs are not ours to fix.

## Known gaps

- **The window trusts its own bundled assets.** A strict CSP allows nothing remote,
  but a flaw in WebView2 itself is outside anything this design controls.
- **The job limits are applied, not seen to fire** - the same gap `winjob` has for its
  memory ceiling, for the same reason.
- **The bridge runs as the user, unsandboxed beyond the job.** It is Sletchy's own
  Kernel, not an untrusted workload; AppContainer would cut it off from the keychain
  it exists to use.
