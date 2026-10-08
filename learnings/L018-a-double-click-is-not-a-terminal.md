# L018 - A double-click is not a terminal

**2026-10-08: the first double-click build of the window could not find npm.**

## What happened

I deleted the old window on 2026-10-07 so `Open-Sletchy.cmd` would build a new one. The
next day I double-clicked it, said yes to the build, and it stopped at once: *"'npm' is
not recognized"*, from the step that builds the window's pages. The launcher itself had
just run npm, from the same window. The window I deleted had been built from a terminal,
so this was the first time the build ran the way the launcher runs it.

## Why it happened

`scripts/tauri.mjs` puts Rust's folder first on the search path for the build, and it did
that with `env.PATH = folder + ";" + env.PATH`, on a copy of `process.env`. Windows does
not mind how a variable's name is spelled, but a copy of `process.env` is a plain object,
and its keys do. Explorer starts a program with the variable spelled `Path`; a terminal
my agent runs spells it `PATH`. From a double-click, `env.PATH` was missing, so the copy
gained a second variable holding only Rust's folder, and Node, which passes a child one
spelling of each name (`PATH` sorts first), passed that one. The tests and probes all ran
in a terminal, where the spelling matched and the line worked.

## The rule

- **Find an environment variable on Windows without regard to case.** Update every
  spelling a copy holds, and make a new one only when there is none
  (`apps/desktop/scripts/first-on-path.mjs`, held by its test)
- **A test standing in for a double-click starts from what a double-click gives**: here,
  `Path`. A probe run from my terminal proves the terminal
- **What only a click runs is unproven until the click has run it.** Say so, as L010 asks
  of a launcher's first run
