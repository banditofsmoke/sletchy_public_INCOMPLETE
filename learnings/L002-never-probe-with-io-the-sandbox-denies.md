# L002 - A probe must not use I/O the sandbox itself denies

**2026-08-13, the AppContainer spike ([ADR-0005](../docs/adr/0005-appcontainer-findings.md) §4).**

## What happened

Probe commands were written the way anyone writes a quiet shell command:

```
cmd /c type somefile > nul
```

Inside an AppContainer, **the child cannot open the NUL device.** The redirect failed
before the command ran, so the process died at startup and the probe recorded a denial that
had nothing to do with the file being read.

The same class of problem showed up repeatedly while building `winjob`: `waitfor`,
`timeout` and `ping` all *launch* inside the container and then fail on services they are
denied, so none of them can be used as a sleep. The working sleep is a `cmd` builtin busy
loop, `for /L %i in (1,1,2000000000) do @rem`, because it needs nothing but the shell.

## Why it happened

A probe is instrumentation, and instrumentation is invisible until it breaks. Redirects,
temp files, environment lookups and helper binaries are all things a test harness reaches
for without thinking - and every one of them is an operation the sandbox may deny. When it
does, the failure is attributed to the thing under test.

The container is doing exactly what it should. The measurement is what is wrong.

## The rule

**A probe may only use I/O the sandbox is expected to permit.** Everything else is set up
by the parent, outside the boundary.

- **The parent opens the file and passes the handle in.** A handle that is already open
  needs no access check, which is precisely why `winjob` captures output this way rather
  than letting the child redirect
- **No `> nul`, no `2>&1` to a path, no temp files created by the child**
- **Shell builtins only** where possible - `exit`, `echo`, `type`, `for` need no PATH,
  and sandboxed children get `PATH=""` by design
- Pass argv elements separately and never pre-quoted; `list2cmdline` will escape a
  pre-quoted string into something else entirely ([L003](L003-a-blocked-dialog-is-a-live-process.md))

When a probe fails, the first question is **"did the thing under test deny this, or did my
instrumentation?"** - and [L001](L001-a-probe-needs-a-positive-control.md)'s positive
control is what answers it.
