# L010 - Test a launcher before you launch it

**2026-10-03, building the double-click launcher for the desktop window.**

## What happened

A new file, `Start Sletchy.cmd`, was written to start the window. Before it had a single
test, it was run by hand from PowerShell to see whether it worked:

```
cmd /c "`"Start Sletchy.cmd`""
```

PowerShell passed the quotes on differently from what was intended. `cmd` received the
name unquoted, read the first word, `Start`, as its own `START` built-in, and asked Windows
to open a file called `Sletchy.cmd`. Windows put this on my screen:

> Windows cannot find 'Sletchy.cmd'.

Nothing was harmed: no file was opened, written or deleted, and no process was left
behind. But this is the only computer I have, and an unexplained error dialog on it
reads as something breaking. My words at the time: *"i really only have one pc, i break this, i
starve on the streets."*

## Why it happened

Three mistakes, each enough on its own:

1. **The manual check came before the test.** The order was build, try it, then test it.
   For anything that starts a process, trying it is the risky part, so it has to come
   after a test has looked at it.
2. **A file name is a command line.** A name beginning with a `cmd` built-in (`start`,
   `call`, `cd`, ...) runs the built-in when typed without quotes, and a name with a space
   needs quotes every time. Either one turns a typing slip into a different program.
3. **Quoting through two shells is not something to eyeball.** PowerShell to `cmd` mangled
   the quotes twice in one session, and the second time was on the dry run. A command line
   that matters is built once, in code, and tested.

The first version also had `( )` blocks. `cmd` parses a block whole, so a path with a
bracket in it (`Program Files (x86)`) expanded inside one ends the block early.

## The rule

- **Anything that launches something gets a dry-run mode, and a test of that mode, before
  it runs for real even once.** `Open-Sletchy.cmd --check` says what it would do, starts
  nothing and never waits for a key.
- **Nothing appears on my screen unannounced.** Say what will open before opening it,
  or let me click it myself.
- **A launcher's name is checked by a test**: no spaces, no built-in as its first word,
  and it never shadows a real command. So is its body: no `( )` blocks, nothing that
  changes the host, every path it names the real one.
- **Run `cmd` from code, not from a shell.** Call it from Python with one exact command
  line, the way Explorer does: `cmd.exe /d /s /c ""<path>" --check"`.

All of it is held by `tests/adversarial/test_launcher.py`. The checks that matter were
proven against the original file: its name failed two of them, and its four bracket lines
failed a third.
