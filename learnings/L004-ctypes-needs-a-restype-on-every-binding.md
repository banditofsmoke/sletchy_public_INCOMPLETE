# L004 - Set `restype` on every ctypes binding, always

**2026-08-14, building `_win32.py` for the `winjob` backend (#31).**

## What happened

A probe failed with `OpenProcessToken: 6` - `ERROR_INVALID_HANDLE`. The handle being passed
came straight from `GetCurrentProcess()`, which cannot fail and cannot return an invalid
handle. The error was impossible.

The cause was one missing line:

```python
GetCurrentProcess.restype = wintypes.HANDLE
```

**ctypes defaults every return value to a 32-bit C `int`.** On 64-bit Windows the
pseudo-handle came back truncated and sign-extended into something meaningless. Nothing
raised. Nothing warned. The value simply became wrong, and the error surfaced one call
later, pointing at the wrong function.

## Why it happened

The default is silent and it is wrong for every handle-returning Win32 function. It also
fails *late* - the bad value propagates until something tries to use it, so the reported
error names an innocent call.

## The rule

**Every ctypes binding declares both `argtypes` and `restype`, at the point of definition,
without exception.** Not the ones that look like they need it. All of them.

```python
kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
```

- A binding without `restype` is a bug even when it currently works, because it works by
  coincidence of value range
- `HANDLE` is pointer-sized. `int` is not. On win64 that difference is invisible until the
  value exceeds 2^31
- When a Win32 error names a call that cannot produce it, **suspect the previous call's
  return type** before suspecting the API

`_win32.py` declares both on all of its bindings for this reason, and that is worth keeping
even where it is verbose.
