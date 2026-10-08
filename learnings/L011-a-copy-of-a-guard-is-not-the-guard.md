# L011 - A copy of a guard is not the guard

**2026-10-03, writing the Abuser story for `sletchy panic` (#94, fixed in #109 and #120).**

## What happened

`panic` reverts what a sandbox run changed on the host. It reads a journal under
`var/run/` and, for each record, runs `icacls <path> /remove:g *<sid> /T` and deletes an
AppContainer profile. The journal is readable without the signing key on purpose, so that
panic works when the keychain is gone.

One hand-written line in that journal - another app's profile name, the user's own SID,
and the paths `C:\Users\<me>` and `C:\` - made panic, with every host call stubbed so
nothing ran, aim:

```
icacls C:\Users\<me> /remove:g *S-1-5-21-...-1001 /T /C /Q
icacls C:\ /remove:g *S-1-5-21-...-1001 /T /C /Q
DeleteAppContainerProfile("Microsoft.NotARealPackage_fake")
```

and report a clean revert. Stop everything, the button for an emergency, was the most
dangerous code in the repo.

The Warden already refused exactly this. Its `revoke_path` runs every path through
`assert_grantable`, whose docstring says the guard "keeps a bad journal entry from turning
a cleanup into a recursive ACL change". Panic did not use it.

## Why it happened

1. **The layering rules forced a copy.** `cli` may not import `warden`, and panic must
   work when the Warden is wedged, so panic reimplemented revoke and delete. That part was
   right.
2. **The copy took the action and left the guard.** The guard lived beside the grant, in
   the Warden's Win32 module, which panic could not import. Nothing said the two
   implementations had to agree, so they did not.
3. **The tests could not see it.** Their fake records used the SID `S-1-15-2-1`, which no
   record the Warden writes ever carries. That SID is `ALL APPLICATION PACKAGES`, a
   well-known group. Every test passed with a value that real code never produces, so a
   refusal of non-Sletchy SIDs would have broken them, and the absence of one went
   unnoticed.

## The rule

- **A rule two planes must both obey lives where both can import it** - at the bottom,
  in the Kernel. `kernel/paths.py` moved there for this reason; `kernel/grantguard.py`
  now does too, and panic and the Warden hold **the same object**, which
  `test_the_warden_and_panic_share_one_guard` asserts. When the layering rules force a
  second implementation of an *action*, the *check* still has one definition.
- **A destructive step validates its input itself, before its first host call.** Panic
  now refuses a record whose profile is not `Sletchy-<its own id>`, whose SID is not the
  one Windows derives from that name, or whose path the shared guard refuses, and keeps
  the record. A guard upstream does not protect a step that can be reached another way.
- **Test fixtures are shaped like what production writes.** Derive them the way the real
  code does (`tests/adversarial/appcontainer.py` derives SIDs exactly as Windows does,
  held equal to Windows by a test), rather than typing a value that merely looks right.
  A fixture production never produces can hide a missing check forever.
- **Ask the abuser's question of the safest command too.** Panic was audited for "does it
  work" (L009) and passed. Nobody had asked "what can someone aim it at".
