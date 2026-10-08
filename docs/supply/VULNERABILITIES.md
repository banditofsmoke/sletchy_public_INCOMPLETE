# Known vulnerabilities - the ones accepted, why, and until when

`scripts/known_vulnerabilities.py` asks the OSV database (osv.dev) about every package
in the three lockfiles on every CI run: `uv.lock`, the window's `package-lock.json` and
its `Cargo.lock` (#34). A known vulnerability fails the run **unless a row here accepts
it**.

A row accepts one advisory, for one reason, until one date. After the date the run fails
again, so an acceptance is a decision that comes back to be made again, never one that
quietly stays. A row with no reason or no date accepts nothing.

Accepting is for an advisory that cannot reach Sletchy: the affected code is never
called, or the package only builds the window and never runs with Sletchy's data. Where
an upgrade fixes it, the upgrade is the answer, not a row.

## Accepted

| Advisory | Package | Why it cannot reach Sletchy | Until |
|---|---|---|---|
| `GHSA-wrw7-89jp-8q8g` | glib 0.18.5 (crates.io) | Linux only: pulled in by Tauri's GTK window (gtk, webkit2gtk). The window ships for Windows, where Tauri uses WebView2 and no GTK crate is built. Fixed in glib 0.20, which waits on Tauri. Look again before any Linux build (#133) | 2027-01-04 |
| `RUSTSEC-2024-0429` | glib 0.18.5 (crates.io) | The same advisory, under RustSec's id | 2027-01-04 |
| `RUSTSEC-2024-0370` | proc-macro-error 1.0.4 (crates.io) | Unmaintained, not a known flaw. A compile-time macro crate on the same Linux-only GTK path (glib-macros, gtk3-macros); none of it is in the Windows window | 2027-01-04 |

Found by the check's first run, 2026-10-04: 606 packages asked, these three answered.
