# `warden/` - enforcement, and the only way out

**This package is the one that says no.** It is also the package most able to damage the
host, so [LAW 0](../../../docs/LAW/00-do-no-harm.md) applies here harder than anywhere
else.

Read [`docs/LAW/isolation.md`](../../../docs/LAW/isolation.md) and
[ADR-0001](../../../docs/adr/0001-no-kernel-driver.md) +
[ADR-0002](../../../docs/adr/0002-pluggable-isolation-backends.md) first.

## Absolute rules

- **No kernel-mode code.** No driver, no minifilter, no WFP callout, no NDIS filter, no
  bootstart service. No Test Signing Mode. This is [ADR-0001](../../../docs/adr/0001-no-kernel-driver.md)
  and it is not a preference.
- **Every host change is reversible, and its undo is wired into `sletchy panic` in the
  same PR.** Not the next PR. The same one.
- **All firewall rules go in the `Sletchy` group** so they can be removed wholesale.
- **Never elevate at runtime.** The one elevated operation is `sletchy install-rules`,
  which is separate, one-shot, auditable, and prints exactly what it will do first.
- **Resource limits are applied before a process runs**, never after. Applying them
  afterwards is a race, and a race in a security boundary is a vulnerability.

## Isolation backends

- Backends implement one interface and are tested against **one shared conformance
  suite** that asserts *behaviour* - "this write is refused", "this connection is
  refused" - never implementation details.
- **A capability whose minimum backend is unavailable does not run.** It never silently
  downgrades. This is the rule that keeps the ladder from becoming a loophole.
- `inproc` **refuses to load outside a test run**. Enforce it in code, not in a comment.
- `container` targets the OCI surface, not Docker's. **CI runs it against Podman** so
  "Docker is not required" stays a tested claim.

## Egress

- **Nothing in Sletchy makes a direct outbound connection.** Every plane gets a
  Kernel-provided client pointed at the local proxy. A raw `httpx`/`requests`/`fetch` call
  anywhere outside `warden/egress/` is a bug - there is a lint rule for it.
- Two independent layers: the OS firewall rule makes the proxy **non-bypassable**; the
  proxy allowlist makes it **granular**. Neither alone is sufficient; never remove one
  because the other exists.
- Every attempt and verdict hits the ledger - including denials, especially denials.
- Allowlist by host, port, method, and size cap. Deny on any ambiguity.

## Filesystem guard

- **Canonicalise first, then confine.** Resolve symlinks and junctions *before* the
  check, and re-verify the resolved path is under the root. Checking before resolving is
  the classic bypass.
- Windows-specific traps that POSIX-shaped designs miss, and that all must be rejected:
  `..` traversal, absolute paths, UNC (`\\?\`, `\\server\share`), drive letters, alternate
  data streams (`file.txt:stream`), and device names (`CON`, `NUL`, `COM1`, `LPT1`, …).
- Quota checked **before** the write.

## Supervisor

- **Allowlist, not blocklist.** A blocklist of dangerous commands is unwinnable.
- Reject path-bearing executables, empty argv, and shell interpreters (`cmd`,
  `powershell`, `pwsh`, `wsl`, `bash`) unless explicitly granted - and a granted shell
  means an allowlisted *script*, never a free prompt.
- Reject LOLBin patterns: `-EncodedCommand`, `-ExecutionPolicy Bypass`, `rundll32`,
  `regsvr32`, `mshta`.
- **A denied command never spawns.** Decide before `CreateProcess`, then emit
  `sandbox.blocked`.
- Children get an **env allowlist**, never the parent environment. Explicitly stripped:
  cloud credentials, DB URLs, preload/import-hook variables, `BASH_FUNC_*`-style exports.

## Supply chain

- Pinned by version **and hash**. New dependencies pass the vetting gate (license, CVE,
  transitive footprint, diff review) and run under the tightest backend while their real
  filesystem and network behaviour is profiled and diffed against what they declared.

## Testing

Adversarial tests are the primary tests here; unit tests are secondary. Every control
answers "what defeats this?" in `tests/adversarial/COVERAGE.md`, fixed or not.

**Tests never target the host's real services, and never target any third party.** Only
Sletchy's own sandboxed surfaces. Fixtures are inert artifacts - a fake token, a malformed
path, a decoy binary - never live malware.
