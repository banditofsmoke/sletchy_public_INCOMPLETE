# ADR-0014 - The container backend runs on Linux only, and never on this machine

**Status:** Accepted · 2026-10-04 · refs #70 · builds on [ADR-0002](0002-pluggable-isolation-backends.md)

## Context

#70 asked a LAW 0 question before any code: on Windows, a container backend is not a
library. Podman and Docker run Linux containers inside a WSL2 virtual machine, which
needs the Virtual Machine Platform, changes the boot configuration and puts the host
under a hypervisor. None of that is covered by "every host change is reversible, and
`sletchy panic` reverts all of it".

The issue offered three acceptable outcomes: a backend that refuses unless the operator
already installed a runtime; a backend for Linux only; or a deferral.

Two facts decided it:

- The machine Sletchy is built on is the operator's only computer, and his income
  (LAW 0). A container backend that ran on it would start Linux virtual machines and
  pull images, both outside `var/` and outside anything panic could prove it undid
- Uttu's release is meant for Windows **and Ubuntu** (#133). On Linux a container is an
  ordinary user-mode process tree: no hypervisor, nothing in the boot configuration

## Decision

1. **The `container` backend is available on Linux only.** On Windows `available()` is
   False whatever is installed, so `select()` never returns it there and the ladder on
   this machine is unchanged: `winjob` stays the default and the strongest rung
2. **Sletchy never installs, enables or starts a container runtime**, on any platform.
   On Linux the backend is available only when `podman` is already on the machine
3. **Podman, not Docker.** Rootless and daemonless; nothing runs with more rights than
   the operator. Docker is never required
4. **The image is pinned by digest** (LAW 4), never by tag, and is never pulled by a
   run: `--pull=never`. Fetching it is the operator's step, or CI's
5. **CI proves it** on the ubuntu runner, against the same conformance suite every
   backend passes
6. Revisiting decision 1 for Windows is the operator's call alone, with WSL2 already
   enabled by him, and would come with its own ADR

## Consequences

- The ladder has a second real rung, so the interface is tested by two implementations
- This machine runs exactly what it ran before
- What a container on Linux does not isolate is written down in `COVERAGE.md` before it
  is called an isolation backend
