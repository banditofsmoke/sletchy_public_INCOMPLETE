# Dependencies - why each one is here, and what it can reach

Every third-party package Sletchy ships, with the reason it was taken and what it can
touch when it runs (#34). LAW 4 says nothing is trusted, imports included: this is where
that trust is written down instead of assumed.

**A dependency is not approved until it has a row here, at the version `uv.lock` pins.**
`tests/adversarial/test_supply_chain.py::test_every_shipped_dependency_has_a_vetting_record_at_its_locked_version`
fails the build when a package is added, removed or upgraded and this file was not
changed in the same pull request. An approval that skips the record is permanently out
of scope (#34).

What ships is the runtime closure of `sletchy` in `uv.lock`: the packages it depends on,
and theirs. Development tools (pytest, ruff, mypy, import-linter) never ship and are not
listed. Measured from `uv.lock` on 2026-10-04: **16 packages**, 2 taken directly.

## How each column was filled

- **Version**: from `uv.lock`, which pins every file by sha256 (`test_every_python_package_is_pinned_by_version_and_hash`)
- **Pulled in by**: from `uv.lock`'s dependency lists
- **Compiled**: from the wheel file names in `uv.lock`. A wheel that is not
  `py3-none-any` carries machine code nobody here has read
- **Licence**: from the installed package's metadata, on each platform CI runs
  (`test_every_shipped_python_dependency_is_licensed_to_ship`). A package installed only
  on Linux is checked by the Linux job, and says so here rather than being guessed
- **Can reach**: a reading of what the package is for. What each one **does when
  imported** is measured: `tests/adversarial/test_quarantine.py` imports every package
  here with an audit hook watching, on Windows and on the Linux CI job, and each one
  imported with no network, no program started and no write outside its own folder
  (`src/sletchy/warden/supply/quarantine.py`)
- **Known vulnerabilities**: asked of OSV for every package in all three lockfiles on
  every CI run (`scripts/known_vulnerabilities.py`). Any that cannot reach Sletchy are
  accepted, with a reason and a date, in [VULNERABILITIES.md](VULNERABILITIES.md)

## The record

| Package | Version | Pulled in by | Compiled | Licence | Why it is here | Can reach |
|---|---|---|---|---|---|---|
| `pydantic` | 2.13.4 | sletchy | no | MIT | Every Kernel contract is a Pydantic model; the schemas are generated from them, never hand-written | Nothing outside the process |
| `pydantic-core` | 2.46.4 | pydantic | **yes** | MIT | Pydantic's validation engine, compiled from Rust | Nothing outside the process, as far as its purpose goes; its machine code is not readable here |
| `annotated-types` | 0.8.0 | pydantic | no | MIT | The constraint markers Pydantic reads (`ge`, `max_length`) | Nothing |
| `typing-inspection` | 0.4.4 | pydantic | no | MIT | Reads type annotations for Pydantic | Nothing |
| `typing-extensions` | 4.16.0 | pydantic, pydantic-core, typing-inspection | no | PSF-2.0 | Newer typing features on older Pythons | Nothing |
| `keyring` | 25.7.0 | sletchy | no | MIT | The OS keychain, the only place secrets live: the ledger's signing key and its high-water mark | **The operator's credential store.** The most sensitive thing any dependency touches |
| `pywin32-ctypes` | 0.2.3 | keyring (Windows) | no | BSD-3-Clause | How `keyring` calls Windows Credential Manager, through ctypes | Windows Credential Manager |
| `jaraco-classes` | 3.4.0 | keyring | no | MIT | Small helpers `keyring` uses | Nothing |
| `jaraco-context` | 6.1.2 | keyring | no | MIT | Small helpers `keyring` uses | Nothing |
| `jaraco-functools` | 4.6.0 | keyring | no | MIT | Small helpers `keyring` uses | Nothing |
| `more-itertools` | 11.1.0 | jaraco-classes, jaraco-functools | no | MIT | Iteration helpers | Nothing |
| `secretstorage` | 3.5.0 | keyring (Linux) | no | checked on Linux CI | How `keyring` reaches the Secret Service on Linux | The Linux keyring, over D-Bus |
| `jeepney` | 0.9.0 | keyring, secretstorage (Linux) | no | checked on Linux CI | D-Bus in pure Python | The user's D-Bus session |
| `cryptography` | 50.0.0 | secretstorage (Linux) | **yes** | checked on Linux CI | Encrypts the Secret Service session | Nothing outside the process; compiled |
| `cffi` | 2.1.1 | cryptography (Linux) | **yes** | checked on Linux CI | How `cryptography` calls its compiled parts | Nothing outside the process; compiled |
| `pycparser` | 3.0 | cffi (Linux) | no | checked on Linux CI | Parses C declarations for `cffi` | Nothing |

## What this record does not check

Written down so it is not mistaken for more than it is (LAW 10):

- **Known vulnerabilities between runs, and unknown ones.** OSV is asked on every CI
  run, so a flaw published today is seen at the next pull request, not before. A flaw
  nobody has reported is in no database
- **Behaviour after import, and in native code.** The quarantine run watches one
  import, through Python's audit hooks. A compiled extension calling the operating
  system directly is invisible to them, and a package that misbehaves only on a certain
  date, host or call would pass anyway (#34's known gaps). Python cannot yet run inside
  the `winjob` container, so the refusals are the hook's, not the operating system's
- **Compiled code.** Three packages ship machine code. Their source is public, but the
  wheels are not rebuilt from it here; the sha256 pins prove the file is the one
  locked, not that it matches its source
- **The window's npm packages and Rust crates.** Their locks pin them by hash, the npm
  licences are checked and every one is asked of OSV; they have no rows here yet, and no
  quarantine run
- **A vetting decision is not a ledger entry.** It is this file, reviewed in a pull
  request; #34 asked for the ledger too, and that is not built
- **Vetting is a snapshot.** A row says why a version was taken. The next version needs
  its own look, which this file forces by failing the build until the row is updated
