# Security

Sletchy is a personal project in build, run by one person on one Windows machine. It is not
released, and nothing here is meant to be installed by anyone else yet.

## Reporting a problem

Please report it privately, through this repository's **Security** tab ("Report a
vulnerability"), and not in a public issue. I read every report, and a fix goes through the
same path as any change here: a test that fails without it first.

## What is already known

Every gap I know of is written down in
[`tests/adversarial/COVERAGE.md`](tests/adversarial/COVERAGE.md), under "Residual gaps".
There is no need to report one of those. A new way past one of the controls, or a gap that
COVERAGE describes wrongly, is exactly what I want to hear about.

## What this repository never holds

Keys, tokens and passwords live in the operating system's keychain, never in a file. A
secret scan runs before every commit and in CI, and fails the build on anything shaped like
a key, or on a secret given a fallback default. My own data (the record, memory, switches) lives outside git
and is never published.
