# The Laws

Short, checkable rules. [Principles](principles.md) explain *why*; these are the *what*,
written so a PR can be measured against them.

Precedence: **LAW 0 > LAW 1 > LAW 2 > LAW 3 > everything else.**

---

<a id="law-0"></a>

## LAW 0 - Do no harm to the host machine

Full text: [00-do-no-harm.md](00-do-no-harm.md). Summary:

- No kernel drivers, no Test Signing Mode, no bootstart services.
- Every host change is reversible by one command. `sletchy stop` fully reverts.
- Runs as a normal user. One auditable elevation, for firewall rules only.
- All state under `var/`. Nothing else on the host is written.
- Hard resource ceilings on every launched process, applied *before* it starts.
- Fail closed, never fail destructive.

**Check:** does this PR change the host outside `var/`? If yes - what is the undo, and
is it in `sletchy stop`?

---

<a id="law-1"></a>

## LAW 1 - Nothing happens off-ledger

Every decision, tool call, model call, egress attempt, flag flip, capability grant, and
policy verdict appends to the ledger **before** it takes effect.

- No side-channel logging. No debug path that skips the ledger.
- The chain verifies on startup. A chain that does not verify halts Sletchy.
- Sletchy never repairs its own ledger.

**Check:** can any code path in this PR act without a ledger append? That is a bug.

---

<a id="law-2"></a>

## LAW 2 - Deny by default

The default answer is no - to egress, to filesystem access, to tools, to secrets, to
process launch, to capability use.

- Ties go to deny. Unparseable policy denies everything and raises.
- A capability whose minimum isolation backend is unavailable **does not run**. It never
  silently downgrades.

**Check:** if the policy file were empty, would this feature still do something? It
should do nothing.

---

<a id="law-3"></a>

## LAW 3 - Declare, then tighten. Never loosen.

Components declare their needs in a typed profile. Policy may only narrow. The enforcer
is a different component from the declarer.

- A merge that widens a declared bound is rejected and the component refuses to start.
- Self-enforcement is not enforcement.

**Check:** is the thing enforcing the limit the same thing that declared it?

---

<a id="law-4"></a>

## LAW 4 - Nothing is trusted, including imports

Agents, tools, models, prompts, dependencies, and Sletchy itself are all inside the
threat model.

- Dependencies pinned by version **and** hash.
- New dependencies pass the vetting gate (license, CVE, footprint, diff) and run
  quarantined while profiled.
- Trust is a score that moves on evidence, not a permanent property.

**Check:** does this PR add a dependency? Where is its vetting record?

---

<a id="law-5"></a>

## LAW 5 - One stream, one vocabulary

One typed async event stream per execution. Hosts are pure translation: no state, no
side effects.

- Adding an event type requires an ADR. Extend a payload first.
- Non-streaming calls wrap the stream, never the reverse.

**Check:** does this host adapter hold state or cause a side effect? Move it.

---

<a id="law-6"></a>

## LAW 6 - Pydantic is the only schema

All config, contracts, profiles, and policies are Pydantic models. Every derived artifact
is generated.

- Hand-written parallel JSON Schema / OpenAPI / UI forms are forbidden.

**Check:** is there a schema in this PR that a human typed twice?

---

<a id="law-7"></a>

## LAW 7 - Humans gate the irreversible

Stop and ask before anything irreversible or outward-facing:

- Spending money. **Mainnet contract deploy requires a second confirmation naming the
  chain and the value at risk.**
- Sending or publishing anything outside the bubble.
- Widening a capability or a policy.
- Binding a listener beyond loopback.
- Deleting user data.

**Check:** could this action embarrass, cost, or expose the operator if it fired
unattended?

---

<a id="law-8"></a>

## LAW 8 - Flags default off

Every capability is individually switchable. Anything touching network, filesystem
outside `var/`, microphone, camera, screen, wallet, or training defaults **off**.

- Flips are ledger-logged with who, when, why.
- No undocumented flags. Dev defaults live in a separate profile that never ships.

**Check:** on a fresh install with no configuration, is this feature inert?

---

<a id="law-9"></a>

## LAW 9 - Build new; scraps are reference

`Scraps and Parts/` is read-only archaeology. Never import from it, never copy from it,
never write to it.

- Every salvaged idea is recorded in [`docs/salvage/INVENTORY.md`](../salvage/INVENTORY.md)
  with a verdict and a destination.

**Check:** did any code in this PR arrive by copy-paste rather than by rewrite?

---

<a id="law-10"></a>

## LAW 10 - Honesty about gaps

Every defensive layer documents what it does **not** catch. Residual gaps go in
`tests/adversarial/COVERAGE.md`, visibly, rather than being implied-covered.

- "Probably fine" is not a coverage claim.
- A test that has never failed against a real attack is a hypothesis.

**Check:** what would defeat this control, and is that written down?

---

## PR checklist

Every PR body answers these. No answers, no merge.

- [ ] **Blast radius** - what on the host can this touch?
- [ ] **Undo** - how is it reversed? Is it in `sletchy stop`?
- [ ] **Ledger** - what events does this emit?
- [ ] **Default state** - is it off by default?
- [ ] **Deny path** - what happens when policy says no?
- [ ] **Gaps** - what does this not catch? Is it in `COVERAGE.md`?
- [ ] **Salvage** - if this rebuilds something from `Scraps and Parts/`, is the
      inventory entry updated?
