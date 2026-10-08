import { useState } from "react";

import { RiskBadge, StatusChip, Switch } from "../components/Bits";
import { EnableDialog } from "../components/EnableDialog";
import { Help } from "../components/Help";
import { HoldButton } from "../components/HoldButton";
import { Serves } from "../components/Instruments";
import { Noc, PlaneBar } from "../components/Noc";
import { Questions } from "../components/Questions";
import { TrustMeter } from "../components/TrustMeter";
import { TalkPlate } from "../components/TalkPlate";
import type { FlagView, PanicResult } from "../generated/contracts";
import type { Sample } from "../lib/noc";
import { relative } from "../lib/time";
import type { SletchyActions, SletchyState } from "../lib/useSletchy";

type Props = SletchyState &
  Pick<SletchyActions, "setFlag" | "loadLedger" | "planPanic" | "runPanic" | "recheck" | "setUp" | "refresh"> & {
    readonly noc: readonly Sample[];
    readonly latencies: readonly number[];
  };

/** The engineer's panel: the NOC, every switch by name, the record, the self-check in full. */
export function CustomView(props: Props) {
  const { status, selfcheck, flags, ledger, setFlag, loadLedger, planPanic, runPanic, recheck, setUp, refresh, noc, latencies } = props;
  const localModels = flags.find((f) => f.name === "mind_local_models")?.enabled ?? false;
  const [asking, setAsking] = useState<FlagView | null>(null);
  const [riskFilter, setRiskFilter] = useState<"all" | FlagView["risk"]>("all");
  const [onlyOn, setOnlyOn] = useState(false);
  const [limit, setLimit] = useState(50);
  const [prefix, setPrefix] = useState("");
  const [deniedOnly, setDeniedOnly] = useState(false);
  const [plan, setPlan] = useState<PanicResult | null>(null);

  const visible = flags.filter((f) => (riskFilter === "all" || f.risk === riskFilter) && (!onlyOn || f.enabled));
  const prefixValid = prefix === "" || /^[a-z][a-z0-9_.]{0,63}$/.test(prefix);
  const toggle = (flag: FlagView, next: boolean) => {
    if (next && flag.risk === "dangerous") setAsking(flag);
    else void setFlag(flag, next);
  };
  const query = () => {
    if (prefixValid) void loadLedger({ limit, denied_only: deniedOnly, action_prefix: prefix || null });
  };

  return (
    <div className="panel panel--custom">
      <section className="plate overview area-over">
        <div className="overview__gauge">{selfcheck && <TrustMeter score={selfcheck.score} ceiling={selfcheck.ceiling} size={190} />}</div>
        <dl className="facts">
          <dt>Ledger</dt>
          <dd>
            {status?.ledger_state ?? "unknown"}
            {status?.entries != null && ` · ${status.entries} entries verified`}
          </dd>
          <dt>Home</dt>
          <dd className="mono">{status?.home ?? "-"}</dd>
          <dt>Kernel</dt>
          <dd className="mono">{status ? `${/^\d/.test(status.version) ? "v" : ""}${status.version} · protocol ${status.protocol}` : "-"}</dd>
          <dt>Switches on</dt>
          <dd>
            {status?.flags_on ?? 0}
            {status && status.dangerous_on.length > 0 && <span className="warn-text"> · dangerous: {status.dangerous_on.join(", ")}</span>}
          </dd>
        </dl>
        {status?.ledger_state === "not_initialised" && (
          <button type="button" className="btn btn--brass" onClick={() => void setUp()}>
            Set up Sletchy
          </button>
        )}
      </section>

      <div className="area-q">
        <Questions flags={flags} />
      </div>

      <section className="plate area-noc" aria-labelledby="noc-title">
        <h2 id="noc-title" className="plate__title">
          Everything Sletchy is running
        </h2>
        <Help id="noc" />
        <Noc samples={noc} latencies={latencies} />
      </section>

      <section className="plate area-sc" aria-labelledby="sc-title">
        <header className="plate__head">
          <h2 id="sc-title" className="plate__title">
            Self-check
          </h2>
          <button type="button" className="btn btn--small" onClick={() => void recheck()}>
            Run again
          </button>
        </header>
        <Help id="meter" />
        <table className="table">
          <thead>
            <tr>
              <th>Check</th>
              <th>Result</th>
              <th className="num">Weight</th>
            </tr>
          </thead>
          <tbody>
            {selfcheck?.checks.map((c) => (
              <tr key={c.id} title={c.plain}>
                <td>
                  {c.label}
                  <div className="small muted mono">{c.detail}</div>
                </td>
                <td>
                  <StatusChip status={c.status} />
                </td>
                <td className="num">{c.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {selfcheck && (
          <p className="small muted">
            {selfcheck.score} of a possible {selfcheck.ceiling} today. Unmeasured earns nothing. Checked {relative(selfcheck.checked_at)}.
          </p>
        )}
      </section>

      {status?.ledger_state === "ok" && <TalkPlate switchedOn={localModels} onAnswered={() => void refresh()} detail />}

      <section className="plate stop area-panic" aria-labelledby="stop-title-c">
        <h2 id="stop-title-c" className="plate__title">
          Stop everything
        </h2>
        <Help id="plan" />
        <Help id="stop" />
        <div className="row">
          <button type="button" className="btn" onClick={async () => setPlan(await planPanic())}>
            Show what it would do
          </button>
          <HoldButton label="Hold to run" onHold={async () => setPlan(await runPanic())} />
        </div>
        {plan && (
          <dl className="facts facts--tight">
            <dt>{plan.dry_run ? "Would reset" : "Reset"}</dt>
            <dd>{plan.dry_run ? "every switch that is on" : `${plan.flags_reset} switch(es)`}</dd>
            <dt>Firewall rules</dt>
            <dd>
              {plan.firewall_rules_kept > 0
                ? `${plan.firewall_rules_kept} kept. They only stop Sletchy's own sandboxes reaching other computers; removing them needs an administrator.`
                : `${plan.firewall_rules_removed} ${plan.dry_run ? "to remove" : "removed"}`}
            </dd>
            <dt>Sandbox changes</dt>
            <dd>{plan.sandbox_changes_reverted}</dd>
            <dt>Runtime files</dt>
            <dd>{plan.runtime_files_cleared}</dd>
            <dt>Result</dt>
            <dd className={plan.clean ? "good-text" : "warn-text"}>{plan.clean ? "clean" : plan.errors.join(" ")}</dd>
          </dl>
        )}
      </section>

      <section className="plate area-flags" aria-labelledby="flags-title">
        <header className="plate__head">
          <h2 id="flags-title" className="plate__title">
            Switches
          </h2>
          <div className="row">
            <label className="inline">
              Risk{" "}
              <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value as typeof riskFilter)}>
                <option value="all">all</option>
                <option value="dangerous">dangerous</option>
                <option value="elevated">elevated</option>
                <option value="safe">safe</option>
              </select>
            </label>
            <label className="inline">
              <input type="checkbox" checked={onlyOn} onChange={(e) => setOnlyOn(e.target.checked)} /> only on
            </label>
          </div>
        </header>
        <Help id="switches" />
        <Help id="dangerous" />
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>What it allows</th>
                <th>Serves</th>
                <th>Risk</th>
                <th>Used by</th>
                <th>Default</th>
                <th>Now</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f) => (
                <tr key={f.name} className={f.enabled ? "row--on" : ""}>
                  <td className="mono">{f.name}</td>
                  <td>
                    <strong>{f.label}</strong>
                    <div className="small muted">{f.description}</div>
                  </td>
                  <td>
                    <Serves serves={f.serves} />
                  </td>
                  <td>
                    <RiskBadge risk={f.risk} />
                  </td>
                  <td className="small">{f.wired ? "Sletchy" : <span className="muted">nothing yet</span>}</td>
                  <td className="small mono">{f.default ? "on" : "off"}</td>
                  <td>
                    <Switch checked={f.enabled} label={`${f.name}: ${f.enabled ? "on" : "off"}`} onChange={(next) => toggle(f, next)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="plate area-ledger" aria-labelledby="ledger-title">
        <header className="plate__head">
          <h2 id="ledger-title" className="plate__title">
            Ledger
          </h2>
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault();
              query();
            }}
          >
            <label className="inline">
              Last{" "}
              <input type="number" min={1} max={500} value={limit} onChange={(e) => setLimit(Math.max(1, Math.min(500, Number(e.target.value) || 1)))} />
            </label>
            <label className="inline">
              Action <input value={prefix} placeholder="kernel.flag" aria-invalid={!prefixValid} onChange={(e) => setPrefix(e.target.value.trim())} />
            </label>
            <label className="inline">
              <input type="checkbox" checked={deniedOnly} onChange={(e) => setDeniedOnly(e.target.checked)} /> refusals only
            </label>
            <button type="submit" className="btn btn--small" disabled={!prefixValid}>
              Show
            </button>
          </form>
        </header>
        <Help id="ledger" />
        {ledger && <PlaneBar entries={ledger.entries} />}
        {ledger && <p className="small muted">Chain verified: {ledger.verified} entries, every signature and link.</p>}
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th className="num">#</th>
                <th>When</th>
                <th>Plane</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Decision</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {ledger && ledger.entries.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted">
                    No entries match.
                  </td>
                </tr>
              )}
              {ledger &&
                [...ledger.entries].reverse().map((e) => (
                  <tr key={e.seq}>
                    <td className="num mono">{e.seq}</td>
                    <td className="small" title={e.ts}>
                      {relative(e.ts)}
                    </td>
                    <td className="mono small">{e.plane}</td>
                    <td className="mono small">{e.actor}</td>
                    <td className="mono small">{e.action}</td>
                    <td>
                      <span className={`chip chip--${e.decision === "allow" ? "pass" : e.decision === "deny" ? "fail" : "warn"}`}>{e.decision}</span>
                    </td>
                    <td className="small">{e.reason}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </section>

      {asking && (
        <EnableDialog
          flag={asking}
          onCancel={() => setAsking(null)}
          onConfirm={(reason, confirm) => {
            const flag = asking;
            setAsking(null);
            void setFlag(flag, true, reason, confirm);
          }}
        />
      )}
    </div>
  );
}
