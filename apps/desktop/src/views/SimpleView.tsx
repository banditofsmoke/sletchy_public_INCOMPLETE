import { useState } from "react";

import { EnableDialog } from "../components/EnableDialog";
import { Help } from "../components/Help";
import { HoldButton } from "../components/HoldButton";
import { Lamps, Lever } from "../components/Instruments";
import { Orrery } from "../components/Orrery";
import { Questions } from "../components/Questions";
import { TalkPlate } from "../components/TalkPlate";
import { TrustMeter } from "../components/TrustMeter";
import type { FlagView } from "../generated/contracts";
import { describe } from "../lib/activity";
import type { Sample } from "../lib/noc";
import { relative } from "../lib/time";
import type { SletchyActions, SletchyState } from "../lib/useSletchy";

type Props = SletchyState &
  Pick<SletchyActions, "setFlag" | "setUp" | "runPanic" | "recheck" | "refresh"> & { readonly noc: readonly Sample[] };

function verdict(failures: number, warnings: number, score: number, ceiling: number): string {
  if (failures) return "Look at this";
  if (warnings) return "Running, with a warning";
  return score >= ceiling ? "All proven" : "Running";
}

/** The instrument panel: gauge, orrery, levers, valve. Words live in Help. */
export function SimpleView(props: Props) {
  const { status, selfcheck, flags, ledger, setFlag, setUp, runPanic, recheck, refresh, noc } = props;
  const localModels = flags.find((f) => f.name === "mind_local_models")?.enabled ?? false;
  const [asking, setAsking] = useState<FlagView | null>(null);
  const [busy, setBusy] = useState(false);
  const notSetUp = status?.ledger_state === "not_initialised";
  const shown = flags.filter((f) => f.risk !== "safe");
  const hidden = flags.length - shown.length;
  const failures = selfcheck?.checks.filter((c) => c.status === "fail").length ?? 0;
  const warnings = selfcheck?.checks.filter((c) => c.status === "warn").length ?? 0;
  const procs = noc.at(-1)?.procs ?? [];

  const toggle = async (flag: FlagView, next: boolean) => {
    if (next && flag.risk === "dangerous") {
      setAsking(flag);
      return;
    }
    setBusy(true);
    await setFlag(flag, next);
    setBusy(false);
  };

  return (
    <div className="panel panel--simple">
      {notSetUp && (
        <section className="plate setup area-setup">
          <h2 className="plate__title">Sletchy isn't set up on this computer yet</h2>
          <button type="button" className="btn btn--brass btn--big" onClick={() => void setUp()}>
            Set up Sletchy
          </button>
          <Help id="setup" />
        </section>
      )}

      <section className="plate area-gauge" aria-labelledby="meter-title">
        <h2 id="meter-title" className="plate__title">
          {selfcheck ? verdict(failures, warnings, selfcheck.score, selfcheck.ceiling) : "Checking..."}
        </h2>
        <div className="gauge-wrap">
          {selfcheck ? <TrustMeter score={selfcheck.score} ceiling={selfcheck.ceiling} /> : <div className="gauge-skeleton" />}
        </div>
        {selfcheck && <Lamps checks={selfcheck.checks} />}
        <div className="row row--center">
          <button type="button" className="btn btn--brass" onClick={() => void recheck()}>
            Check again
          </button>
        </div>
        <Help id="meter" />
        <Help id="recheck" />
        {selfcheck && (
          <details className="limits">
            <summary>What this does not prove</summary>
            <ul>
              {selfcheck.does_not_prove.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </details>
        )}
      </section>

      <section className="plate plate--porthole area-orrery" aria-label="Inside the vault">
        <Orrery flags={flags} entries={ledger?.entries ?? []} procs={procs} ledgerCount={status?.entries ?? null} />
        <Help id="orrery" />
      </section>

      {shown.length > 0 && (
        <section className="plate area-levers" aria-labelledby="switches-title">
          <h2 id="switches-title" className="plate__title">
            Switches <span className="plate__hint">all start off</span>
          </h2>
          <Help id="switches" />
          <Help id="dangerous" />
          <div className="levers">
            {shown.map((flag) => (
              <Lever key={flag.name} flag={flag} disabled={busy} onChange={(next) => void toggle(flag, next)} />
            ))}
          </div>
          {hidden > 0 && (
            <p className="plate__foot">
              {hidden} terminal setting{hidden > 1 ? "s are" : " is"} in Custom.
            </p>
          )}
        </section>
      )}

      {!notSetUp && <TalkPlate switchedOn={localModels} onAnswered={() => void refresh()} />}

      <div className="area-questions">
        <Questions flags={flags} />
      </div>

      <section className="plate stop area-stop" aria-labelledby="stop-title">
        <h2 id="stop-title" className="plate__title">
          Stop everything
        </h2>
        <HoldButton variant="valve" label="Hold to stop everything" holdingLabel="Turning..." onHold={() => void runPanic()} />
        <Help id="stop" />
      </section>

      {ledger && (
        <section className="plate ticker area-ticker" aria-labelledby="activity-title">
          <h2 id="activity-title" className="plate__title">
            Recent activity
          </h2>
          <Help id="activity" />
          {ledger.entries.length === 0 ? (
            <p className="muted">Nothing yet.</p>
          ) : (
            <ul className="ticker__items">
              {[...ledger.entries]
                .reverse()
                .slice(0, 8)
                .map((e) => (
                  <li key={e.seq}>
                    <span>{describe(e, flags)}</span>
                    <time dateTime={e.ts}>{relative(e.ts)}</time>
                  </li>
                ))}
            </ul>
          )}
        </section>
      )}

      {asking && (
        <EnableDialog
          flag={asking}
          onCancel={() => setAsking(null)}
          onConfirm={async (reason, confirm) => {
            const flag = asking;
            setAsking(null);
            setBusy(true);
            await setFlag(flag, true, reason, confirm);
            setBusy(false);
          }}
        />
      )}
    </div>
  );
}
