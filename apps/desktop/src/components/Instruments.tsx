import type { Check, FlagView } from "../generated/contracts";
import { click } from "../lib/sound";

/* ── lamps: one glass bulb per self-check ─────────────────────────────────── */

const LAMP_WORD: Record<string, string> = {
  ledger: "Record",
  switches: "Switches",
  privilege: "User",
  files: "Files",
  network: "Network",
  leftovers: "Leftovers",
  disk: "Disk",
};

const STATUS_ICON: Record<Check["status"], string> = { pass: "✓", warn: "!", fail: "✕", unmeasured: "?" };
const STATUS_WORD: Record<Check["status"], string> = {
  pass: "proven",
  warn: "look at this",
  fail: "problem",
  unmeasured: "not measured yet",
};

export function Lamps({ checks }: { readonly checks: readonly Check[] }) {
  return (
    <ul className="lamps" aria-label="Self-check lamps">
      {checks.map((c) => (
        <li key={c.id} className={`lamp lamp--${c.status}`} title={c.plain}>
          <span className="lamp__bulb" aria-hidden="true">
            {STATUS_ICON[c.status]}
          </span>
          <span className="lamp__word">{LAMP_WORD[c.id] ?? c.label}</span>
          <span className="sr-only">
            {c.label}: {STATUS_WORD[c.status]}. {c.plain}
          </span>
        </li>
      ))}
    </ul>
  );
}

/* ── the three questions, as engraved glyphs ──────────────────────────────── */

export const QUESTION: Record<FlagView["serves"][number], { glyph: string; word: string }> = {
  time: { glyph: "⏱", word: "Saves time" },
  money: { glyph: "¤", word: "Makes money" },
  connection: { glyph: "♥", word: "Connects people" },
  safety: { glyph: "⛨", word: "Keeps you safe" },
};

export function Serves({ serves }: { readonly serves: FlagView["serves"] }) {
  return (
    <span className="serves">
      {serves.map((q) => (
        <span key={q} className={`serves__glyph serves__glyph--${q}`} title={QUESTION[q].word} aria-label={QUESTION[q].word}>
          {QUESTION[q].glyph}
        </span>
      ))}
    </span>
  );
}

/* ── a lever: the switch ──────────────────────────────────────────────────── */

export function Lever({
  flag,
  disabled = false,
  onChange,
}: {
  readonly flag: FlagView;
  readonly disabled?: boolean;
  readonly onChange: (next: boolean) => void;
}) {
  return (
    <div className={`lever${flag.enabled ? " lever--on" : ""} lever--${flag.risk}`} title={flag.description}>
      <button
        type="button"
        role="switch"
        aria-checked={flag.enabled}
        aria-label={`${flag.label}: ${flag.enabled ? "on" : "off"}`}
        disabled={disabled}
        className="lever__slot"
        onClick={() => {
          click(0, flag.enabled ? 2200 : 3000);
          onChange(!flag.enabled);
        }}
      >
        <span className="lever__arm" aria-hidden="true">
          <span className="lever__knob" />
        </span>
      </button>
      <div className="lever__plate">
        <span className="lever__label">{flag.label}</span>
        <span className="lever__meta">
          {flag.risk === "dangerous" && <span className="rivet rivet--red" title="Dangerous" aria-label="Dangerous" />}
          {flag.risk === "elevated" && <span className="rivet rivet--amber" title="Uses this computer" aria-label="Uses this computer" />}
          <Serves serves={flag.serves} />
        </span>
        {!flag.wired && <span className="lever__idle">Not connected yet</span>}
      </div>
    </div>
  );
}

/* ── small charts: a sparkline and a meter against a ceiling ──────────────── */

export function Sparkline({
  values,
  label,
  unit,
  width = 160,
  height = 36,
}: {
  readonly values: readonly number[];
  readonly label: string;
  readonly unit: string;
  readonly width?: number;
  readonly height?: number;
}) {
  const last = values.at(-1);
  if (values.length < 2 || last === undefined) {
    return <div className="spark spark--empty">{label}: collecting...</div>;
  }
  const max = Math.max(...values, 1e-9);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const x = (i: number) => (i / (values.length - 1)) * (width - 4) + 2;
  const y = (v: number) => height - 3 - ((v - min) / span) * (height - 8);
  const points = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const fmt = (v: number) => `${v < 10 ? v.toFixed(1) : Math.round(v)}${unit}`;
  return (
    <figure className="spark">
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${label}: now ${fmt(last)}, highest ${fmt(max)}`}>
        <line x1="0" x2={width} y1={height - 3} y2={height - 3} className="spark__base" />
        <polyline points={points} className="spark__line" />
        <circle cx={x(values.length - 1)} cy={y(last)} r="3" className="spark__dot">
          <title>{fmt(last)}</title>
        </circle>
      </svg>
      <figcaption>
        <span>{label}</span>
        <strong>{fmt(last)}</strong>
      </figcaption>
    </figure>
  );
}

export function Meter({ value, max, label, format }: { readonly value: number; readonly max: number; readonly label: string; readonly format: (n: number) => string }) {
  const share = Math.min(1, Math.max(0, max ? value / max : 0));
  const tone = share < 0.6 ? "ok" : share < 0.85 ? "warn" : "bad";
  return (
    <div className={`meter-bar meter-bar--${tone}`} role="meter" aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} aria-label={label}>
      <div className="meter-bar__head">
        <span>{label}</span>
        <strong>
          {format(value)} <span className="muted">/ {format(max)}</span>
        </strong>
      </div>
      <div className="meter-bar__track">
        <div className="meter-bar__fill" style={{ width: `${(share * 100).toFixed(1)}%` }} />
      </div>
    </div>
  );
}

/**
 * A bar for a wait nobody reports the end of (#207): a model loading, or thinking. The
 * model server says nothing until it is done, so the bar fills against how long the same
 * thing took last time and stops short of the end until it is. The first time, and once
 * it runs past last time, the bar moves without a value, and says why.
 */
export function Waiting({ label, seconds, expected }: { readonly label: string; readonly seconds: number; readonly expected: number | null }) {
  const against = expected !== null && seconds <= expected ? expected : null;
  const share = against !== null ? Math.min(0.95, seconds / against) : 0;
  const said =
    expected === null
      ? "No estimate yet: this time is measured for the next."
      : against !== null
        ? `About ${Math.round(expected)} s, from last time.`
        : `Longer than last time (${Math.round(expected)} s).`;
  return (
    <div
      className={`wait${against === null ? " wait--moving" : ""}`}
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={against !== null ? Math.round(share * 100) : undefined}
    >
      <div className="wait__head">
        <span>{label}</span>
        <span>{said}</span>
      </div>
      <div className="meter-bar__track">
        <div className="wait__fill" style={against !== null ? { width: `${(share * 100).toFixed(1)}%` } : undefined} />
      </div>
    </div>
  );
}
