import type { Check, FlagView } from "../generated/contracts";
import { dismiss, useToasts } from "../lib/store";

export function Logo({ size = 28 }: { readonly size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" className="logo">
      <circle cx="32" cy="32" r="30" className="logo__body" />
      <path className="logo__ring" d="M 47.6 49.6 A 24 24 0 1 1 49.6 47.6" />
      <circle cx="32" cy="32" r="8" className="logo__core" />
    </svg>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  readonly checked: boolean;
  readonly onChange: (next: boolean) => void;
  readonly label: string;
  readonly disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className={`switch${checked ? " switch--on" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span className="switch__knob" aria-hidden="true" />
    </button>
  );
}

export function RiskBadge({ risk }: { readonly risk: FlagView["risk"] }) {
  const text = { safe: "Safe", elevated: "Uses this computer", dangerous: "Dangerous" }[risk];
  return <span className={`badge badge--${risk}`}>{text}</span>;
}

const STATUS_TEXT: Record<Check["status"], { icon: string; word: string }> = {
  pass: { icon: "✓", word: "Proven" },
  warn: { icon: "!", word: "Look at this" },
  fail: { icon: "✕", word: "Problem" },
  unmeasured: { icon: "?", word: "Not measured yet" },
};

export function StatusChip({ status }: { readonly status: Check["status"] }) {
  const s = STATUS_TEXT[status];
  return (
    <span className={`chip chip--${status}`}>
      <span aria-hidden="true">{s.icon}</span> {s.word}
    </span>
  );
}

export function Toasts() {
  const toasts = useToasts();
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast toast--${t.tone}`}>
          <div className="toast__text">
            <strong>{t.title}</strong>
            {t.body && <p>{t.body}</p>}
          </div>
          <button type="button" className="toast__close" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
