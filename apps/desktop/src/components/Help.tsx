import { createContext, useContext } from "react";

import { HELP, type HelpId } from "../lib/help";

export const HelpContext = createContext(false);

/**
 * When Help is on, a card beside a control: what it does, why you would use it, the
 * worst it can do today, and the tests that guard it. When Help is off, nothing.
 */
export function Help({ id }: { readonly id: HelpId }) {
  const on = useContext(HelpContext);
  if (!on) return null;
  const entry = HELP[id];
  return (
    <aside className="help" aria-label={`Help: ${entry.title}`}>
      <div className="help__title">
        <span className="help__icon" aria-hidden="true">
          ?
        </span>
        {entry.title}
      </div>
      <dl className="help__grid">
        <dt>What it does</dt>
        <dd>{entry.what}</dd>
        <dt>Why you'd use it</dt>
        <dd>{entry.why}</dd>
        <dt>Worst it can do</dt>
        <dd>{entry.worst}</dd>
      </dl>
      <details className="help__tests">
        <summary>
          {entry.guards.length} test{entry.guards.length > 1 ? "s" : ""} guard this
        </summary>
        <ul>
          {entry.guards.map((g) => (
            <li key={`${g.file}::${g.test}`} className="mono small">
              {g.file} <span className="muted">::</span> {g.test}
            </li>
          ))}
        </ul>
      </details>
    </aside>
  );
}
