import type { FlagView } from "../generated/contracts";
import { Help } from "./Help";
import { QUESTION } from "./Instruments";

const ORDER = ["time", "money", "connection", "safety"] as const;

/**
 * My three human questions, on the dashboard: does Sletchy help you save time,
 * make money, or connect with people - with safety as the floor beneath them.
 *
 * Counted honestly from the switches: how many could serve each question, how many
 * are on, and how many are actually connected to anything. Today that last number
 * is zero for all of them, and the plate says so rather than implying otherwise.
 */
export function Questions({ flags }: { readonly flags: readonly FlagView[] }) {
  const rows = ORDER.map((q) => {
    const serving = flags.filter((f) => f.serves.includes(q));
    return {
      q,
      total: serving.length,
      on: serving.filter((f) => f.enabled).length,
      wired: serving.filter((f) => f.wired).length,
    };
  });
  const anyWired = rows.some((r) => r.wired > 0);
  return (
    <section className="plate questions" aria-labelledby="q-title">
      <h2 id="q-title" className="plate__title">
        Does it help you?
      </h2>
      <Help id="questions" />
      <ul className="questions__row">
        {rows.map((r) => (
          <li key={r.q} className={`question question--${r.q}${r.on ? " question--on" : ""}`}>
            <span className="question__glyph" aria-hidden="true">
              {QUESTION[r.q].glyph}
            </span>
            <span className="question__word">{QUESTION[r.q].word}</span>
            <span className="question__count">
              <strong>{r.wired}</strong> working · {r.on} on · {r.total} switches
            </span>
          </li>
        ))}
      </ul>
      {!anyWired && <p className="questions__truth">Honestly: nothing is connected to a working feature yet. The safety floor comes first.</p>}
    </section>
  );
}
