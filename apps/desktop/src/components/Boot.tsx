import { useEffect, useRef, useState } from "react";

import { clunk, hiss, ratchet, refuse } from "../lib/sound";

/**
 * The vault door: the opening sequence.
 *
 * The brief, in my words: "steampunkish locks loading into place ... EPIC VISUALS, and sound." The
 * locks are not decoration. Each one is a real start-up check, and it seats only when
 * that check has actually passed - the Kernel answering from inside its job, the
 * ledger verifying, the self-check running, the switches being read. A lock whose
 * check failed stays open and glows red, and the door opens anyway so you can see
 * why. Any key or click skips the show; "reduce motion" skips it entirely; and a check
 * that never answers cannot keep anyone outside, because the door opens by itself at
 * MAX_MS whatever the locks say.
 */

export type LockState = "turning" | "seated" | "failed";

export interface BootSteps {
  readonly kernel: LockState;
  readonly record: LockState;
  readonly selfcheck: LockState;
  readonly switches: LockState;
}

const LOCKS: { key: keyof BootSteps; word: string; angle: number }[] = [
  { key: "kernel", word: "KERNEL", angle: -90 },
  { key: "record", word: "RECORD", angle: 0 },
  { key: "selfcheck", word: "SELF-CHECK", angle: 90 },
  { key: "switches", word: "SWITCHES", angle: 180 },
];

/** Each lock waits at least this long, so the show reads as a sequence. */
const STAGGER_MS = 520;
const OPEN_MS = 1100;
/** The longest the door may stay shut, answered or not. */
export const MAX_MS = 6000;

export function wantsShow(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function Boot({ steps, onDone }: { readonly steps: BootSteps; readonly onDone: () => void }) {
  const [shown, setShown] = useState<Record<keyof BootSteps, LockState>>({
    kernel: "turning",
    record: "turning",
    selfcheck: "turning",
    switches: "turning",
  });
  const [opening, setOpening] = useState(false);
  const started = useRef(Date.now());
  const finished = useRef(false);

  const finish = () => {
    if (finished.current) return;
    finished.current = true;
    onDone();
  };

  // Seat each lock no sooner than its turn in the sequence, and no sooner than its check.
  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = [];
    LOCKS.forEach(({ key }, i) => {
      const real = steps[key];
      if (real === "turning" || shown[key] !== "turning") return;
      const due = started.current + STAGGER_MS * (i + 1);
      timers.push(
        setTimeout(() => {
          setShown((prev) => ({ ...prev, [key]: real }));
          if (real === "seated") {
            ratchet(4);
            clunk(0.18);
          } else {
            refuse();
          }
        }, Math.max(0, due - Date.now())),
      );
    });
    return () => timers.forEach(clearTimeout);
  }, [steps, shown]);

  // When every lock has an answer, turn the wheel and open the door. This depends on
  // `allDone` alone: it once also depended on `opening`, so setting `opening` re-ran the
  // effect, whose cleanup cancelled `t2` - the door swung open and never let you in.
  const allDone = LOCKS.every(({ key }) => shown[key] !== "turning");
  useEffect(() => {
    if (!allDone) return;
    const t1 = setTimeout(() => {
      setOpening(true);
      ratchet(10);
      hiss(0.35, 1.0);
      clunk(0.5);
    }, 380);
    const t2 = setTimeout(finish, 380 + OPEN_MS);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [allDone]);

  // Any key or click skips the show, and nothing keeps the door shut past MAX_MS.
  useEffect(() => {
    const skip = () => finish();
    window.addEventListener("keydown", skip);
    const ceiling = setTimeout(finish, MAX_MS);
    return () => {
      window.removeEventListener("keydown", skip);
      clearTimeout(ceiling);
    };
  }, []);

  const failed = LOCKS.filter(({ key }) => shown[key] === "failed").length;

  return (
    <div className={`boot${opening ? " boot--opening" : ""}`} role="status" aria-live="polite" onClick={finish}>
      <svg className="boot__door" viewBox="0 0 600 600" aria-hidden="true">
        <defs>
          <radialGradient id="b-door" cx="40%" cy="35%" r="75%">
            <stop offset="0" stopColor="#d9ac52" />
            <stop offset="0.55" stopColor="#8d6420" />
            <stop offset="1" stopColor="#2f1f07" />
          </radialGradient>
          <radialGradient id="b-dial" cx="40%" cy="35%" r="70%">
            <stop offset="0" stopColor="#3b2a12" />
            <stop offset="1" stopColor="#120c05" />
          </radialGradient>
        </defs>
        <circle cx="300" cy="300" r="290" className="boot__frame" />
        <g className="boot__leaf">
          <circle cx="300" cy="300" r="268" fill="url(#b-door)" />
          {Array.from({ length: 32 }, (_, i) => {
            const a = (i / 32) * Math.PI * 2;
            return <circle key={i} cx={300 + 252 * Math.cos(a)} cy={300 + 252 * Math.sin(a)} r="5" className="rivet-dot" />;
          })}
          {[0, 90, 180, 270].map((a) => (
            <g key={a} transform={`rotate(${a} 300 300)`}>
              <rect x="292" y="70" width="16" height="70" rx="5" className={`boot__bolt${opening ? " boot__bolt--open" : ""}`} />
            </g>
          ))}
          <g className={`boot__wheel${opening ? " boot__wheel--turn" : ""}`} style={{ transformOrigin: "300px 300px" }}>
            <circle cx="300" cy="300" r="78" className="boot__wheelrim" />
            {[0, 45, 90, 135].map((a) => (
              <rect key={a} x="294" y="222" width="12" height="156" rx="6" className="boot__spoke" transform={`rotate(${a} 300 300)`} />
            ))}
            <circle cx="300" cy="300" r="22" className="boot__hub" />
          </g>
          {LOCKS.map(({ key, word, angle }) => {
            const rad = (angle * Math.PI) / 180;
            const x = 300 + 170 * Math.cos(rad);
            const y = 300 + 170 * Math.sin(rad);
            const state = shown[key];
            return (
              <g key={key} className={`lock lock--${state}`}>
                <circle cx={x} cy={y} r="44" fill="url(#b-dial)" className="lock__dial" />
                <g className="lock__spin" style={{ transformOrigin: `${x}px ${y}px` }}>
                  {Array.from({ length: 12 }, (_, i) => (
                    <line key={i} x1={x} y1={y - 38} x2={x} y2={y - 31} className="lock__tick" transform={`rotate(${i * 30} ${x} ${y})`} />
                  ))}
                  <polygon points={`${x - 5},${y} ${x + 5},${y} ${x},${y - 34}`} className="lock__pointer" />
                </g>
                <circle cx={x} cy={y} r="9" className="lock__lamp" />
                <text x={x} y={y + 62} textAnchor="middle" className="lock__word">
                  {word}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      <p className="boot__caption">
        {opening
          ? failed
            ? `${failed} lock${failed > 1 ? "s" : ""} would not seat - opening so you can see why`
            : "Every lock seated. Opening."
          : "Sletchy is proving itself..."}
        <span className="boot__skip">press any key to skip</span>
      </p>
    </div>
  );
}
