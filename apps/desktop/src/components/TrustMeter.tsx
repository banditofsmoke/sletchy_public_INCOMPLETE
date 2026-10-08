import { band, clamp } from "../lib/meter";

interface Props {
  readonly score: number;
  readonly ceiling: number;
  readonly size?: number;
}

const START = -120; // degrees from 12 o'clock
const SWEEP = 240;
const angle = (v: number) => START + (clamp(v) / 100) * SWEEP;

function tick(cx: number, cy: number, r1: number, r2: number, deg: number) {
  const rad = ((deg - 90) * Math.PI) / 180;
  return {
    x1: cx + r1 * Math.cos(rad),
    y1: cy + r1 * Math.sin(rad),
    x2: cx + r2 * Math.cos(rad),
    y2: cy + r2 * Math.sin(rad),
  };
}

/**
 * The trust meter, as a brass pressure gauge. The needle is what Sletchy proved just
 * now; the red-brass tick on the rim is the best score possible today, so the gap
 * between them reads as "not built yet" rather than as the user's fault.
 */
export function TrustMeter({ score, ceiling, size = 260 }: Props) {
  const c = 100;
  const tone = band(score);
  const label = `Trust meter: ${clamp(score)} out of 100. The highest possible right now is ${clamp(ceiling)}.`;
  const ticks = Array.from({ length: 41 }, (_, i) => i * 2.5);
  const ceil = tick(c, c, 62, 80, angle(ceiling));
  return (
    <svg className={`gauge gauge--${tone}`} width={size} height={size} viewBox="0 0 200 200" role="img" aria-label={label}>
      <defs>
        <radialGradient id="g-bezel" cx="35%" cy="30%" r="80%">
          <stop offset="0" stopColor="#f6dc8a" />
          <stop offset="0.45" stopColor="#b8892d" />
          <stop offset="1" stopColor="#4a3210" />
        </radialGradient>
        <radialGradient id="g-face" cx="50%" cy="40%" r="70%">
          <stop offset="0" stopColor="#f5ead0" />
          <stop offset="1" stopColor="#d9c79c" />
        </radialGradient>
        <linearGradient id="g-glare" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#fff" stopOpacity="0.35" />
          <stop offset="0.5" stopColor="#fff" stopOpacity="0" />
        </linearGradient>
      </defs>
      <circle cx={c} cy={c} r="96" fill="url(#g-bezel)" />
      <circle cx={c} cy={c} r="86" fill="#2a1d0e" />
      <circle cx={c} cy={c} r="83" fill="url(#g-face)" />
      {ticks.map((v) => {
        const major = v % 10 === 0;
        const t = tick(c, c, major ? 66 : 71, 78, angle(v));
        return <line key={v} {...t} className={major ? "gauge__tick gauge__tick--major" : "gauge__tick"} />;
      })}
      {[0, 20, 40, 60, 80, 100].map((v) => {
        const p = tick(c, c, 0, 55, angle(v));
        return (
          <text key={v} x={p.x2} y={p.y2 + 3} className="gauge__num" textAnchor="middle">
            {v}
          </text>
        );
      })}
      {ceiling < 100 && <line {...ceil} className="gauge__ceiling" />}
      <text x={c} y={c + 34} className="gauge__score" textAnchor="middle">
        {clamp(score)}
      </text>
      <text x={c} y={c + 48} className="gauge__caption" textAnchor="middle">
        TRUST · BEST TODAY {clamp(ceiling)}
      </text>
      <g className="gauge__needle" style={{ transform: `rotate(${angle(score)}deg)`, transformOrigin: "100px 100px" }}>
        <polygon points="97,104 103,104 100,26" fill="#1b1209" />
        <polygon points="98.6,40 101.4,40 100,26" fill="#c23b2c" />
      </g>
      <circle cx={c} cy={c} r="8" fill="url(#g-bezel)" stroke="#3a270c" />
      <circle cx={c} cy={c} r="83" fill="url(#g-glare)" pointerEvents="none" />
    </svg>
  );
}
