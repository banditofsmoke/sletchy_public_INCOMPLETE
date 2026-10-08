import { useEffect, useRef, useState } from "react";

import type { EntryView, FlagView } from "../generated/contracts";
import type { Proc } from "../lib/noc";

/**
 * The Orrery: Sletchy's architecture, live, seen through the vault's porthole.
 *
 * The Kernel is the core, and every ledger entry flies into it. The Warden and the
 * SOC are the middle ring. The Mind, Senses, Forge and Vault are the outer ring.
 * The gap in the outer ring is the one door - nothing gets in or out except through
 * the Warden. Each switch is a lamp on the ring of the plane it belongs to; each
 * Kernel process is a bead orbiting the core.
 */

export const PLANE_COLOR: Record<string, string> = {
  kernel: "var(--plane-kernel)",
  warden: "var(--plane-warden)",
  soc: "var(--plane-soc)",
  mind: "var(--plane-mind)",
  senses: "var(--plane-senses)",
  forge: "var(--plane-forge)",
  vault: "var(--plane-other)",
};

/** Which plane a switch belongs to, by its name. */
export function planeOf(flag: string): string {
  if (flag.startsWith("egress") || flag.startsWith("fs_")) return "warden";
  if (flag.startsWith("honeypot") || flag.startsWith("soc")) return "soc";
  if (flag.startsWith("senses")) return "senses";
  if (flag.startsWith("forge")) return "forge";
  if (flag.startsWith("vault")) return "vault";
  if (flag.startsWith("mind")) return "mind";
  return "kernel";
}

const C = 300;
const R_CORE = 64;
const R_INNER = 150;
const R_OUTER = 222;

/** Angle ranges (degrees, 0 = 12 o'clock, clockwise) each plane occupies on its ring. */
const ARCS: Record<string, { r: number; from: number; to: number }> = {
  warden: { r: R_INNER, from: -80, to: 80 },
  soc: { r: R_INNER, from: 100, to: 260 },
  mind: { r: R_OUTER, from: 62, to: 145 },
  senses: { r: R_OUTER, from: 152, to: 230 },
  forge: { r: R_OUTER, from: 237, to: 315 },
  vault: { r: R_OUTER, from: 322, to: 380 },
  kernel: { r: R_CORE + 22, from: 0, to: 360 },
};
const DOOR = 45; // the gate in the outer ring

function at(r: number, deg: number) {
  const rad = ((deg - 90) * Math.PI) / 180;
  return { x: C + r * Math.cos(rad), y: C + r * Math.sin(rad) };
}

function arc(r: number, from: number, to: number): string {
  const a = at(r, from);
  const b = at(r, to);
  const large = to - from > 180 ? 1 : 0;
  return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} A ${r} ${r} 0 ${large} 1 ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
}

function gear(cx: number, cy: number, r: number, teeth: number): string {
  const pts: string[] = [];
  for (let i = 0; i < teeth * 2; i++) {
    const rr = i % 2 === 0 ? r : r * 0.86;
    const a1 = (i / (teeth * 2)) * Math.PI * 2;
    const a2 = ((i + 1) / (teeth * 2)) * Math.PI * 2;
    pts.push(`${(cx + rr * Math.cos(a1)).toFixed(1)},${(cy + rr * Math.sin(a1)).toFixed(1)}`);
    pts.push(`${(cx + rr * Math.cos(a2)).toFixed(1)},${(cy + rr * Math.sin(a2)).toFixed(1)}`);
  }
  return `M ${pts.join(" L ")} Z`;
}

interface Pulse {
  readonly id: number;
  readonly plane: string;
  readonly x: number;
  readonly y: number;
}

export function Orrery({
  flags,
  entries,
  procs,
  ledgerCount,
}: {
  readonly flags: readonly FlagView[];
  readonly entries: readonly EntryView[];
  readonly procs: readonly Proc[];
  readonly ledgerCount: number | null;
}) {
  const [pulses, setPulses] = useState<readonly Pulse[]>([]);
  const lastSeq = useRef<number | null>(null);

  // A new ledger entry flies from its plane's ring into the core.
  useEffect(() => {
    const newest = entries.at(-1)?.seq ?? null;
    if (lastSeq.current !== null && newest !== null && newest > lastSeq.current) {
      const fresh = entries.filter((e) => e.seq > (lastSeq.current ?? -1)).slice(-6);
      const born = fresh.map((e, i) => {
        const where = ARCS[e.plane] ?? ARCS.kernel!;
        const p = at(where.r, (where.from + where.to) / 2 + i * 9);
        return { id: e.seq, plane: e.plane, x: p.x - C, y: p.y - C };
      });
      setPulses((prev) => [...prev, ...born]);
      const ids = new Set(born.map((b) => b.id));
      setTimeout(() => setPulses((prev) => prev.filter((p) => !ids.has(p.id))), 1600);
    }
    lastSeq.current = newest;
  }, [entries]);

  const lamps = flags.map((f) => {
    const plane = planeOf(f.name);
    const where = ARCS[plane] ?? ARCS.kernel!;
    const siblings = flags.filter((g) => planeOf(g.name) === plane);
    const i = siblings.indexOf(f);
    const step = (where.to - where.from) / (siblings.length + 1);
    const deg = plane === "kernel" ? 200 + i * 18 : where.from + step * (i + 1);
    return { flag: f, plane, ...at(where.r, deg) };
  });

  const kernelProcs = procs.filter((p) => p.role === "kernel");
  const door = at(R_OUTER, DOOR);

  return (
    <svg className="orrery" viewBox="0 0 600 600" role="img" aria-label={`Sletchy's architecture, live: ${kernelProcs.length} kernel processes, ${flags.filter((f) => f.enabled).length} switches on, ${ledgerCount ?? 0} ledger entries`}>
      <defs>
        <radialGradient id="o-bezel" cx="40%" cy="35%" r="75%">
          <stop offset="0" stopColor="#f3d27a" />
          <stop offset="0.5" stopColor="#a87a26" />
          <stop offset="1" stopColor="#3e2a0b" />
        </radialGradient>
        <radialGradient id="o-glass" cx="50%" cy="45%" r="60%">
          <stop offset="0" stopColor="#123a3a" />
          <stop offset="0.7" stopColor="#0a1f22" />
          <stop offset="1" stopColor="#050c0e" />
        </radialGradient>
        <radialGradient id="o-core" cx="45%" cy="40%" r="60%">
          <stop offset="0" stopColor="#ffe08a" />
          <stop offset="0.55" stopColor="#c8932f" />
          <stop offset="1" stopColor="#5a3c10" />
        </radialGradient>
        <linearGradient id="o-glare" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fff" stopOpacity="0.16" />
          <stop offset="0.4" stopColor="#fff" stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* clockwork behind the porthole */}
      <g className="orrery__gears" aria-hidden="true">
        <path d={gear(70, 80, 58, 14)} className="gearwork gearwork--cw" style={{ transformOrigin: "70px 80px" }} />
        <path d={gear(540, 520, 64, 16)} className="gearwork gearwork--ccw" style={{ transformOrigin: "540px 520px" }} />
        <path d={gear(548, 92, 34, 10)} className="gearwork gearwork--cw" style={{ transformOrigin: "548px 92px" }} />
      </g>

      <circle cx={C} cy={C} r="286" fill="url(#o-bezel)" />
      {Array.from({ length: 24 }, (_, i) => {
        const p = at(272, i * 15);
        return <circle key={i} cx={p.x} cy={p.y} r="4" className="rivet-dot" />;
      })}
      <circle cx={C} cy={C} r="258" fill="url(#o-glass)" />
      {[R_OUTER + 18, R_INNER + 30, R_CORE + 40].map((r) => (
        <circle key={r} cx={C} cy={C} r={r} className="orrery__hairline" />
      ))}

      {/* the rings, one arc per plane, engraved */}
      {Object.entries(ARCS)
        .filter(([plane]) => plane !== "kernel")
        .map(([plane, { r, from, to }]) => (
          <g key={plane}>
            <path d={arc(r, from, to)} className="orrery__arc" style={{ stroke: PLANE_COLOR[plane] }} />
            <path id={`label-${plane}`} d={arc(r + 18, from + 4, to - 4)} fill="none" />
            <text className="orrery__label">
              <textPath href={`#label-${plane}`} startOffset="50%" textAnchor="middle">
                {plane.toUpperCase()}
              </textPath>
            </text>
          </g>
        ))}

      {/* the one door */}
      <g className="orrery__door">
        <line x1={door.x} y1={door.y} x2={at(R_INNER, DOOR).x} y2={at(R_INNER, DOOR).y} />
        <rect x={door.x - 9} y={door.y - 9} width="18" height="18" rx="3" transform={`rotate(${DOOR} ${door.x} ${door.y})`} />
        <text x={door.x + 16} y={door.y - 12} className="orrery__small">
          THE ONE DOOR
        </text>
      </g>

      {/* the core: the Kernel and its ledger */}
      <path d={gear(C, C, R_CORE + 10, 22)} className="orrery__coregear gearwork--cw" style={{ transformOrigin: `${C}px ${C}px` }} />
      <circle cx={C} cy={C} r={R_CORE} fill="url(#o-core)" className="orrery__core" />
      <text x={C} y={C - 6} className="orrery__corelabel" textAnchor="middle">
        KERNEL
      </text>
      <text x={C} y={C + 18} className="orrery__corecount" textAnchor="middle">
        {ledgerCount ?? "-"}
      </text>
      <text x={C} y={C + 32} className="orrery__small" textAnchor="middle">
        LEDGER ENTRIES
      </text>

      {/* kernel processes orbit the core */}
      <g className="orrery__orbit" style={{ transformOrigin: `${C}px ${C}px` }}>
        {kernelProcs.map((p, i) => {
          const q = at(R_CORE + 22, (360 / Math.max(1, kernelProcs.length)) * i);
          return (
            <circle key={p.pid} cx={q.x} cy={q.y} r="6" className="orrery__proc">
              <title>
                {p.name} · pid {p.pid} · {p.threads} threads · inside the job
              </title>
            </circle>
          );
        })}
      </g>

      {/* every switch is a lamp on its plane's ring */}
      {lamps.map(({ flag, x, y }) => (
        <g key={flag.name} className={`orrery__lamp${flag.enabled ? " orrery__lamp--on" : ""} orrery__lamp--${flag.risk}`}>
          <circle cx={x} cy={y} r="8" />
          <title>
            {flag.label}: {flag.enabled ? "on" : "off"}
            {flag.wired ? "" : " (not connected yet)"}
          </title>
        </g>
      ))}

      {/* ledger pulses fly to the core */}
      {pulses.map((p) => (
        <circle
          key={`pulse-${p.id}`}
          cx={C}
          cy={C}
          r="7"
          className="orrery__pulse"
          style={{ ["--dx" as string]: `${p.x}px`, ["--dy" as string]: `${p.y}px`, fill: PLANE_COLOR[p.plane] ?? PLANE_COLOR.kernel }}
        />
      ))}

      <circle cx={C} cy={C} r="258" fill="url(#o-glare)" pointerEvents="none" />
    </svg>
  );
}
