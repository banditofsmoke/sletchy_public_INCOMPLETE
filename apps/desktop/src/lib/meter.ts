// Geometry for the trust meter: a 240-degree gauge, open at the bottom.

export const START_DEG = 150; // bottom-left, measured clockwise from 3 o'clock
export const SWEEP_DEG = 240;

export interface Point {
  readonly x: number;
  readonly y: number;
}

export function clamp(value: number, lo = 0, hi = 100): number {
  return Math.min(hi, Math.max(lo, Number.isFinite(value) ? value : lo));
}

export function polar(cx: number, cy: number, r: number, deg: number): Point {
  const rad = (deg * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

export function angleFor(value: number): number {
  return START_DEG + (clamp(value) / 100) * SWEEP_DEG;
}

/** An SVG arc from 0 to `value` (0-100). Empty for zero, so nothing draws. */
export function arcPath(cx: number, cy: number, r: number, value: number): string {
  const v = clamp(value);
  if (v <= 0) return "";
  const end = polar(cx, cy, r, angleFor(v));
  const start = polar(cx, cy, r, START_DEG);
  const large = (v / 100) * SWEEP_DEG > 180 ? 1 : 0;
  const f = (n: number) => n.toFixed(2);
  return `M ${f(start.x)} ${f(start.y)} A ${r} ${r} 0 ${large} 1 ${f(end.x)} ${f(end.y)}`;
}

export type Band = "strong" | "fair" | "low";

/** How the score reads. Judged against 100, not against the ceiling: an unbuilt
 * control is a real gap, and the colour should not hide it. */
export function band(score: number): Band {
  const s = clamp(score);
  if (s >= 80) return "strong";
  if (s >= 50) return "fair";
  return "low";
}

export function headline(score: number, ceiling: number, failures: number): string {
  if (failures > 0) return "Something needs your attention.";
  if (score >= ceiling) return "Everything Sletchy can prove right now is fine.";
  return "Sletchy is working, with a few things to look at.";
}
