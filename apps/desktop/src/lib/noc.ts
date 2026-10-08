// The NOC's numbers: Sletchy's own processes and its Kernel's job, sampled every few
// seconds from the shell, with a short history so the window can draw trends.

import { useEffect, useRef, useState } from "react";

import { bridgeInfo } from "../api";

export interface Proc {
  readonly pid: number;
  readonly ppid: number;
  readonly name: string;
  readonly threads: number;
  readonly cpu_ms: number;
  readonly memory_bytes: number;
  readonly private_bytes: number;
  readonly in_job: boolean;
  readonly role: "window" | "webview" | "kernel" | "other";
}

export interface JobStats {
  readonly active_processes: number;
  readonly total_processes: number;
  readonly cpu_ms: number;
  readonly peak_memory_bytes: number;
}

export interface Sample {
  readonly at: number;
  readonly procs: readonly Proc[];
  readonly job: JobStats | null;
  readonly limits: { readonly memory_bytes: number; readonly active_processes: number } | null;
  readonly running: boolean;
  readonly pid: number | null;
}

export const HISTORY = 60;

function asProcs(value: unknown): Proc[] {
  return Array.isArray(value) ? (value as Proc[]) : [];
}

export function toSample(info: Record<string, unknown>, at = Date.now()): Sample {
  return {
    at,
    procs: asProcs(info.processes),
    job: (info.job as JobStats | null | undefined) ?? null,
    limits: (info.limits as Sample["limits"] | undefined) ?? null,
    running: info.running === true,
    pid: typeof info.pid === "number" ? info.pid : null,
  };
}

export function sum(procs: readonly Proc[], role: Proc["role"], key: "memory_bytes" | "threads" | "cpu_ms"): number {
  return procs.filter((p) => p.role === role).reduce((total, p) => total + p[key], 0);
}

/** CPU as a percentage of one core, from two samples of cumulative CPU time. */
export function cpuPercent(prev: Sample | undefined, next: Sample, role: Proc["role"]): number | null {
  if (!prev) return null;
  const wall = next.at - prev.at;
  if (wall <= 0) return null;
  const used = sum(next.procs, role, "cpu_ms") - sum(prev.procs, role, "cpu_ms");
  return Math.max(0, (used / wall) * 100);
}

export function mb(bytes: number): string {
  return bytes >= 1024 ** 3 ? `${(bytes / 1024 ** 3).toFixed(1)} GB` : `${Math.round(bytes / 1024 ** 2)} MB`;
}

/** Sample the shell every `ms`, keeping the last `HISTORY` samples. */
export function useNoc(ms = 2000): readonly Sample[] {
  const [samples, setSamples] = useState<readonly Sample[]>([]);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    // One reading at a time. While the Kernel is busy (a model thinking for minutes),
    // the shell holds every request, so a tick that is still waiting means skip this
    // one, never queue another behind it.
    let waiting = false;
    const tick = async () => {
      if (waiting) return;
      waiting = true;
      try {
        const info = await bridgeInfo();
        if (alive.current) setSamples((prev) => [...prev, toSample(info)].slice(-HISTORY));
      } finally {
        waiting = false;
      }
    };
    void tick();
    const id = setInterval(() => void tick(), ms);
    return () => {
      alive.current = false;
      clearInterval(id);
    };
  }, [ms]);
  return samples;
}
