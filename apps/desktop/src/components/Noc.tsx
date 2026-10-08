import type { EntryView } from "../generated/contracts";
import { cpuPercent, mb, sum, type Sample } from "../lib/noc";
import { Meter, Sparkline } from "./Instruments";
import { PLANE_COLOR } from "./Orrery";

const PLANES = ["kernel", "warden", "soc", "mind", "senses", "forge", "vault"] as const;

/** Ledger entries by plane, as one part-to-whole bar, legend always shown. */
export function PlaneBar({ entries }: { readonly entries: readonly EntryView[] }) {
  const counts = PLANES.map((p) => ({ plane: p, n: entries.filter((e) => e.plane === p).length })).filter((c) => c.n > 0);
  const total = counts.reduce((s, c) => s + c.n, 0);
  if (!total) return <p className="muted small">No ledger entries in this window yet.</p>;
  return (
    <figure className="planebar">
      <figcaption>Where the last {total} ledger entries came from</figcaption>
      <div className="planebar__track" role="img" aria-label={counts.map((c) => `${c.plane} ${c.n}`).join(", ")}>
        {counts.map((c) => (
          <div key={c.plane} className="planebar__seg" style={{ flexGrow: c.n, background: PLANE_COLOR[c.plane] }} title={`${c.plane}: ${c.n}`} />
        ))}
      </div>
      <ul className="legend">
        {counts.map((c) => (
          <li key={c.plane}>
            <span className="legend__swatch" style={{ background: PLANE_COLOR[c.plane] }} />
            {c.plane} <strong>{c.n}</strong>
          </li>
        ))}
      </ul>
    </figure>
  );
}

/** Everything Sletchy is running, with the Kernel's job against its ceilings. */
export function Noc({ samples, latencies }: { readonly samples: readonly Sample[]; readonly latencies: readonly number[] }) {
  const now = samples.at(-1);
  if (!now) return <p className="muted">Reading the process table...</p>;
  const kernelCpu = samples.slice(1).map((s, i) => cpuPercent(samples[i], s, "kernel") ?? 0);
  const windowCpu = samples.slice(1).map((s, i) => cpuPercent(samples[i], s, "window") ?? 0);
  const kernelMem = samples.map((s) => sum(s.procs, "kernel", "memory_bytes") / 1024 ** 2);
  const limits = now.limits;
  const active = now.job?.active_processes ?? now.procs.filter((p) => p.role === "kernel").length;
  return (
    <div className="noc">
      <div className="noc__tiles">
        {limits ? (
          <>
            <Meter label="Kernel processes in the job" value={active} max={limits.active_processes} format={(n) => String(n)} />
            <Meter label="Kernel memory, peak" value={now.job?.peak_memory_bytes ?? 0} max={limits.memory_bytes} format={mb} />
          </>
        ) : (
          <p className="muted small">The Kernel is not running inside a job right now{now.running ? "" : " (it starts with the first request)"}.</p>
        )}
        <Sparkline label="Kernel CPU" unit="%" values={kernelCpu} />
        <Sparkline label="Window CPU" unit="%" values={windowCpu} />
        <Sparkline label="Kernel memory" unit=" MB" values={kernelMem} />
        <Sparkline label="Request time" unit=" ms" values={latencies} />
      </div>
      <div className="table-wrap">
        <table className="table table--dense">
          <caption className="sr-only">Every process Sletchy is running</caption>
          <thead>
            <tr>
              <th>Role</th>
              <th>Process</th>
              <th className="num">PID</th>
              <th className="num">Parent</th>
              <th className="num">Threads</th>
              <th className="num">Memory</th>
              <th className="num">CPU time</th>
              <th>In the job</th>
            </tr>
          </thead>
          <tbody>
            {now.procs.map((p) => (
              <tr key={p.pid}>
                <td>
                  <span className={`role role--${p.role}`}>{p.role}</span>
                </td>
                <td className="mono">{p.name}</td>
                <td className="num mono">{p.pid}</td>
                <td className="num mono">{p.ppid}</td>
                <td className="num">{p.threads}</td>
                <td className="num">{mb(p.memory_bytes)}</td>
                <td className="num">{(p.cpu_ms / 1000).toFixed(1)} s</td>
                <td>{p.in_job ? "✓ yes" : <span className="muted">no</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="small muted">
        Only Sletchy's own processes: the window, its renderers, and the Kernel. Watching the rest of this computer is the
        SOC's job, and it is not built yet.
      </p>
    </div>
  );
}
