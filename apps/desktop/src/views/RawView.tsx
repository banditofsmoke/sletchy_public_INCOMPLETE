import { useEffect, useState } from "react";

import { bridgeInfo, call } from "../api";
import { Help } from "../components/Help";
import { METHOD_NAMES, type MethodName } from "../generated/contracts";
import { clearTranscript, useTranscript } from "../lib/store";

const pretty = (value: unknown) => JSON.stringify(value, null, 2);

/** The JSON, for developers. Same allowlist, same checks: Raw is a view, not a back door. */
export function RawView({ onChanged }: { readonly onChanged: () => void }) {
  const transcript = useTranscript();
  const [method, setMethod] = useState<MethodName>("status");
  const [params, setParams] = useState("{}");
  const [answer, setAnswer] = useState<unknown>(null);
  const [info, setInfo] = useState<Record<string, unknown> | null>(null);
  let parseError: string | null = null;
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(params);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) parseError = "params must be a JSON object";
  } catch (err) {
    parseError = (err as Error).message;
  }

  const loadInfo = async () => setInfo(await bridgeInfo());
  useEffect(() => {
    void loadInfo();
  }, []);

  const send = async () => {
    if (parseError) return;
    // The cast is deliberate: Raw lets a developer send anything, and the bridge -
    // not this screen - is what refuses it.
    const out = await call(method, parsed as never);
    setAnswer(out);
    if (method === "flags.set" || method.startsWith("stop.") || method === "init") onChanged();
  };

  return (
    <div className="raw">
      <section className="card">
        <h2>Console</h2>
        <p className="small muted">
          Requests go through the Rust allowlist and then the Kernel's own. Raw is a view, not a back door: a
          dangerous switch still needs a reason and its name.
        </p>
        <Help id="console" />
        <form
          className="console"
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <label className="field">
            <span>Method</span>
            <select value={method} onChange={(e) => setMethod(e.target.value as MethodName)}>
              {METHOD_NAMES.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Params (JSON)</span>
            <textarea className="mono" rows={5} spellCheck={false} value={params} aria-invalid={parseError !== null} onChange={(e) => setParams(e.target.value)} />
          </label>
          {parseError && <p className="bad-text small">{parseError}</p>}
          <button type="submit" className="btn btn--accent" disabled={parseError !== null}>
            Send
          </button>
        </form>
        {answer !== null && <pre className="json">{pretty(answer)}</pre>}
      </section>

      <section className="card">
        <header className="card__head">
          <h2>Bridge</h2>
          <button type="button" className="btn btn--small" onClick={() => void loadInfo()}>
            Refresh
          </button>
        </header>
        <Help id="bridge" />
        <pre className="json">{pretty(info)}</pre>
      </section>

      <section className="card span-2">
        <header className="card__head">
          <h2>Transcript</h2>
          <button type="button" className="btn btn--small" onClick={clearTranscript}>
            Clear
          </button>
        </header>
        <Help id="transcript" />
        {transcript.length === 0 ? (
          <p className="muted">Every request this window makes appears here.</p>
        ) : (
          <ul className="transcript">
            {transcript.map((t) => (
              <li key={t.id}>
                <details>
                  <summary>
                    <span className={`dot dot--${t.ok ? "ok" : "bad"}`} aria-label={t.ok ? "ok" : "refused"} />
                    <span className="mono">{t.method}</span>
                    <span className="muted small">
                      {new Date(t.at).toLocaleTimeString()} · {t.ms} ms
                    </span>
                  </summary>
                  <pre className="json">{pretty({ params: t.params, answer: t.answer })}</pre>
                </details>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
