import { useMemo, useState } from "react";

import { inApp } from "./api";
import { Logo, Toasts } from "./components/Bits";
import { Boot, wantsShow, type BootSteps, type LockState } from "./components/Boot";
import { Help, HelpContext } from "./components/Help";
import { loadHelp, saveHelp } from "./lib/help";
import { loadMode, MODE_LABELS, MODES, saveMode, type Mode } from "./lib/modes";
import { useNoc } from "./lib/noc";
import { plainError } from "./lib/plain";
import { isMuted, setMuted } from "./lib/sound";
import { useTranscript } from "./lib/store";
import { useSletchy } from "./lib/useSletchy";
import { CustomView } from "./views/CustomView";
import { RawView } from "./views/RawView";
import { SimpleView } from "./views/SimpleView";

function pill(s: ReturnType<typeof useSletchy>): { tone: string; text: string } {
  if (s.connection && !s.connection.ok) return { tone: "bad", text: "Not connected" };
  if (!s.status) return { tone: "idle", text: "Connecting..." };
  if (s.status.ledger_state === "not_initialised") return { tone: "idle", text: "Not set up" };
  if (s.status.ledger_state !== "ok") return { tone: "bad", text: "Needs attention" };
  if (s.selfcheck?.checks.some((c) => c.status === "fail")) return { tone: "bad", text: "Needs attention" };
  if (s.status.dangerous_on.length > 0) return { tone: "warn", text: "Dangerous switch on" };
  return { tone: "good", text: "Protected" };
}

/** Each lock of the vault door is one real start-up check. */
export function bootSteps(s: ReturnType<typeof useSletchy>): BootSteps {
  const failedConnection = s.connection !== null && !s.connection.ok;
  const kernel: LockState = s.connection === null ? "turning" : s.connection.ok ? "seated" : "failed";
  const record: LockState = failedConnection
    ? "failed"
    : !s.status
      ? "turning"
      : s.status.ledger_state === "ok"
        ? "seated"
        : "failed";
  const selfcheck: LockState = s.selfcheck
    ? s.selfcheck.checks.some((c) => c.status === "fail")
      ? "failed"
      : "seated"
    : s.loading
      ? "turning"
      : "failed";
  const switches: LockState = s.loading ? "turning" : s.flags.length > 0 ? "seated" : "failed";
  return { kernel, record, selfcheck, switches };
}

export function App() {
  const sletchy = useSletchy();
  const noc = useNoc();
  const transcript = useTranscript();
  const [mode, setMode] = useState<Mode>(loadMode);
  const [help, setHelp] = useState<boolean>(loadHelp);
  const [muted, setMute] = useState<boolean>(isMuted);
  const [booting, setBooting] = useState<boolean>(wantsShow);
  const status = pill(sletchy);
  const latencies = useMemo(() => transcript.slice(0, 40).map((t) => t.ms).reverse(), [transcript]);
  const choose = (next: Mode) => {
    setMode(next);
    saveMode(next);
  };

  return (
    <div className={`app app--${mode}`}>
      <header className="topbar">
        <div className="brand">
          <Logo />
          <span className="brand__name">SLETCHY</span>
          <span className={`pill pill--${status.tone}`}>
            <span className="pill__dot" aria-hidden="true" />
            {status.text}
          </span>
        </div>
        <nav className="modes" aria-label="View">
          {MODES.map((m) => (
            <button
              key={m}
              type="button"
              className={`modes__btn${m === mode ? " modes__btn--on" : ""}`}
              aria-pressed={m === mode}
              title={MODE_LABELS[m].hint}
              onClick={() => choose(m)}
            >
              {MODE_LABELS[m].name}
            </button>
          ))}
        </nav>
        <div className="topbar__tools">
          <button
            type="button"
            className={`btn btn--small tool${muted ? "" : " tool--on"}`}
            aria-pressed={!muted}
            title="Mechanical sounds"
            onClick={() => {
              setMuted(!muted);
              setMute(!muted);
            }}
          >
            {muted ? "Sound off" : "Sound on"}
          </button>
          <button
            type="button"
            className={`btn btn--small tool help-toggle${help ? " help-toggle--on" : ""}`}
            aria-pressed={help}
            title="Explain every control: what it does, the worst it can do, and the tests that guard it"
            onClick={() => {
              setHelp(!help);
              saveHelp(!help);
            }}
          >
            <span aria-hidden="true">?</span> Help {help ? "on" : "off"}
          </button>
          <button type="button" className="btn btn--small tool" onClick={() => void sletchy.refresh()} disabled={sletchy.loading}>
            {sletchy.loading ? "Checking..." : "Refresh"}
          </button>
        </div>
      </header>

      {!inApp() && (
        <div className="banner" role="note">
          Preview in a browser: these are sample switches, not your real Sletchy. Nothing here can reach your computer.
        </div>
      )}
      {sletchy.connection && !sletchy.connection.ok && (
        <div className="banner banner--bad" role="alert">
          {plainError(sletchy.connection.code)} <span className="mono small">{sletchy.connection.message}</span>
        </div>
      )}
      {help && (
        <div className="banner banner--help" role="note">
          Help is on. Every control now says what it does, why you would use it, the worst it can do today, and the
          tests that guard it. Press <strong>Help</strong> again to hide it.
        </div>
      )}

      <HelpContext.Provider value={help}>
        <main className={`main main--${mode}`}>
          <Help id="modes" />
          <Help id="sound" />
          <Help id="door" />
          {mode === "simple" && <SimpleView {...sletchy} noc={noc} />}
          {mode === "custom" && <CustomView {...sletchy} noc={noc} latencies={latencies} />}
          {mode === "raw" && <RawView onChanged={() => void sletchy.refresh()} />}
        </main>
      </HelpContext.Provider>
      <Toasts />
      {booting && <Boot steps={bootSteps(sletchy)} onDone={() => setBooting(false)} />}
    </div>
  );
}
