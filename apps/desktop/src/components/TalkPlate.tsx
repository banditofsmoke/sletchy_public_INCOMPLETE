import { useCallback, useEffect, useRef, useState } from "react";

import { type AnyErrorCode, call } from "../api";
import type { ModelAnswerResult, ModelsListResult, RunningView } from "../generated/contracts";
import { offered, sections } from "../lib/models";
import { plainError } from "../lib/plain";
import { lastTime, remember, waitKey } from "../lib/timings";
import { Help } from "./Help";
import { Meter, Waiting } from "./Instruments";

const gib = (bytes: number) => `${(bytes / 1024 ** 3).toFixed(2)} GiB`;

/** How often the plate asks whether the model has answered. Each check is quick. */
const CHECK_MS = 1000;

/** The contexts a conversation may have, if the Kernel does not say (#202). */
const CONTEXTS: readonly number[] = [4096, 8192, 16384, 32768];
/** The context the plate starts on: twice what a question had before #202. */
const START_CONTEXT = 8192;

/** What the model server holds for this model now, in one sentence (#202). */
function heldSay(name: string, held: RunningView | null, context: number): { text: string; warn: boolean } {
  if (!held) return { text: "Not loaded yet. Load it now, or just ask: the first question loads it.", warn: false };
  if (held.context_tokens !== context) {
    return {
      text: `Loaded with a context of ${held.context_tokens.toLocaleString()} tokens. Load it again for ${context.toLocaleString()}, or the first question reloads it.`,
      warn: false,
    };
  }
  const share = held.size_bytes > 0 ? held.vram_bytes / held.size_bytes : 0;
  if (share >= 1) {
    return {
      text: `Ready: ${name} is loaded with a context of ${context.toLocaleString()} tokens, all of it on the card. It stays loaded 30 minutes after the last question.`,
      warn: false,
    };
  }
  return {
    text: `Ready, but ${Math.round((1 - share) * 100)}% of it runs on the processor, so answers are slower. A smaller context fits on the card.`,
    warn: true,
  };
}

/** A refusal's own reason says which line it crossed; the rest have a sentence. */
const say = (code: AnyErrorCode, message: string) =>
  code === "model_refused" ? `${plainError(code)} ${message}` : plainError(code);

/** One answered question of the conversation on this plate. */
interface Turn {
  readonly question: string;
  readonly answer: ModelAnswerResult;
}

/**
 * Talk with a model on this computer (ADR-0017, ADR-0018), through the same door, onto
 * the same record, and through the same harness as `sletchy chat`: each question goes
 * with the conversation so far. A question gets a ticket at once and the plate checks
 * back every second, so a model that thinks for minutes never holds up the rest of the
 * window, Stop everything included. One question at a time.
 *
 * The plate never turns the switch on itself. Off, it says where the switch is.
 *
 * Loading is its own step (#202): pick a model and a context, Load model, and the plate
 * says what the server holds, how much of it is on the card, and how long it took. A
 * question asked before that still loads the model first.
 *
 * The list comes in sections, and a load or an answer shows a bar against how long the
 * same thing took last time (#207).
 */
export function TalkPlate({
  switchedOn,
  onAnswered,
  detail = false,
}: {
  readonly switchedOn: boolean;
  readonly onAnswered: () => void;
  readonly detail?: boolean;
}) {
  const [list, setList] = useState<ModelsListResult | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [model, setModel] = useState("");
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [turns, setTurns] = useState<readonly Turn[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [waited, setWaited] = useState(0);
  const [context, setContext] = useState(START_CONTEXT);
  const [loading, setLoading] = useState(false);
  const [loadNote, setLoadNote] = useState<string | null>(null);
  /** How long the wait under way took last time, if it has been timed (#207). */
  const [expected, setExpected] = useState<number | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    setListError(null);
    const out = await call("models.list", {});
    if (!out.ok) {
      setList(null);
      setListError(plainError(out.code));
      return;
    }
    setList(out.value);
    // Offered: fits the card, and can hold a conversation by the server's word (#204).
    const names = offered(out.value.models);
    setModel((current) => (names.includes(current) ? current : (names[0] ?? "")));
  }, []);

  useEffect(() => {
    if (switchedOn) void load();
  }, [switchedOn, load]);

  const ask = async () => {
    const asked = question;
    setAsking(true);
    setError(null);
    setWaited(0);
    setExpected(lastTime("answer", waitKey("answer", model, context)));
    // An empty conversation on the plate starts a new one in the Kernel too.
    const started = await call("model.ask", {
      model,
      question: asked,
      fresh: turns.length === 0,
      context: context as 4096 | 8192 | 16384 | 32768,
    });
    if (started.ok) {
      const { ticket } = started.value;
      for (;;) {
        await new Promise((resolve) => setTimeout(resolve, CHECK_MS));
        if (!mounted.current) return;
        const out = await call("model.answer", { ticket });
        if (!out.ok) {
          setError(say(out.code, out.message));
          break;
        }
        setWaited(out.value.seconds);
        if (out.value.state === "thinking") continue;
        const answer = out.value.state === "answered" ? out.value.answer : null;
        if (answer) {
          remember("answer", waitKey("answer", model, context), out.value.seconds);
          // The Kernel says which turn this is; turn 1 means a new conversation.
          setTurns((held) => [...(answer.turn === 1 ? [] : held), { question: asked, answer }]);
          setQuestion("");
        } else {
          setError(say(out.value.error_code ?? "internal_error", out.value.error ?? ""));
        }
        break;
      }
    } else {
      setError(say(started.code, started.message));
    }
    setAsking(false);
    onAnswered(); // a refusal is on the record too
  };

  /** Put the model on the card before any question, and wait for it as for an answer. */
  const loadModel = async () => {
    setLoading(true);
    setError(null);
    setLoadNote(null);
    setWaited(0);
    setExpected(lastTime("load", waitKey("load", model, context)));
    const started = await call("model.load", { model, context: context as 4096 | 8192 | 16384 | 32768 });
    if (started.ok) {
      for (;;) {
        await new Promise((resolve) => setTimeout(resolve, CHECK_MS));
        if (!mounted.current) return;
        const out = await call("model.answer", { ticket: started.value.ticket });
        if (!out.ok) {
          setError(say(out.code, out.message));
          break;
        }
        setWaited(out.value.seconds);
        if (out.value.state === "thinking") continue;
        const loaded = out.value.state === "loaded" ? out.value.loaded : null;
        if (loaded) {
          remember("load", waitKey("load", model, context), out.value.seconds);
          setLoadNote(`Loaded in ${loaded.seconds.toFixed(1)} s. On the record as entries ${loaded.load_seq} and ${loaded.loaded_seq}.`);
        } else {
          setError(say(out.value.error_code ?? "internal_error", out.value.error ?? ""));
        }
        break;
      }
    } else {
      setError(say(started.code, started.message));
    }
    setLoading(false);
    await load(); // what the server holds now
    onAnswered();
  };

  const unloadModel = async () => {
    setError(null);
    setLoadNote(null);
    const out = await call("model.unload", { model });
    if (!out.ok) setError(say(out.code, out.message));
    await load();
    onAnswered();
  };

  const held = list?.running?.find((r) => r.model === model) ?? null;
  const status = heldSay(model, held, context);
  const busy = asking || loading;

  const last = turns.at(-1)?.answer ?? null;

  return (
    <section className="plate talk area-talk" aria-labelledby="talk-title">
      <div className="plate__head">
        <h2 id="talk-title" className="plate__title">
          Talk to a model
        </h2>
        {list && (
          <span className="plate__hint">
            MODELS UP TO {gib(list.budget_bytes)}, {Math.round(list.share * 100)}% OF THE CARD
          </span>
        )}
      </div>
      <Help id="talk" />

      {turns.length > 0 && (
        <ol className="talk__turns" aria-label="This conversation">
          {turns.map((turn) => (
            <li key={`${turn.answer.conversation}-${turn.answer.turn}`} className="talk__turn">
              <p className="talk__you">{turn.question}</p>
              <p className="talk__text">{turn.answer.text}</p>
              {turn.answer.cut && (
                <p className="muted">
                  The answer is longer than the window shows. All of it is on the record, as entry{" "}
                  {turn.answer.answered_seq}.
                </p>
              )}
              {(turn.answer.recalled ?? 0) > 0 && (
                <p className="muted">
                  {turn.answer.recalled === 1 ? "One passage" : `${turn.answer.recalled} passages`} from memory
                  went with this question, quoted with where each came from: plan entry {turn.answer.plan_seq}.
                </p>
              )}
              {turn.answer.memory_unchecked && (
                <p className="warn-text">
                  Memory was not checked: {turn.answer.model} could not judge what memory found, so none of it went
                  with this question. A larger model can.
                </p>
              )}
              <p className="plate__foot">
                Turn {turn.answer.turn}. {turn.answer.model}, {turn.answer.seconds.toFixed(1)} s. On the record as
                entries {turn.answer.asked_seq} and {turn.answer.answered_seq}.
                {detail && ` It read ${turn.answer.prompt_tokens} tokens and wrote ${turn.answer.answer_tokens}.`}
              </p>
            </li>
          ))}
        </ol>
      )}
      {last && (
        <div className="talk__answer" aria-live="polite">
          <Meter
            value={last.prompt_tokens + last.answer_tokens}
            max={last.context_tokens}
            label="Context used"
            format={(n) => n.toLocaleString()}
          />
          {last.left_out > 0 && (
            <p className="muted">
              The oldest {last.left_out === 1 ? "turn was" : `${last.left_out} turns were`} left out of the last
              question, to leave the model room to answer.
            </p>
          )}
          {last.out_of_room && (
            <p className="warn-text">
              The answer stopped early: the model ran out of room in its context. Start a new conversation, or ask a
              shorter question.
            </p>
          )}
        </div>
      )}

      {!switchedOn ? (
        <p className="muted">
          Local AI models is off. Turn it on in Switches to ask a model on this computer. Nothing leaves the machine.
        </p>
      ) : listError ? (
        <div className="row">
          <p className="warn-text">{listError}</p>
          <button type="button" className="btn btn--small" onClick={() => void load()}>
            Try again
          </button>
        </div>
      ) : !list ? (
        <p className="muted">Looking for models...</p>
      ) : (
        <form
          className="talk__form"
          onSubmit={(e) => {
            e.preventDefault();
            void ask();
          }}
        >
          <label className="field">
            <span>Model</span>
            <select
              value={model}
              onChange={(e) => {
                setModel(e.target.value);
                setTurns([]); // another model is another conversation
                setLoadNote(null);
              }}
              disabled={busy}
            >
              {list.models.length === 0 && <option value="">The model server has no models</option>}
              {sections(list.models).map((s) => (
                <optgroup key={s.label} label={s.label}>
                  {s.models.map((m) => (
                    <option key={m.name} value={m.name} disabled={!s.pickable}>
                      {m.name} ({m.size_bytes >= 0 ? gib(m.size_bytes) : "size unknown"})
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Context</span>
            <select
              value={context}
              onChange={(e) => {
                setContext(Number(e.target.value));
                setTurns([]); // another context is another conversation
                setLoadNote(null);
              }}
              disabled={busy}
            >
              {(list.context_choices ?? CONTEXTS).map((n) => (
                <option key={n} value={n}>
                  {n.toLocaleString()} tokens
                </option>
              ))}
            </select>
          </label>
          <div className="row">
            <button type="button" className="btn btn--small" disabled={busy || !model} onClick={() => void loadModel()}>
              {loading ? "Loading..." : "Load model"}
            </button>
            {held && !busy && (
              <button type="button" className="btn btn--small" onClick={() => void unloadModel()}>
                Unload
              </button>
            )}
          </div>
          <p className={status.warn ? "warn-text" : "muted"} aria-live="polite">
            {loading
              ? `Loading ${model} with a context of ${context.toLocaleString()} tokens${waited >= 1 ? `, ${Math.round(waited)} s so far` : ""}. The rest of Sletchy works as usual.`
              : status.text}
            {!loading && loadNote ? ` ${loadNote}` : ""}
          </p>
          {loading && <Waiting label="Loading" seconds={waited} expected={expected} />}
          <label className="field">
            <span>Your question</span>
            <textarea
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              rows={3}
              maxLength={list.max_question_chars}
              disabled={busy}
            />
          </label>
          <div className="row">
            <button type="submit" className="btn btn--brass" disabled={busy || !model || !question.trim()}>
              {asking ? "Thinking..." : "Ask"}
            </button>
            {turns.length > 0 && !asking && (
              <button type="button" className="btn btn--small" onClick={() => setTurns([])}>
                New conversation
              </button>
            )}
            {asking && (
              <span className="muted" role="status">
                The model is thinking{waited >= 1 ? `, ${Math.round(waited)} s so far` : ""}. The first question loads
                the model, which can take a few minutes; after that, answers take seconds. The rest of Sletchy works as
                usual.
              </span>
            )}
          </div>
          {asking && <Waiting label="Thinking" seconds={waited} expected={expected} />}
        </form>
      )}

      {error && (
        <p className="warn-text" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
