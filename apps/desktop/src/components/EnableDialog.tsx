import { useEffect, useId, useRef, useState } from "react";

import type { FlagView } from "../generated/contracts";

interface Props {
  readonly flag: FlagView;
  readonly onConfirm: (reason: string, confirm: string) => void;
  readonly onCancel: () => void;
}

/**
 * Turning a dangerous switch on takes two proofs, and this dialog asks for both:
 * a reason (the Kernel records it in the ledger) and the switch's exact name typed
 * back (the bridge checks it). The button stays disabled until both are given, but
 * the real check is in the Kernel and the bridge - this only saves a round trip.
 */
export function EnableDialog({ flag, onConfirm, onCancel }: Props) {
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const ref = useRef<HTMLDialogElement>(null);
  const reasonId = useId();
  const typedId = useId();
  const ready = reason.trim().length > 0 && typed === flag.name;

  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open && typeof dialog.showModal === "function") dialog.showModal();
  }, []);

  return (
    <dialog ref={ref} className="dialog" aria-labelledby={`${reasonId}-title`} onCancel={onCancel}>
      <form
        method="dialog"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) onConfirm(reason.trim(), typed);
        }}
      >
        <h2 id={`${reasonId}-title`} className="dialog__title">
          Turn on {flag.label}?
        </h2>
        <p className="dialog__warn">This is a dangerous switch. {flag.description}</p>
        {!flag.wired && (
          <p className="dialog__note">
            Nothing in Sletchy uses this switch yet, so turning it on changes nothing today. It is
            recorded all the same.
          </p>
        )}
        <label className="field" htmlFor={reasonId}>
          <span>Why are you turning this on? This goes in Sletchy's record.</span>
          <textarea id={reasonId} value={reason} maxLength={512} rows={2} onChange={(e) => setReason(e.target.value)} />
        </label>
        <label className="field" htmlFor={typedId}>
          <span>
            Type <code>{flag.name}</code> to confirm
          </span>
          <input id={typedId} value={typed} autoComplete="off" spellCheck={false} onChange={(e) => setTyped(e.target.value)} />
        </label>
        <div className="dialog__actions">
          <button type="button" className="btn" onClick={onCancel}>
            Keep it off
          </button>
          <button type="submit" className="btn btn--danger" disabled={!ready}>
            Turn on
          </button>
        </div>
      </form>
    </dialog>
  );
}
