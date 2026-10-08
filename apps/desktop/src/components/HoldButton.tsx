import { useEffect, useRef, useState } from "react";

import { clunk, hiss, ratchet } from "../lib/sound";

interface Props {
  readonly onHold: () => void;
  readonly label: string;
  readonly holdingLabel?: string;
  readonly ms?: number;
  readonly disabled?: boolean;
  readonly tone?: "danger" | "accent";
  /** "valve" draws a red valve wheel that turns while held. */
  readonly variant?: "button" | "valve";
}

/**
 * A control that fires only after being held. For Stop everything: LAW 0 says it
 * never asks for confirmation, so there is no dialog - but a stray click should not
 * reset every switch either. Holding is a gesture, not a question.
 *
 * Works with a mouse, a finger, and the keyboard (hold Space or Enter).
 */
export function HoldButton({
  onHold,
  label,
  holdingLabel = "Keep holding...",
  ms = 1200,
  disabled = false,
  tone = "danger",
  variant = "button",
}: Props) {
  const [holding, setHolding] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cancel = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    setHolding(false);
  };
  const begin = () => {
    if (disabled || timer.current) return;
    setHolding(true);
    if (variant === "valve") ratchet(8);
    timer.current = setTimeout(() => {
      timer.current = null;
      setHolding(false);
      if (variant === "valve") {
        clunk();
        hiss(0.1, 0.9);
      }
      onHold();
    }, ms);
  };
  useEffect(() => cancel, []);

  return (
    <button
      type="button"
      className={`hold hold--${tone} hold--${variant}${holding ? " hold--active" : ""}`}
      style={{ ["--hold-ms" as string]: `${ms}ms` }}
      disabled={disabled}
      aria-label={`${label} (press and hold)`}
      onPointerDown={begin}
      onPointerUp={cancel}
      onPointerLeave={cancel}
      onKeyDown={(e) => {
        if ((e.key === " " || e.key === "Enter") && !e.repeat) {
          e.preventDefault();
          begin();
        }
      }}
      onKeyUp={(e) => {
        if (e.key === " " || e.key === "Enter") cancel();
      }}
    >
      {variant === "valve" && (
        <svg className="valve" viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="50" className="valve__rim" />
          {[0, 60, 120].map((a) => (
            <rect key={a} x="56" y="14" width="8" height="92" rx="4" className="valve__spoke" transform={`rotate(${a} 60 60)`} />
          ))}
          <circle cx="60" cy="60" r="14" className="valve__hub" />
        </svg>
      )}
      <span className="hold__fill" aria-hidden="true" />
      <span className="hold__label">{holding ? holdingLabel : label}</span>
    </button>
  );
}
