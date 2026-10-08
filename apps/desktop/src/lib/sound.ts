// Mechanical sounds, synthesised. No audio files: every click, ratchet and bolt is
// built from an oscillator or filtered noise with the Web Audio API, so there is
// nothing to download, nothing to vet, and nothing that can carry anything else.
//
// Muted is remembered per computer. Everything here is a no-op when muted, when
// there is no AudioContext (tests, old engines), or when the engine refuses to start.

const KEY = "sletchy.sound";

let ctx: AudioContext | null = null;
let muted = loadMuted();

function loadMuted(): boolean {
  try {
    return window.localStorage.getItem(KEY) === "off";
  } catch {
    return false;
  }
}

export function isMuted(): boolean {
  return muted;
}

export function setMuted(next: boolean): void {
  muted = next;
  try {
    window.localStorage.setItem(KEY, next ? "off" : "on");
  } catch {
    // not remembered; nothing depends on it
  }
}

function audio(): AudioContext | null {
  if (muted) return null;
  const Ctor = (globalThis as { AudioContext?: typeof AudioContext }).AudioContext;
  if (!Ctor) return null;
  try {
    ctx ??= new Ctor();
    if (ctx.state === "suspended") void ctx.resume();
    return ctx;
  } catch {
    return null;
  }
}

function noise(a: AudioContext, seconds: number): AudioBufferSourceNode {
  const buffer = a.createBuffer(1, Math.max(1, Math.floor(a.sampleRate * seconds)), a.sampleRate);
  const data = buffer.getChannelData(0);
  for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;
  const src = a.createBufferSource();
  src.buffer = buffer;
  return src;
}

function envelope(a: AudioContext, at: number, peak: number, decay: number): GainNode {
  const g = a.createGain();
  g.gain.setValueAtTime(0.0001, at);
  g.gain.exponentialRampToValueAtTime(peak, at + 0.004);
  g.gain.exponentialRampToValueAtTime(0.0001, at + decay);
  g.connect(a.destination);
  return g;
}

/** One sharp mechanical tick: a burst of bright noise and a short metallic ping. */
export function click(delay = 0, brightness = 3200): void {
  const a = audio();
  if (!a) return;
  const at = a.currentTime + delay;
  const src = noise(a, 0.03);
  const band = a.createBiquadFilter();
  band.type = "bandpass";
  band.frequency.value = brightness;
  band.Q.value = 6;
  src.connect(band).connect(envelope(a, at, 0.5, 0.03));
  src.start(at);
  const ping = a.createOscillator();
  ping.type = "square";
  ping.frequency.setValueAtTime(brightness * 0.45, at);
  ping.connect(envelope(a, at, 0.04, 0.02));
  ping.start(at);
  ping.stop(at + 0.03);
}

/** A ratchet: `teeth` quick clicks, slowing slightly, as a dial winds. */
export function ratchet(teeth = 6, delay = 0): void {
  for (let i = 0; i < teeth; i++) click(delay + i * 0.045 + i * i * 0.002, 2400 + i * 90);
}

/** The heavy thunk of a bolt seating: a falling low tone under dull noise. */
export function clunk(delay = 0): void {
  const a = audio();
  if (!a) return;
  const at = a.currentTime + delay;
  const tone = a.createOscillator();
  tone.type = "sine";
  tone.frequency.setValueAtTime(120, at);
  tone.frequency.exponentialRampToValueAtTime(42, at + 0.18);
  tone.connect(envelope(a, at, 0.6, 0.22));
  tone.start(at);
  tone.stop(at + 0.25);
  const src = noise(a, 0.12);
  const low = a.createBiquadFilter();
  low.type = "lowpass";
  low.frequency.value = 600;
  src.connect(low).connect(envelope(a, at, 0.35, 0.1));
  src.start(at);
}

/** Steam escaping as the door swings: noise swept through a rising high-pass. */
export function hiss(delay = 0, seconds = 0.7): void {
  const a = audio();
  if (!a) return;
  const at = a.currentTime + delay;
  const src = noise(a, seconds);
  const high = a.createBiquadFilter();
  high.type = "highpass";
  high.frequency.setValueAtTime(700, at);
  high.frequency.exponentialRampToValueAtTime(4800, at + seconds);
  const g = a.createGain();
  g.gain.setValueAtTime(0.0001, at);
  g.gain.exponentialRampToValueAtTime(0.18, at + 0.08);
  g.gain.exponentialRampToValueAtTime(0.0001, at + seconds);
  g.connect(a.destination);
  src.connect(high).connect(g);
  src.start(at);
}

/** A sour two-note buzz for a lock that would not seat. */
export function refuse(delay = 0): void {
  const a = audio();
  if (!a) return;
  const at = a.currentTime + delay;
  for (const [f, t] of [
    [220, 0],
    [180, 0.12],
  ] as const) {
    const o = a.createOscillator();
    o.type = "sawtooth";
    o.frequency.value = f;
    o.connect(envelope(a, at + t, 0.08, 0.14));
    o.start(at + t);
    o.stop(at + t + 0.16);
  }
}
