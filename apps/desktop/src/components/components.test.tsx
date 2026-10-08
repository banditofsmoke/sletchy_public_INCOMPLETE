import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import type { FlagView } from "../generated/contracts";
import { Boot, MAX_MS, type BootSteps } from "./Boot";
import { EnableDialog } from "./EnableDialog";
import { HoldButton } from "./HoldButton";
import { Waiting } from "./Instruments";
import { Orrery } from "./Orrery";
import { TrustMeter } from "./TrustMeter";

afterEach(() => {
  vi.useRealTimers();
});

const camera: FlagView = {
  name: "senses_camera",
  label: "Camera",
  description: "Allow camera capture.",
  risk: "dangerous",
  default: false,
  enabled: false,
  wired: false,
  serves: ["connection"],
};

it("the dialog will not turn a switch on without a reason and the exact name", () => {
  const onConfirm = vi.fn();
  render(<EnableDialog flag={camera} onConfirm={onConfirm} onCancel={() => {}} />);
  const button = screen.getByRole("button", { name: "Turn on" }) as HTMLButtonElement;
  const [reason, typed] = screen.getAllByRole("textbox") as [HTMLTextAreaElement, HTMLInputElement];

  expect(button.disabled).toBe(true);
  fireEvent.change(reason, { target: { value: "video call" } });
  expect(button.disabled).toBe(true);
  fireEvent.change(typed, { target: { value: "Camera" } }); // the label is not the name
  expect(button.disabled).toBe(true);
  fireEvent.change(typed, { target: { value: "senses_camera" } });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);
  expect(onConfirm).toHaveBeenCalledWith("video call", "senses_camera");
});

it("the dialog says when nothing uses the switch yet", () => {
  render(<EnableDialog flag={camera} onConfirm={() => {}} onCancel={() => {}} />);
  expect(screen.getByText(/Nothing in Sletchy uses this switch yet/)).toBeTruthy();
});

it("a click is not a hold", () => {
  vi.useFakeTimers();
  const onHold = vi.fn();
  render(<HoldButton label="Hold to stop everything" onHold={onHold} ms={1000} />);
  const button = screen.getByRole("button");
  fireEvent.pointerDown(button);
  act(() => {
    vi.advanceTimersByTime(300);
  });
  fireEvent.pointerUp(button);
  act(() => {
    vi.advanceTimersByTime(2000);
  });
  expect(onHold).not.toHaveBeenCalled();
});

it("holding long enough fires once, by pointer or by keyboard", () => {
  vi.useFakeTimers();
  const onHold = vi.fn();
  render(<HoldButton label="Hold" onHold={onHold} ms={1000} />);
  const button = screen.getByRole("button");
  fireEvent.pointerDown(button);
  act(() => {
    vi.advanceTimersByTime(1000);
  });
  expect(onHold).toHaveBeenCalledTimes(1);
  fireEvent.keyDown(button, { key: " " });
  act(() => {
    vi.advanceTimersByTime(1000);
  });
  expect(onHold).toHaveBeenCalledTimes(2);
});

it("the meter tells a screen reader its score and its ceiling", () => {
  render(<TrustMeter score={85} ceiling={85} />);
  expect(screen.getByRole("img").getAttribute("aria-label")).toBe(
    "Trust meter: 85 out of 100. The highest possible right now is 85.",
  );
});

it("the orrery puts every switch on a ring and every kernel process at the core", () => {
  const procs = [
    { pid: 1, ppid: 0, name: "sletchy-desktop.exe", threads: 9, cpu_ms: 1, memory_bytes: 1, private_bytes: 1, in_job: false, role: "window" as const },
    { pid: 2, ppid: 1, name: "python.exe", threads: 2, cpu_ms: 1, memory_bytes: 1, private_bytes: 1, in_job: true, role: "kernel" as const },
  ];
  const { container } = render(<Orrery flags={[camera, { ...camera, name: "egress_enabled", label: "Internet access", enabled: true }]} entries={[]} procs={procs} ledgerCount={7} />);
  expect(container.querySelectorAll(".orrery__lamp")).toHaveLength(2);
  expect(container.querySelectorAll(".orrery__lamp--on")).toHaveLength(1);
  expect(container.querySelectorAll(".orrery__proc")).toHaveLength(1); // only the kernel process orbits the core
  expect(screen.getByRole("img", { name: /1 kernel processes, 1 switches on, 7 ledger entries/ })).toBeTruthy();
});

const stuck: BootSteps = { kernel: "turning", record: "turning", selfcheck: "turning", switches: "turning" };

it("the vault door cannot keep anyone outside: a check that never answers still opens it", () => {
  vi.useFakeTimers();
  const onDone = vi.fn();
  render(<Boot steps={stuck} onDone={onDone} />);
  act(() => {
    vi.advanceTimersByTime(MAX_MS - 1);
  });
  expect(onDone).not.toHaveBeenCalled(); // positive control: the ceiling is what opens it
  act(() => {
    vi.advanceTimersByTime(1);
  });
  expect(onDone).toHaveBeenCalledTimes(1);
});

it("any key or a click skips the vault door, and it opens exactly once", () => {
  vi.useFakeTimers();
  const onDone = vi.fn();
  const { container } = render(<Boot steps={stuck} onDone={onDone} />);
  fireEvent.keyDown(window, { key: "Escape" });
  expect(onDone).toHaveBeenCalledTimes(1);
  fireEvent.click(container.querySelector(".boot") as Element);
  act(() => {
    vi.advanceTimersByTime(MAX_MS * 2);
  });
  expect(onDone).toHaveBeenCalledTimes(1);
});

it("the door opens on its own once every lock has answered, even if one failed", () => {
  vi.useFakeTimers();
  const onDone = vi.fn();
  render(<Boot steps={{ kernel: "seated", record: "failed", selfcheck: "seated", switches: "seated" }} onDone={onDone} />);
  // Step the clock the way real time passes, letting React render between ticks.
  for (let t = 0; t < 4000; t += 100) {
    act(() => {
      vi.advanceTimersByTime(100);
    });
  }
  expect(onDone).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/1 lock would not seat - opening so you can see why/)).toBeTruthy();
});

it("a wait fills against last time, stops short of the end, and moves without a value past it (#207)", () => {
  const { rerender } = render(<Waiting label="Loading" seconds={27} expected={54.8} />);
  expect(screen.getByRole("progressbar", { name: "Loading" }).getAttribute("aria-valuenow")).toBe("49");
  expect(screen.getByText("About 55 s, from last time.")).toBeTruthy();

  rerender(<Waiting label="Loading" seconds={54.8} expected={54.8} />);
  expect(screen.getByRole("progressbar", { name: "Loading" }).getAttribute("aria-valuenow")).toBe("95");

  rerender(<Waiting label="Loading" seconds={60} expected={54.8} />);
  expect(screen.getByRole("progressbar", { name: "Loading" }).getAttribute("aria-valuenow")).toBeNull();
  expect(screen.getByText("Longer than last time (55 s).")).toBeTruthy();

  rerender(<Waiting label="Loading" seconds={3} expected={null} />);
  expect(screen.getByText("No estimate yet: this time is measured for the next.")).toBeTruthy();
});
