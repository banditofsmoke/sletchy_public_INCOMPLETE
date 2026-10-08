import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, it } from "vitest";

import { App } from "./App";
import { resetPreview } from "./lib/preview";
import { resetStore } from "./lib/store";

// The whole window, driven through the preview Kernel the way a person would use it.

beforeEach(() => {
  window.localStorage.clear();
  resetPreview();
  resetStore();
});

it("opens in Simple mode, labelled as a preview, with the meter and the switches", async () => {
  render(<App />);
  expect(screen.getByRole("note").textContent).toMatch(/Preview in a browser/);
  await waitFor(() => expect(screen.getByRole("img", { name: /Trust meter: 85/ })).toBeTruthy());
  expect(screen.getByRole("switch", { name: "Camera: off" })).toBeTruthy();
  expect(screen.getAllByText("Not connected yet").length).toBeGreaterThan(0);
  expect(screen.getByText(/terminal setting/)).toBeTruthy();
});

it("a dangerous switch goes through the dialog, then shows on and the status warns", async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole("switch", { name: "Camera: off" }));
  const dialog = await screen.findByRole("dialog");
  const [reason, typed] = within(dialog).getAllByRole("textbox") as [HTMLTextAreaElement, HTMLInputElement];
  fireEvent.change(reason, { target: { value: "video call" } });
  fireEvent.change(typed, { target: { value: "senses_camera" } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Turn on" }));
  expect(await screen.findByRole("switch", { name: "Camera: on" })).toBeTruthy();
  await waitFor(() => expect(screen.getByText("Dangerous switch on")).toBeTruthy());
});

it("before setup, the window offers to set Sletchy up, and setting up shows the switches", async () => {
  resetPreview(false);
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Set up Sletchy" }));
  expect(await screen.findByRole("switch", { name: "Camera: off" })).toBeTruthy();
});

it("switches modes and remembers the choice", async () => {
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Custom" }));
  expect(await screen.findByRole("heading", { name: "Self-check" })).toBeTruthy();
  expect(window.localStorage.getItem("sletchy.mode")).toBe("custom");
  fireEvent.click(screen.getByRole("button", { name: "Raw" }));
  expect(await screen.findByRole("heading", { name: "Transcript" })).toBeTruthy();
});

it("Raw goes through the same rules: a dangerous switch without proofs is refused", async () => {
  window.localStorage.setItem("sletchy.mode", "raw");
  render(<App />);
  const params = await screen.findByLabelText("Params (JSON)");
  fireEvent.change(screen.getByLabelText("Method"), { target: { value: "flags.set" } });
  fireEvent.change(params, { target: { value: '{"name": "senses_camera", "enabled": true}' } });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  await waitFor(() => expect(screen.getAllByText(/confirmation_required/).length).toBeGreaterThan(0));
});

it("Raw will not send params that are not a JSON object", async () => {
  window.localStorage.setItem("sletchy.mode", "raw");
  render(<App />);
  fireEvent.change(await screen.findByLabelText("Params (JSON)"), { target: { value: "[1, 2]" } });
  expect((screen.getByRole("button", { name: "Send" }) as HTMLButtonElement).disabled).toBe(true);
});

it("Help explains every control on the page, with the tests that guard it, and hides again", async () => {
  render(<App />);
  await screen.findByRole("switch", { name: "Camera: off" });
  expect(screen.queryByLabelText(/^Help:/)).toBeNull();

  fireEvent.click(screen.getByRole("button", { name: /Help off/ }));
  const cards = await screen.findAllByLabelText(/^Help:/);
  const titles = cards.map((c) => c.getAttribute("aria-label"));
  for (const expected of ["Help: The trust meter", "Help: Switches", "Help: Dangerous switches", "Help: Stop everything"]) {
    expect(titles).toContain(expected);
  }
  expect(screen.getAllByText("Worst it can do").length).toBe(cards.length);
  expect(window.localStorage.getItem("sletchy.help")).toBe("on");

  fireEvent.click(screen.getByRole("button", { name: /Help on/ }));
  expect(screen.queryByLabelText(/^Help:/)).toBeNull();
});

it("Talk to a model loads a model before any question, says it is ready, and unloads it (#202)", async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole("switch", { name: "Local AI models: off" }));
  expect(await screen.findByText(/Not loaded yet/)).toBeTruthy();

  fireEvent.change(screen.getByLabelText("Context"), { target: { value: "16384" } });
  fireEvent.click(screen.getByRole("button", { name: "Load model" }));
  // The first load has nothing to measure against, so the bar moves without a value (#207).
  const bar = screen.getByRole("progressbar", { name: "Loading" });
  expect(bar.getAttribute("aria-valuenow")).toBeNull();
  expect(screen.getByText(/No estimate yet/)).toBeTruthy();
  expect(await screen.findByText(/Ready: sample-small:1b is loaded with a context of 16.?384 tokens/, undefined, { timeout: 4000 })).toBeTruthy();
  expect(screen.getByText(/Loaded in 0\.1 s/)).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: "Unload" }));
  expect(await screen.findByText(/Not loaded yet/)).toBeTruthy();
});

it("Talk to a model lists a model for memory search and never offers it to talk to (#204)", async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole("switch", { name: "Local AI models: off" }));

  // The smallest model, so the first in the list, and the one picked before #204.
  const embed = (await screen.findByRole("option", { name: /sample-embed:latest/ })) as HTMLOptionElement;
  expect(embed.disabled).toBe(true);
  expect((embed.parentElement as HTMLOptGroupElement).label).toBe("For memory search, not for talking to");
  expect((embed.closest("select") as HTMLSelectElement).value).toBe("sample-small:1b");
});

it("Talk to a model says where its switch is, then asks and shows the answer and the meter", async () => {
  render(<App />);
  expect(await screen.findByText(/Turn it on in Switches/)).toBeTruthy();

  // The plate's own text shows before the switches have loaded, so wait for the switch.
  fireEvent.click(await screen.findByRole("switch", { name: "Local AI models: off" }));
  const box = await screen.findByLabelText("Your question");
  fireEvent.change(box, { target: { value: "Hello?" } });
  fireEvent.click(screen.getByRole("button", { name: "Ask" }));
  // A first question can take minutes while the model loads, so the plate says so.
  expect(await screen.findByText(/The first question loads the model/)).toBeTruthy();

  // The plate checks back once a second; the preview answers on the first check.
  expect(await screen.findByText(/No model was asked/, undefined, { timeout: 4000 })).toBeTruthy();
  expect(screen.getByRole("meter", { name: "Context used" })).toBeTruthy();

  // A second question carries the conversation on; a new conversation starts again.
  fireEvent.change(screen.getByLabelText("Your question"), { target: { value: "And again?" } });
  fireEvent.click(screen.getByRole("button", { name: "Ask" }));
  expect(await screen.findByText(/Turn 2\./, undefined, { timeout: 4000 })).toBeTruthy();
  expect(screen.getByText(/Turn 1\./)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "New conversation" }));
  expect(screen.queryByText(/Turn 1\./)).toBeNull();
  expect(screen.queryByRole("meter", { name: "Context used" })).toBeNull();
});
