import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useWaf, WafProvider } from "../engine";

/**
 * Boot-level smoke test for the SOC state provider: the seeded baseline must
 * render, and the telemetry clock (TICK every ~330ms) must advance the console
 * state over time. Covers the provider wiring, reducer, and buildInitialState
 * under a real DOM environment.
 */

function Probe() {
  const { state, currentRps, activeThreats, avgLatency } = useWaf();
  return (
    <div>
      <span data-testid="mode">{state.mode}</span>
      <span data-testid="target">{state.target}</span>
      <span data-testid="seq">{state.seq}</span>
      <span data-testid="rps">{currentRps}</span>
      <span data-testid="threats">{activeThreats}</span>
      <span data-testid="latency">{avgLatency.toFixed(2)}</span>
    </div>
  );
}

function boot() {
  return render(
    <WafProvider>
      <Probe />
    </WafProvider>,
  );
}

describe("WafProvider", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("boots with the seeded baseline posture", () => {
    boot();
    expect(screen.getByTestId("mode")).toHaveTextContent("off");
    expect(screen.getByTestId("target")).toHaveTextContent("http://localhost:8080");
    // Seeded live log history → a non-zero live window exists on first paint.
    expect(Number(screen.getByTestId("threats").textContent)).toBeGreaterThan(0);
    expect(Number(screen.getByTestId("latency").textContent)).toBeGreaterThan(0);
  });

  it("exposes the full context to consumers (useWaf contract)", () => {
    expect(() => boot()).not.toThrow();
    expect(screen.getByTestId("seq")).toHaveTextContent(/^\d+$/);
  });

  it("advances the telemetry clock as time passes", () => {
    boot();
    const before = Number(screen.getByTestId("seq").textContent);
    act(() => {
      // ~10 TICK dispatches at the 330ms cadence.
      vi.advanceTimersByTime(3300);
    });
    const after = Number(screen.getByTestId("seq").textContent);
    expect(after).toBeGreaterThan(before);
  });

  it("guards useWaf against a missing provider", () => {
    // React 19 may either rethrow render errors or report them via onUncaughtError
    // (console.error), depending on the root setup — accept both signals.
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    let threw = false;
    try {
      render(<Probe />);
    } catch {
      threw = true;
    }
    expect(threw || spy.mock.calls.length > 0).toBe(true);
    spy.mockRestore();
  });
});
