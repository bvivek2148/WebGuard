import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useNow } from "./components/shared";

/**
 * useNow is the shared live-clock hook powering every time-windowed stat in
 * the SOC (threat counts, latency, alert ages). These tests lock in its
 * contract: current epoch on mount, tick every interval, and cleanup.
 */

const T0 = new Date("2026-01-15T12:00:00Z").getTime();

describe("useNow", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns the current epoch time on mount", () => {
    const { result } = renderHook(() => useNow(1000));
    expect(result.current).toBe(T0);
  });

  it("advances by one interval per tick", () => {
    const { result } = renderHook(() => useNow(1000));
    expect(result.current).toBe(T0);

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(result.current).toBe(T0 + 1000);

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(result.current).toBe(T0 + 2000);
  });

  it("does not tick before the interval elapses", () => {
    const { result } = renderHook(() => useNow(1000));
    act(() => {
      vi.advanceTimersByTime(999);
    });
    expect(result.current).toBe(T0);
  });

  it("respects a custom interval", () => {
    const { result } = renderHook(() => useNow(5000));
    act(() => {
      vi.advanceTimersByTime(4999);
    });
    expect(result.current).toBe(T0);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(result.current).toBe(T0 + 5000);
  });

  it("clears its interval on unmount", () => {
    const clearSpy = vi.spyOn(window, "clearInterval");
    const { unmount } = renderHook(() => useNow(1000));
    unmount();
    expect(clearSpy).toHaveBeenCalled();
    clearSpy.mockRestore();
  });
});
