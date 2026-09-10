import { beforeEach, describe, expect, it } from "vitest";
import { buildInitialState, persistSnapshot, reducer, serializePersistedState } from "./engine";
import type { WafState } from "./engine";

/**
 * The SOC console's snapshot feature (export / import / save points) is built
 * on three pieces of engine logic:
 *   - serializePersistedState: the durable subset of state written to files
 *   - persistSnapshot: writing a restored snapshot to localStorage
 *   - RESTORE_STATE: merging a snapshot back over a fresh baseline
 * These tests lock in that contract so the feature can't silently regress.
 */

const PERSIST_KEY = "webguard.soc.v1";

// Minimal localStorage shim — node has none, and the engine only touches it
// inside these functions (never at import time).
const store = new Map<string, string>();
beforeEach(() => {
  store.clear();
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => {
      store.set(k, v);
    },
    removeItem: (k: string) => {
      store.delete(k);
    },
  };
});

describe("serializePersistedState", () => {
  it("includes the durable control keys", () => {
    const snap = serializePersistedState(buildInitialState());
    const keys = Object.keys(snap);
    for (const key of [
      "mode",
      "target",
      "audit",
      "alarms",
      "incidents",
      "canaries",
      "rules",
      "settings",
      "sandbox",
      "findings",
      "blocklist",
      "allowlist",
      "customRules",
      "savedProbes",
      "geoBlock",
      "banAutomation",
      "policySuggestion",
      "integrations",
      "dispatchLog",
      "drillHistory",
      "drillQueue",
      "drillLoop",
      "schedule",
      "drillReports",
    ]) {
      expect(keys).toContain(key);
    }
  });

  it("excludes live telemetry streams", () => {
    const snap = serializePersistedState(buildInitialState());
    expect(snap).not.toHaveProperty("logs");
    expect(snap).not.toHaveProperty("series");
    expect(snap).not.toHaveProperty("stress");
    expect(snap).not.toHaveProperty("stressSeries");
    expect(snap).not.toHaveProperty("ipHits");
    expect(snap).not.toHaveProperty("drill");
  });
});

describe("RESTORE_STATE", () => {
  it("round-trips a full snapshot (mode, blocklist, drill archive)", () => {
    const state = buildInitialState();
    const snap = serializePersistedState(state);
    const next = reducer(state, { type: "RESTORE_STATE", snapshot: snap });
    expect(next.mode).toBe(state.mode);
    expect(next.target).toBe(state.target);
    expect(next.blocklist).toEqual(state.blocklist);
    expect(next.customRules).toEqual(state.customRules);
    expect(next.drillReports).toEqual(state.drillReports);
    expect(next.drillHistory).toEqual(state.drillHistory);
  });

  it("merges a partial snapshot over a fresh baseline", () => {
    const state = buildInitialState();
    const next = reducer(state, {
      type: "RESTORE_STATE",
      snapshot: { mode: "blocking", target: "https://demo.example.com" },
    });
    expect(next.mode).toBe("blocking");
    expect(next.target).toBe("https://demo.example.com");
    // Untouched keys fall back to the seeded baseline…
    expect(next.alarms.length).toBeGreaterThan(0);
    expect(next.blocklist.length).toBeGreaterThan(0);
    // …and live streams are re-seeded rather than carried over.
    expect(next.drill).toBeNull();
    expect(next.logs.length).toBeGreaterThan(0);
  });

  it("forces a mid-run audit to 'done' so the UI can never wedge", () => {
    const state = buildInitialState();
    const next = reducer(state, {
      type: "RESTORE_STATE",
      snapshot: { audit: { ...state.audit, status: "running" as const, progress: 0.5 } },
    });
    expect(next.audit.status).toBe("done");
  });

  it("bumps the generation so effects re-arm after a restore", () => {
    const state = buildInitialState();
    const next = reducer(state, {
      type: "RESTORE_STATE",
      snapshot: { mode: "detection" },
    });
    expect(next.generation).toBe(state.generation + 1);
  });

  it("never throws when the snapshot is missing most keys", () => {
    const state = buildInitialState();
    expect(() =>
      reducer(state, { type: "RESTORE_STATE", snapshot: { mode: "blocking" } }),
    ).not.toThrow();
  });
});

describe("persistSnapshot", () => {
  it("writes a v1 snapshot envelope to localStorage", () => {
    const state = buildInitialState();
    persistSnapshot(serializePersistedState(state));
    const raw = store.get(PERSIST_KEY);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!) as { v: number; savedAt: number; state: Partial<WafState> };
    expect(parsed.v).toBe(1);
    expect(typeof parsed.savedAt).toBe("number");
    expect(parsed.state.mode).toBe(state.mode);
    expect(parsed.state).not.toHaveProperty("logs");
  });

  it("survives storage being unavailable (private mode)", () => {
    (globalThis as { localStorage?: unknown }).localStorage = {
      getItem: () => null,
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
      removeItem: () => undefined,
    };
    expect(() => persistSnapshot(serializePersistedState(buildInitialState()))).not.toThrow();
  });
});
