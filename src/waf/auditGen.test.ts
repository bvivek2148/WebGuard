import { describe, expect, it } from "vitest";
import {
  BASELINE_FINDINGS,
  FINDING_POOL_ID_SET,
  generateAudit,
  hashSeed,
  radarForFindings,
  scoreForFindings,
  RADAR_KEYS,
} from "./data";

/**
 * The vulnerability audit is dynamic by design: every Run Audit draws a fresh
 * target-seeded + randomized subset from the finding pool, so re-scans surface
 * findings that were not in the register before. These tests lock in that
 * contract — determinism given a seed, guaranteed core findings, bounded
 * scores, and real variation across runs/targets.
 */

const TARGET = "http://localhost:8080";

const idsOf = (scan: { findings: { id: string }[] }) => scan.findings.map((f) => f.id);

describe("generateAudit", () => {
  it("always includes the core defect set (no false-clean scans)", () => {
    for (let nonce = 1; nonce <= 12; nonce++) {
      const scan = generateAudit(TARGET, nonce);
      for (const id of ["HDR-01", "HDR-02", "CORS-01", "CK-01", "FP-01", "INJ-01", "INJ-02", "RL-01"]) {
        expect(scan.findings.some((f) => f.id === id), `nonce ${nonce} missing core ${id}`).toBe(true);
      }
    }
  });

  it("draws every finding from the real pool", () => {
    const scan = generateAudit(TARGET, 7);
    for (const f of scan.findings) {
      expect(FINDING_POOL_ID_SET.has(f.id)).toBe(true);
      expect(f.title.length).toBeGreaterThan(5);
      expect(f.evidence.length).toBeGreaterThan(10);
      expect(f.patch.length).toBeGreaterThan(10);
      expect(f.patched).toBe(false);
    }
  });

  it("is deterministic for the same target + nonce", () => {
    const a = generateAudit(TARGET, 42);
    const b = generateAudit(TARGET, 42);
    expect(idsOf(a)).toEqual(idsOf(b));
    expect(a.score).toBe(b.score);
    expect(a.radar).toEqual(b.radar);
  });

  it("varies across runs so re-scans can discover new findings", () => {
    const seen = new Set<string>();
    for (let nonce = 1; nonce <= 10; nonce++) {
      for (const id of idsOf(generateAudit(TARGET, nonce))) seen.add(id);
    }
    // 10 seeded runs must collectively surface more distinct findings than any
    // single scan shows — i.e. genuine re-discovery exists.
    expect(seen.size).toBeGreaterThan(BASELINE_FINDINGS.length);
    expect(seen.size).toBeGreaterThan(generateAudit(TARGET, 1).findings.length);
  });

  it("varies by target URL (same nonce)", () => {
    const seen = new Set<string>();
    const targets = [
      "http://localhost:8080",
      "https://demo.example.com",
      "https://store.acme.io/shop",
      "http://192.168.1.50:3000",
    ];
    for (const t of targets) {
      for (const id of idsOf(generateAudit(t, 5))) seen.add(id);
    }
    expect(seen.size).toBeGreaterThan(BASELINE_FINDINGS.length);
  });

  it("keeps the score inside the posture range and matching the formula", () => {
    for (let nonce = 1; nonce <= 12; nonce++) {
      const scan = generateAudit(TARGET, nonce);
      expect(scan.score).toBeGreaterThanOrEqual(5);
      expect(scan.score).toBeLessThanOrEqual(100);
      expect(scan.score).toBe(scoreForFindings(scan.findings));
      // A first-scan baseline should read as failing (grade F territory).
      expect(scan.score).toBeLessThan(60);
    }
  });

  it("derives a 5-axis OWASP radar bounded to 0..100", () => {
    for (let nonce = 1; nonce <= 6; nonce++) {
      const scan = generateAudit(TARGET, nonce);
      expect(scan.radar).toHaveLength(RADAR_KEYS.length);
      for (const r of scan.radar) {
        expect(r.value).toBeGreaterThanOrEqual(0);
        expect(r.value).toBeLessThanOrEqual(100);
      }
      // Injection axis is always hot because INJ core findings exist.
      expect(scan.radar[0].value).toBeGreaterThan(30);
    }
  });
});

describe("scoreForFindings", () => {
  it("scores a clean register at 100", () => {
    expect(scoreForFindings([])).toBe(100);
  });

  it("clamps at the floor when the register is saturated", () => {
    const critical = {
      id: "X",
      pillar: "injection",
      title: "x",
      severity: "critical" as const,
      evidence: "e",
      explanation: "e",
      patch: "p",
      patched: false,
    };
    expect(scoreForFindings([critical, critical, critical, critical, critical, critical, critical, critical, critical, critical, critical, critical])).toBe(5);
  });

  it("is monotonic: more severe findings never improve the score", () => {
    const base = generateAudit(TARGET, 3).findings;
    const worse = [...base, { ...base[0], id: "extra", severity: "critical" as const }];
    expect(scoreForFindings(worse)).toBeLessThanOrEqual(scoreForFindings(base));
  });
});

describe("radarForFindings", () => {
  it("maps an injection finding onto the Injection axis", () => {
    const f = {
      id: "INJ-99",
      pillar: "injection",
      title: "test",
      severity: "high" as const,
      evidence: "e",
      explanation: "e",
      patch: "p",
      patched: false,
    };
    const radar = radarForFindings([f]);
    expect(radar[0].axis).toBe("Injection");
    expect(radar[0].value).toBeGreaterThan(0);
    // Unhit axes keep a residual floor, never zero — chart stays legible.
    expect(radar[1].value).toBe(6);
  });
});

describe("hashSeed", () => {
  it("is stable and sensitive to input", () => {
    expect(hashSeed("http://localhost:8080")).toBe(hashSeed("http://localhost:8080"));
    expect(hashSeed("http://localhost:8080")).not.toBe(hashSeed("https://demo.example.com"));
  });
});
