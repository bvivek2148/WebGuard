import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { useWaf, timeAgo, type WafAction } from "../engine";
import type {
  AuditHistoryEntry,
  AuditFinding,
  RadarAxis,
  Severity,
} from "../types";
import { SEVERITY_META } from "../types";
import { PILLARS, gradeForScore } from "../data";
import {
  ArrowLeft,
  BarChart3,
  Bug,
  CheckCircle2,
  ChevronRight,
  ClipboardCopy,
  Clock,
  FileDown,
  Globe,
  History,
  Radar as RadarIcon,
  Route,
  Shield,
  ShieldOff,
  Target,
  Timer,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { ExportMenu, BulkExportMenu } from "./ExportMenu";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const PILLAR_ICONS: Record<string, string> = {
  headers: "🛡️",
  cors: "🌐",
  cookies: "🍪",
  fingerprint: "🔍",
  injection: "💉",
  ratelimit: "⏱️",
};

const CVSS_BASE: Record<Severity, number> = {
  critical: 9.1,
  high: 7.5,
  medium: 5.3,
  low: 3.1,
};

function cvssFor(f: AuditFinding): string {
  const jitter = (f.id.charCodeAt(f.id.length - 1) % 5) / 10;
  const sign = f.severity === "critical" || f.severity === "high" ? 1 : -1;
  return (CVSS_BASE[f.severity] + sign * jitter).toFixed(1);
}

const CWE_MAP: Record<string, string> = {
  "HDR-07": "CWE-525",
  "CORS-03": "CWE-942",
  "CK-03": "CWE-1004",
  "FP-02": "CWE-548",
  "FP-03": "CWE-209",
  "FP-04": "CWE-540",
  "INJ-04": "CWE-22",
  "INJ-05": "CWE-78",
  "RL-02": "CWE-307",
  "RL-03": "CWE-640",
};

function cweFor(f: AuditFinding): string {
  if (CWE_MAP[f.id]) return CWE_MAP[f.id];
  switch (f.pillar) {
    case "headers":
      return "CWE-693";
    case "cors":
      return "CWE-942";
    case "cookies":
      return "CWE-614";
    case "fingerprint":
      return "CWE-200";
    case "injection":
      if (/sql|blind/i.test(f.title)) return "CWE-89";
      if (/script|xss/i.test(f.title)) return "CWE-79";
      if (/command/i.test(f.title)) return "CWE-77";
      return "CWE-74";
    case "ratelimit":
      return "CWE-770";
    default:
      return "CWE-693";
  }
}

const PRIORITY_FOR: Record<Severity, "P1" | "P2" | "P3"> = {
  critical: "P1",
  high: "P2",
  medium: "P3",
  low: "P3",
};

const COMPLIANCE = [
  { std: "PCI-DSS", control: "Req 6.5 — injection prevention", pillar: "injection" },
  { std: "PCI-DSS", control: "Req 6.6 — web application firewall", pillar: "headers" },
  { std: "OWASP ASVS", control: "V3 — session cookie flags", pillar: "cookies" },
  { std: "OWASP ASVS", control: "V14 — config & fingerprinting", pillar: "fingerprint" },
  { std: "ISO 27001", control: "A.12.6.1 — DoS resilience", pillar: "ratelimit" },
  { std: "OWASP Top 10", control: "A01/A05 — access control & misconfig", pillar: "cors" },
];

// ---------------------------------------------------------------------------
// Severity badge helper
// ---------------------------------------------------------------------------
function SevBadge({ sev }: { sev: Severity }) {
  const m = SEVERITY_META[sev];
  return (
    <span className={cn("rounded-md border px-1.5 py-0.5 font-mono text-[9px] font-bold", m.badge)}>
      {m.label}
    </span>
  );
}

function PriorityBadge({ sev }: { sev: Severity }) {
  const p = PRIORITY_FOR[sev];
  return (
    <span
      className={cn(
        "rounded-md border px-1.5 py-0.5 font-mono text-[9px] font-bold",
        p === "P1"
          ? "border-wg-rose/50 bg-wg-rose/10 text-wg-rose"
          : p === "P2"
            ? "border-wg-orange/50 bg-wg-orange/10 text-wg-orange"
            : "border-wg-amber/50 bg-wg-amber/10 text-wg-amber",
      )}
    >
      {p}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Detail View — comprehensive scan report
// ---------------------------------------------------------------------------
function ScanDetailView({ entry, onBack, dispatch }: { entry: AuditHistoryEntry; onBack: () => void; dispatch: (action: WafAction) => void }) {
  const findings = entry.auditFindings ?? [];
  const radar = entry.auditRadar ?? [];
  const comparison = entry.comparison ?? [];
  const stats = entry.scanStats;
  const baselineRadar = entry.baselineRadar ?? [];
  const hasFullData = findings.length > 0 || radar.length > 0 || comparison.length > 0;

  // Severity breakdown
  const sevCounts = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) counts[f.severity]++;
    return counts;
  }, [findings]);

  const sevBarData = useMemo(
    () =>
      (["critical", "high", "medium", "low"] as Severity[]).map((s) => ({
        name: SEVERITY_META[s].label,
        value: sevCounts[s],
        fill: SEVERITY_META[s].color,
      })),
    [sevCounts],
  );

  // Pillar breakdown
  const pillarCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const f of findings) map.set(f.pillar, (map.get(f.pillar) ?? 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  }, [findings]);

  // Grouped findings by pillar
  const findingsByPillar = useMemo(() => {
    const map = new Map<string, AuditFinding[]>();
    for (const f of findings) {
      const list = map.get(f.pillar) ?? [];
      list.push(f);
      map.set(f.pillar, list);
    }
    return [...map.entries()];
  }, [findings]);

  // Remediation estimate
  const estRemediation = useMemo(() => {
    const mins = findings.reduce(
      (s, f) => s + (f.severity === "critical" ? 45 : f.severity === "high" ? 30 : f.severity === "medium" ? 20 : 10),
      0,
    );
    return { h: Math.floor(mins / 60), m: mins % 60 };
  }, [findings]);

  // Open vs patched
  const openCount = findings.filter((f) => !f.patched).length;
  const patchedCount = findings.filter((f) => f.patched).length;

  // Baseline radar comparison data
  const radarCompareData = useMemo(() => {
    if (baselineRadar.length === 0 || radar.length === 0) return [];
    return baselineRadar.map((b, i) => ({
      axis: b.axis,
      baseline: b.value,
      current: radar[i]?.value ?? 0,
    }));
  }, [baselineRadar, radar]);

  // Compliance results
  const complianceResults = useMemo(() => {
    return COMPLIANCE.map((c) => {
      const pillarFindings = findings.filter((f) => f.pillar === c.pillar);
      const failing = pillarFindings.filter((f) => !f.patched).length;
      return { ...c, pass: failing === 0, failing, total: pillarFindings.length };
    });
  }, [findings]);

  // Total fixed vs unfixed
  const totalFixed = comparison.filter((r) => r.fixed).length;

  return (
    <div className="flex flex-col gap-4">
      {/* Header with back button */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onBack}
          className="flex size-7 items-center justify-center rounded-lg border border-border/50 text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground"
        >
          <ArrowLeft className="size-3.5" />
        </button>
        <div className="min-w-0 flex-1">
          <h3 className="truncate text-sm font-semibold">Scan Detail Report</h3>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-muted-foreground">
            <span>{new Date(entry.ts).toLocaleString()}</span>
            <span className="hidden text-foreground/30 sm:inline">·</span>
            <span className="hidden sm:inline">{timeAgo(entry.ts)}</span>
            <span className="text-foreground/30">·</span>
            <button
              type="button"
              className="group flex items-center gap-1 font-mono text-muted-foreground transition-colors hover:text-wg-cyan"
              onClick={() => { navigator.clipboard.writeText(entry.target ?? "Unknown"); toast.success("Target URL copied"); }}
            >
              <Globe className="size-3 shrink-0" />
              <span className="truncate">{entry.target ?? "Unknown"}</span>
              <ClipboardCopy className="size-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
            </button>
          </div>
        </div>
        <button
          type="button"
          className="flex h-7 items-center gap-1.5 rounded-md border border-wg-rose/30 px-2 text-[10px] font-semibold text-wg-rose transition-colors hover:bg-wg-rose/10"
          title="Delete this scan record"
          onClick={() => {
            dispatch({ type: "DELETE_AUDIT_HISTORY", id: entry.id });
            toast.success("Scan record deleted");
            onBack();
          }}
        >
          <Trash2 className="size-3" /> Delete
        </button>
        <ExportMenu
          data={{
            label: "Scan report",
            filename: `webguard-scan-${entry.id}`,
            jsonData: entry,
            csvRows: findings.length > 0
              ? [["ID", "Pillar", "Title", "Severity", "Patched", "Evidence"], ...findings.map((f) => [f.id, f.pillar, f.title, f.severity, String(f.patched), f.evidence.replace(/\n/g, " ").replace(/"/g, '""')])]
              : undefined,
            htmlContent: `<!doctype html><html><head><meta charset="utf-8"><title>WebGuard Scan — ${entry.target ?? "Unknown"}</title><style>body{font-family:system-ui;background:#0b1120;color:#e2e8f0;padding:2rem}h1{color:#22d3ee}table{width:100%;border-collapse:collapse;font-size:.8rem}td,th{border:1px solid #1e293b;padding:.5rem}.badge{display:inline-block;padding:.2rem .6rem;border-radius:9999px;font-size:.75rem;font-weight:700;border:1px solid}.ok{color:#34d399;border-color:#34d399}.bad{color:#fb7185;border-color:#fb7185}</style></head><body><h1>WebGuard Scan Report</h1><p>Target: <b>${entry.target ?? "Unknown"}</b> · Score: <b>${entry.score}/100</b> · Grade: <b>${entry.grade}</b> · <span class="badge ${entry.shielded ? "ok" : "bad"}">${entry.shielded ? "WAF ACTIVE" : "WAF OFF"}</span></p><h2>Findings</h2><table><thead><tr><th>ID</th><th>Pillar</th><th>Title</th><th>Severity</th><th>Status</th></tr></thead><tbody>${findings.map((f) => "<tr><td>" + f.id + "</td><td>" + f.pillar + "</td><td>" + f.title + "</td><td>" + f.severity.toUpperCase() + "</td><td>" + (f.patched ? "PATCHED" : "OPEN") + "</td></tr>").join("")}</tbody></table></body></html>`,
          }}
          triggerLabel="Export scan"
        />
      </div>

      {/* Missing data banner for older entries */}
      {!hasFullData && (
        <div className="flex items-start gap-2 rounded-lg border border-wg-amber/30 bg-wg-amber/5 px-3 py-2.5">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-wg-amber" />
          <div className="text-[11px]">
            <p className="font-semibold text-wg-amber">Partial scan data</p>
            <p className="text-muted-foreground">This scan was recorded before detailed telemetry was enabled. Score, grade, and findings count are available, but itemized findings, radar data, and comparison details were not captured.</p>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 1 — Score & Grade Hero
      ═══════════════════════════════════════════════════════════════════ */}
      <div className="flex flex-wrap items-center gap-4 rounded-xl border border-border/40 bg-muted/20 p-4">
        <div className="flex items-center gap-3">
          <span
            className={cn(
              "font-mono text-4xl font-bold",
              entry.shielded ? "text-wg-emerald" : "text-wg-rose",
            )}
          >
            {entry.score}
            <span className="ml-1 text-sm">/100</span>
          </span>
          <span
            className={cn(
              "rounded-lg border px-2.5 py-1 font-mono text-xs font-bold",
              entry.shielded
                ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
            )}
          >
            GRADE {entry.grade}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[10px] font-bold tracking-wider",
              entry.shielded
                ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
            )}
          >
            {entry.shielded ? <Shield className="size-3" /> : <ShieldOff className="size-3" />}
            {entry.shielded ? "WAF ACTIVE" : "WAF OFF"}
          </span>
          <span className="text-[11px] text-muted-foreground">
            {entry.findings} finding{entry.findings !== 1 ? "s" : ""}
          </span>
        </div>
        {entry.baselineScore !== undefined && entry.baselineScore !== entry.score && (
          <span className="text-[11px] text-muted-foreground">
            Baseline: <span className="font-mono font-bold text-wg-rose">{entry.baselineScore}</span>/100
          </span>
        )}
      </div>

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 2 — Scan Summary + Stats Grid
      ═══════════════════════════════════════════════════════════════════ */}
      <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
        <p className="mb-2 text-[11px] font-semibold text-muted-foreground">📋 Scan Summary</p>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px] sm:grid-cols-4">
          <div><span className="text-muted-foreground">Scan ID</span><p className="font-mono text-xs font-bold">{entry.id}</p></div>
          <div><span className="text-muted-foreground">Target</span><p className="truncate font-mono text-xs font-bold">{(entry.target ?? "Unknown").replace(/^https?:\/\//, "").slice(0, 30)}</p></div>
          <div><span className="text-muted-foreground">Date</span><p className="font-mono text-xs font-bold">{new Date(entry.ts).toLocaleDateString()}</p></div>
          <div><span className="text-muted-foreground">Time</span><p className="font-mono text-xs font-bold">{new Date(entry.ts).toLocaleTimeString()}</p></div>
          <div><span className="text-muted-foreground">Protection</span><p className={cn("font-mono text-xs font-bold", entry.shielded ? "text-wg-emerald" : "text-wg-rose")}>{entry.shielded ? "✅ Active" : "❌ Inactive"}</p></div>
          <div><span className="text-muted-foreground">Findings</span><p className="font-mono text-xs font-bold">{entry.findings} total ({openCount} open, {patchedCount} patched)</p></div>
          <div><span className="text-muted-foreground">Posture Score</span><p className={cn("font-mono text-xs font-bold", entry.score >= 90 ? "text-wg-emerald" : entry.score >= 50 ? "text-wg-amber" : "text-wg-rose")}>{entry.score}/100 — Grade {entry.grade}</p></div>
          {entry.baselineScore !== undefined && (
            <div><span className="text-muted-foreground">Baseline Score</span><p className="font-mono text-xs font-bold text-wg-rose">{entry.baselineScore}/100 — Grade {gradeForScore(entry.baselineScore).grade}</p></div>
          )}
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 3 — Scan Probe Stats
      ═══════════════════════════════════════════════════════════════════ */}
      {stats && (
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Route className="size-3.5 text-wg-cyan" /> Scan Probe Statistics
          </p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              { label: "Probes sent", value: stats.probes.toLocaleString(), icon: <Bug className="size-3" /> },
              { label: "Endpoints scanned", value: String(stats.endpoints), icon: <Globe className="size-3" /> },
              { label: "Duration", value: `${(stats.durationMs / 1000).toFixed(1)}s`, icon: <Timer className="size-3" /> },
              { label: "Confidence", value: `${stats.confidence.toFixed(1)}%`, icon: <CheckCircle2 className="size-3" /> },
            ].map((s) => (
              <div key={s.label} className="flex items-center gap-2.5 rounded-lg border border-border/40 bg-muted/30 px-3 py-2.5">
                <span className="text-wg-cyan">{s.icon}</span>
                <div>
                  <p className="text-[9px] text-muted-foreground">{s.label}</p>
                  <p className="font-mono text-sm font-bold">{s.value}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 4 — Remediation Estimate
      ═══════════════════════════════════════════════════════════════════ */}
      {findings.length > 0 && (
        <div className="flex flex-wrap items-center gap-4 rounded-xl border border-border/40 bg-muted/20 p-3">
          <span className="flex size-8 items-center justify-center rounded-lg bg-wg-amber/10 text-wg-amber">
            <Clock className="size-4" />
          </span>
          <div>
            <p className="text-xs font-semibold text-foreground">Estimated Remediation Time</p>
            <p className="text-[11px] text-muted-foreground">
              {entry.shielded
                ? "Origin fixes pending — edge patches already contain everything"
                : `${estRemediation.h}h ${estRemediation.m}m to remediate ${entry.findings} findings in code`}
            </p>
          </div>
          <span className="ml-auto font-mono text-lg font-bold text-wg-amber">
            {estRemediation.h}h {estRemediation.m}m
          </span>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 5 — OWASP Radar + Severity + Baseline Comparison
      ═══════════════════════════════════════════════════════════════════ */}
      <div className="grid gap-3 sm:grid-cols-2">
        {/* OWASP Radar */}
        {radar.length > 0 && (
          <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
            <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
              <RadarIcon className="size-3.5 text-wg-violet" /> OWASP Threat Radar
            </p>
            <div className="h-[220px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="75%" data={radar}>
                  <PolarGrid stroke="#1e293b" />
                  <PolarAngleAxis dataKey="axis" tick={{ fontSize: 9, fill: "#64748b" }} />
                  <PolarRadiusAxis domain={[0, 100]} tick={false} axisLine={false} />
                  <Radar name="Threat" dataKey="value" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.2} strokeWidth={2} />
                  <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 11 }} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
            {/* Radar axis values table */}
            <div className="mt-2 grid grid-cols-1 gap-1">
              {radar.map((r) => (
                <div key={r.axis} className="flex items-center justify-between text-[10px]">
                  <span className="text-muted-foreground">{r.axis}</span>
                  <span className={cn("font-mono font-bold", r.value >= 80 ? "text-wg-rose" : r.value >= 50 ? "text-wg-amber" : "text-wg-emerald")}>{r.value}/100</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Severity Breakdown */}
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <BarChart3 className="size-3.5 text-wg-amber" /> Severity Breakdown
          </p>
          <div className="h-[200px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevBarData} layout="vertical" margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 9, fill: "#64748b" }} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: "#64748b" }} width={70} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16}>
                  {sevBarData.map((d, i) => <Cell key={i} fill={d.fill} fillOpacity={0.7} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {sevBarData.map((d) => (
              <span key={d.name} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                <span className="size-2 rounded-full" style={{ backgroundColor: d.fill }} />
                {d.name}: {d.value}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 6 — Baseline vs Shielded Radar Comparison
      ═══════════════════════════════════════════════════════════════════ */}
      {radarCompareData.length > 0 && (
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <RadarIcon className="size-3.5 text-wg-cyan" /> Baseline vs Shielded Threat Profile
          </p>
          <div className="h-[180px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={radarCompareData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" vertical={false} />
                <XAxis dataKey="axis" tick={{ fontSize: 8, fill: "#64748b" }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: "#64748b" }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 11 }} />
                <Area type="monotone" dataKey="baseline" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.15} strokeWidth={2} name="Baseline" />
                <Area type="monotone" dataKey="current" stroke="#34d399" fill="#34d399" fillOpacity={0.15} strokeWidth={2} name="Current" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-1 flex flex-wrap gap-3 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1"><span className="size-2 rounded-full bg-rose-400" /> Baseline (unshielded)</span>
            <span className="flex items-center gap-1"><span className="size-2 rounded-full bg-emerald-400" /> Current (scan result)</span>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 7 — Pillar Breakdown
      ═══════════════════════════════════════════════════════════════════ */}
      {pillarCounts.length > 0 && (
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Bug className="size-3.5 text-wg-orange" /> Pillar Breakdown
          </p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {pillarCounts.map(([pillar, count]) => {
              const pillarDef = PILLARS.find((p) => p.id === pillar);
              const pillarFindings = findings.filter((f) => f.pillar === pillar);
              const pillarOpen = pillarFindings.filter((f) => !f.patched).length;
              return (
                <div key={pillar} className="flex flex-col gap-1 rounded-lg border border-border/40 bg-muted/30 px-3 py-2.5">
                  <div className="flex items-center gap-1.5">
                    <span>{PILLAR_ICONS[pillar] ?? "📌"}</span>
                    <span className="text-[10px] font-semibold">{pillarDef?.title ?? pillar}</span>
                  </div>
                  <div className="flex items-center gap-2 text-[10px]">
                    <span className="font-mono font-bold text-wg-rose">{count} finding{count !== 1 ? "s" : ""}</span>
                    {pillarOpen > 0 && <span className="text-wg-amber">{pillarOpen} open</span>}
                    {pillarOpen === 0 && <span className="text-wg-emerald">all patched</span>}
                  </div>
                  {pillarDef && <p className="text-[9px] leading-tight text-muted-foreground">{pillarDef.summary}</p>}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 8 — Compliance Mapping
      ═══════════════════════════════════════════════════════════════════ */}
      {complianceResults.length > 0 && (
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <CheckCircle2 className="size-3.5 text-wg-emerald" /> Compliance Impact
          </p>
          <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {complianceResults.map((c) => (
              <div key={c.std + c.control} className="flex items-center gap-2 rounded-lg border border-border/40 bg-muted/30 px-3 py-2">
                <span className={cn("flex size-6 shrink-0 items-center justify-center rounded-md", c.pass ? "bg-wg-emerald/10 text-wg-emerald" : "bg-wg-rose/10 text-wg-rose")}>
                  {c.pass ? <CheckCircle2 className="size-3.5" /> : <TriangleAlert className="size-3.5" />}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-[10px] font-bold text-foreground">{c.std}</p>
                  <p className="truncate text-[9px] text-muted-foreground">{c.control}</p>
                </div>
                <span className={cn("shrink-0 rounded-md border px-1.5 py-0.5 text-[9px] font-bold", c.pass ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose")}>
                  {c.pass ? "PASS" : `${c.failing} FAIL`}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 9 — Itemized Findings (full detail)
      ═══════════════════════════════════════════════════════════════════ */}
      {findings.length > 0 && (
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
              <TriangleAlert className="size-3.5 text-wg-rose" /> Itemized Findings ({findings.length})
            </p>
            <div className="flex gap-1.5 text-[9px]">
              {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
                sevCounts[s] > 0 && <span key={s} className="flex items-center gap-1 rounded-full border border-border/40 bg-muted/30 px-1.5 py-0.5">
                  <span className="size-1.5 rounded-full" style={{ backgroundColor: SEVERITY_META[s].color }} />
                  {sevCounts[s]} {SEVERITY_META[s].label}
                </span>
              ))}
            </div>
          </div>
          <Accordion type="multiple" className="flex flex-col gap-1.5">
            {findings.map((f) => (
              <AccordionItem key={f.id} value={f.id} className="rounded-lg border border-border/40 bg-muted/30 px-3">
                <AccordionTrigger className="py-2 text-[11px] font-semibold hover:no-underline">
                  <div className="flex min-w-0 flex-1 items-center gap-2 text-left">
                    <SevBadge sev={f.severity} />
                    <PriorityBadge sev={f.severity} />
                    <span className="min-w-0 flex-1 truncate">{f.title}</span>
                    <span className="shrink-0 rounded-md border border-border/40 bg-muted/50 px-1.5 py-0.5 text-[9px] text-muted-foreground">
                      {f.pillar}
                    </span>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pb-3">
                  <div className="flex flex-col gap-2.5 text-[11px]">
                    {/* Meta row */}
                    <div className="flex flex-wrap gap-2 text-[10px]">
                      <span className="rounded-md border border-border/40 bg-muted/50 px-1.5 py-0.5 font-mono font-bold text-muted-foreground">ID: {f.id}</span>
                      <span className="rounded-md border border-border/40 bg-muted/50 px-1.5 py-0.5 font-mono font-bold text-muted-foreground">CVSS: {cvssFor(f)}</span>
                      <span className="rounded-md border border-border/40 bg-muted/50 px-1.5 py-0.5 font-mono font-bold text-muted-foreground">CWE: {cweFor(f)}</span>
                      <span className="rounded-md border border-border/40 bg-muted/50 px-1.5 py-0.5 font-mono font-bold text-muted-foreground">Pillar: {f.pillar}</span>
                      {f.patched && (
                        <span className="flex items-center gap-1 rounded-md border border-wg-emerald/40 bg-wg-emerald/10 px-1.5 py-0.5 font-bold text-wg-emerald">
                          <CheckCircle2 className="size-2.5" /> PATCHED
                        </span>
                      )}
                      {!f.patched && (
                        <span className="flex items-center gap-1 rounded-md border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 font-bold text-wg-rose">
                          ⚠ OPEN
                        </span>
                      )}
                    </div>
                    {/* Explanation */}
                    <div>
                      <p className="mb-0.5 font-semibold text-muted-foreground">Explanation</p>
                      <p className="text-foreground/80">{f.explanation}</p>
                    </div>
                    {/* Evidence */}
                    <div>
                      <p className="mb-0.5 font-semibold text-muted-foreground">Raw HTTP Evidence</p>
                      <pre className="max-h-36 overflow-auto whitespace-pre-wrap rounded-lg border border-border/40 bg-muted/50 p-2 font-mono text-[10px] leading-relaxed text-wg-cyan">
                        {f.evidence}
                      </pre>
                    </div>
                    {/* Patch */}
                    {f.patch && (
                      <div>
                        <p className="mb-0.5 font-semibold text-muted-foreground">Virtual Patch Applied</p>
                        <pre className="max-h-28 overflow-auto whitespace-pre-wrap rounded-lg border border-wg-emerald/30 bg-wg-emerald/5 p-2 font-mono text-[10px] text-wg-emerald">
                          {f.patch}
                        </pre>
                      </div>
                    )}
                    {/* OWASP axis */}
                    {f.axis && (
                      <div className="text-[10px] text-muted-foreground">
                        <span className="font-semibold">OWASP Axis:</span> <span className="font-mono">{f.axis}</span>
                      </div>
                    )}
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 10 — Before vs After Comparison Matrix
      ═══════════════════════════════════════════════════════════════════ */}
      {comparison.length > 0 && (
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <div className="mb-2 flex items-center justify-between">
            <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
              <CheckCircle2 className="size-3.5 text-wg-emerald" /> Before vs After Comparison
            </p>
            <span className="text-[10px] text-muted-foreground">{totalFixed}/{comparison.length} controls fixed</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[10px]">
              <thead>
                <tr className="border-b border-border/40">
                  <th className="py-1.5 pr-2 font-semibold text-muted-foreground">Control</th>
                  <th className="py-1.5 pr-2 font-semibold text-wg-rose">Before (WAF OFF)</th>
                  <th className="py-1.5 font-semibold text-wg-emerald">After (WAF ON)</th>
                </tr>
              </thead>
              <tbody>
                {comparison.map((row, i) => (
                  <tr key={i} className="border-b border-border/20">
                    <td className="py-1.5 pr-2 font-semibold">{row.control}</td>
                    <td className="py-1.5 pr-2 text-wg-rose/80">{row.before}</td>
                    <td className="py-1.5">
                      <span className="flex items-center gap-1 text-wg-emerald/80">
                        {row.after}
                        {row.fixed && <CheckCircle2 className="size-3 text-wg-emerald" />}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
          SECTION 11 — Remediation Roadmap
      ═══════════════════════════════════════════════════════════════════ */}
      {openCount > 0 && (
        <div className="rounded-xl border border-border/40 bg-muted/20 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Timer className="size-3.5 text-wg-amber" /> Remediation Roadmap ({openCount} open findings)
          </p>
          <div className="flex flex-col gap-1">
            {findings
              .filter((f) => !f.patched)
              .sort((a, b) => {
                const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
                return order[a.severity] - order[b.severity];
              })
              .map((f, i) => (
                <div key={f.id} className="flex items-center gap-2 rounded-lg border border-border/30 bg-muted/20 px-3 py-2 text-[10px]">
                  <span className="w-5 text-center font-mono font-bold text-muted-foreground">#{i + 1}</span>
                  <SevBadge sev={f.severity} />
                  <PriorityBadge sev={f.severity} />
                  <span className="min-w-0 flex-1 truncate font-semibold">{f.title}</span>
                  <span className="shrink-0 text-muted-foreground">{f.pillar}</span>
                  <span className="shrink-0 font-mono font-bold text-muted-foreground">CVSS {cvssFor(f)}</span>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Dialog
// ---------------------------------------------------------------------------
export function AuditHistoryDialog({
  open,
  onOpenChange,
  initialEntryId,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  initialEntryId?: string | null;
}) {
  const { state, dispatch } = useWaf();
  const history = state.auditHistory;
  const [selectedEntry, setSelectedEntry] = useState<AuditHistoryEntry | null>(null);

  const uniqueTargets = useMemo(() => {
    const set = new Set<string>();
    for (const h of history) set.add(h.target ?? "Unknown");
    return [...set];
  }, [history]);

  const grouped = useMemo(() => {
    const map = new Map<string, AuditHistoryEntry[]>();
    for (const h of history) {
      const list = map.get(h.target ?? "Unknown") ?? [];
      list.push(h);
      map.set(h.target ?? "Unknown", list);
    }
    return [...map.entries()].sort((a, b) => {
      const aLatest = Math.max(...a[1].map((h) => h.ts));
      const bLatest = Math.max(...b[1].map((h) => h.ts));
      return bLatest - aLatest;
    });
  }, [history]);

  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);

  const filtered = selectedTarget
    ? history.filter((h) => (h.target ?? "Unknown") === selectedTarget)
    : history;

  // Sync selectedEntry if history changes
  const activeEntry = selectedEntry
    ? history.find((h) => h.id === selectedEntry.id) ?? null
    : null;

  // Auto-select entry when initialEntryId is provided
  useEffect(() => {
    if (open && initialEntryId) {
      const match = history.find((h) => h.id === initialEntryId);
      if (match) setSelectedEntry(match);
    }
  }, [open, initialEntryId, history]);

  // Reset selection when dialog closes
  useEffect(() => {
    if (!open) setSelectedEntry(null);
  }, [open]);

  if (!open) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl gap-0 p-0 overflow-hidden sm:max-w-3xl">
        <DialogHeader className="border-b border-border/50 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 text-sm">
            <History className="size-4 text-wg-cyan" />
            {activeEntry ? "Scan Detail Report" : "Scan History"}
          </DialogTitle>
          <DialogDescription className="text-xs">
            {activeEntry
              ? `${activeEntry.target ?? "Unknown"} — scanned ${timeAgo(activeEntry.ts)}`
              : `${history.length} scans across ${uniqueTargets.length} target${uniqueTargets.length !== 1 ? "s" : ""} — every completed audit is recorded here`}
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="max-h-[70vh]">
          {activeEntry ? (
            /* Detail view */
            <div className="p-4">
              <ScanDetailView entry={activeEntry} onBack={() => setSelectedEntry(null)} dispatch={dispatch} />
            </div>
          ) : (
            /* List view */
            <div className="flex flex-col">
              {/* Target filter chips */}
              {uniqueTargets.length > 1 && (
                <div className="flex flex-wrap gap-1.5 border-b border-border/50 px-5 py-2.5">
                  <button
                    type="button"
                    onClick={() => setSelectedTarget(null)}
                    className={cn(
                      "rounded-full border px-2.5 py-1 text-[10px] font-semibold transition-colors",
                      !selectedTarget
                        ? "border-wg-cyan/40 bg-wg-cyan/15 text-wg-cyan"
                        : "border-border/50 text-muted-foreground hover:text-foreground",
                    )}
                  >
                    All targets ({history.length})
                  </button>
                  {grouped.map(([target, entries]) => (
                    <button
                      key={target}
                      type="button"
                      onClick={() => setSelectedTarget(target)}
                      className={cn(
                        "flex items-center gap-1 rounded-full border px-2.5 py-1 text-[10px] font-semibold transition-colors",
                        selectedTarget === target
                          ? "border-wg-cyan/40 bg-wg-cyan/15 text-wg-cyan"
                          : "border-border/50 text-muted-foreground hover:text-foreground",
                      )}
                    >
                      <Globe className="size-3" />
                      {(target ?? "Unknown").replace(/^https?:\/\//, "").slice(0, 30)}
                      <span className="ml-0.5 rounded-full bg-muted/60 px-1.5 py-0.5 text-[8px] text-muted-foreground">
                        {entries.length}
                      </span>
                    </button>
                  ))}
                </div>
              )}

              {/* History entries */}
              <div className="flex flex-col gap-1.5 p-4">
                {filtered.length === 0 ? (
                  <p className="py-8 text-center text-xs text-muted-foreground">
                    No scan history yet — run an audit to record your first scan.
                  </p>
                ) : (
                  filtered.map((h) => (
                    <button
                      key={h.id}
                      type="button"
                      onClick={() => setSelectedEntry(h)}
                      className="group flex flex-col gap-1.5 rounded-xl border border-border/40 bg-muted/20 px-3.5 py-2.5 text-left transition-colors hover:border-wg-cyan/30 hover:bg-muted/40 sm:flex-row sm:items-center sm:gap-x-3"
                    >
                      {/* score + grade */}
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            "font-mono text-base font-bold",
                            h.shielded ? "text-wg-emerald" : "text-wg-rose",
                          )}
                        >
                          {h.score}
                          <span className="ml-0.5 text-[10px]">/100</span>
                        </span>
                        <span
                          className={cn(
                            "rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold",
                            h.shielded
                              ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                              : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
                          )}
                        >
                          GRADE {h.grade}
                        </span>
                      </div>

                      {/* target URL */}
                      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                        <Target className="size-3 shrink-0" />
                        <span className="truncate font-mono" title={h.target ?? "Unknown"}>
                          {(h.target ?? "Unknown").replace(/^https?:\/\//, "").slice(0, 45)}
                        </span>
                      </div>

                      {/* findings + shield badge */}
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-muted-foreground">{h.findings} findings</span>
                        <span
                          className={cn(
                            "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                            h.shielded
                              ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                              : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
                          )}
                        >
                          {h.shielded ? <Shield className="size-2.5" /> : <ShieldOff className="size-2.5" />}
                          {h.shielded ? "WAF ACTIVE" : "WAF OFF"}
                        </span>
                      </div>

                      {/* time + delete + chevron */}
                      <span className="ml-auto flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
                        {timeAgo(h.ts)}
                        <button
                          type="button"
                          className="flex size-5 items-center justify-center rounded-md text-muted-foreground/50 transition-colors hover:bg-wg-rose/10 hover:text-wg-rose"
                          title="Delete this scan record"
                          onClick={(e) => {
                            e.stopPropagation();
                            dispatch({ type: "DELETE_AUDIT_HISTORY", id: h.id });
                            toast.success("Scan record deleted");
                          }}
                        >
                          <Trash2 className="size-3" />
                        </button>
                        <ChevronRight className="size-3 text-muted-foreground/50 transition-colors group-hover:text-wg-cyan" />
                      </span>
                    </button>
                  ))
                )}
              </div>
            </div>
          )}
        </ScrollArea>

        {/* footer */}
        <div className="flex items-center justify-between border-t border-border/50 px-5 py-2.5">
          <span className="text-[10px] text-muted-foreground">
            {activeEntry
              ? "Back to list"
              : `${filtered.length} of ${history.length} scans shown`}
          </span>
          {activeEntry ? (
            <Button
              variant="outline"
              size="sm"
              className="h-7 gap-1.5 text-[10px]"
              onClick={() => setSelectedEntry(null)}
            >
              <ArrowLeft className="size-3" /> Back to list
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="flex h-7 items-center gap-1.5 rounded-md border border-wg-rose/30 px-2 text-[10px] font-semibold text-wg-rose transition-colors hover:bg-wg-rose/10"
                title="Delete all scan history"
                onClick={() => {
                  dispatch({ type: "CLEAR_AUDIT_HISTORY" });
                  toast.success("All scan history cleared");
                }}
              >
                <Trash2 className="size-3" /> Clear all
              </button>
              <BulkExportMenu
                data={{
                  label: "scan history",
                  filename: "webguard-scan-history",
                jsonData: history,
                csvRows: [["Scan ID", "Timestamp", "Target", "Score", "Grade", "Shielded", "Findings"],
                  ...history.map((h) => [h.id, new Date(h.ts).toISOString(), h.target ?? "Unknown", String(h.score), h.grade, String(h.shielded), String(h.findings)])],
                htmlContent: `<!doctype html><html><head><meta charset="utf-8"><title>WebGuard Scan History</title><style>body{font-family:system-ui;background:#0b1120;color:#e2e8f0;padding:2rem}h1{color:#22d3ee}table{width:100%;border-collapse:collapse;font-size:.8rem}td,th{border:1px solid #1e293b;padding:.5rem}th{background:#111a2e}</style></head><body><h1>WebGuard Scan History</h1><p>${history.length} scans</p><table><thead><tr><th>Time</th><th>Target</th><th>Score</th><th>Grade</th><th>WAF</th><th>Findings</th></tr></thead><tbody>${history.map((h) => "<tr><td>" + new Date(h.ts).toLocaleString() + "</td><td>" + (h.target ?? "Unknown") + "</td><td>" + h.score + "/100</td><td>" + h.grade + "</td><td>" + (h.shielded ? "ACTIVE" : "OFF") + "</td><td>" + h.findings + "</td></tr>").join("")}</tbody></table></body></html>`,
              }}
            />
              </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
