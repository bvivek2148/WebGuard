import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import { generateAudit } from "../data";
import type { FindingSource, FindingStatus, Severity, VulnFinding } from "../types";
import { SEVERITY_META } from "../types";
import { flagEmoji, SectionTitle, SeverityBadge, timeAgo, useNow } from "./shared";
import { ManualFindingDialog } from "./ManualFindingDialog";
import {
  Braces,
  Bug,
  CheckCircle2,
  ChevronDown,
  ClipboardCopy,
  ClipboardPlus,
  Download,
  FileWarning,
  Lock,
  Radio,
  Save,
  ScanSearch,
  Search,
  ShieldCheck,
  Sparkles,
  StickyNote,
  Timer,
  Trash2,
  UserRound,
  Wrench,
} from "lucide-react";

type SortKey = "newest" | "severity" | "attempts";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

const SORT_OPTIONS: { id: SortKey; label: string }[] = [
  { id: "newest", label: "Newest" },
  { id: "severity", label: "Severity" },
  { id: "attempts", label: "Most attempts" },
];

const STATUS_META: Record<FindingStatus, { label: string; cls: string }> = {
  open: { label: "OPEN", cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" },
  investigating: { label: "INVESTIGATING", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" },
  patched: { label: "PATCHED", cls: "border-wg-sky/40 bg-wg-sky/10 text-wg-sky" },
  fixed: { label: "FIXED", cls: "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" },
};

const SOURCE_META: Record<FindingSource, { label: string; cls: string }> = {
  audit: { label: "AUDIT", cls: "border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan" },
  live: { label: "LIVE", cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" },
  canary: { label: "CANARY", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" },
  manual: { label: "MANUAL", cls: "border-border/40 bg-muted/50 text-muted-foreground" },
};

const STATUS_FILTERS: Array<FindingStatus | "all"> = ["all", "open", "investigating", "patched", "fixed"];
const SEVERITY_FILTERS: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low"];

export function FindingsTab({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const { state, dispatch } = useWaf();
  const now = useNow(1000);
  const [status, setStatus] = useState<FindingStatus | "all">("all");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [source, setSource] = useState<FindingSource | "all">("all");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("newest");

  const filtered = useMemo(() => {
    const out = state.findings
      .filter((f) => status === "all" || f.status === status)
      .filter((f) => severity === "all" || f.severity === severity)
      .filter((f) => source === "all" || f.source === source)
      .filter((f) => {
        if (!query.trim()) return true;
        const q = query.toLowerCase();
        return (
          f.title.toLowerCase().includes(q) ||
          (f.path ?? "").toLowerCase().includes(q) ||
          (f.ruleId ?? "").toLowerCase().includes(q) ||
          (f.patch ?? "").toLowerCase().includes(q) ||
          (f.owner ?? "").toLowerCase().includes(q) ||
          (f.notes ?? "").toLowerCase().includes(q) ||
          (f.tags ?? []).some((t) => t.toLowerCase().includes(q))
        );
      });
    if (sortKey === "severity") {
      out.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.lastSeen - a.lastSeen);
    } else if (sortKey === "attempts") {
      out.sort((a, b) => b.count - a.count || b.lastSeen - a.lastSeen);
    } else {
      out.sort((a, b) => b.lastSeen - a.lastSeen);
    }
    return out;
  }, [state.findings, status, severity, source, query, sortKey]);

  const sevDist = useMemo(() => {
    const open = state.findings.filter((f) => f.status === "open" || f.status === "investigating");
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of open) c[f.severity] += 1;
    const total = Math.max(1, open.length);
    return SEVERITY_ORDER.map((s) => ({ s, n: c[s], pct: (c[s] / total) * 100 }));
  }, [state.findings]);

  const copyPatch = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Virtual patch copied to clipboard");
    } catch {
      toast.error("Clipboard unavailable");
    }
  };

  const copyJson = async (finding: VulnFinding) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
      toast.success("Finding copied as JSON");
    } catch {
      toast.error("Clipboard unavailable");
    }
  };

  const openCount = state.findings.filter((f) => f.status === "open" || f.status === "investigating").length;

  const openFindings = useMemo(
    () =>
      state.findings
        .filter((f) => f.status === "open" || f.status === "investigating")
        .sort((a, b) => a.discoveredAt - b.discoveredAt),
    [state.findings],
  );

  const sourceMix = useMemo(() => {
    const total = Math.max(1, state.findings.length);
    const c: Record<FindingSource, number> = { audit: 0, live: 0, canary: 0, manual: 0 };
    for (const f of state.findings) c[f.source] += 1;
    return (Object.keys(c) as FindingSource[]).map((s) => ({ s, n: c[s], pct: (c[s] / total) * 100 }));
  }, [state.findings]);

  const exportRegister = () => {
    const blob = new Blob([JSON.stringify(state.findings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `webguard-vuln-register-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Vulnerability register exported");
  };

  const ageLabel = (ts: number) => {
    const m = Math.floor((now - ts) / 60_000);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 48) return `${h}h`;
    return `${Math.floor(h / 24)}d`;
  };

  const stats = useMemo(() => {
    const c = { open: 0, investigating: 0, patched: 0, fixed: 0, critical: 0, live: 0 };
    for (const f of state.findings) {
      c[f.status] += 1;
      if (f.severity === "critical") c.critical += 1;
      if (f.source === "live") c.live += 1;
    }
    return c;
  }, [state.findings]);

  const setStatusOf = (id: string, next: FindingStatus) => {
    dispatch({ type: "SET_FINDING_STATUS", id, status: next });
  };

  const openTriage = () => {
    const open = state.findings.filter((f) => f.status === "open" || f.status === "investigating");
    const critical = open.filter((f) => f.severity === "critical").length;
    const high = open.filter((f) => f.severity === "high").length;
    dispatch({
      type: "OPEN_COPILOT",
      context: {
        kind: "triage",
        title: `Posture triage — ${open.length} unresolved findings`,
        attackType: null,
        ip: "-",
        country: "-",
        severity: critical > 0 ? "critical" : high > 0 ? "high" : "low",
        payload: "",
        ruleId: null,
        threatScore: 0,
        path: "-",
        triage: {
          open: open.length,
          critical,
          high,
          items: open.slice(0, 8).map((f) => ({
            title: f.title,
            severity: f.severity,
            patch: f.patch,
            path: f.path,
          })),
        },
      },
    });
  };

  return (
    <div className="flex flex-col gap-4">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <KpiTile
          icon={<FileWarning className="size-4" />}
          label="Open issues"
          value={stats.open}
          accent="text-wg-rose"
          sub="awaiting remediation"
        />
        <KpiTile
          icon={<Bug className="size-4" />}
          label="Critical"
          value={stats.critical}
          accent="text-wg-orange"
          sub="severity critical"
        />
        <KpiTile
          icon={<Radio className="size-4" />}
          label="Live detections"
          value={stats.live}
          accent="text-wg-cyan"
          sub="from live telemetry"
          pulse
        />
        <KpiTile
          icon={<ShieldCheck className="size-4" />}
          label="Patched"
          value={stats.patched}
          accent="text-wg-sky"
          sub="virtual patch live"
        />
        <KpiTile
          icon={<CheckCircle2 className="size-4" />}
          label="Fixed"
          value={stats.fixed}
          accent="text-wg-emerald"
          sub="remediated"
        />
      </div>

      {/* aging exposure + source mix */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="wg-panel p-4">
          <SectionTitle
            title="Aging exposure"
            sub="Oldest unresolved findings — the longer they sit, the more they cost"
            right={
              <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
                <Timer className="mr-1 size-3" /> {openFindings.length} unresolved
              </Badge>
            }
          />
          <div className="flex flex-col">
            {openFindings.slice(0, 5).map((f) => {
              const age = now - f.discoveredAt;
              const old = age > 48 * 3_600_000;
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => {
                    setExpanded(f.id);
                    setStatus("all");
                    setSeverity("all");
                    setQuery("");
                  }}
                  className="flex items-center gap-3 border-b border-border/30 py-2 text-left last:border-0 hover:bg-muted/40"
                >
                  <span
                    className={cn(
                      "flex w-11 shrink-0 items-center justify-center rounded-md border py-1 font-mono text-[10px] font-bold",
                      old ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" : "border-border/50 bg-muted/40 text-muted-foreground",
                    )}
                  >
                    {ageLabel(f.discoveredAt)}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-foreground">{f.title}</span>
                    <span className="block truncate text-[10px] text-muted-foreground">
                      {f.path ?? f.ruleId ?? f.source} · {f.count} attempts
                    </span>
                  </span>
                  <SeverityBadge severity={f.severity} />
                </button>
              );
            })}
            {openFindings.length === 0 && (
              <p className="py-8 text-center text-xs text-wg-emerald">Nothing aging — the exposure queue is empty.</p>
            )}
          </div>
        </div>

        <div className="wg-panel p-4">
          <SectionTitle
            title="Detection sources"
            sub="Where the register learns about new issues"
            right={
              <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
                {state.findings.length} tracked
              </Badge>
            }
          />
          <div className="flex flex-col gap-3">
            {sourceMix.map(({ s, n, pct }) => (
              <div key={s} className="flex items-center gap-3">
                <span className="w-20 shrink-0 text-xs text-foreground/80">{SOURCE_META[s].label}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-border/40">
                  <div
                    className={cn("h-full rounded-full transition-all duration-700", s === "live" && "bg-gradient-to-r from-wg-rose/70 to-wg-rose", s === "audit" && "bg-gradient-to-r from-wg-cyan/70 to-wg-cyan", s === "canary" && "bg-gradient-to-r from-wg-amber/70 to-wg-amber", s === "manual" && "bg-muted-foreground/50")}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="w-8 text-right font-mono text-xs text-muted-foreground">{n}</span>
              </div>
            ))}
            <p className="mt-1 border-t border-border/40 pt-2 text-[10px] leading-relaxed text-muted-foreground">
              Live detections arrive automatically as the telemetry simulator inspects traffic; audit scans register the full
              14-finding baseline; canary trips surface as exposure; and manual entries fill any gaps the automation missed. Every
              source feeds one register — no duplicates.
            </p>
          </div>
        </div>
      </div>

      <div className="wg-panel p-4">
        <SectionTitle
          title="Vulnerability register"
          sub="Every issue WebGuard knows about — scans, live threat observations, canary trips, and anything your team adds manually. Flip the firewall to BLOCKING and re-scan to watch audit findings move to PATCHED."            right={
            <div className="flex flex-wrap items-center gap-1.5">
              {openCount > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 gap-1.5 border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald hover:bg-wg-emerald/20 hover:text-wg-emerald"
                  onClick={() => {
                    dispatch({ type: "SET_MODE", mode: "blocking" });
                    toast.success("Edge patches applied — audit findings moved to PATCHED", { description: "Re-scan the target to verify 100/100" });
                  }}
                >
                  <Lock className="size-3.5" /> Apply all patches
                </Button>
              )}
              <ManualFindingDialog />
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20 hover:text-wg-violet"
                onClick={openTriage}
              >
                <Sparkles className="size-3.5" /> Triage with Copilot
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20 hover:text-wg-cyan"
                onClick={() => {
                  const scan = generateAudit(state.target);
                  dispatch({ type: "START_AUDIT", findings: scan.findings, radar: scan.radar, score: scan.score });
                  onNavigate("audit");
                }}
              >
                <ScanSearch className="size-3.5" /> Run audit
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-border/60 text-muted-foreground hover:text-foreground"
                onClick={exportRegister}
                title="Download the full register as JSON"
              >
                <Download className="size-3.5" /> Export
              </Button>
            </div>
          }
        />

        {/* severity distribution bar */}
        <div className="mb-3">
          <div className="mb-1 flex items-center justify-between text-[10px]">
            <span className="font-semibold uppercase tracking-[0.16em] text-muted-foreground/70">Open exposure by severity</span>
            <span className="font-mono text-muted-foreground">{openCount} open</span>
          </div>
          <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-border/40">
            {sevDist.map(({ s, n, pct }) =>
              n > 0 ? (
                <div
                  key={s}
                  title={`${s}: ${n}`}
                  className="h-full transition-all duration-500"
                  style={{ width: `${pct}%`, background: SEVERITY_META[s].color }}
                />
              ) : null,
            )}
          </div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5">
            {sevDist.map(({ s, n }) => (
              <span key={s} className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                <span className="size-1.5 rounded-full" style={{ background: SEVERITY_META[s].color }} />
                {s} · {n}
              </span>
            ))}
          </div>
        </div>

        {/* filters */}
        <div className="mb-3 flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Status</span>
            {STATUS_FILTERS.map((s) => (
              <FilterChip key={s} active={status === s} onClick={() => setStatus(s)}>
                {s === "all" ? "All" : STATUS_META[s].label}
              </FilterChip>
            ))}
            <span className="ml-3 mr-1 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Severity</span>
            {SEVERITY_FILTERS.map((s) => (
              <FilterChip key={s} active={severity === s} onClick={() => setSeverity(s)}>
                {s === "all" ? "All" : s.toUpperCase()}
              </FilterChip>
            ))}
            <span className="ml-3 mr-1 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Source</span>
            {(["all", "audit", "live", "canary", "manual"] as Array<FindingSource | "all">).map((s) => (
              <FilterChip key={s} active={source === s} onClick={() => setSource(s)}>
                {s === "all" ? "All" : SOURCE_META[s].label}
              </FilterChip>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative max-w-sm flex-1">
              <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search title, path, rule ID, patch…"
                className="h-8 border-border/60 bg-muted/50 pl-8 text-xs focus-visible:ring-cyan-400/40"
              />
            </div>
            <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Sort</span>
            {SORT_OPTIONS.map((s) => (
              <FilterChip key={s.id} active={sortKey === s.id} onClick={() => setSortKey(s.id)}>
                {s.label}
              </FilterChip>
            ))}
          </div>
        </div>

        {/* findings list */}
        <div className="flex flex-col gap-2">
          {filtered.map((f) => {
            const meta = SEVERITY_META[f.severity];
            const open = expanded === f.id;
            return (
              <div
                key={f.id}
                className={cn(
                  "overflow-hidden rounded-xl border transition-colors",
                  f.status === "open"
                    ? "border-border/70 bg-card/60"
                    : "border-border/30 bg-card/30",
                )}
              >
                <button
                  type="button"
                  onClick={() => setExpanded(open ? null : f.id)}
                  className="flex w-full flex-wrap items-start gap-3 p-3.5 text-left"
                >
                  <span
                    className="flex size-9 shrink-0 items-center justify-center rounded-lg"
                    style={{ background: `${meta.color}14` }}
                  >
                    {f.source === "live" ? (
                      <Radio className="size-4" style={{ color: meta.color }} />
                    ) : f.source === "canary" ? (
                      <Bug className="size-4" style={{ color: meta.color }} />
                    ) : (
                      <FileWarning className="size-4" style={{ color: meta.color }} />
                    )}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="text-sm font-medium text-foreground">{f.title}</p>
                      <SeverityBadge severity={f.severity} />
                      <span className={cn("rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", STATUS_META[f.status].cls)}>
                        {STATUS_META[f.status].label}
                      </span>
                      <span className={cn("rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", SOURCE_META[f.source].cls)}>
                        {f.source === "live" && <span className="mr-1 inline-block size-1 animate-pulse rounded-full bg-rose-400 align-middle" />}
                        {SOURCE_META[f.source].label}
                      </span>
                      {f.count > 1 && (
                        <Badge variant="outline" className="border-border/50 font-mono text-[10px] text-muted-foreground">
                          ×{f.count} attempts
                        </Badge>
                      )}
                      {(f.tags ?? []).length > 0 && (
                        <span className="flex flex-wrap items-center gap-1">
                          {f.tags!.slice(0, 4).map((t) => (
                            <span
                              key={t}
                              className="rounded-md border border-border/40 bg-muted/40 px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground"
                            >
                              #{t}
                            </span>
                          ))}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
                      {f.path && <span className="font-mono">{f.path}</span>}
                      {f.ruleId && <span>rule <span className="font-mono">{f.ruleId}</span></span>}
                      {f.owner && (
                        <span className="flex items-center gap-1">
                          <UserRound className="size-3" /> {f.owner}
                        </span>
                      )}
                      <span>first seen {timeAgo(f.discoveredAt)}</span>
                      {f.lastSeen !== f.discoveredAt && <span>· last {timeAgo(f.lastSeen)}</span>}
                    </p>
                  </div>
                  <ChevronDown className={cn("mt-1 size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
                </button>

                {open && (
                  <div className="grid grid-cols-1 gap-3 border-t border-border/40 p-3.5 lg:grid-cols-2">
                    <div>
                      <p className="wg-kicker mb-1.5">Raw evidence</p>
                      <pre className="wg-mono overflow-x-auto rounded-lg border border-wg-rose/20 bg-[#0b0f0d] p-3 text-[11px] leading-relaxed text-wg-rose/90">
                        {f.evidence}
                      </pre>
                    </div>
                    <div>
                      <div className="mb-1.5 flex items-center justify-between">
                        <p className="wg-kicker">WebGuard patch</p>
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            title="Copy finding as JSON"
                            className="text-wg-cyan"
                            onClick={() => copyJson(f)}
                          >
                            <Braces className="size-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            title="Copy patch"
                            className="text-wg-emerald"
                            onClick={() => copyPatch(f.patch)}
                          >
                            <ClipboardCopy className="size-3.5" />
                          </Button>
                        </div>
                      </div>
                      <pre className="wg-mono overflow-x-auto rounded-lg border border-wg-emerald/25 bg-[#0b0f0d] p-3 text-[11px] leading-relaxed text-wg-emerald/90">
                        {f.patch}
                      </pre>
                      <div className="mt-3 flex flex-wrap items-center gap-1.5">
                        {f.status === "open" && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 gap-1.5 border-wg-amber/30 text-wg-amber hover:bg-wg-amber/10"
                            onClick={() => setStatusOf(f.id, "investigating")}
                          >
                            <Sparkles className="size-3.5" /> Investigate
                          </Button>
                        )}
                        {f.status !== "patched" && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 gap-1.5 border-wg-sky/30 text-wg-sky hover:bg-wg-sky/10"
                            onClick={() => setStatusOf(f.id, "patched")}
                          >
                            <Wrench className="size-3.5" /> Mark patched
                          </Button>
                        )}
                        {f.status !== "fixed" && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 gap-1.5 border-wg-emerald/30 text-wg-emerald hover:bg-wg-emerald/10"
                            onClick={() => setStatusOf(f.id, "fixed")}
                          >
                            <CheckCircle2 className="size-3.5" /> Mark fixed
                          </Button>
                        )}
                        {(f.status === "patched" || f.status === "fixed") && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-[11px] text-muted-foreground"
                            onClick={() => setStatusOf(f.id, "open")}
                          >
                            Reopen
                          </Button>
                        )}
                        {f.source === "manual" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 gap-1 text-[11px] text-wg-rose hover:bg-wg-rose/10"
                            onClick={() => {
                              dispatch({ type: "REMOVE_FINDING", id: f.id });
                              toast.success("Manual finding removed from the register");
                            }}
                            title="Remove this manually-added finding"
                          >
                            <Trash2 className="size-3.5" /> Remove
                          </Button>
                        )}
                      </div>
                    </div>
                    <div className="col-span-full border-t border-border/30 pt-3">
                      <FindingTriageEditor finding={f} />
                    </div>
                  </div>
                )}
              </div>
            );
          })}

          {filtered.length === 0 && (
            <div className="flex flex-col items-center gap-2 py-14 text-center">
              <ShieldCheck className="size-8 text-emerald-400/60" />
              <p className="text-sm font-medium text-foreground/80">No findings match</p>
              <p className="text-xs text-muted-foreground">
                {state.findings.length === 0
                  ? "The register is empty. Run an audit or let live telemetry detect the first threat."
                  : "Adjust the filters or search term."}
              </p>
            </div>
          )}
        </div>

        <p className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 animate-pulse rounded-full bg-rose-400" /> LIVE detections are appended automatically as the simulator inspects traffic
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-wg-cyan" /> Audit scans push all 14 baseline findings into this register
          </span>
          <span className="flex items-center gap-1.5">
            {flagEmoji("DE")} Auto-banned subnets feed the Access Control page
          </span>
          <span className="flex items-center gap-1.5">
            <ClipboardPlus className="size-3" /> Anything missed? Add it manually with “Add finding”
          </span>
        </p>
      </div>
    </div>
  );
}

function KpiTile({
  icon,
  label,
  value,
  sub,
  accent,
  pulse,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  sub: string;
  accent: string;
  pulse?: boolean;
}) {
  return (
    <div className="wg-panel flex items-start justify-between gap-3 p-4">
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <div className="mt-1.5 flex items-center gap-2 text-2xl font-semibold tracking-tight text-foreground">
          {value}
          {pulse && value > 0 && <span className="relative flex size-2">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
            <span className="relative inline-flex size-2 rounded-full bg-rose-400" />
          </span>}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
      </div>
      <div className={cn("shrink-0 rounded-lg border border-border/60 bg-background/60 p-2", accent)}>{icon}</div>
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition-colors",
        active
          ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
          : "border-border/50 text-muted-foreground hover:text-foreground/80",
      )}
    >
      {children}
    </button>
  );
}

function FindingTriageEditor({ finding }: { finding: VulnFinding }) {
  const { dispatch } = useWaf();
  const [owner, setOwner] = useState(finding.owner ?? "");
  const [tags, setTags] = useState((finding.tags ?? []).join(", "));
  const [notes, setNotes] = useState(finding.notes ?? "");
  const [dirty, setDirty] = useState(false);

  const save = () => {
    const tagList = tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .slice(0, 12);
    dispatch({
      type: "UPDATE_FINDING",
      id: finding.id,
      patch: {
        owner: owner.trim() || undefined,
        tags: tagList,
        notes: notes.trim() || undefined,
      },
    });
    toast.success("Finding details saved", { description: finding.title });
    setDirty(false);
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <p className="wg-kicker flex items-center gap-1.5">
          <StickyNote className="size-3" /> Triage details
        </p>
        {dirty && (
          <Button
            size="sm"
            className="h-6 gap-1 border-wg-cyan/40 bg-wg-cyan/10 text-[10px] text-wg-cyan hover:bg-wg-cyan/20"
            onClick={save}
          >
            <Save className="size-3" /> Save
          </Button>
        )}
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <div className="relative">
          <UserRound className="absolute left-2.5 top-1/2 size-3 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={owner}
            onChange={(e) => {
              setOwner(e.target.value);
              setDirty(true);
            }}
            placeholder="Owner / assignee"
            className="h-8 border-border/50 bg-muted/40 pl-7 text-[11px] focus-visible:ring-cyan-400/40"
          />
        </div>
        <Input
          value={tags}
          onChange={(e) => {
            setTags(e.target.value);
            setDirty(true);
          }}
          placeholder="Tags, comma-separated (e.g. api, owasp-a01)"
          className="h-8 border-border/50 bg-muted/40 font-mono text-[11px] focus-visible:ring-cyan-400/40"
        />
      </div>
      <Textarea
        value={notes}
        onChange={(e) => {
          setNotes(e.target.value);
          setDirty(true);
        }}
        placeholder="Triage notes — repro steps, blast radius, next actions…"
        className="h-16 w-full border-border/50 bg-muted/40 text-[11px] focus-visible:ring-cyan-400/40"
      />
    </div>
  );
}
