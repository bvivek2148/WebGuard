import { useMemo, useState } from "react";
import { Area, AreaChart, ResponsiveContainer } from "recharts";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { fmtClock, useWaf, copilotContextFromLog } from "../engine";
import type { AttackType, HttpMethod, RequestLog, TrafficFilters, TrafficVerdict } from "../types";
import { ATTACK_LABELS, DEFAULT_TRAFFIC_FILTERS } from "../types";
import { AttackChip, flagEmoji, fmtCompact, METHOD_COLORS, SectionTitle, StatusBadge, ThreatPill, useNow } from "./shared";
import { Activity, Ban, Bot, CheckCircle2, Download, FilterX, Pause, Play, Search, ShieldAlert, ShieldCheck, Sparkles, Timer, X } from "lucide-react";
import { ExportMenu } from "./ExportMenu";

const STATUS_FILTERS = [0, 200, 403, 429, 500];

const METHODS: HttpMethod[] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

const VERDICTS: { id: TrafficVerdict; label: string }[] = [
  { id: "all", label: "All" },
  { id: "benign", label: "Benign" },
  { id: "threat", label: "Threats" },
  { id: "blocked", label: "Blocked" },
  { id: "throttled", label: "Throttled" },
];

const VERDICT_ACTIVE: Record<TrafficVerdict, string> = {
  all: "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan",
  benign: "border-wg-emerald/50 bg-wg-emerald/10 text-wg-emerald",
  threat: "border-wg-rose/50 bg-wg-rose/10 text-wg-rose",
  blocked: "border-wg-rose/50 bg-wg-rose/10 text-wg-rose",
  throttled: "border-wg-amber/50 bg-wg-amber/10 text-wg-amber",
};

const VERDICT_DOT: Record<TrafficVerdict, string> = {
  all: "bg-cyan-400",
  benign: "bg-emerald-400",
  threat: "bg-rose-400",
  blocked: "bg-rose-400",
  throttled: "bg-amber-400",
};

export function TrafficTab({
  filters,
  onFiltersChange,
}: {
  filters: TrafficFilters;
  onFiltersChange: (f: TrafficFilters) => void;
}) {
  const { state, dispatch } = useWaf();
  const now = useNow(1000);
  const { query, status: statusFilter, verdict, method, attack } = filters;
  const set = (patch: Partial<TrafficFilters>) => onFiltersChange({ ...filters, ...patch });
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<RequestLog[] | null>(null);
  const [selected, setSelected] = useState<RequestLog | null>(null);

  // Pause really freezes the stream: we snapshot the logs at pause time and
  // keep rendering that snapshot until the operator resumes.
  const source = paused && frozen ? frozen : state.logs;
  const togglePause = () => {
    if (!paused) setFrozen([...state.logs]);
    else setFrozen(null);
    setPaused((p) => !p);
  };

  // Live counts for the verdict segment (computed before filtering)
  const counts = useMemo(() => {
    let benign = 0;
    let threat = 0;
    let blocked = 0;
    let throttled = 0;
    for (const l of source) {
      if (l.attackType) threat += 1;
      else benign += 1;
      if (l.blocked) blocked += 1;
      if (l.throttled) throttled += 1;
    }
    return { benign, threat, blocked, throttled };
  }, [source]);

  const logs = useMemo(() => {
    let out = source;
    if (statusFilter !== 0) out = out.filter((l) => l.status === statusFilter);
    if (verdict !== "all") {
      out = out.filter((l) =>
        verdict === "benign"
          ? !l.attackType
          : verdict === "threat"
            ? !!l.attackType
            : verdict === "blocked"
              ? l.blocked
              : l.throttled,
      );
    }
    if (method !== "all") out = out.filter((l) => l.method === method);
    if (attack !== "all") out = out.filter((l) => l.attackType === attack);
    if (query.trim()) {
      const q = query.trim().toLowerCase();
      out = out.filter(
        (l) =>
          l.path.toLowerCase().includes(q) ||
          l.ip.toLowerCase().includes(q) ||
          l.city.toLowerCase().includes(q) ||
          l.country.toLowerCase().includes(q) ||
          (l.ruleId ?? "").toLowerCase().includes(q) ||
          (l.attackType ? ATTACK_LABELS[l.attackType].toLowerCase().includes(q) : false) ||
          (l.payload ?? "").toLowerCase().includes(q),
      );
    }
    return out.slice(0, 140);
  }, [source, statusFilter, verdict, method, attack, query]);

  const attackCount = logs.filter((l) => l.attackType).length;
  const blockedCount = logs.filter((l) => l.blocked).length;
  const throttledCount = logs.filter((l) => l.throttled).length;

  const hasActiveFilters =
    query.trim() !== "" ||
    statusFilter !== 0 ||
    verdict !== "all" ||
    method !== "all" ||
    attack !== "all";

  const clearFilters = () => onFiltersChange(DEFAULT_TRAFFIC_FILTERS);

  const windowStats = useMemo(() => {
    const recent = source.filter((l) => now - l.ts <= 30_000);
    return {
      rps: Math.round((recent.length / 30) * 10) / 10,
      threats: recent.filter((l) => l.attackType).length,
      blocked: recent.filter((l) => l.blocked).length,
    };
  }, [source, now]);

  const insights = useMemo(() => {
    const paths = new Map<string, number>();
    const ips = new Map<string, number>();
    const statuses = new Map<number, number>();
    for (const l of source) {
      paths.set(l.path, (paths.get(l.path) ?? 0) + 1);
      ips.set(l.ip, (ips.get(l.ip) ?? 0) + 1);
      statuses.set(l.status, (statuses.get(l.status) ?? 0) + 1);
    }
    const top = (m: Map<string, number>, n: number) =>
      [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
    return {
      paths: top(paths, 5),
      ips: top(ips, 5),
      statuses: [...statuses.entries()].sort((a, b) => b[1] - a[1]),
    };
  }, [source]);

  const maxPath = Math.max(1, ...insights.paths.map(([, n]) => n));
  const maxIp = Math.max(1, ...insights.ips.map(([, n]) => n));

  const exportCsv = () => {
    const header = "time,status,method,path,ip,country,latency_ms,threat_score,attack,rule,entropy";
    const rows = logs.map((l) =>
      [
        fmtClock(l.ts),
        l.status,
        l.method,
        `"${l.path}"`,
        l.ip,
        l.countryCode,
        l.latency.toFixed(2),
        l.threatScore,
        l.attackType ?? "",
        l.ruleId ?? "",
        l.entropy.toFixed(2),
      ].join(","),
    );
    const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `webguard-traffic-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="wg-panel p-4">
        <SectionTitle
          title="Live request stream"
          sub={`${logs.length} requests in view · ${attackCount} threats · ${blockedCount} blocked · ${throttledCount} throttled · newest first`}
          right={
            <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto sm:justify-end">
              <div className="relative min-w-0 flex-1 basis-full sm:basis-auto">
                <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="traffic-search-input"
                  value={query}
                  onChange={(e) => set({ query: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Escape") set({ query: "" });
                  }}
                  placeholder="Search path, IP, rule, payload…"
                  aria-label="Search traffic stream"
                  className="h-8 w-full border-border/60 bg-muted/50 pl-8 pr-8 text-xs focus-visible:ring-cyan-400/40 sm:w-56"
                />
                {query && (
                  <button
                    type="button"
                    onClick={() => set({ query: "" })}
                    className="absolute right-2 top-1/2 flex size-4 -translate-y-1/2 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                    aria-label="Clear search"
                  >
                    <X className="size-3" />
                  </button>
                )}
              </div>
              <ExportMenu
                data={{
                  label: "traffic log",
                  filename: `webguard-traffic-${Date.now()}`,
                  csvRows: [["Time", "Status", "Method", "Path", "IP", "Country", "Latency", "Threat Score", "Attack", "Rule"],
                    ...logs.map((l) => [fmtClock(l.ts), String(l.status), l.method, l.path, l.ip, l.countryCode, l.latency.toFixed(2), String(l.threatScore), l.attackType ?? "", l.ruleId ?? ""])],
                  jsonData: logs,
                }}
              />
              <Button
                variant="outline"
                size="sm"
                className={cn("h-8 gap-1.5", paused ? "border-wg-amber/40 text-wg-amber" : "border-border/60")}
                onClick={togglePause}
              >
                {paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
                {paused ? "Resume" : "Pause"}
              </Button>
            </div>
          }
        />

        {/* filter bar */}
        <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-border/40 bg-muted/20 p-2">
          {/* verdict segment */}
          <div className="flex flex-wrap items-center gap-0.5 rounded-lg border border-border/50 bg-muted/40 p-0.5">
            {VERDICTS.map((v) => {
              const on = verdict === v.id;
              const n = v.id === "all" ? source.length : counts[v.id];
              return (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => set({ verdict: v.id })}
                  title={`Show ${v.label.toLowerCase()} traffic`}
                  className={cn(
                    "flex h-7 items-center gap-1.5 rounded-md border px-2 font-mono text-[10px] font-bold tracking-wider transition-colors",
                    on ? VERDICT_ACTIVE[v.id] : "border-transparent text-muted-foreground hover:text-foreground",
                  )}
                >
                  <span className={cn("size-1.5 rounded-full", on ? VERDICT_DOT[v.id] : "bg-muted-foreground/40")} />
                  {v.label.toUpperCase()}
                  <span className="tabular-nums opacity-70">{n}</span>
                </button>
              );
            })}
          </div>

          <span className="hidden h-5 w-px bg-border/60 sm:block" />

          {/* method chips */}
          <div className="flex flex-wrap items-center gap-0.5">
            <button
              type="button"
              onClick={() => set({ method: "all" })}
              className={cn(
                "rounded-md border px-2 py-1 font-mono text-[10px] font-bold tracking-wider transition-colors",
                method === "all"
                  ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                  : "border-border/50 text-muted-foreground hover:text-foreground/80",
              )}
            >
              ALL
            </button>
            {METHODS.map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => set({ method: method === m ? "all" : m })}
                className={cn(
                  "rounded-md border px-2 py-1 font-mono text-[10px] font-bold tracking-wider transition-colors",
                  method === m
                    ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                    : "border-border/50 text-muted-foreground hover:text-foreground/80",
                )}
              >
                {m}
              </button>
            ))}
          </div>

          <span className="hidden h-5 w-px bg-border/60 sm:block" />

          {/* status chips */}
          <div className="flex flex-wrap items-center gap-0.5">
            {STATUS_FILTERS.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => set({ status: statusFilter === s ? 0 : s })}
                className={cn(
                  "rounded-md border px-2 py-1 font-mono text-[10px] font-bold transition-colors",
                  statusFilter === s
                    ? s === 0
                      ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                      : s === 403
                        ? "border-wg-rose/50 bg-wg-rose/10 text-wg-rose"
                        : s === 429
                          ? "border-wg-amber/50 bg-wg-amber/10 text-wg-amber"
                          : "border-wg-emerald/50 bg-wg-emerald/10 text-wg-emerald"
                    : "border-border/50 text-muted-foreground hover:text-foreground/80",
                )}
              >
                {s === 0 ? "ALL" : s === 403 ? "403" : s === 429 ? "429" : String(s)}
              </button>
            ))}
          </div>

          <span className="hidden h-5 w-px bg-border/60 sm:block" />

          {/* attack type */}
          <Select
            value={attack}
            onValueChange={(v) => set({ attack: v as "all" | AttackType })}
          >
            <SelectTrigger
              size="sm"
              aria-label="Filter by attack type"
              className="h-8 w-48 border-border/50 bg-muted/40 text-xs"
            >
              <SelectValue placeholder="Attack type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All attack types</SelectItem>
              {Object.entries(ATTACK_LABELS).map(([id, label]) => (
                <SelectItem key={id} value={id}>
                  {label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* clear all */}
          <button
            type="button"
            onClick={clearFilters}
            disabled={!hasActiveFilters}
            className={cn(
              "ml-auto flex h-7 items-center gap-1.5 rounded-md border px-2 text-[10px] font-bold tracking-wider transition-colors",
              hasActiveFilters
                ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose hover:bg-wg-rose/20"
                : "cursor-default border-border/40 text-muted-foreground/50",
            )}
          >
            <FilterX className="size-3" />
            CLEAR
          </button>
        </div>

        {/* live strip: stats + sparkline */}
        <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border border-border/40 bg-muted/20 px-3 py-2">
          <span className="flex items-center gap-1.5 text-[10px] font-semibold text-wg-emerald">
            <span className={cn("size-1.5 rounded-full", paused ? "bg-amber-400" : "animate-pulse bg-emerald-400")} />
            {paused ? "STREAM PAUSED" : "LIVE · 3 req/s"}
          </span>
          <span className="flex items-center gap-1.5 font-mono text-[11px] text-wg-cyan">
            <Activity className="size-3.5" /> {windowStats.rps} req/s
          </span>
          <span className={cn("flex items-center gap-1.5 font-mono text-[11px]", windowStats.threats > 0 ? "text-wg-rose" : "text-muted-foreground")}>
            <ShieldAlert className="size-3.5" /> {windowStats.threats} threats / 30s
          </span>
          <span className={cn("flex items-center gap-1.5 font-mono text-[11px]", windowStats.blocked > 0 ? "text-wg-emerald" : "text-muted-foreground")}>
            <ShieldCheck className="size-3.5" /> {windowStats.blocked} blocked / 30s
          </span>
          <span className="ml-auto hidden text-[10px] text-muted-foreground sm:block">
            {paused
              ? `Frozen at ${logs.length} of ${state.logs.length} requests — resume to follow the live stream`
              : hasActiveFilters
                ? `${logs.length} of ${state.logs.length} requests match current filters`
                : `Showing latest ${logs.length} of ${state.logs.length} requests`}
          </span>
        </div>

        {/* throughput sparkline */}
        <div className="mb-3 hidden h-16 w-full overflow-hidden rounded-xl border border-border/40 bg-muted/20 lg:block">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={state.series} margin={{ top: 6, right: 0, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="wg-spark" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area type="monotone" dataKey="rps" stroke="#22d3ee" strokeWidth={1.5} fill="url(#wg-spark)" isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="h-[540px] overflow-auto rounded-xl border border-border/40">
          <table className="w-full min-w-[880px] border-collapse text-left">
            <thead className="sticky top-0 z-10 bg-muted/90">
              <tr className="border-b border-border/60 text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-3 py-2 font-semibold">Time</th>
                <th className="px-2 py-2 font-semibold">Status</th>
                <th className="px-2 py-2 font-semibold">Method</th>
                <th className="px-2 py-2 font-semibold">Path</th>
                <th className="px-2 py-2 font-semibold">Client</th>
                <th className="px-2 py-2 text-right font-semibold">Latency</th>
                <th className="px-2 py-2 text-right font-semibold">Threat</th>
                <th className="px-3 py-2 font-semibold">Signature</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr
                  key={l.id}
                  onClick={() => setSelected(l)}
                  className={cn(
                    "cursor-pointer border-b border-border/20 transition-colors hover:bg-wg-cyan/[0.04]",
                    l.blocked && "bg-wg-rose/[0.04]",
                    l.throttled && "bg-wg-amber/[0.04]",
                  )}
                >
                  <td className="px-3 py-1.5 font-mono text-[11px] text-muted-foreground whitespace-nowrap">{fmtClock(l.ts)}</td>
                  <td className="px-2 py-1.5"><StatusBadge status={l.status} /></td>
                  <td className={cn("px-2 py-1.5 font-mono text-[11px] font-bold", METHOD_COLORS[l.method])}>{l.method}</td>
                  <td className="max-w-[280px] truncate px-2 py-1.5 font-mono text-[11px] text-foreground/80">{l.path}</td>
                  <td className="px-2 py-1.5 whitespace-nowrap">
                    <span className="flex items-center gap-1.5 text-[11px] text-foreground/80">
                      <span className="text-sm leading-none">{flagEmoji(l.countryCode)}</span>
                      <span className="font-mono">{l.ip}</span>
                      <span className="hidden text-muted-foreground lg:inline">· {l.city}</span>
                    </span>
                  </td>
                  <td className="px-2 py-1.5 text-right font-mono text-[11px] tabular-nums text-muted-foreground">
                    {l.latency.toFixed(2)} ms
                  </td>
                  <td className="px-2 py-1.5 text-right"><ThreatPill score={l.threatScore} attack={!!l.attackType} /></td>
                  <td className="max-w-[160px] px-3 py-1.5">
                    {l.ruleId === "IP-BLOCKLIST" ? (
                      <span className="inline-flex items-center gap-1 rounded-md border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 text-[10px] font-bold text-wg-rose">
                        <Ban className="size-3" /> BLOCKLIST
                      </span>
                    ) : l.ruleId === "ALLOWLIST" ? (
                      <span className="inline-flex items-center gap-1 rounded-md border border-wg-emerald/40 bg-wg-emerald/10 px-1.5 py-0.5 text-[10px] font-bold text-wg-emerald">
                        <ShieldCheck className="size-3" /> ALLOWLIST
                      </span>
                    ) : (
                      <AttackChip attack={l.attackType} ruleId={l.ruleId} />
                    )}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-12 text-center text-xs text-muted-foreground">
                    No requests match the current filters.
                    {hasActiveFilters && (
                      <button
                        type="button"
                        onClick={clearFilters}
                        className="ml-2 font-semibold text-wg-cyan underline-offset-2 hover:underline"
                      >
                        Clear filters
                      </button>
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* session totals */}
      <div className="wg-panel flex flex-wrap items-center gap-x-6 gap-y-2 p-4 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Activity className="size-3.5 text-wg-cyan" />
          Session requests <span className="font-mono font-semibold text-foreground">{fmtCompact(state.totalRequests)}</span>
        </span>
        <span className="flex items-center gap-1.5">
          <Ban className="size-3.5 text-wg-rose" />
          Blocked at edge <span className="font-mono font-semibold text-wg-rose">{fmtCompact(state.totalBlocked)}</span>
        </span>
        <span className="flex items-center gap-1.5">
          <Bot className="size-3.5 text-wg-orange" />
          Attacks classified <span className="font-mono font-semibold text-wg-orange">{fmtCompact(state.totalAttacks)}</span>
        </span>
        <span className="flex items-center gap-1.5">
          <ShieldCheck className="size-3.5 text-wg-emerald" />
          Block rate <span className="font-mono font-semibold text-wg-emerald">{state.totalRequests ? ((state.totalBlocked / state.totalRequests) * 100).toFixed(2) : "0.00"}%</span>
        </span>
        <span className="ml-auto text-[10px]">
          Stream shows the latest 140 requests · full history is preserved in the session export
        </span>
      </div>

      {/* session insights */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="wg-panel p-4">
          <SectionTitle title="Top paths" sub="Most-hit endpoints in the stream" />
          <div className="flex flex-col gap-2">
            {insights.paths.map(([path, n]) => (
              <div key={path} className="flex items-center gap-2">
                <span className="w-40 shrink-0 truncate font-mono text-[11px] text-foreground/80">{path}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                  <div className="h-full rounded-full bg-gradient-to-r from-wg-cyan to-wg-emerald" style={{ width: `${(n / maxPath) * 100}%` }} />
                </div>
                <span className="w-8 text-right font-mono text-[11px] text-muted-foreground">{n}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="wg-panel p-4">
          <SectionTitle title="Top clients" sub="Busiest source IPs" />
          <div className="flex flex-col gap-2">
            {insights.ips.map(([ip, n]) => (
              <div key={ip} className="flex items-center gap-2">
                <span className="w-32 shrink-0 truncate font-mono text-[11px] text-foreground/80">{ip}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                  <div className="h-full rounded-full bg-wg-violet/70" style={{ width: `${(n / maxIp) * 100}%` }} />
                </div>
                <span className="w-8 text-right font-mono text-[11px] text-muted-foreground">{n}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="wg-panel p-4">
          <SectionTitle title="Status distribution" sub="Verdicts across the live window" />
          <div className="flex flex-col gap-2">
            {insights.statuses.map(([status, n]) => {
              const pct = state.logs.length > 0 ? (n / state.logs.length) * 100 : 0;
              return (
                <div key={status} className="flex items-center gap-2">
                  <StatusBadge status={status} />
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${pct}%`,
                        background: status === 403 ? "#f43f5e" : status === 429 ? "#facc15" : status === 500 ? "#fb923c" : status === 200 ? "#34d399" : "#22d3ee",
                      }}
                    />
                  </div>
                  <span className="w-10 text-right font-mono text-[11px] text-muted-foreground">{pct.toFixed(1)}%</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <RequestDialog
        log={selected}
        onClose={() => setSelected(null)}
        onAnalyze={(log) => {
          dispatch({ type: "OPEN_COPILOT", context: copilotContextFromLog(log) });
          setSelected(null);
        }}
        onBan={(log) => {
          dispatch({
            type: "ADD_BLOCKED_IP",
            entry: {
              id: `ban-${log.ip}`,
              ip: log.ip,
              reason: `Manual ban from traffic stream — ${log.method} ${log.path}`,
              source: "manual",
              country: log.country,
              countryCode: log.countryCode,
              addedAt: Date.now(),
              hits: 0,
              active: true,
              expiresAt: null,
            },
          });
          setSelected(null);
        }}
      />
    </div>
  );
}

function RequestDialog({
  log,
  onClose,
  onAnalyze,
  onBan,
}: {
  log: RequestLog | null;
  onClose: () => void;
  onAnalyze: (log: RequestLog) => void;
  onBan: (log: RequestLog) => void;
}) {
  const open = !!log;
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto border-border/60 bg-card sm:max-w-2xl">
        {log && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 font-mono text-sm">
                <span className={METHOD_COLORS[log.method]}>{log.method}</span>
                <span className="truncate text-foreground">{log.path}</span>
              </DialogTitle>
              <DialogDescription className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                <span className="flex items-center gap-1.5">
                  <span className="text-sm leading-none">{flagEmoji(log.countryCode)}</span>
                  {log.ip} · {log.city}, {log.country}
                </span>
                <span className="font-mono text-muted-foreground">{fmtClock(log.ts)}</span>
                <span className="flex items-center gap-1 text-muted-foreground"><Timer className="size-3" /> {log.latency.toFixed(2)} ms</span>
                <span className="font-mono text-muted-foreground">entropy {log.entropy.toFixed(2)} bits/char</span>
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-4">
              {/* verdict */}
              <div className={cn(
                "flex items-center gap-3 rounded-xl border p-3.5",
                log.blocked
                  ? "border-wg-rose/40 bg-wg-rose/[0.08]"
                  : log.throttled
                    ? "border-wg-amber/40 bg-wg-amber/[0.08]"
                    : log.attackType
                      ? "border-wg-orange/40 bg-wg-orange/[0.06]"
                      : "border-wg-emerald/40 bg-wg-emerald/[0.06]",
              )}>
                {log.blocked ? (
                  <ShieldCheck className="size-6 shrink-0 text-wg-rose" />
                ) : log.throttled ? (
                  <Timer className="size-6 shrink-0 text-wg-amber" />
                ) : log.attackType ? (
                  <Bot className="size-6 shrink-0 text-wg-orange" />
                ) : (
                  <CheckCircle2 className="size-6 shrink-0 text-wg-emerald" />
                )}
                <div>
                  <p className={cn(
                    "text-sm font-semibold",
                    log.blocked ? "text-wg-rose" : log.throttled ? "text-wg-amber" : log.attackType ? "text-wg-orange" : "text-wg-emerald",
                  )}>
                    {log.blocked
                      ? `BLOCKED · ${log.ruleId}`
                      : log.throttled
                        ? "RATE LIMITED — 429 returned"
                        : log.attackType
                          ? `${ATTACK_LABELS[log.attackType]} detected — logged only (${log.ruleId})`
                          : "Benign — passed all inspection stages"}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {log.blocked
                      ? "Virtual patch matched at the edge. The request never reached the origin."
                      : log.throttled
                        ? "The client exceeded the configured request budget and was throttled."
                        : log.attackType
                          ? "Firewall mode is not blocking this class. Switch to BLOCKING to drop these with 403."
                          : "Threat score below the decision boundary — forwarded to the origin untouched."}
                  </p>
                </div>
              </div>

              {/* payload evidence */}
              {log.payload && (
                <div>
                  <p className="wg-kicker mb-1.5">Payload evidence</p>
                  <pre className="overflow-auto rounded-lg border border-border/40 bg-muted/70 p-3 wg-mono text-[11px] text-foreground/80">
                    {log.matched ? <HighlightedPayload payload={log.payload} match={log.matched} /> : log.payload}
                  </pre>
                </div>
              )}

              {/* headers */}
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <p className="wg-kicker mb-1.5">Request headers</p>
                  <div className="overflow-auto rounded-lg border border-border/40 bg-muted/60 p-2.5">
                    {Object.entries(log.headers).map(([k, v]) => (
                      <p key={k} className="wg-mono text-[11px] leading-relaxed text-muted-foreground">
                        <span className="text-wg-cyan/80">{k}:</span> {v}
                      </p>
                    ))}
                    <p className="wg-mono text-[11px] leading-relaxed text-muted-foreground">
                      <span className="text-wg-cyan/80">User-Agent:</span>{" "}
                      <span className="line-clamp-2">{log.ua}</span>
                    </p>
                  </div>
                </div>
                <div>
                  <p className="wg-kicker mb-1.5">AI classification</p>
                  <div className="flex flex-col gap-2 rounded-lg border border-border/40 bg-muted/60 p-2.5">
                    <Row label="Threat score" value={`${log.threatScore}/100`} tone="text-wg-rose" />
                    <Row label="Entropy" value={`${log.entropy.toFixed(2)} bits/char`} />
                    <Row label="Class" value={log.attackType ? ATTACK_LABELS[log.attackType] : "Benign"} tone={log.attackType ? "text-wg-rose" : "text-wg-emerald"} />
                    <Row label="Matched rule" value={log.ruleId ?? "—"} mono />
                    <Row label="Origin" value={`${log.city}, ${log.country}`} />
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  className="gap-2 border-wg-rose/40 bg-wg-rose/10 text-wg-rose hover:bg-wg-rose/20"
                  onClick={() => onBan(log)}
                >
                  <Ban className="size-4" /> Ban {log.ip}
                </Button>
                <Button
                  className="flex-1 gap-2 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20"
                  onClick={() => onAnalyze(log)}
                >
                  <Sparkles className="size-4" /> Analyze with AI Copilot
                </Button>
              </div>
            </div>
          </>
        )}
        <button type="button" onClick={onClose} className="absolute right-4 top-4 rounded-md p-1 text-muted-foreground hover:text-foreground">
          <X className="size-4" />
        </button>
      </DialogContent>
    </Dialog>
  );
}

function Row({ label, value, tone, mono }: { label: string; value: string; tone?: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("truncate text-right font-medium text-foreground/80", tone, mono && "font-mono")}>{value}</span>
    </div>
  );
}

function HighlightedPayload({ payload, match }: { payload: string; match: string }) {
  const idx = payload.indexOf(match);
  if (idx === -1) return <>{payload}</>;
  return (
    <>
      {payload.slice(0, idx)}
      <mark className="rounded bg-wg-rose/30 px-0.5 text-wg-rose">{payload.slice(idx, idx + match.length)}</mark>
      {payload.slice(idx + match.length)}
    </>
  );
}
