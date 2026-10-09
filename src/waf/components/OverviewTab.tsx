import { useMemo, useState } from "react";
import { Area, Bar, CartesianGrid, ComposedChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useWaf } from "../engine";
import { generateAudit } from "../data";
import { ATTACK_LABELS } from "../types";
import type { AttackType, SeriesPoint } from "../types";
import { flagEmoji, fmtCompact, Kpi, SectionTitle, SeverityBadge, timeAgo, useNow } from "./shared";
import { ThreatMap } from "./ThreatMap";
import { Activity, Ban, BellRing, Clock, Crosshair, FileWarning, FlaskConical, Gauge, History, Pause, Play, ScanSearch, ShieldCheck, ShieldOff, ShieldAlert, Siren, Square, Swords, Zap } from "lucide-react";
import { drillScenarioById, scenarioTotalSec, stageIndexAt } from "../drills";
import { SCENARIO_ICONS } from "./DrillsTab";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { CheckCircle2 } from "lucide-react";
import { SEVERITY_META } from "../types";
import { TargetHistoryDialog } from "./TargetHistoryDialog";

const SERIES_KEYS: { key: keyof SeriesPoint; label: string; color: string }[] = [
  { key: "rps", label: "Traffic", color: "#22d3ee" },
  { key: "attacks", label: "Threats", color: "#fb7185" },
  { key: "blocked", label: "Blocked", color: "#34d399" },
];

/** Compact live-drill strip for the Overview — only rendered while a drill is running. */
function OverviewDrillStatus({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const { state, dispatch } = useWaf();
  const now = useNow(500);
  const drill = state.drill!;
  const scenario = drillScenarioById(drill.scenarioId) ?? null;
  if (!scenario) return null;
  const totalSec = scenarioTotalSec(scenario);
  const elapsedSec = Math.min((now - drill.startedAt) / 1000, totalSec);
  const pct = Math.min(100, (elapsedSec / totalSec) * 100);
  const stageIdx = stageIndexAt(scenario, elapsedSec);
  const stage = scenario.stages[stageIdx];
  const Icon = SCENARIO_ICONS[scenario.id] ?? Swords;
  const blockedRate = drill.stats.requests ? Math.round((drill.stats.blocked / drill.stats.requests) * 100) : 0;

  return (
    <div className="wg-panel flex flex-wrap items-center gap-x-4 gap-y-2 p-3">
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-wg-violet/10 text-wg-violet">
        <Icon className="size-4" />
      </span>
      <div className="min-w-0 flex-1 basis-48">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="flex items-center gap-1.5 text-[10px] font-bold tracking-wider text-wg-violet">
            <span className="relative flex size-1.5">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-violet-400 opacity-75" />
              <span className="relative inline-flex size-1.5 rounded-full bg-violet-400" />
            </span>
            LIVE DRILL
          </span>
          <span className="truncate text-xs font-semibold text-foreground">{scenario.name}</span>
          <span className="font-mono text-[10px] text-muted-foreground">
            stage {stageIdx + 1}/{scenario.stages.length} · {stage.label}
          </span>
        </div>
        <div className="mt-1.5 flex items-center gap-2">
          <div className="h-1 flex-1 overflow-hidden rounded-full bg-border/40">
            <div
              className="h-full rounded-full bg-gradient-to-r from-wg-violet to-wg-emerald transition-all"
              style={{ width: `${pct}%` }}
            />
          </div>
          <span className="shrink-0 font-mono text-[9px] text-muted-foreground">{Math.round(pct)}%</span>
        </div>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] text-muted-foreground">
        <span className="text-wg-cyan">{drill.stats.requests.toLocaleString()} req</span>
        <span className="text-wg-rose">{blockedRate}% blocked</span>
        <span className="text-wg-orange">{drill.stats.attacks} attacks</span>
        <span className="text-wg-amber">{drill.stats.incidents} incidents</span>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-1.5">
        <Button
          size="sm"
          className="h-8 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20"
          onClick={() => onNavigate("drills")}
        >
          <Swords className="size-3.5" /> Console
        </Button>
        <Button
          variant="outline"
          size="sm"
          className={cn("h-8 gap-1.5", drill.paused ? "border-wg-emerald/40 text-wg-emerald hover:bg-wg-emerald/10" : "border-wg-amber/40 text-wg-amber hover:bg-wg-amber/10")}
          onClick={() => dispatch({ type: "TOGGLE_DRILL_PAUSE" })}
        >
          {drill.paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
          {drill.paused ? "Resume" : "Pause"}
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1.5 border-wg-rose/40 text-wg-rose hover:bg-wg-rose/10"
          onClick={() => dispatch({ type: "STOP_DRILL_AND_ARCHIVE" })}
        >
          <Square className="size-3.5" /> Abort
        </Button>
      </div>
    </div>
  );
}

export function OverviewTab({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const { state, dispatch, currentRps, activeThreats, avgLatency } = useWaf();
  const now = useNow(1000);
  const { findings } = state;
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [historyOpen, setHistoryOpen] = useState(false);

  const window30 = useMemo(
    () => state.logs.filter((l) => now - l.ts <= 30_000),
    [state.logs, now],
  );
  const threats30 = window30.filter((l) => l.attackType).length;
  const blocked30 = window30.filter((l) => l.blocked).length;

  // Rate-limit budget reference (rpm → per-second) with enough headroom to show it.
  const budgetRps = Math.round((state.settings.rateLimitRpm / 60) * 10) / 10;
  const yMax = Math.max(6, Math.ceil(budgetRps));

  const attackMix = useMemo(() => {
    const counts = new Map<AttackType, number>();
    for (const l of state.logs) if (l.attackType) counts.set(l.attackType, (counts.get(l.attackType) ?? 0) + 1);
    const total = [...counts.values()].reduce((a, b) => a + b, 0) || 1;
    return [...counts.entries()]
      .map(([type, n]) => ({ type, n, pct: (n / total) * 100, severity: SEVERITY_META_BY_ATTACK[type] }))
      .sort((a, b) => b.n - a.n);
  }, [state.logs]);

  const blockRate = state.totalRequests > 0 ? (state.totalBlocked / state.totalRequests) * 100 : 0;

  const topAttackers = useMemo(() => {
    const byIp = new Map<string, { count: number; blocked: number; log: (typeof state.logs)[number] }>();
    for (const l of state.logs) {
      if (!l.attackType) continue;
      const cur = byIp.get(l.ip) ?? { count: 0, blocked: 0, log: l };
      cur.count += 1;
      if (l.blocked) cur.blocked += 1;
      cur.log = l;
      byIp.set(l.ip, cur);
    }
    return [...byIp.values()].sort((a, b) => b.count - a.count).slice(0, 5);
  }, [state]);

  const openFindings = findings
    .filter((f) => f.status === "open" || f.status === "investigating")
    .slice(0, 3);

  return (
    <div className="flex flex-col gap-4">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <Kpi
          label="Requests (24h)"
          value={fmtCompact(state.totalRequests)}
          sub={`${currentRps} req/s right now`}
          icon={<Activity className="size-4" />}
        />
        <Kpi
          label="Blocked by WAF"
          value={fmtCompact(state.totalBlocked)}
          sub={`${blockRate.toFixed(2)}% of all traffic`}
          icon={<Ban className="size-4" />}
          accent="text-wg-rose"
        />
        <Kpi
          label="Active threats"
          value={
            <span className="flex items-center gap-2">
              {activeThreats}
              {activeThreats > 0 && <span className="relative flex size-2">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
                <span className="relative inline-flex size-2 rounded-full bg-rose-400" />
              </span>}
            </span>
          }
          sub="in last 30s window"
          icon={<Siren className="size-4" />}
          accent="text-wg-rose"
        />
        <Kpi
          label="Ingress latency"
          value={`${avgLatency.toFixed(2)} ms`}
          sub={avgLatency < 2.5 ? "under 2.5 ms SLA" : "above SLA threshold"}
          icon={<Gauge className="size-4" />}
          accent={avgLatency < 2.5 ? "text-wg-emerald" : "text-wg-amber"}
        />
        <Kpi
          label="Posture score"
          value={
            <span className="flex items-baseline gap-1">
              {state.audit.status === "done" ? state.audit.score : "—"}
              {state.audit.status === "done" && (
                <span className={cn("text-sm font-bold", state.audit.score >= 90 ? "text-wg-emerald" : "text-wg-rose")}>
                  {state.audit.score >= 90 ? "A+" : "F"}
                </span>
              )}
            </span>
          }
          sub={state.audit.status === "done" ? (state.audit.verified ? "verified with WAF active" : "baseline scan") : "run an audit to score"}
          icon={<Crosshair className="size-4" />}
          accent={state.audit.status === "done" && state.audit.verified ? "text-wg-emerald" : "text-muted-foreground"}
        />
      </div>

      {/* quick actions */}
      <div className="wg-panel flex flex-wrap items-center gap-2 p-3">
        <span className="mr-1 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
          <Zap className="size-3.5 text-wg-cyan" /> Quick actions
        </span>
        <ActionChip icon={<ScanSearch className="size-3.5" />} label="Run vulnerability audit" onClick={() => {
          const scan = generateAudit(state.target);
          dispatch({ type: "START_AUDIT", findings: scan.findings, radar: scan.radar, score: scan.score });
          onNavigate("audit");
        }} />
        <ActionChip icon={<FileWarning className="size-3.5" />} label={`Findings (${state.findings.filter((f) => f.status === "open").length} open)`} onClick={() => onNavigate("findings")} />
        <ActionChip icon={<BellRing className="size-3.5" />} label={`Alerts (${state.alarms.filter((a) => a.state === "active").length})`} onClick={() => onNavigate("alerts")} />
        <ActionChip icon={<Siren className="size-3.5" />} label={`Incidents (${state.incidents.filter((i) => i.stage === "investigating").length})`} onClick={() => onNavigate("incidents")} />
        <ActionChip icon={<Ban className="size-3.5" />} label={`Blocklist (${state.blocklist.filter((b) => b.active).length})`} onClick={() => onNavigate("access")} />
        <ActionChip icon={<Swords className="size-3.5" />} label="Vulnerability Lab" onClick={() => onNavigate("sandbox")} />
        <ActionChip icon={<History className="size-3.5 text-cyan-600 dark:text-cyan-400" />} label="Target History" onClick={() => setHistoryOpen(true)} />
      </div>

      {/* live drill status — shown only while a campaign is actually running */}
      {state.drill && !state.drill.done && <OverviewDrillStatus onNavigate={onNavigate} />}

      {/* vulnerability lab summary */}
      {state.findings.some((f) => f.source === "live") && (
        <div className="wg-panel p-4">
          <SectionTitle
            title={
              <span className="flex items-center gap-2">
                <FlaskConical className="size-4 text-wg-cyan" />
                Vulnerability Lab Activity
              </span>
            }
            sub="Attack simulations from the interactive vulnerability lab"
            right={
              <Button variant="ghost" size="sm" className="h-7 text-xs text-wg-cyan" onClick={() => onNavigate("sandbox")}>
                Open Lab →
              </Button>
            }
          />
          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-lg border border-border/40 bg-muted/20 px-3 py-2.5">
              <p className="font-mono text-lg font-bold text-wg-cyan">{state.findings.filter((f) => f.source === "live").length}</p>
              <p className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground/70">Lab Findings</p>
            </div>
            <div className="rounded-lg border border-border/40 bg-muted/20 px-3 py-2.5">
              <p className="font-mono text-lg font-bold text-wg-rose">{state.findings.filter((f) => f.source === "live" && f.status === "open").length}</p>
              <p className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground/70">Open Vulnerabilities</p>
            </div>
            <div className="rounded-lg border border-border/40 bg-muted/20 px-3 py-2.5">
              <p className="font-mono text-lg font-bold text-wg-emerald">{state.findings.filter((f) => f.source === "live" && f.status === "patched").length}</p>
              <p className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground/70">WAF-Blocked</p>
            </div>
            <div className="rounded-lg border border-border/40 bg-muted/20 px-3 py-2.5">
              <p className={cn("font-mono text-lg font-bold", state.mode === "blocking" ? "text-wg-emerald" : "text-wg-rose")}>{state.mode === "blocking" ? "ACTIVE" : "OFF"}</p>
              <p className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground/70">WAF Status</p>
            </div>
          </div>
        </div>
      )}

      {/* live drill status — shown only while a campaign is actually running */}
      {state.drill && !state.drill.done && <OverviewDrillStatus onNavigate={onNavigate} />}

      {/* traffic chart + map */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <div className="wg-panel p-4 xl:col-span-3">
          <SectionTitle
            title={
              <span className="flex items-center gap-2">
                Traffic throughput
                <span className="flex items-center gap-1 rounded-md border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 text-[9px] font-bold tracking-wider text-wg-rose">
                  <span className="relative flex size-1.5">
                    <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
                    <span className="relative inline-flex size-1.5 rounded-full bg-rose-400" />
                  </span>
                  LIVE
                </span>
              </span>
            }
            sub="Synchronized real-time view — requests per second, threats detected, blocks enforced"
            right={
              <div className="flex items-center gap-3">
                {SERIES_KEYS.map((s) => (
                  <button
                    key={s.key}
                    type="button"
                    onClick={() =>
                      setHidden((prev) => {
                        const next = new Set(prev);
                        if (next.has(s.key)) next.delete(s.key);
                        else next.add(s.key);
                        return next;
                      })
                    }
                    className="flex items-center gap-1.5 text-[11px] text-muted-foreground transition-colors hover:text-foreground"
                  >
                    <span
                      className="size-2 rounded-full"
                      style={{ background: s.color, opacity: hidden.has(s.key) ? 0.25 : 1 }}
                    />
                    {s.label}
                  </button>
                ))}
              </div>
            }
          />

          {/* live window stats */}
          <div className="mb-3 grid grid-cols-3 gap-2">
            <MiniStat label="Throughput now" value={`${currentRps} req/s`} color="text-wg-cyan" />
            <MiniStat label="Threats · 30s" value={String(threats30)} color={threats30 > 0 ? "text-wg-rose" : "text-muted-foreground"} pulse={threats30 > 0} />
            <MiniStat label="Blocked · 30s" value={String(blocked30)} color={blocked30 > 0 ? "text-wg-emerald" : "text-muted-foreground"} />
          </div>

          <div className="h-[240px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={state.series} margin={{ top: 4, right: 4, left: -14, bottom: 0 }}>
                <defs>
                  {SERIES_KEYS.map((s) => (
                    <linearGradient key={s.key} id={`wg-grad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={s.color} stopOpacity={0.4} />
                      <stop offset="55%" stopColor={s.color} stopOpacity={0.12} />
                      <stop offset="100%" stopColor={s.color} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} interval={11} axisLine={false} tickLine={false} />
                <YAxis domain={[0, yMax]} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip content={<TrafficTooltip series={state.series} mode={state.mode} budget={budgetRps} />} cursor={{ stroke: "rgba(34,211,238,0.25)" }} />

                {/* rate budget ceiling */}
                <ReferenceLine
                  y={budgetRps}
                  stroke="#22d3ee"
                  strokeDasharray="4 4"
                  strokeOpacity={0.45}
                  label={{ value: `rate budget ${budgetRps}/s`, position: "insideTopRight", fill: "#22d3ee", fontSize: 9, fontFamily: "ui-monospace, monospace" }}
                />

                {/* blocked — thin bars at the baseline */}
                {!hidden.has("blocked") && (
                  <Bar
                    dataKey="blocked"
                    name="Blocked"
                    fill="#34d399"
                    fillOpacity={0.55}
                    barSize={7}
                    radius={[2, 2, 0, 0]}
                    isAnimationActive={false}
                  />
                )}

                {/* traffic + threats — smooth areas */}
                {SERIES_KEYS.filter((s) => !hidden.has(s.key) && s.key !== "blocked").map((s) => (
                  <Area
                    key={s.key}
                    type="monotone"
                    dataKey={s.key}
                    name={s.label}
                    stroke={s.color}
                    strokeWidth={2}
                    fill={`url(#wg-grad-${s.key})`}
                    dot={false}
                    activeDot={{ r: 3.5, strokeWidth: 2, stroke: "var(--background)", fill: s.color }}
                    isAnimationActive={false}
                  />
                ))}
              </ComposedChart>
            </ResponsiveContainer>
          </div>

          {/* mode-aware footer */}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border/40 pt-2.5">
            <p className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              {state.mode === "blocking" ? (
                <>
                  <span className="size-1.5 rounded-full bg-emerald-400" />
                  Edge enforcing — blocked requests are dropped with 403, benign traffic rides the sub-3.5 ms fast path
                </>
              ) : state.mode === "detection" ? (
                <>
                  <span className="size-1.5 rounded-full bg-amber-400" />
                  Detection mode — attacks are logged but reach the origin, so the blocked line stays flat
                </>
              ) : (
                <>
                  <span className="size-1.5 rounded-full bg-rose-400" />
                  Firewall OFF — no enforcement. Flip to BLOCKING and watch the blocked line light up
                </>
              )}
            </p>
            {state.mode !== "blocking" && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1.5 border-wg-emerald/40 bg-wg-emerald/10 text-[11px] text-wg-emerald hover:bg-wg-emerald/20 hover:text-wg-emerald"
                onClick={() => dispatch({ type: "SET_MODE", mode: "blocking" })}
              >
                <ShieldCheck className="size-3.5" /> Enforce & patch
              </Button>
            )}
          </div>
        </div>

        <div className="flex flex-col gap-4 xl:col-span-2">
          <div>
            <SectionTitle title="Live attack map" sub="Geo-distributed ingress vs. protected origin" />
            <ThreatMap logs={state.logs} blocklist={state.blocklist} />
          </div>
        </div>
      </div>

      {/* attack mix + top attackers + alarms */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <div className="wg-panel p-4">
          <SectionTitle title="Attack type mix" sub="Share of classified threats in the live window" />
          {attackMix.length === 0 ? (
            <p className="py-8 text-center text-xs text-muted-foreground">No attacks observed yet — keep watching.</p>
          ) : (
            <div className="flex flex-col gap-3">
              {attackMix.map((a) => (
                <div key={a.type} className="flex items-center gap-3">
                  <span className="w-36 shrink-0 truncate text-xs text-foreground/80">{ATTACK_LABELS[a.type]}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${a.pct}%`,
                        background: `linear-gradient(90deg, ${SEVERITY_META[a.severity].color}66, ${SEVERITY_META[a.severity].color})`,
                      }}
                    />
                  </div>
                  <span className="w-10 text-right font-mono text-xs text-muted-foreground">{a.n}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="wg-panel p-4">
          <SectionTitle
            title="Top attackers"
            sub="Most active hostile IPs in the live window"
            right={
              <Button variant="ghost" size="sm" className="h-7 text-xs text-wg-cyan" onClick={() => onNavigate("traffic")}>
                Traffic →
              </Button>
            }
          />
          <div className="flex flex-col">
            {topAttackers.map((t, i) => (
              <div key={t.log.ip} className="flex items-center gap-3 border-b border-border/40 py-2.5 last:border-0">
                <span className="font-mono text-[10px] font-bold text-muted-foreground/60">{i + 1}</span>
                <span className="flex min-w-0 flex-1 items-center gap-2">
                  <span className="text-sm leading-none">{flagEmoji(t.log.countryCode)}</span>
                  <span className="truncate font-mono text-xs text-foreground/90">{t.log.ip}</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="font-mono text-xs font-bold text-wg-rose">{t.count}×</span>
                  <span className="text-[9px] uppercase tracking-wider text-muted-foreground">{t.log.city}</span>
                </span>
                <button
                  type="button"
                  title="Ban this IP"
                  onClick={() =>
                    dispatch({
                      type: "ADD_BLOCKED_IP",
                      entry: {
                        id: `ban-${t.log.ip}`,
                        ip: t.log.ip,
                        reason: `Manual ban — top attacker (${t.count} attempts)`,
                        source: "manual",
                        country: t.log.country,
                        countryCode: t.log.countryCode,
                        addedAt: Date.now(),
                        hits: t.count,
                        active: true,
                        expiresAt: null,
                      },
                    })
                  }
                  className="rounded-md border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 text-[9px] font-bold text-wg-rose transition-colors hover:bg-wg-rose/20"
                >
                  BAN
                </button>
              </div>
            ))}
            {topAttackers.length === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">No hostile traffic in the live window.</p>
            )}
          </div>
        </div>

        <div className="wg-panel p-4">
          <SectionTitle
            title="Recent alarms"
            sub="Highest-severity events in the queue"
            right={
              <Button variant="ghost" size="sm" className="h-7 text-xs text-wg-cyan" onClick={() => onNavigate("alerts")}>
                View all →
              </Button>
            }
          />
          <div className="flex flex-col">
            {state.alarms.slice(0, 5).map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => onNavigate("alerts")}
                className="flex items-center gap-3 border-b border-border/40 py-2.5 text-left last:border-0 hover:bg-muted/40"
              >
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg" style={{ background: `${SEVERITY_META[a.severity].color}14` }}>
                  <BellRing className="size-3.5" style={{ color: SEVERITY_META[a.severity].color }} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-xs font-medium text-foreground">{a.title}</span>
                  <span className="block truncate text-[11px] text-muted-foreground">
                    {a.source} · {timeAgo(a.ts)}
                  </span>
                </span>
                <SeverityBadge severity={a.severity} />
              </button>
            ))}
            {state.alarms.length === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">
                <Clock className="mx-auto mb-2 size-4" /> No alarms — all quiet.
              </p>
            )}
          </div>
        </div>
      </div>

      {/* incidents + findings preview */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="wg-panel p-4">
          <SectionTitle
            title="Recent incidents"
            sub="Open & historical — playbooks keep them contained"
            right={
              <Button variant="ghost" size="sm" className="h-7 text-xs text-wg-cyan" onClick={() => onNavigate("incidents")}>
                Incidents →
              </Button>
            }
          />
          <div className="flex flex-col">
            {state.incidents.slice(0, 4).map((inc) => {
              const meta = SEVERITY_META[inc.severity];
              return (
                <button
                  key={inc.id}
                  type="button"
                  onClick={() => onNavigate("incidents")}
                  className="flex items-center gap-3 border-b border-border/40 py-2.5 text-left last:border-0 hover:bg-muted/40"
                >
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-lg" style={{ background: `${meta.color}14` }}>
                    <Siren className="size-3.5" style={{ color: meta.color }} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-foreground">{inc.title}</span>
                    <span className="block truncate text-[11px] text-muted-foreground">
                      {inc.sourceIp} · {timeAgo(inc.openedAt)}
                    </span>
                  </span>
                  <SeverityBadge severity={inc.severity} />
                </button>
              );
            })}
            {state.incidents.length === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">No incidents — all quiet on the wire.</p>
            )}
          </div>
        </div>

        <div className="wg-panel p-4">
          <SectionTitle
            title="Priority findings"
            sub="Open items from the vulnerability register"
            right={
              <Button variant="ghost" size="sm" className="h-7 text-xs text-wg-cyan" onClick={() => onNavigate("findings")}>
                Register →
              </Button>
            }
          />
          <div className="flex flex-col">
            {openFindings.map((f) => {
              const meta = SEVERITY_META[f.severity];
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => onNavigate("findings")}
                  className="flex items-center gap-3 border-b border-border/40 py-2.5 text-left last:border-0 hover:bg-muted/40"
                >
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-lg" style={{ background: `${meta.color}14` }}>
                    <FileWarning className="size-3.5" style={{ color: meta.color }} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-foreground">{f.title}</span>
                    <span className="block truncate text-[11px] text-muted-foreground">
                      {f.source === "live" ? "live detection" : "audit"}
                      {f.path ? ` · ${f.path}` : ""} · {timeAgo(f.lastSeen)}
                    </span>
                  </span>
                  <SeverityBadge severity={f.severity} />
                </button>
              );
            })}
            {openFindings.length === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">
                <CheckCircle2 className="mx-auto mb-2 size-4 text-wg-emerald" /> Register clean — no open findings.
              </p>
            )}
          </div>
        </div>
      </div>
      <TargetHistoryDialog
        open={historyOpen}
        onOpenChange={setHistoryOpen}
        onSelectTarget={(target) => {
          dispatch({ type: "SET_TARGET", target });
          onNavigate("sandbox");
        }}
      />
    </div>
  );
}

function ActionChip({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex h-8 items-center gap-1.5 rounded-lg border border-border/50 bg-muted/30 px-2.5 text-[11px] font-medium text-foreground/80 transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
    >
      <span className="text-wg-cyan">{icon}</span>
      {label}
    </button>
  );
}

const SEVERITY_META_BY_ATTACK: Record<AttackType, "critical" | "high" | "medium"> = {
  sqli: "critical",
  xss: "high",
  cmdi: "critical",
  "path-traversal": "high",
  "high-entropy": "high",
  bot: "medium",
  scanner: "medium",
};

function TrafficTooltip({
  active,
  payload,
  label,
  series,
  mode,
  budget,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string; payload?: SeriesPoint }>;
  label?: string;
  series: SeriesPoint[];
  mode: "blocking" | "detection" | "off";
  budget: number;
}) {
  if (!active || !payload?.length) return null;
  const point = payload[0]?.payload;
  const idx = point ? series.findIndex((s) => s.t === point.t) : -1;
  const prev = idx > 0 ? series[idx - 1] : null;
  return (
    <div className="min-w-[190px] rounded-lg border border-border/60 bg-popover/95 px-3 py-2 shadow-xl backdrop-blur">
      <div className="mb-1.5 flex items-center justify-between gap-4">
        <p className="font-mono text-[10px] text-muted-foreground">{label}</p>
        <span
          className={cn(
            "rounded border px-1 py-px text-[8px] font-bold tracking-wider",
            mode === "blocking" && "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
            mode === "detection" && "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
            mode === "off" && "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
          )}
        >
          {mode === "blocking" ? "WAF BLOCK" : mode === "detection" ? "WAF DETECT" : "WAF OFF"}
        </span>
      </div>
      {payload.map((p) => {
        const delta = prev ? (p.value ?? 0) - (prev[p.name as keyof SeriesPoint] as number) : 0;
        return (
          <p key={p.name} className="flex items-center gap-2 py-0.5 text-xs">
            <span className="size-2 rounded-full" style={{ background: p.color }} />
            <span className="text-muted-foreground">{p.name}</span>
            <span className="ml-auto pl-3 font-mono font-semibold text-foreground">{p.value}</span>
            {prev && (
              <span className={cn("w-9 text-right font-mono text-[9px]", delta > 0 ? "text-wg-emerald" : delta < 0 ? "text-wg-rose" : "text-muted-foreground/60")}>
                {delta > 0 ? "▲" : delta < 0 ? "▼" : "—"}{Math.abs(delta)}
              </span>
            )}
          </p>
        );
      })}
      <p className="mt-1 flex items-center gap-2 border-t border-border/30 pt-1 text-[10px] text-muted-foreground">
        <span className="text-sm leading-none">{flagEmoji("US")}</span> edge: Ashburn · 1s buckets
      </p>
      <p className="mt-1 flex items-center gap-1.5 border-t border-border/30 pt-1 font-mono text-[9px] text-muted-foreground">
        <span className="size-1 rounded-full bg-cyan-400" /> rate budget {budget}/s — requests above it get 429
      </p>
    </div>
  );
}

function MiniStat({ label, value, color, pulse }: { label: string; value: string; color: string; pulse?: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border/40 bg-muted/30 px-2.5 py-1.5">
      <span className="leading-tight">
        <span className={cn("flex items-center gap-1.5 font-mono text-sm font-bold tabular-nums", color)}>
          {value}
          {pulse && <span className="relative flex size-1.5">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
            <span className="relative inline-flex size-1.5 rounded-full bg-rose-400" />
          </span>}
        </span>
        <span className="block text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground/80">{label}</span>
      </span>
    </div>
  );
}
