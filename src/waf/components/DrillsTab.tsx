import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import { ATTACK_LABELS } from "../types";
import type { AttackType, BlockedIp, WafMode } from "../types";
import {
  DRILL_SCENARIOS,
  buildDrillReport,
  drillReportMarkdown,
  drillScenarioById,
  drillTargetBlockRate,
  drillTargetStopRate,
  drillVerdictPass,
  scenarioTotalSec,
  stageElapsedAt,
  stageIndexAt,
} from "../drills";
import { DrillPlanner } from "./DrillPlanner";
import type { DrillHistoryEntry, DrillReport, DrillScenario, DrillSchedule, DrillState, DrillStats } from "../drills";
import { SectionTitle, useNow } from "./shared";
import { toast } from "sonner";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  Activity,
  AlarmClock,
  Archive,
  BellRing,
  Bomb,
  Bot,
  Boxes,
  Braces,
  CalendarClock,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ClipboardList,
  Crosshair,
  Database,
  Dices,
  Download,
  Droplets,
  FileJson,
  FileSpreadsheet,
  FileText,
  Fingerprint,
  Flag,
  Gauge,
  GitCompareArrows,
  Globe,
  KeyRound,
  ListPlus,
  Lock,
  Pause,
  Play,
  Printer,
  Radar,
  Radio,
  RotateCw,
  Search,
  ShieldBan,
  ShieldCheck,
  ShieldOff,
  Siren,
  SlidersHorizontal,
  Square,
  Swords,
  Target,
  Terminal,
  Timer,
  Trash2,
  TrendingUp,
  Waves,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { ExportMenu } from "./ExportMenu";

export const SCENARIO_ICONS: Record<string, LucideIcon> = {
  "sqli-siege": Database,
  "ddos-storm": Waves,
  "cred-stuffing": KeyRound,
  "xss-evasion": Braces,
  "recon-scout": Radar,
  "api-abuse": Boxes,
  "rce-probe": Terminal,
  "session-forge": Fingerprint,
  "ssrf-pivot": Globe,
  "slow-drip": Droplets,
  "payload-replay": ClipboardList,
};

const DIFFICULTY_CLS: Record<DrillScenario["difficulty"], string> = {
  Basic: "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
  Moderate: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
  Advanced: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
};

const EVENT_TONE: Record<string, { cls: string; icon: LucideIcon }> = {
  info: { cls: "border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan", icon: Crosshair },
  alarm: { cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose", icon: BellRing },
  incident: { cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber", icon: Siren },
  done: { cls: "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald", icon: CheckCircle2 },
};

const MIX_COLORS = ["#f43f5e", "#f59e0b", "#22d3ee", "#8b5cf6", "#34d399", "#fb7185", "#a78bfa", "#2dd4bf"];

function fmtSec(total: number): string {
  const s = Math.max(0, Math.round(total));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function DrillsTab({ onNavigate }: { onNavigate?: (tab: string) => void }) {
  const { state, dispatch } = useWaf();
  const drill = state.drill;
  const now = useNow(500);

  return (
    <div className="flex flex-col gap-4">
      {/* header strip */}
      <div className="wg-panel flex flex-col gap-3 p-4 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <Swords className="size-4 text-wg-violet" />
            Attack Drills & Simulations
          </h2>
          <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">
            Scripted attack scenarios play out through the real WAF pipeline — every request is scored by live
            policy, so traffic, alerts, incidents, blocklist and the attack map react exactly as they would to a
            genuine campaign. Schedule campaigns, loop them, isolate traffic, and export post-exercise reports.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {drill ? (
            <span
              className={cn(
                "flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px] font-bold tracking-wider",
                drill.paused
                  ? "border-wg-amber/40 bg-wg-amber/10 text-wg-amber"
                  : drill.done
                    ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                    : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
              )}
            >
              <span
                className={cn(
                  "size-1.5 rounded-full",
                  drill.done ? "bg-emerald-400" : drill.paused ? "bg-amber-400" : "animate-pulse bg-rose-400",
                )}
              />
              {drill.done ? "COMPLETE" : drill.paused ? "PAUSED" : "LIVE DRILL"}
            </span>
          ) : (
            <span className="flex items-center gap-1.5 rounded-md border border-border/50 bg-muted/40 px-2 py-1 font-mono text-[10px] font-bold tracking-wider text-muted-foreground">
              <span className="size-1.5 rounded-full bg-border" /> IDLE
            </span>
          )}
          {state.drillLoop && (
            <span className="flex items-center gap-1.5 rounded-md border border-wg-violet/40 bg-wg-violet/10 px-2 py-1 font-mono text-[10px] font-bold tracking-wider text-wg-violet">
              <RotateCw className="size-3" /> LOOP ON
            </span>
          )}
          {state.drillQueue.length > 0 && (
            <span className="flex items-center gap-1.5 rounded-md border border-wg-cyan/40 bg-wg-cyan/10 px-2 py-1 font-mono text-[10px] font-bold tracking-wider text-wg-cyan">
              <ListPlus className="size-3" /> {state.drillQueue.length} QUEUED
            </span>
          )}
          {state.schedule.enabled && (
            <span className="flex items-center gap-1.5 rounded-md border border-wg-amber/40 bg-wg-amber/10 px-2 py-1 font-mono text-[10px] font-bold tracking-wider text-wg-amber">
              <CalendarClock className="size-3" /> SCHEDULED
            </span>
          )}
          {!drill && (
            <button
              type="button"
              onClick={() => {
                dispatch({ type: "TOGGLE_DRILL_LOOP" });
                toast.info(state.drillLoop ? "Loop disabled" : "Loop armed — completed drills auto-repeat");
              }}
              className={cn(
                "flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px] font-bold tracking-wider transition-colors",
                state.drillLoop
                  ? "border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20"
                  : "border-border/50 bg-muted/40 text-muted-foreground hover:text-foreground",
              )}
              title="When on, a completed drill automatically re-queues itself and repeats"
            >
              <RotateCw className={cn("size-3", state.drillLoop && "animate-[spin_3s_linear_infinite]")} />
              {state.drillLoop ? "LOOP ON" : "ARM LOOP"}
            </button>
          )}
          {!drill && state.drillQueue.length > 0 && (
            <button
              type="button"
              onClick={() => {
                state.drillQueue.forEach((q) => dispatch({ type: "REMOVE_QUEUED_DRILL", qid: q.qid }));
                toast.info("Queue cleared");
              }}
              className="flex items-center gap-1.5 rounded-md border border-wg-rose/40 bg-wg-rose/10 px-2 py-1 font-mono text-[10px] font-bold tracking-wider text-wg-rose transition-colors hover:bg-wg-rose/20"
              title="Remove everything from the queue"
            >
              <Trash2 className="size-3" /> CLEAR QUEUE
            </button>
          )}
        </div>
      </div>

      {/* blocking-mode hint */}
      {drill && !drill.done && state.mode !== "blocking" && (
        <div className="flex flex-col gap-2 rounded-xl border border-wg-amber/25 bg-wg-amber/[0.06] p-3 sm:flex-row sm:items-center">
          <ShieldOff className="size-4 shrink-0 text-wg-amber" />
          <p className="flex-1 text-xs text-foreground/80">
            Firewall is <span className="font-mono font-bold text-wg-amber">{state.mode.toUpperCase()}</span> — the
            drill is running but attacks reach the origin. Flip to <span className="font-mono font-bold">BLOCKING</span>{" "}
            to watch virtual patches drop them with 403.
          </p>
          <Button
            size="sm"
            className="h-7 shrink-0 gap-1.5 border-wg-emerald/40 bg-wg-emerald/10 text-[11px] text-wg-emerald hover:bg-wg-emerald/20"
            onClick={() => dispatch({ type: "SET_MODE", mode: "blocking" })}
          >
            <ShieldCheck className="size-3.5" /> Enable blocking
          </Button>
        </div>
      )}

      {drill ? (
        <ActiveDrill now={now} onNavigate={onNavigate} />
      ) : (
        <>
          <DrillCampaignRecord />
          <DrillReadiness onNavigate={onNavigate} />
          <ScenarioLibrary />
          <DrillPlanner />
          <SchedulePanel />
          <DrillReportsArchive />
          <DrillHistory />
        </>
      )}
    </div>
  );
}

// ============================================================================
// Campaign record — aggregate across every archived drill + history entry
// ============================================================================

function DrillCampaignRecord() {
  const { state } = useWaf();
  const reports = state.drillReports;
  const history = state.drillHistory;
  const sum = (pick: (r: DrillReport) => number, pickH?: (h: (typeof history)[number]) => number) =>
    reports.reduce((n, r) => n + pick(r), 0) + (pickH ? history.reduce((n, h) => n + pickH(h), 0) : 0);

  const runs = reports.length + history.length;
  const requests = sum((r) => r.stats.requests, (h) => h.stats.requests);
  const blocked = sum((r) => r.stats.blocked, (h) => h.stats.blocked);
  const alarms = sum((r) => r.stats.alarms, (h) => h.stats.alarms);
  const incidents = sum((r) => r.stats.incidents, (h) => h.stats.incidents);
  const bans = sum((r) => r.stats.bans, (h) => h.stats.bans);
  const blockedRate = requests ? Math.round((blocked / requests) * 100) : 0;
  const avgStop = reports.length
    ? Math.round(reports.reduce((n, r) => n + r.attackStopRatePct, 0) / reports.length)
    : 0;

  const trend = useMemo(() => {
    return [...reports]
      .sort((a, b) => new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime())
      .slice(-12)
      .map((r) => ({
        label: `${r.scenario.name.slice(0, 14)}·${new Date(r.startedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`,
        blocked: r.blockedRatePct,
        stop: r.attackStopRatePct,
      }));
  }, [reports]);

  return (
    <div className="flex flex-col gap-3">
      <SectionTitle
        title="Campaign record"
        sub="Lifetime drill volume across this console — every run, request and block is counted"
        right={
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
            <span className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5">{runs} runs</span>
            <span className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 text-wg-cyan">{requests.toLocaleString()} req simulated</span>
            <span className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 text-wg-rose">{blockedRate}% blocked</span>
            {reports.length > 0 && (
              <span className="rounded border border-wg-emerald/30 bg-wg-emerald/[0.06] px-1.5 py-0.5 text-wg-emerald">
                {avgStop}% avg stop rate
              </span>
            )}
          </div>
        }
      />
      <div className="wg-panel grid grid-cols-1 gap-4 p-4 xl:grid-cols-3">
        {/* stop-rate trend across archived reports */}
        <div className="flex flex-col xl:col-span-2">
          <p className="flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <TrendingUp className="size-3 text-wg-emerald" /> Defense trend · archived runs
            </span>
            <span className="font-mono text-[9px] font-normal normal-case tracking-normal">blocked vs attack-stop rate</span>
          </p>
          {trend.length >= 2 ? (
            <div className="mt-2 h-36 text-muted-foreground">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trend} margin={{ left: 4, right: 8, top: 8, bottom: 0 }}>
                  <defs>
                    <linearGradient id="wgDrillBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.45} />
                      <stop offset="100%" stopColor="#f43f5e" stopOpacity={0.03} />
                    </linearGradient>
                    <linearGradient id="wgDrillStop" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#34d399" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="#34d399" stopOpacity={0.03} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.14)" vertical={false} />
                  <XAxis dataKey="label" tick={{ fontSize: 9, fill: "currentColor" }} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={24} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: "currentColor" }} tickLine={false} axisLine={false} width={26} />
                  <Tooltip content={<TrendTooltip />} cursor={{ stroke: "rgba(148,163,184,0.25)" }} />
                  <Area type="monotone" dataKey="blocked" name="Blocked at edge" stroke="#f43f5e" strokeWidth={2} fill="url(#wgDrillBlocked)" dot={{ r: 2, fill: "#f43f5e", strokeWidth: 0 }} activeDot={{ r: 4 }} />
                  <Area type="monotone" dataKey="stop" name="Attack stop rate" stroke="#34d399" strokeWidth={2} fill="url(#wgDrillStop)" dot={{ r: 2, fill: "#34d399", strokeWidth: 0 }} activeDot={{ r: 4 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="mt-2 flex h-36 flex-col items-center justify-center gap-1 rounded-lg border border-dashed border-border/50 text-center">
              <TrendingUp className="size-4 text-muted-foreground/50" />
              <p className="max-w-xs text-[11px] leading-relaxed text-muted-foreground">
                {reports.length === 0
                  ? "No drills archived yet — run a campaign and the stop-rate trend appears here."
                  : "Run one more drill to unlock the defense trend chart."}
              </p>
            </div>
          )}
        </div>

        {/* lifetime tallies */}
        <div className="grid grid-cols-2 gap-2">
          <RecordCell label="Campaigns run" value={runs.toLocaleString()} tone="text-foreground" />
          <RecordCell label="Requests simulated" value={requests.toLocaleString()} tone="text-wg-cyan" />
          <RecordCell label="Blocked at edge" value={`${blocked.toLocaleString()} (${blockedRate}%)`} tone="text-wg-rose" />
          <RecordCell label="Avg attack stop rate" value={`${avgStop}%`} tone="text-wg-emerald" />
          <RecordCell label="Alarms raised" value={alarms.toLocaleString()} tone="text-wg-orange" />
          <RecordCell label="Incidents opened" value={incidents.toLocaleString()} tone="text-wg-amber" />
          <RecordCell label="Canary trips" value={state.canaries.filter((c) => c.trips > 0).length.toLocaleString()} tone="text-wg-violet" />
          <RecordCell label="Edge bans added" value={bans.toLocaleString()} tone="text-wg-cyan" />
        </div>
      </div>
    </div>
  );
}

function RecordCell({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="flex flex-col justify-between rounded-lg border border-border/40 bg-card/40 p-2.5">
      <p className={cn("font-mono text-base font-bold", tone)}>{value}</p>
      <p className="mt-0.5 text-[9px] uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  );
}

function TrendTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border/60 bg-popover/95 px-2.5 py-1.5 text-xs shadow-xl backdrop-blur">
      <p className="font-mono text-[10px] text-muted-foreground">{label}</p>
      <div className="mt-1 flex flex-col gap-0.5">
        {payload.map((p) => (
          <p key={p.name} className="flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ background: p.color }} />
            <span className="text-[10px] text-muted-foreground">{p.name}</span>
            <span className="ml-auto font-mono font-semibold text-foreground">{p.value}%</span>
          </p>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Pre-flight readiness — effective settings that will shape the next drill
// ============================================================================

function DrillReadiness({ onNavigate }: { onNavigate?: (tab: string) => void }) {
  const { state, dispatch } = useWaf();
  const budgetRps = Math.round((state.settings.rateLimitRpm / 60) * 10) / 10;
  const liveRules = state.rules.filter((r) => r.action !== "disable").length;
  const customLive = state.customRules.filter((r) => r.enabled).length;
  const canariesLive = state.canaries.filter((c) => !c.banned).length;
  const bansActive = state.blocklist.filter((b) => b.active).length;

  const rows: Array<{ label: string; value: React.ReactNode; good?: boolean }> = [
    {
      label: "Firewall mode",
      value: state.mode === "blocking" ? "BLOCKING — attacks dropped" : state.mode === "detection" ? "DETECTION — log only" : "OFF — origin exposed",
      good: state.mode === "blocking",
    },
    { label: "Rate budget", value: `${budgetRps}/s (${state.settings.rateLimitRpm} rpm) · 429 above`, good: true },
    { label: "Detection sensitivity", value: `${Math.round(state.settings.sensitivity * 100)}% — entropy & velocity tuning`, good: true },
    {
      label: "Auto-ban",
      value: state.banAutomation.enabled
        ? `armed · ${state.banAutomation.threshold} hits${state.banAutomation.expireHours ? ` · expires ${state.banAutomation.expireHours}h` : ""}`
        : "disabled — IPs are never auto-banned",
      good: state.banAutomation.enabled,
    },
    { label: "Geo-block countries", value: state.geoBlock.length ? state.geoBlock.map((c) => c.toUpperCase()).join(", ") : "none", good: true },
    { label: "Enforcement rules live", value: `${liveRules} built-in + ${customLive} custom · ${bansActive} active bans`, good: true },
    { label: "Canary decoys planted", value: `${canariesLive} live tokens · ${state.canaries.filter((c) => c.trips > 0).length} tripped`, good: true },
  ];

  return (
    <div className="wg-panel flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
            <SlidersHorizontal className="size-4 text-wg-cyan" /> Pre-flight readiness
          </p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">
            The effective defense posture the next drill will run against — flip controls to change the outcome
          </p>
        </div>
        <span
          className={cn(
            "flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px] font-bold tracking-wider",
            state.mode === "blocking"
              ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
              : state.mode === "detection"
                ? "border-wg-amber/40 bg-wg-amber/10 text-wg-amber"
                : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
          )}
        >
          <Gauge className="size-3" />
          {state.mode === "blocking" ? "READY TO BLOCK" : state.mode === "detection" ? "LOG-ONLY POSTURE" : "UNPROTECTED"}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {rows.map((r) => (
          <div key={r.label} className="rounded-lg border border-border/40 bg-card/40 px-3 py-2">
            <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">{r.label}</p>
            <p className={cn("mt-1 text-[11px] leading-snug", r.good ? "text-foreground/85" : "text-wg-amber")}>{r.value}</p>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Quick arm</span>
        <Button
          size="sm"
          className="h-7 gap-1.5 border-wg-emerald/40 bg-wg-emerald/10 text-[11px] text-wg-emerald hover:bg-wg-emerald/20"
          onClick={() => {
            dispatch({ type: "SET_MODE", mode: "blocking" });
            toast.success("Firewall set to BLOCKING — drills will drop attacks with 403");
          }}
        >
          <ShieldCheck className="size-3.5" /> Blocking posture
        </Button>
        <Button
          size="sm"
          className="h-7 gap-1.5 border-wg-amber/40 bg-wg-amber/10 text-[11px] text-wg-amber hover:bg-wg-amber/20"
          onClick={() => {
            dispatch({ type: "SET_MODE", mode: "detection" });
            toast.info("Firewall set to DETECTION — drills will log without dropping");
          }}
        >
          <Radar className="size-3.5" /> Detection posture
        </Button>
        <Button
          size="sm"
          className="h-7 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-[11px] text-wg-violet hover:bg-wg-violet/20"
          onClick={() => {
            dispatch({ type: "TOGGLE_DRILL_LOOP" });
            toast.info(state.drillLoop ? "Loop disabled" : "Loop armed for the next drill");
          }}
        >
          <RotateCw className="size-3.5" /> {state.drillLoop ? "Disarm loop" : "Arm loop"}
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="h-7 gap-1.5 border-border/60 text-[11px] text-muted-foreground hover:text-foreground"
          onClick={() => {
            dispatch({ type: "SET_DRILL_SCHEDULE", patch: { enabled: true, scenarioId: "random", intervalMin: 5 } });
            toast.info("Cadence schedule armed — random scenario every 5 min when idle");
          }}
        >
          <CalendarClock className="size-3.5" /> Arm 5m random
        </Button>
        {onNavigate && (
          <Button
            size="sm"
            variant="outline"
            className="h-7 gap-1.5 border-border/60 text-[11px] text-muted-foreground hover:text-foreground"
            onClick={() => onNavigate("rules")}
          >
            <Lock className="size-3.5" /> Open policy engine
          </Button>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Scenario library (idle state)
// ============================================================================

function ScenarioLibrary() {
  const { state, dispatch } = useWaf();
  const [query, setQuery] = useState("");
  const [diff, setDiff] = useState<"All" | DrillScenario["difficulty"]>("All");
  const drillActive = state.drill !== null;

  const totalStages = DRILL_SCENARIOS.reduce((n, s) => n + s.stages.length, 0);
  const totalSec = DRILL_SCENARIOS.reduce((n, s) => n + scenarioTotalSec(s), 0);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return DRILL_SCENARIOS.filter((s) => {
      if (diff !== "All" && s.difficulty !== diff) return false;
      if (!q) return true;
      const hay = [
        s.name,
        s.tagline,
        s.brief,
        ...s.attackTypes.map((t) => ATTACK_LABELS[t]),
        ...s.stages.map((st) => st.label),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [query, diff]);

  const runRandom = () => {
    const s = DRILL_SCENARIOS[Math.floor(Math.random() * DRILL_SCENARIOS.length)];
    dispatch({ type: "START_DRILL", scenarioId: s.id });
    toast.success(`Attack drill started — ${s.name}`, {
      description: "Watch traffic, alerts and the map react live",
    });
  };

  return (
    <div className="flex flex-col gap-3">
      <SectionTitle
        title="Scenario library"
        sub="Pick a campaign — it plays out over time through the live pipeline"
        right={
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
              {DRILL_SCENARIOS.length} scenarios
            </Badge>
            <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
              {totalStages} stages
            </Badge>
            <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
              {fmtSec(totalSec)} combined
            </Badge>
            <Button
              size="sm"
              className="h-7 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20"
              onClick={runRandom}
            >
              <Dices className="size-3.5" /> Run random
            </Button>
          </div>
        }
      />

      {/* filter row */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[200px] max-w-xs flex-1">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-8 border-border/50 bg-muted/40 pl-8 text-xs"
            placeholder="Filter by name, technique, endpoint…"
            spellCheck={false}
          />
        </div>
        <div className="flex items-center gap-0.5 rounded-lg border border-border/50 bg-muted/40 p-0.5">
          {(["All", "Basic", "Moderate", "Advanced"] as const).map((d) => (
            <button
              key={d}
              type="button"
              onClick={() => setDiff(d)}
              className={cn(
                "rounded-md px-2 py-1 text-[10px] font-semibold transition-colors",
                diff === d ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {d}
            </button>
          ))}
        </div>
        {visible.length !== DRILL_SCENARIOS.length && (
          <span className="font-mono text-[10px] text-muted-foreground">{visible.length} shown</span>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        {visible.map((s) => {
          const Icon = SCENARIO_ICONS[s.id] ?? Swords;
          const totalSec = scenarioTotalSec(s);
          return (
            <div key={s.id} className="wg-panel flex flex-col p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-wg-violet/10 text-wg-violet">
                  <Icon className="size-5" />
                </div>
                <span className={cn("rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", DIFFICULTY_CLS[s.difficulty])}>
                  {s.difficulty.toUpperCase()}
                </span>
              </div>
              <h3 className="mt-3 text-sm font-semibold text-foreground">{s.name}</h3>
              <p className="mt-0.5 text-xs font-medium text-wg-violet/80">{s.tagline}</p>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{s.brief}</p>

              <div className="mt-3 flex flex-wrap items-center gap-1.5">
                {s.attackTypes.map((t) => (
                  <span key={t} className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-wg-cyan">
                    {ATTACK_LABELS[t]}
                  </span>
                ))}
              </div>

              {/* stage preview with threat intensity */}
              <div className="mt-3 flex flex-col gap-1.5">
                {s.stages.map((st, i) => (
                  <div key={st.id} className="flex items-center gap-2">
                    <span className="flex size-4 shrink-0 items-center justify-center rounded-full bg-muted/60 font-mono text-[8px] font-bold text-muted-foreground">
                      {i + 1}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-[10px] text-foreground/75">{st.label}</span>
                    <div
                      className="h-1 w-10 shrink-0 overflow-hidden rounded-full bg-border/40"
                      title={`${Math.round(st.attackShare * 100)}% hostile at ${st.rate} rps`}
                    >
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-wg-orange/70 to-wg-rose"
                        style={{ width: `${st.attackShare * 100}%` }}
                      />
                    </div>
                    <span className="w-7 shrink-0 text-right font-mono text-[9px] text-muted-foreground/70">
                      {fmtSec(st.durationSec)}
                    </span>
                  </div>
                ))}
              </div>

              <div className="mt-3 flex items-center justify-between border-t border-border/40 pt-3 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1 font-mono">
                  <Flag className="size-3 text-wg-cyan" /> {s.stages.length} stages
                </span>
                <span className="flex items-center gap-1 font-mono">
                  <Timer className="size-3 text-wg-cyan" /> {fmtSec(totalSec)} duration
                </span>
              </div>

              <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[9px]">
                <span
                  className="flex items-center gap-1 rounded border border-wg-violet/30 bg-wg-violet/[0.06] px-1.5 py-0.5 font-mono font-semibold text-wg-violet"
                  title={`Rubric target — must stop ≥${drillTargetStopRate(s)}% of hostile requests to PASS`}
                >
                  <Target className="size-2.5" /> stop ≥{drillTargetStopRate(s)}%
                </span>
                <span
                  className="flex items-center gap-1 rounded border border-wg-cyan/30 bg-wg-cyan/[0.06] px-1.5 py-0.5 font-mono font-semibold text-wg-cyan"
                  title={`Edge expectation — block ≥${drillTargetBlockRate(s)}% of all drill traffic`}
                >
                  <ShieldCheck className="size-2.5" /> block ≥{drillTargetBlockRate(s)}%
                </span>
              </div>

              <ScenarioPlayStats scenarioId={s.id} />

              <div className="mt-3 grid grid-cols-[1fr_auto] gap-2">
                <Button
                  className="h-8 w-full gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20"
                  onClick={() => {
                    dispatch({ type: "START_DRILL", scenarioId: s.id });
                    toast.success(`Attack drill started — ${s.name}`, {
                      description: "Watch traffic, alerts and the map react live",
                    });
                  }}
                >
                  <Play className="size-3.5" /> Run drill
                </Button>
                <button
                  type="button"
                  onClick={() => {
                    dispatch({ type: "QUEUE_DRILL", scenarioId: s.id });
                    toast.info(`Queued — ${s.name}`, {
                      description: drillActive
                        ? "Starts automatically when the current drill finishes"
                        : "Starts immediately — the console is idle",
                    });
                  }}
                  className="flex size-8 items-center justify-center rounded-lg border border-border/50 bg-muted/30 text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
                  title="Queue next — auto-starts after the current drill"
                >
                  <ListPlus className="size-4" />
                </button>
              </div>
            </div>
          );
        })}
        {visible.length === 0 && (
          <div className="wg-panel col-span-full flex flex-col items-center gap-2 p-8 text-center">
            <Search className="size-5 text-muted-foreground/60" />
            <p className="text-xs text-muted-foreground">No scenarios match your filter.</p>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-[10px]"
              onClick={() => {
                setQuery("");
                setDiff("All");
              }}
            >
              Clear filters
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Past drills
// ============================================================================

/** CSV summary of every archived drill report. */
function exportReportsCsv(reports: DrillReport[]): void {
  const esc = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;
  const header = [
    "started_at",
    "scenario",
    "difficulty",
    "outcome",
    "mode",
    "requests",
    "attacks",
    "blocked",
    "blocked_pct",
    "stop_rate_pct",
    "alarms",
    "incidents",
    "canary_trips",
    "bans",
    "duration_sec",
  ];
  const rows = reports.map((r) =>
    [
      new Date(r.startedAt).toISOString(),
      r.scenario.name,
      r.scenario.difficulty,
      r.outcome,
      r.mode,
      r.stats.requests,
      r.stats.attacks,
      r.stats.blocked,
      r.blockedRatePct,
      r.attackStopRatePct,
      r.stats.alarms,
      r.stats.incidents,
      r.stats.canaryTrips,
      r.stats.bans,
      Math.round(r.durationSec),
    ]
      .map(esc)
      .join(","),
  );
  downloadFile(
    `webguard-drill-archive-${new Date().toISOString().slice(0, 10)}.csv`,
    [header.join(","), ...rows].join("\n"),
    "text/csv",
  );
}

/** CSV summary of every drill-history entry (console-level runs, incl. aborts). */
function exportHistoryCsv(history: DrillHistoryEntry[]): void {
  const esc = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;
  const header = [
    "started_at",
    "finished_at",
    "scenario",
    "difficulty",
    "outcome",
    "requests",
    "attacks",
    "blocked",
    "blocked_pct",
    "stop_rate_pct",
    "verdict",
    "alarms",
    "incidents",
    "canary_trips",
    "bans",
  ];
  const rows = history.map((h) => {
    const scenario = drillScenarioById(h.scenarioId);
    const blockedRate = h.stats.requests ? Math.round((h.stats.blocked / h.stats.requests) * 100) : 0;
    const stopRate = h.stats.attacks ? Math.round((h.stats.blocked / h.stats.attacks) * 100) : 0;
    const verdict =
      scenario && drillVerdictPass(scenario, stopRate) ? "PASS" : scenario ? "FAIL" : "—";
    return [
      new Date(h.startedAt).toISOString(),
      new Date(h.finishedAt).toISOString(),
      scenario?.name ?? h.scenarioId,
      scenario?.difficulty ?? "—",
      h.outcome,
      h.stats.requests,
      h.stats.attacks,
      h.stats.blocked,
      blockedRate,
      stopRate,
      verdict,
      h.stats.alarms,
      h.stats.incidents,
      h.stats.canaryTrips,
      h.stats.bans,
    ]
      .map(esc)
      .join(",");
  });
  downloadFile(
    `webguard-drill-history-${new Date().toISOString().slice(0, 10)}.csv`,
    [header.join(","), ...rows].join("\n"),
    "text/csv",
  );
}

/** Per-scenario play history shown on library cards — runs, best stop, last played. */
function ScenarioPlayStats({ scenarioId }: { scenarioId: string }) {
  const { state } = useWaf();
  const stats = useMemo(() => {
    const fromReports = state.drillReports.filter((r) => r.scenario.id === scenarioId);
    const fromHistory = state.drillHistory.filter((h) => h.scenarioId === scenarioId);
    const times = fromReports
      .map((r) => new Date(r.startedAt).getTime())
      .concat(fromHistory.map((h) => h.startedAt))
      .sort((a, b) => a - b);
    return {
      total: fromReports.length + fromHistory.length,
      best: fromReports.reduce((best, r) => Math.max(best, r.attackStopRatePct), 0),
      last: times.length > 0 ? times[times.length - 1] : null,
    };
  }, [state.drillReports, state.drillHistory, scenarioId]);
  if (stats.total === 0) return null;
  return (
    <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[9px] text-muted-foreground">
      <span className="flex items-center gap-1 rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono">
        <Play className="size-2.5 text-wg-cyan" /> {stats.total}× played
      </span>
      {stats.best > 0 && (
        <span className="flex items-center gap-1 rounded border border-wg-emerald/30 bg-wg-emerald/[0.06] px-1.5 py-0.5 font-mono text-wg-emerald">
          <TrendingUp className="size-2.5" /> {stats.best}% best stop
        </span>
      )}
      {stats.last && (
        <span className="flex items-center gap-1 rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono">
          <Timer className="size-2.5" /> last {new Date(stats.last).toLocaleDateString([], { month: "short", day: "numeric" })}
        </span>
      )}
    </div>
  );
}

/** Rubric verdict chip — shown on archived reports (has rubric data). */
function VerdictBadge({ rubric }: { rubric: NonNullable<DrillReport["rubric"]> }) {
  return (
    <span
      className={cn(
        "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
        rubric.pass
          ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
          : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
      )}
      title={`Target: ≥${rubric.targetStopRate}% attack stop rate · achieved ${rubric.achievedStopRate}%`}
    >
      {rubric.pass ? <CheckCircle2 className="size-2.5" /> : <X className="size-2.5" />}
      {rubric.pass ? "PASS" : "FAIL"}
    </span>
  );
}

/** Rubric verdict computed on the fly for drill-history entries (no report snapshot). */
function HistoryVerdict({ scenarioId, blocked, attacks }: { scenarioId: string; blocked: number; attacks: number }) {
  const scenario = drillScenarioById(scenarioId);
  if (!scenario) return null;
  const stopRate = attacks ? Math.round((blocked / attacks) * 100) : 0;
  const pass = drillVerdictPass(scenario, stopRate);
  return (
    <span
      className={cn(
        "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
        pass ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
      )}
      title={`Rubric: ≥${drillTargetStopRate(scenario)}% stop rate · achieved ${stopRate}%`}
    >
      {pass ? <CheckCircle2 className="size-2.5" /> : <X className="size-2.5" />}
      {pass ? "PASS" : "FAIL"}
    </span>
  );
}

function DrillHistory() {
  const { state, dispatch } = useWaf();
  if (state.drillHistory.length === 0) return null;
  const runs = state.drillHistory.length;
  const avgBlocked = Math.round(
    (state.drillHistory.reduce((acc, h) => acc + (h.stats.requests ? h.stats.blocked / h.stats.requests : 0), 0) / runs) * 100,
  );
  const totalBans = state.drillHistory.reduce((acc, h) => acc + h.stats.bans, 0);
  return (
    <div className="flex flex-col gap-3">
      <SectionTitle
        title="Drill history"
        sub="Past exercises and their outcomes — kept with the console state"
        right={
          <div className="flex flex-wrap items-center gap-1.5">
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
              <span className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5">{runs} runs</span>
              <span className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 text-wg-rose">{avgBlocked}% avg blocked</span>
              <span className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 text-wg-violet">{totalBans} bans</span>
            </div>
            <ExportMenu
              data={{
                label: "drill history",
                filename: `webguard-drill-history`,
                jsonData: state.drillHistory,
                csvRows: [["Started", "Finished", "Scenario", "Outcome", "Requests", "Attacks", "Blocked", "Alarms", "Incidents"],
                  ...state.drillHistory.map((h) => [String(h.startedAt), String(h.finishedAt), h.scenarioId, h.outcome, String(h.stats.requests), String(h.stats.attacks), String(h.stats.blocked), String(h.stats.alarms), String(h.stats.incidents)])],
              }}
            />
          </div>
        }
      />
      <div className="wg-panel divide-y divide-border/40">
        {state.drillHistory.slice(0, 8).map((h) => {
          const scenario = drillScenarioById(h.scenarioId);
          const blockedRate = h.stats.requests ? Math.round((h.stats.blocked / h.stats.requests) * 100) : 0;
          return (
            <div key={h.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
              <span
                    className={cn(
                      "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                      h.outcome === "completed"
                        ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                        : "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
                    )}
                  >
                    {h.outcome === "completed" ? <CheckCircle2 className="size-2.5" /> : <X className="size-2.5" />}
                    {h.outcome.toUpperCase()}
                  </span>
                  {scenario && (
                    <HistoryVerdict scenarioId={scenario.id} blocked={h.stats.blocked} attacks={h.stats.attacks} />
                  )}
                  <span className="min-w-0 flex-1 truncate text-xs font-medium text-foreground">
                    {scenario?.name ?? h.scenarioId}
                  </span>
              <span className="font-mono text-[10px] text-muted-foreground">
                {new Date(h.startedAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
              </span>
              <span className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-muted-foreground">
                <span className="text-wg-cyan">{h.stats.requests} req</span>
                <span className="text-wg-rose">{blockedRate}% blocked</span>
                <span className="text-wg-orange">{h.stats.alarms} alarms</span>
                <span className="text-wg-amber">{h.stats.incidents} incidents</span>
                <span className="text-wg-violet">{h.stats.bans} bans</span>
              </span>
              <button
                type="button"
                onClick={() => dispatch({ type: "START_DRILL", scenarioId: h.scenarioId })}
                className="flex h-7 shrink-0 items-center gap-1 rounded-md border border-border/50 bg-muted/30 px-2 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-violet/40 hover:text-wg-violet"
              >
                <RotateCw className="size-3" /> Rerun
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ============================================================================
// Cadence schedule — cron-style auto-run on a repeating interval
// ============================================================================

const SCHEDULE_INTERVALS = [5, 10, 15, 30, 60];

function SchedulePanel() {
  const { state, dispatch } = useWaf();
  const s = state.schedule;
  const now = useNow(1000);
  const [scenarioId, setScenarioId] = useState<string>(s.scenarioId);
  const [intervalMin, setIntervalMin] = useState<number>(s.intervalMin);

  const countdownSec =
    s.enabled && s.nextRunAt !== null ? Math.max(0, Math.round((s.nextRunAt - now) / 1000)) : null;
  const countdownLabel =
    countdownSec === null
      ? null
      : `${Math.floor(countdownSec / 60)}:${String(countdownSec % 60).padStart(2, "0")}`;
  const scheduledScenario = s.scenarioId === "random" ? null : drillScenarioById(s.scenarioId);

  const applyPatch = (patch: Partial<DrillSchedule>) =>
    dispatch({ type: "SET_DRILL_SCHEDULE", patch });

  const runNow = () => {
    const id = s.scenarioId === "random" ? DRILL_SCENARIOS[Math.floor(Math.random() * DRILL_SCENARIOS.length)].id : s.scenarioId;
    dispatch({ type: "START_DRILL", scenarioId: id });
    toast.success("Scheduled drill launched now", {
      description: s.scenarioId === "random" ? "A random scenario was picked for this run" : drillScenarioById(id)?.name ?? id,
    });
  };

  return (
    <div className="wg-panel flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
            <CalendarClock className="size-4 text-wg-amber" /> Cadence schedule
          </p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">
            Cron-style auto-run — when the console is idle and the countdown hits zero, the next campaign fires by
            itself and the timer resets
          </p>
        </div>
        {s.enabled && countdownLabel !== null && (
          <span className="flex items-center gap-1.5 rounded-md border border-wg-amber/40 bg-wg-amber/10 px-2 py-1 font-mono text-[11px] font-bold text-wg-amber">
            <Timer className="size-3" /> next run in {countdownLabel}
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-end gap-3">
        {/* interval picker */}
        <div className="flex flex-col gap-1.5">
          <span className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Repeat every</span>
          <div className="flex items-center gap-1 rounded-lg border border-border/50 bg-muted/40 p-0.5">
            {SCHEDULE_INTERVALS.map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => {
                  setIntervalMin(m);
                  if (s.enabled) applyPatch({ intervalMin: m });
                }}
                className={cn(
                  "rounded-md px-2 py-1 font-mono text-[10px] font-semibold transition-colors",
                  intervalMin === m ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                )}
              >
                {m}m
              </button>
            ))}
          </div>
        </div>

        {/* scenario picker */}
        <div className="flex min-w-[180px] flex-col gap-1.5">
          <span className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Scenario</span>
          <select
            value={scenarioId}
            onChange={(e) => {
              setScenarioId(e.target.value);
              if (s.enabled) applyPatch({ scenarioId: e.target.value });
            }}
            className="h-8 rounded-lg border border-border/50 bg-muted/40 px-2 text-xs text-foreground outline-none transition-colors focus:border-wg-amber/50"
          >
            <option value="random">Random scenario</option>
            {DRILL_SCENARIOS.map((sc) => (
              <option key={sc.id} value={sc.id}>
                {sc.name}
              </option>
            ))}
          </select>
        </div>

        {/* actions */}
        <div className="flex flex-wrap items-center gap-2">
          {s.enabled ? (
            <>
              <Button
                size="sm"
                className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20"
                onClick={runNow}
              >
                <Play className="size-3.5" /> Run now
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-border/60 text-muted-foreground hover:text-foreground"
                onClick={() => applyPatch({ enabled: false })}
              >
                <X className="size-3.5" /> Disable schedule
              </Button>
            </>
          ) : (
            <Button
              size="sm"
              className="h-8 gap-1.5 border-wg-amber/40 bg-wg-amber/10 text-wg-amber hover:bg-wg-amber/20"
              onClick={() => applyPatch({ enabled: true, scenarioId, intervalMin })}
            >
              <CalendarClock className="size-3.5" /> Arm schedule
            </Button>
          )}
        </div>
      </div>

      {s.enabled && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-wg-amber/25 bg-wg-amber/[0.05] px-3 py-2 text-[10px] text-foreground/80">
          <span className="flex items-center gap-1.5">
            <CalendarClock className="size-3 text-wg-amber" />
            Next campaign: <span className="font-semibold text-wg-amber">{scheduledScenario?.name ?? "random scenario"}</span>
          </span>
          <span className="flex items-center gap-1.5 font-mono">
            every <span className="font-bold text-wg-amber">{s.intervalMin} min</span> when idle
          </span>
          <span className="ml-auto hidden text-muted-foreground sm:inline">
            {s.nextRunAt !== null ? `countdown from ${new Date(s.nextRunAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "due now"}
          </span>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Report archive + drill comparison
// ============================================================================

function DrillReportsArchive() {
  const { state } = useWaf();
  const reports = state.drillReports;
  const [mode, setMode] = useState<"reports" | "compare">("reports");
  const [openId, setOpenId] = useState<string | null>(null);

  if (reports.length === 0) return null;

  const completed = reports.filter((r) => r.outcome === "completed").length;
  const aborted = reports.length - completed;
  const avgStop = Math.round(
    reports.reduce((acc, r) => acc + (r.stats.attacks ? r.stats.blocked / r.stats.attacks : 0), 0) /
      Math.max(1, reports.filter((r) => r.stats.attacks > 0).length) *
      100,
  );

  return (
    <div className="flex flex-col gap-3">
      <SectionTitle
        title="Report archive"
        sub="Every finished and aborted campaign is snapshotted here — reopen, export or compare"
        right={
          <div className="flex flex-wrap items-center gap-1.5">
            <div className="flex items-center gap-0.5 rounded-lg border border-border/50 bg-muted/40 p-0.5">
              <button
                type="button"
                onClick={() => setMode("reports")}
                className={cn(
                  "flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-semibold transition-colors",
                  mode === "reports" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Archive className="size-3" /> Reports
              </button>
              <button
                type="button"
                onClick={() => setMode("compare")}
                className={cn(
                  "flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-semibold transition-colors",
                  mode === "compare" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <GitCompareArrows className="size-3" /> Compare
              </button>
            </div>
            <span className="rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {reports.length} archived
            </span>
            <span className="hidden rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-wg-emerald sm:inline">
              {completed} completed
            </span>
            {aborted > 0 && (
              <span className="hidden rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-wg-amber sm:inline">
                {aborted} aborted
              </span>
            )}
            <span className="hidden rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-wg-cyan md:inline">
              {avgStop}% avg stop rate
            </span>
            <button
              type="button"
              onClick={() => exportReportsCsv(reports)}
              className="flex h-7 items-center gap-1 rounded-md border border-border/50 bg-muted/40 px-2 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
              title="Download a CSV summary of every archived drill"
            >
              <FileSpreadsheet className="size-3" /> Export all
            </button>
          </div>
        }
      />

      {mode === "compare" ? (
        <DrillCompare reports={reports} />
      ) : (
        <div className="flex flex-col gap-2">
          {reports.map((r) => {
            const scenario = drillScenarioById(r.scenario.id);
            const Icon = SCENARIO_ICONS[r.scenario.id] ?? Swords;
            const open = openId === r.id;
            return (
              <div key={r.id} className="wg-panel overflow-hidden">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-wg-violet/10 text-wg-violet">
                    <Icon className="size-4" />
                  </span>
                  <span
                    className={cn(
                      "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                      r.outcome === "completed"
                        ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                        : r.outcome === "aborted"
                          ? "border-wg-amber/40 bg-wg-amber/10 text-wg-amber"
                          : "border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan",
                    )}
                  >
                    {r.outcome === "completed" ? <CheckCircle2 className="size-2.5" /> : r.outcome === "aborted" ? <X className="size-2.5" /> : <Activity className="size-2.5" />}
                    {r.outcome.toUpperCase()}
                  </span>
                  {r.rubric && <VerdictBadge rubric={r.rubric} />}
                  <span className="min-w-0 flex-1 truncate text-xs font-semibold text-foreground">
                    {r.scenario.name}
                    <span className="ml-2 font-mono text-[9px] font-normal text-muted-foreground">
                      {scenario ? `${scenario.difficulty} · ${fmtSec(r.scenario.totalSec)}` : ""}
                    </span>
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {new Date(r.startedAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </span>
                  <span className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-muted-foreground">
                    <span className="text-wg-cyan">{r.stats.requests} req</span>
                    <span className="text-wg-rose">{r.blockedRatePct}% blocked</span>
                    <span className="text-wg-orange">{r.stats.alarms} alarms</span>
                    <span className="text-wg-violet">{r.stats.bans} bans</span>
                  </span>
                  <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setOpenId(open ? null : r.id)}
                      className="flex h-7 items-center gap-1 rounded-md border border-border/50 bg-muted/30 px-2 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
                    >
                      {open ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />} View
                    </button>
                    <ReportExportButton r={r} />
                    <ReopenReport r={r} />
                  </div>
                </div>
                {open && <ReportViewer report={r} />}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ReopenReport({ r }: { r: DrillReport }) {
  const { dispatch } = useWaf();
  return (
    <button
      type="button"
      onClick={() => dispatch({ type: "START_DRILL", scenarioId: r.scenario.id })}
      className="flex h-7 items-center gap-1 rounded-md border border-border/50 bg-muted/30 px-2 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-violet/40 hover:text-wg-violet"
      title="Replay the same scenario in the console"
    >
      <RotateCw className="size-3" /> Reopen
    </button>
  );
}

function ReportExportButton({ r }: { r: DrillReport }) {
  const btn =
    "flex h-7 items-center gap-1 rounded-md border border-border/50 bg-muted/30 px-2 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan";
  return (
    <>
      <button
        type="button"
        className={btn}
        onClick={() => downloadFile(`webguard-drill-${r.scenario.id}.md`, drillReportMarkdown(r), "text/markdown")}
        title="Download Markdown report"
      >
        <FileText className="size-3" /> MD
      </button>
      <button
        type="button"
        className={btn}
        onClick={() => downloadFile(`webguard-drill-${r.scenario.id}.json`, JSON.stringify(r, null, 2), "application/json")}
        title="Download JSON data"
      >
        <FileJson className="size-3" /> JSON
      </button>
    </>
  );
}

function ReportViewer({ report }: { report: DrillReport }) {
  const [tab, setTab] = useState<"summary" | "stages" | "events" | "bans">("summary");
  const mix = report.stats.attackMix ?? {};
  const mixEntries = Object.entries(mix)
    .map(([type, n]) => ({ type: ATTACK_LABELS[type as AttackType] ?? type, n: n ?? 0 }))
    .sort((a, b) => b.n - a.n);
  const maxMix = Math.max(...mixEntries.map((e) => e.n), 1);

  const tabs: Array<{ id: typeof tab; label: string; count?: number }> = [
    { id: "summary", label: "Summary" },
    { id: "stages", label: "Stages", count: report.stages.length },
    { id: "events", label: "Events", count: report.events.length },
    { id: "bans", label: "Bans", count: report.bans.length },
  ];

  return (
    <div className="border-t border-border/40 bg-card/20 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-0.5 rounded-lg border border-border/50 bg-muted/40 p-0.5">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={cn(
                "flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-semibold transition-colors",
                tab === t.id ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {t.label}
              {t.count !== undefined && (
                <span className={cn("font-mono text-[9px]", t.count === 0 ? "text-muted-foreground/50" : "text-wg-cyan")}>
                  {t.count}
                </span>
              )}
            </button>
          ))}
        </div>
        <span className="font-mono text-[9px] text-muted-foreground">
          {report.mode.toUpperCase()} · {fmtSec(report.durationSec)} elapsed ·{" "}
          {report.finishedAt ? new Date(report.finishedAt).toLocaleTimeString() : "—"}
        </span>
      </div>

      {tab === "summary" && (
        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <ResultCell label="Requests" value={report.stats.requests.toLocaleString()} />
          <ResultCell label="Blocked at edge" value={`${report.stats.blocked.toLocaleString()} (${report.blockedRatePct}%)`} tone="text-wg-rose" />
          <ResultCell label="Attack stop rate" value={`${report.attackStopRatePct}%`} tone="text-wg-emerald" />
          <ResultCell label="Attacks classified" value={report.stats.attacks.toLocaleString()} tone="text-wg-orange" />
          <ResultCell label="Alarms raised" value={report.stats.alarms.toLocaleString()} tone="text-wg-rose" />
          <ResultCell label="Incidents opened" value={report.stats.incidents.toLocaleString()} tone="text-wg-amber" />
          <ResultCell label="Canary trips" value={report.stats.canaryTrips.toLocaleString()} tone="text-wg-violet" />
          <ResultCell label="Edge bans added" value={report.stats.bans.toLocaleString()} tone="text-wg-cyan" />
          {report.rubric && (
            <div className="col-span-2 mt-1 rounded-lg border border-border/50 bg-muted/30 p-2.5 sm:col-span-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">
                  Scoring rubric & verdict
                </p>
                <VerdictBadge rubric={report.rubric} />
              </div>
              <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {[
                  {
                    label: "Attack stop rate",
                    target: `≥${report.rubric.targetStopRate}%`,
                    achieved: `${report.rubric.achievedStopRate}%`,
                    ok: report.rubric.achievedStopRate >= report.rubric.targetStopRate,
                  },
                  {
                    label: "Edge block rate",
                    target: `≥${report.rubric.targetBlockedRate}%`,
                    achieved: `${report.blockedRatePct}%`,
                    ok: report.blockedRatePct >= report.rubric.targetBlockedRate,
                  },
                ].map((c) => (
                  <div key={c.label} className="flex items-center justify-between gap-2 rounded-md border border-border/40 bg-card/40 px-2.5 py-1.5">
                    <span className="text-[10px] text-muted-foreground">{c.label}</span>
                    <span className="flex items-center gap-1.5 font-mono text-[10px]">
                      <span className="text-muted-foreground/70">tgt {c.target}</span>
                      <span className="text-muted-foreground/40">·</span>
                      <span className={c.ok ? "text-wg-emerald" : "text-wg-rose"}>{c.achieved}</span>
                      {c.ok ? <CheckCircle2 className="size-3 text-wg-emerald" /> : <X className="size-3 text-wg-rose" />}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {mixEntries.length > 0 && (
            <div className="col-span-2 sm:col-span-4">
              <p className="mb-1.5 text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Attack mix</p>
              <div className="flex flex-col gap-1">
                {mixEntries.map((e, i) => (
                  <div key={e.type} className="flex items-center gap-2">
                    <span className="w-28 shrink-0 truncate text-[10px] text-foreground/80">{e.type}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${(e.n / maxMix) * 100}%`, background: MIX_COLORS[i % MIX_COLORS.length] }}
                      />
                    </div>
                    <span className="w-10 shrink-0 text-right font-mono text-[10px] text-muted-foreground">{e.n}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {tab === "stages" && (
        <div className="mt-3 flex flex-col gap-1.5">
          {report.stages.map((st) => (
            <div key={st.idx} className="flex items-start gap-2 rounded-lg border border-border/40 bg-card/40 px-3 py-2">
              <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-wg-cyan/10 font-mono text-[9px] font-bold text-wg-cyan">
                {st.idx}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                  <p className="text-[11px] font-semibold text-foreground">{st.label}</p>
                  {st.attackType && (
                    <span className="rounded border border-border/50 bg-muted/40 px-1 py-px font-mono text-[8px] font-semibold text-wg-rose">
                      {st.attackType}
                    </span>
                  )}
                  <span className="font-mono text-[9px] text-muted-foreground">
                    {Math.round(st.attackShare * 100)}% hostile · {st.rate} rps · {fmtSec(st.durationSec)}
                  </span>
                </div>
                <p className="mt-0.5 text-[10px] text-muted-foreground">{st.desc}</p>
                {(st.alarm || st.incident) && (
                  <p className="mt-1 text-[9px] text-muted-foreground/80">
                    {st.alarm && <span className="text-wg-rose">alarm: {st.alarm}</span>}
                    {st.alarm && st.incident && " · "}
                    {st.incident && <span className="text-wg-amber">incident: {st.incident}</span>}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === "events" && (
        <div className="mt-3 flex max-h-56 flex-col gap-1.5 overflow-y-auto overscroll-contain pr-1">
          {report.events.map((e, i) => (
            <div key={i} className="flex items-start gap-2 rounded-lg border border-border/40 bg-card/40 px-2.5 py-1.5">
              <span className="shrink-0 font-mono text-[9px] text-wg-cyan">{e.t}</span>
              <span className="shrink-0 font-mono text-[8px] font-bold uppercase tracking-wider text-muted-foreground/60">
                {e.tone}
              </span>
              <p className="min-w-0 flex-1 text-[10px] leading-relaxed text-foreground/80">{e.text}</p>
            </div>
          ))}
        </div>
      )}

      {tab === "bans" && (
        <div className="mt-3 flex max-h-56 flex-col gap-1.5 overflow-y-auto overscroll-contain pr-1">
          {report.bans.length === 0 && (
            <p className="rounded-lg border border-dashed border-border/50 px-3 py-4 text-center text-[11px] text-muted-foreground">
              No IPs were added to the blocklist during this run.
            </p>
          )}
          {report.bans.map((b, i) => (
            <div key={i} className="flex items-start gap-2 rounded-lg border border-border/40 bg-card/40 px-2.5 py-1.5">
              <span className="shrink-0 font-mono text-[10px] font-semibold text-wg-rose">{b.ip}</span>
              <span className="shrink-0 rounded border border-border/50 bg-muted/40 px-1 py-px font-mono text-[8px] text-muted-foreground">
                {b.source}
              </span>
              <span className="shrink-0 font-mono text-[9px] text-muted-foreground">{b.country}</span>
              <p className="min-w-0 flex-1 truncate text-[10px] text-foreground/70" title={b.reason}>
                {b.reason}
              </p>
              <span className="shrink-0 font-mono text-[9px] text-muted-foreground">{b.hits} hits</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function DrillCompare({ reports }: { reports: DrillReport[] }) {
  const [aId, setAId] = useState(reports[0]?.id ?? "");
  const [bId, setBId] = useState(reports[1]?.id ?? reports[0]?.id ?? "");
  if (reports.length < 2) {
    return (
      <div className="wg-panel flex flex-col items-center gap-2 p-6 text-center">
        <GitCompareArrows className="size-5 text-muted-foreground/60" />
        <p className="max-w-sm text-[11px] leading-relaxed text-muted-foreground">
          Run at least two drills (or let the cadence schedule / loop fill the archive) to compare outcomes side by
          side.
        </p>
      </div>
    );
  }
  const a = reports.find((r) => r.id === aId) ?? reports[0];
  const b = reports.find((r) => r.id === bId) ?? reports[1];

  const pick = "h-8 rounded-lg border border-border/50 bg-muted/40 px-2 text-xs text-foreground outline-none transition-colors focus:border-wg-violet/50";
  const rows: Array<{
    label: string;
    a: string;
    b: string;
    delta?: { aNum: number; bNum: number; higherBetter: boolean };
  }> = [
    { label: "Scenario", a: a.scenario.name, b: b.scenario.name },
    { label: "Outcome", a: a.outcome, b: b.outcome },
    { label: "Duration", a: fmtSec(a.durationSec), b: fmtSec(b.durationSec) },
    { label: "Requests", a: a.stats.requests.toLocaleString(), b: b.stats.requests.toLocaleString() },
    { label: "Attacks classified", a: a.stats.attacks.toLocaleString(), b: b.stats.attacks.toLocaleString() },
    { label: "Blocked at edge", a: `${a.stats.blocked.toLocaleString()} (${a.blockedRatePct}%)`, b: `${b.stats.blocked.toLocaleString()} (${b.blockedRatePct}%)`, delta: { aNum: a.blockedRatePct, bNum: b.blockedRatePct, higherBetter: true } },
    { label: "Attack stop rate", a: `${a.attackStopRatePct}%`, b: `${b.attackStopRatePct}%`, delta: { aNum: a.attackStopRatePct, bNum: b.attackStopRatePct, higherBetter: true } },
    { label: "Alarms raised", a: String(a.stats.alarms), b: String(b.stats.alarms) },
    { label: "Incidents opened", a: String(a.stats.incidents), b: String(b.stats.incidents) },
    { label: "Canary trips", a: String(a.stats.canaryTrips), b: String(b.stats.canaryTrips) },
    { label: "Edge bans added", a: String(a.stats.bans), b: String(b.stats.bans) },
  ];

  return (
    <div className="wg-panel overflow-x-auto">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <p className="text-[11px] text-muted-foreground">
          Compare two archived runs — green marks the stronger stop-rate result.
        </p>
        <div className="flex items-center gap-1.5">
          <select value={a.id} onChange={(e) => setAId(e.target.value)} className={pick}>
            {reports.map((r) => (
              <option key={r.id} value={r.id}>
                {r.scenario.name} · {new Date(r.startedAt).toLocaleDateString()}
              </option>
            ))}
          </select>
          <GitCompareArrows className="size-3.5 shrink-0 text-wg-violet" />
          <select value={b.id} onChange={(e) => setBId(e.target.value)} className={pick}>
            {reports.map((r) => (
              <option key={r.id} value={r.id}>
                {r.scenario.name} · {new Date(r.startedAt).toLocaleDateString()}
              </option>
            ))}
          </select>
        </div>
      </div>
      <table className="mt-3 w-full min-w-[560px] border-collapse text-left">
        <thead>
          <tr className="border-b border-border/40">
            <th className="px-4 py-2 text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Metric</th>
            <th className="px-4 py-2 text-[10px] font-semibold text-wg-violet">{a.scenario.name}</th>
            <th className="px-4 py-2 text-[10px] font-semibold text-wg-cyan">{b.scenario.name}</th>
            <th className="px-4 py-2 text-right text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Delta</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            let deltaCell: React.ReactNode = <span className="text-muted-foreground/40">—</span>;
            if (r.delta) {
              const diff = r.delta.aNum - r.delta.bNum;
              if (diff !== 0) {
                const good = r.delta.higherBetter ? diff > 0 : diff < 0;
                deltaCell = (
                  <span className={cn("font-mono text-[10px] font-bold", good ? "text-wg-emerald" : "text-wg-rose")}>
                    {diff > 0 ? "▲" : "▼"} {Math.abs(diff)}
                  </span>
                );
              } else {
                deltaCell = <span className="font-mono text-[10px] text-muted-foreground/50">=</span>;
              }
            }
            return (
              <tr key={r.label} className="border-b border-border/30 last:border-0">
                <td className="px-4 py-2 text-[10px] font-semibold text-muted-foreground">{r.label}</td>
                <td className="px-4 py-2 font-mono text-[11px] text-foreground">{r.a}</td>
                <td className="px-4 py-2 font-mono text-[11px] text-foreground">{r.b}</td>
                <td className="px-4 py-2 text-right">{deltaCell}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ============================================================================
// Active drill console
// ============================================================================

function ActiveDrill({ now, onNavigate }: { now: number; onNavigate?: (tab: string) => void }) {
  const { state, dispatch } = useWaf();
  const drill = state.drill!;
  const scenario = drillScenarioById(drill.scenarioId) ?? DRILL_SCENARIOS[0];
  const totalSec = scenarioTotalSec(scenario);
  const elapsedSec = drill.done ? (drill.lastTickAt - drill.startedAt) / 1000 : (now - drill.startedAt) / 1000;
  const clampedElapsed = Math.min(elapsedSec, totalSec);
  const stageIdx = drill.done ? scenario.stages.length - 1 : stageIndexAt(scenario, elapsedSec);
  const stage = scenario.stages[stageIdx];
  const stageElapsed = stageElapsedAt(scenario, elapsedSec);
  const overallPct = Math.min(100, (clampedElapsed / totalSec) * 100);
  const stagePct = Math.min(100, (stageElapsed / stage.durationSec) * 100);
  const Icon = SCENARIO_ICONS[scenario.id] ?? Swords;

  const blockedRate = drill.stats.requests ? Math.round((drill.stats.blocked / drill.stats.requests) * 100) : 0;
  const attackBlockRate = drill.stats.attacks ? Math.round((drill.stats.blocked / drill.stats.attacks) * 100) : 0;

  const bans = useMemo(
    () => state.blocklist.filter((b) => b.addedAt >= drill.startedAt),
    [state.blocklist, drill.startedAt],
  );

  return (
    <div className="flex flex-col gap-4">
      {/* console header */}
      <div className="wg-panel p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className={cn("flex size-10 shrink-0 items-center justify-center rounded-xl", drill.done ? "bg-wg-emerald/10 text-wg-emerald" : drill.paused ? "bg-wg-amber/10 text-wg-amber" : "bg-wg-rose/10 text-wg-rose")}>
              <Icon className="size-5" />
            </div>
            <div className="min-w-0">
              <h3 className="truncate text-sm font-semibold text-foreground">{scenario.name}</h3>
              <p className="text-xs text-muted-foreground">
                {drill.done ? (
                  <span className="text-wg-emerald">Drill complete — results below</span>
                ) : drill.paused ? (
                  <span className="text-wg-amber">Paused — stream continues on benign baseline</span>
                ) : (
                  <>
                    Stage {stageIdx + 1} of {scenario.stages.length} ·{" "}
                    <span className="font-medium text-foreground/80">{stage.label}</span>
                  </>
                )}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {/* isolation toggle — pure attack campaign */}
            {!drill.done && (
              <Button
                variant="outline"
                size="sm"
                className={cn(
                  "h-8 gap-1.5",
                  drill.isolated
                    ? "border-wg-amber/50 bg-wg-amber/10 text-wg-amber hover:bg-wg-amber/20"
                    : "border-border/60 text-muted-foreground hover:text-foreground",
                )}
                onClick={() => dispatch({ type: "TOGGLE_DRILL_ISOLATION" })}
                title="When on, every stage emits pure attack traffic with no benign blend"
              >
                <Radio className="size-3.5" />
                <span className="hidden sm:inline">{drill.isolated ? "Isolated" : "Isolate traffic"}</span>
              </Button>
            )}
            {/* queue a rerun */}
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1.5 border-border/60 text-muted-foreground hover:text-foreground"
              onClick={() => {
                dispatch({ type: "QUEUE_DRILL", scenarioId: scenario.id });
                toast.info(`Queued — ${scenario.name}`, {
                  description: "Starts automatically when the current drill finishes",
                });
              }}
              title="Queue this scenario to run again automatically"
            >
              <ListPlus className="size-3.5" />
              <span className="hidden sm:inline">Queue rerun</span>
            </Button>
            {!drill.done && (
              <Button
                variant="outline"
                size="sm"
                className={cn("h-8 gap-1.5", drill.paused ? "border-wg-emerald/40 text-wg-emerald hover:bg-wg-emerald/10" : "border-wg-amber/40 text-wg-amber hover:bg-wg-amber/10")}
                onClick={() => dispatch({ type: "TOGGLE_DRILL_PAUSE" })}
              >
                {drill.paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
                {drill.paused ? "Resume" : "Pause"}
              </Button>
            )}
            {!drill.done && (
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-wg-rose/40 text-wg-rose hover:bg-wg-rose/10"
                onClick={() => dispatch({ type: "STOP_DRILL_AND_ARCHIVE" })}
              >
                <Square className="size-3.5" /> Abort
              </Button>
            )}
            {drill.done && (
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-border/60 text-muted-foreground hover:text-foreground"
                onClick={() => dispatch({ type: "DISMISS_DRILL" })}
              >
                <X className="size-3.5" /> Dismiss
              </Button>
            )}
            {/* report export */}
            <ReportExport scenario={scenario} drill={drill} bans={bans} mode={state.mode} target={state.target} compact />
          </div>
        </div>

        {/* overall progress */}
        <div className="mt-4">
          <div className="flex items-center justify-between text-[10px] text-muted-foreground">
            <span className="font-mono">{fmtSec(clampedElapsed)} / {fmtSec(totalSec)} elapsed</span>
            <span className="font-mono">{Math.round(overallPct)}% complete</span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-border/40">
            <div
              className="h-full rounded-full bg-gradient-to-r from-wg-violet via-wg-cyan to-wg-emerald transition-all"
              style={{ width: `${overallPct}%` }}
            />
          </div>
        </div>
      </div>

      {/* live stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <DrillStat icon={<Activity className="size-4" />} label="Requests" value={drill.stats.requests.toLocaleString()} tone="text-wg-cyan" />
        <DrillStat icon={<ShieldBan className="size-4" />} label="Blocked" value={drill.stats.blocked.toLocaleString()} tone="text-wg-rose" sub={`${blockedRate}% of all`} />
        <DrillStat icon={<Bot className="size-4" />} label="Attacks" value={drill.stats.attacks.toLocaleString()} tone="text-wg-orange" sub={`${attackBlockRate}% stopped`} />
        <DrillStat icon={<BellRing className="size-4" />} label="Alarms" value={drill.stats.alarms.toLocaleString()} tone="text-wg-rose" />
        <DrillStat icon={<Siren className="size-4" />} label="Incidents" value={drill.stats.incidents.toLocaleString()} tone="text-wg-amber" />
        <DrillStat icon={<Bomb className="size-4" />} label="Canary trips" value={drill.stats.canaryTrips.toLocaleString()} tone="text-wg-violet" sub={`${drill.stats.bans} auto-bans`} />
      </div>

      {/* scheduler — queue + loop */}
      <SchedulerPanel scenario={scenario} />
      {/* cadence schedule */}
      <SchedulePanel />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        {/* stage timeline */}
        <div className="wg-panel flex flex-col gap-2 p-4 xl:col-span-3">
          <SectionTitle
            title="Stage timeline"
            sub={drill.done ? "Campaign phases as executed" : "Live campaign phases — current stage highlighted"}
            right={
              <span className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                <AlarmClock className="size-3 text-wg-cyan" />
                {fmtSec(Math.min(elapsedSec, totalSec))}
              </span>
            }
          />
          <div className="flex flex-col gap-2">
            {scenario.stages.map((st, i) => {
              const isCurrent = i === stageIdx && !drill.done;
              const isPast = i < stageIdx || drill.done;
              return (
                <div
                  key={st.id}
                  className={cn(
                    "rounded-lg border p-3 transition-colors",
                    isCurrent ? "border-wg-cyan/40 bg-wg-cyan/[0.05]" : "border-border/40 bg-card/30",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        "flex size-5 shrink-0 items-center justify-center rounded-full font-mono text-[9px] font-bold",
                        isCurrent
                          ? "bg-wg-cyan/15 text-wg-cyan"
                          : isPast
                            ? "bg-wg-emerald/15 text-wg-emerald"
                            : "bg-muted/50 text-muted-foreground/50",
                      )}
                    >
                      {isPast ? <CheckCircle2 className="size-3" /> : i + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-semibold text-foreground">
                        {st.label}
                        {isCurrent && !drill.paused && <span className="ml-2 inline-block size-1.5 animate-pulse rounded-full bg-wg-cyan align-middle" />}
                      </p>
                      <p className="mt-0.5 truncate text-[10px] text-muted-foreground">{st.desc}</p>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {st.attackType && (
                        <span className="hidden rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-wg-cyan sm:inline">
                          {ATTACK_LABELS[st.attackType]}
                        </span>
                      )}
                      <span className="font-mono text-[10px] text-muted-foreground">{fmtSec(st.durationSec)}</span>
                    </div>
                  </div>
                  {(isCurrent || isPast) && (
                    <div className="mt-2 h-1 overflow-hidden rounded-full bg-border/40">
                      <div
                        className={cn("h-full rounded-full", isPast ? "bg-wg-emerald/60" : "bg-wg-cyan")}
                        style={{ width: `${isPast ? 100 : stagePct}%` }}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* quick jumps */}
          <div className="mt-1 flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => onNavigate?.("traffic")}
              className="flex items-center gap-1 rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[10px] text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
            >
              <Activity className="size-3" /> Watch live traffic
            </button>
            <button
              type="button"
              onClick={() => onNavigate?.("alerts")}
              className="flex items-center gap-1 rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[10px] text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
            >
              <BellRing className="size-3" /> Open alerts
            </button>
            <button
              type="button"
              onClick={() => onNavigate?.("incidents")}
              className="flex items-center gap-1 rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[10px] text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
            >
              <Siren className="size-3" /> Open incidents
            </button>
          </div>
        </div>

        {/* event feed + results */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          {drill.done ? (
            <DrillResults scenario={scenario} drill={drill} />
          ) : (
            <div className="wg-panel flex flex-col p-4">
              <SectionTitle title="Drill event feed" sub="Milestones as the campaign unfolds" />
              <div className="flex max-h-72 flex-col gap-1.5 overflow-y-auto overscroll-contain pr-1">
                {drill.events.map((e) => {
                  const tone = EVENT_TONE[e.tone] ?? EVENT_TONE.info;
                  const IconEl = tone.icon;
                  return (
                    <div key={e.id} className="flex items-start gap-2 rounded-lg border border-border/40 bg-card/40 p-2">
                      <span className={cn("mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-md border", tone.cls)}>
                        <IconEl className="size-3" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-[11px] leading-relaxed text-foreground/85">{e.text}</p>
                        <p className="mt-0.5 font-mono text-[9px] text-muted-foreground/70">
                          +{fmtSec((e.t - drill.startedAt) / 1000)} into drill
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Drill scheduler — queue + loop controls
// ============================================================================

function SchedulerPanel({ scenario }: { scenario: DrillScenario }) {
  const { state, dispatch } = useWaf();
  const loop = state.drillLoop;
  const queue = state.drillQueue;

  return (
    <div className="wg-panel flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
            <ListPlus className="size-4 text-wg-cyan" /> Drill scheduler
          </p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">
            Auto-start the next campaign after results — or repeat the current one on loop
          </p>
        </div>
        <button
          type="button"
          onClick={() => dispatch({ type: "TOGGLE_DRILL_LOOP" })}
          className={cn(
            "flex h-7 items-center gap-1.5 rounded-md border px-2 text-[10px] font-bold tracking-wider transition-colors",
            loop
              ? "border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20"
              : "border-border/50 bg-muted/40 text-muted-foreground hover:text-foreground",
          )}
          title="When on, a completed drill automatically re-queues itself and repeats"
        >
          <RotateCw className={cn("size-3", loop && "animate-[spin_3s_linear_infinite]")} />
          {loop ? "LOOP ON" : "LOOP OFF"}
        </button>
      </div>

      {queue.length === 0 && !loop ? (
        <div className="rounded-lg border border-dashed border-border/50 px-3 py-4 text-center text-[11px] text-muted-foreground">
          Nothing queued. Add scenarios from the library (or hit the Queue button here) — the console also has{" "}
          <span className="font-semibold text-foreground/70">Loop</span> to repeat this campaign forever.
        </div>
      ) : (
        <div className="flex flex-col gap-1.5">
          {loop && (
            <div className="flex items-center gap-2 rounded-lg border border-wg-violet/30 bg-wg-violet/[0.06] px-2.5 py-2 text-[11px] text-foreground/85">
              <RotateCw className="size-3.5 shrink-0 text-wg-violet" />
              <span className="min-w-0 flex-1 truncate">
                <span className="font-semibold text-wg-violet">Repeat forever</span> — {scenario.name} re-queues
                automatically when it completes
              </span>
            </div>
          )}
          {queue.map((q, i) => {
            const s = drillScenarioById(q.scenarioId);
            const QIcon = SCENARIO_ICONS[q.scenarioId] ?? Swords;
            return (
              <div key={q.qid} className="flex items-center gap-2 rounded-lg border border-border/40 bg-card/40 px-2.5 py-2">
                <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-wg-violet/10 text-wg-violet">
                  <QIcon className="size-3.5" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[11px] font-semibold text-foreground">{s?.name ?? q.scenarioId}</p>
                  <p className="font-mono text-[9px] text-muted-foreground">
                    #{i + 1} · {s ? fmtSec(scenarioTotalSec(s)) : "—"} · starts after current drill
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => dispatch({ type: "REMOVE_QUEUED_DRILL", qid: q.qid })}
                  className="flex size-6 shrink-0 items-center justify-center rounded-md border border-border/50 text-muted-foreground transition-colors hover:border-wg-rose/40 hover:text-wg-rose"
                  title="Remove from queue"
                >
                  <Trash2 className="size-3" />
                </button>
              </div>
            );
          })}
          <p className="flex items-center gap-1.5 text-[9px] text-muted-foreground">
            <Timer className="size-2.5" /> Results stay on screen ~8s after completion, then the queue advances
            automatically
          </p>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Completion summary
// ============================================================================

function DrillResults({ scenario, drill }: { scenario: DrillScenario; drill: DrillState }) {
  const { state, dispatch } = useWaf();
  const stats = drill.stats;
  const blockedRate = stats.requests ? Math.round((stats.blocked / stats.requests) * 100) : 0;
  const attackBlockRate = stats.attacks ? Math.round((stats.blocked / stats.attacks) * 100) : 0;
  const bans = useMemo(
    () => state.blocklist.filter((b) => b.addedAt >= drill.startedAt),
    [state.blocklist, drill.startedAt],
  );
  const verdicts: Array<{ label: string; value: number; cls: string }> = [
    { label: "Blocked", value: blockedRate, cls: "bg-wg-rose" },
    { label: "Reached origin (detection/off)", value: 100 - blockedRate, cls: "bg-wg-orange" },
  ];

  return (
    <div className="wg-panel flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionTitle title="Drill results" sub={`${scenario.name} — blocked rate ${blockedRate}% of ${stats.requests.toLocaleString()} requests`} />
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={cn(
              "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
              drillVerdictPass(scenario, attackBlockRate)
                ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
            )}
            title={`Rubric: ≥${drillTargetStopRate(scenario)}% attack stop rate required`}
          >
            {drillVerdictPass(scenario, attackBlockRate) ? <CheckCircle2 className="size-2.5" /> : <X className="size-2.5" />}
            {drillVerdictPass(scenario, attackBlockRate) ? "PASS" : "FAIL"}
          </span>
          <ReportExport scenario={scenario} drill={drill} bans={bans} mode={state.mode} target={state.target} compact />
        </div>
      </div>

      {/* verdict mix */}
      <div className="flex h-2.5 overflow-hidden rounded-full bg-border/40">
        {verdicts.map((v) => (
          <div key={v.label} className={v.cls} style={{ width: `${v.value}%` }} />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-muted-foreground">
        {verdicts.map((v) => (
          <span key={v.label} className="flex items-center gap-1.5">
            <span className={cn("size-2 rounded-sm", v.cls)} /> {v.label} · {v.value}%
          </span>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-2">
        <ResultCell label="Attacks classified" value={stats.attacks.toLocaleString()} />
        <ResultCell label="Attack stop rate" value={`${attackBlockRate}%`} tone="text-wg-emerald" />
        <ResultCell label="Alarms raised" value={stats.alarms.toLocaleString()} tone="text-wg-rose" />
        <ResultCell label="Incidents opened" value={stats.incidents.toLocaleString()} tone="text-wg-amber" />
        <ResultCell label="Canary trips" value={stats.canaryTrips.toLocaleString()} tone="text-wg-violet" />
        <ResultCell label="Edge bans (auto/manual)" value={stats.bans.toLocaleString()} tone="text-wg-cyan" />
      </div>

      {/* attack mix by class */}
      <AttackMixChart stats={stats} />

      <div className="rounded-lg border border-wg-emerald/25 bg-wg-emerald/[0.05] p-3">
        <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-wg-emerald">
          <CheckCircle2 className="size-3" /> Exercise complete
        </p>
        <p className="mt-1.5 text-xs leading-relaxed text-foreground/80">
          The campaign was stopped by the live policy. Check the alerts, incidents and blocklist the drill produced,
          then re-run the vulnerability audit to see the posture delta.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          className="h-8 flex-1 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20"
          onClick={() => dispatch({ type: "START_DRILL", scenarioId: scenario.id })}
        >
          <Play className="size-3.5" /> Run again
        </Button>
        <Button
          size="sm"
          className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20"
          onClick={() => dispatch({ type: "QUEUE_DRILL", scenarioId: scenario.id })}
        >
          <ListPlus className="size-3.5" /> Queue rerun
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1.5 border-border/60 text-muted-foreground hover:text-foreground"
          onClick={() => dispatch({ type: "DISMISS_DRILL" })}
        >
          <X className="size-3.5" /> Close
        </Button>
      </div>
    </div>
  );
}

/** Horizontal recharts bar chart of the observed attack mix (per attack class). */
function AttackMixChart({ stats }: { stats: DrillStats }) {
  const entries = useMemo(() => {
    const mix = stats.attackMix ?? {};
    return Object.entries(mix)
      .map(([type, n]) => ({ type: ATTACK_LABELS[type as AttackType] ?? type, n: n ?? 0 }))
      .sort((a, b) => b.n - a.n)
      .slice(0, 8);
  }, [stats.attackMix]);
  if (entries.length === 0) return null;

  return (
    <div className="rounded-lg border border-border/40 bg-card/40 p-3">
      <p className="flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Braces className="size-3 text-wg-cyan" /> Attack mix by class
        </span>
        <span className="font-mono text-[9px] font-normal normal-case tracking-normal">
          {entries.reduce((n, e) => n + e.n, 0)} classified
        </span>
      </p>
      <div className="mt-2 h-44 text-muted-foreground">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={entries} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="type"
              width={104}
              tickLine={false}
              axisLine={false}
              tick={{ fontSize: 10, fill: "currentColor" }}
            />
            <Tooltip content={<MixTooltip />} cursor={{ fill: "rgba(34,211,238,0.06)" }} />
            <Bar dataKey="n" name="Requests" radius={[0, 4, 4, 0]} barSize={12}>
              {entries.map((e, i) => (
                <Cell key={e.type} fill={MIX_COLORS[i % MIX_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function MixTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ value?: number; color?: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border/60 bg-popover/95 px-2.5 py-1.5 text-xs shadow-xl backdrop-blur">
      <p className="font-mono text-[10px] text-muted-foreground">{label}</p>
      <p className="flex items-center gap-1.5 pt-0.5">
        <span className="size-2 rounded-full" style={{ background: payload[0]?.color }} />
        <span className="font-mono font-semibold text-foreground">{payload[0]?.value}</span>
        <span className="text-[10px] text-muted-foreground">requests</span>
      </p>
    </div>
  );
}

function ResultCell({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-border/40 bg-card/40 p-3">
      <p className={cn("font-mono text-sm font-bold", tone ?? "text-foreground")}>{value}</p>
      <p className="mt-0.5 text-[9px] uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  );
}

function DrillStat({
  icon,
  label,
  value,
  tone,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone: string;
  sub?: string;
}) {
  return (
    <div className="wg-panel flex items-start justify-between gap-2 p-3.5">
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <p className={cn("mt-1 font-mono text-xl font-bold", tone)}>{value}</p>
        {sub && <p className="mt-0.5 text-[10px] text-muted-foreground">{sub}</p>}
      </div>
      <span className={cn("shrink-0 rounded-lg border border-border/60 bg-background/60 p-2", tone)}>{icon}</span>
    </div>
  );
}

// Re-export for the dashboard banner
export function scenarioMeta(scenarioId: string): { name: string; totalSec: number } | null {
  const s = drillScenarioById(scenarioId);
  return s ? { name: s.name, totalSec: scenarioTotalSec(s) } : null;
}

// ============================================================================
// Drill report export — Markdown, JSON, and a printable (Save-as-PDF) page
// ============================================================================

function downloadFile(name: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function openDrillPrint(r: DrillReport): void {
  const row = (cells: string[]) => `<tr>${cells.map((c) => `<td>${c}</td>`).join("")}</tr>`;
  const html = `<!doctype html><html><head><meta charset="utf-8"/><title>WebGuard Drill Report — ${r.scenario.name}</title>
<style>
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b0f17; color: #dbe4f0; margin: 40px; }
  h1 { color: #8b5cf6; font-size: 22px; }
  h2 { color: #22d3ee; font-size: 15px; margin-top: 28px; border-bottom: 1px solid #1e293b; padding-bottom: 6px; }
  table { border-collapse: collapse; width: 100%; margin-top: 10px; }
  th, td { border: 1px solid #1e293b; padding: 6px 10px; font-size: 11px; text-align: left; vertical-align: top; }
  th { background: #131a2a; color: #8b5cf6; }
  .meta { color: #94a3b8; font-size: 12px; line-height: 1.7; }
</style></head><body>
<h1>WebGuard Attack Drill Report — ${r.scenario.name}</h1>
<p class="meta">${r.scenario.tagline}<br/>
Difficulty: ${r.scenario.difficulty} · Outcome: ${r.outcome.toUpperCase()} · Firewall mode: ${r.mode.toUpperCase()} · Target: ${r.target}<br/>
Started: ${new Date(r.startedAt).toLocaleString()} · Finished: ${r.finishedAt ? new Date(r.finishedAt).toLocaleString() : "—"} · ${fmtSec(r.durationSec)} elapsed</p>
<h2>Campaign summary</h2>
<table><tbody>
${row(["<b>Requests</b>", "<b>Attacks</b>", "<b>Blocked</b>", "<b>Stop rate</b>", "<b>Alarms</b>", "<b>Incidents</b>", "<b>Canaries</b>", "<b>Bans</b>"])}
${row([r.stats.requests.toLocaleString(), r.stats.attacks.toLocaleString(), `${r.stats.blocked.toLocaleString()} (${r.blockedRatePct}%)`, `${r.attackStopRatePct}%`, String(r.stats.alarms), String(r.stats.incidents), String(r.stats.canaryTrips), String(r.stats.bans)])}
</tbody></table>
<h2>Stage timeline</h2>
<table><thead><tr><th>#</th><th>Stage</th><th>Attack</th><th>Hostile</th><th>Rate</th><th>Duration</th><th>Alarm / Incident</th></tr></thead><tbody>
${r.stages.map((st) => row([String(st.idx), st.label, st.attackType ?? "benign", `${Math.round(st.attackShare * 100)}%`, `${st.rate} rps`, fmtSec(st.durationSec), [st.alarm, st.incident].filter(Boolean).join(" · ") || "—"])).join("")}
</tbody></table>
<h2>Event feed</h2>
<table><tbody>
${r.events.map((e) => row([e.t, e.tone.toUpperCase(), e.text])).join("")}
</tbody></table>
${r.bans.length ? `<h2>Blocked IPs added during the drill</h2><table><thead><tr><th>IP</th><th>Source</th><th>Country</th><th>Hits</th><th>Reason</th></tr></thead><tbody>${r.bans.map((b) => row([b.ip, b.source, b.country, String(b.hits), b.reason])).join("")}</tbody></table>` : ""}
<p class="meta">Generated by WebGuard SOC Console · ${new Date(r.exportedAt).toLocaleString()}</p>
</body></html>`;
  const w = window.open("", "_blank");
  if (!w) return;
  w.document.open();
  w.document.write(html);
  w.document.close();
  w.focus();
  window.setTimeout(() => w.print(), 400);
}

/** Compact export button group (Markdown / JSON / printable PDF). */
function ReportExport({
  scenario,
  drill,
  bans,
  mode,
  target,
  compact,
}: {
  scenario: DrillScenario;
  drill: DrillState;
  bans: BlockedIp[];
  mode: WafMode;
  target: string;
  compact?: boolean;
}) {
  const report = useMemo(
    () => buildDrillReport(scenario, drill, bans, mode, target),
    [scenario, drill, bans, mode, target],
  );
  const btn =
    "flex h-7 items-center gap-1 rounded-md border border-border/50 bg-muted/40 px-2 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan";
  return (
    <div className="flex items-center gap-1.5">
      <span className={cn("text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/60", compact && "hidden sm:inline")}>
        Report
      </span>
      <button
        type="button"
        className={btn}
        onClick={() => downloadFile(`webguard-drill-${scenario.id}.md`, drillReportMarkdown(report), "text/markdown")}
        title="Download Markdown report"
      >
        <FileText className="size-3" /> MD
      </button>
      <button
        type="button"
        className={btn}
        onClick={() => downloadFile(`webguard-drill-${scenario.id}.json`, JSON.stringify(report, null, 2), "application/json")}
        title="Download JSON data"
      >
        <FileJson className="size-3" /> JSON
      </button>
      <button
        type="button"
        className={btn}
        onClick={() => openDrillPrint(report)}
        title="Open printable report (Save as PDF from the browser print dialog)"
      >
        <Printer className="size-3" /> PDF
      </button>
    </div>
  );
}
