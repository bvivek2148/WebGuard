import { useEffect, useMemo, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { ATTACK_SPECS } from "../data";
import { uid, useWaf } from "../engine";
import type { Alarm, AlarmState } from "../types";
import { SEVERITY_META } from "../types";
import { flagEmoji, SectionTitle, SeverityBadge, StatusBadge, timeAgo, useNow } from "./shared";
import {
  Activity,
  BellRing,
  Bug,
  CheckCheck,
  CheckCircle2,
  Clock4,
  Gauge,
  Plus,
  Search,
  ShieldBan,
  ShieldCheck,
  Siren,
  Sparkles,
  Timer,
  X,
} from "lucide-react";
import { Input } from "@/components/ui/input";

const SIM_SOURCES: Array<{ source: string; ip: string; code: string }> = [
  { source: "91.134.22.7 · Frankfurt", ip: "91.134.22.7", code: "DE" },
  { source: "45.155.4.12 · Frankfurt", ip: "45.155.4.12", code: "DE" },
  { source: "159.65.81.9 · Singapore", ip: "159.65.81.9", code: "SG" },
  { source: "133.242.7.101 · Tokyo", ip: "133.242.7.101", code: "JP" },
  { source: "103.5.140.22 · Tokyo", ip: "103.5.140.22", code: "JP" },
];

const STATE_FILTERS: Array<AlarmState | "all"> = ["all", "active", "acknowledged", "snoozed", "resolved"];
const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"] as const;

/** Active alarms older than this are flagged for escalation. */
const ESCALATE_AFTER_MS = 3 * 60_000;

const STATE_CHIP: Record<AlarmState, { label: string; cls: string }> = {
  active: { label: "ACTIVE", cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" },
  acknowledged: { label: "ACKNOWLEDGED", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" },
  snoozed: { label: "SNOOZED", cls: "border-wg-sky/40 bg-wg-sky/10 text-wg-sky" },
  resolved: { label: "RESOLVED", cls: "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" },
};

function extractIp(source: string): string | null {
  const m = source.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
  return m ? m[0] : null;
}

export function AlertsTab() {
  const { state, dispatch } = useWaf();
  const [stateFilter, setStateFilter] = useState<AlarmState | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<(typeof SEVERITY_FILTERS)[number]>("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const now = useNow(1000);

  const alarms = useMemo(
    () =>
      state.alarms
        .filter((a) => stateFilter === "all" || a.state === stateFilter)
        .filter((a) => severityFilter === "all" || a.severity === severityFilter)
        .filter((a) => {
          if (!query.trim()) return true;
          const q = query.toLowerCase();
          return (
            a.title.toLowerCase().includes(q) ||
            a.source.toLowerCase().includes(q) ||
            a.detail.toLowerCase().includes(q) ||
            a.ruleId.toLowerCase().includes(q)
          );
        }),
    [state.alarms, stateFilter, severityFilter, query],
  );

  const counts = useMemo(() => {
    const c: Record<AlarmState, number> = { active: 0, acknowledged: 0, snoozed: 0, resolved: 0 };
    for (const a of state.alarms) c[a.state] += 1;
    return c;
  }, [state.alarms]);

  // Escalation watch — active alarms past the SLA window
  const escalated = useMemo(
    () => state.alarms.filter((a) => a.state === "active" && now - a.ts > ESCALATE_AFTER_MS),
    [state.alarms, now],
  );

  // 12-hour volume histogram (CSS bars, no chart dependency)
  const volume = useMemo(() => {
    const buckets = Array.from({ length: 12 }, () => ({ active: 0, quiet: 0 }));
    for (const a of state.alarms) {
      const ageH = Math.floor((now - a.ts) / 3_600_000);
      if (ageH >= 0 && ageH < 12) {
        if (a.state === "active") buckets[11 - ageH].active += 1;
        else buckets[11 - ageH].quiet += 1;
      }
    }
    const max = Math.max(1, ...buckets.map((b) => b.active + b.quiet));
    return { buckets, max };
  }, [state.alarms, now]);

  const resolveRate = state.alarms.length ? Math.round((counts.resolved / state.alarms.length) * 100) : 100;

  // Master-detail selection
  const selected: Alarm | null = alarms.find((a) => a.id === selectedId) ?? alarms[0] ?? null;

  const simulateAlarm = () => {
    const spec = ATTACK_SPECS[Math.floor(Math.random() * ATTACK_SPECS.length)];
    const origin = SIM_SOURCES[Math.floor(Math.random() * SIM_SOURCES.length)];
    const alarm: Alarm = {
      id: uid("AL"),
      severity: spec.severity,
      title: `${spec.label} — ${spec.path}`,
      source: origin.source,
      ts: Date.now(),
      state: "active",
      detail: `Rule ${spec.ruleId} matched ${spec.label.toLowerCase()} traffic. ${state.mode === "blocking" ? "Dropped with 403 before reaching origin." : "Logged — origin processed the request."}`,
      ruleId: spec.ruleId,
      sourceIp: origin.ip,
      countryCode: origin.code,
    };
    dispatch({ type: "ADD_ALARM", alarm });
    setSelectedId(alarm.id);
  };

  const ackEscalated = () => {
    for (const a of escalated) dispatch({ type: "ACK_ALARM", id: a.id });
  };

  return (
    <div className="flex flex-col gap-4">
      {/* triage KPI strip */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <AlarmStat icon={<Activity className="size-4" />} label="Total alarms" value={state.alarms.length} accent="text-wg-cyan" sub="rolling queue (max 40)" />
        <AlarmStat icon={<Siren className="size-4" />} label="Active now" value={counts.active} accent="text-wg-rose" sub="needs triage" />
        <AlarmStat icon={<Timer className="size-4" />} label="Escalated" value={escalated.length} accent="text-wg-amber" sub={`idle > ${ESCALATE_AFTER_MS / 60_000} min`} />
        <AlarmStat icon={<CheckCircle2 className="size-4" />} label="Resolve rate" value={resolveRate} accent="text-wg-emerald" sub="of all alarms resolved" suffix="%" />
      </div>

      {/* escalation watch */}
      {escalated.length > 0 && (
        <div className="flex flex-col gap-1.5 rounded-xl border border-wg-amber/25 bg-wg-amber/[0.06] p-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-wg-amber">
              <Timer className="size-3.5" /> Escalation watch — {escalated.length} alarm{escalated.length > 1 ? "s" : ""} past the {ESCALATE_AFTER_MS / 60_000}-minute SLA
            </p>
            <Button
              variant="outline"
              size="sm"
              className="ml-auto h-6 gap-1 border-wg-amber/30 text-[10px] text-wg-amber hover:bg-wg-amber/10"
              onClick={ackEscalated}
            >
              <CheckCheck className="size-3" /> Ack escalated
            </Button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {escalated.slice(0, 6).map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => setSelectedId(a.id)}
                className="flex items-center gap-1.5 rounded-md border border-border/40 bg-card/60 px-1.5 py-0.5 transition-colors hover:border-wg-amber/50"
              >
                <span className="size-1.5 rounded-full" style={{ background: SEVERITY_META[a.severity].color }} />
                <span className="max-w-52 truncate text-[10px] text-foreground/80">{a.title}</span>
                <span className="font-mono text-[9px] text-wg-amber">{Math.round((now - a.ts) / 60_000)}m</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* master-detail alert center */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        {/* left — queue */}
        <div className="wg-panel flex flex-col p-4 xl:col-span-2">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Alert queue</h3>
              <p className="mt-0.5 text-xs text-muted-foreground">Select an alarm to inspect & respond</p>
            </div>
            <div className="flex items-center gap-1.5">
              {counts.active > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-wg-amber/30 text-[11px] text-wg-amber hover:bg-wg-amber/10"
                  onClick={() => dispatch({ type: "ACK_ALL_ALARMS" })}
                >
                  <CheckCheck className="size-3.5" /> Ack all
                </Button>
              )}
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1.5 border-wg-rose/30 text-[11px] text-wg-rose hover:bg-wg-rose/10"
                onClick={simulateAlarm}
              >
                <Plus className="size-3.5" /> Simulate
              </Button>
            </div>
          </div>

          {/* filters */}
          <div className="mb-2 flex flex-wrap items-center gap-1.5">
            {STATE_FILTERS.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setStateFilter(s)}
                className={cn(
                  "rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition-colors",
                  stateFilter === s
                    ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                    : "border-border/50 text-muted-foreground hover:text-foreground/80",
                )}
              >
                {s}
                {s !== "all" && <span className="ml-1 font-mono text-[10px] opacity-70">{counts[s]}</span>}
              </button>
            ))}
          </div>
          <div className="mb-2 flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Severity</span>
            {SEVERITY_FILTERS.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSeverityFilter(s)}
                className={cn(
                  "rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition-colors",
                  severityFilter === s
                    ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                    : "border-border/50 text-muted-foreground hover:text-foreground/80",
                )}
              >
                {s === "all" ? "All" : s.toUpperCase()}
              </button>
            ))}
          </div>
          <div className="relative mb-3">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search title, source, rule…"
              className="h-8 border-border/60 bg-muted/50 pl-8 text-xs focus-visible:ring-cyan-400/40"
            />
          </div>

          {/* alarm rows */}
          <div className="-mx-1 flex flex-1 flex-col gap-1 overflow-y-auto pr-1 max-h-[380px] lg:max-h-[480px] xl:max-h-[560px]">
            {alarms.map((a) => {
              const meta = SEVERITY_META[a.severity];
              const ageMin = Math.floor((now - a.ts) / 60_000);
              const isSel = selected?.id === a.id;
              return (
                <button
                  key={a.id}
                  type="button"
                  onClick={() => setSelectedId(a.id)}
                  className={cn(
                    "group relative flex items-center gap-2.5 overflow-hidden rounded-lg border p-2.5 text-left transition-all",
                    isSel
                      ? "border-wg-cyan/50 bg-wg-cyan/[0.07]"
                      : "border-border/40 bg-card/40 hover:border-border/80 hover:bg-muted/50",
                  )}
                >
                  {/* severity rail */}
                  <span className="absolute inset-y-0 left-0 w-[3px]" style={{ background: meta.color }} />
                  <span
                    className="ml-0.5 flex size-7 shrink-0 items-center justify-center rounded-md"
                    style={{ background: `${meta.color}14` }}
                  >
                    {a.severity === "critical" ? (
                      <Siren className="size-3.5" style={{ color: meta.color }} />
                    ) : (
                      <BellRing className="size-3.5" style={{ color: meta.color }} />
                    )}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-foreground">{a.title}</span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px] text-muted-foreground">
                      <span className="truncate">{a.source}</span>
                      <span className="shrink-0 font-mono">{ageMin < 1 ? "<1m" : `${ageMin}m`}</span>
                      {a.state === "active" && now - a.ts > ESCALATE_AFTER_MS && (
                        <span className="shrink-0 rounded border border-wg-amber/40 bg-wg-amber/10 px-1 text-[8px] font-bold text-wg-amber">SLA</span>
                      )}
                    </span>
                  </span>
                  <span className={cn("shrink-0 rounded-md border px-1.5 py-0.5 text-[8px] font-bold tracking-wider", STATE_CHIP[a.state].cls)}>
                    {STATE_CHIP[a.state].label}
                  </span>
                </button>
              );
            })}
            {alarms.length === 0 && (
              <div className="flex flex-col items-center gap-2 py-14 text-center">
                <ShieldCheck className="size-8 text-emerald-400/60" />
                <p className="text-sm font-medium text-foreground/80">No alarms match</p>
                <p className="text-xs text-muted-foreground">The queue is quiet. New signature matches appear here instantly.</p>
              </div>
            )}
          </div>
        </div>

        {/* right — inspector */}
        <div className="flex flex-col gap-4 xl:col-span-3">
          {/* volume histogram — below the inspector on mobile so the inspector is reachable right after the queue */}
          <div className="wg-panel order-2 p-4 xl:order-none">
            <SectionTitle
              title="Alert volume · 12h"
              sub="Hourly alarm arrivals — active vs. handled"
              right={
                <Badge variant="outline" className="gap-1 border-border/50 text-[10px] text-muted-foreground">
                  <span className="size-1.5 rounded-full bg-wg-rose" /> active
                  <span className="ml-1 size-1.5 rounded-full bg-wg-emerald/70" /> handled
                </Badge>
              }
            />
            <div className="flex h-20 items-end gap-1.5">
              {volume.buckets.map((b, i) => {
                const total = b.active + b.quiet;
                return (
                  <div key={i} className="group flex h-full flex-1 flex-col items-center justify-end gap-1">
                    <span className="font-mono text-[9px] leading-none text-muted-foreground/70 opacity-0 transition-opacity group-hover:opacity-100">
                      {total}
                    </span>
                    <div className="flex w-full flex-col justify-end rounded-sm" style={{ height: `${Math.max(6, (total / volume.max) * 100)}%` }}>
                      <div className="w-full flex-1 rounded-t-sm bg-wg-emerald/50 transition-colors group-hover:bg-wg-emerald/70" style={{ height: total ? `${(b.quiet / Math.max(1, total)) * 100}%` : "0%" }} />
                      <div className="w-full rounded-sm bg-wg-rose/70 transition-colors group-hover:bg-wg-rose" style={{ height: total ? `${(b.active / Math.max(1, total)) * 100}%` : "0%" }} />
                    </div>
                    {i % 3 === 0 && (
                      <span className="text-[9px] leading-none text-muted-foreground/60">
                        {i === 0 ? "now" : `${i * 3}h`}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* inspector — first on mobile so selection lands right under the queue */}
          <div className="order-1 flex flex-col xl:order-none">
            {selected ? (
              <AlarmInspector alarm={selected} onClose={() => setSelectedId(null)} />
            ) : (
              <div className="wg-panel flex flex-col items-center gap-3 p-10 text-center">
                <div className="flex size-12 items-center justify-center rounded-xl border border-border/50 bg-muted/40 text-muted-foreground">
                  <Gauge className="size-5" />
                </div>
                <p className="text-sm font-medium text-foreground/80">No alarm selected</p>
                <p className="max-w-sm text-xs text-muted-foreground">
                  Pick an alarm from the queue — or simulate one — to inspect the source, matched rule, related traffic, and run response actions.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Alarm inspector — deep-dive panel for the selected alarm
// ============================================================================

function AlarmInspector({ alarm, onClose }: { alarm: Alarm; onClose: () => void }) {
  const { state, dispatch } = useWaf();
  const now = useNow(1000);
  const selfRef = useRef<HTMLDivElement | null>(null);

  // On mobile/tablet (below xl) the inspector renders below the queue — bring it into view on selection
  useEffect(() => {
    if (window.matchMedia("(max-width: 1279px)").matches) {
      selfRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, []);
  const meta = SEVERITY_META[alarm.severity];
  const sourceIp = alarm.sourceIp ?? extractIp(alarm.source);
  const alreadyBlocked = sourceIp ? state.blocklist.some((b) => b.ip === sourceIp && b.active) : true;
  const ageMin = Math.floor((now - alarm.ts) / 60_000);
  const isEscalated = alarm.state === "active" && now - alarm.ts > ESCALATE_AFTER_MS;

  const related = useMemo(
    () => (sourceIp ? state.logs.filter((l) => l.ip === sourceIp).slice(0, 4) : []),
    [state.logs, sourceIp],
  );

  const ack = () => dispatch({ type: "ACK_ALARM", id: alarm.id });
  const snooze = () => dispatch({ type: "SNOOZE_ALARM", id: alarm.id });
  const resolve = () => dispatch({ type: "RESOLVE_ALARM", id: alarm.id });

  const blockSource = () => {
    if (!sourceIp || alreadyBlocked) return;
    dispatch({
      type: "ADD_BLOCKED_IP",
      entry: {
        id: uid("BAN"),
        ip: sourceIp,
        reason: `Alarm triage — ${alarm.title.split(" — ")[0] ?? alarm.ruleId}`,
        source: "manual",
        country: alarm.countryCode ?? "—",
        countryCode: alarm.countryCode ?? "—",
        addedAt: Date.now(),
        hits: 0,
        active: true,
        expiresAt: null,
      },
    });
  };

  const openIncident = () => {
    dispatch({
      type: "ADD_INCIDENT",
      incident: {
        id: uid("INC"),
        title: alarm.title,
        vector: alarm.title.split(" — ")[0] || alarm.ruleId,
        severity: alarm.severity,
        sourceIp: sourceIp ?? "0.0.0.0",
        country: alarm.countryCode ?? "DE",
        stage: "investigating",
        openedAt: Date.now(),
        closedAt: null,
        detail: `Promoted from alarm ${alarm.id}: ${alarm.detail}`,
        playbook: null,
      },
    });
    ack();
  };

  const analyze = () => {
    dispatch({
      type: "OPEN_COPILOT",
      context: {
        kind: "log",
        title: alarm.title,
        attackType: null,
        ip: sourceIp ?? "-",
        country: alarm.countryCode ?? "-",
        severity: alarm.severity,
        payload: alarm.detail,
        ruleId: alarm.ruleId,
        threatScore: alarm.severity === "critical" ? 96 : alarm.severity === "high" ? 84 : alarm.severity === "medium" ? 62 : 38,
        path: alarm.title.split(" — ")[1] ?? "-",
      },
    });
  };

  return (
    <div ref={selfRef} className="wg-panel scroll-mt-4 overflow-hidden">
      {/* header */}
      <div className="border-b border-border/50 p-4" style={{ background: `${meta.color}08` }}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-lg" style={{ background: `${meta.color}14` }}>
                {alarm.severity === "critical" ? (
                  <Siren className="size-4" style={{ color: meta.color }} />
                ) : (
                  <BellRing className="size-4" style={{ color: meta.color }} />
                )}
              </span>
              <p className="text-base font-semibold leading-tight text-foreground">{alarm.title}</p>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <SeverityBadge severity={alarm.severity} />
              <span className={cn("rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", STATE_CHIP[alarm.state].cls)}>
                {STATE_CHIP[alarm.state].label}
              </span>
              {isEscalated && (
                <span className="flex items-center gap-1 rounded-md border border-wg-amber/40 bg-wg-amber/10 px-1.5 py-0.5 text-[9px] font-bold text-wg-amber">
                  <Timer className="size-2.5" /> PAST SLA
                </span>
              )}
              <span className="font-mono text-[10px] text-muted-foreground">
                {alarm.id} · {ageMin < 1 ? "<1 min" : `${ageMin} min`} ago · {timeAgo(alarm.ts)}
              </span>
            </div>
          </div>
          <Button variant="ghost" size="icon-sm" onClick={onClose} className="text-muted-foreground">
            <X className="size-4" />
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 p-4 lg:grid-cols-2">
        {/* source */}
        <div className="flex flex-col gap-2">
          <p className="wg-kicker">Source</p>
          <div className="flex items-center gap-3 rounded-xl border border-border/40 bg-card/50 p-3">
            <span className="text-2xl leading-none">{flagEmoji(alarm.countryCode ?? "DE")}</span>
            <div className="min-w-0 flex-1">
              <p className="truncate font-mono text-sm font-medium text-foreground">{sourceIp ?? alarm.source}</p>
              <p className="text-[10px] text-muted-foreground">{alarm.source} · {alarm.countryCode ?? "—"}</p>
            </div>
            {sourceIp && !alreadyBlocked && (
              <Button variant="outline" size="sm" className="h-7 gap-1.5 border-wg-rose/40 text-[11px] text-wg-rose hover:bg-wg-rose/10" onClick={blockSource}>
                <ShieldBan className="size-3.5" /> Block
              </Button>
            )}
            {alreadyBlocked && (
              <span className="rounded-md border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 text-[9px] font-bold text-wg-rose">BANNED</span>
            )}
          </div>

          {/* rule */}
          <div className="rounded-xl border border-border/40 bg-card/50 p-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">Matched rule</p>
              <span className="rounded border border-wg-cyan/30 bg-wg-cyan/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-wg-cyan">{alarm.ruleId}</span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-foreground/80">{alarm.detail}</p>
            <p className="mt-2 text-[10px] text-muted-foreground">
              {state.mode === "blocking"
                ? "Firewall is BLOCKING — this traffic is dropped with 403 before reaching the origin."
                : state.mode === "detection"
                  ? "Firewall is in DETECTION — this traffic reached the origin. Flip to BLOCKING to enforce."
                  : "Firewall is OFF — the origin is fully exposed to this traffic."}
            </p>
          </div>

          {/* related traffic */}
          <div className="rounded-xl border border-border/40 bg-card/50 p-3">
            <p className="mb-2 flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
              Related traffic from this source
              <span className="font-mono text-muted-foreground/70">{related.length} recent</span>
            </p>
            <div className="flex flex-col">
              {related.map((l) => (
                <div key={l.id} className="flex items-center gap-2 border-b border-border/25 py-1.5 last:border-0">
                  <StatusBadge status={l.status} />
                  <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-foreground/80">
                    {l.method} {l.path}
                  </span>
                  <span className="shrink-0 font-mono text-[9px] text-muted-foreground">{l.latency.toFixed(1)}ms</span>
                </div>
              ))}
              {related.length === 0 && <p className="py-3 text-center text-[10px] text-muted-foreground">No matching requests in the stream.</p>}
            </div>
          </div>
        </div>

        {/* response actions */}
        <div className="flex flex-col gap-2">
          <p className="wg-kicker">Response</p>
          <div className="grid grid-cols-2 gap-2">
            {alarm.state !== "acknowledged" && (
              <ActionBtn icon={<CheckCheck className="size-3.5" />} label="Acknowledge" tone="border-wg-amber/30 text-wg-amber hover:bg-wg-amber/10" onClick={ack} />
            )}
            {alarm.state !== "snoozed" && alarm.state !== "resolved" && (
              <ActionBtn icon={<Clock4 className="size-3.5" />} label="Snooze 1h" tone="border-wg-sky/30 text-wg-sky hover:bg-wg-sky/10" onClick={snooze} />
            )}
            {alarm.state !== "resolved" && (
              <ActionBtn icon={<ShieldCheck className="size-3.5" />} label="Resolve" tone="border-wg-emerald/30 text-wg-emerald hover:bg-wg-emerald/10" onClick={resolve} />
            )}
            {alarm.state !== "resolved" && (
              <ActionBtn icon={<Bug className="size-3.5" />} label="Open incident" tone="border-wg-rose/30 text-wg-rose hover:bg-wg-rose/10" onClick={openIncident} />
            )}
            {alarm.state !== "resolved" && (
              <ActionBtn icon={<Sparkles className="size-3.5" />} label="Analyze with AI" tone="border-wg-violet/40 text-wg-violet hover:bg-wg-violet/10" onClick={analyze} className="col-span-2" />
            )}
          </div>

          {/* triage timeline */}
          <div className="mt-1 rounded-xl border border-border/40 bg-card/50 p-3">
            <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">Triage state</p>
            <div className="flex items-center gap-1">
              {(["active", "acknowledged", "snoozed", "resolved"] as AlarmState[]).map((s, i) => {
                const done = STATE_ORDER_INDEX[alarm.state] >= i;
                const cur = alarm.state === s;
                return (
                  <div key={s} className="flex flex-1 flex-col items-center gap-1">
                    <span
                      className={cn(
                        "flex size-5 items-center justify-center rounded-full border font-mono text-[9px] font-bold",
                        cur
                          ? "border-wg-cyan/60 bg-wg-cyan/15 text-wg-cyan"
                          : done
                            ? "border-border/40 bg-muted/40 text-muted-foreground"
                            : "border-border/20 bg-transparent text-muted-foreground/40",
                      )}
                    >
                      {i + 1}
                    </span>
                    <span className={cn("text-center text-[8px] font-semibold uppercase tracking-wider", cur ? "text-wg-cyan" : "text-muted-foreground/60")}>
                      {s === "acknowledged" ? "acked" : s}
                    </span>
                  </div>
                );
              })}
            </div>
            <p className="mt-2 text-[10px] leading-relaxed text-muted-foreground">
              {alarm.state === "resolved"
                ? "Resolved alarms are retained in the queue for audit and no longer count toward exposure."
                : alarm.state === "acknowledged"
                  ? "Acknowledged — the team owns this alarm. It still counts toward active exposure until resolved."
                  : alarm.state === "snoozed"
                    ? "Snoozed — hidden from the active queue for 1h, then re-surfaces if the signature still fires."
                    : "Active — no owner yet. Acknowledge to claim it, or let the escalation watch flag it past 3 minutes."}
            </p>
          </div>

          {/* disposition summary */}
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Severity", value: alarm.severity.toUpperCase(), cls: meta.badge },
              { label: "Age", value: ageMin < 1 ? "<1m" : `${ageMin}m`, cls: "border-border/40 bg-muted/40 text-muted-foreground" },
              { label: "Attempts", value: String(1 + related.length), cls: "border-border/40 bg-muted/40 text-muted-foreground" },
            ].map((s) => (
              <div key={s.label} className={cn("rounded-lg border px-2 py-1.5 text-center", s.cls)}>
                <p className="font-mono text-xs font-bold">{s.value}</p>
                <p className="text-[8px] uppercase tracking-wider opacity-70">{s.label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

const STATE_ORDER_INDEX: Record<AlarmState, number> = { active: 0, acknowledged: 1, snoozed: 2, resolved: 3 };

function ActionBtn({
  icon,
  label,
  tone,
  onClick,
  className,
}: {
  icon: React.ReactNode;
  label: string;
  tone: string;
  onClick: () => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn("flex h-9 items-center justify-center gap-1.5 rounded-lg border text-[11px] font-medium transition-colors", tone, className)}
    >
      {icon}
      {label}
    </button>
  );
}

function AlarmStat({
  icon,
  label,
  value,
  accent,
  sub,
  suffix = "",
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  accent: string;
  sub: string;
  suffix?: string;
}) {
  return (
    <div className="wg-panel flex items-start justify-between gap-3 p-4">
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <div className="mt-1.5 text-2xl font-semibold tracking-tight text-foreground">
          {value}
          {suffix && <span className="ml-0.5 text-sm font-medium text-muted-foreground">{suffix}</span>}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
      </div>
      <div className={cn("shrink-0 rounded-lg border border-border/60 bg-background/60 p-2", accent)}>{icon}</div>
    </div>
  );
}
