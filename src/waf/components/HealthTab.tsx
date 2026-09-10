import { useMemo } from "react";
import { Area, AreaChart, ResponsiveContainer } from "recharts";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import { SectionTitle, useNow } from "./shared";
import { Activity, AlertTriangle, Cpu, Database, Gauge, Globe, Globe2, HeartPulse, Network, Server, ShieldCheck, Waypoints } from "lucide-react";

const STRESS_KEYS: { key: "waf" | "app" | "lb" | "db"; label: string; color: string }[] = [
  { key: "waf", label: "WAF engine", color: "#22d3ee" },
  { key: "lb", label: "Load balancer", color: "#a78bfa" },
  { key: "app", label: "Origin app", color: "#fbbf24" },
  { key: "db", label: "Database", color: "#34d399" },
];

const NODE_META: { id: string; label: string; sub: string; icon: typeof Globe }[] = [
  { id: "clients", label: "Client edge", sub: "TLS termination · CDN ingress", icon: Globe },
  { id: "edge-dns", label: "Edge DNS", sub: "authoritative + threat filter", icon: Network },
  { id: "lb", label: "Load balancer", sub: "L7 routing · health checks", icon: Waypoints },
  { id: "waf", label: "WAF engine", sub: "5-pass inspection pipeline", icon: ShieldCheck },
  { id: "app", label: "Origin app", sub: "shop.example.com", icon: Server },
  { id: "db", label: "Database", sub: "postgres · primary replica", icon: Database },
];

const NODE_WEIGHTS: Record<string, number> = {
  clients: 0.34,
  "edge-dns": 0.08,
  lb: 0.22,
  waf: 0.18,
  app: 0.12,
  db: 0.06,
};

function healthOf(stress: number): { label: string; dot: string; cls: string } {
  if (stress < 0.45) return { label: "HEALTHY", dot: "bg-emerald-400", cls: "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" };
  if (stress < 0.7) return { label: "DEGRADED", dot: "bg-amber-400", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" };
  return { label: "CRITICAL", dot: "bg-rose-400", cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" };
}

export function HealthTab() {
  const { state, currentRps, avgLatency } = useWaf();

  const nodes = useMemo(
    () =>
      NODE_META.map((n) => {
        const stress = state.stress[n.id] ?? 0.2;
        const h = healthOf(stress);
        return {
          ...n,
          stress,
          rps: Math.round(currentRps * NODE_WEIGHTS[n.id] * 10) / 10,
          heapMb: Math.round(48 + stress * 460),
          latencyMs: Math.round((0.4 + stress * 9) * 10) / 10,
          errRate: Math.round(stress * 2.6 * 10) / 10,
          health: h,
        };
      }),
    [state.stress, currentRps],
  );

  const healthy = nodes.filter((n) => n.health.label === "HEALTHY").length;
  const degraded = nodes.filter((n) => n.health.label === "DEGRADED").length;
  const critical = nodes.filter((n) => n.health.label === "CRITICAL").length;
  const overall = Math.max(0, Math.round(100 - nodes.reduce((s, n) => s + n.stress * 55, 0) / nodes.length));
  const underLoad = state.underAttack;
  const now = useNow(1000);

  // Live auto-protection signals vs. the configured thresholds
  const liveSignals = useMemo(() => {
    const window = state.logs.filter((l) => now - l.ts <= 60_000);
    const errors = window.filter((l) => l.status >= 500).length;
    const payloadLogs = window.filter((l) => l.payload);
    return {
      fivexxPct: window.length ? (errors / window.length) * 100 : 0,
      entropyAvg: payloadLogs.length
        ? payloadLogs.reduce((s, l) => s + l.entropy, 0) / payloadLogs.length
        : 0,
    };
  }, [state.logs, now]);

  const thresholdRows = [
    {
      label: "5xx spike trigger",
      value: `${state.thresholds.fivexx}%`,
      live: `${liveSignals.fivexxPct.toFixed(1)}% now`,
      triggered: liveSignals.fivexxPct >= state.thresholds.fivexx,
      desc: "Origin error rate above this % in a 60s window escalates an incident",
    },
    {
      label: "DDoS burst trigger",
      value: `${state.thresholds.ddos} req/s`,
      live: `${currentRps} req/s now`,
      triggered: currentRps >= state.thresholds.ddos,
      desc: "Sustained ingress above this rate triggers auto-scaling + challenge mode",
    },
    {
      label: "Entropy anomaly cutoff",
      value: `${state.thresholds.entropy} bits/char`,
      live: `${liveSignals.entropyAvg.toFixed(2)} avg now`,
      triggered: liveSignals.entropyAvg >= state.thresholds.entropy,
      desc: "Payload entropy above this cutoff is flagged by the ML classifier",
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <HealthStat icon={<HeartPulse className="size-4" />} label="Overall health" value={`${overall}%`} accent={overall >= 75 ? "text-wg-emerald" : overall >= 55 ? "text-wg-amber" : "text-wg-rose"} sub={`${healthy} healthy · ${degraded} degraded`} />
        <HealthStat icon={<Activity className="size-4" />} label="Edge throughput" value={`${currentRps} rps`} accent="text-wg-cyan" sub="live ingress" />
        <HealthStat icon={<Gauge className="size-4" />} label="Ingress latency" value={`${avgLatency.toFixed(2)} ms`} accent={avgLatency < 2.5 ? "text-wg-emerald" : "text-wg-amber"} sub="edge round-trip" />
        <HealthStat icon={<Cpu className="size-4" />} label="Nodes at risk" value={`${critical}`} accent={critical > 0 ? "text-wg-rose" : "text-wg-emerald"} sub="critical load" />
      </div>

      {/* load history */}
      <div className="wg-panel p-4">
        <SectionTitle
          title="Load history"
          sub="Live stress per tier over the last 60 seconds — watch the WAF absorb attack bursts"
          right={
            <div className="flex items-center gap-3">
              {STRESS_KEYS.map((s) => (
                <span key={s.key} className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                  <span className="size-2 rounded-full" style={{ background: s.color }} />
                  {s.label}
                </span>
              ))}
            </div>
          }
        />
        <div className="h-[180px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={state.stressSeries} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
              <defs>
                {STRESS_KEYS.map((s) => (
                  <linearGradient key={s.key} id={`wg-hgrad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={s.color} stopOpacity={0.3} />
                    <stop offset="100%" stopColor={s.color} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <Area
                type="monotone"
                dataKey="waf"
                name="WAF engine"
                stroke="#22d3ee"
                strokeWidth={1.6}
                fill="url(#wg-hgrad-waf)"
                dot={false}
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="lb"
                name="Load balancer"
                stroke="#a78bfa"
                strokeWidth={1.4}
                fill="url(#wg-hgrad-lb)"
                dot={false}
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="app"
                name="Origin app"
                stroke="#fbbf24"
                strokeWidth={1.4}
                fill="url(#wg-hgrad-app)"
                dot={false}
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="db"
                name="Database"
                stroke="#34d399"
                strokeWidth={1.4}
                fill="url(#wg-hgrad-db)"
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        {state.stressSeries.length === 0 && (
          <p className="py-6 text-center text-xs text-muted-foreground">Collecting load samples…</p>
        )}
      </div>

      <div className="wg-panel p-4">
        <SectionTitle
          title="Edge node health"
          sub="Live utilization across the WebGuard edge stack — updates every telemetry tick"
          right={
            <Badge
              variant="outline"
              className={cn(
                "gap-1.5 text-[10px]",
                underLoad
                  ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose"
                  : "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
              )}
            >
              <span className={cn("size-1.5 rounded-full", underLoad ? "animate-pulse bg-rose-400" : "bg-emerald-400")} />
              {underLoad ? "UNDER ATTACK — WAF absorbing" : "NOMINAL"}
            </Badge>
          }
        />

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {nodes.map((n) => (
            <div key={n.id} className="rounded-xl border border-border/50 bg-card/40 p-4">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-wg-cyan/10 text-wg-cyan">
                    <n.icon className="size-4" />
                  </span>
                  <div className="leading-tight">
                    <p className="text-sm font-medium text-foreground">{n.label}</p>
                    <p className="text-[10px] text-muted-foreground">{n.sub}</p>
                  </div>
                </div>
                <span className={cn("flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", n.health.cls)}>
                  <span className={cn("size-1.5 rounded-full", n.health.dot, n.health.label === "CRITICAL" && "animate-pulse")} />
                  {n.health.label}
                </span>
              </div>

              <div className="mt-3">
                <div className="mb-1 flex items-center justify-between text-[10px]">
                  <span className="text-muted-foreground">Load</span>
                  <span className="font-mono font-bold" style={{ color: n.stress > 0.7 ? "#f43f5e" : n.stress > 0.45 ? "#facc15" : "#34d399" }}>
                    {Math.round(n.stress * 100)}%
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-border/50">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${Math.min(100, n.stress * 100)}%`,
                      background:
                        n.stress > 0.7
                          ? "linear-gradient(90deg,#fb923c,#f43f5e)"
                          : n.stress > 0.45
                            ? "linear-gradient(90deg,#22d3ee,#facc15)"
                            : "linear-gradient(90deg,#22d3ee,#34d399)",
                    }}
                  />
                </div>
              </div>

              <div className="mt-3 grid grid-cols-4 gap-2 text-center">
                <Metric label="rps" value={String(n.rps)} />
                <Metric label="errors" value={`${n.errRate}%`} />
                <Metric label="heap" value={`${n.heapMb} MB`} />
                <Metric label="latency" value={`${n.latencyMs} ms`} />
              </div>
            </div>
          ))}
        </div>

        <p className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <Activity className="size-3.5 text-wg-cyan" />
          Metrics are derived live from the telemetry simulator — flip the firewall or run an audit to watch load shift.
        </p>
      </div>

      {/* auto-protection thresholds */}
      <div className="wg-panel p-4">
        <SectionTitle
          title="Auto-protection thresholds"
          sub="Signals that trigger edge automation — measured live against the Policy Engine settings"
          right={
            <Badge variant="outline" className="gap-1.5 border-border/50 text-[10px] text-muted-foreground">
              <Activity className="size-3 text-wg-cyan" /> 60s sliding window
            </Badge>
          }
        />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {thresholdRows.map((t) => (
            <div
              key={t.label}
              className={cn(
                "rounded-xl border p-3.5",
                t.triggered ? "border-wg-rose/40 bg-wg-rose/[0.06]" : "border-border/40 bg-muted/20",
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">{t.label}</p>
                <span
                  className={cn(
                    "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                    t.triggered
                      ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose"
                      : "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
                  )}
                >
                  {t.triggered && <AlertTriangle className="size-2.5" />}
                  {t.triggered ? "TRIGGERED" : "CLEAR"}
                </span>
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="font-mono text-lg font-bold text-foreground">{t.value}</span>
                <span className="font-mono text-[11px] text-muted-foreground">{t.live}</span>
              </div>
              <p className="mt-1.5 text-[10px] leading-relaxed text-muted-foreground">{t.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* infra strip */}
      <div className="wg-panel flex flex-wrap items-center gap-x-6 gap-y-2 p-4 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Globe2 className="size-3.5 text-wg-cyan" /> 12 edge regions · anycast
        </span>
        <span className="flex items-center gap-1.5">
          <HeartPulse className="size-3.5 text-wg-emerald" /> Uptime 99.98% (30d)
        </span>
        <span className="flex items-center gap-1.5">
          <ShieldCheck className="size-3.5 text-wg-emerald" /> Engine v2.1.0 · CRS 4.0
        </span>
        <span className="flex items-center gap-1.5">
          <Activity className="size-3.5 text-wg-cyan" /> Health checks every 5s
        </span>
        <span className="flex items-center gap-1.5">
          <Server className="size-3.5 text-wg-cyan" /> Origin: shop.example.com (us-east-1)
        </span>
      </div>
    </div>
  );
}

function HealthStat({
  icon,
  label,
  value,
  accent,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  accent: string;
  sub: string;
}) {
  return (
    <div className="wg-panel flex items-start justify-between gap-3 p-4">
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <div className={cn("mt-1.5 text-2xl font-semibold tracking-tight", accent)}>{value}</div>
        <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
      </div>
      <div className={cn("shrink-0 rounded-lg border border-border/60 bg-background/60 p-2", accent)}>{icon}</div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border/40 bg-muted/30 px-1 py-1.5">
      <p className="font-mono text-[11px] font-semibold text-foreground/90">{value}</p>
      <p className="text-[9px] uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  );
}
