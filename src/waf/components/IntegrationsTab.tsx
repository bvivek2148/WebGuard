import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import type { IntegrationId } from "../types";
import { SectionTitle, flagEmoji, timeAgo } from "./shared";
import {
  BellRing,
  CheckCircle2,
  Code2,
  Copy,
  Globe2,
  Mail,
  Play,
  Send,
  ShieldAlert,
  ShieldCheck,
  Slack,
  Webhook,
  Workflow,
  Zap,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

type EventKind = "alarm" | "incident" | "finding" | "digest";

const EVENT_KINDS: { id: EventKind; label: string; icon: LucideIcon; cls: string }[] = [
  { id: "alarm", label: "Alarms", icon: BellRing, cls: "text-wg-rose" },
  { id: "incident", label: "Incidents", icon: ShieldAlert, cls: "text-wg-amber" },
  { id: "finding", label: "Findings", icon: Zap, cls: "text-wg-sky" },
  { id: "digest", label: "Digests", icon: Send, cls: "text-wg-emerald" },
];

const DEFAULT_ROUTES: Record<IntegrationId, EventKind[]> = {
  slack: ["alarm", "incident", "finding", "digest"],
  pagerduty: ["alarm", "incident"],
  email: ["finding", "digest"],
  webhook: ["alarm", "incident", "finding", "digest"],
};

const CHANNEL_LATENCY: Record<IntegrationId, number> = {
  slack: 340,
  pagerduty: 890,
  email: 2100,
  webhook: 120,
};

const CHANNEL_ICONS: Record<IntegrationId, typeof Slack> = {
  slack: Slack,
  pagerduty: BellRing,
  email: Mail,
  webhook: Webhook,
};

const CHANNEL_ACCENT: Record<IntegrationId, string> = {
  slack: "text-wg-violet",
  pagerduty: "text-wg-rose",
  email: "text-wg-sky",
  webhook: "text-wg-emerald",
};

export function IntegrationsTab() {
  const { state, dispatch } = useWaf();
  const [routes, setRoutes] = useState<Record<IntegrationId, EventKind[]>>(DEFAULT_ROUTES);
  const [previewKind, setPreviewKind] = useState<EventKind>("alarm");

  const stats = useMemo(() => {
    const enabled = state.integrations.filter((i) => i.enabled).length;
    const last = state.dispatchLog[0] ?? null;
    return { enabled, total: state.integrations.length, last, logLen: state.dispatchLog.length };
  }, [state.integrations, state.dispatchLog]);

  const channelStats = useMemo(() => {
    const map = new Map<IntegrationId, { sent: number; ok: number }>();
    for (const d of state.dispatchLog) {
      const c = map.get(d.channel) ?? { sent: 0, ok: 0 };
      c.sent += 1;
      if (d.ok) c.ok += 1;
      map.set(d.channel, c);
    }
    return map;
  }, [state.dispatchLog]);

  const toggleRoute = (id: IntegrationId, kind: EventKind) =>
    setRoutes((prev) => {
      const cur = prev[id];
      const next = cur.includes(kind) ? cur.filter((k) => k !== kind) : [...cur, kind];
      return { ...prev, [id]: next };
    });

  const testChannel = (id: IntegrationId, label: string) => {
    const channel = state.integrations.find((i) => i.id === id);
    if (!channel) return;
    if (!channel.enabled) {
      dispatch({ type: "TOGGLE_INTEGRATION", id });
    }
    dispatch({
      type: "DISPATCH",
      channel: id,
      event: `Test event from WebGuard — ${label} channel reachable`,
    });
  };

  const dispatchDigest = () => {
    const open = state.findings.filter((f) => f.status === "open").length;
    const alarms = state.alarms.filter((a) => a.state === "active").length;
    const incidents = state.incidents.filter((i) => i.stage === "investigating").length;
    const targets = state.integrations.filter((i) => i.enabled && routes[i.id].includes("digest"));
    if (targets.length === 0) {
      toast.error("No enabled channel routes digests — check the routing matrix");
      return;
    }
    targets.forEach((ch) =>
      dispatch({
        type: "DISPATCH",
        channel: ch.id,
        event:
          ch.id === "slack"
            ? `Digest — ${alarms} active alarms · ${incidents} incidents · ${open} open findings`
            : `POST /wg-events — posture snapshot (${open} open findings, blocklist ${state.blocklist.filter((b) => b.active).length} active)`,
      }),
    );
    toast.success(`Digest dispatched to ${targets.length} channel${targets.length > 1 ? "s" : ""}`);
  };

  const dispatchScenario = (event: string, kind: EventKind) => {
    const routed = state.integrations.filter((i) => i.enabled && routes[i.id].includes(kind));
    if (routed.length === 0) {
      toast.error("No enabled channel routes this event type — check the routing matrix");
      return;
    }
    routed.forEach((ch) => dispatch({ type: "DISPATCH", channel: ch.id, event: `${event} → ${ch.label}` }));
    toast.success(`Dispatched to ${routed.length} channel${routed.length > 1 ? "s" : ""}`);
  };

  const buildPayload = (kind: EventKind) => {
    const ts = new Date().toISOString();
    const open = state.findings.filter((f) => f.status === "open").length;
    const activeAlarms = state.alarms.filter((a) => a.state === "active").length;
    const incidents = state.incidents.filter((i) => i.stage === "investigating").length;
    switch (kind) {
      case "alarm":
        return {
          event: "alert.triggered",
          id: "AL-9f3k2",
          severity: "critical",
          title: "SQL Injection — /api/search",
          rule: "OWASP-CRIT-942100",
          source: { ip: "91.134.22.7", country: "DE" },
          blocked: state.mode === "blocking",
          ts,
        };
      case "incident":
        return {
          event: "incident.opened",
          id: "INC-4a1c",
          title: "SQL Injection burst from 91.134.22.7",
          vector: "SQL Injection",
          severity: "critical",
          sourceIp: "91.134.22.7",
          stage: "investigating",
          ts,
        };
      case "finding":
        return {
          event: "finding.created",
          id: "FN-7712",
          title: "Path Traversal against /api/download",
          severity: "high",
          source: "live",
          path: "/api/download",
          patch: "Reject ../ sequences at the edge",
          ts,
        };
      case "digest":
        return {
          event: "posture.digest",
          openFindings: open,
          activeAlarms,
          incidents,
          blocklist: state.blocklist.filter((b) => b.active).length,
          mode: state.mode,
          rateLimitRpm: state.settings.rateLimitRpm,
          ts,
        };
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <IntegStat icon={<Webhook className="size-4" />} label="Channels configured" value={stats.total} accent="text-wg-cyan" sub="slack · pagerduty · email · webhook" />
        <IntegStat icon={<CheckCircle2 className="size-4" />} label="Channels enabled" value={stats.enabled} accent="text-wg-emerald" sub="receiving events" />
        <IntegStat icon={<Send className="size-4" />} label="Events dispatched" value={stats.logLen} accent="text-wg-amber" sub="this session" />
        <IntegStat
          icon={<Zap className="size-4" />}
          label="Last dispatch"
          value={stats.last ? timeAgo(stats.last.ts).replace(" ago", "") : "—"}
          accent="text-wg-rose"
          sub={stats.last ? stats.last.event.slice(0, 34) + "…" : "no events yet"}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        {/* channel cards */}
        <div className="flex flex-col gap-4 xl:col-span-3">
          <div className="wg-panel p-4">
            <SectionTitle
              title="Alert integrations"
              sub="Forward alarms, incidents, and findings to the tools your team already lives in. Events are dispatched directly to the configured endpoint."
              right={
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-[11px] text-wg-cyan hover:bg-wg-cyan/20"
                  onClick={dispatchDigest}
                >
                  <Send className="size-3.5" /> Dispatch status digest
                </Button>
              }
            />

            <div className="flex flex-col gap-3">
              {state.integrations.map((ch) => {
                const Icon = CHANNEL_ICONS[ch.id];
                const accent = CHANNEL_ACCENT[ch.id];
                return (
                  <div
                    key={ch.id}
                    className={cn(
                      "rounded-xl border p-3.5 transition-colors",
                      ch.enabled ? "border-border/60 bg-card/50" : "border-border/30 bg-card/25 opacity-80",
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-3">
                      <span className={cn("flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted/60", accent)}>
                        <Icon className="size-4" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-medium text-foreground">{ch.label}</p>
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[9px]",
                              ch.enabled
                                ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                                : "border-border/50 text-muted-foreground",
                            )}
                          >
                            {ch.enabled ? "ENABLED" : "DISABLED"}
                          </Badge>
                        </div>
                        <p className="text-[11px] text-muted-foreground">{ch.hint}</p>
                        {(channelStats.get(ch.id)?.sent ?? 0) > 0 && (
                          <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                            {channelStats.get(ch.id)?.sent ?? 0} events · {channelStats.get(ch.id)?.ok ?? 0} ok · ~{CHANNEL_LATENCY[ch.id]} ms avg delivery
                          </p>
                        )}
                      </div>
                      <Switch
                        checked={ch.enabled}
                        onCheckedChange={() => dispatch({ type: "TOGGLE_INTEGRATION", id: ch.id })}
                        className={ch.enabled ? "data-[state=checked]:bg-wg-emerald" : ""}
                      />
                    </div>

                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <div className="relative min-w-0 flex-1">
                        <Globe2 className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                        <Input
                          value={ch.target}
                          onChange={(e) => dispatch({ type: "SET_INTEGRATION_TARGET", id: ch.id, target: e.target.value })}
                          placeholder={ch.placeholder}
                          className="h-8 border-border/60 bg-muted/50 pl-8 font-mono text-xs focus-visible:ring-cyan-400/40"
                          spellCheck={false}
                        />
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-[11px] text-wg-cyan hover:bg-wg-cyan/20"
                        onClick={() => testChannel(ch.id, ch.label)}
                      >
                        <Send className="size-3.5" /> Send test
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* routing matrix */}
            <div className="mt-4 rounded-xl border border-border/40 bg-muted/20 p-3">
              <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                <Workflow className="size-3.5 text-wg-cyan" /> Event routing matrix — which channels receive which events
              </p>
              <div className="mt-2 flex flex-col gap-2">
                {state.integrations.map((ch) => {
                  const Icon = CHANNEL_ICONS[ch.id];
                  return (
                    <div key={ch.id} className="flex items-center gap-2.5 rounded-lg border border-border/30 bg-card/40 px-3 py-2">
                      <span className={cn("flex size-6 shrink-0 items-center justify-center rounded-md bg-muted/60", CHANNEL_ACCENT[ch.id])}>
                        <Icon className="size-3" />
                      </span>
                      <span className="w-20 shrink-0 truncate text-[11px] font-medium text-foreground/80">{ch.label}</span>
                      <div className="flex flex-1 flex-wrap gap-1.5">
                        {EVENT_KINDS.map((k) => {
                          const on = routes[ch.id].includes(k.id);
                          return (
                            <button
                              key={k.id}
                              type="button"
                              onClick={() => toggleRoute(ch.id, k.id)}
                              className={cn(
                                "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider transition-colors",
                                on ? cn("border-border/50 bg-background/70", k.cls) : "border-border/25 bg-transparent text-muted-foreground/50 hover:text-muted-foreground",
                              )}
                            >
                              <k.icon className="size-2.5" /> {k.label.toUpperCase()}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* scenario dispatch */}
            <div className="mt-4 flex flex-col gap-2 rounded-xl border border-border/40 bg-muted/20 p-3">
              <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                Dispatch scenarios — to every enabled, routed channel
              </p>
              <div className="flex flex-wrap gap-1.5">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-wg-rose/30 text-[11px] text-wg-rose hover:bg-wg-rose/10"
                  onClick={() => dispatchScenario("Critical alarm — SQLi burst on /api/search", "alarm")}
                >
                  <Play className="size-3" /> Critical alarm
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-wg-amber/30 text-[11px] text-wg-amber hover:bg-wg-amber/10"
                  onClick={() => dispatchScenario("Incident auto-opened — Credential stuffing campaign", "incident")}
                >
                  <Play className="size-3" /> Incident opened
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-wg-sky/30 text-[11px] text-wg-sky hover:bg-wg-sky/10"
                  onClick={() => dispatchScenario("New finding — Path Traversal against /api/download", "finding")}
                >
                  <Play className="size-3" /> New finding
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-wg-emerald/30 text-[11px] text-wg-emerald hover:bg-wg-emerald/10"
                  onClick={() => dispatchScenario("IP auto-banned — 185.220.101.0/24 (6+ blocked)", "alarm")}
                >
                  <Play className="size-3" /> Auto-ban
                </Button>
              </div>
            </div>

            {/* webhook payload builder */}
            <div className="mt-3 overflow-hidden rounded-xl border border-border/40 bg-muted/20">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/30 px-3 py-1.5">
                <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-wg-cyan">
                  <Code2 className="size-3.5" /> Webhook payload — builder
                </p>
                <span className="font-mono text-[9px] text-muted-foreground">POST /wg-events</span>
              </div>
              <div className="flex flex-wrap gap-1.5 border-b border-border/30 px-3 py-2">
                {EVENT_KINDS.map((k) => (
                  <button
                    key={k.id}
                    type="button"
                    onClick={() => setPreviewKind(k.id)}
                    className={cn(
                      "flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider transition-colors",
                      previewKind === k.id ? cn("border-border/60 bg-background/80", k.cls) : "border-border/25 text-muted-foreground/60 hover:text-muted-foreground",
                    )}
                  >
                    <k.icon className="size-2.5" /> {k.label}
                  </button>
                ))}
                <Button
                  variant="ghost"
                  size="sm"
                  className="ml-auto h-6 gap-1 px-1.5 text-[10px] text-muted-foreground hover:text-wg-cyan"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(JSON.stringify(buildPayload(previewKind), null, 2));
                      toast.success("Payload copied to clipboard");
                    } catch {
                      toast.error("Clipboard unavailable");
                    }
                  }}
                >
                  <Copy className="size-3" /> Copy
                </Button>
              </div>
              <pre className="overflow-auto px-3 py-2.5 font-mono text-[10px] leading-relaxed text-wg-emerald/90">
                {JSON.stringify(buildPayload(previewKind), null, 2)}
              </pre>
            </div>

            <p className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <ShieldCheck className="size-3.5 text-wg-emerald" />
              Webhook payloads are formatted for direct production consumption and incident management.
            </p>
          </div>
        </div>

        {/* dispatch log */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          <div className="wg-panel p-4">
            <SectionTitle
              title="Dispatch log"
              sub="Recent events sent to connected channels"
              right={
                <Badge variant="outline" className="gap-1.5 border-border/50 text-[10px] text-muted-foreground">
                  <Zap className="size-3" /> {stats.logLen} events
                </Badge>
              }
            />
            <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              {state.integrations.map((ch) => {
                const st = channelStats.get(ch.id) ?? { sent: 0, ok: 0 };
                const max = Math.max(1, ...[...channelStats.values()].map((v) => v.sent));
                return (
                  <div key={ch.id} className="rounded-lg border border-border/30 bg-muted/20 p-2">
                    <p className="truncate text-[9px] font-bold uppercase tracking-wider text-muted-foreground/70">{ch.label}</p>
                    <div className="mt-1 flex items-baseline gap-1">
                      <span className="text-sm font-semibold text-foreground">{st.sent}</span>
                      <span className="text-[9px] text-muted-foreground">sent</span>
                    </div>
                    <div className="mt-1 h-1 overflow-hidden rounded-full bg-border/40">
                      <div
                        className={cn("h-full rounded-full", CHANNEL_ACCENT[ch.id].replace("text-", "bg-"))}
                        style={{ width: `${(st.sent / max) * 100}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex flex-col">
              {state.dispatchLog.map((d) => {
                const Icon = CHANNEL_ICONS[d.channel];
                return (
                  <div key={d.id} className="flex items-start gap-2.5 border-b border-border/30 py-2.5 last:border-0">
                    <span className={cn("mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md bg-muted/60", CHANNEL_ACCENT[d.channel])}>
                      <Icon className="size-3" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs text-foreground/90">{d.event}</p>
                      <p className="mt-0.5 flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
                        {d.channel} · {timeAgo(d.ts)}
                        {d.ok && <CheckCircle2 className="size-3 text-wg-emerald" />}
                      </p>
                    </div>
                  </div>
                );
              })}
              {state.dispatchLog.length === 0 && (
                <p className="py-10 text-center text-xs text-muted-foreground">
                  Nothing dispatched yet — press “Send test” on a channel.
                </p>
              )}
            </div>
          </div>

          <div className="wg-panel flex flex-col gap-3 p-4">
            <p className="wg-kicker">What gets forwarded</p>
            {[
              { label: "Critical & high alarms", detail: "immediately, to enabled channels" },
              { label: "Incident auto-open", detail: "when the engine opens a new incident" },
              { label: "New live findings", detail: "when a novel attack class is observed" },
              { label: "Posture digest", detail: "on demand via the digest button" },
            ].map((r) => (
              <div key={r.label} className="flex items-center gap-2.5">
                <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-wg-cyan/10 text-wg-cyan">
                  <BellRing className="size-3" />
                </span>
                <div className="leading-tight">
                  <p className="text-xs font-medium text-foreground">{r.label}</p>
                  <p className="text-[10px] text-muted-foreground">{r.detail}</p>
                </div>
              </div>
            ))}
            <p className="mt-1 flex items-center gap-1.5 border-t border-border/40 pt-2.5 text-[10px] text-muted-foreground">
              {flagEmoji("US")} Region: us-east-1 · retries: 3 · backoff: exponential
            </p>
          </div>

          {/* status strip */}
          <div className="wg-panel p-4">
            <p className="wg-kicker mb-2">Channel status</p>
            <div className="flex flex-col gap-1.5">
              {state.integrations.map((ch) => (
                <div key={ch.id} className="flex items-center gap-2 text-xs">
                  <span className={cn("size-1.5 rounded-full", ch.enabled ? "animate-pulse bg-emerald-400" : "bg-muted-foreground/40")} />
                  <span className="flex-1 text-foreground/80">{ch.label}</span>
                  <span className={cn("font-mono text-[10px]", ch.enabled ? "text-wg-emerald" : "text-muted-foreground")}>
                    {ch.enabled ? "OPERATIONAL" : "PAUSED"}
                  </span>
                </div>
              ))}
            </div>
            <p className="mt-2.5 border-t border-border/40 pt-2 text-[10px] text-muted-foreground">
              Timeout 5s · max payload 512 KB · HMAC-SHA256 signature on delivery
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function IntegStat({
  icon,
  label,
  value,
  accent,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  accent: string;
  sub: string;
}) {
  return (
    <div className="wg-panel flex items-start justify-between gap-3 p-4">
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <div className="mt-1.5 text-2xl font-semibold tracking-tight text-foreground">{value}</div>
        <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
      </div>
      <div className={cn("shrink-0 rounded-lg border border-border/60 bg-background/60 p-2", accent)}>{icon}</div>
    </div>
  );
}
