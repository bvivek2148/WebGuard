import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { PLAYBOOKS, SEVERITY_ORDER } from "../data";
import { copilotContextFromIncident, randInt, uid, useWaf } from "../engine";
import type { Incident, IncidentStage, PlaybookId, Severity } from "../types";
import { SEVERITY_META } from "../types";
import { flagEmoji, SectionTitle, SeverityBadge, timeAgo, useNow } from "./shared";
import { CheckCircle2, ChevronDown, Lock, Play, Plus, ShieldBan, Siren, Sparkles, TimerReset, Workflow } from "lucide-react";

const VECTORS: { vector: string; severity: Severity; path: string; detail: string }[] = [
  { vector: "SQL Injection", severity: "critical", path: "/api/search", detail: "Tautology probes detected against the search endpoint; all attempts blocked at the edge." },
  { vector: "Cross-Site Scripting", severity: "high", path: "/search", detail: "Script-bearing query reflections observed; the edge encoding patch is active." },
  { vector: "Command Injection", severity: "critical", path: "/api/ping", detail: "Shell-metacharacter chaining attempted on the diagnostics endpoint." },
  { vector: "Path Traversal", severity: "high", path: "/api/download", detail: "Dot-dot-slash sweep against the download endpoint; rule 930120 engaged." },
  { vector: "Bad Bot", severity: "medium", path: "/api/login", detail: "Credential-stuffing pattern at elevated velocity; throttling applied." },
  { vector: "Recon Scanner", severity: "low", path: "/.env", detail: "Sensitive-path probing from rotating addresses; responses cloaked." },
];

const STAGE_FILTERS: Array<IncidentStage | "all"> = ["all", "investigating", "mitigated", "resolved"];

const STAGE_META: Record<IncidentStage, { label: string; cls: string }> = {
  investigating: { label: "INVESTIGATING", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" },
  mitigated: { label: "MITIGATED", cls: "border-sky-400/40 bg-sky-500/10 text-wg-sky" },
  resolved: { label: "RESOLVED", cls: "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" },
};

const PLAYBOOK_ICONS: Record<PlaybookId, typeof ShieldBan> = {
  quarantine: ShieldBan,
  throttle: TimerReset,
  lockdown: Lock,
};

export function IncidentsTab() {
  const now = useNow(1000);
  const { state, dispatch } = useWaf();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [stageFilter, setStageFilter] = useState<IncidentStage | "all">("all");

  const investigating = state.incidents.filter((i) => i.stage === "investigating").length;
  const mitigated = state.incidents.filter((i) => i.stage === "mitigated").length;
  const resolved = state.incidents.filter((i) => i.stage === "resolved").length;
  const playbooksRun = state.incidents.filter((i) => i.playbook).length;

  const recent = state.incidents.filter((i) => now - i.openedAt <= 600_000);

  const playbookUse = useMemo(() => {
    const c = { quarantine: 0, throttle: 0, lockdown: 0 } as Record<PlaybookId, number>;
    for (const i of state.incidents) if (i.playbook) c[i.playbook] += 1;
    const total = Math.max(1, state.incidents.filter((i) => i.playbook).length);
    return PLAYBOOKS.map((p) => ({ ...p, n: c[p.id], pct: (c[p.id] / total) * 100 }));
  }, [state.incidents]);

  // MTTR across closed incidents (minutes)
  const mttrMin = useMemo(() => {
    const closed = state.incidents.filter((i) => i.stage === "resolved" && i.closedAt != null);
    if (closed.length === 0) return null;
    const total = closed.reduce((s, i) => s + (i.closedAt! - i.openedAt), 0);
    return total / closed.length / 60_000;
  }, [state.incidents]);

  // Repeat offenders — source IPs behind multiple incidents
  const { incidents: allIncidents, blocklist } = state;
  const repeatOffenders = useMemo(() => {
    const byIp = new Map<string, typeof allIncidents>();
    for (const i of allIncidents) {
      const arr = byIp.get(i.sourceIp) ?? [];
      arr.push(i);
      byIp.set(i.sourceIp, arr);
    }
    return [...byIp.entries()]
      .map(([ip, incs]) => ({
        ip,
        incs,
        count: incs.length,
        open: incs.filter((i) => i.stage !== "resolved").length,
        lastAt: Math.max(...incs.map((i) => i.openedAt)),
        topSeverity: incs.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))[0].severity,
        country: incs[0].country,
        blocked: blocklist.some((b) => b.ip === ip && b.active),
      }))
      .filter((r) => r.count > 1 || r.open > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [allIncidents, blocklist]);

  const simulateIncident = () => {
    const v = VECTORS[Math.floor(Math.random() * VECTORS.length)];
    const ip = `${185}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
    dispatch({
      type: "ADD_INCIDENT",
      incident: {
        id: uid("INC"),
        title: `${v.vector} against ${v.path}`,
        vector: v.vector,
        severity: v.severity,
        sourceIp: ip,
        country: "DE",
        stage: "investigating",
        openedAt: Date.now(),
        closedAt: null,
        detail: v.detail,
        playbook: null,
      },
    });
  };

  const sorted = [...state.incidents]
    .filter((i) => stageFilter === "all" || i.stage === stageFilter)
    .sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );

  return (
    <div className="flex flex-col gap-4">
      {/* response stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <IncidentStat icon={<Siren className="size-4" />} label="Investigating" value={investigating} accent="text-wg-amber" sub="needs a playbook" />
        <IncidentStat icon={<Workflow className="size-4" />} label="Mitigated" value={mitigated} accent="text-wg-sky" sub="contained at the edge" />
        <IncidentStat icon={<CheckCircle2 className="size-4" />} label="Resolved" value={resolved} accent="text-wg-emerald" sub="closed out" />
        <IncidentStat icon={<Play className="size-4" />} label="Playbooks run" value={playbooksRun} accent="text-wg-cyan" sub="automated response" />
      </div>

      {/* response intelligence — MTTR + repeat offenders */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <div className="wg-panel p-4 xl:col-span-2">
          <SectionTitle
            title="Containment & MTTR"
            sub="Mean time to resolve — measured from open to closed"
            right={
              <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
                {state.incidents.filter((i) => i.closedAt != null).length} closed
              </Badge>
            }
          />
          <div className="flex items-end gap-2">
            <span className="font-mono text-4xl font-semibold tracking-tight text-wg-emerald">
              {mttrMin != null ? mttrMin.toFixed(1) : "—"}
            </span>
            <span className="pb-1 text-xs font-medium text-muted-foreground">min avg</span>
          </div>
          <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
            {mttrMin != null
              ? `Average ${mttrMin.toFixed(1)} minutes from first detection to closed. Playbook-automated incidents resolve fastest — run lockdown or quarantine on the next open case to compare.`
              : "Resolve an incident to start measuring mean time to resolution."}
          </p>
          <div className="mt-3 flex flex-col gap-1.5">
            {[
              { label: "Playbook-driven", n: state.incidents.filter((i) => i.playbook && i.closedAt != null).length },
              { label: "Manual close", n: state.incidents.filter((i) => !i.playbook && i.closedAt != null).length },
            ].map((row) => (
              <div key={row.label} className="flex items-center gap-2 text-[11px]">
                <span className="w-32 shrink-0 text-muted-foreground">{row.label}</span>
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-border/40">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-wg-cyan to-wg-emerald"
                    style={{ width: `${(row.n / Math.max(1, state.incidents.filter((i) => i.closedAt != null).length)) * 100}%` }}
                  />
                </div>
                <span className="w-5 text-right font-mono text-muted-foreground">{row.n}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="wg-panel p-4 xl:col-span-3">
          <SectionTitle
            title="Repeat offenders"
            sub="Source IPs behind multiple incidents — one click bans them at the edge"
            right={
              <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
                {repeatOffenders.length} tracked
              </Badge>
            }
          />
          <div className="flex flex-col">
            {repeatOffenders.map((r) => {
              const meta = SEVERITY_META[r.topSeverity];
              return (
                <div key={r.ip} className="flex items-center gap-3 border-b border-border/30 py-2 last:border-0">
                  <span className="text-sm leading-none">{flagEmoji(r.country)}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-mono text-[11px] font-medium text-foreground">{r.ip}</span>
                      <span className="rounded border px-1 py-0.5 text-[9px] font-bold" style={{ color: meta.color, borderColor: `${meta.color}40`, background: `${meta.color}12` }}>
                        {r.count} INCIDENT{r.count > 1 ? "S" : ""}
                      </span>
                      {r.open > 0 && (
                        <span className="rounded border border-wg-amber/40 bg-wg-amber/10 px-1 py-0.5 text-[9px] font-bold text-wg-amber">
                          {r.open} OPEN
                        </span>
                      )}
                      {r.blocked && (
                        <span className="rounded border border-wg-rose/40 bg-wg-rose/10 px-1 py-0.5 text-[9px] font-bold text-wg-rose">BANNED</span>
                      )}
                    </div>
                    <p className="mt-0.5 truncate text-[10px] text-muted-foreground">
                      last seen {timeAgo(r.lastAt)} · {r.incs.map((i) => i.vector).filter((v, idx, arr) => arr.indexOf(v) === idx).slice(0, 2).join(", ")}
                    </p>
                  </div>
                  {!r.blocked && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 shrink-0 gap-1.5 border-wg-rose/40 text-[11px] text-wg-rose hover:bg-wg-rose/10"
                      onClick={() =>
                        dispatch({
                          type: "ADD_BLOCKED_IP",
                          entry: {
                            id: uid("BAN"),
                            ip: r.ip,
                            reason: `Repeat offender — ${r.count} incidents`,
                            source: "manual",
                            country: r.country,
                            countryCode: r.country,
                            addedAt: Date.now(),
                            hits: 0,
                            active: true,
                            expiresAt: null,
                          },
                        })
                      }
                    >
                      <ShieldBan className="size-3.5" /> Ban
                    </Button>
                  )}
                </div>
              );
            })}
            {repeatOffenders.length === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">No repeat sources — every offender is a first-timer or already banned.</p>
            )}
          </div>
        </div>
      </div>

      {/* playbook usage */}
      {playbookUse.some((p) => p.n > 0) && (
        <div className="wg-panel p-4">
          <SectionTitle title="Playbook usage" sub="Which automated responses have fired across incidents" />
          <div className="flex flex-col gap-2">
            {playbookUse.map((p) => {
              const Icon = PLAYBOOK_ICONS[p.id];
              return (
                <div key={p.id} className="flex items-center gap-3">
                  <Icon className="size-4 shrink-0 text-wg-cyan" />
                  <span className="w-44 shrink-0 truncate text-xs text-foreground/80">{p.name}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                    <div className="h-full rounded-full bg-gradient-to-r from-wg-cyan to-wg-emerald" style={{ width: `${p.pct}%` }} />
                  </div>
                  <span className="w-6 text-right font-mono text-[11px] text-muted-foreground">{p.n}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="wg-panel p-4">
        <SectionTitle
          title="Incident response"
          sub={`${state.incidents.length} open & historical incidents · run automated playbooks or hand off to the AI copilot`}
          right={
            <div className="flex flex-wrap items-center gap-1.5">
              {STAGE_FILTERS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setStageFilter(s)}
                  className={cn(
                    "rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition-colors",
                    stageFilter === s
                      ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                      : "border-border/50 text-muted-foreground hover:text-foreground/80",
                  )}
                >
                  {s}
                  {s !== "all" && (
                    <span className="ml-1 font-mono text-[10px] opacity-70">
                      {s === "investigating" ? investigating : s === "mitigated" ? mitigated : resolved}
                    </span>
                  )}
                </button>
              ))}
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1.5 border-wg-rose/30 text-[11px] text-wg-rose hover:bg-wg-rose/10"
                onClick={simulateIncident}
              >
                <Plus className="size-3.5" /> Simulate incident
              </Button>
            </div>
          }
        />

        {/* live feed — incidents auto-opened recently */}
        {recent.length > 0 && (
          <div className="mb-3 flex flex-col gap-1.5 rounded-xl border border-wg-rose/20 bg-wg-rose/[0.05] p-2.5">
            <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-wg-rose">
              <span className="relative flex size-1.5">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
                <span className="relative inline-flex size-1.5 rounded-full bg-rose-400" />
              </span>
              Live feed — {recent.length} auto-opened in the last 10 min
            </p>
            {recent.slice(0, 3).map((i) => (
              <motion.div
                key={i.id}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                className="flex items-center gap-2.5 rounded-lg border border-border/40 bg-card/60 px-2.5 py-1.5"
              >
                <span className="size-1.5 shrink-0 rounded-full bg-wg-rose" />
                <span className="min-w-0 flex-1 truncate text-xs text-foreground/90">{i.title}</span>
                <span className="hidden font-mono text-[10px] text-muted-foreground sm:inline">{i.sourceIp}</span>
                <Badge variant="outline" className="border-wg-rose/40 bg-wg-rose/10 text-[9px] text-wg-rose">
                  AUTO-OPENED
                </Badge>
                <span className="font-mono text-[10px] text-muted-foreground">{timeAgo(i.openedAt)}</span>
              </motion.div>
            ))}
          </div>
        )}
        <div className="flex flex-col gap-2.5">
          {sorted.map((inc) => (
            <motion.div
              key={inc.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
            >
              <IncidentCard
                incident={inc}
                expanded={expanded === inc.id}
                onToggle={() => setExpanded((e) => (e === inc.id ? null : inc.id))}
              />
            </motion.div>
          ))}
          {sorted.length === 0 && (
            <p className="py-14 text-center text-xs text-muted-foreground">No incidents — all quiet on the wire.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function IncidentStat({
  icon,
  label,
  value,
  accent,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
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

function IncidentCard({
  incident,
  expanded,
  onToggle,
}: {
  incident: Incident;
  expanded: boolean;
  onToggle: () => void;
}) {
  const { state, dispatch } = useWaf();
  const meta = SEVERITY_META[incident.severity];
  const stage = STAGE_META[incident.stage];
  const alreadyBlocked = state.blocklist.some((b) => b.ip === incident.sourceIp && b.active);

  const runPlaybook = (pb: PlaybookId) => {
    dispatch({ type: "RUN_PLAYBOOK", id: incident.id, playbook: pb });
  };

  return (
    <div className="rounded-xl border border-border/50 bg-card/50 p-3.5">
      <div className="flex flex-wrap items-start gap-3">
        <span
          className="flex size-9 shrink-0 items-center justify-center rounded-lg"
          style={{ background: `${meta.color}14` }}
        >
          <ShieldBan className="size-4" style={{ color: meta.color }} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm font-medium text-foreground">{incident.title}</p>
            <SeverityBadge severity={incident.severity} />
            <span className={cn("rounded-md border px-1.5 py-0.5 text-[10px] font-bold tracking-wider", stage.cls)}>
              {stage.label}
            </span>
            {incident.playbook && (
              <Badge variant="outline" className="gap-1 border-wg-emerald/40 bg-wg-emerald/10 text-[10px] text-wg-emerald">
                <Play className="size-3" /> {PLAYBOOKS.find((p) => p.id === incident.playbook)?.name}
              </Badge>
            )}
          </div>
          <p className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="text-sm leading-none">{flagEmoji(incident.country)}</span> {incident.sourceIp}
            </span>
            <span>vector: {incident.vector}</span>
            <span>opened {timeAgo(incident.openedAt)}</span>
          </p>
        </div>
        <Button variant="ghost" size="icon-sm" onClick={onToggle} className="text-muted-foreground">
          <ChevronDown className={cn("size-4 transition-transform", expanded && "rotate-180")} />
        </Button>
      </div>

      {expanded && (
        <div className="mt-3 flex flex-col gap-3 border-t border-border/40 pt-3">
          {/* response timeline */}
          <div className="flex flex-col gap-1.5 rounded-xl border border-border/40 bg-muted/30 p-3">
            {[
              { label: "Opened", detail: `detected on ${incident.sourceIp} · ${incident.vector}`, icon: Siren, tone: "text-wg-amber" },
              incident.playbook
                ? { label: `Playbook · ${PLAYBOOKS.find((p) => p.id === incident.playbook)?.name}`, detail: PLAYBOOKS.find((p) => p.id === incident.playbook)?.description ?? "", icon: Play, tone: "text-wg-cyan" }
                : incident.stage === "investigating"
                  ? { label: "Awaiting response", detail: "no playbook applied yet — recommend one below", icon: TimerReset, tone: "text-muted-foreground" }
                  : { label: "Contained manually", detail: "stage progressed without a playbook", icon: CheckCircle2, tone: "text-wg-sky" },
              incident.stage === "resolved"
                ? { label: "Resolved", detail: "incident closed out", icon: CheckCircle2, tone: "text-wg-emerald" }
                : incident.stage === "mitigated"
                  ? { label: "Mitigated", detail: "contained at the edge — awaiting resolution", icon: ShieldBan, tone: "text-wg-sky" }
                  : { label: "Investigating", detail: "open — severity triage in progress", icon: Siren, tone: "text-wg-rose" },
            ].map((s, i, arr) => (
              <div key={s.label} className="flex items-start gap-2.5">
                <div className="flex flex-col items-center">
                  <span className={cn("flex size-5 shrink-0 items-center justify-center rounded-full border bg-card", s.tone)}>
                    <s.icon className="size-2.5" />
                  </span>
                  {i < arr.length - 1 && <span className="mt-0.5 h-3 w-px bg-border/60" />}
                </div>
                <div className="pb-1.5 leading-tight">
                  <p className={cn("text-[11px] font-semibold", s.tone === "text-muted-foreground" ? "text-foreground/70" : s.tone)}>{s.label}</p>
                  <p className="text-[10px] text-muted-foreground">{s.detail}</p>
                </div>
              </div>
            ))}
          </div>

          <p className="text-xs leading-relaxed text-foreground/80">{incident.detail}</p>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
              Run playbook:
            </span>
            {PLAYBOOKS.map((p) => {
              const Icon = PLAYBOOK_ICONS[p.id];
              const active = incident.playbook === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  title={p.description}
                  onClick={() => runPlaybook(p.id)}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-all",
                    active
                      ? "border-wg-emerald/50 bg-wg-emerald/10 text-wg-emerald"
                      : "border-border/50 text-muted-foreground hover:border-wg-cyan/40 hover:text-wg-cyan",
                  )}
                >
                  <Icon className="size-3.5" />
                  {p.name}
                </button>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {!alreadyBlocked && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1.5 border-wg-rose/40 text-wg-rose hover:bg-wg-rose/10"
                title={`Block ${incident.sourceIp} at the edge`}
                onClick={() =>
                  dispatch({
                    type: "ADD_BLOCKED_IP",
                    entry: {
                      id: uid("BAN"),
                      ip: incident.sourceIp,
                      reason: `Incident ${incident.id} — ${incident.vector}`,
                      source: "manual",
                      country: incident.country,
                      countryCode: incident.country,
                      addedAt: Date.now(),
                      hits: 0,
                      active: true,
                      expiresAt: null,
                    },
                  })
                }
              >
                <ShieldBan className="size-3.5" /> Ban {incident.sourceIp}
              </Button>
            )}
            {incident.stage !== "resolved" && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1.5 border-wg-emerald/30 text-wg-emerald hover:bg-wg-emerald/10"
                onClick={() =>
                  dispatch({
                    type: "SET_INCIDENT_STAGE",
                    id: incident.id,
                    stage: incident.stage === "investigating" ? "mitigated" : "resolved",
                  })
                }
              >
                <CheckCircle2 className="size-3.5" />
                Mark {incident.stage === "investigating" ? "mitigated" : "resolved"}
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              className="h-7 gap-1.5 border-wg-cyan/30 text-wg-cyan hover:bg-wg-cyan/10"
              onClick={() => dispatch({ type: "OPEN_COPILOT", context: copilotContextFromIncident(incident) })}
            >
              <Sparkles className="size-3.5" /> AI post-mortem
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
