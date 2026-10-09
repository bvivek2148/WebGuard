import { useEffect, useState } from "react";
import {
  Activity,
  Ban,
  BellRing,
  Bomb,
  Bot,
  Check,
  CheckCircle2,
  Code2,
  Cpu,
  Database,
  FileWarning,
  FilterX,
  FlaskConical,
  Radar,
  ScanSearch,
  Search,
  ShieldCheck,
  ShieldOff,
  ShieldX,
  Siren,
  SlidersHorizontal,
  Sparkles,
  Timer,
  Webhook,
  Download,
  RotateCcw,
  History,
  CircleDot,
  Eraser,
  Swords,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { clearSavedState, copilotContextFromIncident, uid, useWaf } from "../engine";
import { ATTACK_LABELS } from "../types";
import type { Alarm, TrafficFilters, WafMode } from "../types";
import { DEFAULT_TRAFFIC_FILTERS } from "../types";
import { ATTACK_ORIGINS, ATTACK_SPECS, generateAudit, originIp, pickOrigin } from "../data";
import { DRILL_SCENARIOS, scenarioTotalSec } from "../drills";

/** Random pick used by the “Run random drill” command — module scope keeps the
 * impure call out of render so the purity rule stays satisfied. */
function pickRandomScenarioId(): string {
  return DRILL_SCENARIOS[Math.floor(Math.random() * DRILL_SCENARIOS.length)].id;
}
import { SCENARIO_ICONS } from "./DrillsTab";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useAuth } from "@/hooks/use-auth";

interface NavCommand {
  id: string;
  label: string;
  keywords: string;
  icon: LucideIcon;
}

const NAV_COMMANDS: NavCommand[] = [
  { id: "overview", label: "Overview", keywords: "home soc dashboard posture status map", icon: Radar },
  { id: "traffic", label: "Live Traffic", keywords: "requests stream logs telemetry", icon: Activity },
  { id: "health", label: "Edge Health", keywords: "nodes health stress cpu latency load", icon: Cpu },
  { id: "audit", label: "Vulnerability Audit", keywords: "scan audit baseline score posture", icon: ScanSearch },
  { id: "findings", label: "Findings & Vulnerabilities", keywords: "issues vulns register findings vulnerabilities discovered", icon: FileWarning },
  { id: "canaries", label: "Canary Tokens", keywords: "canary token trip honeypot bait", icon: Bomb },
  { id: "sandbox", label: "Request Sandbox", keywords: "sandbox trace simulate test request", icon: FlaskConical },
  { id: "alerts", label: "Alerts", keywords: "alarm alerts notifications push", icon: BellRing },
  { id: "incidents", label: "Incidents", keywords: "incident response playbook breach", icon: Siren },
  { id: "access", label: "IP Blocklist & Rules", keywords: "ban blocklist ip cidr custom rules access control deny", icon: Ban },
  { id: "rules", label: "Policy Engine", keywords: "rules policy engine waf configure sensitivity", icon: SlidersHorizontal },
  { id: "integrations", label: "Integrations & Webhooks", keywords: "slack pagerduty email webhook dispatch alerts automate", icon: Webhook },
  { id: "drills", label: "Attack Drills", keywords: "drill simulation exercise scenario campaign attack test live", icon: Swords },
];

interface FilterCommand {
  id: string;
  label: string;
  keywords: string;
  icon: LucideIcon;
  patch: Partial<TrafficFilters> | typeof DEFAULT_TRAFFIC_FILTERS;
}

const FILTER_COMMANDS: FilterCommand[] = [
  { id: "blocked", label: "Live Traffic — blocked only", keywords: "blocked dropped 403 denied edge", icon: ShieldX, patch: { verdict: "blocked" } },
  { id: "threats", label: "Live Traffic — threats only", keywords: "attacks threats malicious hostile", icon: Bot, patch: { verdict: "threat" } },
  { id: "benign", label: "Live Traffic — benign only", keywords: "clean ok healthy passed", icon: CheckCircle2, patch: { verdict: "benign" } },
  { id: "throttled", label: "Live Traffic — throttled only", keywords: "rate limited 429 budget", icon: Timer, patch: { verdict: "throttled" } },
  { id: "status-403", label: "Live Traffic — status 403", keywords: "forbidden 403 denied", icon: ShieldX, patch: { status: 403, verdict: "all" } },
  { id: "status-429", label: "Live Traffic — status 429", keywords: "throttled 429 rate limit", icon: Timer, patch: { status: 429, verdict: "all" } },
  { id: "xss", label: "Live Traffic — XSS payloads", keywords: "cross site scripting xss reflected injection", icon: Code2, patch: { attack: "xss", status: 0, verdict: "all", query: "" } },
  { id: "sqli", label: "Live Traffic — SQL injection", keywords: "sqli injection sql database tautology", icon: Database, patch: { attack: "sqli", status: 0, verdict: "all", query: "" } },
  { id: "clear", label: "Clear traffic filters", keywords: "reset clear all filters none", icon: FilterX, patch: DEFAULT_TRAFFIC_FILTERS },
];

interface ModeCommand {
  id: WafMode;
  label: string;
  keywords: string;
  icon: LucideIcon;
}

const MODE_COMMANDS: ModeCommand[] = [
  { id: "blocking", label: "Firewall — BLOCKING (active)", keywords: "block mode active enforce 403 drop", icon: ShieldCheck },
  { id: "detection", label: "Firewall — DETECTION (log only)", keywords: "detect log monitor observe mode", icon: Radar },
  { id: "off", label: "Firewall — OFF (unprotected)", keywords: "off bypass unprotected raw exposed", icon: ShieldOff },
];

const RECENT_KEY = "webguard.palette.recent.v1";
const MAX_RECENT = 5;

export function CommandPalette({
  open,
  onOpenChange,
  onNavigate,
  filters,
  onFiltersChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onNavigate: (tab: string) => void;
  filters: TrafficFilters;
  onFiltersChange: (f: TrafficFilters) => void;
}) {
  const { state, dispatch, currentRps } = useWaf();
  const [recents, setRecents] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem(RECENT_KEY);
      const arr = JSON.parse(raw ?? "[]");
      return Array.isArray(arr) ? arr.filter((x) => typeof x === "string").slice(0, MAX_RECENT) : [];
    } catch {
      return [];
    }
  });

  // Global Cmd/Ctrl+K shortcut
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onOpenChange]);

  const pushRecent = (id: string) => {
    setRecents((prev) => {
      const next = [id, ...prev.filter((r) => r !== id)].slice(0, MAX_RECENT);
      try {
        localStorage.setItem(RECENT_KEY, JSON.stringify(next));
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  };

  const go = (tab: string, record = true) => {
    if (record) pushRecent(`nav-${tab}`);
    onOpenChange(false);
    onNavigate(tab);
  };

  // ---- live context for command badges ----
  const openFindings = state.findings.filter((f) => f.status === "open" || f.status === "investigating").length;
  const activeAlarms = state.alarms.filter((a) => a.state === "active").length;
  const openIncidents = state.incidents.filter((i) => i.stage !== "resolved").length;
  const activeBans = state.blocklist.filter((b) => b.active).length;
  const openSandbox = state.sandbox.length;

  const navBadge: Record<string, { text: string; tone: string }> = {
    traffic: { text: `${currentRps} rps`, tone: "text-wg-cyan" },
    alerts: { text: String(activeAlarms), tone: activeAlarms > 0 ? "text-wg-rose" : "text-muted-foreground" },
    incidents: { text: String(openIncidents), tone: openIncidents > 0 ? "text-wg-amber" : "text-muted-foreground" },
    findings: { text: String(openFindings), tone: openFindings > 0 ? "text-wg-amber" : "text-muted-foreground" },
    access: { text: String(activeBans), tone: activeBans > 0 ? "text-wg-rose" : "text-muted-foreground" },
    sandbox: { text: String(openSandbox), tone: "text-muted-foreground" },
  };

  const isFilterApplied = (c: FilterCommand) => {
    if (c.id === "clear") {
      return JSON.stringify(filters) === JSON.stringify(DEFAULT_TRAFFIC_FILTERS);
    }
    const patch = c.patch as Partial<TrafficFilters>;
    if ("verdict" in patch && patch.verdict !== undefined) {
      if (patch.verdict === "all") return filters.verdict === "all";
      return filters.verdict === patch.verdict && (patch.status === undefined || filters.status === patch.status);
    }
    if ("attack" in patch && patch.attack !== undefined) return filters.attack === patch.attack;
    if ("status" in patch && patch.status !== undefined) return filters.status === patch.status;
    return false;
  };

  const applyFilters = (c: FilterCommand) => {
    onFiltersChange({ ...filters, ...c.patch });
    pushRecent(`filter-${c.id}`);
    go("traffic", false);
  };

  const focusTrafficSearch = () => {
    pushRecent("action-search");
    go("traffic", false);
    window.setTimeout(() => document.getElementById("traffic-search-input")?.focus(), 80);
  };

  const openCopilot = (kind: "posture" | "triage" | "incident" | "threat") => {
    pushRecent(`copilot-${kind}`);
    if (kind === "triage") {
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
            items: open.slice(0, 8).map((f) => ({ title: f.title, severity: f.severity, patch: f.patch, path: f.path })),
          },
        },
      });
    } else if (kind === "incident") {
      const latest = state.incidents[0];
      if (!latest) {
        toast.info("No incidents yet — simulate one first");
        return;
      }
      dispatch({ type: "OPEN_COPILOT", context: copilotContextFromIncident(latest) });
    } else if (kind === "threat") {
      const hostile = [...state.logs].find((l) => l.attackType);
      if (!hostile) {
        toast.info("No hostile traffic in the live window");
        return;
      }
      dispatch({
        type: "OPEN_COPILOT",
        context: {
          kind: "log",
          title: `${ATTACK_LABELS[hostile.attackType!]} — ${hostile.path}`,
          attackType: hostile.attackType,
          ip: hostile.ip,
          country: hostile.countryCode,
          severity: hostile.attackType === "sqli" || hostile.attackType === "cmdi" ? "critical" : hostile.attackType === "xss" || hostile.attackType === "path-traversal" || hostile.attackType === "high-entropy" ? "high" : "medium",
          payload: hostile.payload ?? "",
          ruleId: hostile.ruleId,
          threatScore: hostile.threatScore,
          path: hostile.path,
        },
      });
    } else {
      dispatch({
        type: "OPEN_COPILOT",
        context: {
          kind: "log",
          title: "Current SOC posture",
          attackType: null,
          ip: "-",
          country: "-",
          severity: "low",
          payload: "",
          ruleId: null,
          threatScore: 0,
          path: "-",
        },
      });
    }
    onOpenChange(false);
  };

  const runAudit = () => {
    pushRecent("action-audit");
    const scan = generateAudit(state.target);
    dispatch({ type: "START_AUDIT", findings: scan.findings, radar: scan.radar, score: scan.score });
    go("audit", false);
  };

  const setMode = (mode: WafMode) => {
    pushRecent(`mode-${mode}`);
    dispatch({ type: "SET_MODE", mode });
    onOpenChange(false);
    toast.success(`Firewall switched to ${mode.toUpperCase()}`);
  };

  const simulateAlarm = () => {
    pushRecent("action-alarm");
    const spec = ATTACK_SPECS[Math.floor(Math.random() * ATTACK_SPECS.length)];
    const origin = pickOrigin(ATTACK_ORIGINS);
    const alarm: Alarm = {
      id: uid("AL"),
      severity: spec.severity,
      title: `${spec.label} — ${spec.path}`,
      source: "live-detection",
      ts: Date.now(),
      state: "active",
      detail: `Rule ${spec.ruleId} matched ${spec.label.toLowerCase()} traffic. ${state.mode === "blocking" ? "Dropped with 403 before reaching origin." : "Logged — origin processed the request."}`,
      ruleId: spec.ruleId,
      sourceIp: originIp(origin),
      countryCode: origin.geo.code,
    };
    dispatch({ type: "ADD_ALARM", alarm });
    onOpenChange(false);
    onNavigate("alerts");
    toast.success(`Alarm raised — ${spec.ruleId}`);
  };

  const banTopAttacker = () => {
    pushRecent("action-ban");
    const byIp = new Map<string, number>();
    for (const l of state.logs) if (l.attackType) byIp.set(l.ip, (byIp.get(l.ip) ?? 0) + 1);
    const top = [...byIp.entries()].sort((a, b) => b[1] - a[1])[0];
    if (!top) {
      toast.info("No hostile IPs in the live window");
      return;
    }
    const log = state.logs.find((l) => l.ip === top[0]);
    dispatch({
      type: "ADD_BLOCKED_IP",
      entry: {
        id: uid("BAN"),
        ip: top[0],
        reason: `Top attacker — ${top[1]} hostile requests in live window`,
        source: "auto",
        country: log?.country ?? "—",
        countryCode: log?.countryCode ?? "—",
        addedAt: Date.now(),
        hits: top[1],
        active: true,
        expiresAt: null,
      },
    });
    onOpenChange(false);
    onNavigate("access");
    toast.success(`Banned ${top[0]} — ${top[1]} hostile requests`);
  };

  const deployCanary = () => {
    pushRecent("action-canary");
    onOpenChange(false);
    onNavigate("canaries");
    toast.info("Canary Tokens — deploy a new token from the composer");
  };

  const clearSandbox = () => {
    pushRecent("action-clear-sandbox");
    dispatch({ type: "CLEAR_SANDBOX" });
    onOpenChange(false);
    toast.success("Sandbox runs cleared");
  };

  const startDrill = () => {
    startScenarioDrill(pickRandomScenarioId());
  };

  const startScenarioDrill = (scenarioId: string) => {
    const s = DRILL_SCENARIOS.find((x) => x.id === scenarioId) ?? DRILL_SCENARIOS[0];
    pushRecent(`drill-${s.id}`);
    dispatch({ type: "START_DRILL", scenarioId: s.id });
    onOpenChange(false);
    onNavigate("drills");
    toast.success(`Attack drill started — ${s.name}`, {
      description: `${s.stages.length} stages · ${scenarioTotalSec(s)}s campaign — watch traffic, alerts and the map react live`,
    });
  };

  const exportSoc = () => {
    pushRecent("session-export");
    const report = {
      app: "WebGuard SOC Console",
      exportedAt: new Date().toISOString(),
      sessionStartedAt: state.sessionStartedAt,
      state,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `webguard-soc-export-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onOpenChange(false);
    toast.success("SOC data exported as JSON");
  };

  const { user } = useAuth();
  const isSuperAdmin = Boolean(user?.isSuperAdmin);

  const resetDemo = () => {
    const ok = window.confirm(
      "Reset all WebGuard data?\n\nMode, blocklist, custom rules, findings, incidents, alerts and integrations return to the seeded baseline. This cannot be undone.",
    );
    if (!ok) return;
    pushRecent("session-reset");
    clearSavedState();
    dispatch({ type: "RESET_STATE" });
    onOpenChange(false);
    toast.info("State reset to baseline");
  };

  const visibleNavCommands = NAV_COMMANDS.filter((c) => {
    if (!isSuperAdmin) {
      const nonAdminHidden = ["health", "findings", "canaries", "rules", "drills", "integrations"];
      if (nonAdminHidden.includes(c.id)) {
        return false;
      }
    }
    return true;
  });

  // Lookup for rendering the Recent group from persisted ids
  const recentLookup: Record<string, { label: string; icon: LucideIcon }> = {};
  for (const c of visibleNavCommands) recentLookup[`nav-${c.id}`] = { label: c.label, icon: c.icon };
  for (const c of FILTER_COMMANDS) recentLookup[`filter-${c.id}`] = { label: c.label, icon: c.icon };
  for (const c of MODE_COMMANDS) recentLookup[`mode-${c.id}`] = { label: c.label, icon: c.icon };
  recentLookup["copilot-posture"] = { label: "Analyze current SOC posture", icon: Sparkles };
  recentLookup["copilot-triage"] = { label: "Triage findings with Copilot", icon: FileWarning };
  recentLookup["copilot-incident"] = { label: "Analyze latest incident", icon: Siren };
  recentLookup["copilot-threat"] = { label: "Review latest live threat", icon: Bot };
  recentLookup["action-audit"] = { label: "Run vulnerability audit", icon: ScanSearch };
  recentLookup["action-search"] = { label: "Search live traffic…", icon: Search };
  recentLookup["action-alarm"] = { label: "Simulate security alarm", icon: BellRing };
  recentLookup["action-ban"] = { label: "Ban top hostile IP", icon: Ban };
  recentLookup["action-canary"] = { label: "Deploy canary token", icon: Bomb };
  recentLookup["action-clear-sandbox"] = { label: "Clear sandbox runs", icon: Eraser };
  recentLookup["action-drill"] = { label: "Start attack drill", icon: Swords };
  for (const s of DRILL_SCENARIOS) {
    recentLookup[`drill-${s.id}`] = { label: `Run drill — ${s.name}`, icon: SCENARIO_ICONS[s.id] ?? Swords };
  }
  recentLookup["session-export"] = { label: "Export SOC data (JSON)", icon: Download };
  recentLookup["session-reset"] = { label: "Reset data", icon: RotateCcw };

  const totalCommands = visibleNavCommands.length + FILTER_COMMANDS.length + MODE_COMMANDS.length + 4 + 7 + 2 + DRILL_SCENARIOS.length;
  const recentItems = recents.map((id) => recentLookup[id]).filter(Boolean).slice(0, MAX_RECENT);

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="WebGuard command palette"
      description="Jump between SOC modules, filter live traffic, and control the firewall."
      className="w-full max-w-[min(36rem,calc(100vw-2rem))] sm:max-w-xl"
    >
      <CommandInput placeholder="Type a command or search…" />
      <CommandList>
        <CommandEmpty>No commands found.</CommandEmpty>

        {recentItems.length > 0 && (
          <>
            <CommandGroup heading="Recent">
              {recentItems.map(({ label, icon: Icon }) => (
                <CommandItem key={label} keywords={label.split(" ")} onSelect={() => pushRecent(label)}>
                  <Icon />
                  <span>{label}</span>
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        <CommandGroup heading="Navigate">
          {visibleNavCommands.map(({ id, label, keywords, icon: Icon }) => {
            const badge = navBadge[id];
            return (
              <CommandItem key={id} keywords={keywords.split(" ")} onSelect={() => go(id)}>
                <Icon />
                <span>{label}</span>
                {badge && (
                  <span className={cn("ml-auto font-mono text-[10px] tabular-nums", badge.tone)}>{badge.text}</span>
                )}
              </CommandItem>
            );
          })}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Live traffic filters">
          {FILTER_COMMANDS.map((c) => {
            const applied = isFilterApplied(c);
            return (
              <CommandItem key={c.id} keywords={c.keywords.split(" ")} onSelect={() => applyFilters(c)}>
                <c.icon />
                <span>{c.label}</span>
                {applied && (
                  <span className="ml-auto flex items-center gap-1 rounded-md border border-wg-cyan/40 bg-wg-cyan/10 px-1.5 py-0.5 text-[9px] font-bold tracking-wider text-wg-cyan">
                    <Check className="size-2.5" /> APPLIED
                  </span>
                )}
              </CommandItem>
            );
          })}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Firewall mode">
          {MODE_COMMANDS.map(({ id, label, keywords, icon: Icon }) => {
            const current = state.mode === id;
            return (
              <CommandItem key={id} keywords={keywords.split(" ")} onSelect={() => setMode(id)}>
                <Icon />
                <span>{label}</span>
                {current && (
                  <span className="ml-auto flex items-center gap-1 rounded-md border border-wg-emerald/40 bg-wg-emerald/10 px-1.5 py-0.5 text-[9px] font-bold tracking-wider text-wg-emerald">
                    <CircleDot className="size-2.5" /> CURRENT
                  </span>
                )}
              </CommandItem>
            );
          })}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Analysis">
          <CommandItem keywords={["ai", "assistant", "analyze", "gemini", "posture"]} onSelect={() => openCopilot("posture")}>
            <Sparkles />
            <span>Analyze current SOC posture</span>
          </CommandItem>
          <CommandItem keywords={["triage", "prioritize", "findings", "vulns", "register"]} onSelect={() => openCopilot("triage")}>
            <FileWarning />
            <span>Triage findings with Copilot</span>
            {openFindings > 0 && <span className="ml-auto font-mono text-[10px] text-wg-amber">{openFindings} open</span>}
          </CommandItem>
          <CommandItem keywords={["incident", "postmortem", "latest", "breach"]} onSelect={() => openCopilot("incident")}>
            <Siren />
            <span>Analyze latest incident</span>
            {openIncidents > 0 && <span className="ml-auto font-mono text-[10px] text-wg-amber">{openIncidents} open</span>}
          </CommandItem>
          <CommandItem keywords={["threat", "hostile", "attack", "live", "last"]} onSelect={() => openCopilot("threat")}>
            <Bot />
            <span>Review latest live threat</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Quick actions">
          <CommandItem keywords={["scan", "baseline", "vulnerability", "rescan"]} onSelect={runAudit}>
            <ScanSearch />
            <span>Run vulnerability audit</span>
          </CommandItem>
          <CommandItem keywords={["search", "query", "find", "filter"]} onSelect={focusTrafficSearch}>
            <Search />
            <span>Search live traffic…</span>
          </CommandItem>
          <CommandItem keywords={["alarm", "simulate", "test", "push", "notification"]} onSelect={simulateAlarm}>
            <BellRing />
            <span>Simulate security alarm</span>
          </CommandItem>
          <CommandItem keywords={["ban", "block", "ip", "attacker", "hostile", "top"]} onSelect={banTopAttacker}>
            <Ban />
            <span>Ban top hostile IP</span>
          </CommandItem>
          <CommandItem keywords={["canary", "deploy", "token", "honeypot", "bait"]} onSelect={deployCanary}>
            <Bomb />
            <span>Deploy canary token</span>
          </CommandItem>
          <CommandItem keywords={["sandbox", "clear", "wipe", "runs", "results"]} onSelect={clearSandbox}>
            <Eraser />
            <span>Clear sandbox runs</span>
          </CommandItem>
          <CommandItem keywords={["drill", "simulation", "exercise", "scenario", "attack", "campaign", "test", "random"]} onSelect={startDrill}>
            <Swords />
            <span>Start random attack drill</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Drill scenarios">
          {DRILL_SCENARIOS.map((s) => {
            const Icon = SCENARIO_ICONS[s.id] ?? Swords;
            return (
              <CommandItem
                key={s.id}
                keywords={[s.name, s.tagline, s.difficulty, "drill", "simulation", "scenario", "campaign", ...s.attackTypes]}
                onSelect={() => startScenarioDrill(s.id)}
              >
                <Icon />
                <span>Run drill — {s.name}</span>
                <span className="ml-auto font-mono text-[10px] text-muted-foreground">{scenarioTotalSec(s)}s</span>
              </CommandItem>
            );
          })}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Session">
          <CommandItem keywords={["export", "download", "backup", "json", "report"]} onSelect={exportSoc}>
            <Download />
            <span>Export SOC data (JSON)</span>
          </CommandItem>
          <CommandItem keywords={["reset", "clear", "wipe", "fresh", "restart"]} onSelect={resetDemo}>
            <RotateCcw />
            <span>Reset data</span>
          </CommandItem>
        </CommandGroup>

        <div className="flex items-center justify-between border-t border-border/50 px-3 py-2 text-[10px] text-muted-foreground">
          <span>
            <kbd className="rounded border border-border/60 bg-muted/50 px-1 font-mono">↑↓</kbd> navigate
            <kbd className="ml-2 rounded border border-border/60 bg-muted/50 px-1 font-mono">↵</kbd> select
            <kbd className="ml-2 rounded border border-border/60 bg-muted/50 px-1 font-mono">esc</kbd> close
          </span>
          <span className="flex items-center gap-2">
            <span className="hidden sm:inline">
              <History className="mr-0.5 inline size-2.5" /> recents tracked
            </span>
            <span className="font-mono">{totalCommands} commands · ⌘K</span>
          </span>
        </div>
      </CommandList>
    </CommandDialog>
  );
}
