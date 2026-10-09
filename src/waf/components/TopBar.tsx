import { useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useAuth } from "@/hooks/use-auth";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import type { RequestLog, SeriesPoint, WafMode } from "../types";
import { ATTACK_LABELS } from "../types";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Activity, BellRing, Clock4, Download, Gauge, Globe, LogOut, Menu, Radar, RotateCcw, Search, ShieldCheck, ShieldOff, Siren, Sparkles, Swords, Timer, Upload, Zap } from "lucide-react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { useRef } from "react";
import { clearSavedState, persistSnapshot, serializePersistedState } from "../engine";
import type { PersistedState } from "../engine";
import { flagEmoji, fmtCompact, fmtDuration, useNow } from "./shared";
import { scenarioMeta } from "./DrillsTab";
import { SavePoints } from "./SavePoints";

const MODES: { mode: WafMode; label: string; short: string; icon: typeof ShieldOff; active: string; idle: string }[] = [
  {
    mode: "off",
    label: "OFF — Unprotected",
    short: "OFF",
    icon: ShieldOff,
    active: "border-wg-rose/50 bg-wg-rose/15 text-wg-rose shadow-[0_0_18px_rgba(244,63,94,0.2)]",
    idle: "border-border/60 text-muted-foreground hover:text-foreground/80",
  },
  {
    mode: "detection",
    label: "DETECTION — Log Only",
    short: "DETECT",
    icon: Radar,
    active: "border-wg-amber/50 bg-wg-amber/15 text-wg-amber shadow-[0_0_18px_rgba(245,158,11,0.2)]",
    idle: "border-border/60 text-muted-foreground hover:text-foreground/80",
  },
  {
    mode: "blocking",
    label: "BLOCKING — Active",
    short: "BLOCK",
    icon: ShieldCheck,
    active: "border-wg-emerald/60 bg-wg-emerald/15 text-wg-emerald shadow-[0_0_20px_rgba(52,211,153,0.25)]",
    idle: "border-border/60 text-muted-foreground hover:text-foreground/80",
  },
];

export function TopBar({
  onMenuClick,
  onOpenPalette,
  onNavigate,
}: {
  onMenuClick: () => void;
  onOpenPalette: () => void;
  onNavigate?: (tab: string) => void;
}) {
  const { state, dispatch, currentRps, activeThreats, avgLatency } = useWaf();
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const now = useNow(1000);
  const importRef = useRef<HTMLInputElement | null>(null);

  const blockedPct = state.totalRequests ? Math.round((state.totalBlocked / state.totalRequests) * 100) : 0;
  const attackPct = state.totalRequests ? Math.round((state.totalAttacks / state.totalRequests) * 100) : 0;

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const handleExport = () => {
    const report = {
      app: "WebGuard SOC Console",
      exportedAt: new Date().toISOString(),
      v: 1,
      note: "Full console snapshot — import it back via the profile menu (Import SOC data)",
      state: serializePersistedState(state),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `webguard-soc-snapshot-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Console snapshot exported", {
      description: "Firewall mode, blocklist, rules, findings, alarms, incidents, drills and integrations included",
    });
  };

  const handleImport = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as { state?: unknown };
        if (!parsed.state || typeof parsed.state !== "object" || Array.isArray(parsed.state)) {
          throw new Error("no state object found — this is not a WebGuard snapshot");
        }
        const snapshot = parsed.state as Partial<PersistedState>;
        dispatch({ type: "RESTORE_STATE", snapshot });
        persistSnapshot(snapshot as PersistedState);
        toast.success("Console snapshot restored", {
          description: "Mode, blocklist, rules, findings, alarms, incidents, drills and integrations reloaded",
        });
      } catch (err) {
        toast.error("Could not import snapshot", {
          description: err instanceof Error ? err.message : "Not a valid WebGuard export file",
        });
      }
    };
    reader.readAsText(file);
  };

  const handleReset = () => {
    const ok = window.confirm(
      "Reset all WebGuard data?\n\nThis will completely clear all local storage, session storage, audit history, findings, alarms, incidents, custom rules, and telemetry. This cannot be undone.",
    );
    if (!ok) return;
    try {
      clearSavedState();
      localStorage.clear();
      sessionStorage.clear();
    } catch (e) {}
    dispatch({ type: "RESET_STATE" });
    toast.success("All project data, storage, and telemetry successfully reset!");
  };

  const isSuperAdmin = Boolean(user?.isSuperAdmin);
  const sessionLabel = fmtDuration(now - state.sessionStartedAt);

  // Live drill progress for the top-bar ring indicator.
  const drillMeta = state.drill ? scenarioMeta(state.drill.scenarioId) : null;
  const drillTotalSec = drillMeta?.totalSec ?? 60;
  const drillElapsed = state.drill
    ? state.drill.done
      ? (state.drill.lastTickAt - state.drill.startedAt) / 1000
      : (now - state.drill.startedAt) / 1000
    : 0;
  const drillPct = Math.min(100, Math.max(0, (drillElapsed / drillTotalSec) * 100));

  return (
    <header className="sticky top-0 z-30 border-b border-border/60 bg-background/85 backdrop-blur-xl">
      <div className="flex flex-col gap-2 px-4 py-2.5 lg:flex-row lg:flex-wrap lg:items-center lg:gap-x-3 lg:gap-y-2 lg:px-6">
        {/* row 1 (mobile) / left (desktop): hamburger + target */}
        <div className="flex min-w-0 items-center gap-2 lg:basis-full 2xl:basis-auto 2xl:flex-1">
          <button
            type="button"
            onClick={onMenuClick}
            className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-border/60 bg-muted/40 text-muted-foreground lg:hidden"
          >
            <Menu className="size-4" />
          </button>

          <div className="relative min-w-0 flex-1 lg:max-w-md">
            <Globe className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={state.target}
              onChange={(e) => dispatch({ type: "SET_TARGET", target: e.target.value })}
              className="h-8 border-border/60 bg-muted/50 pl-8 font-mono text-xs text-foreground focus-visible:ring-primary/40"
              placeholder="https://target.example.com"
              spellCheck={false}
            />
          </div>
          <span className="hidden shrink-0 items-center gap-1 rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-2 py-1 text-[10px] font-bold text-wg-emerald xl:flex">
            <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" />
            EDGE CONNECTED
          </span>
        </div>

        {/* row 2 (mobile) / right (desktop): mode controller + live actions */}
        <div className="flex flex-wrap items-center gap-2 lg:basis-full lg:gap-x-3 2xl:basis-auto">
          {/* mode controller */}
          <div className="flex shrink-0 items-center gap-1 rounded-xl border border-border/70 bg-muted/40 p-1">
          {MODES.map(({ mode, short, label, icon: Icon, active, idle }) => {
            const on = state.mode === mode;
            return (
              <button
                key={mode}
                type="button"
                title={label}
                onClick={() => dispatch({ type: "SET_MODE", mode })}
                className={cn(
                  "flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-[10px] font-bold tracking-wider transition-all",
                  on ? active : idle,
                )}
              >
                <Icon className="size-3.5" />
                <span className="hidden md:inline">{short}</span>
              </button>
            );
          })}
        </div>

        {/* indicators + actions */}
        <div className="ml-auto flex flex-wrap items-center justify-end gap-2 lg:gap-2.5">
          <Popover>
            <PopoverTrigger asChild>
              <button type="button" title="Inspect ingress latency — click for details" className="group">
                <Indicator
                  icon={<Gauge className="size-3.5" />}
                  label="Latency"
                  value={`${avgLatency.toFixed(2)} ms`}
                  tone={avgLatency < 2.5 ? "text-wg-emerald" : "text-wg-amber"}
                  hideBelow="xl"
                  interactive
                />
              </button>
            </PopoverTrigger>
            <PopoverContent align="end" sideOffset={6} className="w-72 max-w-[min(18rem,calc(100vw-2rem))] border-border/60 p-0">
              <LatencyPanel logs={state.logs} avgLatency={avgLatency} />
            </PopoverContent>
          </Popover>

          <Popover>
            <PopoverTrigger asChild>
              <button type="button" title="Inspect traffic velocity — click for details" className="group">
                <Indicator
                  icon={<Activity className="size-3.5" />}
                  label="RPS"
                  value={String(currentRps)}
                  tone="text-wg-cyan"
                  hideBelow="lg"
                  interactive
                />
              </button>
            </PopoverTrigger>
            <PopoverContent align="end" sideOffset={6} className="w-72 max-w-[min(18rem,calc(100vw-2rem))] border-border/60 p-0">
              <RpsPanel series={state.series} currentRps={currentRps} budget={Math.round((state.settings.rateLimitRpm / 60) * 10) / 10} />
            </PopoverContent>
          </Popover>

          <Popover>
            <PopoverTrigger asChild>
              <button type="button" title="Inspect live threat posture — click for details" className="group">
                <Indicator
                  icon={<BellRing className="size-3.5" />}
                  label="Threats"
                  value={
                    <span className="flex items-center gap-1.5">
                      {activeThreats}
                      {activeThreats > 0 && <span className="relative flex size-1.5">
                        <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
                        <span className="relative inline-flex size-1.5 rounded-full bg-rose-400" />
                      </span>}
                    </span>
                  }
                  tone="text-wg-rose"
                  interactive
                  hideLabelBelow="sm"
                />
              </button>
            </PopoverTrigger>
            <PopoverContent align="end" sideOffset={6} className="w-72 max-w-[min(18rem,calc(100vw-2rem))] border-border/60 p-0">
              <ThreatsPanel logs={state.logs} activeThreats={activeThreats} />
            </PopoverContent>
          </Popover>

          {state.drill && drillMeta && (
            <button
              type="button"
              onClick={() => onNavigate?.("drills")}
              title={`${state.drill.done ? "Drill complete" : state.drill.paused ? "Drill paused" : "Live attack drill"} — ${drillMeta.name} · ${Math.round(drillPct)}% — click to open the drill console`}
              className={cn(
                "flex shrink-0 items-center gap-2 rounded-lg border px-2 py-1 transition-colors",
                state.drill.done
                  ? "border-wg-emerald/40 bg-wg-emerald/10 hover:bg-wg-emerald/20"
                  : state.drill.paused
                    ? "border-wg-amber/40 bg-wg-amber/10 hover:bg-wg-amber/20"
                    : "border-wg-violet/40 bg-wg-violet/10 hover:bg-wg-violet/20",
              )}
            >
              <DrillRing pct={drillPct} done={state.drill.done} paused={state.drill.paused} />
              <span className="text-left leading-tight">
                <span
                  className={cn(
                    "block font-mono text-[9px] font-bold tracking-wider",
                    state.drill.done
                      ? "text-wg-emerald"
                      : state.drill.paused
                        ? "text-wg-amber"
                        : "text-wg-violet",
                  )}
                >
                  {state.drill.done ? "DRILL DONE" : state.drill.paused ? "PAUSED" : "LIVE DRILL"}
                </span>
                <span className="block max-w-[110px] truncate text-[9px] text-muted-foreground">{drillMeta.name}</span>
              </span>
            </button>
          )}

          <ThemeToggle />
          <button
            type="button"
            onClick={onOpenPalette}
            title="Search & commands (Ctrl+K)"
            className="flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-border/60 bg-muted/40 px-2.5 text-muted-foreground transition-colors hover:text-foreground"
          >
            <Search className="size-3.5" />
            <span className="hidden text-[11px] font-medium md:inline">Search</span>
            <kbd className="hidden rounded border border-border/60 bg-background/60 px-1 font-mono text-[9px] font-semibold lg:inline">⌘K</kbd>
          </button>
          <Button
            variant="outline"
            size="sm"
            className="h-8 shrink-0 gap-1.5 border-primary/40 bg-primary/10 text-primary hover:bg-primary/20 hover:text-primary"
            onClick={() =>
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
              })
            }
          >
            <Sparkles className="size-3.5" />
            <span className="hidden sm:inline">Copilot</span>
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button type="button" className="flex size-8 items-center justify-center rounded-lg border border-border/60 bg-muted/40 transition-colors hover:border-primary/50">
                <Avatar className="size-6">
                  <AvatarFallback className="bg-primary/20 text-[10px] font-bold text-primary">
                    {(user?.name ?? user?.email ?? "O")[0]?.toUpperCase()}
                  </AvatarFallback>
                </Avatar>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-72 p-0">
              {/* operator identity card */}
              <div className="rounded-t-lg border-b border-border/50 bg-muted/30 px-3 py-3">
                <div className="flex items-center gap-3">
                  <Avatar className="size-10">
                    <AvatarFallback className="bg-primary/20 text-sm font-bold text-primary">
                      {(user?.name ?? user?.email ?? "O")[0]?.toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="min-w-0 flex-1">
                    <DropdownMenuLabel className="truncate p-0 text-sm text-foreground">
                      {user?.name ?? "SOC Operator"}
                    </DropdownMenuLabel>
                    <p className="truncate text-[11px] text-muted-foreground">{user?.email ?? "operator@webguard.dev"}</p>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      <span
                        className={cn(
                          "rounded border px-1.5 py-px text-[9px] font-bold tracking-wider",
                          isSuperAdmin
                            ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald"
                            : "border-primary/40 bg-primary/10 text-primary"
                        )}
                      >
                        {isSuperAdmin ? "ROLE · SUPERADMIN" : "ROLE · GUEST / ANALYST"}
                      </span>
                      <span className="flex items-center gap-1 rounded border border-border/50 bg-muted/60 px-1.5 py-px text-[9px] font-semibold text-muted-foreground">
                        <Timer className="size-2.5" /> shift {sessionLabel}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* live console stats */}
              <div className="grid grid-cols-2 gap-px bg-border/40">
                <ProfileStat label="Active threats" value={activeThreats} tone={activeThreats > 0 ? "text-wg-rose" : "text-wg-emerald"} icon={<Siren className="size-3" />} />
                <ProfileStat label="Open findings" value={state.findings.filter((f) => f.status === "open" || f.status === "investigating").length} tone="text-wg-amber" icon={<ShieldOff className="size-3" />} />
                <ProfileStat label="Active bans" value={state.blocklist.filter((b) => b.active).length} tone="text-wg-rose" icon={<ShieldCheck className="size-3" />} />
                <ProfileStat label="Incidents" value={state.incidents.filter((i) => i.stage !== "resolved").length} tone="text-wg-cyan" icon={<Clock4 className="size-3" />} />
              </div>

              {/* session activity mix (Admin Only) */}
              {isSuperAdmin && (
                <div className="border-b border-border/50 px-3 py-2.5">
                  <p className="mb-2 text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                    Session activity · {fmtCompact(state.totalRequests)} requests
                  </p>
                  <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-border/40">
                    <div className="h-full bg-wg-rose" style={{ width: `${blockedPct}%` }} title={`blocked ${blockedPct}%`} />
                    <div className="h-full bg-wg-amber" style={{ width: `${Math.max(0, attackPct - blockedPct)}%` }} title={`attacks ${attackPct}%`} />
                    <div className="h-full bg-wg-emerald" style={{ width: `${Math.max(0, 100 - attackPct)}%` }} title="benign" />
                  </div>
                  <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[9px] text-muted-foreground">
                    <span className="flex items-center gap-1"><span className="size-1.5 rounded-full bg-wg-rose" /> blocked {blockedPct}%</span>
                    <span className="flex items-center gap-1"><span className="size-1.5 rounded-full bg-wg-amber" /> attacks {attackPct}%</span>
                    <span className="flex items-center gap-1"><span className="size-1.5 rounded-full bg-wg-emerald" /> benign {100 - attackPct}%</span>
                  </div>
                </div>
              )}

              {/* live console status — mode + latency + velocity at a glance (Admin Only) */}
              {isSuperAdmin && (
                <>
                  <DropdownMenuSeparator />
                  <div className="border-b border-border/50 px-3 py-2.5">
                    <p className="mb-1.5 text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                      Console status
                    </p>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span
                        className={cn(
                          "flex items-center gap-1.5 rounded-md border px-2 py-1 text-[9px] font-bold tracking-wider",
                          state.mode === "blocking" && "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
                          state.mode === "detection" && "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
                          state.mode === "off" && "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
                        )}
                      >
                        {state.mode === "blocking" ? <ShieldCheck className="size-3" /> : state.mode === "detection" ? <Radar className="size-3" /> : <ShieldOff className="size-3" />}
                        {state.mode.toUpperCase()}
                      </span>
                      <span className={cn("rounded-md border border-border/40 bg-muted/50 px-2 py-1 font-mono text-[9px]", avgLatency < 2.5 ? "text-wg-emerald" : "text-wg-amber")}>
                        <Gauge className="mr-1 inline size-2.5" />
                        {avgLatency.toFixed(2)} ms
                      </span>
                      <span className="rounded-md border border-border/40 bg-muted/50 px-2 py-1 font-mono text-[9px] text-wg-cyan">
                        <Activity className="mr-1 inline size-2.5" />
                        {currentRps} rps
                      </span>
                      <span className={cn("rounded-md border border-border/40 bg-muted/50 px-2 py-1 font-mono text-[9px]", activeThreats > 0 ? "text-wg-rose" : "text-wg-emerald")}>
                        <Siren className="mr-1 inline size-2.5" />
                        {activeThreats} threats
                      </span>
                    </div>
                  </div>
                </>
              )}

              {isSuperAdmin && (
                <>
                  <DropdownMenuItem onClick={onOpenPalette} className="gap-2 text-xs">
                    <Search className="size-3.5" /> Open command palette
                    <kbd className="ml-auto rounded border border-border/60 bg-muted/50 px-1 font-mono text-[9px]">⌘K</kbd>
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => navigate("/")} className="gap-2 text-xs">
                    <Zap className="size-3.5" /> Back to site
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={handleExport}
                    className="gap-2 text-xs"
                  >
                    <Download className="size-3.5" /> Export SOC data
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => importRef.current?.click()} className="gap-2 text-xs">
                    <Upload className="size-3.5" /> Import SOC data
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <SavePoints />
                  <DropdownMenuSeparator />
                </>
              )}

              <DropdownMenuItem onClick={handleReset} className="gap-2 text-xs">
                <RotateCcw className="size-3.5" /> Reset data
              </DropdownMenuItem>
              <input
                ref={importRef}
                type="file"
                accept="application/json,.json"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) handleImport(file);
                  e.target.value = "";
                }}
              />
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleSignOut} className="gap-2 text-xs text-wg-rose">
                <LogOut className="size-3.5" /> Sign out
              </DropdownMenuItem>
              <div className="flex items-center justify-between border-t border-border/40 px-3 py-1.5 text-[9px] text-muted-foreground/60">
                <span>
                  <kbd className="rounded border border-border/60 bg-muted/50 px-1 font-mono">⌘K</kbd> commands
                </span>
                <span className="font-mono">webguard v2.4</span>
              </div>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        </div>
      </div>
    </header>
  );
}

// ============================================================================
// Clickable live-status panels
// ============================================================================

function LatencyPanel({ logs, avgLatency }: { logs: RequestLog[]; avgLatency: number }) {
  const sample = useMemo(() => logs.slice(0, 40), [logs]);
  const max = Math.max(1, ...sample.map((l) => l.latency));
  const p95 = useMemo(() => {
    const sorted = [...sample.map((l) => l.latency)].sort((a, b) => a - b);
    return sorted.length ? sorted[Math.floor(sorted.length * 0.95)] ?? sorted[sorted.length - 1] : 0;
  }, [sample]);
  const slowest = useMemo(() => {
    let best: (typeof sample)[number] | null = null;
    for (const l of sample) if (!best || l.latency > best.latency) best = l;
    return best;
  }, [sample]);
  const underSla = avgLatency < 2.5;

  return (
    <div>
      <div className="flex items-start justify-between gap-2 border-b border-border/50 px-3 py-2.5">
        <div>
          <p className="text-xs font-semibold text-foreground">Ingress latency</p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">edge → WAF processing · live sample</p>
        </div>
        <span className={cn("rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold", underSla ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" : "border-wg-amber/40 bg-wg-amber/10 text-wg-amber")}>
          {underSla ? "WITHIN SLA" : "SLA BREACH"}
        </span>
      </div>
      <div className="flex flex-col gap-2.5 px-3 py-3">
        <div className="flex items-end gap-4">
          <div>
            <p className="font-mono text-2xl font-bold tabular-nums text-foreground">{avgLatency.toFixed(2)} ms</p>
            <p className="text-[10px] text-muted-foreground">average now · SLA &lt; 2.5 ms</p>
          </div>
          <div className="mb-0.5">
            <p className="font-mono text-sm font-semibold text-wg-amber">p95 {p95.toFixed(2)} ms</p>
            <p className="text-[10px] text-muted-foreground">95th percentile</p>
          </div>
        </div>

        {/* latency sparkline */}
        <div className="flex h-14 items-end gap-px">
          {sample.map((l, i) => (
            <div
              key={i}
              className={cn("flex-1 rounded-t-sm", l.latency >= 2.5 ? "bg-wg-amber/70" : "bg-wg-emerald/60")}
              style={{ height: `${Math.max(6, (l.latency / max) * 100)}%` }}
              title={`${l.latency.toFixed(2)} ms`}
            />
          ))}
          {sample.length === 0 && <p className="text-[10px] text-muted-foreground">Collecting samples…</p>}
        </div>

        <div className="grid grid-cols-2 gap-2 border-t border-border/40 pt-2 text-[10px]">
          <span className="text-muted-foreground">Slowest request</span>
          <span className="truncate text-right font-mono text-foreground/90">
            {slowest ? `${slowest.latency.toFixed(2)} ms · ${slowest.method} ${slowest.path}` : "—"}
          </span>
          <span className="text-muted-foreground">Blocking overhead</span>
          <span className="text-right font-mono text-foreground/90">+0.00 ms (inlined)</span>
        </div>
      </div>
    </div>
  );
}

function RpsPanel({ series, currentRps, budget }: { series: SeriesPoint[]; currentRps: number; budget: number }) {
  const window = useMemo(() => series.slice(-40), [series]);
  const max = Math.max(1, ...window.map((s) => s.rps), budget);
  const peak = Math.max(0, ...window.map((s) => s.rps));
  const avg = window.length ? window.reduce((s, p) => s + p.rps, 0) / window.length : 0;
  const over = currentRps >= budget;

  return (
    <div>
      <div className="flex items-start justify-between gap-2 border-b border-border/50 px-3 py-2.5">
        <div>
          <p className="text-xs font-semibold text-foreground">Traffic velocity</p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">requests/sec · 1s buckets</p>
        </div>
        <span className={cn("rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold", over ? "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" : "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald")}>
          {over ? "AT BUDGET" : "NOMINAL"}
        </span>
      </div>
      <div className="flex flex-col gap-2.5 px-3 py-3">
        <div className="flex items-end gap-4">
          <div>
            <p className="font-mono text-2xl font-bold tabular-nums text-foreground">{currentRps}</p>
            <p className="text-[10px] text-muted-foreground">req/s right now</p>
          </div>
          <div className="mb-0.5 grid grid-cols-2 gap-x-4 text-[10px]">
            <span className="text-muted-foreground">60s avg</span>
            <span className="text-right font-mono text-foreground/90">{avg.toFixed(1)}</span>
            <span className="text-muted-foreground">peak</span>
            <span className="text-right font-mono text-foreground/90">{peak}</span>
          </div>
        </div>

        <div className="flex h-14 items-end gap-px">
          {window.map((p, i) => (
            <div
              key={i}
              className={cn("flex-1 rounded-t-sm", p.rps >= budget ? "bg-wg-amber/70" : "bg-wg-cyan/60")}
              style={{ height: `${Math.max(6, (p.rps / max) * 100)}%` }}
              title={`${p.label} · ${p.rps} rps`}
            />
          ))}
        </div>

        <div className="grid grid-cols-2 gap-2 border-t border-border/40 pt-2 text-[10px]">
          <span className="text-muted-foreground">Rate budget</span>
          <span className="text-right font-mono text-wg-cyan">{budget}/s · 429 above</span>
          <span className="text-muted-foreground">Threat share · 60s</span>
          <span className="text-right font-mono text-foreground/90">
            {window.reduce((s, p) => s + p.attacks, 0)} requests
          </span>
        </div>
      </div>
    </div>
  );
}

function ThreatsPanel({ logs, activeThreats }: { logs: RequestLog[]; activeThreats: number }) {
  const now = useNow(1000);
  const window60 = useMemo(() => logs.filter((l) => now - l.ts <= 60_000), [logs, now]);
  const mix = useMemo(() => {
    const counts = new Map<string, number>();
    for (const l of window60) if (l.attackType) counts.set(ATTACK_LABELS[l.attackType], (counts.get(ATTACK_LABELS[l.attackType]) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [window60]);
  const maxMix = Math.max(1, ...mix.map(([, n]) => n));
  const blocked = window60.filter((l) => l.blocked).length;
  const topAttacker = useMemo(() => {
    const byIp = new Map<string, number>();
    for (const l of window60) if (l.attackType) byIp.set(l.ip, (byIp.get(l.ip) ?? 0) + 1);
    return [...byIp.entries()].sort((a, b) => b[1] - a[1])[0] ?? null;
  }, [window60]);
  const topLog = window60.find((l) => l.ip === topAttacker?.[0]);

  return (
    <div>
      <div className="flex items-start justify-between gap-2 border-b border-border/50 px-3 py-2.5">
        <div>
          <p className="text-xs font-semibold text-foreground">Live threat posture</p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">60s sliding window · classified attacks</p>
        </div>
        <span className={cn("rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold", activeThreats > 0 ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" : "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald")}>
          {activeThreats > 0 ? "UNDER FIRE" : "CLEAR"}
        </span>
      </div>
      <div className="flex flex-col gap-2.5 px-3 py-3">
        <div className="flex items-end gap-4">
          <div>
            <p className="font-mono text-2xl font-bold tabular-nums text-foreground">{activeThreats}</p>
            <p className="text-[10px] text-muted-foreground">active threats now</p>
          </div>
          <div className="mb-0.5 grid grid-cols-2 gap-x-4 text-[10px]">
            <span className="text-muted-foreground">blocked · 60s</span>
            <span className="text-right font-mono text-foreground/90">{blocked}</span>
            <span className="text-muted-foreground">hostile IPs</span>
            <span className="text-right font-mono text-foreground/90">{new Set(window60.filter((l) => l.attackType).map((l) => l.ip)).size}</span>
          </div>
        </div>

        <div className="flex flex-col gap-1.5">
          {mix.map(([label, n]) => (
            <div key={label} className="flex items-center gap-2">
              <span className="w-32 shrink-0 truncate text-[10px] text-foreground/80">{label}</span>
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                <div className="h-full rounded-full bg-gradient-to-r from-wg-rose to-wg-orange" style={{ width: `${(n / maxMix) * 100}%` }} />
              </div>
              <span className="w-5 text-right font-mono text-[10px] text-muted-foreground">{n}</span>
            </div>
          ))}
          {mix.length === 0 && <p className="py-2 text-center text-[10px] text-muted-foreground">No classified attacks in the window.</p>}
        </div>

        {topAttacker && topLog && (
          <div className="flex items-center gap-2 rounded-lg border border-wg-rose/20 bg-wg-rose/[0.05] px-2.5 py-2 text-[10px]">
            <span className="text-sm leading-none">{flagEmoji(topLog.countryCode)}</span>
            <span className="truncate font-mono text-foreground/90">{topAttacker[0]}</span>
            <span className="ml-auto shrink-0 font-mono font-bold text-wg-rose">{topAttacker[1]}×</span>
          </div>
        )}
      </div>
    </div>
  );
}

/** SVG progress ring shown while an attack drill is live (or finished). */
function DrillRing({ pct, done, paused }: { pct: number; done: boolean; paused: boolean }) {
  const r = 15.5;
  const c = 2 * Math.PI * r;
  const color = done ? "#34d399" : paused ? "#f59e0b" : "#8b5cf6";
  return (
    <div className="relative size-8 shrink-0">
      <svg viewBox="0 0 36 36" className="size-8 -rotate-90">
        <circle cx="18" cy="18" r={r} fill="none" stroke="currentColor" strokeOpacity="0.15" strokeWidth="3.5" className="text-foreground" />
        <circle
          cx="18"
          cy="18"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="3.5"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - Math.min(100, Math.max(0, pct)) / 100)}
        />
      </svg>
      <Swords className="absolute inset-0 m-auto size-3.5" style={{ color }} />
    </div>
  );
}

function ProfileStat({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: number; tone: string }) {
  return (
    <div className="flex items-center gap-2 bg-background px-3 py-2">
      <span className={tone}>{icon}</span>
      <span className="min-w-0 flex-1 truncate text-[10px] text-muted-foreground">{label}</span>
      <span className={cn("font-mono text-xs font-bold", tone)}>{value}</span>
    </div>
  );
}

function Indicator({
  icon,
  label,
  value,
  tone,
  hideBelow,
  hideLabelBelow,
  interactive = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
  tone: string;
  hideBelow?: "lg" | "xl";
  hideLabelBelow?: "sm";
  interactive?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex shrink-0 items-center gap-2 rounded-lg border px-2.5 py-1.5 transition-colors",
        interactive && "border-border/60 bg-muted/40 hover:border-wg-cyan/50 hover:bg-muted/60",
        hideBelow === "xl" && "hidden xl:flex",
        hideBelow === "lg" && "hidden lg:flex",
      )}
    >
      <span className={cn("text-muted-foreground", interactive && "transition-colors group-hover:text-wg-cyan")}>{icon}</span>
      <span className="leading-tight">
        <span className={cn("block font-mono text-xs font-semibold tabular-nums", tone)}>{value}</span>
        <span className={cn("block text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground/80", hideLabelBelow === "sm" && "hidden sm:block")}>
          {label}
        </span>
      </span>
    </div>
  );
}
