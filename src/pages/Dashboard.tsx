import { useEffect, useRef, useState } from "react";
import { WafProvider, useWaf } from "@/waf/engine";
import { useAuth } from "@/hooks/use-auth";
import { TopBar } from "@/waf/components/TopBar";
import { SocSidebar } from "@/waf/components/SocSidebar";
import { OverviewTab } from "@/waf/components/OverviewTab";
import { AuditTab } from "@/waf/components/AuditTab";
import { TrafficTab } from "@/waf/components/TrafficTab";
import { AlertsTab } from "@/waf/components/AlertsTab";
import { IncidentsTab } from "@/waf/components/IncidentsTab";
import { CanariesTab } from "@/waf/components/CanariesTab";
import { SandboxTab } from "@/waf/components/SandboxTab";
import { RulesTab } from "@/waf/components/RulesTab";
import { FindingsTab } from "@/waf/components/FindingsTab";
import { AccessTab } from "@/waf/components/AccessTab";
import { IntegrationsTab } from "@/waf/components/IntegrationsTab";
import { HealthTab } from "@/waf/components/HealthTab";
import { DrillsTab, scenarioMeta } from "@/waf/components/DrillsTab";
import { CopilotDrawer } from "@/waf/components/CopilotDrawer";
import { CommandPalette } from "@/waf/components/CommandPalette";
import { fmtDuration, useNow } from "@/waf/components/shared";
import { cn } from "@/lib/utils";
import type { TrafficFilters } from "@/waf/types";
import { DEFAULT_TRAFFIC_FILTERS } from "@/waf/types";
import { Database, Pause, Play, ShieldCheck, Square, Swords, Timer } from "lucide-react";
import { toast } from "sonner";


// Simple media query hook
function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    typeof window !== "undefined" ? window.matchMedia(query).matches : false
  );
  useEffect(() => {
    const mql = window.matchMedia(query);
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener("change", handler);
    setMatches(mql.matches);
    return () => mql.removeEventListener("change", handler);
  }, [query]);
  return matches;
}

export default function Dashboard() {
  return (
    <div className="min-h-screen overflow-x-clip bg-background text-foreground">
      <WafProvider>
        <SocShell />
      </WafProvider>
    </div>
  );
}

function SocShell() {
  const [tab, setTab] = useState("overview");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [trafficFilters, setTrafficFilters] = useState<TrafficFilters>(DEFAULT_TRAFFIC_FILTERS);
  const { state } = useWaf();
  const { user } = useAuth();
  const isSuperAdmin = Boolean(user?.isSuperAdmin);

  // If a non-admin is currently on a restricted tab, reset to overview
  useEffect(() => {
    if (!isSuperAdmin && (tab === "findings" || tab === "canaries" || tab === "integrations")) {
      setTab("overview");
    }
  }, [isSuperAdmin, tab]);

  const isLgScreen = useMediaQuery("(min-width: 1024px)");
  const [sidebarWidth, setSidebarWidth] = useState<number>(() => {
    try {
      const raw = localStorage.getItem("webguard.sidebar.width");
      if (raw) return Number(raw);
    } catch { /* ignore */ }
    return 256;
  });
  const now = useNow(1000);

  const navigate = (t: string) => {
    if (!isSuperAdmin && (t === "findings" || t === "canaries" || t === "integrations")) {
      setTab("overview");
    } else {
      setTab(t);
    }
    setSidebarOpen(false);
  };

  return (
    <div className="wg-grid-bg relative min-h-screen">
      <SocSidebar active={tab} onNavigate={navigate} open={sidebarOpen} onClose={() => setSidebarOpen(false)} width={sidebarWidth} onWidthChange={setSidebarWidth} />

      <div className="flex min-h-screen flex-col" style={{ paddingLeft: isLgScreen ? sidebarWidth : 0 }}>
        <TopBar onMenuClick={() => setSidebarOpen(true)} onOpenPalette={() => setPaletteOpen(true)} onNavigate={navigate} />

        {state.drill && <DrillBanner now={now} onOpen={() => navigate("drills")} />}

        <main className="mx-auto w-full max-w-[1500px] flex-1 px-4 py-4 lg:px-6">
          {tab === "overview" && <OverviewTab onNavigate={navigate} />}
          {tab === "audit" && <AuditTab onNavigate={navigate} />}
          {tab === "traffic" && <TrafficTab filters={trafficFilters} onFiltersChange={setTrafficFilters} />}
          {tab === "health" && <HealthTab />}
          {tab === "alerts" && <AlertsTab />}
          {tab === "incidents" && <IncidentsTab />}
          {tab === "canaries" && isSuperAdmin && <CanariesTab />}
          {tab === "sandbox" && <SandboxTab />}
          {tab === "findings" && isSuperAdmin && <FindingsTab onNavigate={navigate} />}
          {tab === "access" && <AccessTab />}
          {tab === "rules" && <RulesTab onNavigate={navigate} />}
          {tab === "integrations" && isSuperAdmin && <IntegrationsTab />}
          {tab === "drills" && <DrillsTab onNavigate={navigate} />}
        </main>

        <footer className="mx-auto flex w-full max-w-[1500px] flex-wrap items-center justify-between gap-x-4 gap-y-1.5 px-4 pb-6 pt-2 text-[10px] text-muted-foreground/70 lg:px-6">
          <p className="flex items-center gap-1.5">
            <ShieldCheck className="size-3.5" />
            WebGuard SOC Console · telemetry simulated locally — no real traffic leaves the browser
          </p>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="flex items-center gap-1.5 font-mono">
              <Timer className="size-3.5 text-wg-cyan" />
              session {fmtDuration(now - state.sessionStartedAt)}
            </span>
            <span className="flex items-center gap-1.5" title="Mode, blocklist, rules, findings and incidents persist in this browser between sessions">
              <Database className="size-3.5 text-wg-emerald" />
              saved locally
            </span>
            <span className="font-mono">
              {state.totalRequests.toLocaleString()} reqs · {state.totalBlocked.toLocaleString()} blocked ·{" "}
              {state.totalAttacks.toLocaleString()} threats
            </span>
          </div>
        </footer>
      </div>

      <CopilotDrawer />
      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onNavigate={navigate}
        filters={trafficFilters}
        onFiltersChange={setTrafficFilters}
      />
    </div>
  );
}

/** Slim global banner shown while an attack drill is active (or finished). */
function DrillBanner({ now, onOpen }: { now: number; onOpen: () => void }) {
  const { state, dispatch } = useWaf();
  const d = state.drill;
  const prevDone = useRef(d?.done ?? false);

  // One-shot completion toast — fires on the transition to done, not every tick.
  useEffect(() => {
    if (d && d.done && !prevDone.current) {
      toast.success(`Drill complete — ${scenarioMeta(d.scenarioId)?.name ?? "scenario"}`, {
        description: "The campaign was contained by the live policy. Open the drill console for full results.",
      });
    }
    prevDone.current = d?.done ?? false;
  }, [d]);

  if (!d) return null;
  const meta = scenarioMeta(d.scenarioId);
  const totalSec = meta?.totalSec ?? 60;
  const elapsed = d.done ? (d.lastTickAt - d.startedAt) / 1000 : (now - d.startedAt) / 1000;
  const pct = Math.min(100, Math.max(0, (elapsed / totalSec) * 100));

  return (
    <div className="mx-auto w-full max-w-[1500px] px-4 pt-3 lg:px-6">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-wg-violet/30 bg-wg-violet/[0.07] px-3 py-2">
        <button type="button" onClick={onOpen} className="flex min-w-0 items-center gap-2 text-left">
          <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-wg-violet/15 text-wg-violet">
            <Swords className="size-3.5" />
          </span>
          <span className="min-w-0">
            <span className="block truncate text-[11px] font-semibold text-wg-violet">
              {d.done ? "Drill complete —" : d.paused ? "Drill paused —" : "Attack drill running —"} {meta?.name}
            </span>
            <span className="block truncate text-[9px] text-muted-foreground">
              {d.done ? "results ready · dismiss to return to normal telemetry" : d.paused ? "stream continues on benign baseline" : "live scenario through the WAF pipeline"}
            </span>
          </span>
        </button>

        <div className="min-w-[100px] flex-1">
          <div className="h-1.5 overflow-hidden rounded-full bg-border/40">
            <div
              className={cn("h-full rounded-full transition-all", d.done ? "bg-wg-emerald" : "bg-wg-violet")}
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>
        <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{Math.round(pct)}%</span>

        <div className="flex shrink-0 items-center gap-1.5">
          {!d.done && (
            <>
              <button
                type="button"
                onClick={() => dispatch({ type: "TOGGLE_DRILL_PAUSE" })}
                className={cn(
                  "flex h-7 items-center gap-1.5 rounded-md border px-2 text-[10px] font-semibold transition-colors",
                  d.paused
                    ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald hover:bg-wg-emerald/20"
                    : "border-wg-amber/40 bg-wg-amber/10 text-wg-amber hover:bg-wg-amber/20",
                )}
              >
                {d.paused ? <Play className="size-3" /> : <Pause className="size-3" />}
                {d.paused ? "Resume" : "Pause"}
              </button>
              <button
                type="button"
                onClick={() => dispatch({ type: "STOP_DRILL" })}
                className="flex h-7 items-center gap-1.5 rounded-md border border-wg-rose/40 bg-wg-rose/10 px-2 text-[10px] font-semibold text-wg-rose transition-colors hover:bg-wg-rose/20"
              >
                <Square className="size-3" /> Abort
              </button>
            </>
          )}
          <button
            type="button"
            onClick={onOpen}
            className="flex h-7 items-center gap-1.5 rounded-md border border-wg-violet/40 bg-wg-violet/10 px-2 text-[10px] font-semibold text-wg-violet transition-colors hover:bg-wg-violet/20"
          >
            <Swords className="size-3" /> Console
          </button>
        </div>
      </div>
    </div>
  );
}
