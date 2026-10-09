import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/use-auth";
import { useWaf } from "../engine";
import {
  Activity,
  Ban,
  BellRing,
  Bomb,
  Cpu,
  FlaskConical,
  FileWarning,
  LogOut,
  Radar,
  ScanSearch,
  ShieldCheck,
  Siren,
  SlidersHorizontal,
  Swords,
  Webhook,
  X,
} from "lucide-react";
import { useNavigate } from "react-router";
import { fmtDuration, ModeBadge, useNow } from "./shared";
import { Database } from "lucide-react";

const SIDEBAR_WIDTH_KEY = "webguard.sidebar.width";
function savedSidebarWidth(): number | null {
  try {
    const raw = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    if (raw) return Number(raw);
  } catch { /* ignore */ }
  return null;
}
function clampSidebarWidth(w: number) {
  return Math.min(Math.max(w, 200), 380);
}

interface NavItem {
  id: string;
  label: string;
  icon: typeof Radar;
}

const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "Monitoring",
    items: [
      { id: "overview", label: "Overview", icon: Radar },
      { id: "traffic", label: "Live Traffic", icon: Activity },
      { id: "health", label: "Edge Health", icon: Cpu },
    ],
  },
  {
    title: "Security",
    items: [
      { id: "audit", label: "Vulnerability Audit", icon: ScanSearch },
      { id: "findings", label: "Findings & Vulnerabilities", icon: FileWarning },
      { id: "canaries", label: "Canary Tokens", icon: Bomb },
      { id: "sandbox", label: "Request Sandbox", icon: FlaskConical },
    ],
  },
  {
    title: "Response",
    items: [
      { id: "alerts", label: "Alerts", icon: BellRing },
      { id: "incidents", label: "Incidents", icon: Siren },
    ],
  },
  {
    title: "Defense",
    items: [
      { id: "access", label: "IP Blocklist & Rules", icon: Ban },
      { id: "rules", label: "Policy Engine", icon: SlidersHorizontal },
    ],
  },
  {
    title: "Exercises",
    items: [{ id: "drills", label: "Attack Drills", icon: Swords }],
  },
  {
    title: "Automate",
    items: [{ id: "integrations", label: "Integrations & Webhooks", icon: Webhook }],
  },
];

export function SocSidebar({
  active,
  onNavigate,
  open,
  onClose,
  width: externalWidth,
  onWidthChange,
}: {
  active: string;
  onNavigate: (tab: string) => void;
  open: boolean;
  onClose: () => void;
  width?: number;
  onWidthChange?: (w: number) => void;
}) {
  const { state } = useWaf();
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const now = useNow(1000);

  // Resizable sidebar width
  const sidebarWidth = externalWidth ?? 256;
  const setSidebarWidth = onWidthChange ?? (() => {});
  const widthRef = useRef(sidebarWidth);
  useEffect(() => { widthRef.current = sidebarWidth; }, [sidebarWidth]);

  const onResizePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    const startX = e.clientX;
    const startW = widthRef.current;
    const move = (ev: PointerEvent) => {
      setSidebarWidth(clampSidebarWidth(startW + (ev.clientX - startX)));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      try { localStorage.setItem(SIDEBAR_WIDTH_KEY, String(widthRef.current)); } catch { /* ignore */ }
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const activeAlerts = state.alarms.filter((a) => a.state === "active").length;
  const investigating = state.incidents.filter((i) => i.stage === "investigating").length;
  const openFindings = state.findings.filter((f) => f.status === "open").length;
  const activeBans = state.blocklist.filter((b) => b.active).length;

  const isSuperAdmin = Boolean(user?.isSuperAdmin);

  // Filter navigation items for non-admin users
  const filteredNavGroups = NAV_GROUPS.map((group) => {
    const visibleItems = group.items.filter((item) => {
      if (!isSuperAdmin) {
        // Non-admin cannot see findings, canaries, or integrations
        if (item.id === "findings" || item.id === "canaries" || item.id === "integrations") {
          return false;
        }
      }
      return true;
    });
    return {
      ...group,
      items: visibleItems,
    };
  }).filter((group) => group.items.length > 0);

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const badgeFor = (id: string): number => {
    if (id === "alerts") return activeAlerts;
    if (id === "incidents") return investigating;
    if (id === "findings") return openFindings;
    if (id === "access") return activeBans;
    return 0;
  };

  return (
    <>
      {open && (
        <div className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden" onClick={onClose} />
      )}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex flex-col border-r border-border/60 bg-background/95 backdrop-blur-xl transition-transform duration-200",
          open ? "translate-x-0" : "-translate-x-full",
          "lg:translate-x-0",
        )}
      >
        {/* brand */}
        <div className="flex shrink-0 items-center justify-between border-b border-border/50" style={{ height: Math.round(sidebarWidth * 0.17), paddingLeft: Math.round(sidebarWidth * 0.05), paddingRight: Math.round(sidebarWidth * 0.05) }}>
          <button
            type="button"
            onClick={() => {
              onNavigate("overview");
            }}
            className="flex items-center gap-2.5"
          >
            <div className="flex items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400 to-emerald-400 shadow-[0_0_16px_rgba(34,211,238,0.35)]" style={{ width: Math.round(sidebarWidth * 0.1), height: Math.round(sidebarWidth * 0.1) }}>
              <ShieldCheck className="text-[#04121c]" style={{ width: Math.round(sidebarWidth * 0.05), height: Math.round(sidebarWidth * 0.05) }} />
            </div>
            <span className="leading-tight text-left">
              <span className="block font-bold tracking-tight text-foreground" style={{ fontSize: Math.min(16, Math.round(sidebarWidth * 0.06)) }}>
                WebGuard<span className="text-wg-cyan">.</span>
              </span>
              <span className="block text-[9px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">
                AI WAF · SOC
              </span>
            </span>
          </button>
          <button
            type="button"
            onClick={onClose}
            className="flex size-8 items-center justify-center rounded-lg text-muted-foreground hover:text-foreground lg:hidden"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* nav */}
        <nav className="flex-1 overflow-y-auto py-4" style={{ paddingLeft: Math.round(sidebarWidth * 0.04), paddingRight: Math.round(sidebarWidth * 0.04) }}>
          {filteredNavGroups.map((group) => (
            <div key={group.title} className="mb-5">
              <p className="mb-1.5 text-[9px] font-bold uppercase tracking-[0.2em] text-muted-foreground/70" style={{ paddingLeft: Math.round(sidebarWidth * 0.02), paddingRight: Math.round(sidebarWidth * 0.02) }}>
                {group.title}
              </p>
              <div className="flex flex-col gap-0.5">
                {group.items.map(({ id, label, icon: Icon }) => {
                  const isActive = active === id;
                  const badge = badgeFor(id);
                  return (
                    <button
                      key={id}
                      type="button"
                      onClick={() => onNavigate(id)}
                      className={cn(
                        "group flex items-center gap-2.5 rounded-lg border font-medium transition-colors",
                        isActive
                          ? "border-primary/30 bg-primary/10 text-primary"
                          : "border-transparent text-muted-foreground hover:bg-muted/50 hover:text-foreground",
                      )}
                      style={{ height: Math.round(sidebarWidth * 0.11), paddingLeft: Math.round(sidebarWidth * 0.03), paddingRight: Math.round(sidebarWidth * 0.03), fontSize: Math.min(14, Math.round(sidebarWidth * 0.052)) }}
                    >
                      <Icon className={cn("shrink-0", isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} style={{ width: Math.round(sidebarWidth * 0.055), height: Math.round(sidebarWidth * 0.055) }} />
                      <span className="flex-1 truncate text-left">{label}</span>
                      {id === "drills" && state.drill && !state.drill.done && (
                        <span className="flex shrink-0 items-center gap-1 rounded border border-wg-violet/40 bg-wg-violet/10 px-1 py-px font-mono text-[8px] font-bold text-wg-violet">
                          <span className="size-1 animate-pulse rounded-full bg-wg-violet" />
                          LIVE
                        </span>
                      )}
                      {badge > 0 && (
                        <span
                          className={cn(
                            "flex h-4 min-w-4 items-center justify-center rounded-full px-1 font-mono text-[9px] font-bold",
                            id === "alerts" || id === "findings"
                              ? "bg-wg-rose/15 text-wg-rose"
                              : "bg-wg-amber/15 text-wg-amber",
                          )}
                        >
                          {badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* mode + user */}
        <div className="shrink-0 border-t border-border/50" style={{ padding: Math.round(sidebarWidth * 0.04) }}>
          <div className="rounded-xl border border-border/50 bg-muted/40 p-3">
            <p className="wg-kicker mb-1.5">Edge status</p>
            <ModeBadge mode={state.mode} />
            <p className="mt-2 flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" />
              {state.mode === "blocking"
                ? "Virtual patches live · 403 on match"
                : state.mode === "detection"
                  ? "Log only — origin exposed"
                  : "Unprotected — raw origin traffic"}
            </p>
            <div className="mt-2 flex items-center justify-between border-t border-border/40 pt-2 text-[9.5px] text-muted-foreground/80">
              <span className="flex items-center gap-1 font-mono">
                <Activity className="size-3 text-wg-cyan" />
                session {fmtDuration(now - state.sessionStartedAt)}
              </span>
              <span className="flex items-center gap-1" title="All SOC state is saved to this browser between sessions">
                <Database className="size-3 text-wg-emerald" />
                saved locally
              </span>
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2 rounded-xl border border-border/50 bg-muted/30 px-2.5 py-2">
            <div className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-[10px] font-bold text-primary">
              {(user?.name ?? user?.email ?? "O")[0]?.toUpperCase()}
            </div>
            <div className="min-w-0 flex-1 leading-tight">
              <p className="truncate text-xs font-medium text-foreground">{user?.name ?? "SOC Operator"}</p>
              <p className="truncate text-[10px] text-muted-foreground">{user?.email ?? "operator@webguard.dev"}</p>
            </div>
            <button
              type="button"
              title="Sign out"
              onClick={handleSignOut}
              className="flex size-7 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-wg-rose/10 hover:text-wg-rose"
            >
              <LogOut className="size-3.5" />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
