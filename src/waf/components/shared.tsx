import { cn } from "@/lib/utils";
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import type { HttpMethod, RequestLog, Severity, WafMode } from "../types";
import { ATTACK_LABELS, SEVERITY_META } from "../types";

export { timeAgo } from "../engine";

// ============================================================================
// Formatting helpers
// ============================================================================

export function fmtNum(n: number): string {
  return n.toLocaleString("en-US");
}

export function fmtCompact(n: number): string {
  return Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${m}:${pad(sec)}`;
}

/** Re-renders the calling component every `intervalMs` — for live clocks. */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(iv);
  }, [intervalMs]);
  return now;
}

export function flagEmoji(code: string): string {
  return code
    .toUpperCase()
    .replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

export function statusLabel(status: number): string {
  switch (status) {
    case 200:
      return "200 OK";
    case 301:
      return "301 Moved";
    case 403:
      return "403 Forbidden";
    case 404:
      return "404 Not Found";
    case 429:
      return "429 Throttled";
    case 500:
      return "500 Error";
    default:
      return String(status);
  }
}

export const METHOD_COLORS: Record<HttpMethod, string> = {
  GET: "text-wg-cyan",
  POST: "text-wg-emerald",
  PUT: "text-wg-amber",
  DELETE: "text-wg-rose",
  PATCH: "text-wg-violet",
  OPTIONS: "text-muted-foreground",
};

// ============================================================================
// Small presentational atoms
// ============================================================================

export function StatusBadge({ status, className }: { status: number; className?: string }) {
  const styles: Record<number, string> = {
    200: "bg-wg-emerald/10 text-wg-emerald border-wg-emerald/25",
    301: "bg-wg-sky/10 text-wg-sky border-wg-sky/25",
    403: "bg-wg-rose/10 text-wg-rose border-wg-rose/30",
    404: "bg-muted/50 text-foreground/80 border-border/20",
    429: "bg-wg-amber/10 text-wg-amber border-wg-amber/30",
    500: "bg-wg-orange/10 text-wg-orange border-wg-orange/30",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[11px] font-medium whitespace-nowrap",
        styles[status] ?? "bg-muted/50 text-foreground/80 border-border/20",
        className,
      )}
    >
      <span
        className={cn(
          "size-1.5 rounded-full",
          status === 200 && "bg-emerald-400",
          status === 403 && "bg-rose-400",
          status === 429 && "bg-amber-400",
          status === 500 && "bg-orange-400",
          status === 404 && "bg-slate-400",
          status === 301 && "bg-sky-400",
        )}
      />
      {statusLabel(status)}
    </span>
  );
}

export function ThreatPill({ score, attack }: { score: number; attack: boolean }) {
  const color =
    score >= 70
      ? "text-wg-rose border-wg-rose/40 bg-wg-rose/10"
      : score >= 40
        ? "text-wg-amber border-wg-amber/30 bg-wg-amber/10"
        : "text-muted-foreground border-border/25 bg-muted/50";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[11px] font-semibold whitespace-nowrap",
        color,
      )}
    >
      {attack && <span className="relative flex size-1.5">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
        <span className="relative inline-flex size-1.5 rounded-full bg-rose-400" />
      </span>}
      {score}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-bold tracking-wider",
        meta.badge,
        className,
      )}
    >
      {meta.label}
    </span>
  );
}

export function AttackChip({ attack, ruleId }: { attack: RequestLog["attackType"]; ruleId: string | null }) {
  if (!attack) return <span className="text-[11px] text-muted-foreground">benign</span>;
  return (
    <span className="inline-flex flex-col leading-tight">
      <span className="text-[11px] font-medium text-wg-rose">{ATTACK_LABELS[attack]}</span>
      {ruleId && <span className="font-mono text-[10px] text-muted-foreground">{ruleId}</span>}
    </span>
  );
}

export function ModeBadge({ mode, className }: { mode: WafMode; className?: string }) {
  const cfg = {
    blocking: { label: "BLOCKING", dot: "bg-emerald-400", text: "text-wg-emerald", border: "border-wg-emerald/40", bg: "bg-wg-emerald/10", ring: "shadow-[0_0_16px_rgba(52,211,153,0.25)]" },
    detection: { label: "DETECTION", dot: "bg-amber-400", text: "text-wg-amber", border: "border-wg-amber/40", bg: "bg-wg-amber/10", ring: "" },
    off: { label: "OFF", dot: "bg-rose-400", text: "text-wg-rose", border: "border-wg-rose/40", bg: "bg-wg-rose/10", ring: "" },
  }[mode];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-bold tracking-[0.14em]",
        cfg.bg,
        cfg.text,
        cfg.border,
        cfg.ring,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", cfg.dot, mode === "blocking" && "animate-pulse")} />
      WAF {cfg.label}
    </span>
  );
}

export function Kpi({
  label,
  value,
  sub,
  icon,
  accent = "text-wg-cyan",
  className,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: ReactNode;
  accent?: string;
  className?: string;
}) {
  return (
    <div className={cn("wg-panel flex items-start justify-between gap-3 p-4", className)}>
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <div className="mt-1.5 truncate text-2xl font-semibold tracking-tight text-foreground">{value}</div>
        {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
      </div>
      {icon && <div className={cn("shrink-0 rounded-lg border border-border/60 bg-background/60 p-2", accent)}>{icon}</div>}
    </div>
  );
}

export function SectionTitle({ title, sub, right }: { title: ReactNode; sub?: string; right?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
      <div>
        <h3 className="text-sm font-semibold text-foreground">{title}</h3>
        {sub && <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>}
      </div>
      {right}
    </div>
  );
}

export function EmptyState({ icon, title, sub }: { icon: ReactNode; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <div className="text-muted-foreground/70">{icon}</div>
      <p className="text-sm font-medium text-muted-foreground">{title}</p>
      {sub && <p className="max-w-sm text-xs text-muted-foreground">{sub}</p>}
    </div>
  );
}
