import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function SeverityPieTip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; payload?: { color?: string } }>;
}) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div className="rounded-lg border border-border/60 bg-popover/95 px-3 py-2 shadow-xl">
      <p className="flex items-center gap-2 text-xs">
        <span className="size-2 rounded-full" style={{ background: p.payload?.color }} />
        <span className="text-muted-foreground">{p.name}</span>
        <span className="ml-3 font-mono font-semibold text-foreground">{p.value} open</span>
      </p>
    </div>
  );
}

export function RunStat({
  icon,
  label,
  value,
  accent,
  sub,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  accent: string;
  sub: string;
}) {
  return (
    <div className="flex items-center gap-2.5 rounded-xl border border-border/40 bg-muted/30 p-3">
      <span
        className={cn(
          "flex size-8 shrink-0 items-center justify-center rounded-lg border border-border/60 bg-background/60",
          accent,
        )}
      >
        {icon}
      </span>
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <p className="font-mono text-sm font-bold text-foreground">{value}</p>
        <p className="truncate text-[10px] text-muted-foreground">{sub}</p>
      </div>
    </div>
  );
}
