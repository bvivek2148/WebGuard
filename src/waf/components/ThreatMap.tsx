import { useMemo, useState } from "react";
import type { CSSProperties } from "react";
import { cn } from "@/lib/utils";
import type { AttackType, BlockedIp, RequestLog } from "../types";
import { ATTACK_LABELS } from "../types";
import { SERVER_ORIGIN } from "../data";
import { flagEmoji, fmtCompact, useNow } from "./shared";

// Approximate country centroids for banned subnets that lack precise geo.
const COUNTRY_COORDS: Record<string, [number, number]> = {
  DE: [51.16, 10.45],
  SG: [1.35, 103.82],
  JP: [36.2, 138.25],
  US: [39.8, -98.5],
  RU: [61.5, 105.3],
  BR: [-14.2, -51.9],
  IN: [20.6, 78.9],
  GB: [54.0, -2.4],
  NL: [52.2, 5.2],
  FR: [46.6, 2.2],
  AU: [-25.0, 133.8],
  CA: [56.1, -106.3],
};

const W = 1000;
const H = 460;

function project(lat: number, lon: number): [number, number] {
  return [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];
}

interface Cluster {
  city: string;
  code: string;
  lat: number;
  lon: number;
  count: number;
  attacks: number;
  rps: number;
  threat: number; // avg threat score across requests from this hotspot
}

export function ThreatMap({ logs, blocklist }: { logs: RequestLog[]; blocklist?: BlockedIp[] }) {
  const [hover, setHover] = useState<Cluster | null>(null);
  const now = useNow(1000);

  const clusters = useMemo<Cluster[]>(() => {
    const recent = logs.filter((l) => now - l.ts <= 90_000);
    const byCity = new Map<string, Cluster>();
    for (const l of recent) {
      const key = l.city;
      const c = byCity.get(key);
      if (c) {
        c.count += 1;
        if (l.attackType) c.attacks += 1;
        c.threat += l.threatScore;
      } else {
        byCity.set(key, {
          city: l.city,
          code: l.countryCode,
          lat: l.lat,
          lon: l.lon,
          count: 1,
          attacks: l.attackType ? 1 : 0,
          rps: 0,
          threat: l.threatScore,
        });
      }
    }
    const out = [...byCity.values()];
    const span = Math.max(1, (now - Math.min(...recent.map((l) => l.ts))) / 1000);
    for (const c of out) c.threat = Math.round(c.threat / Math.max(1, c.count));
    for (const c of out) c.rps = c.count / span;
    return out.sort((a, b) => b.count - a.count);
  }, [logs, now]);

  // Attack-class mix across the 90s window — what the hostile dots actually are
  const attackMix = useMemo(() => {
    const counts = new Map<AttackType, number>();
    for (const l of logs) {
      if (now - l.ts > 90_000 || !l.attackType) continue;
      counts.set(l.attackType, (counts.get(l.attackType) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [logs, now]);
  const maxMix = Math.max(1, ...attackMix.map(([, n]) => n));

  const bans = useMemo(() => {
    const byCode = new Map<string, number>();
    for (const b of blocklist ?? []) {
      if (!b.active) continue;
      if (b.countryCode && b.countryCode !== "—") byCode.set(b.countryCode, (byCode.get(b.countryCode) ?? 0) + 1);
    }
    return [...byCode.entries()].map(([code, n]) => ({
      code,
      n,
      coords: COUNTRY_COORDS[code] ?? [20, 20],
    }));
  }, [blocklist]);

  // 90s-window stats for the footer — same window as the clusters
  const windowStats = useMemo(() => {
    const recent = logs.filter((l) => now - l.ts <= 90_000);
    const hostile = recent.filter((l) => l.attackType).length;
    const blocked = recent.filter((l) => l.blocked).length;
    return {
      requests: recent.length,
      hostile,
      blocked,
      countries: new Set(recent.map((l) => l.countryCode)).size,
      hostilePct: recent.length ? Math.round((hostile / recent.length) * 100) : 0,
    };
  }, [logs, now]);

  const [sx, sy] = project(SERVER_ORIGIN.lat, SERVER_ORIGIN.lon);
  const maxCount = Math.max(1, ...clusters.map((c) => c.count));

  return (
    <div className="relative overflow-hidden rounded-2xl border border-border/70 bg-card">
      <svg viewBox={`0 0 ${W} ${H}`} className="block w-full">
        <defs>
          <radialGradient id="wg-map-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(34,211,238,0.16)" />
            <stop offset="100%" stopColor="rgba(34,211,238,0)" />
          </radialGradient>
          <linearGradient id="wg-arc" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#fb7185" stopOpacity="0.05" />
            <stop offset="50%" stopColor="#22d3ee" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#34d399" stopOpacity="0.2" />
          </linearGradient>
          <style>{`
            @keyframes wg-arc-draw { from { stroke-dashoffset: var(--arc-len); } to { stroke-dashoffset: 0; } }
            @keyframes wg-ring { 0% { transform: scale(0.6); opacity: 0.9; } 100% { transform: scale(2.4); opacity: 0; } }
            .wg-arc { animation: wg-arc-draw 1.4s ease-out both; }
            .wg-ring { transform-box: fill-box; transform-origin: center; animation: wg-ring 2.4s ease-out infinite; }
          `}</style>
        </defs>

        <rect x="0" y="0" width={W} height={H} fill="url(#wg-map-glow)" />

        {/* graticule */}
        {Array.from({ length: 13 }).map((_, i) => (
          <line key={`v${i}`} x1={(i / 12) * W} y1="0" x2={(i / 12) * W} y2={H} stroke="rgba(96,150,220,0.07)" strokeWidth="1" />
        ))}
        {Array.from({ length: 7 }).map((_, i) => (
          <line key={`h${i}`} x1="0" y1={(i / 6) * H} x2={W} y2={(i / 6) * H} stroke="rgba(96,150,220,0.07)" strokeWidth="1" />
        ))}

        {/* arcs: origin → protected origin */}
        {clusters.map((c, i) => {
          const [x, y] = project(c.lat, c.lon);
          const mx = (x + sx) / 2;
          const my = Math.min(y, sy) - Math.abs(sx - x) * 0.22 - 14;
          const len = Math.hypot(sx - x, sy - y) + 120;
          return (
            <path
              key={c.city}
              d={`M ${x} ${y} Q ${mx} ${my} ${sx} ${sy}`}
              fill="none"
              stroke="url(#wg-arc)"
              strokeWidth={c.attacks > 0 ? 1.6 : 1}
              strokeDasharray={len}
              className="wg-arc"
              style={{ animationDelay: `${i * 90}ms` } as CSSProperties}
              opacity={c.attacks > 0 ? 0.9 : 0.45}
            />
          );
        })}

        {/* origin dots */}
        {clusters.map((c) => {
          const [x, y] = project(c.lat, c.lon);
          const r = 3 + (c.count / maxCount) * 9;
          const hostile = c.attacks / Math.max(1, c.count) > 0.35;
          return (
            <g
              key={`d${c.city}`}
              onMouseEnter={() => setHover(c)}
              onMouseLeave={() => setHover(null)}
              style={{ cursor: "pointer" }}
            >
              <circle cx={x} cy={y} r={r + 6} fill={hostile ? "rgba(244,63,94,0.14)" : "rgba(34,211,238,0.12)"} />
              <circle
                cx={x}
                cy={y}
                r={r}
                fill={hostile ? "#fb7185" : "#22d3ee"}
                style={{ filter: `drop-shadow(0 0 6px ${hostile ? "#fb7185" : "#22d3ee"})` }}
              />
              {c.attacks > 0 && (
                <circle cx={x} cy={y} r={r} fill="none" stroke="#fb7185" strokeWidth="1" className="wg-ring" />
              )}
            </g>
          );
        })}

        {/* banned subnets — red X pins */}
        {bans.map((b) => {
          const [x, y] = project(b.coords[0], b.coords[1]);
          return (
            <g key={`ban-${b.code}`}>
              <circle cx={x} cy={y} r="11" fill="rgba(244,63,94,0.14)" className="wg-ring" />
              <path
                d={`M ${x - 4.5} ${y - 4.5} L ${x + 4.5} ${y + 4.5} M ${x + 4.5} ${y - 4.5} L ${x - 4.5} ${y + 4.5}`}
                stroke="#f43f5e"
                strokeWidth="2.2"
                strokeLinecap="round"
                style={{ filter: "drop-shadow(0 0 7px rgba(244,63,94,0.9))" }}
              />
              <text
                x={x}
                y={y - 14}
                textAnchor="middle"
                fill="#f43f5e"
                fontSize="9"
                fontWeight="700"
                fontFamily="ui-monospace, monospace"
              >
                {b.code} ×{b.n}
              </text>
            </g>
          );
        })}

        {/* protected origin node */}
        <circle cx={sx} cy={sy} r="26" fill="rgba(52,211,153,0.12)" />
        <circle cx={sx} cy={sy} r="14" fill="none" stroke="#34d399" strokeWidth="1.2" className="wg-ring" />
        <circle cx={sx} cy={sy} r="6" fill="#34d399" style={{ filter: "drop-shadow(0 0 8px #34d399)" }} />
        <text x={sx} y={sy - 18} textAnchor="middle" fill="#34d399" fontSize="11" fontWeight="600" fontFamily="ui-monospace, monospace">
          ORIGIN
        </text>
      </svg>

      {/* hover tooltip — cluster details at the exact dot position */}
      {hover && (() => {
        const [hx, hy] = project(hover.lat, hover.lon);
        const share = Math.round((hover.attacks / Math.max(1, hover.count)) * 100);
        const level = hover.threat >= 70 ? "CRITICAL" : hover.threat >= 45 ? "ELEVATED" : hover.threat >= 25 ? "GUARDED" : "LOW";
        const levelTone =
          hover.threat >= 70
            ? "border-wg-rose/50 bg-wg-rose/10 text-wg-rose"
            : hover.threat >= 45
              ? "border-wg-amber/50 bg-wg-amber/10 text-wg-amber"
              : hover.threat >= 25
                ? "border-wg-sky/50 bg-wg-sky/10 text-wg-sky"
                : "border-wg-emerald/50 bg-wg-emerald/10 text-wg-emerald";
        return (
          <div
            className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-[calc(100%+14px)] rounded-lg border border-border/60 bg-popover/95 px-3 py-2 shadow-xl backdrop-blur"
            style={{ left: `${(hx / W) * 100}%`, top: `${(hy / H) * 100}%` }}
          >
            <p className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
              <span className="text-sm leading-none">{flagEmoji(hover.code)}</span>
              {hover.city}
              <span className="text-[9px] font-normal uppercase tracking-wider text-muted-foreground">{hover.code}</span>
            </p>
            <div className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-0.5 text-[10px]">
              <span className="text-muted-foreground">requests</span>
              <span className="text-right font-mono text-foreground/90">{hover.count}</span>
              <span className="text-muted-foreground">hostile</span>
              <span className="text-right font-mono text-wg-rose">{hover.attacks} · {share}%</span>
              <span className="text-muted-foreground">avg threat</span>
              <span className="text-right font-mono text-foreground/90">{hover.threat}/100</span>
              <span className="text-muted-foreground">velocity</span>
              <span className="text-right font-mono text-foreground/90">{hover.rps.toFixed(1)} rps</span>
            </div>
            <span className={cn("mt-1.5 inline-block rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-widest", levelTone)}>
              THREAT · {level}
            </span>
          </div>
        );
      })()}

      {/* legend (desktop overlay) */}
      <div className="pointer-events-none absolute bottom-3 left-3 hidden flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-border/50 bg-muted/60 px-3 py-1.5 backdrop-blur sm:flex">
        <span className="flex items-center gap-1.5 text-[10px] text-foreground/80">
          <span className="size-2 rounded-full bg-cyan-400" /> benign
        </span>
        <span className="flex items-center gap-1.5 text-[10px] text-foreground/80">
          <span className="size-2 rounded-full bg-rose-400" /> hostile
        </span>
        <span className="flex items-center gap-1.5 text-[10px] text-foreground/80">
          <span className="size-2 rounded-full bg-emerald-400" /> protected origin
        </span>
        {bans.length > 0 && (
          <span className="flex items-center gap-1.5 text-[10px] text-wg-rose">
            <span className="font-mono text-[9px] font-bold">✕</span> banned ({bans.reduce((s, b) => s + b.n, 0)})
          </span>
        )}
        <span className="flex items-center gap-1.5 text-[10px] text-foreground/80">
          <span className="h-1.5 w-12 rounded-full bg-gradient-to-r from-cyan-400 via-amber-400 to-rose-500" />
          intensity
        </span>
      </div>

      {/* right column — hotspots with intensity bars + live attack mix */}
      <div className="absolute right-3 top-3 hidden w-[220px] flex-col gap-1.5 md:flex">
        <div className="flex flex-col gap-1 rounded-lg border border-border/50 bg-muted/60 p-2.5 backdrop-blur">
          <p className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
            <span className="relative flex size-1.5">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-rose-400 opacity-75" />
              <span className="relative inline-flex size-1.5 rounded-full bg-rose-400" />
            </span>
            Hotspots · 90s
          </p>
          {clusters.slice(0, 5).map((c) => {
            const hostileShare = c.attacks / Math.max(1, c.count);
            return (
              <div key={c.city} className="flex items-center justify-between gap-3 text-[11px]">
                <span className="flex min-w-0 items-center gap-1.5 text-foreground/80">
                  <span className="text-sm leading-none">{flagEmoji(c.code)}</span>
                  <span className="truncate">{c.city}</span>
                </span>
                <span
                  className={cn(
                    "flex shrink-0 items-center gap-2",
                    c.attacks > 0 ? "font-mono font-semibold text-wg-rose" : "font-mono text-muted-foreground",
                  )}
                >
                  {c.attacks > 0 ? `⚠ ${c.attacks}/${c.count}` : `${fmtCompact(c.count)}`}
                  <span className="flex h-1 w-10 overflow-hidden rounded-full bg-border/40">
                    <span
                      className={cn("h-full rounded-full", hostileShare > 0.35 ? "bg-wg-rose" : "bg-wg-cyan")}
                      style={{ width: `${Math.round(hostileShare * 100)}%` }}
                    />
                  </span>
                </span>
              </div>
            );
          })}
        </div>

        {attackMix.length > 0 && (
          <div className="flex flex-col gap-1.5 rounded-lg border border-border/50 bg-muted/60 p-2.5 backdrop-blur">
            <p className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
              <span className="size-1.5 animate-pulse rounded-full bg-rose-400" />
              Attack mix · 90s
            </p>
            {attackMix.map(([t, n]) => (
              <div key={t} className="flex items-center gap-2 text-[10px]">
                <span className="w-[84px] shrink-0 truncate text-foreground/75">{ATTACK_LABELS[t]}</span>
                <span className="h-1 flex-1 overflow-hidden rounded-full bg-border/40">
                  <span
                    className="block h-full rounded-full bg-gradient-to-r from-wg-rose to-wg-orange"
                    style={{ width: `${(n / maxMix) * 100}%` }}
                  />
                </span>
                <span className="w-5 shrink-0 text-right font-mono text-muted-foreground">{n}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* live stats footer (desktop overlay) */}
      <div className="absolute bottom-3 right-3 hidden items-center gap-3 rounded-lg border border-border/50 bg-muted/60 px-3 py-1.5 backdrop-blur xl:flex">
        <span className="flex items-center gap-1.5 font-mono text-[10px] text-foreground/90">
          <span className="size-1.5 rounded-full bg-cyan-400" />
          {fmtCompact(windowStats.requests)} req
        </span>
        <span className={cn("flex items-center gap-1.5 font-mono text-[10px]", windowStats.hostile > 0 ? "text-wg-rose" : "text-muted-foreground")}>
          <span className="size-1.5 rounded-full bg-rose-400" />
          {windowStats.hostile} hostile ({windowStats.hostilePct}%)
        </span>
        <span className="flex items-center gap-1.5 font-mono text-[10px] text-wg-emerald">
          <span className="size-1.5 rounded-full bg-emerald-400" />
          {windowStats.blocked} blocked
        </span>
        <span className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
          <span className="text-[11px] leading-none">🌐</span>
          {windowStats.countries} regions
        </span>
        <span className="flex items-center gap-1.5 font-mono text-[10px] text-wg-orange">
          <span className="size-1.5 rounded-full bg-orange-400" />
          {clusters.filter((c) => c.attacks > 0).length} hostile cities
        </span>
      </div>

      {/* mobile/tablet bar — legend + key stats stacked cleanly under the map (below xl) */}
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5 border-t border-border/40 bg-muted/40 px-3 py-2 text-[10px] xl:hidden">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="flex items-center gap-1.5 text-foreground/80">
            <span className="size-2 rounded-full bg-cyan-400" /> benign
          </span>
          <span className="flex items-center gap-1.5 text-foreground/80">
            <span className="size-2 rounded-full bg-rose-400" /> hostile
          </span>
          <span className="flex items-center gap-1.5 text-foreground/80">
            <span className="size-2 rounded-full bg-emerald-400" /> origin
          </span>
          {bans.length > 0 && (
            <span className="flex items-center gap-1 text-wg-rose">
              <span className="font-mono font-bold">✕</span> {bans.reduce((s, b) => s + b.n, 0)} banned
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono">
          <span className="text-wg-cyan">{fmtCompact(windowStats.requests)} req</span>
          <span className={windowStats.hostile > 0 ? "text-wg-rose" : "text-muted-foreground"}>
            {windowStats.hostile} hostile
          </span>
          <span className="text-wg-emerald">{windowStats.blocked} blocked</span>
        </div>
      </div>
    </div>
  );
}
