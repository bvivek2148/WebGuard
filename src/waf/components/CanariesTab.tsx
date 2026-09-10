import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { uid, useWaf } from "../engine";
import type { CanaryToken } from "../types";
import { SectionTitle, timeAgo, useNow } from "./shared";
import { Bomb, Plus, ShieldAlert, Trash2, Trophy, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

const TRIP_IPS = ["91.134.22.7", "45.155.4.12", "159.65.81.9", "128.199.44.2", "103.5.140.22"];

const PLACEMENT_PRESETS = [
  "HTML comment (homepage)",
  "Hidden form input (login)",
  "Custom response header",
  "Fake .env credential",
  "Honeypot API route",
];

export function CanariesTab() {
  const now = useNow(1000);
  const { state, dispatch } = useWaf();
  const [placement, setPlacement] = useState("");

  const addCanary = () => {
    const token: CanaryToken = {
      id: uid("CAN"),
      key: Math.random().toString(16).slice(2, 10),
      placement: placement.trim() || "HTML comment (homepage)",
      trips: 0,
      lastIp: null,
      banned: false,
      createdAt: Date.now(),
    };
    dispatch({ type: "ADD_CANARY", token });
    setPlacement("");
  };

  const armed = state.canaries.filter((c) => !c.banned).length;
  const totalTrips = state.canaries.reduce((s, c) => s + c.trips, 0);
  const canaryBans = state.blocklist.filter((b) => b.source === "canary" && b.active).length;
  const placementOf = (id: string) => state.canaries.find((c) => c.id === id)?.placement ?? "—";
  const maxTrips = Math.max(1, ...state.canaries.map((c) => c.trips));
  const ranked = [...state.canaries].sort((a, b) => b.trips - a.trips);
  const detectionRate = totalTrips > 0 ? Math.round((canaryBans / totalTrips) * 100) : 0;

  // Unique IPs that have tripped tokens, with ban status + counts
  const tripSources = useMemo(() => {
    const byIp = new Map<string, number>();
    for (const t of state.canaryTrips) byIp.set(t.ip, (byIp.get(t.ip) ?? 0) + 1);
    return [...byIp.entries()]
      .map(([ip, n]) => ({ ip, n, banned: state.blocklist.some((b) => b.ip === ip && b.active) }))
      .sort((a, b) => b.n - a.n)
      .slice(0, 6);
  }, [state.canaryTrips, state.blocklist]);

  const deployPreset = (p: string) => {
    dispatch({
      type: "ADD_CANARY",
      token: {
        id: uid("CAN"),
        key: Math.random().toString(16).slice(2, 10),
        placement: p,
        trips: 0,
        lastIp: null,
        banned: false,
        createdAt: Date.now(),
      },
    });
  };

  return (
    <div className="flex flex-col gap-4">
      {/* stats strip */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <CanaryStat icon={<Bomb className="size-4" />} label="Armed tokens" value={armed} accent="text-wg-cyan" sub="live tripwires" />
        <CanaryStat icon={<Zap className="size-4" />} label="Total trips" value={totalTrips} accent="text-wg-amber" sub="attacker touches" />
        <CanaryStat icon={<ShieldAlert className="size-4" />} label="Canary bans" value={canaryBans} accent="text-wg-rose" sub="IPs auto-blocked" />
        <CanaryStat icon={<Bomb className="size-4" />} label="Trips · 24h" value={state.canaryTrips.filter((t) => now - t.ts <= 86_400_000).length} accent="text-wg-emerald" sub="recent activity" />
        <CanaryStat icon={<Trophy className="size-4" />} label="Detection rate" value={detectionRate} accent="text-wg-sky" sub="bans per trip" suffix="%" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <div className="flex flex-col gap-4 xl:col-span-3">
      <div className="wg-panel p-4">
        <SectionTitle
          title="Canary tokens"
          sub="Decoy credentials and markers planted across the origin. Any use is a trip — attackers get banned automatically."
          right={
            <Badge variant="outline" className="gap-1.5 border-border/50 text-[10px] text-muted-foreground">
              <Bomb className="size-3" /> {state.canaries.filter((c) => !c.banned).length} armed
            </Badge>
          }
        />

        {/* add form */}
        <div className="mb-3 flex flex-col gap-2 sm:flex-row">
          <Input
            value={placement}
            onChange={(e) => setPlacement(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addCanary()}
            placeholder="Placement hint — e.g. Hidden form input (login)"
            className="h-9 flex-1 border-border/60 bg-muted/50 text-xs focus-visible:ring-cyan-400/40"
          />
          <Button className="h-9 gap-2 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20" onClick={addCanary}>
            <Plus className="size-4" /> Deploy token
          </Button>
        </div>
        <div className="mb-4 flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Presets — click to stage, ⚡ to deploy</span>
          {PLACEMENT_PRESETS.map((p) => (
            <span key={p} className="flex items-center gap-1 rounded-md border border-border/50 bg-muted/40 p-1">
              <button
                type="button"
                onClick={() => setPlacement(p)}
                className="rounded px-2 py-1 text-[11px] text-foreground/80 transition-colors hover:text-wg-cyan"
              >
                {p}
              </button>
              <button
                type="button"
                title={`Deploy “${p}” now`}
                onClick={() => deployPreset(p)}
                className="rounded p-1 text-[11px] text-wg-emerald transition-colors hover:bg-wg-emerald/10"
              >
                <Zap className="size-3" />
              </button>
            </span>
          ))}
        </div>

        <div className="overflow-x-auto rounded-xl border border-border/40">
          <table className="w-full border-collapse text-left">
            <thead className="bg-muted/90">
              <tr className="border-b border-border/60 text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-3 py-2 font-semibold">ID</th>
                <th className="px-3 py-2 font-semibold">Token</th>
                <th className="px-3 py-2 font-semibold">Placement</th>
                <th className="px-3 py-2 text-center font-semibold">Trips</th>
                <th className="px-3 py-2 font-semibold">Last tripped by</th>
                <th className="px-3 py-2 font-semibold">Deployed</th>
                <th className="px-3 py-2 text-center font-semibold">Banned</th>
                <th className="px-3 py-2 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.canaries.map((c) => (
                <tr key={c.id} className="border-b border-border/25 last:border-0">
                  <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{c.id}</td>
                  <td className="px-3 py-2">
                    <code className="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-[11px] text-wg-emerald">{c.key}</code>
                  </td>
                  <td className="max-w-[200px] truncate px-3 py-2 text-xs text-foreground/80">{c.placement}</td>
                  <td className="px-3 py-2 text-center">
                    <span className={c.trips > 0 ? "font-mono text-xs font-bold text-wg-rose" : "font-mono text-xs text-muted-foreground"}>
                      {c.trips}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{c.lastIp ?? "—"}</td>
                  <td className="px-3 py-2 text-[11px] text-muted-foreground">{timeAgo(c.createdAt)}</td>
                  <td className="px-3 py-2 text-center">
                    <Switch
                      checked={c.banned}
                      onCheckedChange={() => dispatch({ type: "TOGGLE_CANARY", id: c.id })}
                      className={c.banned ? "data-[state=checked]:bg-wg-rose" : ""}
                    />
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-1.5">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        title="Simulate a trip"
                        className="text-wg-amber"
                        onClick={() =>
                          dispatch({
                            type: "TRIP_CANARY",
                            id: c.id,
                            ip: TRIP_IPS[Math.floor(Math.random() * TRIP_IPS.length)],
                          })
                        }
                      >
                        <Zap className="size-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        title="Remove token"
                        className="text-rose-400"
                        onClick={() => dispatch({ type: "REMOVE_CANARY", id: c.id })}
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
              {state.canaries.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-12 text-center text-xs text-muted-foreground">
                    No canaries deployed — attackers have no tripwires to step on.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <p className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <ShieldAlert className="size-3.5 text-wg-amber" />
          When a token trips 3×, the offending IP is auto-banned at the edge and appears in the IP blocklist. Zap ⚡ simulates a live trip.
        </p>
      </div>
      </div>

        {/* effectiveness + recent trips */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          <div className="wg-panel p-4">
            <SectionTitle
              title="Trap effectiveness"
              sub="Which decoys catch the most hands — ranked by trips"
              right={
                <Badge variant="outline" className="gap-1 border-border/50 text-[10px] text-muted-foreground">
                  <Trophy className="size-3 text-wg-amber" /> {ranked[0]?.placement ?? "—"}
                </Badge>
              }
            />
            <div className="flex flex-col gap-2">
              {ranked.map((c, i) => (
                <div key={c.id} className="flex items-center gap-2.5">
                  <span className="w-4 font-mono text-[10px] font-bold text-muted-foreground/60">{i + 1}</span>
                  <span className="w-36 shrink-0 truncate text-[11px] text-foreground/80">{c.placement}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                    <div
                      className={cn("h-full rounded-full", c.banned ? "bg-gradient-to-r from-wg-rose to-wg-orange" : "bg-gradient-to-r from-wg-cyan to-wg-emerald")}
                      style={{ width: `${(c.trips / maxTrips) * 100}%` }}
                    />
                  </div>
                  <span className={cn("w-6 text-right font-mono text-[11px] font-bold", c.trips > 0 ? "text-wg-rose" : "text-muted-foreground")}>
                    {c.trips}
                  </span>
                </div>
              ))}
              {state.canaries.length === 0 && (
                <p className="py-6 text-center text-xs text-muted-foreground">Deploy a token to start measuring.</p>
              )}
            </div>
          </div>

          <div className="wg-panel p-4">
            <SectionTitle
              title="Trip feed"
              sub="Every canary touch, newest first — auto-bans fire on the 3rd trip"
              right={
                <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
                  {state.canaryTrips.length} events
                </Badge>
              }
            />
            <div className="flex flex-col">
              {state.canaryTrips.slice(0, 8).map((t, i) => {
                const token = state.canaries.find((c) => c.id === t.tokenId);
                return (
                  <div key={t.id} className="flex items-start gap-3 border-b border-border/30 py-2.5 last:border-0">
                    <span className={cn(
                      "mt-1 flex size-6 shrink-0 items-center justify-center rounded-full border font-mono text-[9px] font-bold",
                      (token?.trips ?? 0) >= 3
                        ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose"
                        : "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
                    )}>
                      {i + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-medium text-foreground">{placementOf(t.tokenId)}</p>
                      <p className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[11px] text-muted-foreground">
                        <span className="font-mono text-wg-rose">{t.ip}</span>
                        <span>·</span>
                        <span>{timeAgo(t.ts)}</span>
                        {(token?.trips ?? 0) >= 3 && (
                          <span className="rounded border border-wg-rose/40 bg-wg-rose/10 px-1 text-[9px] font-bold text-wg-rose">
                            BANNED
                          </span>
                        )}
                      </p>
                    </div>
                  </div>
                );
              })}
              {state.canaryTrips.length === 0 && (
                <p className="py-8 text-center text-xs text-muted-foreground">No trips yet — the traps are still clean.</p>
              )}
            </div>
          </div>

          <div className="wg-panel p-4">
            <SectionTitle
              title="Trip sources"
              sub="Hostile IPs that touched a decoy — ban any that are still roaming"
              right={
                <Badge variant="outline" className="border-border/50 text-[10px] text-muted-foreground">
                  {tripSources.length} unique
                </Badge>
              }
            />
            <div className="flex flex-col">
              {tripSources.map((s) => (
                <div key={s.ip} className="flex items-center gap-2.5 border-b border-border/30 py-2 last:border-0">
                  <span className="w-5 shrink-0 text-right font-mono text-[11px] font-bold text-muted-foreground/60">
                    {s.n}×
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground/90">{s.ip}</span>
                  {s.banned ? (
                    <span className="rounded border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 text-[9px] font-bold text-wg-rose">BANNED</span>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 gap-1 border-wg-rose/40 text-[10px] text-wg-rose hover:bg-wg-rose/10"
                      onClick={() =>
                        dispatch({
                          type: "ADD_BLOCKED_IP",
                          entry: {
                            id: uid("BAN"),
                            ip: s.ip,
                            reason: `Canary trip source — ${s.n} touch${s.n > 1 ? "es" : ""}`,
                            source: "manual",
                            country: "—",
                            countryCode: "—",
                            addedAt: Date.now(),
                            hits: 0,
                            active: true,
                            expiresAt: null,
                          },
                        })
                      }
                    >
                      <ShieldAlert className="size-3" /> Ban
                    </Button>
                  )}
                </div>
              ))}
              {tripSources.length === 0 && (
                <p className="py-6 text-center text-xs text-muted-foreground">No trip sources yet.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function CanaryStat({
  icon,
  label,
  value,
  accent,
  sub,
  suffix = "",
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  accent: string;
  sub: string;
  suffix?: string;
}) {
  return (
    <div className="wg-panel flex items-start justify-between gap-3 p-4">
      <div className="min-w-0">
        <p className="wg-kicker">{label}</p>
        <div className="mt-1.5 text-2xl font-semibold tracking-tight text-foreground">
          {value}
          {suffix && <span className="ml-0.5 text-sm font-medium text-muted-foreground">{suffix}</span>}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
      </div>
      <div className={cn("shrink-0 rounded-lg border border-border/60 bg-background/60 p-2", accent)}>{icon}</div>
    </div>
  );
}
