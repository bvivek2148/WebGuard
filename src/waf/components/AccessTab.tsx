import { Fragment, useMemo, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { uid, useWaf } from "../engine";
import type { BanSource, CustomRuleMatch, RequestLog, RuleAction } from "../types";
import { ATTACK_LABELS } from "../types";
import { flagEmoji, SectionTitle, StatusBadge, timeAgo, useNow } from "./shared";
import { Ban, ClipboardCopy, FileDown, Globe2, History, Network, Plus, Radio, Route, Search, ShieldCheck, ShieldOff, Timer, Trash2, Upload, Zap } from "lucide-react";
import { ExportMenu } from "./ExportMenu";

const BAN_SOURCE_META: Record<string, { label: string; cls: string }> = {
  auto: { label: "AUTO", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" },
  canary: { label: "CANARY", cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" },
  manual: { label: "MANUAL", cls: "border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan" },
};

const MATCH_META: Record<CustomRuleMatch, { label: string; hint: string }> = {
  path: { label: "Path", hint: "/admin" },
  ip: { label: "IP / CIDR", hint: "185.220.0.0/16" },
  country: { label: "Country", hint: "ru" },
  ua: { label: "User-Agent", hint: "curl" },
  header: { label: "Header", hint: "x-api-key" },
};

const ACTION_OPTIONS: RuleAction[] = ["block", "challenge", "log", "disable"];

const BAN_DURATION_MS: Record<"permanent" | "1h" | "24h" | "7d", number | null> = {
  permanent: null,
  "1h": 3_600_000,
  "24h": 86_400_000,
  "7d": 604_800_000,
};

// Preview the first few hosts inside a /24 block — makes CIDR bans legible
function cidrPreview(ip: string): string[] {
  if (!ip.endsWith("/24")) return [];
  const base = ip.replace("/24", "");
  return [1, 2, 3, 4, 5, 254].map((h) => `${base}.${h}`);
}

// Country deny-list options — codes the telemetry simulator can actually produce
const GEO_COUNTRIES = [
  { code: "DE", name: "Germany" },
  { code: "US", name: "United States" },
  { code: "SG", name: "Singapore" },
  { code: "JP", name: "Japan" },
  { code: "AU", name: "Australia" },
  { code: "RU", name: "Russia" },
  { code: "GB", name: "United Kingdom" },
  { code: "NL", name: "Netherlands" },
  { code: "FR", name: "France" },
  { code: "IN", name: "India" },
  { code: "BR", name: "Brazil" },
];

const RULE_TEMPLATES: Array<{
  name: string;
  matchType: CustomRuleMatch;
  matchValue: string;
  action: RuleAction;
  desc: string;
}> = [
  { name: "Block /staging", matchType: "path", matchValue: "/staging", action: "block", desc: "403 for anything under /staging" },
  { name: "Challenge scrapers", matchType: "ua", matchValue: "python-requests", action: "challenge", desc: "CAPTCHA automated scraping clients" },
  { name: "Block RU uploads", matchType: "country", matchValue: "ru", action: "block", desc: "Deny upload flows from this region" },
  { name: "Log /api/v1 probes", matchType: "path", matchValue: "/api/v1", action: "log", desc: "Watch API probing without blocking" },
  { name: "Drop x-debug", matchType: "header", matchValue: "x-debug", action: "block", desc: "Reject requests carrying debug headers" },
];

export function AccessTab() {
  const { state, dispatch } = useWaf();
  const [banInput, setBanInput] = useState("");
  const [banDuration, setBanDuration] = useState<"permanent" | "1h" | "24h" | "7d">("permanent");
  const [expandedCidr, setExpandedCidr] = useState<string | null>(null);
  const [banQuery, setBanQuery] = useState("");
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [ruleName, setRuleName] = useState("");
  const [ruleType, setRuleType] = useState<CustomRuleMatch>("path");
  const [ruleValue, setRuleValue] = useState("");
  const [ruleAction, setRuleAction] = useState<RuleAction>("block");
  const [allowInput, setAllowInput] = useState("");
  const [allowLabel, setAllowLabel] = useState("");

  const activeBans = state.blocklist.filter((b) => b.active);
  const expiredBans = state.blocklist.filter((b) => !b.active).length;
  const activeRules = state.customRules.filter((r) => r.enabled);
  const edgeHits =
    state.blocklist.reduce((s, b) => s + b.hits, 0) + state.customRules.reduce((s, r) => s + r.hits, 0);
  const blockingRules = state.rules.filter((r) => r.action === "block").length;

  // ---- enforcement KPIs over the live window ----
  const nowMs = useNow(1000);
  const blocked30 = state.logs.filter((l) => l.blocked && nowMs - l.ts <= 30_000).length;
  const throttled30 = state.logs.filter((l) => l.throttled && nowMs - l.ts <= 30_000).length;
  const avgBanAge = useMemo(() => {
    if (activeBans.length === 0) return 0;
    return Math.round(activeBans.reduce((s, b) => s + (nowMs - b.addedAt), 0) / activeBans.length / 60_000);
  }, [activeBans, nowMs]);

  const customRuleNames = useMemo(() => new Map(state.customRules.map((r) => [r.id, r.name])), [state.customRules]);

  // ---- attacker intelligence: hostile IPs not yet blocked ----
  const suggestedBans = useMemo(() => {
    const byIp = new Map<string, { n: number; log: RequestLog }>();
    for (const l of state.logs) {
      if (!l.attackType || l.ruleId === "IP-BLOCKLIST" || l.ruleId === "ALLOWLIST") continue;
      const banned = state.blocklist.some((b) => b.active && matchesAddr(b.ip, l.ip));
      const trusted = state.allowlist.some((a) => matchesAddr(a.ip, l.ip));
      if (banned || trusted) continue;
      const cur = byIp.get(l.ip) ?? { n: 0, log: l };
      cur.n += 1;
      cur.log = l;
      byIp.set(l.ip, cur);
    }
    return [...byIp.values()].sort((a, b) => b.n - a.n).slice(0, 5);
  }, [state.logs, state.blocklist, state.allowlist]);

  // ---- blocked attack mix — what the blocklist + custom rules actually drop ----
  const blockedMix = useMemo(() => {
    const counts = new Map<string, number>();
    for (const l of state.logs) {
      if (!l.blocked) continue;
      if (l.attackType) {
        const k = ATTACK_LABELS[l.attackType];
        counts.set(k, (counts.get(k) ?? 0) + 1);
      } else if (customRuleNames.has(l.ruleId ?? "")) {
        const k = "Custom rules";
        counts.set(k, (counts.get(k) ?? 0) + 1);
      } else if (l.ruleId === "GEO-BLOCK") {
        const k = "Geo-block";
        counts.set(k, (counts.get(k) ?? 0) + 1);
      } else if (l.ruleId === "IP-BLOCKLIST") {
        const k = "IP blocklist";
        counts.set(k, (counts.get(k) ?? 0) + 1);
      }
    }
    const arr = [...counts.entries()].map(([k, n]) => ({ k, n })).sort((a, b) => b.n - a.n);
    const max = Math.max(1, ...arr.map((a) => a.n));
    return { arr, max };
  }, [state.logs, customRuleNames]);

  // ---- ban timeline — most recent additions to the blocklist (active + expired) ----
  const banTimeline = useMemo(
    () => [...state.blocklist].sort((a, b) => b.addedAt - a.addedAt).slice(0, 6),
    [state.blocklist],
  );

  const topBans = useMemo(() => {
    return [...activeBans].sort((a, b) => b.hits - a.hits).slice(0, 5);
  }, [activeBans]);
  const topMax = Math.max(1, ...topBans.map((b) => b.hits));

  const filteredBans = useMemo(() => {
    const q = banQuery.trim().toLowerCase();
    if (!q) return activeBans;
    return activeBans.filter(
      (b) =>
        b.ip.toLowerCase().includes(q) ||
        b.reason.toLowerCase().includes(q) ||
        b.country.toLowerCase().includes(q) ||
        b.countryCode.toLowerCase().includes(q) ||
        b.source.includes(q),
    );
  }, [activeBans, banQuery]);

  const expiredBansList = useMemo(() => state.blocklist.filter((b) => !b.active), [state.blocklist]);

  const topRules = useMemo(
    () => [...state.customRules].filter((r) => r.hits > 0).sort((a, b) => b.hits - a.hits).slice(0, 4),
    [state.customRules],
  );
  const topRulesMax = Math.max(1, ...topRules.map((r) => r.hits));

  const PIPELINE = [
    { id: "allow", label: "Allowlist", icon: ShieldCheck, cls: "text-wg-emerald", count: state.allowlist.length },
    { id: "block", label: "Blocklist", icon: Ban, cls: "text-wg-rose", count: activeBans.length },
    { id: "rules", label: "Custom rules", icon: Network, cls: "text-wg-amber", count: activeRules.length },
    { id: "rate", label: "Rate limit", icon: Timer, cls: "text-wg-sky", count: `${state.settings.rateLimitRpm} rpm` },
    { id: "crs", label: "CRS classes", icon: Globe2, cls: "text-wg-violet", count: blockingRules },
    { id: "ml", label: "ML classifier", icon: Zap, cls: "text-wg-cyan", count: state.settings.sensitivity.toFixed(2) },
  ];

  const geoDist = useMemo(() => {
    const byCode = new Map<string, number>();
    for (const b of activeBans) {
      if (b.countryCode && b.countryCode !== "—") byCode.set(b.countryCode, (byCode.get(b.countryCode) ?? 0) + 1);
    }
    const arr = [...byCode.entries()].map(([code, n]) => ({ code, n })).sort((a, b) => b.n - a.n);
    const max = Math.max(1, ...arr.map((a) => a.n));
    return { arr, max };
  }, [activeBans]);

  // Live enforcement feed — every request actioned by the blocklist, allowlist or a custom rule
  const enforcementFeed = useMemo(
    () =>
      state.logs
        .filter((l) => l.ruleId === "IP-BLOCKLIST" || l.ruleId === "ALLOWLIST" || customRuleNames.has(l.ruleId ?? ""))
        .slice(0, 14),
    [state.logs, customRuleNames],
  );

  const copyJson = async () => {
    try {
      const policy = {
        allowlist: state.allowlist.map((a) => ({ ip: a.ip, label: a.label })),
        blocklist: activeBans.map((b) => ({ ip: b.ip, reason: b.reason, source: b.source })),
        customRules: state.customRules.map((r) => ({
          name: r.name,
          matchType: r.matchType,
          matchValue: r.matchValue,
          action: r.action,
          enabled: r.enabled,
        })),
      };
      await navigator.clipboard.writeText(JSON.stringify(policy, null, 2));
      toast.success("Edge policy (allowlist + blocklist + rules) copied as JSON");
    } catch {
      toast.error("Clipboard unavailable");
    }
  };

  const addBan = () => {
    const ip = banInput.trim();
    if (!ip) return;
    const durMs = BAN_DURATION_MS[banDuration];
    dispatch({
      type: "ADD_BLOCKED_IP",
      entry: {
        id: uid("BAN"),
        ip,
        reason: durMs ? `Manual ban — expires in ${banDuration}` : "Manual ban by operator",
        source: "manual",
        country: "—",
        countryCode: "—",
        addedAt: Date.now(),
        hits: 0,
        active: true,
        expiresAt: durMs ? Date.now() + durMs : null,
      },
    });
    toast.success(durMs ? `Banned ${ip} for ${banDuration} — expires automatically` : `Banned ${ip} permanently`);
    setBanInput("");
  };

  const addRule = () => {
    if (!ruleName.trim() || !ruleValue.trim()) return;
    dispatch({
      type: "ADD_CUSTOM_RULE",
      rule: {
        id: uid("CR"),
        name: ruleName.trim(),
        matchType: ruleType,
        matchValue: ruleValue.trim(),
        action: ruleAction,
        enabled: true,
        hits: 0,
      },
    });
    setRuleName("");
    setRuleValue("");
    setRuleAction("block");
  };

  const quickBan = (ip: string) => {
    dispatch({
      type: "ADD_BLOCKED_IP",
      entry: {
        id: uid("BAN"),
        ip,
        reason: "Banned from enforcement feed",
        source: "manual",
        country: "—",
        countryCode: "—",
        addedAt: new Date().getTime(),
        hits: 0,
        active: true,
        expiresAt: null,
      },
    });
    toast.success(`${ip} added to blocklist`);
  };

  const addTemplate = (t: (typeof RULE_TEMPLATES)[number]) => {
    if (state.customRules.some((r) => r.name === t.name)) {
      toast.error("A rule with this name already exists");
      return;
    }
    dispatch({
      type: "ADD_CUSTOM_RULE",
      rule: {
        id: uid("CR"),
        name: t.name,
        matchType: t.matchType,
        matchValue: t.matchValue,
        action: t.action,
        enabled: true,
        hits: 0,
      },
    });
    toast.success(`Rule added — ${t.name}`);
  };

  const fmtCountdown = (ts: number) => {
    const ms = ts - new Date().getTime();
    if (ms <= 0) return "now";
    const h = Math.floor(ms / 3_600_000);
    const m = Math.floor((ms % 3_600_000) / 60_000);
    return h > 0 ? `${h}h ${m}m` : `${m}m`;
  };

  const sourceDist = useMemo(() => {
    const c: Record<BanSource, number> = { manual: 0, auto: 0, canary: 0 };
    for (const b of activeBans) c[b.source] += 1;
    const total = Math.max(1, activeBans.length);
    return { c, total };
  }, [activeBans]);

  const addAllow = () => {
    const ip = allowInput.trim();
    if (!ip) return;
    dispatch({
      type: "ADD_ALLOWED_IP",
      entry: {
        id: uid("ALW"),
        ip,
        label: allowLabel.trim() || "Trusted source",
        addedAt: Date.now(),
        hits: 0,
      },
    });
    toast.success(`${ip} added to the allowlist — WAF inspection bypassed`);
    setAllowInput("");
    setAllowLabel("");
  };

  const exportCsv = () => {
    const esc = (s: string) => `"${s.replace(/"/g, '""')}"`;
    const rows = [
      "type,ip,detail,source,country,addedUtc,hits",
      ...activeBans.map((b) =>
        ["block", b.ip, b.reason, b.source, b.country, new Date(b.addedAt).toISOString(), String(b.hits)].map(esc).join(","),
      ),
      ...state.allowlist.map((a) =>
        ["allow", a.ip, a.label, "trusted", "—", new Date(a.addedAt).toISOString(), String(a.hits)].map(esc).join(","),
      ),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `webguard-edge-policy-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${activeBans.length} bans + ${state.allowlist.length} allowlist entries to CSV`);
  };

  const addBulk = () => {
    const lines = bulkText
      .split(/[\n,;\s]+/)
      .map((l) => l.trim())
      .filter((l) => /^[0-9a-f.:/]+$/i.test(l) && l.length > 3);
    if (lines.length === 0) {
      toast.error("No valid IPs / CIDRs found — paste one per line");
      return;
    }
    for (const ip of lines) {
      dispatch({
        type: "ADD_BLOCKED_IP",
        entry: {
          id: uid("BAN"),
          ip,
          reason: "Bulk import by operator",
          source: "manual",
          country: "—",
          countryCode: "—",
          addedAt: Date.now(),
          hits: 0,
          active: true,
          expiresAt: null,
        },
      });
    }
    toast.success(`Banned ${lines.length} addresses — bulk import complete`);
    setBulkText("");
    setBulkOpen(false);
  };

  const clearExpired = () => {
    const ids = expiredBansList.map((b) => b.id);
    ids.forEach((id) => dispatch({ type: "REMOVE_BLOCKED_IP", id }));
    toast.success(`Cleared ${ids.length} expired bans`);
  };

  return (
    <div className="flex flex-col gap-4">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile
          icon={<Ban className="size-4" />}
          label="Active bans"
          value={activeBans.length}
          accent="text-wg-rose"
          sub={expiredBans > 0 ? `enforced at the edge · ${expiredBans} expired` : "enforced at the edge"}
        />
        <StatTile
          icon={<Zap className="size-4" />}
          label="Auto-bans"
          value={state.blocklist.filter((b) => b.source === "auto" && b.active).length}
          accent="text-wg-amber"
          sub="from repeated attacks"
        />
        <StatTile icon={<Network className="size-4" />} label="Custom rules live" value={activeRules.length} accent="text-wg-cyan" sub="path · IP · country · UA" />
        <StatTile icon={<ShieldCheck className="size-4" />} label="Trusted sources" value={state.allowlist.length} accent="text-wg-emerald" sub="bypass all enforcement" />
      </div>

      {/* enforcement KPIs — live window */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile
          icon={<Ban className="size-4" />}
          label="Blocked · 30s"
          value={blocked30}
          accent="text-wg-rose"
          sub={state.mode === "blocking" ? "dropped at the edge" : state.mode === "detection" ? "none — log-only mode" : "none — WAF off"}
        />
        <StatTile
          icon={<Timer className="size-4" />}
          label="Throttled · 30s"
          value={throttled30}
          accent="text-wg-amber"
          sub="429 rate-limit drops"
        />
        <StatTile
          icon={<Globe2 className="size-4" />}
          label="Avg ban age"
          value={avgBanAge}
          accent="text-wg-cyan"
          sub={`${activeBans.length} active · ${expiredBans} expired`}
        />
        <StatTile
          icon={<History className="size-4" />}
          label="Policy gates"
          value={state.allowlist.length + activeBans.length + activeRules.length}
          accent="text-wg-emerald"
          sub="allow + block + custom rules live"
        />
      </div>

      {/* edge protection automation + geo-block */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="wg-panel p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <div>
              <p className="text-sm font-semibold text-foreground">Auto-ban automation</p>
              <p className="text-xs text-muted-foreground">
                Repeated blocked requests from a subnet trigger an automatic /24 ban at the edge
              </p>
            </div>
            <Switch
              checked={state.banAutomation.enabled}
              onCheckedChange={() =>
                dispatch({ type: "SET_BAN_AUTOMATION", patch: { enabled: !state.banAutomation.enabled } })
              }
              className={state.banAutomation.enabled ? "data-[state=checked]:bg-wg-emerald" : ""}
            />
          </div>
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-3">
              <span className="w-24 shrink-0 text-[11px] text-muted-foreground">Ban threshold</span>
              <Slider
                value={[state.banAutomation.threshold]}
                min={2}
                max={12}
                step={1}
                disabled={!state.banAutomation.enabled}
                onValueChange={(v) => dispatch({ type: "SET_BAN_AUTOMATION", patch: { threshold: v[0] } })}
                className="flex-1 [&_[role=slider]]:border-wg-amber [&_[role=slider]]:bg-wg-amber"
              />
              <span className="w-8 shrink-0 text-right font-mono text-xs font-bold text-wg-amber">{state.banAutomation.threshold}</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="w-24 shrink-0 text-[11px] text-muted-foreground">Auto-ban expiry</span>
              <Select
                value={state.banAutomation.expireHours === null ? "permanent" : state.banAutomation.expireHours === 1 ? "1h" : state.banAutomation.expireHours === 24 ? "24h" : "7d"}
                onValueChange={(v) =>
                  dispatch({
                    type: "SET_BAN_AUTOMATION",
                    patch: { expireHours: v === "permanent" ? null : v === "1h" ? 1 : v === "24h" ? 24 : 168 },
                  })
                }
              >
                <SelectTrigger className="h-8 flex-1 border-border/60 bg-muted/50 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-border/60 bg-popover">
                  <SelectItem value="permanent" className="text-xs">Permanent (until removed)</SelectItem>
                  <SelectItem value="1h" className="text-xs">Expire after 1 hour</SelectItem>
                  <SelectItem value="24h" className="text-xs">Expire after 24 hours</SelectItem>
                  <SelectItem value="7d" className="text-xs">Expire after 7 days</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <p className="flex items-center gap-1.5 border-t border-border/40 pt-2.5 text-[10px] text-muted-foreground">
              <Zap className="size-3 text-wg-amber" />
              {state.banAutomation.enabled
                ? `Auto-bans activate after ${state.banAutomation.threshold} blocked requests from the same /24 subnet${state.banAutomation.expireHours ? `, expiring after ${state.banAutomation.expireHours}h` : " (permanent)"}.`
                : "Auto-banning is disabled — hostile subnets will keep hitting the edge without being banned."}
            </p>
          </div>
        </div>

        <div className="wg-panel p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <div>
              <p className="text-sm font-semibold text-foreground">Geo-blocking (country deny-list)</p>
              <p className="text-xs text-muted-foreground">
                Drop every request originating from a denied country with 403 — before any other gate
              </p>
            </div>
            <Badge
              variant="outline"
              className={cn(
                "gap-1.5 text-[10px]",
                state.geoBlock.length > 0
                  ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose"
                  : "border-border/50 text-muted-foreground",
              )}
            >
              <Globe2 className="size-3" /> {state.geoBlock.length} blocked
            </Badge>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {GEO_COUNTRIES.map((c) => {
              const on = state.geoBlock.includes(c.code);
              return (
                <button
                  key={c.code}
                  type="button"
                  onClick={() => dispatch({ type: "TOGGLE_GEO_BLOCK", code: c.code })}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[11px] transition-colors",
                    on
                      ? "border-wg-rose/50 bg-wg-rose/10 text-wg-rose"
                      : "border-border/50 bg-muted/40 text-muted-foreground hover:text-foreground/80",
                  )}
                >
                  <span className="text-sm leading-none">{flagEmoji(c.code)}</span>
                  {c.name}
                  <span className={cn("font-mono text-[9px]", on ? "text-wg-rose" : "text-muted-foreground/60")}>
                    {on ? "DENY" : "ALLOW"}
                  </span>
                </button>
              );
            })}
          </div>
          <p className="mt-2.5 border-t border-border/40 pt-2.5 text-[10px] text-muted-foreground">
            Geo-blocked requests appear in Live Traffic with a{" "}
            <span className="font-mono text-wg-rose">GEO-BLOCK</span> verdict. Allowlisted sources bypass geo rules.
          </p>
        </div>
      </div>

      {/* evaluation pipeline */}
      <div className="wg-panel p-4">
        <div className="mb-2.5 flex items-center gap-2">
          <Route className="size-3.5 text-wg-cyan" />
          <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
            Request evaluation order — every request walks these gates
          </p>
          <span className="ml-auto hidden font-mono text-[10px] text-muted-foreground sm:block">
            {state.mode === "blocking" ? "enforcing" : state.mode === "detection" ? "log-only" : "bypassed"}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {PIPELINE.map((g, i) => (
            <div key={g.id} className="flex items-center gap-1.5">
              {i > 0 && <span className="text-muted-foreground/40">→</span>}
              <div
                className={cn(
                  "flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5",
                  state.mode === "off" && i > 0 ? "border-border/25 bg-muted/20 opacity-45" : "border-border/40 bg-muted/40",
                )}
              >
                <g.icon className={cn("size-3.5", g.cls)} />
                <span className="text-[11px] font-medium text-foreground/90">{g.label}</span>
                <span className="rounded bg-background/60 px-1 py-0.5 font-mono text-[9px] text-muted-foreground">{g.count}</span>
              </div>
            </div>
          ))}
          <span className="ml-1 text-[10px] font-bold uppercase tracking-widest text-muted-foreground/60">→ verdict</span>
        </div>
        <p className="mt-2 text-[10px] text-muted-foreground">
          Allowlisted sources short-circuit every gate. When the firewall is OFF all gates are bypassed and traffic hits the origin raw.
        </p>
      </div>

      {/* attacker intelligence */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="wg-panel p-4">
          <SectionTitle
            title={
              <span className="flex items-center gap-2">
                <Zap className="size-4 text-wg-amber" /> Top attackers not yet blocked
              </span>
            }
            sub="Hostile IPs still getting through — one click adds them to the blocklist"
          />
          <div className="flex flex-col">
            {suggestedBans.map((s) => (
              <div key={s.log.ip} className="flex items-center gap-3 border-b border-border/30 py-2.5 last:border-0">
                <span className="flex min-w-0 flex-1 items-center gap-2">
                  <span className="text-sm leading-none">{flagEmoji(s.log.countryCode)}</span>
                  <span className="truncate font-mono text-xs text-foreground/90">{s.log.ip}</span>
                </span>
                <span className="hidden shrink-0 rounded-md border border-wg-rose/30 bg-wg-rose/10 px-1.5 py-0.5 text-[9px] font-bold text-wg-rose sm:inline">
                  {s.log.attackType ? ATTACK_LABELS[s.log.attackType].toUpperCase() : "THREAT"}
                </span>
                <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                  {s.log.city} · {s.n}×
                </span>
                <button
                  type="button"
                  onClick={() =>
                    dispatch({
                      type: "ADD_BLOCKED_IP",
                      entry: {
                        id: uid("BAN"),
                        ip: s.log.ip,
                        reason: `Manual ban — ${s.n} hostile attempts (${s.log.attackType ? ATTACK_LABELS[s.log.attackType] : "unknown"})`,
                        source: "manual",
                        country: s.log.country,
                        countryCode: s.log.countryCode,
                        addedAt: Date.now(),
                        hits: 0,
                        active: true,
                        expiresAt: null,
                      },
                    })
                  }
                  className="shrink-0 rounded-md border border-wg-rose/40 bg-wg-rose/10 px-2 py-1 text-[9px] font-bold text-wg-rose transition-colors hover:bg-wg-rose/20"
                >
                  BAN
                </button>
              </div>
            ))}
            {suggestedBans.length === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">
                No unblocked attackers in the live window — the edge is holding.
              </p>
            )}
          </div>
          <p className="mt-2 border-t border-border/30 pt-2 text-[10px] text-muted-foreground">
            Derived live from the traffic stream: every attack-classified request from an IP that is neither
            blocklisted nor allowlisted. Ban one and it starts dropping with 403 immediately.
          </p>
        </div>

        <div className="wg-panel p-4">
          <SectionTitle
            title={
              <span className="flex items-center gap-2">
                <Route className="size-4 text-wg-rose" /> Blocked attack mix
              </span>
            }
            sub="What the blocklist, custom rules and geo-gates actually dropped in the live window"
          />
          {blockedMix.arr.length === 0 ? (
            <p className="py-8 text-center text-xs text-muted-foreground">
              No blocks yet — flip the firewall to BLOCKING and watch enforcement events accumulate here.
            </p>
          ) : (
            <div className="flex flex-col gap-2.5">
              {blockedMix.arr.slice(0, 7).map((b) => (
                <div key={b.k} className="flex items-center gap-3">
                  <span className="w-36 shrink-0 truncate text-xs text-foreground/85">{b.k}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-border/40">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-wg-rose/60 to-wg-rose"
                      style={{ width: `${(b.n / blockedMix.max) * 100}%` }}
                    />
                  </div>
                  <span className="w-8 shrink-0 text-right font-mono text-xs text-muted-foreground">{b.n}</span>
                </div>
              ))}
              <div className="mt-1 flex flex-wrap items-center gap-4 border-t border-border/30 pt-2.5 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Ban className="size-3 text-wg-rose" /> {state.blocklist.filter((b) => b.active).length} blocklist entries
                </span>
                <span className="flex items-center gap-1.5">
                  <Network className="size-3 text-wg-amber" /> {activeRules.length} custom rules live
                </span>
                <span className="flex items-center gap-1.5">
                  <Globe2 className="size-3 text-wg-violet" /> {state.geoBlock.length} countries denied
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ban timeline */}
      {banTimeline.length > 0 && (
        <div className="wg-panel p-4">
          <div className="mb-2.5 flex items-center gap-2">
            <History className="size-3.5 text-wg-cyan" />
            <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
              Recent blocklist activity
            </p>
            <span className="ml-auto font-mono text-[10px] text-muted-foreground">
              newest first · {state.blocklist.length} total entries
            </span>
          </div>
          <div className="flex flex-col gap-1.5">
            {banTimeline.map((b) => (
              <div key={b.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-border/40 bg-muted/30 px-3 py-1.5">
                <span
                  className={cn(
                    "rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                    BAN_SOURCE_META[b.source].cls,
                  )}
                >
                  {BAN_SOURCE_META[b.source].label}
                </span>
                <span className="font-mono text-[11px] font-semibold text-wg-rose">{b.ip}</span>
                <span className="min-w-0 flex-1 truncate text-[11px] text-muted-foreground">{b.reason}</span>
                {b.expiresAt ? (
                  <span className="flex items-center gap-1 font-mono text-[9px] text-wg-amber">
                    <Timer className="size-2.5" />
                    {b.active ? `expires in ${fmtCountdown(b.expiresAt)}` : "expired"}
                  </span>
                ) : (
                  <span className="font-mono text-[9px] text-muted-foreground">permanent</span>
                )}
                <span className="font-mono text-[10px] text-muted-foreground">{timeAgo(b.addedAt)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        {/* IP blocklist */}
        <div className="flex flex-col gap-4 xl:col-span-3">
          <div className="wg-panel p-4">
            <SectionTitle
              title="IP blocklist"
              sub="Banned addresses & subnets are dropped with 403 in BLOCKING mode before any origin contact. /24 subnets auto-ban after 6 blocked requests."
              right={
                <div className="flex items-center gap-1.5">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 gap-1.5 text-[11px] text-muted-foreground hover:text-wg-cyan"
                    onClick={copyJson}
                    title="Copy edge policy (allowlist + blocklist + rules) as JSON"
                  >
                    <ClipboardCopy className="size-3.5" /> JSON
                  </Button>
                  <Badge variant="outline" className="gap-1.5 border-border/50 text-[10px] text-muted-foreground">
                    <Ban className="size-3" /> {activeBans.length} active
                  </Badge>
                </div>
              }
            />

            {geoDist.arr.length > 0 && (
              <div className="mb-3">
                <p className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Bans by country</p>
                <div className="flex flex-col gap-1.5">
                  {geoDist.arr.map((g) => (
                    <div key={g.code} className="flex items-center gap-2">
                      <span className="flex w-14 items-center gap-1.5 text-[11px] text-foreground/80">
                        <span className="text-sm leading-none">{flagEmoji(g.code)}</span> {g.code}
                      </span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                        <div className="h-full rounded-full bg-wg-rose/70" style={{ width: `${(g.n / geoDist.max) * 100}%` }} />
                      </div>
                      <span className="w-5 text-right font-mono text-[11px] text-muted-foreground">{g.n}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="mb-3 flex items-center gap-2">
              <span className="shrink-0 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">By source</span>
              <div className="flex h-2 flex-1 overflow-hidden rounded-full bg-border/40">
                <div className="h-full bg-wg-cyan" style={{ width: `${(sourceDist.c.manual / sourceDist.total) * 100}%` }} />
                <div className="h-full bg-wg-amber" style={{ width: `${(sourceDist.c.auto / sourceDist.total) * 100}%` }} />
                <div className="h-full bg-wg-rose" style={{ width: `${(sourceDist.c.canary / sourceDist.total) * 100}%` }} />
              </div>
              <span className="shrink-0 font-mono text-[9px] text-muted-foreground">
                M {sourceDist.c.manual} · A {sourceDist.c.auto} · C {sourceDist.c.canary}
              </span>
            </div>

            <div className="mb-3 flex flex-col gap-2 sm:flex-row">
              <Input
                value={banInput}
                onChange={(e) => setBanInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addBan()}
                placeholder="IP or CIDR — e.g. 45.155.4.12 or 185.220.0.0/16"
                className="h-9 flex-1 border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                spellCheck={false}
              />
              <Button className="h-9 gap-2 border-wg-rose/40 bg-wg-rose/10 text-wg-rose hover:bg-wg-rose/20" onClick={addBan}>
                <Ban className="size-4" /> Ban address
              </Button>
              <Select value={banDuration} onValueChange={(v) => setBanDuration(v as typeof banDuration)}>
                <SelectTrigger className="h-9 w-44 border-border/60 bg-muted/50 text-[11px]">
                  <Timer className="size-3.5 text-wg-amber" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-border/60 bg-popover">
                  <SelectItem value="permanent" className="text-xs">Permanent ban</SelectItem>
                  <SelectItem value="1h" className="text-xs">1 hour</SelectItem>
                  <SelectItem value="24h" className="text-xs">24 hours</SelectItem>
                  <SelectItem value="7d" className="text-xs">7 days</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="mb-3 flex flex-col gap-2 lg:flex-row">
              <div className="relative min-w-0 flex-1">
                <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={banQuery}
                  onChange={(e) => setBanQuery(e.target.value)}
                  placeholder={`Filter ${activeBans.length} active bans — IP, country, reason, source…`}
                  className="h-8 border-border/60 bg-muted/50 pl-8 text-xs focus-visible:ring-cyan-400/40"
                  spellCheck={false}
                />
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <ExportMenu
                  data={{
                    label: "edge policy",
                    filename: `webguard-edge-policy-${Date.now()}`,
                    csvRows: [["Type", "IP", "Detail", "Source", "Country", "Added", "Hits"],
                      ...activeBans.map((b) => ["block", b.ip, b.reason, b.source, b.country, new Date(b.addedAt).toISOString(), String(b.hits)]),
                      ...state.allowlist.map((a) => ["allow", a.ip, a.label, "trusted", "—", new Date(a.addedAt).toISOString(), String(a.hits)])],
                    jsonData: { bans: activeBans, allowlist: state.allowlist },
                  }}
                />
                <Button
                  variant="outline"
                  size="sm"
                  className={cn("h-8 gap-1.5 border-border/60 text-[11px]", bulkOpen ? "border-wg-amber/50 bg-wg-amber/10 text-wg-amber" : "text-muted-foreground hover:text-wg-amber")}
                  onClick={() => setBulkOpen((o) => !o)}
                >
                  <Upload className="size-3.5" /> Bulk import
                </Button>
                {expiredBansList.length > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 gap-1.5 border-border/60 text-[11px] text-muted-foreground hover:text-wg-emerald"
                    onClick={clearExpired}
                  >
                    <History className="size-3.5" /> Clear {expiredBansList.length} expired
                  </Button>
                )}
              </div>
            </div>

            {bulkOpen && (
              <div className="mb-3 rounded-xl border border-wg-amber/30 bg-wg-amber/[0.05] p-3">
                <p className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-wg-amber">
                  Bulk import — paste IPs / CIDRs, one per line
                </p>
                <Textarea
                  value={bulkText}
                  onChange={(e) => setBulkText(e.target.value)}
                  placeholder={"185.220.101.4\n91.134.22.0/24\n45.155.4.12"}
                  className="min-h-20 resize-none border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-amber-400/40"
                  spellCheck={false}
                />
                <div className="mt-2 flex items-center justify-between gap-2">
                  <p className="text-[10px] text-muted-foreground">
                    Valid addresses are added as permanent manual bans.
                  </p>
                  <Button
                    size="sm"
                    className="h-7 gap-1.5 border-wg-amber/40 bg-wg-amber/10 text-[11px] text-wg-amber hover:bg-wg-amber/20"
                    onClick={addBulk}
                  >
                    <Upload className="size-3.5" /> Import bans
                  </Button>
                </div>
              </div>
            )}

            <div className="overflow-x-auto rounded-xl border border-border/40">
              <table className="w-full border-collapse text-left">
                <thead className="bg-muted/90">
                  <tr className="border-b border-border/60 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="px-3 py-2 font-semibold">Address</th>
                    <th className="px-3 py-2 font-semibold">Country</th>
                    <th className="px-3 py-2 font-semibold">Reason</th>
                    <th className="px-3 py-2 text-center font-semibold">Source</th>
                    <th className="px-3 py-2 text-center font-semibold">Hits</th>
                    <th className="px-3 py-2 font-semibold">Added</th>
                    <th className="px-3 py-2 text-right font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredBans.map((b) => {
                    const preview = cidrPreview(b.ip);
                    return (
                      <Fragment key={b.id}>
                    <tr className="border-b border-border/25 last:border-0">
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[11px] font-semibold text-wg-rose">{b.ip}</span>
                          {preview.length > 0 && (
                            <button
                              type="button"
                              onClick={() => setExpandedCidr((c) => (c === b.id ? null : b.id))}
                              className="flex size-5 items-center justify-center rounded border border-border/50 bg-muted/50 text-[9px] text-muted-foreground transition-colors hover:border-wg-cyan/50 hover:text-wg-cyan"
                              title="Expand subnet preview"
                            >
                              {expandedCidr === b.id ? "−" : "+"}
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-[11px] text-muted-foreground">
                        {b.countryCode !== "—" ? (
                          <span className="flex items-center gap-1.5">
                            <span className="text-sm leading-none">{flagEmoji(b.countryCode)}</span> {b.country}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="max-w-[240px] px-3 py-2">
                        <p className="truncate text-xs text-foreground/80">{b.reason}</p>
                        {b.expiresAt && (
                          <p className="mt-0.5 flex items-center gap-1 font-mono text-[9px] text-wg-amber">
                            <Timer className="size-2.5" /> expires in {fmtCountdown(b.expiresAt)}
                          </p>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center">
                        <span className={cn("rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", BAN_SOURCE_META[b.source].cls)}>
                          {BAN_SOURCE_META[b.source].label}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-center font-mono text-xs text-muted-foreground">{b.hits}</td>
                      <td className="px-3 py-2 text-[11px] text-muted-foreground">{timeAgo(b.addedAt)}</td>
                      <td className="px-3 py-2">
                        <div className="flex justify-end">
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            title="Remove from blocklist"
                            className="text-wg-emerald"
                            onClick={() => dispatch({ type: "REMOVE_BLOCKED_IP", id: b.id })}
                          >
                            <ShieldOff className="size-3.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                    {expandedCidr === b.id && preview.length > 0 && (
                      <tr className="border-b border-border/25 bg-muted/30">
                        <td colSpan={7} className="px-3 py-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                              Subnet hosts ({b.ip.replace("/24", "").split(".").slice(0, 3).join(".")}.0 – .255):
                            </span>
                            {preview.map((ip) => (
                              <span key={ip} className="rounded-md border border-border/50 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                                {ip}
                              </span>
                            ))}
                            <span className="font-mono text-[10px] text-muted-foreground/70">…</span>
                            <span className="ml-auto font-mono text-[10px] text-wg-rose">256 addresses · /24</span>
                          </div>
                        </td>
                      </tr>
                    )}
                    </Fragment>
                  );})}
                  {filteredBans.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-3 py-12 text-center text-xs text-muted-foreground">
                        {activeBans.length > 0
                          ? "No bans match the current filter — clear the search box."
                          : "Blocklist empty — repeated blocked attacks and canary trips will populate it automatically."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {topBans.some((b) => b.hits > 0) && (
              <div className="mt-3">
                <p className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                  Top blocked subnets — by enforcement hits
                </p>
                <div className="flex flex-col gap-1.5">
                  {topBans.map((b) => (
                    <div key={b.id} className="flex items-center gap-2">
                      <span className="w-32 shrink-0 truncate font-mono text-[11px] font-semibold text-wg-rose">{b.ip}</span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                        <div className="h-full rounded-full bg-wg-rose/70" style={{ width: `${(b.hits / topMax) * 100}%` }} />
                      </div>
                      <span className="w-10 shrink-0 text-right font-mono text-[10px] text-muted-foreground">{b.hits} hits</span>
                    </div>
                  ))}
                </div>
                <p className="mt-1.5 truncate text-[9px] text-muted-foreground">
                  {topBans[0] && `${topBans[0].ip} — ${topBans[0].reason}`}
                </p>
              </div>
            )}

            <p className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <Zap className="size-3.5 text-wg-amber" />
              Bans appear here in real time as the simulator drops attacks — watch the Live Traffic tab for{" "}
              <span className="font-mono text-wg-rose">IP-BLOCKLIST</span> verdicts. 24h temporary bans expire automatically.
            </p>
          </div>
        </div>

        {/* custom rules */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          <div className="wg-panel p-4">
            <SectionTitle
              title="Custom edge rules"
              sub="Your own match → action policies, evaluated before the CRS engine on every request."
            />

            <div className="flex flex-col gap-2 rounded-xl border border-border/40 bg-muted/30 p-3">
              <Input
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                placeholder="Rule name — e.g. Block staging subdomain"
                className="h-8 border-border/60 bg-muted/50 text-xs focus-visible:ring-cyan-400/40"
              />
              <div className="flex gap-2">
                <Select value={ruleType} onValueChange={(v) => setRuleType(v as CustomRuleMatch)}>
                  <SelectTrigger className="h-8 w-32 border-border/60 bg-muted/50 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="border-border/60 bg-popover">
                    {(Object.keys(MATCH_META) as CustomRuleMatch[]).map((m) => (
                      <SelectItem key={m} value={m} className="text-xs">
                        {MATCH_META[m].label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  value={ruleValue}
                  onChange={(e) => setRuleValue(e.target.value)}
                  placeholder={MATCH_META[ruleType].hint}
                  className="h-8 flex-1 border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                  spellCheck={false}
                />
              </div>
              <div className="flex gap-2">
                <Select value={ruleAction} onValueChange={(v) => setRuleAction(v as RuleAction)}>
                  <SelectTrigger className="h-8 flex-1 border-border/60 bg-muted/50 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="border-border/60 bg-popover">
                    {ACTION_OPTIONS.map((a) => (
                      <SelectItem key={a} value={a} className="text-xs">
                        {a}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 px-3 text-wg-cyan hover:bg-wg-cyan/20" onClick={addRule}>
                  <Plus className="size-3.5" /> Add rule
                </Button>
              </div>
            </div>

            <div className="mt-3">
              <p className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                One-click templates
              </p>
              <div className="flex flex-wrap gap-1.5">
                {RULE_TEMPLATES.map((t) => (
                  <button
                    key={t.name}
                    type="button"
                    title={t.desc}
                    onClick={() => addTemplate(t)}
                    className="flex items-center gap-1 rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[10px] text-foreground/80 transition-colors hover:border-wg-cyan/50 hover:text-wg-cyan"
                  >
                    <Plus className="size-3" /> {t.name}
                  </button>
                ))}
              </div>
              <p className="mt-1 text-[9px] text-muted-foreground">
                Prebuilt policies — staging lockdown, scraper CAPTCHA, geo-denial, API probe watch, and debug-header
                rejection. Click to add, then tune the action.
              </p>
            </div>

            <div className="mt-3 flex flex-col gap-2">
              {state.customRules.map((r) => (
                <div key={r.id} className="rounded-xl border border-border/40 bg-card/40 p-3">
                  <div className="flex items-start gap-2.5">
                    <Switch
                      checked={r.enabled}
                      onCheckedChange={() => dispatch({ type: "TOGGLE_CUSTOM_RULE", id: r.id })}
                      className={r.enabled ? "data-[state=checked]:bg-wg-emerald" : ""}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-foreground">{r.name}</p>
                      <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                        {MATCH_META[r.matchType].label.toLowerCase()}: <span className="text-wg-cyan">{r.matchValue}</span> · {r.hits} hits
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      title="Delete rule"
                      className="text-rose-400"
                      onClick={() => dispatch({ type: "REMOVE_CUSTOM_RULE", id: r.id })}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                  <div className="mt-2 flex items-center justify-between gap-2">
                    <span
                      className={cn(
                        "rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                        r.action === "block" && "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
                        r.action === "challenge" && "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
                        r.action === "log" && "border-wg-sky/40 bg-wg-sky/10 text-wg-sky",
                        r.action === "disable" && "border-border/40 bg-muted/50 text-muted-foreground",
                      )}
                    >
                      {r.action.toUpperCase()}
                    </span>
                    <Select
                      value={r.action}
                      onValueChange={(v) => dispatch({ type: "SET_CUSTOM_RULE_ACTION", id: r.id, action: v as RuleAction })}
                    >
                      <SelectTrigger className="h-7 w-32 border-border/60 bg-muted/50 text-[11px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="border-border/60 bg-popover">
                        {ACTION_OPTIONS.map((a) => (
                          <SelectItem key={a} value={a} className="text-xs">
                            {a}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ))}
              {state.customRules.length === 0 && (
                <p className="py-8 text-center text-xs text-muted-foreground">
                  No custom rules yet — create one above.
                </p>
              )}
            </div>

            {topRules.length > 0 && (
              <div className="mt-4 border-t border-border/40 pt-3">
                <p className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                  Most enforced rules — by edge hits
                </p>
                <div className="flex flex-col gap-1.5">
                  {topRules.map((r) => (
                    <div key={r.id} className="flex items-center gap-2">
                      <span className="w-32 shrink-0 truncate text-[11px] text-foreground/80">{r.name}</span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                        <div
                          className={cn(
                            "h-full rounded-full",
                            r.action === "block" && "bg-wg-rose",
                            r.action === "challenge" && "bg-wg-amber",
                            r.action === "log" && "bg-wg-sky",
                            r.action === "disable" && "bg-border",
                          )}
                          style={{ width: `${(r.hits / topRulesMax) * 100}%` }}
                        />
                      </div>
                      <span className="w-14 shrink-0 text-right font-mono text-[10px] text-muted-foreground">{r.hits.toLocaleString()} hits</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* allowlist / trusted sources */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          <div className="wg-panel p-4">
            <SectionTitle
              title="Allowlist · trusted sources"
              sub="IPs on the allowlist bypass every gate — no blocklist, no custom rules, no ML inspection. For offices, CI runners and partner APIs."
              right={
                <Badge variant="outline" className="gap-1.5 border-wg-emerald/40 bg-wg-emerald/10 text-[10px] text-wg-emerald">
                  <ShieldCheck className="size-3" /> {state.allowlist.length} sources
                </Badge>
              }
            />
            <div className="flex flex-col gap-2 rounded-xl border border-border/40 bg-muted/30 p-3">
              <div className="flex gap-2">
                <Input
                  value={allowInput}
                  onChange={(e) => setAllowInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addAllow()}
                  placeholder="IP or CIDR — e.g. 198.51.100.0/24"
                  className="h-8 flex-1 border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-emerald-400/40"
                  spellCheck={false}
                />
                <Input
                  value={allowLabel}
                  onChange={(e) => setAllowLabel(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addAllow()}
                  placeholder="Label"
                  className="h-8 w-28 border-border/60 bg-muted/50 text-xs focus-visible:ring-emerald-400/40"
                />
              </div>
              <Button
                className="h-8 gap-1.5 border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald hover:bg-wg-emerald/20"
                onClick={addAllow}
              >
                <Plus className="size-3.5" /> Add trusted source
              </Button>
            </div>
            <div className="mt-3 flex flex-col gap-2">
              {state.allowlist.map((a) => (
                <div key={a.id} className="flex items-center gap-2.5 rounded-xl border border-border/40 bg-card/40 p-3">
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-wg-emerald/10 text-wg-emerald">
                    <ShieldCheck className="size-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-xs font-semibold text-wg-emerald">{a.ip}</p>
                    <p className="truncate text-[10px] text-muted-foreground">
                      {a.label} · {a.hits.toLocaleString()} requests passed · added {timeAgo(a.addedAt)}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    title="Remove from allowlist"
                    className="text-wg-rose"
                    onClick={() => dispatch({ type: "REMOVE_ALLOWED_IP", id: a.id })}
                  >
                    <ShieldOff className="size-3.5" />
                  </Button>
                </div>
              ))}
              {state.allowlist.length === 0 && (
                <p className="py-6 text-center text-xs text-muted-foreground">No trusted sources yet — add one above.</p>
              )}
            </div>
            <p className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <Zap className="size-3.5 text-wg-emerald" />
              Allowlisted requests appear in Live Traffic with an <span className="font-mono text-wg-emerald">ALLOWLIST</span> tag and never count as threats.
            </p>
          </div>
        </div>

        {/* live enforcement feed */}
        <div className="flex flex-col gap-4 xl:col-span-3">
          <div className="wg-panel p-4">
            <SectionTitle
              title="Live enforcement feed"
              sub="Every request actioned by the allowlist, blocklist or a custom rule — streamed straight from the edge"
              right={
                <Badge variant="outline" className="gap-1.5 border-border/50 text-[10px] text-muted-foreground">
                  <Radio className="size-3 animate-pulse text-wg-rose" /> {enforcementFeed.length} in view · {edgeHits.toLocaleString()} total
                </Badge>
              }
            />
            <div className="flex flex-col">
              {enforcementFeed.map((l) => {
                const isBan = l.ruleId === "IP-BLOCKLIST";
                const isAllow = l.ruleId === "ALLOWLIST";
                const ruleName = customRuleNames.get(l.ruleId ?? "");
                return (
                  <div key={l.id} className="flex items-center gap-2.5 border-b border-border/25 py-2 last:border-0">
                    <span
                      className={cn(
                        "flex size-6 shrink-0 items-center justify-center rounded-md",
                        isBan && "bg-wg-rose/10 text-wg-rose",
                        isAllow && "bg-wg-emerald/10 text-wg-emerald",
                        ruleName && "bg-wg-amber/10 text-wg-amber",
                      )}
                    >
                      {isBan ? <Ban className="size-3" /> : isAllow ? <ShieldCheck className="size-3" /> : <Network className="size-3" />}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs text-foreground/90">
                        <span className="font-mono text-[11px] text-muted-foreground">{l.method}</span> {l.path}
                      </p>
                      <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                        {l.ip} · {timeAgo(l.ts)}
                      </p>
                    </div>
                    <span
                      className={cn(
                        "shrink-0 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                        isBan && "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
                        isAllow && "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
                        ruleName && "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
                      )}
                    >
                      {isBan ? "IP-BLOCKLIST" : isAllow ? "ALLOWLIST" : (ruleName ?? "").toUpperCase()}
                    </span>
                    <StatusBadge status={l.status} className="shrink-0" />
                    {!isBan && (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        title={`Ban ${l.ip}`}
                        className="shrink-0 text-wg-rose"
                        onClick={() => quickBan(l.ip)}
                      >
                        <Ban className="size-3" />
                      </Button>
                    )}
                  </div>
                );
              })}
              {enforcementFeed.length === 0 && (
                <p className="py-10 text-center text-xs text-muted-foreground">
                  No enforcement events yet — flip the firewall to BLOCKING and watch live traffic populate this feed.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function matchesAddr(entry: string, ip: string): boolean {
  if (entry.endsWith("/24")) return ip.startsWith(entry.replace("/24", ""));
  return entry === ip;
}

function StatTile({
  icon,
  label,
  value,
  sub,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  sub: string;
  accent: string;
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
