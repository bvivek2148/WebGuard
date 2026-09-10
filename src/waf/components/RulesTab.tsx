import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import type { WafState } from "../engine";
import type { AttackType, RuleAction, RuleSetting, WafMode } from "../types";
import { ATTACK_LABELS } from "../types";
import { SectionTitle, ModeBadge, timeAgo } from "./shared";
import {
  Activity,
  ArrowRight,
  Ban,
  Bot,
  CheckCircle2,
  Cpu,
  FlaskConical,
  Gauge,
  History,
  Lock,
  Network,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Timer,
  XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Profile {
  id: string;
  label: string;
  desc: string;
  cls: string;
  rules: Record<string, RuleAction>;
  sensitivity: number;
  rateLimitRpm: number;
}

const PROFILES: Profile[] = [
  {
    id: "strict",
    label: "STRICT",
    desc: "Hard-block everything, tighten budgets",
    cls: "border-wg-rose/50 bg-wg-rose/10 text-wg-rose",
    rules: { sqli: "block", xss: "block", cmdi: "block", "path-traversal": "block", bots: "block" },
    sensitivity: 0.95,
    rateLimitRpm: 300,
  },
  {
    id: "balanced",
    label: "BALANCED",
    desc: "Block exploits, challenge bots — recommended",
    cls: "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan",
    rules: { sqli: "block", xss: "block", cmdi: "block", "path-traversal": "block", bots: "challenge" },
    sensitivity: 0.85,
    rateLimitRpm: 600,
  },
  {
    id: "permissive",
    label: "PERMISSIVE",
    desc: "Log-only posture — minimal interference",
    cls: "border-wg-amber/50 bg-wg-amber/10 text-wg-amber",
    rules: { sqli: "challenge", xss: "log", cmdi: "challenge", "path-traversal": "log", bots: "disable" },
    sensitivity: 0.7,
    rateLimitRpm: 1000,
  },
];

const CLASS_RULE: Record<AttackType, string> = {
  sqli: "sqli",
  xss: "xss",
  cmdi: "cmdi",
  "path-traversal": "path-traversal",
  "high-entropy": "sqli",
  bot: "bots",
  scanner: "bots",
};

const SIM_CLASSES: Array<AttackType | "benign"> = ["benign", "sqli", "xss", "cmdi", "path-traversal", "high-entropy", "bot", "scanner"];

type SimGateStatus = "pass" | "block" | "throttle" | "info";

interface SimGate {
  id: string;
  label: string;
  icon: LucideIcon;
  status: SimGateStatus;
  detail: string;
}

interface SimResult {
  gates: SimGate[];
  status: number;
  label: string;
  tone: "rose" | "emerald" | "amber" | "sky";
  summary: string;
}

function finalize(gates: SimGate[], status: number, label: string, tone: SimResult["tone"], summary: string): SimResult {
  return { gates, status, label, tone, summary };
}

/**
 * Walk a request through the exact gate pipeline the edge uses — computed live
 * from the current policy (rules, tuning, thresholds, bucket, mode).
 */
function simulateRequest(
  state: Pick<WafState, "mode" | "settings" | "thresholds" | "bucket" | "rules" | "customRules">,
  cls: AttackType | "benign",
  trusted: boolean,
  banned: boolean,
): SimResult {
  const gates: SimGate[] = [];
  const add = (g: SimGate) => gates.push(g);
  const mode = state.mode;

  // Gate 1 — allowlist
  if (trusted) {
    add({ id: "allow", label: "Allowlist", icon: ShieldCheck, status: "pass", detail: "Trusted source matched — all inspection short-circuited" });
    return finalize(gates, 200, "ALLOWED", "emerald", "Trusted source bypassed the WAF entirely (ALLOWLIST verdict)");
  }
  add({ id: "allow", label: "Allowlist", icon: ShieldCheck, status: "pass", detail: "Not allowlisted — continuing down the pipeline" });

  // Gate 2 — blocklist
  if (banned) {
    add({ id: "block", label: "Blocklist", icon: Ban, status: "block", detail: "Source IP matches an active ban — dropped before origin contact" });
    return finalize(gates, 403, "BLOCKED", "rose", "Blocklist verdict (IP-BLOCKLIST) · zero origin contact");
  }
  add({ id: "block", label: "Blocklist", icon: Ban, status: "pass", detail: "No matching ban for this source" });

  // Gate 3 — custom rules
  const enabledRules = state.customRules.filter((r) => r.enabled).length;
  add({ id: "rules", label: "Custom rules", icon: Network, status: "pass", detail: `${enabledRules} enabled — none matched this request` });

  // Gate 4 — rate limit
  const budgetPerSec = Math.max(1, Math.round(state.settings.rateLimitRpm / 60));
  const overBudget = state.bucket.requests >= budgetPerSec;
  if (overBudget && cls !== "bot") {
    add({ id: "rate", label: "Rate limit", icon: Timer, status: "throttle", detail: `Budget ${state.settings.rateLimitRpm} rpm exceeded — 429 throttle` });
    if (mode !== "off") return finalize(gates, 429, "THROTTLED", "amber", "Rate budget exhausted for this second — request throttled");
  } else {
    add({ id: "rate", label: "Rate limit", icon: Timer, status: "pass", detail: `${state.settings.rateLimitRpm} rpm budget · ${state.bucket.requests}/${budgetPerSec} used this second` });
  }

  // Gate 5 — CRS class rule
  const rule = cls === "benign" ? undefined : state.rules.find((r) => r.id === CLASS_RULE[cls]);
  if (cls === "benign") {
    add({ id: "crs", label: "CRS classes", icon: ScanSearch, status: "pass", detail: "Benign request — no signature matched" });
  } else if (rule?.action === "disable") {
    add({ id: "crs", label: "CRS classes", icon: ScanSearch, status: "info", detail: `${rule.label} is DISABLED — signature ignored` });
  } else if (rule?.action === "log") {
    add({ id: "crs", label: "CRS classes", icon: ScanSearch, status: "info", detail: `${rule.label} set to LOG ONLY — recorded, not dropped` });
  } else {
    add({ id: "crs", label: "CRS classes", icon: ScanSearch, status: "block", detail: `Signature ${rule?.ruleIds ?? ""} matched (${rule?.label ?? cls}) — action ${rule?.action ?? "block"}` });
    if (mode === "blocking") return finalize(gates, 403, "BLOCKED", "rose", `CRS rule ${rule?.ruleIds ?? ""} blocked the request at the edge`);
  }

  // Gate 6 — ML classifier
  if (cls === "benign") {
    add({ id: "ml", label: "ML classifier", icon: Cpu, status: "pass", detail: `Entropy 1.2 bits/char — well below cutoff ${state.thresholds.entropy.toFixed(2)}` });
  } else {
    const score = Math.min(99, Math.round(64 + state.thresholds.entropy * 6 + 12));
    const flagged = score / 100 >= state.settings.sensitivity;
    add({
      id: "ml",
      label: "ML classifier",
      icon: Cpu,
      status: flagged ? "block" : "pass",
      detail: `Threat score ${score}/100 · sensitivity ${state.settings.sensitivity.toFixed(2)} — ${flagged ? "flagged as malicious" : "below decision boundary"}`,
    });
    if (flagged && mode === "blocking") return finalize(gates, 403, "BLOCKED", "rose", "ML classifier flagged the payload — dropped with 403");
  }

  if (mode === "off") return finalize(gates, 200, "ALLOWED", "sky", "Firewall OFF — request reached the origin raw, uninspected");
  if (mode === "detection" && cls !== "benign") return finalize(gates, 200, "LOGGED", "amber", "Detection mode — attack logged, origin still processed it");
  return finalize(gates, 200, "ALLOWED", "emerald", "All gates passed — request forwarded to the origin");
}

const GATE_META: Record<SimGateStatus, { label: string; cls: string }> = {
  pass: { label: "PASS", cls: "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" },
  block: { label: "BLOCK", cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" },
  throttle: { label: "THROTTLE", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" },
  info: { label: "SKIP", cls: "border-border/40 bg-muted/50 text-muted-foreground" },
};

const ACTION_META: Record<RuleAction, { label: string; cls: string }> = {
  block: { label: "BLOCK", cls: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" },
  challenge: { label: "CHALLENGE", cls: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber" },
  log: { label: "LOG ONLY", cls: "border-wg-sky/40 bg-wg-sky/10 text-wg-sky" },
  disable: { label: "DISABLED", cls: "border-border/40 bg-muted/50 text-muted-foreground" },
};

export function RulesTab({ onNavigate }: { onNavigate?: (tab: string) => void }) {
  const { state, dispatch } = useWaf();
  const [changes, setChanges] = useState<{ id: number; ts: number; text: string }[]>([]);

  // ---- pending rule suggested by the Request Sandbox bypass sweep ----
  const suggestion = state.policySuggestion;
  const acceptSuggestion = () => {
    if (!suggestion) return;
    dispatch({ type: "ADD_CUSTOM_RULE", rule: { ...suggestion, enabled: true } });
    dispatch({ type: "CLEAR_POLICY_SUGGESTION" });
    toast.success(`Rule \u201c${suggestion.name}\u201d applied to the edge`);
  };
  const dismissSuggestion = () => {
    dispatch({ type: "CLEAR_POLICY_SUGGESTION" });
    toast.info("Suggestion dismissed");
  };

  // ---- request simulator ----
  const [simClass, setSimClass] = useState<AttackType | "benign">("sqli");
  const [simTrusted, setSimTrusted] = useState(false);
  const [simBanned, setSimBanned] = useState(false);
  const sim = useMemo(
    () => simulateRequest(state, simClass, simTrusted, simBanned),
    [state, simClass, simTrusted, simBanned],
  );

  // ---- live per-class impact (last 120 requests) ----
  const classImpact = useMemo(() => {
    const recent = state.logs.slice(0, 120);
    const byClass = new Map<AttackType, { total: number; blocked: number }>();
    for (const l of recent) {
      if (!l.attackType) continue;
      const c = byClass.get(l.attackType) ?? { total: 0, blocked: 0 };
      c.total += 1;
      if (l.blocked) c.blocked += 1;
      byClass.set(l.attackType, c);
    }
    const arr = Object.keys(ATTACK_LABELS) as AttackType[];
    const max = Math.max(1, ...arr.map((a) => byClass.get(a)?.total ?? 0));
    return { arr, byClass, max };
  }, [state.logs]);

  const logChange = (text: string) =>
    setChanges((prev) => [{ id: Date.now() + Math.random(), ts: Date.now(), text }, ...prev].slice(0, 8));

  const applyProfile = (p: Profile) => {
    for (const [id, action] of Object.entries(p.rules)) {
      dispatch({ type: "SET_RULE", id, action });
    }
    dispatch({ type: "SET_SETTING", key: "sensitivity", value: p.sensitivity });
    dispatch({ type: "SET_SETTING", key: "rateLimitRpm", value: p.rateLimitRpm });
    logChange(`Applied ${p.label} profile — all classes + tuning updated`);
    toast.success(`${p.label} profile applied — policy reconfigured`);
  };

  const setRule = (r: RuleSetting, action: RuleAction) => {
    dispatch({ type: "SET_RULE", id: r.id, action });
    logChange(`${r.label} → ${action}`);
  };

  const coverage = Math.round((state.rules.filter((r) => r.action === "block" || r.action === "challenge").length / state.rules.length) * 100);
  const blockingRules = state.rules.filter((r) => r.action === "block").length;
  const activeRules = state.customRules.filter((r) => r.enabled).length;
  const activeBans = state.blocklist.filter((b) => b.active).length;

  return (
    <div className="flex flex-col gap-4">
      {/* pending rule suggestion from the sandbox bypass sweep */}
      {suggestion && (
        <div className="rounded-xl border border-wg-violet/40 bg-wg-violet/[0.06] p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-start gap-3">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-wg-violet/15 text-wg-violet">
                <ShieldAlert className="size-4" />
              </span>
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-sm font-semibold text-foreground">
                  Pending rule — suggested by the Request Sandbox bypass sweep
                  <Badge variant="outline" className="border-wg-violet/40 bg-wg-violet/10 text-[9px] text-wg-violet">
                    DRAFT
                  </Badge>
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  An evasion slipped past the signature engine during a fuzz sweep. WebGuard recommends closing the
                  gap at the edge with a custom rule.
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <span className="rounded-md border border-border/40 bg-muted/40 px-2 py-0.5 font-mono text-[10px] text-foreground/85">
                    {suggestion.matchType} · {suggestion.matchValue}
                  </span>
                  <span
                    className={cn(
                      "rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                      suggestion.action === "block"
                        ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose"
                        : suggestion.action === "challenge"
                          ? "border-wg-amber/40 bg-wg-amber/10 text-wg-amber"
                          : "border-wg-sky/40 bg-wg-sky/10 text-wg-sky",
                    )}
                  >
                    {suggestion.action}
                  </span>
                  <span className="max-w-[260px] truncate rounded-md border border-border/40 bg-muted/40 px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                    {suggestion.name}
                  </span>
                </div>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              <Button
                variant="ghost"
                size="sm"
                className="h-8 text-[11px] text-muted-foreground hover:text-foreground"
                onClick={dismissSuggestion}
              >
                Dismiss
              </Button>
              <Button
                size="sm"
                className="h-8 gap-1.5 border-wg-violet/40 bg-wg-violet/15 text-[11px] text-wg-violet hover:bg-wg-violet/25"
                onClick={acceptSuggestion}
              >
                <CheckCircle2 className="size-3.5" /> Apply rule
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* policy stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <PolicyStat icon={<ScanSearch className="size-4" />} label="CRS rule classes" value={state.rules.length} accent="text-wg-cyan" sub="OWASP Core Rule Set" />
        <PolicyStat icon={<ShieldAlert className="size-4" />} label="Hard-blocking" value={blockingRules} accent="text-wg-rose" sub="classes set to BLOCK" />
        <PolicyStat icon={<Network className="size-4" />} label="Custom rules" value={activeRules} accent="text-wg-amber" sub="live on the edge" />
        <PolicyStat icon={<Ban className="size-4" />} label="IPs banned" value={activeBans} accent="text-wg-emerald" sub="enforced with 403" />
      </div>

      {/* request simulator + live class impact */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <div className="wg-panel p-4 lg:col-span-3">
          <SectionTitle
            title={
              <span className="flex items-center gap-2">
                <FlaskConical className="size-4 text-wg-cyan" /> Request simulator
              </span>
            }
            sub="Walk a request through the exact gate pipeline the edge uses — driven by the live policy below."
            right={<ModeBadge mode={state.mode} />}
          />

          <div className="flex flex-wrap items-center gap-2">
            <Select value={simClass} onValueChange={(v) => setSimClass(v as AttackType | "benign")}>
              <SelectTrigger className="h-8 w-48 border-border/60 bg-muted/50 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="border-border/60 bg-popover">
                {SIM_CLASSES.map((c) => (
                  <SelectItem key={c} value={c} className="text-xs">
                    {c === "benign" ? "Benign request" : ATTACK_LABELS[c]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <button
              type="button"
              onClick={() => setSimTrusted((t) => !t)}
              className={cn(
                "h-8 rounded-lg border px-2.5 text-[11px] transition-colors",
                simTrusted ? "border-wg-emerald/50 bg-wg-emerald/10 text-wg-emerald" : "border-border/40 bg-muted/30 text-muted-foreground",
              )}
            >
              <span className="flex items-center gap-1.5">
                <ShieldCheck className="size-3.5" /> Allowlisted IP
              </span>
            </button>
            <button
              type="button"
              onClick={() => setSimBanned((t) => !t)}
              className={cn(
                "h-8 rounded-lg border px-2.5 text-[11px] transition-colors",
                simBanned ? "border-wg-rose/50 bg-wg-rose/10 text-wg-rose" : "border-border/40 bg-muted/30 text-muted-foreground",
              )}
            >
              <span className="flex items-center gap-1.5">
                <Ban className="size-3.5" /> Blocklisted IP
              </span>
            </button>
          </div>

          <div className="mt-3 flex flex-col gap-1.5">
            {sim.gates.map((g, i) => (
              <div key={g.id} className="flex items-center gap-2.5 rounded-lg border border-border/40 bg-muted/30 px-3 py-2">
                <span
                  className={cn(
                    "flex size-6 shrink-0 items-center justify-center rounded-md",
                    g.status === "pass" && "bg-wg-emerald/10 text-wg-emerald",
                    g.status === "block" && "bg-wg-rose/10 text-wg-rose",
                    g.status === "throttle" && "bg-wg-amber/10 text-wg-amber",
                    g.status === "info" && "bg-muted/60 text-muted-foreground",
                  )}
                >
                  <g.icon className="size-3" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-medium text-foreground">
                    {i + 1}. {g.label}
                  </p>
                  <p className="truncate text-[10px] text-muted-foreground">{g.detail}</p>
                </div>
                <span className={cn("shrink-0 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", GATE_META[g.status].cls)}>
                  {GATE_META[g.status].label}
                </span>
              </div>
            ))}
          </div>

          <div
            className={cn(
              "mt-3 flex flex-wrap items-center gap-3 rounded-xl border p-3.5",
              sim.tone === "rose" && "border-wg-rose/40 bg-wg-rose/10",
              sim.tone === "emerald" && "border-wg-emerald/40 bg-wg-emerald/10",
              sim.tone === "amber" && "border-wg-amber/40 bg-wg-amber/10",
              sim.tone === "sky" && "border-wg-sky/40 bg-wg-sky/10",
            )}
          >
            <span
              className={cn(
                "flex size-9 items-center justify-center rounded-lg",
                sim.tone === "rose" && "bg-wg-rose/20 text-wg-rose",
                sim.tone === "emerald" && "bg-wg-emerald/20 text-wg-emerald",
                sim.tone === "amber" && "bg-wg-amber/20 text-wg-amber",
                sim.tone === "sky" && "bg-wg-sky/20 text-wg-sky",
              )}
            >
              {sim.status === 200 ? <CheckCircle2 className="size-4" /> : <XCircle className="size-4" />}
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-mono text-sm font-bold tracking-wider text-foreground">
                {sim.status} · {sim.label}
              </p>
              <p className="text-[11px] text-muted-foreground">{sim.summary}</p>
            </div>
            <span className="hidden font-mono text-[10px] text-muted-foreground sm:block">
              verdict in {Math.max(1, sim.gates.length * 2 + 1)}ms
            </span>
          </div>
        </div>

        <div className="wg-panel p-4 lg:col-span-2">
          <SectionTitle
            title={
              <span className="flex items-center gap-2">
                <Activity className="size-4 text-wg-rose" /> Live class impact
              </span>
            }
            sub="Attack classes observed in the last 120 requests — and how many were dropped"
          />
          <div className="flex flex-col gap-2.5">
            {classImpact.arr.map((a) => {
              const c = classImpact.byClass.get(a) ?? { total: 0, blocked: 0 };
              const w = (c.total / classImpact.max) * 100;
              return (
                <div key={a} className="flex items-center gap-2.5">
                  <span className="w-28 truncate text-[11px] text-foreground/80">{ATTACK_LABELS[a]}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                    <div
                      className={cn("h-full rounded-full", c.total === 0 ? "bg-border/30" : c.blocked >= c.total * 0.8 ? "bg-wg-emerald" : "bg-wg-rose")}
                      style={{ width: `${Math.max(w, c.total > 0 ? 6 : 0)}%` }}
                    />
                  </div>
                  <span className="w-14 text-right font-mono text-[10px] text-muted-foreground">
                    {c.total > 0 ? `${c.blocked}/${c.total}` : "—"}
                  </span>
                </div>
              );
            })}
          </div>
          <p className="mt-3 flex items-center gap-1.5 border-t border-border/40 pt-2.5 text-[10px] text-muted-foreground">
            <ArrowRight className="size-3 text-wg-cyan" />
            Bars reflect enforcement live — flip the firewall to BLOCKING and blocked counts climb in real time.
          </p>
        </div>
      </div>

      <div className="wg-panel p-4">
        <SectionTitle
          title="Policy engine"
          sub="Per-class rule actions applied at the edge. Challenge escalates bots to a CAPTCHA gate."
          right={<ModeBadge mode={state.mode} />}
        />
        <div className="flex flex-col gap-2">
          {state.rules.map((r) => (
            <div key={r.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-border/40 bg-muted/40 px-3.5 py-2.5">
              <span className="flex size-8 items-center justify-center rounded-lg bg-wg-cyan/10 text-wg-cyan">
                {r.id === "bots" ? <Bot className="size-4" /> : <ScanSearch className="size-4" />}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground">{r.label}</p>
                <p className="font-mono text-[10px] text-muted-foreground">CRS rules: {r.ruleIds}</p>
              </div>
              <span
                className={cn(
                  "rounded-md border px-2 py-1 text-[10px] font-bold tracking-wider",
                  ACTION_META[r.action].cls,
                )}
              >
                {ACTION_META[r.action].label}
              </span>
              <Select value={r.action} onValueChange={(v) => setRule(r, v as RuleAction)}>
                <SelectTrigger className="h-8 w-36 border-border/60 bg-muted/50 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-border/60 bg-popover">
                  {(["block", "challenge", "log", "disable"] as RuleAction[]).map((a) => (
                    <SelectItem key={a} value={a} className="text-xs">
                      {ACTION_META[a].label.toLowerCase()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ))}
        </div>
      </div>

      {/* preset profiles + coverage */}
      <div className="wg-panel p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-foreground">Preset profiles</p>
            <p className="text-xs text-muted-foreground">One-click policy configs for common postures</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">Coverage</span>
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-28 overflow-hidden rounded-full bg-border/40">
                <div
                  className={cn("h-full rounded-full", coverage >= 80 ? "bg-wg-emerald" : coverage >= 60 ? "bg-wg-amber" : "bg-wg-rose")}
                  style={{ width: `${coverage}%` }}
                />
              </div>
              <span className="font-mono text-xs font-bold text-foreground">{coverage}%</span>
            </div>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {PROFILES.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => applyProfile(p)}
              className={cn("flex flex-1 flex-col gap-0.5 rounded-xl border p-3 text-left transition-all hover:opacity-90", p.cls)}
            >
              <span className="text-[11px] font-bold tracking-widest">{p.label}</span>
              <span className="text-[10px] opacity-80">{p.desc}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* tuning */}
        <div className="wg-panel p-4">
          <SectionTitle title="ML & traffic tuning" sub="Detection sensitivity and request budgets" />
          <SliderRow
            icon={<SlidersHorizontal className="size-3.5" />}
            label="AI sensitivity"
            sub="Decision boundary for the threat classifier"
            value={state.settings.sensitivity}
            min={0.5}
            max={0.99}
            step={0.01}
            fmt={(v) => v.toFixed(2)}
            onChange={(v) => dispatch({ type: "SET_SETTING", key: "sensitivity", value: v })}
          />
          <SliderRow
            icon={<Activity className="size-3.5" />}
            label="Rate-limit budget"
            sub="Requests per minute before 429 throttling"
            value={state.settings.rateLimitRpm}
            min={10}
            max={1000}
            step={10}
            fmt={(v) => `${v} rpm`}
            onChange={(v) => dispatch({ type: "SET_SETTING", key: "rateLimitRpm", value: v })}
          />
        </div>

        {/* anomaly thresholds */}
        <div className="wg-panel p-4">
          <SectionTitle title="Anomaly thresholds" sub="Spike triggers that escalate alarms & incidents" />
          <SliderRow
            icon={<Ban className="size-3.5" />}
            label="5xx spike"
            sub="Error-rate % that raises an availability alarm"
            value={state.thresholds.fivexx}
            min={5}
            max={50}
            step={1}
            fmt={(v) => `${v}%`}
            onChange={(v) => dispatch({ type: "SET_THRESHOLD", key: "fivexx", value: v })}
          />
          <SliderRow
            icon={<Gauge className="size-3.5" />}
            label="DDoS burst"
            sub="Requests/sec that flags a volumetric attack"
            value={state.thresholds.ddos}
            min={30}
            max={300}
            step={10}
            fmt={(v) => `${v} rps`}
            onChange={(v) => dispatch({ type: "SET_THRESHOLD", key: "ddos", value: v })}
          />
          <SliderRow
            icon={<ShieldAlert className="size-3.5" />}
            label="Entropy cutoff"
            sub="Bits/char above which payloads are ML-blocked"
            value={state.thresholds.entropy}
            min={2.5}
            max={5.5}
            step={0.05}
            fmt={(v) => `${v.toFixed(2)} bits`}
            onChange={(v) => dispatch({ type: "SET_THRESHOLD", key: "entropy", value: v })}
          />
        </div>
      </div>

      {/* change log */}
      {changes.length > 0 && (
        <div className="wg-panel p-4">
          <SectionTitle
            title={
              <span className="flex items-center gap-2">
                <History className="size-4 text-wg-cyan" /> Policy change log
              </span>
            }
            sub="Recent configuration updates — newest first"
          />
          <div className="flex flex-col gap-1">
            {changes.map((c) => (
              <div key={c.id} className="flex items-center gap-3 rounded-lg border border-border/40 bg-muted/30 px-3 py-1.5 text-xs">
                <ShieldCheck className="size-3.5 shrink-0 text-wg-emerald" />
                <span className="flex-1 text-foreground/80">{c.text}</span>
                <span className="font-mono text-[10px] text-muted-foreground">{timeAgo(c.ts)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="wg-panel flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex size-9 items-center justify-center rounded-lg bg-emerald-400/10 text-wg-emerald">
            <Lock className="size-4" />
          </div>
          <div>
            <p className="text-sm font-semibold text-foreground">Mode behavior preview</p>
            <p className="text-xs text-muted-foreground">
              Current policy in <span className="font-mono">{state.mode}</span> mode — challenge escalates bots to a CAPTCHA gate
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {onNavigate && (
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1.5 border-wg-amber/40 bg-wg-amber/10 text-[11px] text-wg-amber hover:bg-wg-amber/20 hover:text-wg-amber"
              onClick={() => onNavigate("access")}
            >
              <Ban className="size-3.5" /> IP blocklist & custom rules
            </Button>
          )}
          {(["blocking", "detection", "off"] as WafMode[]).map((m) => (
            <Button
              key={m}
              variant="outline"
              size="sm"
              className={cn(
                "h-8 text-[11px]",
                state.mode === m &&
                  (m === "blocking"
                    ? "border-wg-emerald/50 bg-wg-emerald/15 text-wg-emerald"
                    : m === "detection"
                      ? "border-wg-amber/50 bg-wg-amber/15 text-wg-amber"
                      : "border-wg-rose/50 bg-wg-rose/15 text-wg-rose"),
              )}
              onClick={() => dispatch({ type: "SET_MODE", mode: m })}
            >
              {m === "blocking" ? "Block & patch" : m === "detection" ? "Log only" : "Bypass (raw)"}
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
}

function PolicyStat({
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

function SliderRow({
  icon,
  label,
  sub,
  value,
  min,
  max,
  step,
  fmt,
  onChange,
}: {
  icon: React.ReactNode;
  label: string;
  sub: string;
  value: number;
  min: number;
  max: number;
  step: number;
  fmt: (v: number) => string;
  onChange: (v: number) => void;
}) {
  return (
    <div className="py-3">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-wg-cyan">{icon}</span>
          <div>
            <p className="text-xs font-medium text-foreground">{label}</p>
            <p className="text-[10px] text-muted-foreground">{sub}</p>
          </div>
        </div>
        <Badge variant="outline" className="border-wg-cyan/30 bg-wg-cyan/5 font-mono text-[11px] text-wg-cyan">
          {fmt(value)}
        </Badge>
      </div>
      <Slider
        value={[value]}
        min={min}
        max={max}
        step={step}
        onValueChange={(v) => onChange(v[0])}
        className="[&_[role=slider]]:border-wg-cyan [&_[role=slider]]:bg-wg-cyan"
      />
    </div>
  );
}
