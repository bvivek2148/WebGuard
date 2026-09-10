import { useMemo, useState, useCallback, useRef, useEffect } from "react";
import { toast } from "sonner";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import { uid, shannonEntropy, randInt } from "../engine";
import type { HttpMethod, Severity, VulnFinding } from "../types";
import { SEVERITY_META, ATTACK_LABELS } from "../types";
import { SectionTitle, StatusBadge, timeAgo } from "./shared";
import {
  SITE_TEMPLATES,
  VULN_DEFS,
  ATTACK_CHAINS,
  type VulnId,
  type SiteTemplateId,
  type LabSiteConfig,
  type LabAttackResult,
  type AttackChain,
  runLabAttack,
  labResultToLog,
  labResultToFinding,
} from "../vulnLab";
import {
  AlertTriangle,
  ArrowRight,
  Ban,
  Braces,
  Bug,
  ChevronDown,
  ChevronRight,
  ClipboardCopy,
  Code2,
  Copy,
  Crosshair,
  Database,
  FileDown,
  FlaskConical,
  Globe2,
  Layers,
  Lock,
  Play,
  Plus,
  Rocket,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Swords,
  Terminal,
  Trash2,
  TreePine,
  Trophy,
  Zap,
  X,
} from "lucide-react";

// ============================================================================
// VulnLabTab — Interactive Vulnerability Lab
// ============================================================================

export interface VulnLabProps {
  templateId: SiteTemplateId;
  setTemplateId: (v: SiteTemplateId) => void;
  enabledVulns: VulnId[];
  setEnabledVulns: (v: VulnId[] | ((prev: VulnId[]) => VulnId[])) => void;
  wafOn: boolean;
  setWafOn: (v: boolean | ((prev: boolean) => boolean)) => void;
  attackHistory: LabAttackResult[];
  setAttackHistory: (v: LabAttackResult[] | ((prev: LabAttackResult[]) => LabAttackResult[])) => void;
}

export function VulnLabTab(props: VulnLabProps) {
  const { state, dispatch } = useWaf();
  const [activeSection, setActiveSection] = useState<"builder" | "chains" | "custom">("builder");

  // Site configuration
  const { templateId, setTemplateId, enabledVulns, setEnabledVulns, wafOn, setWafOn, attackHistory, setAttackHistory } = props;

  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});

  // Attack state
  const [attackPayload, setAttackPayload] = useState("");
  const [attackMethod, setAttackMethod] = useState<HttpMethod>("POST");
  const [attackPath, setAttackPath] = useState("/api/login");

  const [expandedResult, setExpandedResult] = useState<string | null>(null);
  const [selectedChain, setSelectedChain] = useState<string | null>(null);
  const [runningChain, setRunningChain] = useState<{ chainId: string; step: number; results: LabAttackResult[] } | null>(null);

  // Custom vuln
  const [customVulnName, setCustomVulnName] = useState("");
  const [customVulnPayload, setCustomVulnPayload] = useState("");
  const [customVulnSeverity, setCustomVulnSeverity] = useState<Severity>("medium");

  // Attack effect animation
  const [attackEffect, setAttackEffect] = useState<"exploit" | "blocked" | null>(null);

  const template = SITE_TEMPLATES.find((t) => t.id === templateId)!;

  // Initialize field values when template changes
  useEffect(() => {
    const vals: Record<string, string> = {};
    for (const f of template.fields) vals[f.id] = f.defaultValue;
    setFieldValues(vals);
    if (templateId === "login") { setAttackPath("/api/login"); setAttackMethod("POST"); }
    else if (templateId === "search") { setAttackPath("/search?q=test"); setAttackMethod("GET"); }
    else if (templateId === "contact") { setAttackPath("/api/contact"); setAttackMethod("POST"); }
    else if (templateId === "api") { setAttackPath("/api/users?id=42"); setAttackMethod("GET"); }
  }, [templateId]);

  const toggleVuln = useCallback((vid: VulnId) => {
    setEnabledVulns((prev) => prev.includes(vid) ? prev.filter((v) => v !== vid) : [...prev, vid]);
  }, []);

  // Get vulns relevant to current template
  const relevantVulns = useMemo(() => {
    const fieldVulnIds = new Set(template.fields.flatMap((f) => f.vulnIds));
    return Object.values(VULN_DEFS).filter((v) => fieldVulnIds.has(v.id) || v.id === "custom");
  }, [template]);

  // Trigger attack effect animation
  const triggerEffect = useCallback((type: "exploit" | "blocked") => {
    setAttackEffect(type);
    setTimeout(() => setAttackEffect(null), 2000);
  }, []);

  // Run single attack
  const launchAttack = useCallback(() => {
    if (!attackPayload.trim()) {
      toast.error("Enter an attack payload first");
      return;
    }
    const config: LabSiteConfig = {
      templateId,
      enabledVulns,
      customVulnName,
      customVulnPayload,
      customVulnSeverity,
      fieldValues,
    };
    const result = runLabAttack(config, attackPayload, attackMethod, attackPath, wafOn);
    setAttackHistory((prev) => [result, ...prev].slice(0, 100));

    // Integrate with live sections
    dispatch({ type: "INJECT_LOG", log: labResultToLog(result) });
    if (!result.blocked && result.vulnId !== "custom") {
      dispatch({ type: "ADD_FINDING", finding: labResultToFinding(result) as VulnFinding });
    }

    if (result.blocked) {
      triggerEffect("blocked");
      toast.success("Attack BLOCKED by WebGuard WAF", { description: `${VULN_DEFS[result.vulnId]?.label} — 403 Forbidden` });
    } else {
      triggerEffect("exploit");
      toast.error("Attack SUCCEEDED — vulnerability exploited!", { description: `${VULN_DEFS[result.vulnId]?.label} — ${result.response.status}` });
    }
  }, [attackPayload, attackMethod, attackPath, wafOn, templateId, enabledVulns, customVulnName, customVulnPayload, customVulnSeverity, fieldValues, dispatch, triggerEffect]);

  // Run attack chain
  const launchChain = useCallback((chain: AttackChain) => {
    setSelectedChain(chain.id);
    const config: LabSiteConfig = {
      templateId: "api",
      enabledVulns: chain.steps.map((s) => s.vulnId),
      customVulnName: "",
      customVulnPayload: "",
      customVulnSeverity: "medium",
      fieldValues: {},
    };

    setRunningChain({ chainId: chain.id, step: 0, results: [] });

    chain.steps.forEach((step, i) => {
      setTimeout(() => {
        const method: HttpMethod = step.vulnId === "sqli-login" || step.vulnId === "cmdi" || step.vulnId === "csrf" || step.vulnId === "stored-xss" || step.vulnId === "email-injection" ? "POST" : "GET";
        const path = step.vulnId === "sqli-search" ? "/search?q=test" : step.vulnId === "sqli-login" ? "/api/login" : step.vulnId === "cmdi" ? "/api/ping" : step.vulnId === "ssrf" ? "/api/ping" : `/api/${step.vulnId}`;
        const result = runLabAttack(config, step.payload, method, path, wafOn, chain.id, i);
        setAttackHistory((prev) => [result, ...prev].slice(0, 100));
        dispatch({ type: "INJECT_LOG", log: labResultToLog(result) });
        if (!result.blocked) dispatch({ type: "ADD_FINDING", finding: labResultToFinding(result) as VulnFinding });

        setRunningChain((prev) => {
          if (!prev) return null;
          const newResults = [...prev.results, result];
          if (i === chain.steps.length - 1) {
            setTimeout(() => setRunningChain(null), 1500);
          }
          return { ...prev, step: i + 1, results: newResults };
        });
      }, (i + 1) * 1200);
    });

    toast.info(`Attack chain started: ${chain.name}`, { description: `${chain.steps.length} steps — watch the exploit unfold` });
  }, [wafOn, dispatch]);

  // Stats
  const totalAttacks = attackHistory.length;
  const blockedCount = attackHistory.filter((r) => r.blocked).length;
  const exploitedCount = totalAttacks - blockedCount;
  const chainCount = new Set(attackHistory.filter((r) => r.chainId).map((r) => r.chainId)).size;
  const blockRate = totalAttacks > 0 ? Math.round((blockedCount / totalAttacks) * 100) : 0;

  return (
    <div className="flex flex-col gap-4">
      {/* Header Stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <LabStat icon={<FlaskConical className="size-4" />} label="Lab attacks" value={totalAttacks} accent="text-wg-cyan" sub="this session" />
        <LabStat icon={<ShieldCheck className="size-4" />} label="Blocked by WAF" value={blockedCount} accent="text-wg-emerald" sub={totalAttacks > 0 ? `${blockRate}% stop rate` : "403 responses"} />
        <LabStat icon={<ShieldOff className="size-4" />} label="Exploits succeeded" value={exploitedCount} accent="text-wg-rose" sub="vulnerabilities hit" />
        <LabStat icon={<Swords className="size-4" />} label="Attack chains" value={chainCount} accent="text-wg-violet" sub="multi-step runs" />
        <LabStat
          icon={wafOn ? <Shield className="size-4" /> : <Ban className="size-4" />}
          label="WAF Status"
          value={wafOn ? "ON" : "OFF"}
          accent={wafOn ? "text-wg-emerald" : "text-wg-rose"}
          sub={wafOn ? "Blocking attacks" : "Vulnerable"}
        />
      </div>

      {/* Section Navigation */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        {([
          { id: "builder" as const, label: "🛡️ Site Builder" },
          { id: "chains" as const, label: "⛓️ Attack Chains" },
          { id: "custom" as const, label: "🔧 Custom Vuln" },
        ]).map(({ id, label }) => (
          <button
            key={id}
            type="button"
            onClick={() => setActiveSection(id)}
            className={cn(
              "flex shrink-0 items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors",
              activeSection === id ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan" : "border-border/40 text-muted-foreground hover:text-foreground/80",
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* SITE BUILDER                                                       */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {activeSection === "builder" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          {/* Left: Site Builder + Vulnerability Toggles */}
          <div className="flex flex-col gap-4 xl:col-span-4">
            {/* Template Selector */}
            <div className="wg-panel p-4">
              <SectionTitle title="Vulnerable Website" sub="Choose a template and configure which vulnerabilities to enable" />
              <div className="mt-3 grid grid-cols-2 gap-2">
                {SITE_TEMPLATES.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setTemplateId(t.id)}
                    className={cn(
                      "flex items-start gap-2.5 rounded-xl border p-3 text-left transition-all",
                      templateId === t.id
                        ? "border-wg-cyan/50 bg-wg-cyan/[0.06] shadow-[0_0_15px_rgba(34,211,238,0.06)]"
                        : "border-border/40 bg-muted/20 hover:border-wg-cyan/30",
                    )}
                  >
                    <span className="text-xl">{t.icon}</span>
                    <span className="min-w-0">
                      <span className="block text-xs font-semibold text-foreground">{t.label}</span>
                      <span className="mt-0.5 block text-[10px] leading-snug text-muted-foreground">{t.description}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Vulnerability Toggles */}
            <div className="wg-panel p-4">
              <SectionTitle title="Active Vulnerabilities" sub="Toggle which vulns the simulated site has" right={<Badge variant="outline" className="gap-1 border-wg-rose/40 bg-wg-rose/10 text-[10px] text-wg-rose">{enabledVulns.length} enabled</Badge>} />
              <div className="mt-3 flex flex-col gap-2">
                {relevantVulns.map((vuln) => {
                  const enabled = enabledVulns.includes(vuln.id);
                  const sm = SEVERITY_META[vuln.severity];
                  return (
                    <button
                      key={vuln.id}
                      type="button"
                      onClick={() => toggleVuln(vuln.id)}
                      className={cn(
                        "flex items-center gap-3 rounded-xl border p-3 text-left transition-all",
                        enabled
                          ? "border-wg-rose/40 bg-wg-rose/[0.06] shadow-[0_0_12px_rgba(244,63,94,0.04)]"
                          : "border-border/30 bg-muted/10 opacity-60 hover:opacity-80",
                      )}
                    >
                      <div className={cn("flex size-8 shrink-0 items-center justify-center rounded-lg text-sm", enabled ? "bg-wg-rose/15" : "bg-muted/40")}>
                        {enabled ? "🔓" : "🔒"}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-foreground">{vuln.label}</span>
                          <span className={cn("rounded-full border px-1.5 py-0.5 text-[8px] font-bold", sm.badge)}>{sm.label}</span>
                        </div>
                        <p className="mt-0.5 text-[10px] text-muted-foreground">{vuln.cwe} · {vuln.category}</p>
                      </div>
                      <div className={cn("size-5 shrink-0 rounded-full border-2 transition-all duration-300", enabled ? "border-wg-rose bg-wg-rose shadow-[0_0_8px_rgba(244,63,94,0.4)]" : "border-border/60 bg-transparent")} />
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Field Values */}
            <div className="wg-panel p-4">
              <SectionTitle title="Field Values" sub="Pre-fill values or enter attack payloads" />
              <div className="mt-3 flex flex-col gap-2.5">
                {template.fields.map((field) => (
                  <div key={field.id}>
                    <label className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">{field.label}</label>
                    {field.type === "textarea" ? (
                      <Textarea
                        value={fieldValues[field.id] ?? ""}
                        onChange={(e) => setFieldValues((prev) => ({ ...prev, [field.id]: e.target.value }))}
                        placeholder={field.placeholder}
                        className="min-h-16 resize-none border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                        spellCheck={false}
                      />
                    ) : field.type === "select" ? (
                      <select
                        value={fieldValues[field.id] ?? ""}
                        onChange={(e) => setFieldValues((prev) => ({ ...prev, [field.id]: e.target.value }))}
                        className="h-9 w-full rounded-md border border-border/60 bg-muted/50 px-2 font-mono text-xs text-foreground"
                      >
                        <option value="all">All Categories</option>
                        <option value="waf">WAF</option>
                        <option value="auth">Auth</option>
                      </select>
                    ) : (
                      <Input
                        value={fieldValues[field.id] ?? ""}
                        onChange={(e) => setFieldValues((prev) => ({ ...prev, [field.id]: e.target.value }))}
                        placeholder={field.placeholder}
                        type={field.type}
                        className="h-9 border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                        spellCheck={false}
                      />
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Middle: Attack Workshop + Results */}
          <div className="flex flex-col gap-4 xl:col-span-5">
            {/* WAF Toggle — enhanced with animation */}
            <div
              className={cn(
                "wg-panel p-4 transition-all duration-500",
                attackEffect === "exploit" && "shadow-[0_0_30px_rgba(244,63,94,0.1)]",
                attackEffect === "blocked" && "shadow-[0_0_30px_rgba(52,211,153,0.1)]",
              )}
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <SectionTitle title="WebGuard Protection" sub="Toggle WAF to see before vs. after" />
                <button
                  type="button"
                  onClick={() => setWafOn((v) => !v)}
                  className={cn(
                    "group flex items-center gap-2.5 rounded-xl border-2 px-5 py-3 text-sm font-bold transition-all duration-300",
                    wafOn
                      ? "border-wg-emerald bg-wg-emerald/15 text-wg-emerald shadow-[0_0_25px_rgba(52,211,153,0.2)] hover:shadow-[0_0_35px_rgba(52,211,153,0.3)]"
                      : "border-wg-rose bg-wg-rose/15 text-wg-rose shadow-[0_0_25px_rgba(244,63,94,0.2)] hover:shadow-[0_0_35px_rgba(244,63,94,0.3)]",
                  )}
                >
                  {wafOn ? (
                    <Shield className="size-5 transition-transform duration-300 group-hover:scale-110" />
                  ) : (
                    <ShieldOff className="size-5 transition-transform duration-300 group-hover:scale-110" />
                  )}
                  {wafOn ? "WEBGUARD ACTIVE — BLOCKING" : "WEBGUARD OFF — UNPROTECTED"}
                </button>
              </div>
              {wafOn ? (
                <div className="mt-3 rounded-xl border border-wg-emerald/30 bg-wg-emerald/[0.06] p-3">
                  <p className="flex items-center gap-2 text-[11px] font-semibold text-wg-emerald">
                    <span className="size-1.5 animate-pulse rounded-full bg-wg-emerald" />
                    ✅ Virtual patches active: {enabledVulns.length} vulnerabilities monitored
                  </p>
                  <p className="mt-1 text-[10px] text-wg-emerald/80">
                    Attacks will be intercepted at the edge and blocked with 403 responses. No origin contact is made.
                  </p>
                </div>
              ) : (
                <div className="mt-3 rounded-xl border border-wg-rose/30 bg-wg-rose/[0.06] p-3">
                  <p className="flex items-center gap-2 text-[11px] font-semibold text-wg-rose">
                    <span className="size-1.5 animate-pulse rounded-full bg-wg-rose" />
                    ⚠️ No protection! The site is fully vulnerable
                  </p>
                  <p className="mt-1 text-[10px] text-wg-rose/80">
                    All enabled attack vectors will succeed. Data will be exposed and the server may be compromised.
                  </p>
                </div>
              )}
            </div>

            {/* Attack Composer — enhanced */}
            <div className="wg-panel p-4">
              <SectionTitle
                title="Attack Workshop"
                sub="Craft and launch an attack against the vulnerable site"
                right={
                  <span className="flex items-center gap-1.5 rounded-lg border border-wg-rose/30 bg-wg-rose/10 px-2.5 py-1 text-[10px] font-bold text-wg-rose">
                    <Rocket className="size-3" /> ATTACK
                  </span>
                }
              />
              <div className="mt-3 flex flex-col gap-2.5">
                <div className="flex gap-2">
                  <select
                    value={attackMethod}
                    onChange={(e) => setAttackMethod(e.target.value as HttpMethod)}
                    className="h-9 w-24 rounded-md border border-border/60 bg-muted/50 px-2 font-mono text-xs font-bold text-wg-cyan"
                  >
                    {(["GET", "POST", "PUT", "DELETE"] as HttpMethod[]).map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                  <Input
                    value={attackPath}
                    onChange={(e) => setAttackPath(e.target.value)}
                    className="h-9 flex-1 border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                    spellCheck={false}
                  />
                </div>
                <Textarea
                  value={attackPayload}
                  onChange={(e) => setAttackPayload(e.target.value)}
                  placeholder="Enter attack payload — try: username=admin' OR '1'='1'--"
                  className="min-h-20 resize-none border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                  spellCheck={false}
                />
                {/* Quick payload suggestions */}
                <div className="flex flex-wrap gap-1.5">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground/60">Quick:</span>
                  {relevantVulns.flatMap((v) => v.samplePayloads.slice(0, 1).map((p, i) => (
                    <button
                      key={`${v.id}-${i}`}
                      type="button"
                      onClick={() => { setAttackPayload(p); setAttackMethod(v.id.includes("login") ? "POST" : "GET"); }}
                      className="flex items-center gap-1 rounded-md border border-border/50 bg-muted/40 px-2 py-0.5 text-[10px] text-foreground/70 transition-colors hover:border-wg-rose/40 hover:text-wg-rose"
                    >
                      <Bug className="size-2.5" />
                      {v.label.split("(")[0].trim()}
                    </button>
                  )))}
                </div>
                <Button
                  onClick={launchAttack}
                  className={cn(
                    "h-11 gap-2 rounded-xl text-sm font-bold shadow-lg transition-all",
                    wafOn
                      ? "border-wg-emerald/40 bg-gradient-to-r from-wg-emerald/20 to-emerald-600/20 text-wg-emerald hover:shadow-wg-emerald/20"
                      : "border-wg-rose/40 bg-gradient-to-r from-wg-rose/20 to-rose-600/20 text-wg-rose hover:shadow-wg-rose/20",
                  )}
                >
                  <Rocket className="size-4" />
                  {wafOn ? "Launch Attack (WAF will defend)" : "Launch Attack (site is vulnerable!)"}
                </Button>
              </div>
            </div>

            {/* Attack Results — enhanced with more detail */}
            <div className="flex flex-col gap-3">
              <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
                <FlaskConical className="size-4 text-wg-cyan" /> Attack Results
                {attackHistory.length > 0 && (
                  <span className="ml-2 font-mono text-[10px] font-normal text-muted-foreground">
                    {attackHistory.length} total · {blockedCount} blocked · {exploitedCount} exploited
                  </span>
                )}
              </p>
              {attackHistory.length === 0 ? (
                <div className="wg-panel flex flex-col items-center gap-3 p-10 text-center">
                  <div className="flex size-16 items-center justify-center rounded-2xl bg-muted/30">
                    <FlaskConical className="size-8 text-muted-foreground/50" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">No attacks launched yet</p>
                    <p className="mt-1 max-w-sm text-xs text-muted-foreground">
                      Select a template, enable vulnerabilities, and launch an attack against the site. Toggle the WAF to see the difference between protected and unprotected states.
                    </p>
                  </div>
                </div>
              ) : (
                attackHistory.slice(0, 15).map((r) => {
                  const vulnDef = VULN_DEFS[r.vulnId];
                  const sm = vulnDef ? SEVERITY_META[vulnDef.severity] : null;
                  return (
                    <div
                      key={r.id}
                      className="wg-panel overflow-hidden p-0 transition-all duration-300"
                      style={{ borderLeft: `4px solid ${r.blocked ? "#34d399" : "#f43f5e"}` }}
                    >
                      <button
                        type="button"
                        onClick={() => setExpandedResult(expandedResult === r.id ? null : r.id)}
                        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-muted/20"
                      >
                        <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-xl text-sm", r.blocked ? "bg-wg-emerald/15" : "bg-wg-rose/15")}>
                          {r.blocked ? <ShieldCheck className="size-4 text-wg-emerald" /> : <AlertTriangle className="size-4 text-wg-rose" />}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-foreground">{vulnDef?.label ?? "Custom"}</span>
                            {sm && <span className={cn("rounded-full border px-1.5 py-0.5 text-[8px] font-bold", sm.badge)}>{sm.label}</span>}
                          </div>
                          <p className="mt-0.5 max-w-[300px] truncate font-mono text-[10px] text-muted-foreground">{r.payload.slice(0, 80)}</p>
                        </div>
                        <StatusBadge status={r.response.status} />
                        <span className={cn("shrink-0 rounded-md border px-2 py-0.5 text-[9px] font-bold tracking-wider", r.blocked ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose")}>
                          {r.blocked ? "BLOCKED" : "EXPLOITED"}
                        </span>
                        <span className={cn("shrink-0 font-mono text-[9px] font-bold", r.threatScore > 70 ? "text-wg-rose" : r.threatScore > 40 ? "text-wg-amber" : "text-wg-emerald")}>
                          t{r.threatScore}
                        </span>
                        <ChevronDown className={cn("size-4 shrink-0 text-muted-foreground transition-transform duration-200", expandedResult === r.id && "rotate-180")} />
                      </button>

                      {expandedResult === r.id && (
                        <div className="border-t border-border/40 bg-muted/10 px-4 py-4">
                          {/* Threat Score Bar */}
                          <div className="mb-3 rounded-xl border border-border/40 bg-muted/20 p-3">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Threat Score</span>
                              <span className={cn("font-mono text-lg font-bold", r.threatScore > 70 ? "text-wg-rose" : r.threatScore > 40 ? "text-wg-amber" : "text-wg-emerald")}>
                                {r.threatScore}<span className="text-xs text-muted-foreground">/100</span>
                              </span>
                            </div>
                            <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-border/40">
                              <div
                                className={cn("h-full rounded-full transition-all duration-700", r.threatScore > 70 ? "bg-gradient-to-r from-wg-rose to-red-400" : r.threatScore > 40 ? "bg-gradient-to-r from-wg-amber to-yellow-400" : "bg-gradient-to-r from-wg-emerald to-emerald-400")}
                                style={{ width: `${r.threatScore}%` }}
                              />
                            </div>
                          </div>

                          {/* Before/After comparison — enhanced */}
                          <div className="mb-3 grid grid-cols-2 gap-3">
                            <div className="rounded-xl border border-wg-rose/30 bg-wg-rose/[0.04] p-3">
                              <p className="mb-2 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-wg-rose">
                                <ShieldOff className="size-3" /> WAF OFF — What Happened
                              </p>
                              <pre className="max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[10px] leading-relaxed text-foreground/80">{r.evidence}</pre>
                            </div>
                            <div className="rounded-xl border border-wg-emerald/30 bg-wg-emerald/[0.04] p-3">
                              <p className="mb-2 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-wg-emerald">
                                <ShieldCheck className="size-3" /> WAF ON — What WebGuard Does
                              </p>
                              <pre className="max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[10px] leading-relaxed text-foreground/80">{vulnDef?.wafPatch ?? "Custom patch applied"}</pre>
                            </div>
                          </div>

                          {/* Vulnerability details — enhanced */}
                          {vulnDef && (
                            <div className="mb-3 rounded-xl border border-border/40 bg-muted/20 p-3">
                              <div className="flex flex-wrap items-center gap-3">
                                <span className="text-xs font-semibold text-foreground">{vulnDef.label}</span>
                                <span className={cn("rounded-full border px-1.5 py-0.5 text-[8px] font-bold", SEVERITY_META[vulnDef.severity].badge)}>{SEVERITY_META[vulnDef.severity].label}</span>
                                <span className="font-mono text-[9px] text-muted-foreground">{vulnDef.cwe} · {vulnDef.owasp}</span>
                              </div>
                              <p className="mt-1.5 text-[11px] text-muted-foreground">{vulnDef.description}</p>
                              <p className="mt-1 text-[11px] text-wg-rose font-medium">Impact: {vulnDef.impact}</p>
                            </div>
                          )}

                          {/* Attack Summary */}
                          <div className="mb-3 rounded-xl border border-border/40 bg-muted/20 p-3">
                            <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
                              <Layers className="mr-1 inline size-3 text-wg-cyan" />
                              Attack Analysis
                            </p>
                            <div className="flex flex-col gap-1.5">
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-muted-foreground">Verdict</span>
                                <span className={cn("font-bold", r.blocked ? "text-wg-emerald" : "text-wg-rose")}>{r.blocked ? "BLOCKED" : "EXPLOITED"}</span>
                              </div>
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-muted-foreground">Status Code</span>
                                <span className="font-mono font-bold text-foreground">{r.response.status}</span>
                              </div>
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-muted-foreground">Threat Score</span>
                                <span className={cn("font-mono font-bold", r.threatScore > 70 ? "text-wg-rose" : r.threatScore > 40 ? "text-wg-amber" : "text-wg-emerald")}>{r.threatScore}/100</span>
                              </div>
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-muted-foreground">WAF State</span>
                                <span className={cn("font-bold", r.wafOn ? "text-wg-emerald" : "text-wg-rose")}>{r.wafOn ? "ACTIVE" : "OFF"}</span>
                              </div>
                            </div>
                          </div>

                          {/* HTTP trace — enhanced */}
                          <div className="overflow-hidden rounded-lg border border-border/40">
                            <div className="flex items-center justify-between border-b border-border/30 bg-muted/40 px-3 py-1.5">
                              <p className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-wider text-muted-foreground/70">
                                <Terminal className="size-3" /> Raw HTTP Exchange
                              </p>
                              <span className="font-mono text-[9px] text-muted-foreground">lab-simulation</span>
                            </div>
                            <pre className="max-h-48 overflow-auto bg-[#0a0e18] px-3 py-2 font-mono text-[10px] leading-relaxed text-foreground/70">
                              <span className="text-wg-cyan">{r.request.method} {r.request.path}</span>{"\n"}
                              <span className="text-wg-cyan">host:</span> {r.request.headers["Host"]}{"\n"}
                              {Object.entries(r.request.headers).filter(([k]) => k !== "Host").slice(0, 3).map(([k, v]) => (
                                <span key={k}><span className="text-wg-cyan">{k.toLowerCase()}:</span> {v}{"\n"}</span>
                              ))}
                              {"\n"}
                              <span className={r.blocked ? "text-wg-emerald" : "text-wg-rose"}>→ {r.response.status} {r.response.status === 200 ? "OK" : r.response.status === 403 ? "Forbidden" : "Too Many Requests"}</span>{"\n"}
                              {Object.entries(r.response.headers).map(([k, v]) => (
                                <span key={k}><span className="text-wg-cyan">{k}:</span> {v}{"\n"}</span>
                              ))}
                              {"\n"}
                              <span className={r.blocked ? "text-wg-emerald" : "text-wg-rose"}>{r.response.body.slice(0, 300)}</span>
                            </pre>
                          </div>

                          {/* Action buttons */}
                          <div className="mt-3 flex flex-wrap gap-2">
                            <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-[10px] text-wg-cyan" onClick={() => { navigator.clipboard.writeText(r.payload); toast.success("Payload copied"); }}>
                              <Copy className="size-3" /> Copy payload
                            </Button>
                            <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-[10px] text-wg-amber" onClick={() => dispatch({ type: "ADD_FINDING", finding: labResultToFinding(r) as VulnFinding })}>
                              <Bug className="size-3" /> Log as finding
                            </Button>
                            <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-[10px] text-wg-emerald" onClick={() => dispatch({ type: "INJECT_LOG", log: labResultToLog(r) })}>
                              <Play className="size-3" /> Replay in traffic
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right: Quick Chains + History Stats */}
          <div className="flex flex-col gap-4 xl:col-span-3">
            {/* Vulnerability Status Summary — enhanced with animated score */}
            <div className="wg-panel p-4">
              <SectionTitle title="Site Security Posture" sub="Current state of the vulnerable site" />
              <div className="mt-3 flex flex-col gap-2">
                {relevantVulns.map((v) => {
                  const enabled = enabledVulns.includes(v.id);
                  const sm = SEVERITY_META[v.severity];
                  const hitCount = attackHistory.filter((r) => r.vulnId === v.id).length;
                  return (
                    <div key={v.id} className="flex items-center gap-2 rounded-lg border border-border/30 bg-muted/20 px-2.5 py-2">
                      <span className="text-sm">{enabled ? "🔓" : "🔒"}</span>
                      <span className="min-w-0 flex-1 truncate text-[10px] font-medium text-foreground/80">{v.label.split("(")[0].trim()}</span>
                      {hitCount > 0 && <span className="font-mono text-[9px] text-wg-rose">{hitCount}×</span>}
                      <span className={cn("rounded-full border px-1 py-0.5 text-[7px] font-bold", sm.badge)}>{sm.label}</span>
                    </div>
                  );
                })}
              </div>

              {/* Score Gauge — enhanced */}
              <div className="mt-3 rounded-xl border border-border/40 bg-muted/20 p-3">
                <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Security Score</p>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className={cn("font-mono text-4xl font-bold tracking-tighter transition-colors duration-500", enabledVulns.length === 0 ? "text-wg-emerald" : enabledVulns.length > 3 ? "text-wg-rose" : "text-wg-amber")}>
                    {enabledVulns.length === 0 ? "100" : Math.max(10, 100 - enabledVulns.length * 15 - exploitedCount * 5)}
                  </span>
                  <span className="text-xs text-muted-foreground">/100</span>
                  <span className={cn("ml-auto rounded-full border px-2.5 py-1 text-[9px] font-bold", enabledVulns.length === 0 ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" : enabledVulns.length > 3 ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose" : "border-wg-amber/40 bg-wg-amber/10 text-wg-amber")}>
                    {enabledVulns.length === 0 ? "GRADE A+" : enabledVulns.length > 3 ? "GRADE F" : "GRADE C"}
                  </span>
                </div>
                {/* Score bar */}
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-border/40">
                  <div
                    className={cn("h-full rounded-full transition-all duration-700", enabledVulns.length === 0 ? "bg-gradient-to-r from-wg-emerald to-emerald-400" : enabledVulns.length > 3 ? "bg-gradient-to-r from-wg-rose to-red-400" : "bg-gradient-to-r from-wg-amber to-yellow-400")}
                    style={{ width: `${enabledVulns.length === 0 ? 100 : Math.max(10, 100 - enabledVulns.length * 15 - exploitedCount * 5)}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Exploit Distribution Chart */}
            {attackHistory.length > 0 && (
              <div className="wg-panel p-4">
                <SectionTitle title="Attack Distribution" sub="Results by vulnerability type" />
                <div className="mt-3 h-[180px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={Object.entries(
                        attackHistory.reduce(
                          (acc, r) => {
                            const key = r.vulnId;
                            acc[key] = (acc[key] ?? { blocked: 0, exploited: 0 });
                            if (r.blocked) acc[key].blocked++;
                            else acc[key].exploited++;
                            return acc;
                          },
                          {} as Record<string, { blocked: number; exploited: number }>,
                        ),
                      ).map(([k, v]) => ({
                        name: VULN_DEFS[k as VulnId]?.label?.split("(")[0]?.trim().slice(0, 12) ?? k,
                        blocked: v.blocked,
                        exploited: v.exploited,
                      }))}
                      margin={{ top: 6, right: 4, left: -18, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" vertical={false} />
                      <XAxis dataKey="name" tick={{ fontSize: 8, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} interval={0} angle={-30} textAnchor="end" height={50} />
                      <YAxis tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                      <Tooltip contentStyle={{ fontSize: 11, background: "var(--popover)", border: "1px solid var(--border)" }} />
                      <Bar dataKey="blocked" name="Blocked" stackId="a" fill="#34d399" radius={[0, 0, 0, 0]} />
                      <Bar dataKey="exploited" name="Exploited" stackId="a" fill="#f43f5e" radius={[3, 3, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Recent Chain Activity */}
            {attackHistory.some((r) => r.chainId) && (
              <div className="wg-panel p-4">
                <SectionTitle title="Chain Progress" sub="Multi-step attack chain results" />
                <div className="mt-3 flex flex-col gap-2">
                  {[...new Set(attackHistory.filter((r) => r.chainId).map((r) => r.chainId))].map((cid) => {
                    const chain = ATTACK_CHAINS.find((c) => c.id === cid);
                    const chainResults = attackHistory.filter((r) => r.chainId === cid);
                    const allBlocked = chainResults.every((r) => r.blocked);
                    return (
                      <div key={cid} className="rounded-lg border border-border/40 bg-muted/20 p-2.5">
                        <p className="text-xs font-semibold text-foreground">{chain?.icon} {chain?.name ?? cid}</p>
                        <div className="mt-1.5 flex gap-1">
                          {chainResults.map((r, i) => (
                            <div key={i} className={cn("size-6 rounded-full border flex items-center justify-center text-[8px] font-bold", r.blocked ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose")}>
                              {i + 1}
                            </div>
                          ))}
                        </div>
                        <p className="mt-1 text-[9px] text-muted-foreground">{allBlocked ? "🛡️ All steps blocked" : "⚠️ Some steps exploited"}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* ATTACK CHAINS                                                      */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {activeSection === "chains" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {ATTACK_CHAINS.map((chain) => {
            const sm = SEVERITY_META[chain.severity];
            const isRunning = runningChain?.chainId === chain.id;
            return (
              <div key={chain.id} className="wg-panel p-5" style={{ borderLeft: `3px solid ${sm.color}` }}>
                <div className="flex items-start gap-3">
                  <span className="text-2xl">{chain.icon}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-bold text-foreground">{chain.name}</h3>
                      <span className={cn("rounded-full border px-1.5 py-0.5 text-[8px] font-bold", sm.badge)}>{sm.label}</span>
                      <span className="rounded-full border border-border/40 bg-muted/40 px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wider text-muted-foreground">{chain.difficulty}</span>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{chain.tagline}</p>

                    {/* Steps */}
                    <div className="mt-3 flex flex-col gap-1.5">
                      {chain.steps.map((step, i) => {
                        const vDef = VULN_DEFS[step.vulnId];
                        const result = runningChain?.chainId === chain.id ? runningChain.results[i] : undefined;
                        return (
                          <div key={i} className={cn("flex items-start gap-2 rounded-lg border px-3 py-2 transition-colors", result?.blocked === true ? "border-wg-emerald/40 bg-wg-emerald/[0.04]" : result ? "border-wg-rose/40 bg-wg-rose/[0.04]" : "border-border/30 bg-muted/10")}>
                            <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-muted/40 text-[9px] font-bold text-muted-foreground">{i + 1}</span>
                            <div className="min-w-0 flex-1">
                              <p className="text-[10px] font-semibold text-foreground/80">{step.description}</p>
                              <p className="mt-0.5 max-w-[300px] truncate font-mono text-[9px] text-muted-foreground">{step.payload.slice(0, 70)}</p>
                            </div>
                            {result && (
                              <span className={cn("shrink-0 rounded-md border px-1.5 py-0.5 text-[8px] font-bold", result.blocked ? "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald" : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose")}>
                                {result.blocked ? "BLOCKED" : "EXPLOITED"}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>

                    {/* Final Impact */}
                    <div className="mt-3 rounded-lg border border-border/40 bg-muted/20 p-2.5">
                      <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Final Impact</p>
                      <p className="mt-1 text-[11px] text-foreground/80">{chain.finalImpact}</p>
                    </div>

                    <Button
                      onClick={() => launchChain(chain)}
                      disabled={isRunning}
                      className={cn("mt-3 h-8 gap-1.5 text-[11px] font-bold", isRunning ? "bg-muted text-muted-foreground" : "border-wg-rose/40 bg-wg-rose/10 text-wg-rose hover:bg-wg-rose/20")}
                    >
                      {isRunning ? (
                        <><span className="size-1.5 animate-pulse rounded-full bg-amber-400" /> Running step {runningChain?.step ?? 0}/{chain.steps.length}...</>
                      ) : (
                        <><Play className="size-3" /> Launch Chain ({chain.steps.length} steps)</>
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* CUSTOM VULNERABILITY                                               */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {activeSection === "custom" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <div className="wg-panel p-5">
            <SectionTitle title="Custom Vulnerability" sub="Define your own vulnerability and test it against WebGuard" />
            <div className="mt-4 flex flex-col gap-3">
              <div>
                <label className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Vulnerability Name</label>
                <Input
                  value={customVulnName}
                  onChange={(e) => setCustomVulnName(e.target.value)}
                  placeholder="e.g., Insecure Deserialization"
                  className="h-9 border-border/60 bg-muted/50 text-xs focus-visible:ring-cyan-400/40"
                />
              </div>
              <div>
                <label className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Severity</label>
                <div className="flex gap-2">
                  {(["critical", "high", "medium", "low"] as Severity[]).map((sev) => {
                    const sm = SEVERITY_META[sev];
                    return (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => setCustomVulnSeverity(sev)}
                        className={cn(
                          "rounded-lg border px-3 py-1.5 text-[10px] font-bold transition-colors",
                          customVulnSeverity === sev ? sm.badge : "border-border/40 text-muted-foreground hover:text-foreground/80",
                        )}
                      >
                        {sm.label}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div>
                <label className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Test Payload</label>
                <Textarea
                  value={customVulnPayload}
                  onChange={(e) => setCustomVulnPayload(e.target.value)}
                  placeholder="Enter a custom payload to test..."
                  className="min-h-24 resize-none border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                  spellCheck={false}
                />
              </div>
              <Button
                onClick={() => {
                  if (!customVulnName.trim() || !customVulnPayload.trim()) {
                    toast.error("Fill in the vulnerability name and payload");
                    return;
                  }
                  if (!enabledVulns.includes("custom")) setEnabledVulns((prev) => [...prev, "custom"]);
                  setAttackPayload(customVulnPayload);
                  setActiveSection("builder");
                  setTimeout(() => {
                    const config: LabSiteConfig = {
                      templateId,
                      enabledVulns: [...enabledVulns, "custom"],
                      customVulnName,
                      customVulnPayload,
                      customVulnSeverity,
                      fieldValues,
                    };
                    const result = runLabAttack(config, customVulnPayload, attackMethod, attackPath, wafOn);
                    setAttackHistory((prev) => [result, ...prev].slice(0, 100));
                    dispatch({ type: "INJECT_LOG", log: labResultToLog(result) });
                    if (result.blocked) triggerEffect("blocked");
                    else triggerEffect("exploit");
                    toast.success(`Custom attack: ${result.blocked ? "BLOCKED" : "EXPLOITED"}`);
                  }, 100);
                }}
                className="h-10 gap-2 border-wg-violet/40 bg-wg-violet/10 text-sm font-bold text-wg-violet hover:bg-wg-violet/20"
              >
                <Zap className="size-4" /> Test Custom Vulnerability
              </Button>
            </div>
          </div>

          {/* Custom Vuln Guide */}
          <div className="flex flex-col gap-4">
            <div className="wg-panel p-5">
              <SectionTitle title="How Custom Vulnerabilities Work" />
              <div className="mt-3 flex flex-col gap-3">
                {[
                  { step: "1", title: "Define your vulnerability", desc: "Name it, set severity, and write a description of the weakness.", icon: <Bug className="size-4 text-wg-violet" /> },
                  { step: "2", title: "Craft a test payload", desc: "Write the exact attack string that would exploit this vulnerability.", icon: <Code2 className="size-4 text-wg-cyan" /> },
                  { step: "3", title: "Run the test", desc: "Launch the attack against the simulated site with WAF OFF to see exploitation.", icon: <Play className="size-4 text-wg-rose" /> },
                  { step: "4", title: "Activate WebGuard", desc: "Toggle WAF ON and re-run. WebGuard will detect and block the custom payload.", icon: <Shield className="size-4 text-wg-emerald" /> },
                  { step: "5", title: "Analyze results", desc: "Review the before/after comparison, raw HTTP exchange, and virtual patch applied.", icon: <Search className="size-4 text-wg-amber" /> },
                ].map(({ step, title, desc, icon }) => (
                  <div key={step} className="flex items-start gap-3 rounded-lg border border-border/30 bg-muted/10 px-3 py-2.5">
                    <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-wg-violet/15 text-wg-violet">{icon}</span>
                    <div>
                      <p className="text-xs font-semibold text-foreground">{title}</p>
                      <p className="mt-0.5 text-[10px] text-muted-foreground">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="wg-panel p-5">
              <SectionTitle title="Custom Payload Examples" />
              <div className="mt-3 flex flex-col gap-2">
                {[
                  { label: "Insecure Deserialization", payload: '{"type":"Java","data":"rO0ABXNy..."}', sev: "critical" },
                  { label: "XML External Entity", payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', sev: "high" },
                  { label: "Prototype Pollution", payload: '{"__proto__":{"admin":true}}', sev: "medium" },
                  { label: "NoSQL Injection", payload: '{"username":{"$gt":""},"password":{"$gt":""}}', sev: "high" },
                ].map((ex) => (
                  <button
                    key={ex.label}
                    type="button"
                    onClick={() => { setCustomVulnName(ex.label); setCustomVulnPayload(ex.payload); setCustomVulnSeverity(ex.sev as Severity); }}
                    className="rounded-lg border border-border/30 bg-muted/10 px-3 py-2 text-left transition-colors hover:border-wg-violet/40"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-semibold text-foreground/80">{ex.label}</span>
                      <span className={cn("rounded-full border px-1 py-0.5 text-[7px] font-bold", SEVERITY_META[ex.sev as Severity].badge)}>{SEVERITY_META[ex.sev as Severity].label}</span>
                    </div>
                    <p className="mt-0.5 max-w-[350px] truncate font-mono text-[9px] text-muted-foreground">{ex.payload.slice(0, 60)}</p>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Shared stat card ────────────────────────────────────────────────────────

function LabStat({ icon, label, value, accent, sub }: { icon: React.ReactNode; label: string; value: number | string; accent: string; sub: string }) {
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
