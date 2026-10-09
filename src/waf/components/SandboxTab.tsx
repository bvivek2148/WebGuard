import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Bar, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { ATTACK_ORIGINS, ATTACK_SPECS, BENIGN_ORIGINS, originIp, pickOrigin } from "../data";
import { rand, randInt, shannonEntropy, uid, useWaf } from "../engine";
import type {
  AllowedIp,
  AttackSpec,
  BlockedIp,
  CustomRule,
  HttpMethod,
  RequestLog,
  SandboxResult,
  SavedProbe,
  TraceStep,
  TraceVerdict,
  VulnFinding,
  WafMode,
} from "../types";
import { SectionTitle, StatusBadge, flagEmoji, timeAgo } from "./shared";
import { Activity, Ban, Binary, BookmarkPlus, Bot, Braces, ChevronDown, ClipboardCopy, Code2, Crosshair, Database, Eraser, FileDown, FlaskConical, FolderTree, Gauge, Globe2, KeyRound, Layers, Library, ListChecks, Play, Plus, RadarIcon, Save, Send, Server, ShieldAlert, ShieldCheck, Shuffle, SlidersHorizontal, Sparkles, Swords, Timer, TriangleAlert, Waypoints, X, Zap } from "lucide-react";
import { copilotContextFromSandbox } from "./sandboxCopilot";
import { VulnLabTab } from "./VulnLabTab";
import { WebLabTab } from "./WebLabTab";
import type { SiteTemplateId, VulnId, LabAttackResult } from "../vulnLab";
import { ExportMenu } from "./ExportMenu";

const VERDICT_ACCENT: Record<SandboxResult["verdict"], string> = {
  BLOCKED: "#f43f5e",
  THROTTLED: "#facc15",
  ALLOWED: "#34d399",
};

export function SandboxTab() {
  const { state, dispatch } = useWaf();
  const [method, setMethod] = useState<HttpMethod>("GET");
  const [path, setPath] = useState("/api/search?id=1");
  const [payload, setPayload] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [runMode, setRunMode] = useState<WafMode | "global">("global");
  const [sourcePreset, setSourcePreset] = useState<"benign" | "attacker" | "custom">("benign");
  const [src, setSrc] = useState(() => {
    const o = pickOrigin(BENIGN_ORIGINS);
    return { ip: originIp(o), code: o.geo.code };
  });
  const [headers, setHeaders] = useState<Array<{ key: string; value: string }>>([
    {
      key: "User-Agent",
      value:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    },
    { key: "Accept", value: "text/html,application/xhtml+xml" },
    { key: "X-Requested-With", value: "XMLHttpRequest" },
  ]);
  const [headersOpen, setHeadersOpen] = useState(false);
  const [probeLabel, setProbeLabel] = useState("");
  const [libOpen, setLibOpen] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(PAYLOAD_LIBRARY.map((g) => [g.group, true])),
  );
  const [sweep, setSweep] = useState<
    | null
    | Array<{ label: string; desc: string; payload: string; result: SandboxResult }>
  >(null);
  const [burst, setBurst] = useState<{ label: string; done: number; total: number } | null>(null);
  const [sandboxSubTab, setSandboxSubTab] = useState<"sandbox" | "lab" | "weblab">("sandbox");
  const [labTemplateId, setLabTemplateId] = useState<SiteTemplateId>("login");
  const [labEnabledVulns, setLabEnabledVulns] = useState<VulnId[]>(["sqli-login", "brute-force"]);
  const [labWafOn, setLabWafOn] = useState(false);
  const [labAttackHistory, setLabAttackHistory] = useState<LabAttackResult[]>([]);

  const applySourcePreset = (p: "benign" | "attacker" | "custom") => {
    setSourcePreset(p);
    if (p === "custom") return;
    const o = pickOrigin(p === "benign" ? BENIGN_ORIGINS : ATTACK_ORIGINS);
    setSrc({ ip: originIp(o), code: o.geo.code });
  };

  const previewSpec = useMemo(
    () => (method && path ? detectSpec(method, path, payload) : null),
    [method, path, payload],
  );

  // How the edge policy treats the composer's source IP right now
  const srcStatus = useMemo(() => {
    const matchIp = (entry: string, ip: string) =>
      entry === ip || (entry.endsWith("/24") && ip.startsWith(entry.replace("/24", "")));
    return {
      allowlisted: state.allowlist.some((a) => matchIp(a.ip, src.ip)),
      banned: state.blocklist.some((b) => b.active && matchIp(b.ip, src.ip)),
      geoBlocked: state.geoBlock.includes(src.code),
    };
  }, [state.allowlist, state.blocklist, state.geoBlock, src.ip, src.code]);

  // Verdict trend for the last runs — latency bars + threat-score line
  const trendData = useMemo(
    () =>
      [...state.sandbox].reverse().map((r, i) => ({
        n: `#${i + 1}`,
        latencyMs: Math.round(r.latencyMs * 10) / 10,
        threatScore: r.threatScore,
        verdict: r.verdict,
        path: r.path,
      })),
    [state.sandbox],
  );

  // Custom headers as a flat record — what the request actually carries
  const headersRecord = useMemo(() => {
    const out: Record<string, string> = {};
    for (const h of headers) if (h.key.trim()) out[h.key.trim()] = h.value;
    return out;
  }, [headers]);

  // Evasion rating — how hard the current payload works to hide from signatures
  const evasion = useMemo(() => evasionRating(payload), [payload]);

  // Raw HTTP request preview — exactly what would hit the edge
  const requestPreview = useMemo(() => {
    const isBody = method === "POST" || method === "PUT" || method === "PATCH";
    const hasQuery = path.includes("?");
    const url = isBody || !payload ? path : path + (hasQuery ? "&" : "?") + payload;
    return { url, body: isBody ? payload : null, headers: headersRecord };
  }, [method, path, payload, headersRecord]);

  const send = () => {
    const effectiveMode = runMode === "global" ? state.mode : runMode;
    const result = runSandbox(
      method,
      path,
      payload,
      effectiveMode,
      state.settings.sensitivity,
      state.thresholds.entropy,
      src.ip,
      state.blocklist,
      state.allowlist,
      state.geoBlock,
      state.customRules,
      headersRecord,
      src.code,
    );
    dispatch({ type: "ADD_SANDBOX", result });
    toast.success(`Sandbox verdict: ${result.verdict} · ${result.status}`);
  };

  const saveProbe = () => {
    const label = probeLabel.trim() || `${method} ${path}`;
    dispatch({
      type: "ADD_SAVED_PROBE",
      probe: { id: uid("SP"), label, method, path, payload },
    });
    toast.success(`Probe saved to library — ${label}`);
    setProbeLabel("");
  };

  const runSavedProbe = (p: SavedProbe) => {
    const effectiveMode = runMode === "global" ? state.mode : runMode;
    const result = runSandbox(
      p.method,
      p.path,
      p.payload,
      effectiveMode,
      state.settings.sensitivity,
      state.thresholds.entropy,
      src.ip,
      state.blocklist,
      state.allowlist,
      state.geoBlock,
      state.customRules,
      headersRecord,
      src.code,
    );
    dispatch({ type: "ADD_SANDBOX", result });
    toast.success(`Probe ${p.label} → ${result.verdict} · ${result.status}`);
  };

  const loadProbe = (p: SavedProbe) => {
    setMethod(p.method);
    setPath(p.path);
    setPayload(p.payload);
    toast.info(`Loaded probe — ${p.label}`);
  };

  const applyScenario = (s: (typeof SCENARIOS)[number]) => {
    setMethod(s.method);
    setPath(s.path);
    setPayload(s.payload);
    applySourcePreset(s.src);
    toast.info(`Scenario loaded — ${s.label}`);
  };

  const runAllSavedProbes = () => {
    if (state.savedProbes.length === 0) return;
    const effectiveMode = runMode === "global" ? state.mode : runMode;
    for (const p of state.savedProbes) {
      const result = runSandbox(
        p.method,
        p.path,
        p.payload,
        effectiveMode,
        state.settings.sensitivity,
        state.thresholds.entropy,
        src.ip,
        state.blocklist,
        state.allowlist,
        state.geoBlock,
        state.customRules,
        headersRecord,
        src.code,
      );
      dispatch({ type: "ADD_SANDBOX", result });
    }
    toast.success(`Ran ${state.savedProbes.length} saved probes through the pipeline`);
  };

  const runBypassSweep = () => {
    const effectiveMode = runMode === "global" ? state.mode : runMode;
    const base = payload || "id=1' OR 1=1--";
    const runs = [
      { label: "Original", desc: "raw payload as composed", payload: base },
      ...MUTATIONS.map((m) => ({ label: m.label, desc: m.desc, payload: m.apply(base) })),
    ].map((r) => ({
      ...r,
      result: runSandbox(
        method,
        path,
        r.payload,
        effectiveMode,
        state.settings.sensitivity,
        state.thresholds.entropy,
        src.ip,
        state.blocklist,
        state.allowlist,
        state.geoBlock,
        state.customRules,
        headersRecord,
        src.code,
      ),
    }));
    setSweep(runs);
    const evaded = runs.filter((r) => r.result.verdict === "ALLOWED" && r.label !== "Original").length;
    if (evaded > 0) {
      const evadedRuns = runs.filter((r) => r.result.verdict === "ALLOWED" && r.label !== "Original");
      dispatch({
        type: "SUGGEST_CUSTOM_RULE",
        rule: {
          id: uid("CR"),
          name: `Block ${evadedRuns[0].label} evasions on ${path.split("?")[0]}`,
          matchType: "path",
          matchValue: path.split("?")[0],
          action: "block",
          enabled: true,
          hits: 0,
        },
      });
      toast.info(
        `${evaded} evasion${evaded === 1 ? "" : "s"} slipped through — a rule suggestion was pushed to the Policy Engine`,
      );
    } else {
      toast.success("Bypass sweep complete — every mutation was caught at the edge");
    }
  };

  const suggestRuleFromSweep = (
    evaded: Array<{ label: string; desc: string; payload: string; result: SandboxResult }>,
  ) => {
    const first = evaded[0];
    if (!first) return;
    dispatch({
      type: "SUGGEST_CUSTOM_RULE",
      rule: {
        id: uid("CR"),
        name: `Block ${first.label} evasions on ${path.split("?")[0]}`,
        matchType: "path",
        matchValue: path.split("?")[0],
        action: "block",
        enabled: true,
        hits: 0,
      },
    });
    toast.success("Rule suggestion pushed to Policy Engine — review & apply there");
  };

  // Burst launcher — fire a scripted flood through the pipeline, sampled into the live stream
  const runBurst = (preset: (typeof BURST_PRESETS)[number]) => {
    if (burst) return;
    const effectiveMode = runMode === "global" ? state.mode : runMode;
    const total = preset.runs.length * 15;
    const results: SandboxResult[] = [];
    for (let i = 0; i < total; i++) {
      const t = preset.runs[i % preset.runs.length];
      results.push(
        runSandbox(
          t.method,
          t.path,
          `${t.payload}${i % 5 === 0 ? `&seq=${i}` : ""}`,
          effectiveMode,
          state.settings.sensitivity,
          state.thresholds.entropy,
          src.ip,
          state.blocklist,
          state.allowlist,
          state.geoBlock,
          state.customRules,
          headersRecord,
          src.code,
        ),
      );
    }
    const blocked = results.filter((r) => r.verdict !== "ALLOWED").length;
    setBurst({ label: preset.label, done: 0, total });
    let idx = 0;
    const step = 12;
    const timer = window.setInterval(() => {
      const chunk = results.slice(idx, idx + step);
      for (const r of chunk) {
        dispatch({ type: "ADD_SANDBOX", result: r });
        if (Math.random() < 0.45) dispatch({ type: "INJECT_LOG", log: sandboxToLog(r) });
      }
      idx += step;
      setBurst((b) => (b ? { ...b, done: Math.min(idx, total) } : b));
      if (idx >= total) {
        window.clearInterval(timer);
        toast.success(`Burst complete — ${preset.label}: ${blocked}/${total} stopped at the edge`);
        setTimeout(() => setBurst(null), 1500);
      }
    }, 110);
  };

  const exportRuns = () => {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            app: "WebGuard Request Sandbox",
            exportedAt: new Date().toISOString(),
            runContext: { mode: runMode, source: src.ip, target: state.target },
            runs: state.sandbox,
          },
          null,
          2,
        ),
      ],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `webguard-sandbox-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${state.sandbox.length} sandbox runs as JSON`);
  };

  const logAsFinding = (r: SandboxResult) => {
    const spec = r.matchedRule ? ATTACK_SPECS.find((s) => s.ruleId === r.matchedRule) : null;
    const finding: VulnFinding = {
      id: uid("FN"),
      title: `${r.verdict} sandbox run — ${r.method} ${r.path}`,
      severity: spec?.severity ?? "high",
      source: "manual",
      status: "open",
      discoveredAt: new Date().getTime(),
      lastSeen: new Date().getTime(),
      count: 1,
      evidence: `${r.method} ${r.path}\npayload: ${r.payload}\nverdict: ${r.verdict} · ${r.matchedRule ?? "no rule matched"}\nthreat ${r.threatScore}/100 · entropy ${r.entropy.toFixed(2)} bits/char`,
      patch: r.matchedRule
        ? `Enforce ${r.matchedRule} at the edge · reject this payload pattern`
        : "Review payload policy — high-entropy content flagged",
      ruleId: r.matchedRule,
      path: r.path,
      pillar: null,
    };
    dispatch({ type: "ADD_FINDING", finding });
    toast.success("Run logged to Findings & Vulnerabilities");
  };

  const runs = state.sandbox.length;
  const blockedRuns = state.sandbox.filter((r) => r.verdict === "BLOCKED" || r.verdict === "THROTTLED").length;
  const avgThreat = runs > 0 ? Math.round(state.sandbox.reduce((s, r) => s + r.threatScore, 0) / runs) : 0;
  const avgLatency = runs > 0 ? state.sandbox.reduce((s, r) => s + r.latencyMs, 0) / runs : 0;

  const dist = useMemo(() => {
    const c = { ALLOWED: 0, BLOCKED: 0, THROTTLED: 0 } as Record<SandboxResult["verdict"], number>;
    for (const r of state.sandbox) c[r.verdict] += 1;
    return c;
  }, [state.sandbox]);
  const distTotal = Math.max(1, runs);

  // ---- mode matrix: same request evaluated under every firewall mode ----
  const modeMatrix = useMemo(() => {
    const m = runMode === "global" ? state.mode : runMode;
    return (["blocking", "detection", "off"] as WafMode[]).map((mode) => ({
      mode,
      current: mode === m,
      r: runSandbox(
        method,
        path,
        payload,
        mode,
        state.settings.sensitivity,
        state.thresholds.entropy,
        src.ip,
        state.blocklist,
        state.allowlist,
        state.geoBlock,
        state.customRules,
        headersRecord,
        src.code,
      ),
    }));
  }, [
    method,
    path,
    payload,
    runMode,
    src.ip,
    src.code,
    state.mode,
    state.settings.sensitivity,
    state.thresholds.entropy,
    state.blocklist,
    state.allowlist,
    state.geoBlock,
    state.customRules,
    headersRecord,
  ]);

  const applyMutation = (m: (typeof MUTATIONS)[number]) => {
    setPayload(m.apply(payload || "id=1' OR 1=1--"));
    toast.info(`${m.label} — ${m.desc}`);
  };

  const runSuite = () => {
    const effectiveMode = runMode === "global" ? state.mode : runMode;
    const results = ALL_QUICK_PAYLOADS.map((q) =>
      runSandbox(
        "GET",
        q.path,
        q.payload,
        effectiveMode,
        state.settings.sensitivity,
        state.thresholds.entropy,
        src.ip,
        state.blocklist,
        state.allowlist,
        state.geoBlock,
        state.customRules,
        headersRecord,
        src.code,
      ),
    );
    results.forEach((r) => dispatch({ type: "ADD_SANDBOX", result: r }));
    const caught = results.filter((r) => r.verdict !== "ALLOWED").length;
    toast.success(`Suite complete — ${caught}/${results.length} blocked or throttled`);
  };

  const originResponse = (r: SandboxResult) => {
    if (r.verdict === "BLOCKED")
      return {
        status: 403,
        reason: "Forbidden",
        body: `WebGuard WAF — request blocked${r.matchedRule ? ` (${r.matchedRule})` : ""}. No origin contact was made.`,
      };
    if (r.verdict === "THROTTLED")
      return {
        status: 429,
        reason: "Too Many Requests",
        body: "Rate limit exceeded — retry after 1 second. Connection accepted at the edge only.",
      };
    return {
      status: 200,
      reason: "OK",
      body: `Origin response — ${r.path} returned normally in ${r.latencyMs.toFixed(1)} ms.${
        r.threatScore > 40 ? " (anomaly logged)" : ""
      }`,
    };
  };

  // Turn a sandbox verdict into a live-stream entry (shared by per-run replay + full suite)
  const sandboxToLog = (r: SandboxResult): RequestLog => {
    const spec = r.matchedRule ? ATTACK_SPECS.find((s) => s.ruleId === r.matchedRule) : null;
    const origin = pickOrigin(r.verdict === "ALLOWED" ? BENIGN_ORIGINS : ATTACK_ORIGINS);
    return {
      id: uid("REQ"),
      ts: new Date().getTime(),
      status: r.status,
      method: r.method as HttpMethod,
      path: r.path,
      ip: originIp(origin),
      countryCode: origin.geo.code,
      country: origin.geo.country,
      lat: origin.geo.lat,
      lon: origin.geo.lon,
      city: origin.geo.city,
      latency: r.latencyMs,
      threatScore: r.threatScore,
      attackType: spec?.type ?? null,
      ruleId: r.matchedRule,
      blocked: r.verdict === "BLOCKED",
      throttled: r.verdict === "THROTTLED",
      entropy: r.entropy,
      ua: "webguard-sandbox-replay",
      payload: r.payload,
      matched: spec?.match ?? null,
      headers: { Host: "shop.example.com", "User-Agent": "webguard-sandbox-replay", Accept: "*/*", ...r.headers },
    };
  };

  const replayInTraffic = (r: SandboxResult) => {
    dispatch({ type: "INJECT_LOG", log: sandboxToLog(r) });
    toast.success(`Replayed ${r.method} ${r.path} into the live stream — ${r.verdict}`);
  };

  const replaySuiteInTraffic = () => {
    const effectiveMode = runMode === "global" ? state.mode : runMode;
    const results = ALL_QUICK_PAYLOADS.map((q) =>
      runSandbox(
        "GET",
        q.path,
        q.payload,
        effectiveMode,
        state.settings.sensitivity,
        state.thresholds.entropy,
        src.ip,
        state.blocklist,
        state.allowlist,
        state.geoBlock,
        state.customRules,
        headersRecord,
        src.code,
      ),
    );
    results.forEach((r) => dispatch({ type: "INJECT_LOG", log: sandboxToLog(r) }));
    const caught = results.filter((r) => r.verdict !== "ALLOWED").length;
    toast.success(`Replayed ${results.length} probes into the live stream — ${caught} dropped by the edge`);
  };

  const copyPayload = async (payload: string) => {
    try {
      await navigator.clipboard.writeText(payload);
      toast.success("Payload copied to clipboard");
    } catch {
      toast.error("Clipboard unavailable");
    }
  };

  const engineConfig = [
    { label: "Sensitivity", value: state.settings.sensitivity.toFixed(2), sub: "signature strictness", tone: "text-wg-cyan" },
    { label: "Entropy cutoff", value: state.thresholds.entropy.toFixed(2), sub: "bits/char anomaly", tone: "text-wg-amber" },
    { label: "Rate budget", value: `${state.settings.rateLimitRpm} rpm`, sub: "429 above this", tone: "text-wg-emerald" },
    { label: "Custom rules", value: `${state.customRules.filter((r) => r.enabled).length} live`, sub: "edge policies", tone: "text-wg-violet" },
  ];

  return (
    <div className="flex flex-col gap-4">
      {/* Sandbox sub-tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        {([
          ["sandbox", "Request Sandbox", <FlaskConical className="size-3.5" />],
          ["lab", "Vulnerability Lab", <Swords className="size-3.5" />],
          ["weblab", "Web Lab", <Globe2 className="size-3.5" />],
        ] as const).map(([tab, label, icon]) => (
          <button
            key={tab}
            type="button"
            onClick={() => setSandboxSubTab(tab)}
            className={cn(
              "flex shrink-0 items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors",
              sandboxSubTab === tab
                ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                : "border-border/40 text-muted-foreground hover:text-foreground/80",
            )}
          >
            {icon}
            {label}
          </button>
        ))}
      </div>
      {sandboxSubTab === "lab" ? (
        <VulnLabTab
          templateId={labTemplateId}
          setTemplateId={setLabTemplateId}
          enabledVulns={labEnabledVulns}
          setEnabledVulns={setLabEnabledVulns}
          wafOn={labWafOn}
          setWafOn={setLabWafOn}
          attackHistory={labAttackHistory}
          setAttackHistory={setLabAttackHistory}
        />
      ) : sandboxSubTab === "weblab" ? (
        <WebLabTab
          templateId={labTemplateId}
          enabledVulns={labEnabledVulns}
          wafOn={labWafOn}
        />
      ) : (
      <>
      {/* run stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <SandboxStat icon={<FlaskConical className="size-4" />} label="Pipeline runs" value={runs} accent="text-wg-cyan" sub="this session" />
        <SandboxStat
          icon={<Send className="size-4" />}
          label="Blocked / throttled"
          value={runs > 0 ? Math.round((blockedRuns / runs) * 100) : 0}
          accent="text-wg-rose"
          sub={runs > 0 ? `${blockedRuns} of ${runs} runs` : "no runs yet"}
        />
        <SandboxStat icon={<Sparkles className="size-4" />} label="Avg threat score" value={avgThreat} accent="text-wg-amber" sub="classifier output" />
        <SandboxStat icon={<Timer className="size-4" />} label="Avg latency" value={runs > 0 ? `${avgLatency.toFixed(1)} ms` : "—"} accent="text-wg-emerald" sub="edge round-trip" />
      </div>

      {/* ================================================================ */}
      {/* COMPOSER — request builder + live preview side by side           */}
      {/* ================================================================ */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        {/* builder */}
        <div className="wg-panel p-4 xl:col-span-3">
          <SectionTitle
            title="Request builder"
            sub="Compose any request and inspect it through the 6-stage WAF pipeline — the origin never sees it"
            right={
              <Badge variant="outline" className="gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-[10px] text-wg-cyan">
                <span className="size-1.5 animate-pulse rounded-full bg-cyan-400" /> LIVE PREVIEW
              </Badge>
            }
          />

          {/* quick-start scenarios */}
          <div className="mb-3">
            <p className="mb-1.5 text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
              Quick-start scenarios
            </p>
            <div className="flex flex-wrap gap-1.5">
              {SCENARIOS.map((s) => (
                <button
                  key={s.label}
                  type="button"
                  onClick={() => applyScenario(s)}
                  className="flex items-center gap-1.5 rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[11px] text-foreground/80 transition-colors hover:border-wg-cyan/50 hover:text-wg-cyan"
                >
                  <s.icon className="size-3.5" /> {s.label}
                </button>
              ))}
            </div>
          </div>

          {/* method + path + payload */}
          <div className="flex flex-col gap-2.5">
            <div className="flex gap-2">
              <Select value={method} onValueChange={(v) => setMethod(v as HttpMethod)}>
                <SelectTrigger className="h-9 w-28 border-border/60 bg-muted/50 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-border/60 bg-popover">
                  {(["GET", "POST", "PUT", "DELETE", "PATCH"] as HttpMethod[]).map((m) => (
                    <SelectItem key={m} value={m} className="text-xs">
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                className="h-9 flex-1 border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
                placeholder="/api/search?id=1"
                spellCheck={false}
              />
            </div>
            <Textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder="Payload body / query string — try: id=1' OR 1=1--"
              className="min-h-24 resize-none border-border/60 bg-muted/50 font-mono text-xs focus-visible:ring-cyan-400/40"
              spellCheck={false}
            />
          </div>

          {/* custom headers editor */}
          <div className="mt-2.5 rounded-xl border border-border/40 bg-muted/20">
            <button
              type="button"
              onClick={() => setHeadersOpen((o) => !o)}
              className="flex w-full items-center justify-between gap-2 px-2.5 py-1.5 text-left"
            >
              <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                <Braces className="size-3" /> Request headers
                <span className="rounded bg-background/60 px-1 py-0.5 font-mono text-[9px] text-wg-cyan">
                  {headers.filter((h) => h.key.trim()).length}
                </span>
              </span>
              <ChevronDown className={cn("size-3.5 text-muted-foreground transition-transform", headersOpen && "rotate-180")} />
            </button>
            {headersOpen && (
              <div className="flex flex-col gap-1.5 border-t border-border/30 px-2.5 py-2">
                {headers.map((h, i) => (
                  <div key={i} className="flex gap-1.5">
                    <Input
                      value={h.key}
                      onChange={(e) =>
                        setHeaders((prev) => prev.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)))
                      }
                      placeholder="Header"
                      className="h-7 w-36 border-border/60 bg-muted/50 font-mono text-[11px] focus-visible:ring-cyan-400/40"
                      spellCheck={false}
                    />
                    <Input
                      value={h.value}
                      onChange={(e) =>
                        setHeaders((prev) => prev.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))
                      }
                      placeholder="Value"
                      className="h-7 flex-1 border-border/60 bg-muted/50 font-mono text-[11px] focus-visible:ring-cyan-400/40"
                      spellCheck={false}
                    />
                    <button
                      type="button"
                      title="Remove header"
                      onClick={() => setHeaders((prev) => prev.filter((_, j) => j !== i))}
                      className="flex size-7 shrink-0 items-center justify-center rounded-md border border-border/50 text-muted-foreground transition-colors hover:border-wg-rose/40 hover:text-wg-rose"
                    >
                      <X className="size-3" />
                    </button>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={() => setHeaders((prev) => [...prev, { key: "", value: "" }])}
                  className="flex h-7 items-center justify-center gap-1.5 rounded-md border border-dashed border-border/60 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-cyan/50 hover:text-wg-cyan"
                >
                  <Plus className="size-3" /> Add header
                </button>
                <p className="text-[9px] text-muted-foreground">
                  Custom rules matching headers (e.g. x-debug) are enforced against these — set one and watch the
                  pipeline react.
                </p>
              </div>
            )}
          </div>

          {/* detection preview + evasion + send */}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border/40 bg-muted/20 px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
              <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                <Activity className="size-3 text-wg-cyan" />
                Entropy:{" "}
                <span className="font-mono text-wg-cyan">
                  {payload ? shannonEntropy(payload).toFixed(2) : "0.00"}
                </span>
                {payload && shannonEntropy(payload) > state.thresholds.entropy && (
                  <span className="ml-0.5 text-wg-rose">↑ above {state.thresholds.entropy}</span>
                )}
              </span>
              {evasion.score > 0 && (
                <span
                  className={cn(
                    "rounded-full border px-1.5 py-0.5 font-mono text-[9px] font-bold",
                    evasion.score >= 60
                      ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose"
                      : evasion.score >= 30
                        ? "border-wg-amber/40 bg-wg-amber/10 text-wg-amber"
                        : "border-wg-sky/40 bg-wg-sky/10 text-wg-sky",
                  )}
                  title={`Evasion factors: ${evasion.factors.join(", ")}`}
                >
                  evasion {evasion.score}/100
                </span>
              )}
              {previewSpec && (
                <span className="flex items-center gap-1.5 rounded-md border border-wg-rose/30 bg-wg-rose/[0.06] px-2 py-0.5 text-[10px] font-medium text-wg-rose">
                  <TriangleAlert className="size-3 shrink-0" />
                  flags <span className="font-semibold">{previewSpec.label}</span>
                  <span className="font-mono text-[9px] text-muted-foreground">{previewSpec.ruleId}</span>
                </span>
              )}
            </div>
            <Button className="h-9 gap-2 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20" onClick={send}>
              <Send className="size-4" /> Run through pipeline
            </Button>
          </div>
        </div>

        {/* preview + run context */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          {/* raw request preview */}
          <div className="wg-panel overflow-hidden p-0">
            <div className="flex items-center justify-between border-b border-border/40 px-3 py-2">
              <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                <Braces className="size-3" /> Raw request — as sent to the edge
              </p>
              <span className="font-mono text-[9px] text-muted-foreground">HTTP/1.1</span>
            </div>
            <pre className="overflow-x-auto bg-muted/30 px-3 py-2.5 font-mono text-[10px] leading-relaxed text-foreground/75">
              <span className="text-wg-cyan">{method} {requestPreview.url}</span>
              {"\n"}
              <span className="text-wg-cyan">host:</span> {state.target.replace(/^https?:\/\//, "") || "localhost:8080"}
              {"\n"}
              <span className="text-wg-cyan">user-agent:</span> webguard-sandbox/1.0 (replay)
              {Object.entries(requestPreview.headers).map(([k, v]) => (
                <span key={k}>
                  {"\n"}
                  <span className="text-wg-cyan">{k.toLowerCase()}:</span> {v}
                </span>
              ))}
              <span>
                {"\n"}
                <span className="text-wg-cyan">x-forwarded-for:</span> {src.ip}
              </span>
              {requestPreview.body !== null && (
                <>
                  {"\n"}
                  <span className="text-wg-cyan">content-type:</span> application/x-www-form-urlencoded
                  {"\n"}
                  <span className="text-wg-emerald">{requestPreview.body}</span>
                </>
              )}
            </pre>
          </div>

          {/* run context */}
          <div className="wg-panel p-3.5">
            <div className="mb-2 flex items-center justify-between">
              <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                <Layers className="size-3 text-wg-cyan" /> Run context
              </p>
              <span className="font-mono text-[9px] text-muted-foreground">
                {runMode === "global" ? `inherits global: ${state.mode}` : `override: ${runMode}`}
              </span>
            </div>

            <div className="mb-2.5 flex flex-wrap items-center gap-1.5">
              {(["global", "blocking", "detection", "off"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setRunMode(m)}
                  className={cn(
                    "h-7 rounded-md border px-2.5 text-[10px] font-bold tracking-wider transition-colors",
                    runMode === m
                      ? m === "blocking"
                        ? "border-wg-emerald/50 bg-wg-emerald/10 text-wg-emerald"
                        : m === "detection"
                          ? "border-wg-amber/50 bg-wg-amber/10 text-wg-amber"
                          : m === "off"
                            ? "border-wg-rose/50 bg-wg-rose/10 text-wg-rose"
                            : "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                      : "border-border/40 text-muted-foreground hover:text-foreground/80",
                  )}
                >
                  {m === "global" ? "GLOBAL" : m.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="flex gap-2">
              <Select
                value={sourcePreset}
                onValueChange={(v) => applySourcePreset(v as "benign" | "attacker" | "custom")}
              >
                <SelectTrigger className="h-8 w-32 border-border/60 bg-muted/50 text-[11px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-border/60 bg-popover">
                  <SelectItem value="benign" className="text-xs">Random benign</SelectItem>
                  <SelectItem value="attacker" className="text-xs">Random attacker</SelectItem>
                  <SelectItem value="custom" className="text-xs">Custom IP</SelectItem>
                </SelectContent>
              </Select>
              <div className="relative min-w-0 flex-1">
                <Globe2 className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={src.ip}
                  onChange={(e) => setSrc((s) => ({ ...s, ip: e.target.value, code: "—" }))}
                  className="h-8 border-border/60 bg-muted/50 pl-8 font-mono text-[11px] focus-visible:ring-cyan-400/40"
                  spellCheck={false}
                />
              </div>
              <span className="flex h-8 w-10 shrink-0 items-center justify-center rounded-lg border border-border/40 bg-muted/50 text-base">
                {src.code !== "—" ? flagEmoji(src.code) : "🌐"}
              </span>
            </div>

            {srcStatus.banned && (
              <p className="mt-2 flex items-center gap-1.5 rounded-md border border-wg-rose/30 bg-wg-rose/[0.06] px-2 py-1 text-[10px] font-semibold text-wg-rose">
                <Ban className="size-3 shrink-0" /> Source is blocklisted — the edge drops it before any inspection.
              </p>
            )}
            {srcStatus.allowlisted && (
              <p className="mt-2 flex items-center gap-1.5 rounded-md border border-wg-emerald/30 bg-wg-emerald/[0.06] px-2 py-1 text-[10px] font-semibold text-wg-emerald">
                <ShieldCheck className="size-3 shrink-0" /> Source is allowlisted — every gate is bypassed (ALLOWLIST verdict).
              </p>
            )}
            {srcStatus.geoBlocked && (
              <p className="mt-2 flex items-center gap-1.5 rounded-md border border-wg-rose/30 bg-wg-rose/[0.06] px-2 py-1 text-[10px] font-semibold text-wg-rose">
                <Globe2 className="size-3 shrink-0" /> {flagEmoji(src.code)} {src.code} is geo-blocked — this request drops with 403.
              </p>
            )}
            <p className="mt-2 flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <ShieldCheck className="size-3 text-wg-emerald" />
              Policy: sensitivity {state.settings.sensitivity.toFixed(2)} · entropy cutoff {state.thresholds.entropy.toFixed(2)} · rate budget {state.settings.rateLimitRpm} rpm — allowlist & blocklist are enforced on the source IP.
            </p>
          </div>
        </div>
      </div>

      {/* ================================================================ */}
      {/* WORKBENCH — library | results | analytics                        */}
      {/* ================================================================ */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* ---------- library (left) ---------- */}
        <div className="flex flex-col gap-4 xl:col-span-4">
          {/* payload library */}
          <div className="wg-panel p-4">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
                  <Library className="size-4 text-wg-cyan" /> Payload library
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {ALL_QUICK_PAYLOADS.length} hand-picked probes across OWASP classes — click to load, or run everything at once.
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-[10px] text-wg-cyan hover:bg-wg-cyan/20"
                  onClick={replaySuiteInTraffic}
                  title="Replay every library payload through the live edge stream with the current run context"
                >
                  <Play className="size-3" /> Replay live
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-[10px] text-wg-violet hover:bg-wg-violet/20"
                  onClick={runSuite}
                  title="Run every library payload through the pipeline with the current run context"
                >
                  <ListChecks className="size-3" /> Run suite
                </Button>
              </div>
            </div>

            <div className="mb-2 flex flex-wrap gap-1">
              {PAYLOAD_LIBRARY.map((g) => (
                <span
                  key={g.group}
                  title={`${g.items.length} probes in this OWASP class`}
                  className="flex items-center gap-1 rounded-full border border-border/40 bg-muted/40 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground"
                >
                  <RadarIcon className="size-2.5" /> {g.group} · {g.items.length}
                </span>
              ))}
            </div>

            <div className="flex flex-col gap-2">
              {PAYLOAD_LIBRARY.map((g) => {
                const open = libOpen[g.group] ?? true;
                return (
                  <div key={g.group} className="overflow-hidden rounded-lg border border-border/40">
                    <button
                      type="button"
                      onClick={() => setLibOpen((prev) => ({ ...prev, [g.group]: !open }))}
                      className="flex w-full items-center justify-between gap-2 bg-muted/30 px-2.5 py-1.5 text-left transition-colors hover:bg-muted/50"
                    >
                      <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
                        <RadarIcon className="size-3 text-wg-rose/70" /> {g.group}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <span className="font-mono text-[9px] text-muted-foreground/70">{g.items.length}</span>
                        <ChevronDown className={cn("size-3 text-muted-foreground transition-transform", open && "rotate-180")} />
                      </span>
                    </button>
                    {open && (
                      <div className="flex flex-wrap gap-1.5 p-2">
                        {g.items.map((q) => (
                          <button
                            key={q.label}
                            type="button"
                            onClick={() => {
                              setPath(q.path);
                              setPayload(q.payload);
                            }}
                            className="rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[11px] text-foreground/80 transition-colors hover:border-wg-rose/40 hover:text-wg-rose"
                          >
                            {q.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* burst launcher */}
          <div className="wg-panel p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div>
                <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
                  <Zap className="size-4 text-wg-amber" /> Burst launcher
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Scripted attack floods replayed through the pipeline — 120 requests per preset, sampled into Live
                  Traffic and the SOC counters.
                </p>
              </div>
              {burst && (
                <span className="flex shrink-0 items-center gap-1.5 rounded-md border border-wg-amber/40 bg-wg-amber/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-wg-amber">
                  <span className="size-1.5 animate-pulse rounded-full bg-amber-400" /> running
                </span>
              )}
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {BURST_PRESETS.map((p) => (
                <button
                  key={p.label}
                  type="button"
                  disabled={!!burst}
                  onClick={() => runBurst(p)}
                  className={cn(
                    "group flex items-start gap-2.5 rounded-xl border p-3 text-left transition-colors",
                    burst
                      ? "cursor-not-allowed border-border/30 opacity-60"
                      : "border-border/40 bg-muted/20 hover:border-wg-amber/50",
                  )}
                >
                  <span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-wg-amber/10 text-wg-amber">
                    <p.icon className="size-3.5" />
                  </span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
                      {p.label}
                      {burst?.label === p.label && <span className="size-1.5 animate-pulse rounded-full bg-amber-400" />}
                    </span>
                    <span className="mt-0.5 block text-[10px] leading-snug text-muted-foreground">{p.desc}</span>
                    <span className="mt-1 inline-flex items-center gap-1 text-[9px] font-bold uppercase tracking-wider text-wg-amber">
                      <Play className="size-2.5" /> launch flood
                    </span>
                  </span>
                </button>
              ))}
            </div>
            {burst && (
              <div className="mt-2.5">
                <div className="flex items-center justify-between text-[9px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <span>{burst.label} — flooding edge</span>
                  <span className="font-mono">{burst.done}/{burst.total}</span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-border/40">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-wg-amber to-wg-rose transition-[width] duration-150"
                    style={{ width: `${Math.round((burst.done / burst.total) * 100)}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* bypass fuzzer + sweep */}
          <div className="wg-panel p-4">
            <p className="mb-1.5 flex items-center gap-1.5 text-sm font-semibold text-foreground">
              <Shuffle className="size-4 text-wg-amber" /> Bypass fuzzer
            </p>
            <p className="mb-2 text-xs text-muted-foreground">
              Real evasions: mixed-case keywords, comment splicing, single & double URL-encoding, null bytes, and tab injection — the same chains OWASP recommends fuzzing against.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {MUTATIONS.map((m) => (
                <button
                  key={m.label}
                  type="button"
                  title={m.desc}
                  onClick={() => applyMutation(m)}
                  className="rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[11px] text-foreground/80 transition-colors hover:border-wg-amber/50 hover:text-wg-amber"
                >
                  {m.label}
                </button>
              ))}
            </div>

            <div className="mt-3 overflow-hidden rounded-xl border border-wg-violet/30 bg-wg-violet/[0.05]">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-wg-violet/20 px-3 py-2">
                <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-wg-violet">
                  <Shuffle className="size-3.5" /> Sweep — fuzz every evasion at once
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-[10px] text-wg-violet hover:bg-wg-violet/20"
                  onClick={runBypassSweep}
                  title="Run the original payload plus all 6 evasion mutations and see which get through"
                >
                  <Play className="size-3" /> Run sweep
                </Button>
              </div>
              {sweep && (
                <div className="flex flex-col gap-1 px-3 py-2">
                  {sweep.map((r) => (
                    <div key={r.label} className="flex flex-wrap items-center gap-2 rounded-lg border border-border/30 bg-card/50 px-2 py-1.5">
                      <span className="w-24 shrink-0 text-[11px] font-medium text-foreground/85">{r.label}</span>
                      <span
                        className={cn(
                          "shrink-0 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider",
                          r.result.verdict === "ALLOWED" && "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
                          r.result.verdict === "BLOCKED" && "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
                          r.result.verdict === "THROTTLED" && "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
                        )}
                      >
                        {r.result.verdict}
                      </span>
                      <span className="min-w-0 flex-1 truncate font-mono text-[9.5px] text-muted-foreground">
                        {r.result.matchedRule ?? "no rule matched"}
                      </span>
                      <span className="shrink-0 font-mono text-[9px] text-wg-rose">t {r.result.threatScore}</span>
                    </div>
                  ))}
                  {sweep.filter((r) => r.result.verdict === "ALLOWED" && r.label !== "Original").length > 0 ? (
                    <>
                      <p className="pt-1 text-[9px] leading-relaxed text-muted-foreground">
                        Evasion found — mutations marked ALLOWED slip past the signature engine. Raise sensitivity or
                        add a custom rule to close the gap.
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 gap-1.5 self-start border-wg-violet/40 bg-wg-violet/10 text-[10px] text-wg-violet hover:bg-wg-violet/20"
                        onClick={() =>
                          suggestRuleFromSweep(
                            sweep.filter((r) => r.result.verdict === "ALLOWED" && r.label !== "Original"),
                          )
                        }
                      >
                        <ShieldAlert className="size-3" /> Suggest edge rule
                      </Button>
                    </>
                  ) : (
                    <p className="pt-1 text-[9px] leading-relaxed text-muted-foreground">
                      No evasion succeeded — every mutation was caught at the edge.
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* saved probes */}
          <div className="wg-panel p-4">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
                <Save className="size-4 text-wg-violet" /> Saved probes
              </p>
              <div className="flex flex-wrap items-center gap-1.5">
                <Input
                  value={probeLabel}
                  onChange={(e) => setProbeLabel(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && saveProbe()}
                  placeholder="Probe name"
                  className="h-7 w-36 border-border/60 bg-muted/50 text-[11px] focus-visible:ring-cyan-400/40"
                />
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-[11px] text-wg-violet hover:bg-wg-violet/20"
                  onClick={saveProbe}
                  title="Persist the current composer state as a reusable probe"
                >
                  <BookmarkPlus className="size-3.5" /> Save composer
                </Button>
                {state.savedProbes.length > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 gap-1.5 border-wg-emerald/40 bg-wg-emerald/10 text-[11px] text-wg-emerald hover:bg-wg-emerald/20"
                    onClick={runAllSavedProbes}
                    title={`Run all ${state.savedProbes.length} saved probes through the pipeline`}
                  >
                    <Play className="size-3.5" /> Run all ({state.savedProbes.length})
                  </Button>
                )}
              </div>
            </div>
            {state.savedProbes.length > 0 ? (
              <div className="flex flex-col gap-2">
                {state.savedProbes.map((p) => (
                  <div key={p.id} className="rounded-xl border border-border/40 bg-card/40 p-3 transition-colors hover:border-wg-violet/40">
                    <div className="flex items-start gap-2.5">
                      <span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-wg-violet/10 text-wg-violet">
                        <Save className="size-3.5" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-xs font-medium text-foreground">{p.label}</p>
                        <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
                          <span className="text-wg-cyan">{p.method}</span> {p.path}
                          {p.payload && <span className="text-wg-amber">?{p.payload}</span>}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          title="Run this probe through the pipeline"
                          className="text-wg-emerald"
                          onClick={() => runSavedProbe(p)}
                        >
                          <Play className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          title="Load into composer"
                          className="text-wg-cyan"
                          onClick={() => loadProbe(p)}
                        >
                          <Braces className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          title="Delete probe"
                          className="text-wg-rose"
                          onClick={() => dispatch({ type: "REMOVE_SAVED_PROBE", id: p.id })}
                        >
                          <X className="size-3.5" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="rounded-xl border border-dashed border-border/40 p-5 text-center text-[11px] text-muted-foreground">
                No saved probes yet — compose a request and hit “Save composer” to keep it for later.
              </p>
            )}
            <p className="mt-1.5 text-[9px] text-muted-foreground">
              Saved probes persist across sessions and can be run individually or replayed into Live Traffic.
            </p>
          </div>
        </div>

        {/* ---------- results (middle) ---------- */}
        <div className="flex flex-col gap-3 xl:col-span-5">
          <div className="flex items-center justify-between">
            <p className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
              <Waypoints className="size-4 text-wg-cyan" /> Pipeline verdicts
              <span className="font-mono text-[10px] font-normal text-muted-foreground">newest first</span>
            </p>
            <div className="flex items-center gap-1.5">
              {runs > 0 && (
                <>
                  <ExportMenu
                    data={{
                      label: "sandbox runs",
                      filename: `webguard-sandbox-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}`,
                      jsonData: { app: "WebGuard Request Sandbox", exportedAt: new Date().toISOString(), runs: state.sandbox },
                      csvRows: [["Method", "Path", "Status", "Verdict", "Latency", "Rule"],
                        ...state.sandbox.map((r) => [r.method, r.path, String(r.status), r.verdict, String(r.latencyMs), r.matchedRule ?? ""])],
                    }}
                    triggerLabel="Export"
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 gap-1.5 text-[11px] text-muted-foreground hover:text-wg-rose"
                    onClick={() => dispatch({ type: "CLEAR_SANDBOX" })}
                  >
                    <Eraser className="size-3.5" /> Clear runs
                  </Button>
                </>
              )}
            </div>
          </div>

          {runs > 0 && (
            <div className="flex flex-col gap-2">
              {/* verdict distribution */}
              <div className="flex items-center gap-3 rounded-xl border border-border/40 bg-muted/20 px-3 py-2">
                {(["ALLOWED", "BLOCKED", "THROTTLED"] as const).map((v) => (
                  <div key={v} className="flex flex-1 items-center gap-2">
                    <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                      <div
                        className={cn(
                          "h-full rounded-full",
                          v === "ALLOWED" && "bg-wg-emerald",
                          v === "BLOCKED" && "bg-wg-rose",
                          v === "THROTTLED" && "bg-wg-amber",
                        )}
                        style={{ width: `${(dist[v] / distTotal) * 100}%` }}
                      />
                    </span>
                    <span className={cn("font-mono text-[11px] font-bold", v === "ALLOWED" ? "text-wg-emerald" : v === "BLOCKED" ? "text-wg-rose" : "text-wg-amber")}>
                      {dist[v]}
                    </span>
                    <span className="text-[9px] uppercase tracking-wider text-muted-foreground">{v}</span>
                  </div>
                ))}
              </div>

              {/* recent verdict dots */}
              <div className="flex items-center gap-2 rounded-xl border border-border/40 bg-muted/20 px-3 py-2">
                <span className="flex items-center gap-1 text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                  <Waypoints className="size-3 text-wg-cyan" /> Recent
                </span>
                <div className="flex flex-1 items-center gap-1">
                  {[...state.sandbox].reverse().slice(0, 16).map((r) => (
                    <span
                      key={r.id}
                      title={`${r.method} ${r.path} → ${r.verdict} (threat ${r.threatScore})`}
                      className={cn(
                        "size-2.5 rounded-full transition-transform hover:scale-125",
                        r.verdict === "ALLOWED" && "bg-wg-emerald",
                        r.verdict === "BLOCKED" && "bg-wg-rose",
                        r.verdict === "THROTTLED" && "bg-wg-amber",
                      )}
                    />
                  ))}
                </div>
                <span className="font-mono text-[9px] text-muted-foreground">oldest → newest</span>
              </div>
            </div>
          )}

          {state.sandbox.length === 0 && (
            <div className="wg-panel flex flex-col items-center gap-3 p-10 text-center">
              <FlaskConical className="size-8 text-muted-foreground/70" />
              <p className="text-sm font-medium text-muted-foreground">No runs yet</p>
              <p className="max-w-sm text-xs text-muted-foreground">
                Compose a request on the left and run it through the WAF pipeline. Try a classic SQLi tautology or a
                high-entropy archive upload.
              </p>
            </div>
          )}
          {state.sandbox.map((r) => (
            <div
              key={r.id}
              className="wg-panel p-3.5"
              style={{ borderLeft: `3px solid ${VERDICT_ACCENT[r.verdict]}` }}
            >
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-[11px] font-bold text-wg-cyan">{r.method}</span>
                <span className="max-w-[220px] truncate font-mono text-xs text-foreground/80 sm:max-w-xs">{r.path}</span>
                <StatusBadge status={r.status} />
                <span
                  className={cn(
                    "rounded-md border px-1.5 py-0.5 text-[10px] font-bold tracking-wider",
                    r.verdict === "BLOCKED" && "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
                    r.verdict === "THROTTLED" && "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
                    r.verdict === "ALLOWED" && "border-wg-emerald/40 bg-wg-emerald/10 text-wg-emerald",
                  )}
                >
                  {r.verdict}
                </span>
                <span className="ml-auto flex items-center gap-2 text-[11px] text-muted-foreground">
                  <span className="flex items-center gap-1"><Timer className="size-3" /> {r.latencyMs.toFixed(2)} ms</span>
                  <span className="font-mono text-wg-rose">threat {r.threatScore}</span>
                  {r.verdict !== "ALLOWED" && (
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      title="Log as finding"
                      className="text-wg-amber"
                      onClick={() => logAsFinding(r)}
                    >
                      <TriangleAlert className="size-3.5" />
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    title="Replay in live traffic"
                    className="text-wg-cyan"
                    onClick={() => replayInTraffic(r)}
                  >
                    <Play className="size-3.5" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    title="Copy payload"
                    className="text-muted-foreground"
                    onClick={() => copyPayload(r.payload)}
                  >
                    <ClipboardCopy className="size-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon-sm" onClick={() => setExpanded((e) => (e === r.id ? null : r.id))}>
                    <ChevronDown className={cn("size-4 transition-transform", expanded === r.id && "rotate-180")} />
                  </Button>
                </span>
              </div>

              {r.matchedRule && (
                <p className="mt-2 flex flex-wrap items-center gap-2 wg-mono text-[11px] text-wg-rose">
                  matched rule <span className="font-bold">{r.matchedRule}</span>
                  {r.entropy > 0 && <> · entropy {r.entropy.toFixed(2)}</>}
                  <span className="text-muted-foreground">· {timeAgo(r.ts)}</span>
                </p>
              )}

              {expanded === r.id && (
                <div className="mt-3 border-t border-border/40 pt-3">
                  <div className="flex items-center justify-between">
                    <p className="wg-kicker">Stage trace</p>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 gap-1.5 text-[11px] text-wg-cyan"
                      onClick={() =>
                        dispatch({
                          type: "OPEN_COPILOT",
                          context: copilotContextFromSandbox(r),
                        })
                      }
                    >
                      <Sparkles className="size-3.5" /> AI analysis
                    </Button>
                  </div>
                  <div className="mt-2 flex flex-col gap-1">
                    {r.trace.map((t, i) => (
                      <TraceRow key={i} step={t} maxUs={Math.max(1, ...r.trace.map((s) => s.durationUs))} />
                    ))}
                  </div>

                  <div className="mt-3 overflow-hidden rounded-lg border border-border/40">
                    <div className="flex items-center justify-between border-b border-border/30 bg-muted/40 px-2.5 py-1">
                      <p className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                        <Server className="size-3 text-wg-cyan" /> Origin server response
                      </p>
                      <span className="font-mono text-[9px] text-muted-foreground">
                        HTTP/1.1 {originResponse(r).status} {originResponse(r).reason}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1.5 bg-muted/30 px-2.5 py-2">
                      <pre className="font-mono text-[10px] leading-relaxed text-foreground/70">
                        <span className="text-wg-cyan">content-type:</span> text/html; charset=utf-8
                        {"\n"}
                        <span className="text-wg-cyan">cache-control:</span> no-store
                        {"\n"}
                        <span className="text-wg-cyan">x-webguard:</span> {r.matchedRule ?? "passthrough"}
                        {"\n"}
                        <span className="text-wg-emerald">{originResponse(r).body}</span>
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* ---------- analytics (right) ---------- */}
        <div className="flex flex-col gap-3 xl:col-span-3">
          {/* mode matrix */}
          <div className="wg-panel p-3.5">
            <div className="mb-2 flex items-center gap-2">
              <Gauge className="size-3.5 text-wg-cyan" />
              <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                Mode matrix
              </p>
            </div>
            <div className="flex flex-col gap-2">
              {modeMatrix.map(({ mode, current, r }) => (
                <div
                  key={mode}
                  className={cn(
                    "rounded-xl border p-2.5",
                    current
                      ? "border-wg-cyan/50 bg-wg-cyan/[0.06]"
                      : "border-border/30 bg-muted/20",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={cn(
                        "text-[9px] font-bold uppercase tracking-widest",
                        mode === "blocking" && "text-wg-emerald",
                        mode === "detection" && "text-wg-amber",
                        mode === "off" && "text-wg-rose",
                      )}
                    >
                      {mode}
                    </span>
                    {current && <span className="text-[8px] font-bold text-wg-cyan">● ACTIVE</span>}
                  </div>
                  <div className="mt-1 flex items-center justify-between gap-2">
                    <p
                      className={cn(
                        "font-mono text-sm font-bold",
                        r.verdict === "BLOCKED" && "text-wg-rose",
                        r.verdict === "THROTTLED" && "text-wg-amber",
                        r.verdict === "ALLOWED" && "text-wg-emerald",
                      )}
                    >
                      {r.verdict}
                    </p>
                    <span className="font-mono text-[9px] text-muted-foreground">t {r.threatScore}</span>
                  </div>
                  <p className="text-[9px] text-muted-foreground">
                    {r.status} · {r.matchedRule ?? (r.verdict === "ALLOWED" ? "no rule" : "—")}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* verdict trend */}
          {trendData.length >= 2 && (
            <div className="wg-panel p-3.5">
              <div className="mb-2 flex items-center gap-2">
                <RadarIcon className="size-3.5 text-wg-cyan" />
                <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                  Verdict trend — last {trendData.length} runs
                </p>
                <span className="ml-auto font-mono text-[9px] text-muted-foreground">latency · threat</span>
              </div>
              <div className="h-[150px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={trendData} margin={{ top: 6, right: 4, left: -18, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" vertical={false} />
                    <XAxis dataKey="n" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
                    <YAxis yAxisId="lat" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} />
                    <YAxis yAxisId="threat" orientation="right" domain={[0, 100]} tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} width={30} />
                    <Tooltip content={<TrendTip />} cursor={{ fill: "rgba(148,163,184,0.07)" }} />
                    <Bar yAxisId="lat" dataKey="latencyMs" name="Latency (ms)" radius={[3, 3, 0, 0]} barSize={14} fill="#22d3ee" fillOpacity={0.55} isAnimationActive={false} />
                    <Line yAxisId="threat" dataKey="threatScore" name="Threat score" type="monotone" stroke="#fb7185" strokeWidth={2} dot={{ r: 2, fill: "#fb7185" }} isAnimationActive={false} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* engine config */}
          <div className="wg-panel p-3.5">
            <div className="mb-2 flex items-center gap-2">
              <SlidersHorizontal className="size-3.5 text-wg-violet" />
              <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                Engine config applied
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {engineConfig.map((c) => (
                <div key={c.label} className="rounded-lg border border-border/40 bg-muted/30 px-2.5 py-2">
                  <p className={cn("font-mono text-sm font-bold", c.tone)}>{c.value}</p>
                  <p className="text-[9px] font-semibold uppercase tracking-wider text-foreground/80">{c.label}</p>
                  <p className="text-[9px] text-muted-foreground">{c.sub}</p>
                </div>
              ))}
            </div>
            <p className="mt-2 text-[9px] leading-relaxed text-muted-foreground">
              Runs inherit the live Policy Engine + Access Control state — tweak sensitivity, add a custom rule, or ban
              the source IP and re-run to see the verdict flip.
            </p>
          </div>
        </div>
      </div>
    </>
      )}
    </div>
  );
}

// One-click scenarios — realistic composer states for instant testing
const SCENARIOS: Array<{
  label: string;
  icon: typeof Database;
  method: HttpMethod;
  path: string;
  payload: string;
  src: "benign" | "attacker";
}> = [
  {
    label: "SQLi probe",
    icon: Database,
    method: "GET",
    path: "/api/search?id=1",
    payload: "id=1' OR 1=1--",
    src: "attacker",
  },
  {
    label: "XSS spray",
    icon: Code2,
    method: "GET",
    path: "/search?q=test",
    payload: "q=<script>alert(document.cookie)</script>",
    src: "attacker",
  },
  {
    label: "Credential stuffing",
    icon: Bot,
    method: "POST",
    path: "/api/login",
    payload: "user=admin&pass=password123",
    src: "attacker",
  },
  {
    label: "High-entropy upload",
    icon: Binary,
    method: "POST",
    path: "/api/upload",
    payload:
      "file=UEsDBAoAAAAAADxQZ1hF4v1zFgAAABYAAAAIABwAY2hvZGVsZXhwb3NlZF9maWxlLnR4dFVUCQADQ29sYWNrZQ==",
    src: "attacker",
  },
  {
    label: "Benign baseline",
    icon: ShieldCheck,
    method: "GET",
    path: "/api/search?q=waf",
    payload: "q=firewall+comparison",
    src: "benign",
  },
];

// Categorized payload library — grouped by OWASP attack class
const PAYLOAD_LIBRARY: Array<{
  group: string;
  items: Array<{ label: string; path: string; payload: string }>;
}> = [
  {
    group: "SQL Injection",
    items: [
      { label: "Tautology", path: "/api/search?id=1", payload: "id=1' OR 1=1--" },
      { label: "UNION extract", path: "/api/search?id=1", payload: "id=1' UNION SELECT username,password FROM users--" },
      { label: "Blind boolean", path: "/api/login", payload: "user=admin' AND '1'='1&pass=x" },
      { label: "Error-based", path: "/api/items", payload: "id=1 AND extractvalue(1,concat(0x7e,(select version())))" },
      { label: "Stacked queries", path: "/api/items", payload: "id=1; DROP TABLE logs--" },
    ],
  },
  {
    group: "Cross-Site Scripting",
    items: [
      { label: "Reflected XSS", path: "/search?q=test", payload: "q=<script>alert(document.cookie)</script>" },
      { label: "Img onerror", path: "/search?q=test", payload: "q=<img src=x onerror=alert(1)>" },
      { label: "SVG payload", path: "/profile", payload: "name=<svg/onload=alert(document.domain)>" },
      { label: "Encoded XSS", path: "/search?q=test", payload: "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
    ],
  },
  {
    group: "Command Injection",
    items: [
      { label: "Semicolon chain", path: "/api/ping", payload: "host=8.8.8.8;cat /etc/passwd" },
      { label: "Pipe read", path: "/api/dns", payload: "domain=example.com|whoami" },
      { label: "Backtick exec", path: "/api/ping", payload: "host=`id`" },
      { label: "Newline inject", path: "/api/mail", payload: "to=admin@corp.com%0Acat+/etc/shadow" },
    ],
  },
  {
    group: "Path Traversal",
    items: [
      { label: "Classic traversal", path: "/api/download", payload: "file=../../../../etc/passwd" },
      { label: "Encoded dots", path: "/api/download", payload: "file=..%2F..%2F..%2Fetc%2Fpasswd" },
      { label: "Double-encoded", path: "/api/download", payload: "file=%252e%252e%252fetc%252fpasswd" },
      { label: "Windows traversal", path: "/api/download", payload: "file=..\\..\\..\\windows\\win.ini" },
    ],
  },
  {
    group: "Bots & Scanners",
    items: [
      { label: "SQLi probe", path: "/?id=1'", payload: "id=1'" },
      { label: "wp-login brute", path: "/wp-login.php", payload: "log=admin&pwd=test" },
      { label: "Credential stuffing", path: "/api/login", payload: "user=admin&pass=password123" },
      { label: "Webshell archive", path: "/api/upload", payload: "file=UEsDBAoAAAAAADxQZ1hF4v1zFgAAABYAAAAIABwAY2hvZGVsZXhwb3NlZF9maWxlLnR4dFVUCQADQ29sYWNrZQ==" },
      { label: "Directory brute", path: "/admin", payload: "" },
    ],
  },
  {
    group: "Benign baseline",
    items: [
      { label: "Search query", path: "/api/search?q=waf", payload: "q=firewall+comparison" },
      { label: "Product page", path: "/products/42", payload: "" },
      { label: "Checkout", path: "/api/checkout", payload: "cart=abc123&coupon=SAVE10" },
    ],
  },
];

const ALL_QUICK_PAYLOADS = PAYLOAD_LIBRARY.flatMap((g) => g.items);

// Burst launcher — scripted attack floods, each replayed through the pipeline
const BURST_PRESETS: Array<{
  label: string;
  desc: string;
  icon: typeof Database;
  runs: Array<{ label: string; method: HttpMethod; path: string; payload: string }>;
}> = [
  {
    label: "SQLi flood",
    desc: "120 varied SQL injection probes against /api/*",
    icon: Database,
    runs: [
      { label: "sqli-v1", method: "GET", path: "/api/search", payload: "id=1' OR '1'='1" },
      { label: "sqli-v2", method: "GET", path: "/api/search", payload: "id=1 UNION SELECT 1,2,3--" },
      { label: "sqli-v3", method: "POST", path: "/api/login", payload: "user=admin'--&pass=x" },
      { label: "sqli-v4", method: "GET", path: "/api/items", payload: "id=1 AND 1=1" },
      { label: "sqli-v5", method: "GET", path: "/api/search", payload: "id=1; DROP TABLE users--" },
      { label: "sqli-v6", method: "POST", path: "/api/orders", payload: "coupon=' OR 1=1--" },
      { label: "sqli-v7", method: "GET", path: "/api/items", payload: "id=(SELECT 1 FROM dual)" },
      { label: "sqli-v8", method: "GET", path: "/api/search", payload: "id=1' AND sleep(5)--" },
    ],
  },
  {
    label: "XSS sweep",
    desc: "120 reflected cross-site payloads against /search",
    icon: Crosshair,
    runs: [
      { label: "xss-v1", method: "GET", path: "/search", payload: "q=<script>alert(1)</script>" },
      { label: "xss-v2", method: "GET", path: "/search", payload: "q=<img src=x onerror=alert(document.cookie)>" },
      { label: "xss-v3", method: "GET", path: "/search", payload: "q=javascript:alert(1)//" },
      { label: "xss-v4", method: "GET", path: "/profile", payload: "name=<svg/onload=alert(1)>" },
      { label: "xss-v5", method: "GET", path: "/search", payload: "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
      { label: "xss-v6", method: "GET", path: "/search", payload: "q=<body onload=alert(document.domain)>" },
      { label: "xss-v7", method: "POST", path: "/api/comments", payload: "text=<iframe srcdoc='<script>alert(1)</script>'>" },
      { label: "xss-v8", method: "GET", path: "/search", payload: "q=\" onmouseover=alert(1) \"" },
    ],
  },
  {
    label: "Credential stuffing",
    desc: "120 login attempts at the auth edge",
    icon: KeyRound,
    runs: [
      { label: "auth-v1", method: "POST", path: "/api/auth/login", payload: "user=admin&pass=password123" },
      { label: "auth-v2", method: "POST", path: "/api/auth/login", payload: "user=admin&pass=123456" },
      { label: "auth-v3", method: "POST", path: "/api/auth/login", payload: "user=root&pass=toor" },
      { label: "auth-v4", method: "POST", path: "/api/auth/login", payload: "user=admin&pass=qwerty" },
      { label: "auth-v5", method: "POST", path: "/api/auth/login", payload: "user=administrator&pass=admin" },
      { label: "auth-v6", method: "POST", path: "/api/auth/login", payload: "user=admin&pass=letmein" },
      { label: "auth-v7", method: "POST", path: "/api/auth/login", payload: "user=test&pass=test123" },
      { label: "auth-v8", method: "POST", path: "/api/auth/login", payload: "user=admin&pass=password" },
    ],
  },
  {
    label: "Path traversal",
    desc: "120 directory-escape probes against /static/",
    icon: FolderTree,
    runs: [
      { label: "ptra-v1", method: "GET", path: "/static/", payload: "file=../../../../etc/passwd" },
      { label: "ptra-v2", method: "GET", path: "/static/", payload: "file=..%2F..%2F..%2Fetc%2Fpasswd" },
      { label: "ptra-v3", method: "GET", path: "/static/", payload: "file=%252e%252e%252fetc%252fpasswd" },
      { label: "ptra-v4", method: "GET", path: "/static/", payload: "file=..\\..\\..\\windows\\win.ini" },
      { label: "ptra-v5", method: "GET", path: "/static/", payload: "file=....//....//etc/shadow" },
      { label: "ptra-v6", method: "GET", path: "/static/", payload: "file=..;/..;/etc/passwd" },
      { label: "ptra-v7", method: "GET", path: "/static/", payload: "file=%c0%ae%c0%ae/etc/passwd" },
      { label: "ptra-v8", method: "GET", path: "/static/", payload: "file=../../../../proc/self/environ" },
    ],
  },
];

// Bypass fuzzer — common evasion techniques real attackers chain against signature engines
const MUTATIONS: { label: string; desc: string; apply: (p: string) => string }[] = [
  {
    label: "Case swap",
    desc: "mixed-case keywords evade case-sensitive signatures",
    apply: (p) =>
      p.replace(/union|select|script|or\b/gi, (m) =>
        m
          .split("")
          .map((c, i) => (i % 2 ? c.toLowerCase() : c.toUpperCase()))
          .join(""),
      ),
  },
  { label: "Comment splice", desc: "/**/ replaces whitespace — bypasses naive tokenizers", apply: (p) => p.replace(/\s+/g, "/**/") },
  { label: "URL encode", desc: "%27 instead of ' — evades raw-byte matching", apply: (p) => p.replace(/'/g, "%27").replace(/</g, "%3C").replace(/>/g, "%3E") },
  { label: "Double encode", desc: "%2527 — evades single-decode WAFs", apply: (p) => p.replace(/'/g, "%2527").replace(/</g, "%253C") },
  { label: "Null byte", desc: "%00 mid-payload — truncates parsers", apply: (p) => p.replace(/\s+/g, "%00") },
  { label: "Tab injection", desc: "\t between tokens — slips regex boundary checks", apply: (p) => p.replace(/\s+/g, "\t") },
];

function ipMatchesEntry(entry: string, ip: string): boolean {
  if (entry.endsWith("/24")) return ip.startsWith(entry.replace("/24", ""));
  return entry === ip;
}

function sandboxRuleMatch(
  rule: CustomRule,
  path: string,
  ip: string,
  headers: Record<string, string>,
  countryCode: string,
): boolean {
  const v = rule.matchValue.toLowerCase();
  switch (rule.matchType) {
    case "path":
      return path.toLowerCase().includes(v);
    case "ip":
      return ipMatchesEntry(rule.matchValue, ip);
    case "country":
      return countryCode.toLowerCase() === v;
    case "ua":
      return (headers["User-Agent"] ?? "").toLowerCase().includes(v);
    case "header":
      return (
        Object.keys(headers).some((k) => k.toLowerCase().includes(v)) ||
        Object.values(headers).some((h) => h.toLowerCase().includes(v))
      );
    default:
      return false;
  }
}

// How hard the current payload works to evade signature matching (0-100)
function evasionRating(payload: string): { score: number; factors: string[] } {
  if (!payload) return { score: 0, factors: [] };
  const factors: string[] = [];
  let score = 0;
  if (/%[0-9a-f]{2}/i.test(payload)) {
    score += 25;
    factors.push("URL-encoded");
  }
  if (/%25[0-9a-f]{2}/i.test(payload)) {
    score += 20;
    factors.push("double-encoded");
  }
  if (/\/\*\*\//.test(payload)) {
    score += 15;
    factors.push("comment splice");
  }
  if (/[a-z][A-Z]|[A-Z][a-z]/.test(payload)) {
    score += 10;
    factors.push("mixed case");
  }
  if (/%00/.test(payload)) {
    score += 15;
    factors.push("null byte");
  }
  if (/\t/.test(payload)) {
    score += 10;
    factors.push("tab injection");
  }
  if (payload.length > 120) {
    score += 10;
    factors.push("oversized");
  }
  return { score: Math.min(95, score), factors };
}

function detectSpec(method: HttpMethod, path: string, payload: string): AttackSpec | null {
  return (
    ATTACK_SPECS.find(
      (s) =>
        (s.match && payload.toLowerCase().includes(s.match.toLowerCase())) ||
        (s.payload && payload.toLowerCase().includes(s.payload.toLowerCase())) ||
        (s.match && s.path !== "/" && path.includes(s.match)),
    ) ?? null
  );
}

function runSandbox(
  method: HttpMethod,
  path: string,
  payload: string,
  mode: WafMode,
  sensitivity: number,
  entropyThreshold: number,
  ip: string,
  blocklist: BlockedIp[],
  allowlist: AllowedIp[],
  geoBlock: string[],
  customRules: CustomRule[],
  headers: Record<string, string>,
  countryCode: string,
): SandboxResult {
  const entropy = payload ? shannonEntropy(payload) : 0;
  const spec = detectSpec(method, path, payload);
  const ts = Date.now();

  const trace: TraceStep[] = [];
  const add = (stage: string, verdict: TraceVerdict, detail: string) =>
    trace.push({ stage, durationUs: randInt(40, 900), verdict, detail });
  const finish = (
    status: number,
    verdict: SandboxResult["verdict"],
    matchedRule: string | null,
    threatScore: number,
  ): SandboxResult => ({
    id: uid("SBX"),
    ts,
    method,
    path,
    status,
    verdict,
    threatScore,
    matchedRule,
    entropy,
    latencyMs: trace.reduce((s, t) => s + t.durationUs, 0) / 1000 + rand(0.4, 1.8),
    payload,
    trace,
    headers,
  });

  add("TLS & protocol inspection", "pass", "handshake valid, HTTP/2 negotiated");

  // ---- allowlist: trusted sources bypass everything ----
  const allowlisted = allowlist.some((a) => ipMatchesEntry(a.ip, ip));
  if (allowlisted && mode !== "off") {
    add("IP allowlist", "pass", `source ${ip} is allowlisted — inspection bypassed`);
    add("CRS signature engine", "info", "skipped — trusted source");
    add("ML entropy classifier", "info", "skipped — trusted source");
    add("Rate-limit budget", "info", "exempt from throttling");
    add("Honeytoken scan", "info", "not scanned");
    return finish(200, "ALLOWED", "ALLOWLIST", 0);
  }

  // ---- geo-block: denied countries drop before anything else ----
  if (geoBlock.includes(countryCode) && mode === "blocking") {
    add("Geo-blocking", "block", `country ${countryCode} is deny-listed — dropped`);
    add("CRS signature engine", "info", "skipped — dropped at gate");
    add("ML entropy classifier", "info", "skipped — dropped at gate");
    add("Rate-limit budget", "info", "skipped — dropped at gate");
    add("Honeytoken scan", "info", "skipped — dropped at gate");
    return finish(403, "BLOCKED", "GEO-BLOCK", 55);
  }

  // ---- blocklist: active bans drop with 403 ----
  const banned = blocklist.some((b) => b.active && ipMatchesEntry(b.ip, ip));
  if (banned && mode === "blocking") {
    add("IP blocklist", "block", `source ${ip} matches an active ban — dropped`);
    add("CRS signature engine", "info", "skipped — dropped at gate");
    add("ML entropy classifier", "info", "skipped — dropped at gate");
    add("Rate-limit budget", "info", "skipped — dropped at gate");
    add("Honeytoken scan", "info", "skipped — dropped at gate");
    return finish(403, "BLOCKED", "IP-BLOCKLIST", 60);
  }

  // ---- custom edge rules: your own path / IP / country / UA / header policies ----
  const ruleMatch = customRules.find((r) => r.enabled && sandboxRuleMatch(r, path, ip, headers, countryCode));
  if (ruleMatch) {
    const enforce = mode === "blocking" && (ruleMatch.action === "block" || ruleMatch.action === "challenge");
    add("Custom edge rules", enforce ? "block" : "pass", `matched “${ruleMatch.name}” — action ${ruleMatch.action}`);
    if (enforce) {
      add("CRS signature engine", "info", "skipped — dropped at custom rule");
      add("ML entropy classifier", "info", "skipped — dropped at custom rule");
      add("Rate-limit budget", "info", "skipped — dropped at custom rule");
      add("Honeytoken scan", "info", "skipped — dropped at custom rule");
      return finish(403, "BLOCKED", ruleMatch.id, 68);
    }
  } else {
    add("Custom edge rules", "pass", `${customRules.filter((r) => r.enabled).length} live rules — none matched`);
  }

  if (spec) {
    add("CRS signature engine", mode === "blocking" ? "block" : "pass", `matched ${spec.ruleId} — ${spec.label}`);
  } else {
    add("CRS signature engine", "pass", "no known signature matched");
  }
  if (entropy > entropyThreshold) {
    add("ML entropy classifier", mode === "blocking" ? "block" : "pass", `${entropy.toFixed(2)} bits/char > ${entropyThreshold} threshold`);
  } else {
    add("ML entropy classifier", "pass", `${entropy.toFixed(2)} bits/char within bounds`);
  }
  if (spec?.type === "bot" || spec?.type === "scanner") {
    add("IP reputation & bot score", mode === "blocking" ? "block" : "pass", "automation fingerprint high");
  } else {
    add("IP reputation & bot score", "pass", `reputation clean for ${ip} (score 12/100)`);
  }
  const throttled = mode !== "off" && Math.random() < 0.06;
  add("Rate-limit budget", throttled ? "throttle" : "pass", throttled ? "burst limit exceeded — 429" : "within budget");
  add(
    "Honeytoken scan",
    "info",
    `${spec ? "no canary markers present in payload" : "benign payload, no markers"} · ${Object.keys(headers).length} headers carried`,
  );

  const blocked = spec && mode === "blocking";
  const entropyBlocked = !spec && entropy > entropyThreshold && mode === "blocking";
  const status = throttled ? 429 : blocked || entropyBlocked ? 403 : 200;
  const verdict: SandboxResult["verdict"] = throttled ? "THROTTLED" : blocked || entropyBlocked ? "BLOCKED" : "ALLOWED";

  const threatScore = spec
    ? Math.min(99, Math.round(64 + entropy * 5.5))
    : entropyBlocked
      ? 72
      : Math.max(2, Math.round(entropy * 14));

  return finish(
    status,
    verdict,
    blocked || entropyBlocked ? (spec?.ruleId ?? "ML-ENTROPY-001") : null,
    threatScore,
  );
}

function SandboxStat({
  icon,
  label,
  value,
  accent,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
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

function TraceRow({ step, maxUs }: { step: TraceStep; maxUs: number }) {
  const vCls = {
    pass: "border-wg-emerald/30 bg-wg-emerald/10 text-wg-emerald",
    block: "border-wg-rose/40 bg-wg-rose/10 text-wg-rose",
    throttle: "border-wg-amber/40 bg-wg-amber/10 text-wg-amber",
    info: "border-border/30 bg-muted/50 text-foreground/80",
  }[step.verdict];
  const vLabel = { pass: "PASS", block: "BLOCK", throttle: "429", info: "INFO" }[step.verdict];
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border/30 bg-muted/40 px-2.5 py-1.5">
      <span className={cn("w-14 shrink-0 rounded border px-1 py-0.5 text-center text-[9px] font-bold", vCls)}>{vLabel}</span>
      <span className="w-40 shrink-0 truncate text-[11px] font-medium text-foreground/80">{step.stage}</span>
      <span className="min-w-0 flex-1 truncate text-[11px] text-muted-foreground">{step.detail}</span>
      <span className="hidden w-16 shrink-0 sm:block">
        <span className="block h-1 overflow-hidden rounded-full bg-border/40">
          <span
            className={cn(
              "block h-full rounded-full",
              step.verdict === "pass" && "bg-wg-emerald/70",
              step.verdict === "block" && "bg-wg-rose/70",
              step.verdict === "throttle" && "bg-wg-amber/70",
              step.verdict === "info" && "bg-sky-400/50",
            )}
            style={{ width: `${Math.max(8, (step.durationUs / maxUs) * 100)}%` }}
          />
        </span>
      </span>
      <span className="w-12 shrink-0 text-right font-mono text-[10px] text-muted-foreground">{step.durationUs}µs</span>
    </div>
  );
}

function TrendTip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; payload?: { verdict?: string; path?: string } }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload;
  return (
    <div className="rounded-lg border border-border/60 bg-popover/95 px-3 py-2 shadow-xl">
      <p className="font-mono text-[10px] text-muted-foreground">
        run {label} · {d?.verdict}
      </p>
      <p className="mt-0.5 max-w-[220px] truncate font-mono text-[10px] text-muted-foreground">{d?.path}</p>
      <div className="mt-1 flex flex-col gap-0.5 text-xs">
        {payload.map((p) => (
          <p key={p.name} className="flex items-center gap-2">
            <span
              className="size-2 rounded-full"
              style={{ background: p.name === "Latency (ms)" ? "#22d3ee" : "#fb7185" }}
            />
            <span className="text-muted-foreground">{p.name}</span>
            <span className="ml-auto font-mono font-semibold text-foreground">
              {p.name === "Latency (ms)" ? `${p.value} ms` : `${p.value}/100`}
            </span>
          </p>
        ))}
      </div>
    </div>
  );
}
