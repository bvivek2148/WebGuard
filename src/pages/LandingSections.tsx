import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router";
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  Ban,
  BellRing,
  Binary,
  Bomb,
  Bot,
  BrainCircuit,
  Check,
  CheckCircle2,
  ChevronDown,
  Code2,
  Cpu,
  Database,
  FileWarning,
  FlaskConical,
  Globe,
  ListChecks,
  Pause,
  Play,
  Radar,
  Rocket,
  RotateCcw,
  ScanSearch,
  Server,
  ShieldCheck,
  ShieldOff,
  Siren,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  Webhook,
  Wifi,
  Wrench,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PostureGauge } from "@/waf/components/PostureGauge";

/* ============================================================================
   SOC console module tour
   ============================================================================ */

const MODULES: { icon: LucideIcon; title: string; body: string; badge?: string }[] = [
  {
    icon: Radar,
    title: "Overview",
    body: "Posture gauge, synchronized throughput charts, geo threat map and edge node health in a single pane.",
    badge: "LIVE",
  },
  {
    icon: Activity,
    title: "Live Traffic",
    body: "High-speed request stream with AI threat scores, full-text search, verdict filters, live sparkline and CSV export.",
  },
  {
    icon: Cpu,
    title: "Edge Health",
    body: "Live node telemetry across the edge stack — load, latency, heap, and availability, updated every tick.",
    badge: "LIVE",
  },
  {
    icon: ScanSearch,
    title: "Vulnerability Audit",
    body: "Scores any origin across 6 pillars with raw HTTP evidence, an OWASP threat radar and a before/after matrix.",
  },
  {
    icon: Bomb,
    title: "Canary Tokens",
    body: "Tripwire honeypots planted in fake configs — anyone who touches one is identified and auto-banned.",
  },
  {
    icon: FlaskConical,
    title: "Request Sandbox",
    body: "Replay any payload through the engine and watch each detection pass — verdict by verdict, microsecond by microsecond.",
  },
  {
    icon: BellRing,
    title: "Alerts",
    body: "Severity-ranked alarms with acknowledge, snooze and resolve workflows so nothing slips through.",
  },
  {
    icon: Siren,
    title: "Incidents",
    body: "Triage console with one-click playbooks: quarantine the IP, throttle the traffic, lock down auth.",
  },
  {
    icon: FileWarning,
    title: "Findings & Vulnerabilities",
    body: "A living vulnerability register — every scan result and live threat observation lands here as a tracked, actionable issue.",
    badge: "LIVE",
  },
  {
    icon: Ban,
    title: "IP Blocklist & Rules",
    body: "Ban addresses and CIDRs by hand or automatically, and write your own path / IP / country / UA edge rules.",
  },
  {
    icon: SlidersHorizontal,
    title: "Policy Engine",
    body: "Per-attack-class actions — block, challenge, log or bypass — with live sensitivity and rate limits.",
  },
  {
    icon: Webhook,
    title: "Integrations & Webhooks",
    body: "Forward alarms, incidents, and findings to Slack, PagerDuty, email, or any webhook — with a live dispatch log.",
  },
];

/* ============================================================================
   WebGuard vs. the old way
   ============================================================================ */

const COMPARISON: { label: string; none: string; traditional: string; wg: string }[] = [
  {
    label: "Deployment",
    none: "—",
    traditional: "Hardware / appliance, weeks of tuning",
    wg: "One toggle, zero code, instant",
  },
  {
    label: "Virtual patching",
    none: "—",
    traditional: "Vendor rule packs, manual updates",
    wg: "Headers, banners, CORS & cookies injected at the edge",
  },
  {
    label: "Novel attacks",
    none: "Missed",
    traditional: "Signature gap — unseen payloads pass",
    wg: "Shannon entropy + behavior classifier",
  },
  {
    label: "Telemetry",
    none: "Raw, unstructured logs",
    traditional: "Static dashboards",
    wg: "Live stream with AI threat scores",
  },
  {
    label: "AI analysis",
    none: "—",
    traditional: "—",
    wg: "Copilot: intent, root cause, remediation",
  },
  {
    label: "Proof of fix",
    none: "—",
    traditional: "Manual re-testing",
    wg: "Side-by-side Before vs. After matrix",
  },
  {
    label: "Backend required",
    none: "—",
    traditional: "Yes",
    wg: "None — runs in the browser",
  },
  {
    label: "Response time",
    none: "—",
    traditional: "Minutes to hours of tuning",
    wg: "Under 2 ms per request",
  },
  {
    label: "Ops overhead",
    none: "—",
    traditional: "Dedicated WAF team",
    wg: "Zero ops — one toggle",
  },
];

/* ============================================================================
   OWASP Top 10 coverage
   ============================================================================ */

type OwaspStatus = "covered" | "partial" | "roadmap";

const OWASP_STATUS: Record<OwaspStatus, { label: string; cls: string }> = {
  covered: { label: "COVERED", cls: "border-wg-emerald/30 bg-wg-emerald/10 text-wg-emerald" },
  partial: { label: "PARTIAL", cls: "border-wg-amber/30 bg-wg-amber/10 text-wg-amber" },
  roadmap: { label: "ROADMAP", cls: "border-border/60 bg-muted/40 text-muted-foreground" },
};

const OWASP: { rank: string; name: string; status: OwaspStatus; how: string }[] = [
  {
    rank: "A01",
    name: "Broken Access Control",
    status: "covered",
    how: "Path-traversal shielding, sensitive-file allow-lists and canary-token tripwires.",
  },
  {
    rank: "A02",
    name: "Cryptographic Failures",
    status: "partial",
    how: "HSTS, Secure-cookie and transport-hardening patches at the edge.",
  },
  {
    rank: "A03",
    name: "Injection",
    status: "covered",
    how: "SQLi, XSS and command injection blocked by CRS-style signature rules.",
  },
  {
    rank: "A04",
    name: "Insecure Design",
    status: "covered",
    how: "Entropy scoring, rate limits and sandbox replay for flawed-by-design surfaces.",
  },
  {
    rank: "A05",
    name: "Security Misconfiguration",
    status: "covered",
    how: "Header injection, CORS hardening and server-banner cloaking.",
  },
  {
    rank: "A06",
    name: "Vulnerable & Outdated Components",
    status: "partial",
    how: "Version banners are cloaked so scanners can't map known CVEs.",
  },
  {
    rank: "A07",
    name: "Identification & Auth Failures",
    status: "covered",
    how: "Credential-stuffing throttles, login rate limits and bot fingerprinting.",
  },
  {
    rank: "A08",
    name: "Software & Data Integrity",
    status: "partial",
    how: "Webshell and high-entropy staging detection on upload paths.",
  },
  {
    rank: "A09",
    name: "Logging & Monitoring Failures",
    status: "covered",
    how: "Live stream, severity-ranked alerts and incident playbooks out of the box.",
  },
  {
    rank: "A10",
    name: "Server-Side Request Forgery",
    status: "roadmap",
    how: "Sandbox replay and payload tracing are being extended to SSRF patterns.",
  },
];

export function OwaspCoverage() {
  return (
    <section id="owasp" className="relative z-10 mx-auto w-full max-w-6xl px-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/50 bg-card/60 px-5 py-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-primary">Coverage map</p>
          <h3 className="mt-1 text-lg font-bold tracking-tight">OWASP Top 10, covered where it counts</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
          <span className="rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-2 py-1 font-mono font-bold text-wg-emerald">6 covered</span>
          <span className="rounded-md border border-wg-amber/30 bg-wg-amber/10 px-2 py-1 font-mono font-bold text-wg-amber">3 partial</span>
          <span className="rounded-md border border-border/60 bg-muted/40 px-2 py-1 font-mono font-bold">1 roadmap</span>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {OWASP.map((o, i) => (
          <motion.div
            key={o.rank}
            initial={{ opacity: 0, y: 12 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.35, delay: (i % 5) * 0.05 }}
            className="flex flex-col rounded-2xl border border-border/50 bg-card/60 p-4 transition-colors hover:border-primary/30"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] font-bold text-muted-foreground/70">{o.rank}</span>
              <span className={`rounded-md border px-1.5 py-0.5 text-[9px] font-bold ${OWASP_STATUS[o.status].cls}`}>
                {OWASP_STATUS[o.status].label}
              </span>
            </div>
            <h3 className="mt-2 text-[13px] font-semibold leading-snug text-foreground">{o.name}</h3>
            <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">{o.how}</p>
          </motion.div>
        ))}
      </div>
      <div className="mt-6 flex flex-wrap items-center justify-center gap-5 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-wg-emerald" /> Covered — blocked & audited end to end
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-wg-amber" /> Partial — mitigated via edge patches
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-muted-foreground/40" /> Roadmap — planned detection
        </span>
      </div>
    </section>
  );
}

/* ============================================================================
   In action — an attack, replayed across the SOC phases
   ============================================================================ */

const INCIDENT: {
  t: string;
  icon: LucideIcon;
  title: string;
  detail: string;
  verdict: string;
  tone: string;
  phase: string;
}[] = [
  {
    t: "0:00",
    icon: ScanSearch,
    title: "Recon probe detected",
    detail: "GET /.env from 103.5.140.22 — SCAN-DETECT-002 fingerprints the stack",
    verdict: "LOGGED",
    phase: "Recon",
    tone: "border-border/60 bg-muted/40 text-muted-foreground",
  },
  {
    t: "0:04",
    icon: Database,
    title: "SQLi attempt dropped",
    detail: "GET /api/search?id=1' OR 1=1-- from 91.134.22.7 — rule 942100",
    verdict: "403 BLOCKED",
    phase: "Exploitation",
    tone: "border-wg-rose/30 bg-wg-rose/10 text-wg-rose",
  },
  {
    t: "0:11",
    icon: Bot,
    title: "Credential stuffing throttled",
    detail: "POST /api/login × 412 from 45.155.4.12 — BOT-BLOCK-001",
    verdict: "429 + CAPTCHA",
    phase: "Exploitation",
    tone: "border-wg-amber/30 bg-wg-amber/10 text-wg-amber",
  },
  {
    t: "0:23",
    icon: Code2,
    title: "XSS spray blocked",
    detail: "GET /search?q=<script>… from 128.199.44.2 — rule 941100",
    verdict: "403 BLOCKED",
    phase: "Exploitation",
    tone: "border-wg-rose/30 bg-wg-rose/10 text-wg-rose",
  },
  {
    t: "0:31",
    icon: Siren,
    title: "Incident auto-opened",
    detail: "Credential-stuffing campaign — severity HIGH — playbook suggested automatically",
    verdict: "SEV HIGH",
    phase: "Detection",
    tone: "border-wg-orange/30 bg-wg-orange/10 text-wg-orange",
  },
  {
    t: "0:47",
    icon: ShieldCheck,
    title: "Playbook executed",
    detail: "QUARANTINE — 45.155.4.12 banned, /api/login throttled to 10 req/min",
    verdict: "ENFORCED",
    phase: "Response",
    tone: "border-wg-cyan/30 bg-wg-cyan/10 text-wg-cyan",
  },
  {
    t: "0:52",
    icon: BrainCircuit,
    title: "Copilot brief delivered",
    detail: "Intent, root cause and remediation code for every blocked payload",
    verdict: "READY",
    phase: "Response",
    tone: "border-wg-emerald/30 bg-wg-emerald/10 text-wg-emerald",
  },
];

const INCIDENT_STATS = [
  { label: "Requests inspected", value: "1,284", cls: "text-foreground" },
  { label: "Blocked at edge", value: "2", cls: "text-wg-rose" },
  { label: "Throttled + challenged", value: "1", cls: "text-wg-amber" },
  { label: "Recon probes logged", value: "1", cls: "text-muted-foreground" },
  { label: "Incidents auto-opened", value: "1", cls: "text-wg-orange" },
  { label: "Playbooks executed", value: "1", cls: "text-wg-cyan" },
];

const PHASE_META: Record<string, { icon: LucideIcon; chip: string; dot: string }> = {
  Recon: {
    icon: ScanSearch,
    chip: "border-border/60 bg-muted/40 text-muted-foreground",
    dot: "bg-muted-foreground/60",
  },
  Exploitation: {
    icon: Bomb,
    chip: "border-wg-rose/30 bg-wg-rose/10 text-wg-rose",
    dot: "bg-wg-rose",
  },
  Detection: {
    icon: Siren,
    chip: "border-wg-orange/30 bg-wg-orange/10 text-wg-orange",
    dot: "bg-wg-orange",
  },
  Response: {
    icon: ShieldCheck,
    chip: "border-wg-cyan/30 bg-wg-cyan/10 text-wg-cyan",
    dot: "bg-wg-cyan",
  },
};

const PHASE_ORDER = ["Recon", "Exploitation", "Detection", "Response"];

export function IncidentWalkthrough({ ctaHref }: { ctaHref: string }) {
  const [active, setActive] = useState(0);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused) return;
    const iv = window.setInterval(() => setActive((a) => (a + 1) % INCIDENT.length), 1700);
    return () => window.clearInterval(iv);
  }, [paused]);

  const progress = ((active + 1) / INCIDENT.length) * 100;
  const events = INCIDENT.map((e, idx) => ({ ...e, idx }));

  return (
    <section id="incident" className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
      <div className="mx-auto mb-8 max-w-2xl text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">In action</p>
        <h2 className="mt-3 text-3xl font-bold tracking-tight">A 90-second attack, replayed phase by phase</h2>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
          Recon, exploit attempts, credential stuffing — then an incident that opens itself, a playbook that runs
          itself, and a brief that explains it all. No analyst required.
        </p>
      </div>

      {/* session stats */}
      <div className="mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-border/50 bg-border/40 sm:grid-cols-3 md:grid-cols-6">
        {INCIDENT_STATS.map((s) => (
          <div key={s.label} className="bg-card/80 px-3 py-3 text-center">
            <p className={`font-mono text-lg font-bold ${s.cls}`}>{s.value}</p>
            <p className="mt-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{s.label}</p>
          </div>
        ))}
      </div>

      {/* replay console */}
      <div className="overflow-hidden rounded-2xl border border-border/50 bg-card/60 shadow-[0_20px_60px_-30px_rgba(1,6,18,0.4)]">
        {/* console header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/40 px-5 py-3">
          <div className="flex items-center gap-2.5">
            <span className="flex size-8 items-center justify-center rounded-lg border border-wg-rose/30 bg-wg-rose/10 text-wg-rose">
              <Siren className="size-4" />
            </span>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-wg-rose">Attack replay · 90 s</p>
              <p className="font-mono text-[10px] text-muted-foreground">
                {INCIDENT.length} events · 4 phases · {paused ? "paused" : "auto-advancing"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] font-bold text-muted-foreground">
              {active + 1} / {INCIDENT.length}
            </span>
            <button
              type="button"
              onClick={() => setPaused((p) => !p)}
              className="flex h-7 items-center gap-1.5 rounded-md border border-border/60 bg-card px-2.5 text-[10px] font-bold text-foreground/80 transition-colors hover:border-primary/40 hover:text-primary"
            >
              {paused ? <Play className="size-3" /> : <Pause className="size-3" />}
              {paused ? "Play" : "Pause"}
            </button>
            <button
              type="button"
              onClick={() => {
                setActive(0);
                setPaused(false);
              }}
              title="Restart replay"
              className="flex size-7 items-center justify-center rounded-md border border-border/60 bg-card text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
            >
              <RotateCcw className="size-3" />
            </button>
          </div>
        </div>

        {/* progress */}
        <div className="h-1 w-full bg-border/40">
          <div
            className="h-full bg-gradient-to-r from-wg-rose via-wg-amber to-wg-emerald transition-all duration-700 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* phase board */}
        <div className="grid grid-cols-1 gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
          {PHASE_ORDER.map((phase) => {
            const meta = PHASE_META[phase];
            const column = events.filter((e) => e.phase === phase);
            return (
              <div key={phase} className="flex flex-col rounded-xl border border-border/40 bg-muted/20 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className={`flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.14em] ${meta.chip}`}>
                    <meta.icon className="size-3" /> {phase}
                  </span>
                  <span className="font-mono text-[9px] font-bold text-muted-foreground/70">{column.length}</span>
                </div>
                <div className="mt-2.5 flex flex-1 flex-col gap-2">
                  {column.map((e) => {
                    const isActive = e.idx === active;
                    const isPast = e.idx < active;
                    return (
                      <motion.div
                        key={e.t}
                        initial={{ opacity: 0, y: 8 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true, margin: "-30px" }}
                        transition={{ duration: 0.3, delay: (e.idx % 3) * 0.06 }}
                        className={`relative rounded-xl border p-3 transition-all duration-300 ${
                          isActive
                            ? "border-wg-cyan/60 bg-wg-cyan/[0.07] shadow-[0_0_24px_rgba(34,211,238,0.12)]"
                            : isPast
                              ? "border-border/50 bg-card/70 opacity-60"
                              : "border-border/50 bg-card/70"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="flex items-center gap-1.5 font-mono text-[9px] font-bold text-muted-foreground/70">
                            <span className={`size-1.5 rounded-full ${meta.dot}`} /> {e.t}
                          </span>
                          {isActive && (
                            <span className="flex items-center gap-1 rounded border border-wg-cyan/40 bg-wg-cyan/10 px-1.5 py-0.5 text-[8px] font-bold text-wg-cyan">
                              <span className="size-1 animate-pulse rounded-full bg-cyan-400" /> LIVE
                            </span>
                          )}
                        </div>
                        <p className="mt-1.5 text-[11px] font-semibold leading-snug text-foreground">{e.title}</p>
                        <p className="mt-1 font-mono text-[9.5px] leading-relaxed text-muted-foreground">{e.detail}</p>
                        <span className={`mt-2 inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[8.5px] font-bold ${e.tone}`}>
                          <e.icon className="size-2.5" /> {e.verdict}
                        </span>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        {/* board footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border/40 bg-muted/20 px-5 py-3">
          <p className="flex items-center gap-2 text-[11px] text-muted-foreground">
            <Sparkles className="size-3.5 text-wg-cyan" />
            What you just watched: <span className="font-semibold text-foreground">1 incident auto-opened · 1 playbook enforced · 0 analyst keystrokes</span>
          </p>
          <span className="rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-2 py-1 font-mono text-[9px] font-bold text-wg-emerald">
            NO HUMAN REQUIRED
          </span>
        </div>
      </div>

      <div className="mt-8 text-center">
        <Button asChild variant="outline" size="lg" className="h-10 gap-2 border-border/60 px-5 text-foreground/80">
          <Link to={ctaHref}>
            Open the incident console <ArrowRight className="size-4" />
          </Link>
        </Button>
      </div>
    </section>
  );
}

/* ============================================================================
   The killer workflow — Audit → Shield → Verify, running live
   ============================================================================ */

const WORKFLOW_STEPS: {
  icon: LucideIcon;
  step: string;
  title: string;
  tagline: string;
  body: string;
  checklist: string[];
  result: string;
  resultCls: string;
  tone: string;
  duration: string;
  deltaBefore: string;
  deltaAfter: string;
  deltaAfterCls: string;
}[] = [
  {
    icon: ScanSearch,
    step: "01",
    title: "Audit",
    tagline: "WAF OFF — scan the raw origin",
    body: "WebGuard deep-scans the target with the firewall off, exposing the true baseline: 6 pillars, 14 findings with raw HTTP evidence, and an OWASP threat radar.",
    checklist: ["6 pillars scored", "14 findings captured", "OWASP radar built"],
    result: "28/100 · Grade F",
    resultCls: "text-wg-rose border-wg-rose/30 bg-wg-rose/10",
    tone: "text-wg-rose border-wg-rose/30 bg-wg-rose/10",
    duration: "~2 s",
    deltaBefore: "No protection",
    deltaAfter: "Raw baseline logged",
    deltaAfterCls: "text-muted-foreground border-border/60 bg-muted/40",
  },
  {
    icon: ShieldCheck,
    step: "02",
    title: "Shield",
    tagline: "Flip the firewall to BLOCKING",
    body: "14 virtual patches deploy instantly at the edge — security headers injected, server banner cloaked, CORS hardened, injection shielded.",
    checklist: ["Headers injected", "Banners cloaked", "CORS hardened"],
    result: "14 patches live",
    resultCls: "text-wg-cyan border-wg-cyan/30 bg-wg-cyan/10",
    tone: "text-wg-cyan border-wg-cyan/30 bg-wg-cyan/10",
    duration: "instant",
    deltaBefore: "14 defects live",
    deltaAfter: "14 patches deployed",
    deltaAfterCls: "text-wg-emerald border-wg-emerald/30 bg-wg-emerald/10",
  },
  {
    icon: BadgeCheck,
    step: "03",
    title: "Verify",
    tagline: "Re-scan and prove it",
    body: "Re-scan with the WAF active — the posture leaps to a verified A+ and the Before vs. After matrix fills itself in, side by side.",
    checklist: ["Score re-verified", "Matrix filled in", "0 code changes"],
    result: "100/100 · Grade A+",
    resultCls: "text-wg-emerald border-wg-emerald/30 bg-wg-emerald/10",
    tone: "text-wg-emerald border-wg-emerald/30 bg-wg-emerald/10",
    duration: "~2 s",
    deltaBefore: "28/100 · Grade F",
    deltaAfter: "100/100 · Grade A+",
    deltaAfterCls: "text-wg-emerald border-wg-emerald/30 bg-wg-emerald/10",
  },
];

const WORKFLOW_STATUS = [
  "AUDIT COMPLETE — 6 pillars · 14 findings captured",
  "DEPLOYING 14 VIRTUAL PATCHES AT THE EDGE…",
  "VERIFIED — 100/100 · GRADE A+ · 0 defects",
];

const SESSION_LINES: { kind: "cmd" | "out" | "good" | "bad" | "busy"; text: string }[] = [
  { kind: "cmd", text: "wg audit --target http://localhost:8080" },
  { kind: "out", text: "6 pillars scanned · 14 findings captured with raw HTTP evidence" },
  { kind: "bad", text: "posture: 28/100 · GRADE F · 14 live defects" },
  { kind: "cmd", text: "wg shield --mode blocking" },
  { kind: "busy", text: "deploying 14 virtual patches at the edge…" },
  { kind: "good", text: "headers injected · banner cloaked · CORS hardened · rate limits live" },
  { kind: "cmd", text: "wg verify --re-scan" },
  { kind: "good", text: "posture re-verified: 100/100 · GRADE A+ · 0 defects" },
  { kind: "good", text: "before/after comparison matrix written" },
];

export function WorkflowShowcase({ ctaHref }: { ctaHref: string }) {
  const [line, setLine] = useState(0);

  useEffect(() => {
    const iv = window.setInterval(() => setLine((l) => (l + 1) % (SESSION_LINES.length + 2)), 950);
    return () => window.clearInterval(iv);
  }, []);

  const visible = Math.min(line, SESSION_LINES.length);
  const phase = line < 3 ? 0 : line < 6 ? 1 : 2;
  const shielded = phase === 2;
  const patching = phase === 1;
  const defects = shielded ? 0 : 14;

  const lineColor = (kind: string) =>
    kind === "cmd"
      ? "text-slate-100"
      : kind === "bad"
        ? "text-rose-300"
        : kind === "good"
          ? "text-emerald-300"
          : kind === "busy"
            ? "text-amber-300"
            : "text-slate-400";

  return (
    <div className="overflow-hidden rounded-2xl border border-border/50 bg-card/60 shadow-[0_20px_60px_-30px_rgba(1,6,18,0.4)]">
      {/* session header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/40 px-5 py-3">
        <div className="flex items-center gap-2.5">
          <span className="flex size-8 items-center justify-center rounded-lg border border-wg-cyan/30 bg-wg-cyan/10 text-wg-cyan">
            <Terminal className="size-4" />
          </span>
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-wg-cyan">
              Live session — audit → shield → verify
            </p>
            <p className="font-mono text-[10px] text-muted-foreground">
              target http://localhost:8080 · simulating in-browser
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[9px] font-bold">
          {WORKFLOW_STEPS.map((s, i) => (
            <span
              key={s.step}
              className={`flex items-center gap-1 rounded-full border px-2 py-1 transition-all duration-500 ${
                i === phase
                  ? s.tone
                  : "border-border/60 bg-muted/40 text-muted-foreground/50"
              }`}
            >
              {i === phase && <span className="size-1 animate-pulse rounded-full bg-current" />}
              {s.title}
            </span>
          ))}
        </div>
      </div>

      {/* body: session console + live score */}
      <div className="grid grid-cols-1 gap-5 p-5 lg:grid-cols-[1.15fr_1fr]">
        {/* CLI console */}
        <div className="flex flex-col overflow-hidden rounded-2xl border border-border/50 bg-[#060b09] p-4 font-mono">
          <div className="mb-3 flex items-center justify-between border-b border-white/10 pb-2 text-[9px] uppercase tracking-[0.16em]">
            <span className="font-bold text-slate-500">wg-cli — session log</span>
            <span className="text-slate-500">t+{String(Math.min(Math.floor(line * 0.95), 8)).padStart(2, "0")}s</span>
          </div>
          <div className="flex flex-col gap-1.5 text-[11px] leading-relaxed">
            {SESSION_LINES.slice(0, visible).map((ln, i) => (
              <div key={i} className={`flex items-start gap-2 ${lineColor(ln.kind)}`}>
                <span className={`shrink-0 select-none ${ln.kind === "cmd" ? "text-cyan-400" : "text-slate-600"}`}>
                  {ln.kind === "cmd" ? "$" : "·"}
                </span>
                <span className="min-w-0">{ln.text}</span>
              </div>
            ))}
            {visible < SESSION_LINES.length ? (
              <span className="mt-0.5 inline-block h-3.5 w-2 animate-pulse bg-cyan-400" />
            ) : (
              <div className="mt-2 flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-2 py-1.5 text-[10px] font-bold text-emerald-300">
                <CheckCircle2 className="size-3.5 shrink-0" /> SESSION COMPLETE — posture verified · replaying…
              </div>
            )}
          </div>
        </div>

        {/* live score panel */}
        <div className="flex flex-col rounded-2xl border border-border/50 bg-muted/20 p-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">Live score</p>
            <span className="flex items-center gap-1.5 rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-2 py-0.5 font-mono text-[9px] font-bold text-wg-emerald">
              <span className="size-1 animate-pulse rounded-full bg-emerald-400" /> STREAMING
            </span>
          </div>
          <div className="flex flex-1 flex-col items-center justify-center py-4">
            <PostureGauge score={shielded ? 100 : 28} size={200} />
            <div className="mt-3 flex w-full max-w-[200px] items-center justify-between text-[10px]">
              <span className="font-mono font-bold text-wg-rose">DEFECTS {defects}</span>
              <span className={`font-mono font-bold ${shielded ? "text-wg-emerald" : "text-wg-amber"}`}>
                {shielded ? "CLEAN" : patching ? "PATCHING" : "EXPOSED"}
              </span>
            </div>
            <div className="mt-2 h-1 w-full max-w-[200px] overflow-hidden rounded-full bg-border/40">
              <div
                className="h-full rounded-full bg-gradient-to-r from-wg-rose via-wg-amber to-wg-emerald transition-all duration-1000 ease-out"
                style={{ width: `${shielded ? 100 : patching ? 62 : 28}%` }}
              />
            </div>
            <p className="mt-3 flex items-center gap-1.5 font-mono text-[9.5px] text-wg-cyan">
              <span className="size-1 animate-pulse rounded-full bg-cyan-400" />
              {WORKFLOW_STATUS[phase]}
            </p>
          </div>
        </div>
      </div>

      {/* footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border/40 bg-muted/20 px-5 py-3">
        <p className="font-mono text-[10px] text-muted-foreground">
          28 → 100 in ~10 seconds · 14 virtual patches · 0 code changes
        </p>
        <Button
          asChild
          size="sm"
          className="h-8 gap-1.5 bg-gradient-to-r from-cyan-400 to-emerald-400 font-semibold text-[#04121c] hover:opacity-90"
        >
          <Link to={ctaHref}>
            Run it yourself <ArrowRight className="size-3.5" />
          </Link>
        </Button>
      </div>
    </div>
  );
}

/* ============================================================================
   Built for — personas
   ============================================================================ */

const ROLES = [
  {
    icon: Wrench,
    title: "AppSec & platform engineers",
    body: "Audit before you merge, patch instantly, and prove the fix in the PR.",
    points: ["Baseline scans on any origin", "Virtual patches with zero code deploys", "Replay payloads in the sandbox"],
  },
  {
    icon: ShieldCheck,
    title: "CISOs & security leads",
    body: "A demo your board understands — 28 → 100 in ten seconds, with evidence.",
    points: ["Before vs. After comparison matrix", "OWASP Top 10 coverage map", "Automated incident playbooks"],
  },
  {
    icon: Rocket,
    title: "Founders & startups",
    body: "Ship fast without a security team. Virtual patches buy you weeks of runway.",
    points: ["Runs entirely in the browser", "No backend, no API keys", "Demo-able in one conversation"],
  },
];

export function RolesSection({ ctaHref }: { ctaHref: string }) {
  return (
    <section id="roles" className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
      <div className="mx-auto mb-10 max-w-2xl text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">Built for</p>
        <h2 className="mt-3 text-3xl font-bold tracking-tight">One product, three kinds of wins</h2>
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {ROLES.map((r, i) => (
          <motion.div
            key={r.title}
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.4, delay: i * 0.07 }}
            className="flex flex-col rounded-2xl border border-border/50 bg-card/60 p-5"
          >
            <div className="flex size-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <r.icon className="size-5" />
            </div>
            <h3 className="mt-4 text-sm font-semibold text-foreground">{r.title}</h3>
            <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{r.body}</p>
            <ul className="mt-3 flex flex-col gap-2">
              {r.points.map((p) => (
                <li key={p} className="flex items-start gap-2 text-[11px] leading-relaxed text-muted-foreground">
                  <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-wg-emerald" />
                  {p}
                </li>
              ))}
            </ul>
            <Link
              to={ctaHref}
              className="mt-4 inline-flex items-center gap-1 text-[11px] font-semibold text-primary/70 transition-colors hover:text-primary"
            >
              Try it for your team <ArrowRight className="size-3" />
            </Link>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

/* ============================================================================
   Live attack stream marquee
   ============================================================================ */

const MARQUEE_ITEMS = [
  "403 · SQLi 942100 — 91.134.22.7 → /api/search",
  "429 · cred stuffing BOT-BLOCK-001 — 45.155.4.12 → /api/login",
  "403 · XSS 941100 — 128.199.44.2 → /search",
  "403 · cmd injection 932160 — 185.220.101.4 → /api/ping",
  "403 · path traversal 930120 — 133.242.7.101 → /api/download",
  "LOG · recon probe SCAN-DETECT-002 — 103.5.140.22 → /.env",
  "403 · webshell staging ML-ENTROPY-001 — 159.65.81.9 → /api/upload",
  "200 · benign — 73.221.14.8 → /api/products?category=waf",
];

export function AttackStreamMarquee() {
  const row = [...MARQUEE_ITEMS, ...MARQUEE_ITEMS];
  return (
    <div className="relative z-10 mx-auto w-full max-w-6xl px-5 py-4">
      <div className="overflow-hidden rounded-xl border border-border/50 bg-card/60 py-2.5 [mask-image:linear-gradient(90deg,transparent,black_10%,black_90%,transparent)]">
        <div className="flex w-max items-center whitespace-nowrap font-mono text-[11px] text-muted-foreground [animation:wg-marquee_42s_linear_infinite]">
          {row.map((r, i) => (
            <span key={i} className="mr-10 flex items-center gap-2">
              <span className="size-1.5 rounded-full bg-wg-emerald/70" />
              {r}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ============================================================================
   How WebGuard works — layer stack + live request trace
   ============================================================================ */

const LAYERS = [
  {
    icon: Globe,
    tag: "01",
    title: "The edge",
    sub: "Reverse proxy · zero code changes",
    metric: "1.9 ms / req",
    points: [
      "Intercepts every request in under 2 ms",
      "Injects virtual patches — headers, banner cloaking, CORS, cookie flags",
      "Enforces rate limits, IP bans and mode-aware policy",
    ],
    tone: "text-wg-sky border-wg-sky/25 bg-wg-sky/[0.06]",
  },
  {
    icon: BrainCircuit,
    tag: "02",
    title: "The engine",
    sub: "Five-pass inspection, per request",
    metric: "5 passes / req",
    points: [
      "Signature rules match known attack patterns",
      "Shannon entropy flags obfuscation and webshells",
      "Behavior classifier catches bots, scanners and stuffing",
    ],
    tone: "text-wg-cyan border-wg-cyan/25 bg-wg-cyan/[0.06]",
  },
  {
    icon: Radar,
    tag: "03",
    title: "The console",
    sub: "A real-time security operations center",
    metric: "live · 214 rps",
    points: [
      "Live request stream with AI threat scores",
      "Alerts, incident triage and automated playbooks",
      "AI copilot explains intent, root cause and remediation",
    ],
    tone: "text-wg-emerald border-wg-emerald/25 bg-wg-emerald/[0.06]",
  },
];

const TRACE_STAGES = [
  { icon: Wifi, name: "Inbound capture", detail: "headers · body · path · client IP", tag: "0.3 ms", tone: "text-muted-foreground", frac: 0.16 },
  { icon: ListChecks, name: "Signature rules", detail: "CRS 942100 — tautology match on id", tag: "HIT", tone: "text-wg-rose", frac: 0.21 },
  { icon: Binary, name: "Shannon entropy", detail: "3.1 bits/char — within normal range", tag: "PASS", tone: "text-wg-emerald", frac: 0.37 },
  { icon: BrainCircuit, name: "Behavior classifier", detail: "burst + headless UA fingerprint", tag: "FLAG", tone: "text-wg-amber", frac: 0.26 },
  { icon: ShieldCheck, name: "Policy decision", detail: "verdict applied from active mode", tag: "0.4 ms", tone: "text-wg-cyan", frac: 0.05 },
];

const TRACE_MODES = [
  {
    id: "blocking",
    short: "BLOCK",
    label: "403 at the edge — hostile traffic dropped",
    dot: "bg-emerald-400",
    on: "border-wg-emerald/50 bg-wg-emerald/15 text-wg-emerald shadow-[0_0_14px_rgba(52,211,153,0.2)]",
    off: "border-border/60 text-muted-foreground hover:text-foreground",
    verdict: {
      icon: ShieldOff,
      title: "403 BLOCKED at the edge",
      detail: "dropped in 1.9 ms — never reaches origin",
      box: "border-wg-rose/30 bg-wg-rose/[0.07]",
      text: "text-wg-rose",
    },
  },
  {
    id: "detection",
    short: "DETECT",
    label: "Log only — inspected, zero drops",
    dot: "bg-amber-400",
    on: "border-wg-amber/50 bg-wg-amber/15 text-wg-amber shadow-[0_0_14px_rgba(245,158,11,0.2)]",
    off: "border-border/60 text-muted-foreground hover:text-foreground",
    verdict: {
      icon: Radar,
      title: "200 PASS · logged, score 87",
      detail: "inspected and forwarded — flagged for review",
      box: "border-wg-amber/30 bg-wg-amber/[0.07]",
      text: "text-wg-amber",
    },
  },
  {
    id: "off",
    short: "OFF",
    label: "Raw origin exposed — no inspection",
    dot: "bg-rose-400",
    on: "border-wg-rose/50 bg-wg-rose/15 text-wg-rose shadow-[0_0_14px_rgba(244,63,94,0.2)]",
    off: "border-border/60 text-muted-foreground hover:text-foreground",
    verdict: {
      icon: ShieldOff,
      title: "200 PASS · no inspection",
      detail: "WAF bypassed — vulnerable baseline served",
      box: "border-border/50 bg-muted/30",
      text: "text-muted-foreground",
    },
  },
];

const FLOW_NODES = [
  { icon: Globe, label: "Browser", sub: "any client", accent: false },
  { icon: ShieldCheck, label: "WebGuard Edge", sub: "virtual patches · 403 on match", accent: true },
  { icon: BrainCircuit, label: "Engine", sub: "signatures · entropy · behavior", accent: false },
  { icon: Server, label: "Origin", sub: "patched or raw baseline", accent: false },
];

export function HowItWorks({ ctaHref }: { ctaHref: string }) {
  const [mode, setMode] = useState(0);
  const [stage, setStage] = useState(0);

  useEffect(() => {
    const iv = window.setInterval(() => setStage((s) => (s + 1) % TRACE_STAGES.length), 850);
    return () => window.clearInterval(iv);
  }, []);

  const activeMode = TRACE_MODES[mode];
  const verdict = activeMode.verdict;

  return (
    <section id="how" className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
      <div className="mx-auto mb-10 max-w-2xl text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">How it works</p>
        <h2 className="mt-3 text-3xl font-bold tracking-tight">Three layers, one product</h2>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
          WebGuard sits in front of any origin and splits the work across three layers — an edge proxy that patches,
          an engine that inspects, and a console that shows you everything in real time.
        </p>
      </div>

      <div className="grid grid-cols-1 items-stretch gap-4 lg:grid-cols-[1fr_1.08fr]">
        {/* left: layer stack */}
        <div className="flex flex-col gap-3">
          {LAYERS.map((l, i) => (
            <motion.div
              key={l.tag}
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ duration: 0.4, delay: i * 0.07 }}
              className={`relative rounded-2xl border p-5 ${l.tone}`}
            >
              <div className="flex items-start gap-3">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-current/25 bg-current/10">
                  <l.icon className="size-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] font-bold text-muted-foreground/70">{l.tag}</span>
                    <h3 className="text-base font-semibold text-foreground">{l.title}</h3>
                  </div>
                  <p className="text-[11px] font-medium text-muted-foreground">{l.sub}</p>
                </div>
                <span className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-current/25 bg-current/10 px-2 py-1 font-mono text-[10px] font-bold">
                  <Sparkles className="size-3" /> {l.metric}
                </span>
              </div>
              <ul className="mt-3 flex flex-col gap-1.5">
                {l.points.map((p) => (
                  <li key={p} className="flex items-start gap-2 text-[11px] leading-relaxed text-muted-foreground">
                    <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-current" />
                    {p}
                  </li>
                ))}
              </ul>
              {i < LAYERS.length - 1 && (
                <div className="absolute -bottom-3.5 left-1/2 z-10 -translate-x-1/2">
                  <div className="flex size-6 items-center justify-center rounded-full border border-border/60 bg-card text-muted-foreground/70 shadow-sm">
                    <ChevronDown className="size-3.5" />
                  </div>
                </div>
              )}
            </motion.div>
          ))}
          <div className="rounded-2xl border border-border/50 bg-card/60 p-4 text-[11px] leading-relaxed text-muted-foreground">
            <span className="font-semibold text-foreground">Full loop: </span>
            Browser → Edge (patch + inspect) → Engine (5 passes) → Origin — and every verdict streams back to the
            console for the AI copilot.
          </div>
        </div>

        {/* right: live trace */}
        <div className="flex flex-col overflow-hidden rounded-2xl border border-border/50 bg-card/60">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/40 px-4 py-3">
            <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-wg-cyan">
              <Activity className="size-3.5" /> Live trace — request replay
            </p>
            <span className="flex items-center gap-1.5 rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-2 py-1 font-mono text-[9px] font-bold text-wg-emerald">
              <span className="size-1 animate-pulse rounded-full bg-emerald-400" />
              EDGE CONNECTED
            </span>
          </div>

          <div className="border-b border-border/30 bg-muted/20 px-4 py-2.5 font-mono text-[11px]">
            <span className="text-foreground/90">GET /api/search?id=1' OR 1=1--</span>
            <span className="text-muted-foreground/60"> · 91.134.22.7</span>
          </div>

          {/* pass progress */}
          <div className="flex items-center gap-1.5 px-4 pb-1 pt-3">
            {TRACE_STAGES.map((s, i) => (
              <span
                key={s.name}
                className={`h-1 flex-1 rounded-full transition-all duration-300 ${
                  i <= stage ? "bg-gradient-to-r from-wg-cyan to-wg-emerald" : "bg-border/50"
                }`}
              />
            ))}
            <span className="ml-0.5 shrink-0 font-mono text-[8px] font-bold uppercase tracking-wider text-muted-foreground/60">
              pass {stage + 1}/{TRACE_STAGES.length}
            </span>
          </div>

          <div className="flex flex-col gap-2.5 px-4 py-4">
            {TRACE_STAGES.map((s, i) => {
              const state = i < stage ? "done" : i === stage ? "active" : "pending";
              return (
                <motion.div
                  key={s.name}
                  animate={{ opacity: state === "pending" ? 0.55 : 1 }}
                  transition={{ duration: 0.3 }}
                  className={`flex items-center gap-3 rounded-xl border px-3 py-2.5 transition-colors duration-300 ${
                    state === "active"
                      ? "border-wg-cyan/50 bg-wg-cyan/[0.06]"
                      : state === "done"
                        ? "border-border/50 bg-card/60"
                        : "border-border/40 bg-muted/10"
                  }`}
                >
                  <span
                    className={`flex size-7 shrink-0 items-center justify-center rounded-lg transition-colors duration-300 ${
                      state === "active"
                        ? "bg-wg-cyan/15 text-wg-cyan"
                        : state === "done"
                          ? "bg-wg-emerald/10 text-wg-emerald"
                          : "bg-muted text-muted-foreground/60"
                    }`}
                  >
                    {state === "done" ? <Check className="size-3.5" /> : <s.icon className="size-3.5" />}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold text-foreground">{s.name}</p>
                    <p className="truncate font-mono text-[10px] text-muted-foreground">{s.detail}</p>
                    <div className="mt-1.5 h-0.5 w-full max-w-[110px] overflow-hidden rounded-full bg-border/40">
                      <div
                        className={`h-full rounded-full bg-wg-cyan transition-all duration-500 ${
                          state === "pending" ? "opacity-30" : "opacity-80"
                        }`}
                        style={{ width: `${s.frac * 100}%` }}
                      />
                    </div>
                  </div>
                  <span className={`shrink-0 font-mono text-[9px] font-bold ${s.tone}`}>{s.tag}</span>
                </motion.div>
              );
            })}

            {/* verdict */}
            <div className={`mt-1 flex items-center justify-between gap-3 rounded-xl border px-3.5 py-3 ${verdict.box}`}>
              <div className="flex items-center gap-2.5">
                <verdict.icon className={`size-4 shrink-0 ${verdict.text}`} />
                <div>
                  <p className={`text-xs font-bold ${verdict.text}`}>{verdict.title}</p>
                  <p className="font-mono text-[10px] text-muted-foreground">{verdict.detail}</p>
                </div>
              </div>
              <span className="shrink-0 font-mono text-[9px] text-muted-foreground/70">1.9 ms</span>
            </div>

            {/* virtual patches injected */}
            <div className="overflow-hidden rounded-xl border border-border/50 bg-muted/20">
              <div className="flex items-center justify-between border-b border-border/30 px-3 py-1.5">
                <p className="text-[9px] font-bold uppercase tracking-[0.16em] text-wg-emerald">
                  Virtual patches injected at the edge
                </p>
                <span className="font-mono text-[9px] text-muted-foreground">0 origin changes</span>
              </div>
              <pre className="px-3 py-2 font-mono text-[9.5px] leading-relaxed text-wg-emerald/90">
{`+ Strict-Transport-Security: max-age=31536000; preload
+ X-Frame-Options: DENY
+ Server: WebGuard Edge (cloaked)
+ Set-Cookie: session…; HttpOnly; Secure; SameSite=Lax`}
              </pre>
            </div>
          </div>

          {/* mode switcher */}
          <div className="mt-auto border-t border-border/40 bg-muted/20 px-4 pb-3 pt-2.5">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-[9px] font-bold uppercase tracking-[0.18em] text-muted-foreground">Mode</span>
              {TRACE_MODES.map((m, i) => (
                <button
                  key={m.id}
                  type="button"
                  title={m.label}
                  onClick={() => setMode(i)}
                  className={`flex h-6 items-center gap-1.5 rounded-md border px-2 text-[9px] font-bold tracking-wider transition-all ${
                    i === mode ? m.on : m.off
                  }`}
                >
                  <span className={`size-1.5 rounded-full ${m.dot}`} /> {m.short}
                </button>
              ))}
            </div>
            <p className="mt-2 flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <span className={`size-1.5 rounded-full ${activeMode.dot}`} />
              {activeMode.label}
            </p>
          </div>
        </div>
      </div>

      {/* request flow diagram */}
      <div className="mt-8 overflow-hidden rounded-2xl border border-border/50 bg-card/60">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/40 px-5 py-3">
          <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
            <Activity className="size-3.5 text-wg-cyan" /> Request flow — one hostile request, end to end
          </p>
          <span className="flex items-center gap-1.5 rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-2 py-1 font-mono text-[9px] font-bold text-wg-emerald">
            <span className="size-1 animate-pulse rounded-full bg-emerald-400" /> LIVE
          </span>
        </div>
        <div className="px-5 py-7">
          <div className="relative">
            {/* packet lane */}
            <div className="absolute left-[5%] right-[5%] top-1/2 h-px -translate-y-1/2 bg-gradient-to-r from-border/30 via-border/60 to-border/30" />
            {/* benign packet */}
            <motion.span
              className="absolute top-1/2 z-10 size-2 -translate-y-1/2 rounded-full bg-wg-cyan shadow-[0_0_12px_rgba(34,211,238,0.9)]"
              animate={{ left: ["4%", "96%"] }}
              transition={{ duration: 2.6, repeat: Infinity, ease: "linear" }}
            />
            {/* hostile packet — dropped at the edge */}
            <motion.span
              className="absolute top-1/2 z-10 size-1.5 -translate-y-1/2 rounded-full bg-wg-rose shadow-[0_0_10px_rgba(244,63,94,0.9)]"
              animate={{ left: ["4%", "32%"], opacity: [0, 1, 1, 0] }}
              transition={{ duration: 1.5, repeat: Infinity, repeatDelay: 1.3, ease: "easeIn" }}
            />
            <motion.span
              className="absolute top-0 z-10 -translate-y-2 rounded-md border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 font-mono text-[8px] font-bold text-wg-rose"
              style={{ left: "30%" }}
              animate={{ opacity: [0, 1, 1, 0] }}
              transition={{ duration: 1.5, repeat: Infinity, repeatDelay: 1.3 }}
            >
              403 BLOCKED
            </motion.span>
            {/* nodes */}
            <div className="relative grid grid-cols-2 gap-2 sm:grid-cols-4">
              {FLOW_NODES.map((n) => (
                <div
                  key={n.label}
                  className={`flex items-center gap-2.5 rounded-xl border px-3 py-3 ${
                    n.accent ? "border-primary/40 bg-primary/10" : "border-border/60 bg-muted/30"
                  }`}
                >
                  <div
                    className={`flex size-8 shrink-0 items-center justify-center rounded-lg ${
                      n.accent ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                    }`}
                  >
                    <n.icon className="size-4" />
                  </div>
                  <div className="min-w-0 leading-tight">
                    <p className={`truncate text-xs font-semibold ${n.accent ? "text-primary" : "text-foreground"}`}>
                      {n.label}
                    </p>
                    <p className="truncate font-mono text-[8.5px] text-muted-foreground">{n.sub}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          {/* edge labels */}
          <div className="mt-3 flex items-center justify-between px-[5%]">
            {["1.9 ms · TLS", "5 passes / req", "allow"].map((t) => (
              <span
                key={t}
                className="rounded-md border border-border/60 bg-muted/40 px-2 py-0.5 font-mono text-[9px] font-bold text-muted-foreground"
              >
                {t}
              </span>
            ))}
          </div>
          <p className="mt-5 text-center text-[11px] leading-relaxed text-muted-foreground">
            Benign traffic reaches the origin in ~1.9 ms — hostile requests are{" "}
            <span className="font-mono font-bold text-wg-rose">403 BLOCKED at the edge</span>, so the origin only ever
            sees inspected, allowed traffic.
          </p>
        </div>
      </div>

      <div className="mt-8 text-center">
        <Button asChild size="lg" className="h-11 gap-2 bg-gradient-to-r from-cyan-400 to-emerald-400 px-7 font-semibold text-[#04121c] shadow-[0_0_30px_rgba(34,211,238,0.35)] hover:opacity-90">
          <Link to={ctaHref}>
            Open the SOC console <ArrowRight className="size-4" />
          </Link>
        </Button>
      </div>
    </section>
  );
}

/* ============================================================================
   SOC console tour — module by module
   ============================================================================ */

export function ConsoleTour({ ctaHref }: { ctaHref: string }) {
  return (
    <section id="console" className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
      <div className="mx-auto mb-10 max-w-2xl text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">The product</p>
        <h2 className="mt-3 text-3xl font-bold tracking-tight">The console, module by module</h2>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
          Twelve working modules, every one interactive. This is the whole SOC — not a screenshot of one.
        </p>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {MODULES.map((m, i) => (
          <motion.div
            key={m.title}
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.4, delay: i * 0.05 }}
            className="group flex flex-col rounded-2xl border border-border/50 bg-card/60 p-5 transition-colors hover:border-primary/30"
          >
            <div className="flex items-center justify-between">
              <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary transition-shadow group-hover:shadow-[0_0_20px_rgba(34,211,238,0.2)]">
                <m.icon className="size-4" />
              </div>
              {m.badge && (
                <span className="flex items-center gap-1 rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-1.5 py-0.5 text-[9px] font-bold text-wg-emerald">
                  <span className="size-1 animate-pulse rounded-full bg-emerald-400" />
                  {m.badge}
                </span>
              )}
            </div>
            <h3 className="mt-3 text-sm font-semibold text-foreground">{m.title}</h3>
            <p className="mt-1.5 flex-1 text-[11px] leading-relaxed text-muted-foreground">{m.body}</p>
            <Link
              to={ctaHref}
              className="mt-3 inline-flex items-center gap-1 text-[11px] font-semibold text-primary/70 transition-colors group-hover:text-primary"
            >
              Open module <ArrowRight className="size-3" />
            </Link>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

/* ============================================================================
   WebGuard vs. the old way — comparison table
   ============================================================================ */

export function ComparisonTable({ ctaHref }: { ctaHref: string }) {
  return (
    <section className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
      <div className="mx-auto mb-10 max-w-2xl text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">Why WebGuard</p>
        <h2 className="mt-3 text-3xl font-bold tracking-tight">The old way vs. the WebGuard way</h2>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
          Traditional WAFs take weeks to tune and still miss what they've never seen. WebGuard patches instantly,
          catches novel payloads, and proves the fix — all in the browser.
        </p>
      </div>
      <div className="overflow-x-auto rounded-2xl border border-border/50 bg-card/60 shadow-[0_20px_60px_-30px_rgba(1,6,18,0.4)]">
        <table className="w-full min-w-[720px] text-left text-xs">
          <thead>
            <tr className="border-b border-border/50 text-[10px] uppercase tracking-wider">
              <th className="px-5 py-4 font-semibold text-muted-foreground">Capability</th>
              <th className="px-4 py-4 font-semibold text-wg-rose">No protection</th>
              <th className="px-4 py-4 font-semibold text-muted-foreground">Traditional WAF</th>
              <th className="bg-primary/[0.05] px-4 py-4 font-semibold text-wg-emerald">
                <span className="flex items-center gap-1.5">
                  WebGuard
                  <span className="rounded border border-wg-emerald/40 bg-wg-emerald/10 px-1.5 py-0.5 text-[8px] font-bold tracking-widest">
                    RECOMMENDED
                  </span>
                </span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/30">
            {COMPARISON.map((r) => (
              <tr key={r.label} className="transition-colors hover:bg-muted/30">
                <td className="px-5 py-3.5 font-medium text-foreground">{r.label}</td>
                <td className="px-4 py-3.5">
                  {r.none === "—" ? (
                    <span className="text-muted-foreground/40">—</span>
                  ) : (
                    <span className="flex items-start gap-1.5 text-wg-rose/80">
                      <X className="mt-0.5 size-3.5 shrink-0" /> {r.none}
                    </span>
                  )}
                </td>
                <td className="px-4 py-3.5 text-muted-foreground/80">{r.traditional}</td>
                <td className="bg-primary/[0.05] px-4 py-3.5 font-medium text-wg-emerald">
                  <span className="flex items-start gap-1.5">
                    <Check className="mt-0.5 size-3.5 shrink-0" /> {r.wg}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-center text-[10px] text-muted-foreground/60">
        Illustrative benchmark — figures are generated by the client-side telemetry simulator.
      </p>
      <div className="mt-7 text-center">
        <Button
          asChild
          size="lg"
          className="h-11 gap-2 bg-gradient-to-r from-cyan-400 to-emerald-400 px-7 font-semibold text-[#04121c] shadow-[0_0_30px_rgba(34,211,238,0.35)] hover:opacity-90"
        >
          <Link to={ctaHref}>
            Prove it on your own target <ArrowRight className="size-4" />
          </Link>
        </Button>
      </div>
    </section>
  );
}
