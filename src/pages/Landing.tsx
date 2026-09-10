import { Fragment, useEffect, useRef, useState } from "react";
import { motion, useInView } from "framer-motion";
import { Link } from "react-router";
import {
  ArrowDown,
  ArrowRight,
  Binary,
  Bot,
  BrainCircuit,
  Bug,
  CheckCircle2,
  ChevronRight,
  Code2,
  Cookie,
  Database,
  FileLock,
  Fingerprint,
  FolderSearch,
  Gauge,
  Globe,
  ListChecks,
  Lock,
  Radar,
  ScanSearch,
  Share2,
  ShieldCheck,
  ShieldOff,
  Sparkles,
  Terminal,
  Timer,
  TriangleAlert,
  Wifi,
  Zap,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useAuth } from "@/hooks/use-auth";
import { BASELINE_FINDINGS, PILLARS } from "@/waf/data";
import { SEVERITY_META } from "@/waf/types";
import type { Severity } from "@/waf/types";
import {
  AttackStreamMarquee,
  ComparisonTable,
  ConsoleTour,
  HowItWorks,
  IncidentWalkthrough,
  OwaspCoverage,
  RolesSection,
  WorkflowShowcase,
} from "./LandingSections";

const TICKER = [
  { ip: "91.134.22.7", rule: "942100", label: "SQLi tautology", path: "/api/search" },
  { ip: "45.155.4.12", rule: "932160", label: "cmd injection", path: "/api/ping" },
  { ip: "159.65.81.9", rule: "ML-ENTROPY-001", label: "webshell staging", path: "/api/upload" },
  { ip: "128.199.44.2", rule: "941100", label: "reflected XSS", path: "/search" },
  { ip: "133.242.7.101", rule: "930120", label: "path traversal", path: "/api/download" },
  { ip: "103.5.140.22", rule: "SCAN-DETECT-002", label: "recon probe", path: "/.env" },
  { ip: "185.220.101.4", rule: "BOT-BLOCK-001", label: "cred stuffing", path: "/wp-login.php" },
];

const CONSOLE_ROWS = [
  { status: 403, method: "GET", path: "/api/search?id=1' OR 1=1--", ip: "91.134.22.7", score: 98 },
  { status: 200, method: "GET", path: "/api/products?category=waf", ip: "73.221.14.8", score: 3 },
  { status: 429, method: "POST", path: "/api/login", ip: "45.155.4.12", score: 87 },
  { status: 403, method: "GET", path: "/.env", ip: "103.5.140.22", score: 92 },
  { status: 200, method: "GET", path: "/assets/app.js", ip: "86.17.44.9", score: 2 },
  { status: 403, method: "POST", path: "/api/upload", ip: "159.65.81.9", score: 96 },
  { status: 200, method: "GET", path: "/graphql", ip: "92.40.19.8", score: 4 },
  { status: 301, method: "GET", path: "/blog/top-10-waf-features", ip: "49.207.12.4", score: 5 },
];

const FEATURES = [
  {
    icon: ScanSearch,
    title: "Baseline vulnerability audits",
    body: "One click scores any origin across 6 security pillars with raw HTTP evidence, an OWASP threat radar, and an itemized defect list.",
  },
  {
    icon: Zap,
    title: "Instant virtual patching",
    body: "Activate the firewall and WebGuard injects headers, cloaks the server banner, hardens CORS, and shields injection points — with zero code deploys.",
  },
  {
    icon: Radar,
    title: "Real-time SOC telemetry",
    body: "Live request stream with AI threat scores, synchronized throughput charts, and a geo threat map plotting every hostile origin.",
  },
  {
    icon: Bot,
    title: "AI copilot analysis",
    body: "One click on any request, incident, or sandbox run produces intent, payload breakdown, root cause, an executive summary, and remediation code.",
  },
  {
    icon: Fingerprint,
    title: "Entropy & ML classification",
    body: "Signature rules catch known payloads; Shannon entropy and a behavior classifier catch what signatures miss — webshells, staging, and novel obfuscation.",
  },
  {
    icon: Gauge,
    title: "Mode-aware policy engine",
    body: "Block, challenge, log-only, or bypass per attack class with tunable sensitivity, rate limits, and anomaly thresholds — all live-adjustable.",
  },
];

const LAYER_NAV = [
  {
    id: "threats",
    icon: ScanSearch,
    name: "Attack classes",
    desc: "What arrives at the edge — 7 classes, live in the simulator",
    count: "7",
    chips: ["SQLi", "XSS", "RCE", "Traversal", "Obfuscated", "Bots", "Scanners"],
    flow: "detected by",
  },
  {
    id: "engine",
    icon: BrainCircuit,
    name: "Detection engine",
    desc: "5 passes on every request — signatures, entropy, behavior",
    count: "5",
    chips: ["Signature", "Entropy", "Behavior"],
    flow: "assessed by",
  },
  {
    id: "pillars",
    icon: ListChecks,
    name: "Audit pillars",
    desc: "6 pillars · 14 findings with raw HTTP evidence",
    count: "6",
    chips: ["Headers", "CORS", "Cookies", "Fingerprint", "Injection", "Rate-limit"],
    flow: "mapped to",
  },
  {
    id: "owasp",
    icon: Globe,
    name: "OWASP map",
    desc: "10 of 10 categories addressed",
    count: "10",
    chips: ["A01–A10"],
    flow: "",
  },
];

const MATRIX = [
  { control: "Strict-Transport-Security", before: "Missing", after: "max-age=31536000; preload" },
  { control: "CORS origin", before: "* + credentials", after: "Allow-list + Vary: Origin" },
  { control: "Server banner", before: "Apache/2.4.41 · PHP/7.4.33", after: "WebGuard Edge (cloaked)" },
  { control: "Session cookie", before: "PHPSESSID=…; path=/", after: "HttpOnly; Secure; SameSite" },
  { control: "Rate limiting", before: "Unlimited login attempts", after: "10 req/min + CAPTCHA" },
];

const TESTIMONIALS = [
  {
    quote: "We cut our exploit surface to zero in a single session. The Before vs. After matrix sold the entire security board.",
    name: "Maya Chen",
    role: "Head of Application Security, Northwind",
  },
  {
    quote: "The live traffic stream with AI threat scores turned our SOC from reactive to surgical. Everything is demo-able, nothing is fake.",
    name: "Daniel Okafor",
    role: "CISO, Globex Systems",
  },
  {
    quote: "Deploying a WAF usually takes weeks of tuning. WebGuard's audit-to-shield loop closed the gap in one afternoon.",
    name: "Sofia Reyes",
    role: "Staff Engineer, Acme Commerce",
  },
];

const TRUST = ["Northwind", "Globex", "Initech", "Vandelay", "Pied Piper", "Umbrella"];

/* ============================================================================
   Threat catalog — one entry per attack class in the simulator
   ============================================================================ */

interface ThreatDef {
  id: string;
  label: string;
  severity: Severity;
  rule: string;
  owasp: string;
  payload: string;
  how: string;
  detect: string[];
  response: string;
  responseDetail: string;
  icon: LucideIcon;
}

const THREATS: ThreatDef[] = [
  {
    id: "sqli",
    label: "SQL Injection",
    severity: "critical",
    rule: "942100",
    owasp: "A03 — Injection",
    payload: "GET /api/search?id=1' OR 1=1-- HTTP/1.1\nSELECT * FROM products WHERE id = '1' OR 1=1--'",
    how: "An attacker injects SQL metacharacters into an unsanitized parameter. ' OR 1=1-- rewrites the WHERE clause into a tautology, dumping the entire table — accounts, orders, payment data — in one request.",
    detect: [
      "OWASP CRS rule 942100 matches tautologies, stacked queries and UNION selects",
      "SQL-context heuristics catch reflection inside quotes, comments and numeric casts",
      "Anomaly detection flags SELECT-shaped responses after injection attempts",
    ],
    response: "403 BLOCKED at the edge",
    responseDetail: "Request dropped before reaching origin — rejected in under 2 ms.",
    icon: Database,
  },
  {
    id: "xss",
    label: "Cross-Site Scripting",
    severity: "high",
    rule: "941100",
    owasp: "A03 — Injection",
    payload: "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\n200 OK — payload echoed into <h1>",
    how: "Unvalidated input is echoed into the DOM. The payload executes with the victim's session, enabling account takeover, credential theft and phishing — and it survives page reloads.",
    detect: [
      "Rule 941100 matches script tags, event handlers and obfuscated variants",
      "Context-aware encoding audit flags every unescaped reflection point",
      "Entropy boost catches base64 / hex-encoded payloads signatures miss",
    ],
    response: "403 BLOCKED at the edge",
    responseDetail: "Injection attempts are dropped; stored reflections are flagged for review.",
    icon: Code2,
  },
  {
    id: "cmdi",
    label: "Command Injection",
    severity: "critical",
    rule: "932160",
    owasp: "A03 — Injection",
    payload: "POST /api/ping HTTP/1.1\nhost=127.0.0.1; whoami && cat /etc/passwd",
    how: "Untrusted input reaches a shell command. Chained with ; or $(…), it executes with the web server's privileges — full remote code execution on the origin.",
    detect: [
      "Rule 932160 matches shell metacharacters and chained command patterns",
      "Response-timing heuristics flag process-spawn anomalies",
      "High-entropy detection catches base64-encoded command stagers",
    ],
    response: "403 BLOCKED at the edge",
    responseDetail: "Shell metacharacters on any parameter trigger an immediate drop.",
    icon: Terminal,
  },
  {
    id: "path-traversal",
    label: "Path Traversal",
    severity: "high",
    rule: "930120",
    owasp: "A01 — Broken Access Control",
    payload: "GET /api/download?file=../../../../etc/passwd HTTP/1.1",
    how: "../ sequences escape the web root and read arbitrary files — /etc/passwd, .env, source code. It's the reconnaissance step that precedes most real breaches.",
    detect: [
      "Rule 930120 matches traversal sequences and encoded variants (%2e%2e%2f)",
      "Path normalization comparison defeats canonicalization bypasses",
      "Sensitive-file allow-list denies /etc, .env and source maps outright",
    ],
    response: "403 BLOCKED at the edge",
    responseDetail: "Traversal sequences, encoded or not, are normalized and rejected.",
    icon: FolderSearch,
  },
  {
    id: "high-entropy",
    label: "Obfuscated Payloads",
    severity: "high",
    rule: "ML-ENTROPY-001",
    owasp: "A04 — Insecure Design",
    payload: "POST /api/upload HTTP/1.1\neyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNzUyMT… (48.7 bits/char)",
    how: "Webshells and staged malware hide inside long, random-looking strings — base64 blobs, JWTs, encrypted traffic. Signature rules never see them; statistics do.",
    detect: [
      "Shannon entropy > 4.5 bits/char on path + body signals encoding or obfuscation",
      "Behavior classifier correlates upload + immediate GET-back of a new file",
      "Cross-check against known webshell and stager families",
    ],
    response: "403 BLOCKED · challenge on borderline",
    responseDetail: "Scores above threshold are dropped; borderline scores get a JS / CAPTCHA challenge.",
    icon: Binary,
  },
  {
    id: "bot",
    label: "Bad Bots & Stuffing",
    severity: "high",
    rule: "BOT-BLOCK-001",
    owasp: "A07 — Identification & Auth Failures",
    payload: "POST /api/login HTTP/1.1 × 12,400 requests\nfrom 91.134.22.7 in 90 s — all processed",
    how: "Rotating proxies replay stolen username / password pairs at machine speed. Each single attempt looks benign; the aggregate is a takeover.",
    detect: [
      "Velocity rules flag >10 req/min per IP on auth endpoints",
      "UA and behavior fingerprinting separates headless kits from real browsers",
      "Honeypot fields and cookie checks catch automation frameworks",
    ],
    response: "429 THROTTLED → CAPTCHA",
    responseDetail: "Rate limits trip first; repeat offenders are IP-banned by the policy engine.",
    icon: Bot,
  },
  {
    id: "scanner",
    label: "Recon Scanners",
    severity: "medium",
    rule: "SCAN-DETECT-002",
    owasp: "A05 — Security Misconfiguration",
    payload: "GET /.env → 404 · GET /wp-login.php → 404 · GET /actuator → 404",
    how: "Attackers enumerate before they strike: /.env, /wp-login.php, /actuator. Each 404 fingerprints your stack and maps the attack surface for later.",
    detect: [
      "Known-probe path signatures (env, git, actuator, phpinfo, backups)",
      "Burst heuristics across distinct paths from a single origin",
      "IP reputation tiers escalate repeat scanners to full blocking",
    ],
    response: "403 after 3 probes · 429 during bursts",
    responseDetail: "Early probes are logged; bursts and known probes escalate to blocking.",
    icon: ScanSearch,
  },
];

/* ============================================================================
   Detection engine pipeline
   ============================================================================ */

const ENGINE_STEPS: { icon: LucideIcon; title: string; body: string; time: string }[] = [
  {
    icon: Wifi,
    title: "Inbound capture",
    body: "Every request — headers, body, path, client IP — is captured at the edge with sub-2 ms latency and normalized for inspection.",
    time: "0.3 ms",
  },
  {
    icon: ListChecks,
    title: "Signature rules",
    body: "An OWASP CRS-style rule set (942100, 941100, 932160…) matches known attack patterns, including obfuscated and encoded variants.",
    time: "0.4 ms",
  },
  {
    icon: Binary,
    title: "Shannon entropy",
    body: "Statistical analysis scores payload randomness. 4.5+ bits per character flags base64 blobs, webshells and novel obfuscation.",
    time: "0.7 ms",
  },
  {
    icon: BrainCircuit,
    title: "Behavior classifier",
    body: "Per-IP and per-session analysis of velocity, probe bursts, method mix and headless fingerprints catches bots and scanners.",
    time: "0.5 ms",
  },
  {
    icon: ShieldCheck,
    title: "Verdict & response",
    body: "BLOCK 403, CHALLENGE CAPTCHA, THROTTLE 429 or LOG — decided by the active mode: BLOCKING, DETECTION or OFF.",
    time: "0.0 ms",
  },
];

/* ============================================================================
   FAQ
   ============================================================================ */

const FAQ_ITEMS: { q: string; a: string }[] = [
  {
    q: "Is this a real vulnerability scanner?",
    a: "The telemetry is simulated client-side, but the audit logic, detection rules and scoring model are real — they run against a realistic mock origin with no external network calls. That's what makes the whole demo safe to run in a browser.",
  },
  {
    q: "What do the three firewall modes do?",
    a: "BLOCKING drops attacks with 403 and injects virtual patches at the edge. DETECTION inspects and scores every request but never drops a connection — perfect for testing. OFF bypasses the WAF entirely and exposes the raw, vulnerable baseline.",
  },
  {
    q: "What exactly is a virtual patch?",
    a: "A policy enforced at the edge without touching your code: security header injection, server banner cloaking, CORS hardening, cookie flags, rate limits and injection shielding. Toggle the firewall off and every patch vanishes instantly.",
  },
  {
    q: "How is the posture score computed?",
    a: "Across 6 pillars and 14 findings, weighted by severity — critical findings weigh 4×, high 2×, then medium and low. With the WAF off the origin sits at 28/100 Grade F; with every virtual patch active it reaches 100/100 Grade A+.",
  },
  {
    q: "What is Shannon entropy and why does it matter?",
    a: "Entropy measures how random a string is. Legitimate inputs are predictable, around 2–3 bits per character; encoded exploits and webshells are not, usually 4.5+. It's the detection layer that catches payloads no signature has ever seen.",
  },
  {
    q: "Do I need a backend or API keys?",
    a: "No. Everything — live telemetry, threat scoring, audits, the AI copilot — runs entirely in the browser. Sign in with email or as a guest to persist your demo session.",
  },
];

export default function Landing() {
  const { isAuthenticated, isLoading } = useAuth();
  const [tick, setTick] = useState(0);
  const [layer, setLayer] = useState<"" | "threats" | "engine" | "pillars" | "owasp">("threats");

  useEffect(() => {
    const iv = window.setInterval(() => setTick((t) => (t + 1) % TICKER.length), 1600);
    return () => window.clearInterval(iv);
  }, []);

  const item = TICKER[tick];
  const ctaHref = isAuthenticated ? "/dashboard" : "/auth";
  const ctaLabel = isAuthenticated ? "Open Dashboard" : "Launch Console";

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="wg-grid-bg relative overflow-hidden">
        {/* ambient glows */}
        <div className="pointer-events-none absolute -top-40 left-1/2 h-[480px] w-[820px] -translate-x-1/2 rounded-full bg-primary/[0.08] blur-[120px]" />
        <div className="pointer-events-none absolute top-[60%] -left-40 h-[380px] w-[380px] rounded-full bg-wg-emerald/[0.07] blur-[100px]" />
        <div className="pointer-events-none absolute top-[40%] -right-40 h-[380px] w-[380px] rounded-full bg-wg-rose/[0.07] blur-[100px]" />

        {/* nav */}
        <nav className="sticky top-0 z-30 border-b border-border/40 bg-background/80 backdrop-blur-xl">
          <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-5 py-4">
            <Link to="/" className="flex items-center gap-2.5">
              <div className="flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-emerald-400 shadow-[0_0_24px_rgba(34,211,238,0.35)]">
                <ShieldCheck className="size-5 text-[#04121c]" />
              </div>
              <div className="leading-tight">
                <p className="text-base font-bold tracking-tight">
                  WebGuard<span className="text-wg-cyan">.</span>
                </p>
                <p className="text-[9px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
                  AI WAF · SOC Console
                </p>
              </div>
            </Link>
            <div className="hidden items-center gap-5 text-sm text-muted-foreground lg:flex">
              <a href="#features" className="transition-colors hover:text-foreground">Features</a>
              <a href="#deepdive" className="transition-colors hover:text-foreground">Deep dive</a>
              <a href="#how" className="transition-colors hover:text-foreground">How it works</a>
              <a href="#workflow" className="transition-colors hover:text-foreground">Workflow</a>
              <a href="#incident" className="transition-colors hover:text-foreground">In action</a>
              <a href="#faq" className="transition-colors hover:text-foreground">FAQ</a>
            </div>
            <div className="flex items-center gap-2.5">
              <ThemeToggle />
              <Button
                asChild
                className="h-9 gap-2 bg-gradient-to-r from-cyan-400 to-emerald-400 font-semibold text-[#04121c] shadow-[0_0_20px_rgba(34,211,238,0.25)] hover:opacity-90"
              >
                <Link to={ctaHref}>
                  {isLoading ? "Loading…" : ctaLabel} <ArrowRight className="size-4" />
                </Link>
              </Button>
            </div>
          </div>
        </nav>

        {/* hero */}
        <section className="relative z-10 mx-auto grid w-full max-w-6xl grid-cols-1 items-center gap-12 px-5 pb-16 pt-14 lg:grid-cols-2 lg:pt-20">
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55 }}>
            <Badge className="gap-1.5 border-primary/30 bg-primary/10 px-2.5 py-1 text-[11px] font-semibold text-primary">
              <Sparkles className="size-3" /> AI-Powered Web Application Firewall
            </Badge>
            <h1 className="mt-5 text-4xl font-bold leading-[1.08] tracking-tight sm:text-5xl lg:text-[3.4rem]">
              Audit it.
              <br />
              <span className="bg-gradient-to-r from-wg-cyan via-primary to-wg-emerald bg-clip-text text-transparent">
                Shield it. Prove it.
              </span>
            </h1>
            <p className="mt-5 max-w-xl text-[15px] leading-relaxed text-muted-foreground">
              WebGuard runs a full vulnerability audit, deploys virtual patches at the edge with one toggle, and
              re-verifies a perfect posture — all inside a real-time Security Operations Center with live telemetry,
              AI threat analysis, and automated incident playbooks.
            </p>
            <div className="mt-7 flex flex-wrap items-center gap-3">
              <Button asChild size="lg" className="h-11 gap-2 bg-gradient-to-r from-cyan-400 to-emerald-400 px-6 font-semibold text-[#04121c] shadow-[0_0_30px_rgba(34,211,238,0.35)] hover:opacity-90">
                <Link to={ctaHref}>
                  {isLoading ? "Loading…" : "Open the SOC Console"} <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg" className="h-11 gap-2 border-border/60 px-6 text-foreground/80">
                <Link to={ctaHref}>
                  <Timer className="size-4" /> {isLoading ? "Loading…" : isAuthenticated ? "Resume live demo" : "Live demo — 60s"}
                </Link>
              </Button>
            </div>
            <div className="mt-8 flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5"><CheckCircle2 className="size-3.5 text-wg-emerald" /> No backend required</span>
              <span className="flex items-center gap-1.5"><CheckCircle2 className="size-3.5 text-wg-emerald" /> Fully interactive simulation</span>
              <span className="flex items-center gap-1.5"><CheckCircle2 className="size-3.5 text-wg-emerald" /> Sign in with email or guest</span>
            </div>
          </motion.div>

          {/* live console preview */}
          <motion.div
            initial={{ opacity: 0, scale: 0.97 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="relative mx-auto w-full max-w-lg"
          >
            <ConsolePreview />
            {/* live block ticker */}
            <div className="relative z-10 -mt-5 overflow-hidden rounded-xl border border-border/60 bg-card/95 shadow-[0_20px_60px_-20px_rgba(0,0,0,0.5)] backdrop-blur">
              <div className="flex items-center justify-between border-b border-border/40 px-3.5 py-2">
                <p className="flex items-center gap-1.5 text-[10px] font-bold tracking-[0.18em] text-wg-emerald">
                  <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" /> LIVE BLOCK FEED
                </p>
                <span className="font-mono text-[10px] text-muted-foreground">{item.rule}</span>
              </div>
              <motion.div
                key={tick}
                initial={{ opacity: 0, x: 24 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.35 }}
                className="flex items-center gap-3 px-3.5 py-2.5"
              >
                <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-wg-rose/15 text-wg-rose">
                  <ShieldOff className="size-3.5" />
                </span>
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-foreground">
                    <span className="text-wg-rose">403</span> · {item.label}
                  </p>
                  <p className="truncate font-mono text-[10px] text-muted-foreground">
                    {item.ip} → {item.path}
                  </p>
                </div>
                <span className="ml-auto shrink-0 font-mono text-[10px] font-bold text-wg-rose">BLOCKED</span>
              </motion.div>
            </div>
          </motion.div>
        </section>

        {/* stats strip */}
        <section className="relative z-10 mx-auto w-full max-w-6xl px-5 pb-14">
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-border/50 bg-border/40 md:grid-cols-4">
            {[
              { value: 100, suffix: "/100", label: "Verified posture (A+)" },
              { value: 1.9, suffix: " ms", decimals: 1, label: "Ingress latency" },
              { value: 14, suffix: "", label: "Virtual patches, one toggle" },
              { value: 6, suffix: "", label: "OWASP pillars audited" },
            ].map((s) => (
              <div key={s.label} className="bg-card px-5 py-5">
                <p className="font-mono text-2xl font-bold text-wg-cyan">
                  <CountUp to={s.value} suffix={s.suffix} decimals={s.decimals ?? 0} />
                </p>
                <p className="mt-1 text-[11px] uppercase tracking-wider text-muted-foreground">{s.label}</p>
              </div>
            ))}
          </div>
        </section>

        {/* live attack stream marquee */}
        <AttackStreamMarquee />

        {/* features */}
        <section id="features" className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
          <div className="mx-auto mb-10 max-w-2xl text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">Capabilities</p>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">A full SOC, in your browser</h2>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Every screen is wired to a live telemetry simulator — no backend, no API keys, just a working security
              operations center you can demo end to end.
            </p>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f, i) => (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-60px" }}
                transition={{ duration: 0.4, delay: i * 0.05 }}
                className="group rounded-2xl border border-border/50 bg-card/60 p-5 transition-colors hover:border-primary/30"
              >
                <div className="flex size-10 items-center justify-center rounded-xl bg-primary/10 text-primary transition-shadow group-hover:shadow-[0_0_20px_rgba(34,211,238,0.2)]">
                  <f.icon className="size-5" />
                </div>
                <h3 className="mt-4 text-sm font-semibold text-foreground">{f.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{f.body}</p>
              </motion.div>
            ))}
          </div>
        </section>

        {/* deep-dive explorer — threats | engine | pillars | owasp */}
        <section id="deepdive" className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
          <div className="mx-auto mb-8 max-w-2xl text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">Under the hood</p>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">Everything WebGuard does, in one place</h2>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Stacked like the product itself: the attacks that arrive at the edge, the engine that catches them, the
              audit that scores the origin, and the OWASP map it all maps to. Open a layer to dig in.
            </p>
          </div>
          <div className="flex flex-col items-stretch">
            {LAYER_NAV.map((l, i) => {
              const open = layer === l.id;
              return (
                <Fragment key={l.id}>
                  <div className="overflow-hidden rounded-2xl border border-border/50 bg-card/60 transition-colors hover:border-border/80">
                    <button
                      type="button"
                      onClick={() => setLayer(open ? "" : (l.id as "threats" | "engine" | "pillars" | "owasp"))}
                      className={`flex w-full items-center gap-4 px-5 py-4 text-left transition-colors ${
                        open ? "border-b border-border/40" : ""
                      }`}
                    >
                      <span
                        className={`flex size-10 shrink-0 items-center justify-center rounded-xl border font-mono text-[10px] font-bold transition-colors ${
                          open
                            ? "border-primary/40 bg-primary/15 text-primary"
                            : "border-border/60 bg-muted/40 text-muted-foreground"
                        }`}
                      >
                        L{i + 1}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2">
                          <l.icon className="size-4 shrink-0 text-primary" />
                          <span className="text-sm font-bold text-foreground">{l.name}</span>
                          <span className="rounded-md border border-border/60 bg-muted/40 px-1.5 py-0.5 font-mono text-[9px] font-bold text-muted-foreground">
                            {l.count}
                          </span>
                        </span>
                        <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">{l.desc}</span>
                      </span>
                      <span className="hidden max-w-[280px] flex-wrap items-center justify-end gap-1 md:flex">
                        {l.chips.map((c) => (
                          <span
                            key={c}
                            className="rounded-md border border-border/60 bg-muted/40 px-1.5 py-0.5 font-mono text-[8.5px] font-semibold text-muted-foreground"
                          >
                            {c}
                          </span>
                        ))}
                      </span>
                      <span
                        className={`hidden shrink-0 rounded-md border px-2 py-1 font-mono text-[9px] font-bold transition-colors sm:inline-flex ${
                          open
                            ? "border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan"
                            : "border-border/60 bg-muted/40 text-muted-foreground"
                        }`}
                      >
                        {open ? "CLOSE" : "EXPLORE"}
                      </span>
                      <ChevronRight
                        className={`size-4 shrink-0 text-muted-foreground/50 transition-transform duration-300 ${
                          open ? "rotate-90" : ""
                        }`}
                      />
                    </button>
                    {open && (
                      <div className="pt-2">
                        {l.id === "threats" && <ThreatCatalog ctaHref={ctaHref} />}
                        {l.id === "engine" && <DetectionPipeline />}
                        {l.id === "pillars" && <PillarsDetail />}
                        {l.id === "owasp" && <OwaspCoverage />}
                      </div>
                    )}
                  </div>
                  {i < LAYER_NAV.length - 1 && (
                    <div className="relative flex h-9 items-center justify-center">
                      <span className="absolute left-1/2 top-0 h-full w-px -translate-x-1/2 bg-border/50" />
                      <span className="relative z-10 flex items-center gap-1.5 rounded-full border border-border/60 bg-background px-2.5 py-0.5 text-[8.5px] font-bold uppercase tracking-[0.16em] text-muted-foreground">
                        <ArrowDown className="size-3" /> {l.flow}
                      </span>
                    </div>
                  )}
                </Fragment>
              );
            })}
          </div>
        </section>

        {/* how it works */}
        <HowItWorks ctaHref={ctaHref} />

        {/* console tour */}
        <ConsoleTour ctaHref={ctaHref} />

        {/* incident walkthrough */}
        <IncidentWalkthrough ctaHref={ctaHref} />

        {/* workflow */}
        <section id="workflow" className="relative z-10 mx-auto w-full max-w-6xl scroll-mt-20 px-5 py-14">
          <div className="mx-auto mb-10 max-w-2xl text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">The killer workflow</p>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">Audit → Shield → Verify</h2>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              The complete lifecycle WebGuard proves, end to end, in about ten seconds — running live right here.
            </p>
          </div>
          <WorkflowShowcase ctaHref={ctaHref} />
        </section>

        {/* verification matrix */}
        <section id="verify" className="relative z-10 mx-auto w-full max-w-5xl scroll-mt-20 px-5 py-14">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.45 }}
            className="overflow-hidden rounded-2xl border border-border/50 bg-card/60"
          >
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 px-6 py-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">Proof, not promises</p>
                <h3 className="mt-1 text-xl font-bold tracking-tight">Before vs. After comparison</h3>
              </div>
              <div className="flex items-center gap-2 text-[11px]">
                <span className="rounded-md border border-wg-rose/30 bg-wg-rose/10 px-2 py-1 font-bold text-wg-rose">WAF OFF · GRADE F</span>
                <ArrowRight className="size-4 text-muted-foreground" />
                <span className="rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-2 py-1 font-bold text-wg-emerald">WAF ON · GRADE A+</span>
              </div>
            </div>
            <div className="divide-y divide-border/30">
              {MATRIX.map((row) => (
                <div key={row.control} className="grid grid-cols-[1.15fr_1fr_1.25fr] items-center gap-3 px-6 py-3 text-xs">
                  <span className="text-muted-foreground">{row.control}</span>
                  <span className="flex items-center gap-2 font-mono text-wg-rose/80 line-through decoration-wg-rose/40">
                    <TriangleAlert className="size-4 shrink-0 text-wg-rose" /> {row.before}
                  </span>
                  <span className="flex items-center gap-2 font-mono text-wg-emerald">
                    <CheckCircle2 className="size-4 shrink-0 text-wg-emerald" /> {row.after}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        </section>

        {/* comparison */}
        <ComparisonTable ctaHref={ctaHref} />

        {/* built for */}
        <RolesSection ctaHref={ctaHref} />

        {/* trust strip */}
        <section className="relative z-10 mx-auto w-full max-w-6xl px-5 py-8">
          <p className="text-center text-[10px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
            Trusted by security teams shipping fast
          </p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-x-10 gap-y-3">
            {TRUST.map((t) => (
              <span key={t} className="font-mono text-sm font-semibold uppercase tracking-[0.2em] text-muted-foreground/60 transition-colors hover:text-muted-foreground">
                {t}
              </span>
            ))}
          </div>
        </section>

        {/* testimonials */}
        <section className="relative z-10 mx-auto w-full max-w-6xl px-5 py-14">
          <div className="mx-auto mb-10 max-w-2xl text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">Field notes</p>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">Security teams on WebGuard</h2>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {TESTIMONIALS.map((t, i) => (
              <motion.div
                key={t.name}
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-60px" }}
                transition={{ duration: 0.4, delay: i * 0.07 }}
                className="flex flex-col justify-between rounded-2xl border border-border/50 bg-card/60 p-5"
              >
                <p className="text-[13px] leading-relaxed text-foreground/80">“{t.quote}”</p>
                <div className="mt-4 flex items-center gap-2.5">
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/15 text-[11px] font-bold text-primary">
                    {t.name[0]}
                  </div>
                  <div className="leading-tight">
                    <p className="text-xs font-semibold text-foreground">{t.name}</p>
                    <p className="text-[10px] text-muted-foreground">{t.role}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </section>

        {/* FAQ */}
        <FaqSection />

        {/* final CTA */}
        <section className="relative z-10 mx-auto w-full max-w-6xl px-5 py-16">
          <div className="relative overflow-hidden rounded-3xl border border-primary/25 bg-gradient-to-br from-card via-background to-card px-6 py-14 text-center">
            <div className="pointer-events-none absolute left-1/2 top-0 h-40 w-[600px] -translate-x-1/2 rounded-full bg-primary/10 blur-[80px]" />
            <div className="relative">
              <div className="mx-auto flex size-14 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10 text-primary shadow-[0_0_40px_rgba(34,211,238,0.2)]">
                <Lock className="size-7" />
              </div>
              <h2 className="mx-auto mt-6 max-w-xl text-3xl font-bold tracking-tight">
                See a 28/100 website become a <span className="text-wg-emerald">100/100</span> in ten seconds
              </h2>
              <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-muted-foreground">
                Run the baseline audit, flip the firewall on, re-scan, and watch the comparison matrix fill in. All
                simulated, all interactive.
              </p>
              <div className="mt-6 flex flex-wrap items-center justify-center gap-2 text-[11px] text-muted-foreground">
                {["Run the baseline audit", "Flip the firewall to BLOCKING", "Re-scan the target", "Compare the matrix"].map(
                  (s, i) => (
                    <span
                      key={s}
                      className="flex items-center gap-1.5 rounded-full border border-border/60 bg-background/60 px-3 py-1"
                    >
                      <span className="font-mono font-bold text-primary">{i + 1}</span> {s}
                    </span>
                  ),
                )}
              </div>
              <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
                <Button asChild size="lg" className="h-11 gap-2 bg-gradient-to-r from-cyan-400 to-emerald-400 px-7 font-semibold text-[#04121c] shadow-[0_0_30px_rgba(34,211,238,0.35)] hover:opacity-90">
                  <Link to={ctaHref}>
                    {isAuthenticated ? "Open the SOC Console" : "Start the demo"} <ArrowRight className="size-4" />
                  </Link>
                </Button>
                <Button asChild variant="outline" size="lg" className="h-11 gap-2 border-border/60 px-6 text-foreground/80">
                  <Link to={ctaHref}>
                    <Globe className="size-4" /> {isAuthenticated ? "Open Dashboard" : "Sign in with email"}
                  </Link>
                </Button>
              </div>
            </div>
          </div>
        </section>

        {/* footer */}
        <footer className="relative z-10 border-t border-border/40">
          <div className="mx-auto grid w-full max-w-6xl grid-cols-1 gap-8 px-5 py-12 md:grid-cols-[1.4fr_1fr_1fr]">
            <div>
              <div className="flex items-center gap-2.5">
                <div className="flex size-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400 to-emerald-400">
                  <ShieldCheck className="size-4 text-[#04121c]" />
                </div>
                <p className="text-sm font-bold tracking-tight">
                  WebGuard<span className="text-wg-cyan">.</span>
                </p>
              </div>
              <p className="mt-3 max-w-xs text-xs leading-relaxed text-muted-foreground">
                AI-Powered Web Application Firewall & real-time Security Operations Center. Audit, shield, and verify
                any origin — end to end, in the browser.
              </p>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Product</p>
              <ul className="mt-3 flex flex-col gap-2 text-xs text-muted-foreground">
                <li><a href="#features" className="transition-colors hover:text-foreground">Capabilities</a></li>
                <li><a href="#how" className="transition-colors hover:text-foreground">How it works</a></li>
                <li><a href="#console" className="transition-colors hover:text-foreground">Console tour</a></li>
                <li><a href="#deepdive" className="transition-colors hover:text-foreground">Deep-dive explorer</a></li>
                <li><a href="#incident" className="transition-colors hover:text-foreground">Incident walkthrough</a></li>
                <li><a href="#workflow" className="transition-colors hover:text-foreground">Audit → Shield → Verify</a></li>
                <li><a href="#verify" className="transition-colors hover:text-foreground">Comparison matrix</a></li>
                <li><a href="#roles" className="transition-colors hover:text-foreground">Built for</a></li>
                <li><Link to={ctaHref} className="transition-colors hover:text-foreground">SOC Console</Link></li>
              </ul>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Platform</p>
              <ul className="mt-3 flex flex-col gap-2 text-xs text-muted-foreground">
                <li><span className="flex items-center gap-1.5"><CheckCircle2 className="size-3 text-wg-emerald" /> No backend required</span></li>
                <li><span className="flex items-center gap-1.5"><CheckCircle2 className="size-3 text-wg-emerald" /> Client-side telemetry</span></li>
                <li><span className="flex items-center gap-1.5"><CheckCircle2 className="size-3 text-wg-emerald" /> Light & dark themes</span></li>
              </ul>
            </div>
          </div>
          <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-3 border-t border-border/40 px-5 py-6 text-[11px] text-muted-foreground/70">
            <p className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-primary/70" />
              WebGuard — AI-Powered WAF & Real-Time SOC Dashboard
            </p>
            <p>Telemetry simulated client-side · no external calls · made for demos</p>
          </div>
        </footer>
      </div>
    </div>
  );
}

/* ============================================================================
   Live console preview (hero visual)
   ============================================================================ */

const STATUS_STYLE: Record<number, { cls: string; label: string }> = {
  200: { cls: "border-wg-emerald/30 bg-wg-emerald/10 text-wg-emerald", label: "200 OK" },
  301: { cls: "border-wg-sky/30 bg-wg-sky/10 text-wg-sky", label: "301" },
  403: { cls: "border-wg-rose/30 bg-wg-rose/10 text-wg-rose", label: "403" },
  429: { cls: "border-wg-amber/30 bg-wg-amber/10 text-wg-amber", label: "429" },
};

const PREVIEW_MODES = [
  {
    id: "blocking",
    short: "BLOCK",
    label: "BLOCKING — attacks dropped with 403",
    badgeCls: "border-wg-emerald/40 bg-wg-emerald/15 text-wg-emerald",
    dot: "bg-emerald-400",
    on: "border-wg-emerald/50 bg-wg-emerald/15 text-wg-emerald shadow-[0_0_14px_rgba(52,211,153,0.2)]",
    off: "border-border/60 text-muted-foreground hover:text-foreground",
  },
  {
    id: "detection",
    short: "DETECT",
    label: "DETECTION — log only, zero drops",
    badgeCls: "border-wg-amber/40 bg-wg-amber/15 text-wg-amber",
    dot: "bg-amber-400",
    on: "border-wg-amber/50 bg-wg-amber/15 text-wg-amber shadow-[0_0_14px_rgba(245,158,11,0.2)]",
    off: "border-border/60 text-muted-foreground hover:text-foreground",
  },
  {
    id: "off",
    short: "OFF",
    label: "OFF — raw origin exposed",
    badgeCls: "border-wg-rose/40 bg-wg-rose/15 text-wg-rose",
    dot: "bg-rose-400",
    on: "border-wg-rose/50 bg-wg-rose/15 text-wg-rose shadow-[0_0_14px_rgba(244,63,94,0.2)]",
    off: "border-border/60 text-muted-foreground hover:text-foreground",
  },
] as const;

function ConsolePreview() {
  const [offset, setOffset] = useState(0);
  const [modeIdx, setModeIdx] = useState(0);
  const mode = PREVIEW_MODES[modeIdx];

  useEffect(() => {
    const iv = window.setInterval(() => setOffset((o) => (o + 1) % CONSOLE_ROWS.length), 1400);
    return () => window.clearInterval(iv);
  }, []);

  const visible = Array.from({ length: 4 }, (_, i) => {
    const r = CONSOLE_ROWS[(offset + i) % CONSOLE_ROWS.length];
    if (mode.id === "off") return { ...r, status: 200, score: 0, flagged: false };
    if (mode.id === "detection") {
      const hostile = r.status === 403 || r.status === 429;
      return hostile ? { ...r, status: 200, flagged: true } : { ...r, flagged: false };
    }
    return { ...r, flagged: false };
  });

  const hostile = visible.filter((r) => r.flagged || r.status === 403 || r.status === 429).length;

  const footerStat =
    mode.id === "blocking"
      ? { icon: ShieldOff, label: `${hostile} dropped`, cls: "text-wg-rose" }
      : mode.id === "detection"
        ? { icon: Radar, label: `${hostile} flagged`, cls: "text-wg-amber" }
        : { icon: ShieldOff, label: "EXPOSED", cls: "text-wg-rose" };

  return (
    <div className="relative overflow-hidden rounded-2xl border border-border/60 bg-card/95 shadow-[0_30px_80px_-30px_rgba(1,6,18,0.6)] backdrop-blur">
      {/* header */}
      <div className="flex items-center justify-between border-b border-border/40 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="flex gap-1.5">
            <span className="size-2.5 rounded-full bg-wg-rose/70" />
            <span className="size-2.5 rounded-full bg-wg-amber/70" />
            <span className="size-2.5 rounded-full bg-wg-emerald/70" />
          </span>
          <span className="ml-1 font-mono text-[10px] text-muted-foreground">webguard — SOC console</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 rounded-md border border-wg-emerald/30 bg-wg-emerald/10 px-1.5 py-0.5 text-[9px] font-bold text-wg-emerald">
            <span className="size-1 animate-pulse rounded-full bg-emerald-400" /> EDGE
          </span>
          <span className={`flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9px] font-bold tracking-wider ${mode.badgeCls}`}>
            <span className={`size-1 animate-pulse rounded-full ${mode.dot}`} />
            {mode.id === "blocking" ? "BLOCKING" : mode.id === "detection" ? "DETECT" : "OFF"}
          </span>
        </div>
      </div>

      {/* traffic rows */}
      <div className="flex flex-col divide-y divide-border/30">
        {visible.map((r, i) => {
          const s = STATUS_STYLE[r.status];
          return (
            <motion.div
              key={`${offset}-${modeIdx}-${i}`}
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="flex items-center gap-2.5 px-4 py-2"
            >
              <span className={`w-[68px] shrink-0 rounded border px-1.5 py-0.5 text-center font-mono text-[9px] font-bold ${s.cls}`}>
                {s.label}
              </span>
              <span className="w-10 shrink-0 font-mono text-[10px] font-bold text-foreground/80">{r.method}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-muted-foreground">{r.path}</span>
              <span className="hidden font-mono text-[9px] text-muted-foreground/70 sm:inline">{r.ip}</span>
              {r.flagged ? (
                <span className="shrink-0 rounded-full border border-wg-amber/40 bg-wg-amber/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-wg-amber">
                  LOG {r.score}
                </span>
              ) : (
                <span
                  className={`shrink-0 rounded-full border px-1.5 py-0.5 font-mono text-[9px] font-semibold ${
                    r.score >= 80
                      ? "border-wg-rose/40 bg-wg-rose/10 text-wg-rose"
                      : "border-border text-muted-foreground"
                  }`}
                >
                  {r.score}
                </span>
              )}
            </motion.div>
          );
        })}
      </div>

      {/* footer metrics */}
      <div className="flex items-center justify-between border-t border-border/40 bg-muted/30 px-4 py-2.5">
        <div className="flex gap-4">
          <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <Gauge className="size-3 text-wg-cyan" /> <span className="font-mono font-semibold text-foreground/80">1.9 ms</span>
          </span>
          <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <Radar className="size-3 text-wg-cyan" /> <span className="font-mono font-semibold text-foreground/80">214 rps</span>
          </span>
          <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <footerStat.icon className={`size-3 ${footerStat.cls}`} />
            <span className={`font-mono font-semibold ${footerStat.cls}`}>{footerStat.label}</span>
          </span>
        </div>
        <svg width="110" height="26" viewBox="0 0 110 26" className="shrink-0">
          <defs>
            <linearGradient id="wg-spark" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#34d399" stopOpacity="0.9" />
            </linearGradient>
          </defs>
          <polyline
            points="0,18 12,14 24,16 36,10 48,12 60,6 72,9 84,4 96,7 110,2"
            fill="none"
            stroke="url(#wg-spark)"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>

      {/* firewall mode switcher */}
      <div className="flex flex-wrap items-center justify-center gap-1.5 border-t border-border/40 bg-muted/30 px-4 py-2">
        <span className="mr-1 text-[9px] font-bold uppercase tracking-[0.18em] text-muted-foreground">Firewall</span>
        {PREVIEW_MODES.map((m, i) => (
          <button
            key={m.id}
            type="button"
            title={m.label}
            onClick={() => setModeIdx(i)}
            className={`flex h-6 items-center gap-1.5 rounded-md border px-2 text-[9px] font-bold tracking-wider transition-all ${
              i === modeIdx ? m.on : m.off
            }`}
          >
            <span className={`size-1.5 rounded-full ${m.dot}`} /> {m.short}
          </button>
        ))}
      </div>
    </div>
  );
}

/* ============================================================================
   Animated counter
   ============================================================================ */

function CountUp({ to, suffix = "", decimals = 0 }: { to: number; suffix?: string; decimals?: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  const [val, setVal] = useState(0);

  useEffect(() => {
    if (!inView) return;
    const start = performance.now();
    const dur = 1100;
    let raf = 0;
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      setVal(to * (1 - Math.pow(1 - t, 3)));
      if (t < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [inView, to]);

  return (
    <span ref={ref}>
      {val.toFixed(decimals)}
      {suffix}
    </span>
  );
}

/* ============================================================================
   Threat catalog — interactive attack-class tabs
   ============================================================================ */

function ThreatCatalog({ ctaHref }: { ctaHref: string }) {
  return (
    <section id="threats" className="relative z-10 mx-auto w-full max-w-6xl px-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/50 bg-card/60 px-5 py-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-primary">Threat catalog</p>
          <h3 className="mt-1 text-lg font-bold tracking-tight">The attacks WebGuard blocks</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
          <span className="rounded-md border border-border/60 bg-muted/40 px-2 py-1 font-mono font-bold">7 classes</span>
          <span>severity · rule · OWASP mapping</span>
        </div>
      </div>

      <Tabs defaultValue="sqli">
        <TabsList className="flex h-auto w-full flex-wrap justify-start gap-1 rounded-xl border border-border/50 bg-card/60 p-1.5">
          {THREATS.map((t) => (
            <TabsTrigger
              key={t.id}
              value={t.id}
              className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary dark:data-[state=active]:bg-primary/15"
            >
              <t.icon className="size-3.5" />
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {THREATS.map((t) => (
          <TabsContent key={t.id} value={t.id} className="mt-3">
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="grid grid-cols-1 gap-4 lg:grid-cols-[1.1fr_1fr]"
            >
              {/* attacker side */}
              <div className="rounded-2xl border border-border/50 bg-card/60 p-5">
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span
                    className={`rounded-md border px-2 py-0.5 font-bold ${SEVERITY_META[t.severity].badge}`}
                  >
                    {SEVERITY_META[t.severity].label}
                  </span>
                  <span className="rounded-md border border-border/60 bg-muted/40 px-2 py-0.5 font-mono font-semibold text-muted-foreground">
                    {t.rule}
                  </span>
                  <span className="rounded-md border border-border/60 bg-muted/40 px-2 py-0.5 text-muted-foreground">
                    {t.owasp}
                  </span>
                </div>
                <h3 className="mt-3 text-lg font-bold tracking-tight">{t.label}</h3>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{t.how}</p>
                <p className="mt-4 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                  Typical payload
                </p>
                <pre className="mt-2 overflow-x-auto rounded-lg border border-border/60 bg-muted/50 p-3 font-mono text-[11px] leading-relaxed text-foreground/85">
                  {t.payload}
                </pre>
              </div>

              {/* defender side */}
              <div className="rounded-2xl border border-wg-emerald/25 bg-card/60 p-5">
                <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-wg-emerald">
                  <ShieldCheck className="size-3.5" /> How WebGuard catches it
                </p>
                <ul className="mt-3 flex flex-col gap-2.5">
                  {t.detect.map((d) => (
                    <li key={d} className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
                      <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-wg-emerald" />
                      {d}
                    </li>
                  ))}
                </ul>
                <div className="mt-4 flex items-center gap-2.5 rounded-lg border border-wg-rose/25 bg-wg-rose/[0.06] px-3 py-2.5">
                  <ShieldOff className="size-4 shrink-0 text-wg-rose" />
                  <div className="text-xs">
                    <p className="font-bold text-wg-rose">{t.response}</p>
                    <p className="mt-0.5 text-muted-foreground">{t.responseDetail}</p>
                  </div>
                </div>
              </div>
            </motion.div>
          </TabsContent>
        ))}
      </Tabs>

      <div className="mt-8 text-center">
        <Button asChild variant="outline" size="lg" className="h-10 gap-2 border-border/60 px-5 text-foreground/80">
          <Link to={ctaHref}>
            Watch them in the live stream <ArrowRight className="size-4" />
          </Link>
        </Button>
      </div>
    </section>
  );
}

/* ============================================================================
   Detection engine pipeline
   ============================================================================ */

function DetectionPipeline() {
  return (
    <section id="engine" className="relative z-10 mx-auto w-full max-w-6xl px-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/50 bg-card/60 px-5 py-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-primary">Inside the engine</p>
          <h3 className="mt-1 text-lg font-bold tracking-tight">Every request, inspected in five passes</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
          <span className="rounded-md border border-border/60 bg-muted/40 px-2 py-1 font-mono font-bold">5 passes</span>
          <span>~1.9 ms per request</span>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        {ENGINE_STEPS.map((s, i) => (
          <motion.div
            key={s.title}
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.4, delay: i * 0.07 }}
            className="relative rounded-2xl border border-border/50 bg-card/60 p-4"
          >
            <div className="flex items-center justify-between">
              <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <s.icon className="size-4" />
              </div>
              <span className="font-mono text-[9px] font-bold text-muted-foreground/60">PASS {i + 1} · {s.time}</span>
            </div>
            <h3 className="mt-3 text-sm font-semibold text-foreground">{s.title}</h3>
            <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">{s.body}</p>
            {i < ENGINE_STEPS.length - 1 && (
              <ArrowRight className="absolute -right-2.5 top-1/2 hidden size-4 -translate-y-1/2 text-muted-foreground/40 md:block" />
            )}
          </motion.div>
        ))}
      </div>
      <div className="mt-6 flex flex-wrap items-center justify-center gap-2 rounded-2xl border border-border/50 bg-card/60 px-5 py-4 text-[11px] text-muted-foreground">
        <ShieldCheck className="size-4 shrink-0 text-wg-emerald" />
        <span>
          Typical hostile path: <span className="font-mono font-bold text-wg-rose">403 BLOCKED</span> in ~1.9 ms total
          — hostile traffic never reaches the origin.
        </span>
      </div>
    </section>
  );
}

/* ============================================================================
   Six audit pillars — accordion with raw evidence + virtual patches
   ============================================================================ */

const PILLAR_ICONS: Record<string, LucideIcon> = {
  FileLock,
  Share2,
  Cookie,
  Fingerprint,
  Bug,
  Gauge,
};

function PillarsDetail() {
  const byPillar = (id: string) => BASELINE_FINDINGS.filter((f) => f.pillar === id);
  return (
    <section id="pillars" className="relative z-10 mx-auto w-full max-w-4xl px-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/50 bg-card/60 px-5 py-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-primary">The audit, in detail</p>
          <h3 className="mt-1 text-lg font-bold tracking-tight">Six pillars. Fourteen findings.</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
          <span className="rounded-md border border-wg-rose/30 bg-wg-rose/10 px-2 py-1 font-mono font-bold text-wg-rose">14 findings</span>
          <span>evidence · impact · virtual patch</span>
        </div>
      </div>
      <Accordion type="single" collapsible className="rounded-2xl border border-border/50 bg-card/60 px-5">
        {PILLARS.map((p) => {
          const Icon = PILLAR_ICONS[p.icon] ?? Gauge;
          const findings = byPillar(p.id);
          return (
            <AccordionItem key={p.id} value={p.id} className="border-border/40">
              <AccordionTrigger className="py-4 hover:no-underline">
                <span className="flex flex-1 items-center gap-3 pr-3 text-left">
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Icon className="size-4" />
                  </span>
                  <span className="flex-1">
                    <span className="block text-sm font-semibold text-foreground">{p.title}</span>
                    <span className="mt-0.5 block text-[11px] text-muted-foreground">{p.summary}</span>
                  </span>
                  <span className="shrink-0 rounded-md border border-wg-rose/30 bg-wg-rose/10 px-2 py-0.5 text-[10px] font-bold text-wg-rose">
                    {findings.length} finding{findings.length > 1 ? "s" : ""}
                  </span>
                </span>
              </AccordionTrigger>
              <AccordionContent>
                <div className="flex flex-col gap-3 pb-4">
                  {findings.map((f) => (
                    <div key={f.id} className="rounded-xl border border-border/50 bg-muted/30 p-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded-md border px-2 py-0.5 text-[10px] font-bold ${SEVERITY_META[f.severity].badge}`}
                        >
                          {SEVERITY_META[f.severity].label}
                        </span>
                        <span className="font-mono text-[10px] text-muted-foreground">{f.id}</span>
                        <span className="text-xs font-semibold text-foreground">{f.title}</span>
                      </div>
                      <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">{f.explanation}</p>
                      <pre className="mt-2.5 overflow-x-auto rounded-lg border border-border/60 bg-card/80 p-2.5 font-mono text-[10.5px] leading-relaxed text-foreground/80">
                        {f.evidence}
                      </pre>
                      <p className="mt-2.5 flex items-start gap-1.5 text-[11px] leading-relaxed">
                        <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-wg-emerald" />
                        <span className="text-wg-emerald">
                          <span className="font-bold">Virtual patch — </span>
                          <span className="font-mono text-[10.5px]">{f.patch}</span>
                        </span>
                      </p>
                    </div>
                  ))}
                </div>
              </AccordionContent>
            </AccordionItem>
          );
        })}
      </Accordion>
    </section>
  );
}

/* ============================================================================
   FAQ
   ============================================================================ */

function FaqSection() {
  return (
    <section id="faq" className="relative z-10 mx-auto w-full max-w-4xl scroll-mt-20 px-5 py-14">
      <div className="mx-auto mb-10 max-w-2xl text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">FAQ</p>
        <h2 className="mt-3 text-3xl font-bold tracking-tight">Straight answers</h2>
      </div>
      <Accordion type="single" collapsible className="rounded-2xl border border-border/50 bg-card/60 px-5">
        {FAQ_ITEMS.map((f) => (
          <AccordionItem key={f.q} value={f.q} className="border-border/40">
            <AccordionTrigger className="py-4 text-left text-sm font-semibold hover:no-underline">
              {f.q}
            </AccordionTrigger>
            <AccordionContent className="text-xs leading-relaxed text-muted-foreground">{f.a}</AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </section>
  );
}
