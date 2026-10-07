import { ATTACK_LABELS } from "./types";
import type { AttackType, BlockedIp, Severity, WafMode } from "./types";

// ============================================================================
// Attack Drill mode — scripted, staged attack scenarios that play out over
// time through the real WAF pipeline so every screen reacts live.
// ============================================================================

export interface DrillStage {
  id: string;
  label: string;
  desc: string;
  durationSec: number;
  /** Attack class this stage generates (null = benign-only segment). */
  attackType: AttackType | null;
  /** 0..1 — fraction of requests in this stage that are hostile. */
  attackShare: number;
  /** Target request rate for the stage (requests/second). */
  rate: number;
  /** Optional path pool — when present, requests pick paths from it. */
  pathPool?: string[];
  /** Raised the moment the stage begins. */
  alarm?: { title: string; severity: Severity };
  /** Opened the moment the stage begins. */
  incident?: { title: string; severity: Severity };
  /** Milestone event text shown in the drill feed. */
  milestone?: string;
}

export interface DrillScenario {
  id: string;
  name: string;
  tagline: string;
  difficulty: "Basic" | "Moderate" | "Advanced";
  brief: string;
  attackTypes: AttackType[];
  stages: DrillStage[];
}

export type DrillEventTone = "info" | "alarm" | "incident" | "done";

export interface DrillEvent {
  id: string;
  t: number;
  text: string;
  tone: DrillEventTone;
}

export interface DrillStats {
  requests: number;
  blocked: number;
  attacks: number;
  alarms: number;
  incidents: number;
  canaryTrips: number;
  bans: number;
  /** Per-attack-class counter observed during the drill (drives the mix chart). */
  attackMix?: Partial<Record<AttackType, number>>;
}

export interface DrillState {
  scenarioId: string;
  startedAt: number;
  stageIdx: number;
  paused: boolean;
  done: boolean;
  /** True = campaign emits pure attack traffic (no benign blend in stages). */
  isolated?: boolean;
  /** Set when the drill flips to done — drives the auto-advance timer. */
  doneAt?: number;
  events: DrillEvent[];
  stats: DrillStats;
  lastTickAt: number;
}

/** A scenario waiting to auto-start when the current drill finishes (or when idle). */
export interface QueuedDrill {
  qid: string;
  scenarioId: string;
}

/** How long a finished drill keeps its results on screen before the queue advances. */
export const DRILL_AUTO_ADVANCE_MS = 8000;

/** Repeating-cadence schedule — the console auto-starts a scenario when idle and due. */
export interface DrillSchedule {
  enabled: boolean;
  /** Minutes between auto-runs. */
  intervalMin: number;
  /** Scenario id, or "random" to pick one each run. */
  scenarioId: string | "random";
  /** Epoch ms of the next auto-run (null while disabled). */
  nextRunAt: number | null;
}

export const DEFAULT_DRILL_SCHEDULE: DrillSchedule = {
  enabled: false,
  intervalMin: 10,
  scenarioId: "random",
  nextRunAt: null,
};

export type DrillOutcome = "completed" | "aborted";

export interface DrillHistoryEntry {
  id: string;
  scenarioId: string;
  startedAt: number;
  finishedAt: number;
  outcome: DrillOutcome;
  stats: DrillStats;
}

export function emptyDrillStats(): DrillStats {
  return { requests: 0, blocked: 0, attacks: 0, alarms: 0, incidents: 0, canaryTrips: 0, bans: 0, attackMix: {} };
}

export function scenarioTotalSec(s: DrillScenario): number {
  return s.stages.reduce((t, st) => t + st.durationSec, 0);
}

/** Index of the stage that covers `elapsedSec` into the scenario. */
export function stageIndexAt(s: DrillScenario, elapsedSec: number): number {
  let acc = 0;
  for (let i = 0; i < s.stages.length; i++) {
    acc += s.stages[i].durationSec;
    if (elapsedSec < acc) return i;
  }
  return s.stages.length - 1;
}

/** Seconds elapsed inside the current stage. */
export function stageElapsedAt(s: DrillScenario, elapsedSec: number): number {
  const idx = stageIndexAt(s, elapsedSec);
  let acc = 0;
  for (let i = 0; i < idx; i++) acc += s.stages[i].durationSec;
  return Math.max(0, elapsedSec - acc);
}

export const DRILL_SCENARIOS: DrillScenario[] = [
  {
    id: "sqli-siege",
    name: "SQLi Siege",
    tagline: "Scanner recon escalates into a sustained SQL injection flood against the API.",
    difficulty: "Advanced",
    brief:
      "A scripted campaign that starts with reconnaissance, then pivots into targeted injection bursts against /api/search, blends with benign traffic, and finishes with a full-scale flood. Watch the blocklist, alerts, and incident queue react in real time.",
    attackTypes: ["scanner", "sqli"],
    stages: [
      {
        id: "recon",
        label: "Recon sweep",
        desc: "Automated scanner enumerates API surface and probes for injection reflection points.",
        durationSec: 8,
        attackType: "scanner",
        attackShare: 0.55,
        rate: 4,
        pathPool: ["/api/search", "/api/products", "/api/orders", "/.env", "/admin"],
        milestone: "Scanner sweep detected against the API surface",
      },
      {
        id: "burst",
        label: "Targeted SQLi bursts",
        desc: "Injection payloads hammer /api/search with tautologies and stacked queries.",
        durationSec: 18,
        attackType: "sqli",
        attackShare: 0.7,
        rate: 8,
        pathPool: ["/api/search?q=", "/api/products?filter=", "/api/orders?status="],
        alarm: { title: "SQLi burst on /api/search — high attempt rate", severity: "critical" },
      },
      {
        id: "blend",
        label: "Blended noise",
        desc: "Attackers mix injections with legitimate-looking traffic to evade velocity rules.",
        durationSec: 12,
        attackType: "sqli",
        attackShare: 0.35,
        rate: 6,
        pathPool: ["/api/search?q=", "/api/products?filter="],
        milestone: "Attackers blending malicious payloads with benign traffic",
      },
      {
        id: "flood",
        label: "Full-scale flood",
        desc: "Coordinated injection flood from distributed sources — the decisive push.",
        durationSec: 14,
        attackType: "sqli",
        attackShare: 0.85,
        rate: 14,
        pathPool: ["/api/search?q=", "/api/products?filter=", "/api/orders?status="],
        incident: { title: "SQLi campaign against /api/search", severity: "critical" },
      },
    ],
  },
  {
    id: "ddos-storm",
    name: "DDoS Storm",
    tagline: "A botnet ramps from low-rate probing into a full volumetric flood.",
    difficulty: "Advanced",
    brief:
      "Bad-bot traffic escalates through three phases — probing, amplification burst, and origin soak — before the botnet disperses. Rate limiting, throttling, and the stress model react live to the flood.",
    attackTypes: ["bot", "scanner"],
    stages: [
      {
        id: "probe",
        label: "Low-rate probing",
        desc: "Botnet nodes test the edge with scattered requests to map defenses.",
        durationSec: 8,
        attackType: "bot",
        attackShare: 0.5,
        rate: 5,
        pathPool: ["/", "/wp-login.php", "/api/health", "/cdn/asset.js"],
      },
      {
        id: "amplify",
        label: "Amplification burst",
        desc: "Traffic velocity spikes — the edge budget is breached and throttling engages.",
        durationSec: 16,
        attackType: "bot",
        attackShare: 0.9,
        rate: 20,
        pathPool: ["/", "/api/search", "/api/products", "/wp-login.php", "/cdn/asset.js"],
        alarm: { title: "Traffic anomaly — possible DDoS in progress", severity: "critical" },
      },
      {
        id: "soak",
        label: "Origin soak",
        desc: "Sustained volumetric flood saturates the origin — edge stress peaks.",
        durationSec: 14,
        attackType: "bot",
        attackShare: 0.75,
        rate: 12,
        pathPool: ["/", "/api/search", "/api/products", "/cdn/asset.js"],
        incident: { title: "Sustained volumetric flood — DDoS incident", severity: "high" },
      },
      {
        id: "cooldown",
        label: "Dispersal",
        desc: "Botnet nodes peel off — residual traffic is monitored for re-ramp.",
        durationSec: 12,
        attackType: "bot",
        attackShare: 0.2,
        rate: 4,
        pathPool: ["/", "/api/health"],
        milestone: "Attackers dispersing — monitoring residual traffic for re-ramp",
      },
    ],
  },
  {
    id: "cred-stuffing",
    name: "Credential Stuffing",
    tagline: "A distributed botnet grinds through stolen credentials against the login endpoint.",
    difficulty: "Moderate",
    brief:
      "Stolen-credential lists are replayed against /api/login from a rotating pool of hostile IPs, ramping from a slow crawl into a distributed stuffing storm that triggers lockout pressure and rate alarms.",
    attackTypes: ["bot"],
    stages: [
      {
        id: "ramp",
        label: "Slow ramp",
        desc: "A handful of bot IPs begin replaying credential lists at low velocity.",
        durationSec: 12,
        attackType: "bot",
        attackShare: 0.45,
        rate: 4,
        pathPool: ["/api/login", "/api/auth", "/api/session"],
        milestone: "Repeated login failures detected from rotating IPs",
      },
      {
        id: "distributed",
        label: "Distributed ramp",
        desc: "The botnet widens — stuffing attempts now arrive from many subnets.",
        durationSec: 16,
        attackType: "bot",
        attackShare: 0.75,
        rate: 9,
        pathPool: ["/api/login", "/api/auth"],
        alarm: { title: "Credential stuffing ramp on /api/login", severity: "high" },
      },
      {
        id: "lockout",
        label: "Lockout storm",
        desc: "Sustained stuffing triggers throttling and account-lockout pressure.",
        durationSec: 18,
        attackType: "bot",
        attackShare: 0.6,
        rate: 10,
        pathPool: ["/api/login", "/api/auth", "/api/session"],
        incident: { title: "Credential stuffing campaign — lockout pressure", severity: "high" },
      },
    ],
  },
  {
    id: "xss-evasion",
    name: "XSS & Evasion Sweep",
    tagline: "Reflected XSS payloads evolve from plain signatures to obfuscated variants.",
    difficulty: "Moderate",
    brief:
      "A sweep against /search starts with textbook reflected payloads, then shifts to encoded and obfuscated variants designed to dodge signature engines — testing entropy and behavior layers.",
    attackTypes: ["xss", "scanner"],
    stages: [
      {
        id: "probe",
        label: "Signature probes",
        desc: "Classic reflected <script> payloads probe the search endpoint.",
        durationSec: 10,
        attackType: "xss",
        attackShare: 0.5,
        rate: 3,
        pathPool: ["/search?q=", "/api/search?q="],
      },
      {
        id: "obfuscate",
        label: "Obfuscation attempts",
        desc: "Encoded, case-shifted, and nested payloads attempt to bypass signatures.",
        durationSec: 16,
        attackType: "xss",
        attackShare: 0.7,
        rate: 7,
        pathPool: ["/search?q=", "/api/search?q=", "/search?term="],
        alarm: { title: "XSS sweep against /search — obfuscated payloads", severity: "high" },
      },
      {
        id: "rain",
        label: "Payload rain",
        desc: "A dense mix of XSS variants rains across search and comment endpoints.",
        durationSec: 20,
        attackType: "xss",
        attackShare: 0.75,
        rate: 11,
        pathPool: ["/search?q=", "/api/search?q=", "/api/comments", "/search?term="],
        incident: { title: "Persistent XSS campaign against search", severity: "high" },
      },
    ],
  },
  {
    id: "api-abuse",
    name: "API Abuse",
    tagline: "OWASP API Top 10 — IDOR probing, mass assignment and scraping against the API tier.",
    difficulty: "Moderate",
    brief:
      "A campaign aimed squarely at the API tier: object-ID enumeration and path-traversal probes first, then mass-assignment POSTs that try to smuggle privileged fields, finishing with a scraper storm that breaches the rate budget and triggers 429 pressure.",
    attackTypes: ["path-traversal", "bot"],
    stages: [
      {
        id: "idor",
        label: "IDOR & path probing",
        desc: "Object-ID enumeration and traversal probes sweep the API tier for broken access control.",
        durationSec: 10,
        attackType: "path-traversal",
        attackShare: 0.55,
        rate: 4,
        pathPool: ["/api/orders/1001", "/api/users/42", "/api/invoices", "/api/download?file=", "/api/export?path="],
        alarm: { title: "IDOR enumeration against /api/orders — broken object-level auth", severity: "high" },
      },
      {
        id: "mass",
        label: "Mass assignment flood",
        desc: "POSTs smuggle privileged fields (role, isAdmin) into user/checkout endpoints.",
        durationSec: 16,
        attackType: "bot",
        attackShare: 0.7,
        rate: 9,
        pathPool: ["/api/users", "/api/checkout", "/api/profile", "/api/invoices"],
        milestone: "Mass-assignment payloads detected on user & checkout endpoints",
      },
      {
        id: "scrape",
        label: "Scraper storm",
        desc: "Coordinated scraping of catalog & pricing breaches the rate budget — throttling engages.",
        durationSec: 18,
        attackType: "bot",
        attackShare: 0.85,
        rate: 14,
        pathPool: ["/api/products", "/api/pricing", "/api/search", "/api/catalog"],
        incident: { title: "Sustained API scraping campaign — rate budget breached", severity: "high" },
      },
    ],
  },
  {
    id: "rce-probe",
    name: "RCE Probe",
    tagline: "Command injection and high-entropy payloads hunt for code execution in file APIs.",
    difficulty: "Advanced",
    brief:
      "An attacker probes file-conversion and render endpoints for command injection, then switches to high-entropy encoded payloads engineered to dodge signature engines, and finally fuses both into a dense payload rain.",
    attackTypes: ["cmdi", "high-entropy"],
    stages: [
      {
        id: "cmdi-probe",
        label: "Command injection probes",
        desc: "Shell-metacharacter payloads target convert/export/render endpoints.",
        durationSec: 12,
        attackType: "cmdi",
        attackShare: 0.55,
        rate: 3,
        pathPool: ["/api/convert?cmd=", "/api/export?format=", "/api/render?template=", "/api/thumbnail?size="],
        alarm: { title: "Command injection probes against /api/convert", severity: "critical" },
      },
      {
        id: "entropy",
        label: "Entropy evasion",
        desc: "Base64 and high-entropy encoded payloads attempt to slip past the signature engine.",
        durationSec: 16,
        attackType: "high-entropy",
        attackShare: 0.7,
        rate: 7,
        pathPool: ["/api/convert?data=", "/api/import?raw=", "/api/execute?input=", "/api/render?template="],
        milestone: "High-entropy evasion wave — entropy classifier engaged",
      },
      {
        id: "fusion",
        label: "Payload fusion",
        desc: "Injection and encoded variants fuse into a dense rain across all file endpoints.",
        durationSec: 20,
        attackType: "cmdi",
        attackShare: 0.8,
        rate: 12,
        pathPool: ["/api/convert?cmd=", "/api/export?format=", "/api/import?raw=", "/api/execute?input="],
        incident: { title: "Persistent RCE probe campaign against file-conversion APIs", severity: "critical" },
      },
    ],
  },
  {
    id: "recon-scout",
    name: "Insider Recon",
    tagline: "A methodical scout hunts secrets, hidden endpoints, and canary decoys.",
    difficulty: "Basic",
    brief:
      "A patient scanner walks the perimeter — probing for .env leaks and admin panels, crawling deeper into the app, then tripping canary decoys. Watch findings appear in the register and the offender get auto-banned.",
    attackTypes: ["scanner", "path-traversal"],
    stages: [
      {
        id: "probing",
        label: "Path probing",
        desc: "Scanner requests known-sensitive paths: .env, backups, admin panels.",
        durationSec: 10,
        attackType: "scanner",
        attackShare: 0.6,
        rate: 3,
        pathPool: ["/.env", "/.git/config", "/admin", "/backup.zip", "/wp-login.php"],
        alarm: { title: "Sensitive-path probe — /.env and backup files", severity: "medium" },
      },
      {
        id: "crawl",
        label: "Deep crawl",
        desc: "Hidden endpoints enumerated across the application tree.",
        durationSec: 14,
        attackType: "scanner",
        attackShare: 0.65,
        rate: 6,
        pathPool: ["/api/users", "/api/config", "/api/debug", "/api/health", "/api/export"],
        milestone: "Deep crawl — hidden endpoints being enumerated",
      },
      {
        id: "decoy",
        label: "Decoy hunt",
        desc: "Path-traversal attempts trip canary tokens planted in the app.",
        durationSec: 16,
        attackType: "path-traversal",
        attackShare: 0.5,
        rate: 5,
        pathPool: ["/api/download?file=", "/api/upload?path=", "/static/../"],
        milestone: "Canary decoys tripped — offender IPs flagged for auto-ban",
      },
    ],
  },
  {
    id: "session-forge",
    name: "JWT Forge & Session Hijack",
    tagline: "Token tampering, session replay and cookie theft aimed at the auth tier.",
    difficulty: "Advanced",
    brief:
      "A campaign against the identity layer: the attacker maps the auth surface, forges high-entropy tampered JWTs, replays and fixes sessions, then finishes with a credential-stuffing finale against /api/login. Watch alarms, incidents and the blocklist react to each phase.",
    attackTypes: ["scanner", "high-entropy", "xss"],
    stages: [
      {
        id: "surface",
        label: "Auth surface mapping",
        desc: "Scanner enumerates auth, profile and token endpoints.",
        durationSec: 10,
        attackType: "scanner",
        attackShare: 0.5,
        rate: 4,
        pathPool: ["/api/auth/me", "/api/auth/refresh", "/api/account", "/api/session", "/api/users/me"],
        milestone: "Auth surface mapped — token & session endpoints discovered",
      },
      {
        id: "forge",
        label: "Token forgery attempts",
        desc: "High-entropy tampered JWTs and alg-confusion payloads probe /api/auth endpoints.",
        durationSec: 16,
        attackType: "high-entropy",
        attackShare: 0.7,
        rate: 7,
        pathPool: ["/api/auth/me", "/api/auth/refresh", "/api/account", "/api/orders"],
        alarm: { title: "JWT forgery attempts against /api/auth — alg-confusion signatures", severity: "critical" },
      },
      {
        id: "replay",
        label: "Session replay & fixation",
        desc: "Stolen-cookie and session-fixation payloads hit comment and profile endpoints.",
        durationSec: 18,
        attackType: "xss",
        attackShare: 0.65,
        rate: 8,
        pathPool: ["/api/comments", "/profile", "/api/users/me", "/api/session"],
        milestone: "Session replay detected — cookie exfiltration signatures firing",
      },
      {
        id: "stuff",
        label: "Credential-stuffing finale",
        desc: "A dense dump of leaked credentials floods the login endpoint — throttling and bans engage.",
        durationSec: 14,
        attackType: "high-entropy",
        attackShare: 0.85,
        rate: 12,
        pathPool: ["/api/login", "/api/auth/refresh", "/api/account"],
        incident: { title: "Credential-stuffing campaign against /api/login", severity: "critical" },
      },
    ],
  },
  {
    id: "ssrf-pivot",
    name: "SSRF Pivot & File Exfil",
    tagline: "Server-side request forgery pivots into internal services and secret exfiltration.",
    difficulty: "Advanced",
    brief:
      "The attacker probes for SSRF reflection points, then pivots into internal services and cloud metadata endpoints, exfiltrates files and secrets, and finally sweeps laterally across internal ranges. Every reflection point is scored by the live policy.",
    attackTypes: ["scanner", "path-traversal", "high-entropy"],
    stages: [
      {
        id: "fingerprint",
        label: "Reflection-point mapping",
        desc: "Scanner probes URL, fetch and proxy parameters for server-side reflection.",
        durationSec: 10,
        attackType: "scanner",
        attackShare: 0.5,
        rate: 4,
        pathPool: ["/api/fetch?url=", "/api/preview?link=", "/api/import?src=", "/proxy?target="],
        alarm: { title: "SSRF reflection probes on /api/fetch — URL parameters", severity: "high" },
      },
      {
        id: "pivot",
        label: "Internal pivot probes",
        desc: "Path-traversal payloads reach for internal hosts and metadata endpoints.",
        durationSec: 16,
        attackType: "path-traversal",
        attackShare: 0.7,
        rate: 6,
        pathPool: ["/api/fetch?url=http://127.0.0.1:22", "/api/fetch?url=http://169.254.169.254", "/api/preview?link=file:///etc/", "/proxy?target=10.0.0.1"],
        milestone: "Internal pivot attempts — metadata & loopback endpoints targeted",
      },
      {
        id: "exfil",
        label: "File & secret exfiltration",
        desc: "High-entropy fetches attempt to read secrets, configs and cloud credentials.",
        durationSec: 16,
        attackType: "high-entropy",
        attackShare: 0.75,
        rate: 8,
        pathPool: ["/api/fetch?url=file:///etc/passwd", "/api/import?src=s3://creds", "/api/preview?link=file:///var/www/.env"],
        alarm: { title: "Secret-exfil attempts — cloud metadata & file:// fetches", severity: "critical" },
      },
      {
        id: "sweep",
        label: "Lateral sweep",
        desc: "A coordinated sweep across internal ranges finishes the campaign.",
        durationSec: 14,
        attackType: "scanner",
        attackShare: 0.8,
        rate: 10,
        pathPool: ["/proxy?target=10.0.0.0/8", "/api/fetch?url=http://192.168.1.1", "/api/import?src=file:///root/"],
        incident: { title: "SSRF lateral sweep — internal network scanning", severity: "critical" },
      },
    ],
  },
  {
    id: "slow-drip",
    name: "Slowloris Weakening",
    tagline: "Low-and-slow connection exhaustion that quietly eats origin capacity.",
    difficulty: "Moderate",
    brief:
      "Instead of a volumetric flood, the botnet holds connections open with trickled bytes — slow POST bodies, partial headers and timed pulses that stay under the velocity radar. Watch connection saturation and origin latency climb while the rate limiter stays quiet.",
    attackTypes: ["bot"],
    stages: [
      {
        id: "hold",
        label: "Connection hold",
        desc: "Bots open connections and trickle headers to pin worker slots.",
        durationSec: 12,
        attackType: "bot",
        attackShare: 0.6,
        rate: 4,
        pathPool: ["/", "/index.html", "/api/health", "/static/app.js"],
        alarm: { title: "Slowloris connection-hold pattern — worker slots pinned", severity: "high" },
      },
      {
        id: "trickle",
        label: "Trickle flood",
        desc: "Slow POST bodies stream one byte at a time, staying under the rate budget.",
        durationSec: 18,
        attackType: "bot",
        attackShare: 0.75,
        rate: 6,
        pathPool: ["/api/upload", "/api/import", "/api/search", "/api/query"],
        milestone: "Trickle flood — slow POST bodies below velocity threshold",
      },
      {
        id: "pulse",
        label: "Timed pulse bursts",
        desc: "Short bursts timed to blend with legitimate traffic patterns.",
        durationSec: 16,
        attackType: "bot",
        attackShare: 0.6,
        rate: 8,
        pathPool: ["/", "/api/products", "/static/*.js", "/api/health"],
        milestone: "Pulse bursts detected — attack timing correlated across sources",
      },
      {
        id: "soak",
        label: "Origin soak",
        desc: "Sustained partial requests exhaust origin capacity and push latency up.",
        durationSec: 16,
        attackType: "bot",
        attackShare: 0.85,
        rate: 10,
        pathPool: ["/", "/api/health", "/static/app.js", "/api/search"],
        incident: { title: "Origin soak — connection saturation raising latency", severity: "high" },
      },
    ],
  },
  {
    id: "payload-replay",
    name: "Polyglot Payload Replay",
    tagline: "Captured payloads replayed, mutated and fused into multi-class injection storms.",
    difficulty: "Moderate",
    brief:
      "A replay-driven campaign: payloads captured from an earlier engagement are replayed verbatim, mutated with character fuzzers, combined into polyglot injections that are simultaneously SQL, XSS and command injection, then stormed across the API at full speed.",
    attackTypes: ["sqli", "xss", "cmdi"],
    stages: [
      {
        id: "replay",
        label: "Captured-payload replay",
        desc: "Previously captured injection payloads are replayed against the same endpoints.",
        durationSec: 12,
        attackType: "sqli",
        attackShare: 0.55,
        rate: 5,
        pathPool: ["/api/search?q=", "/api/products?filter=", "/api/orders?status="],
        milestone: "Replay campaign detected — payloads match prior engagement signatures",
      },
      {
        id: "polyglot",
        label: "Polyglot injection",
        desc: "Payloads that are simultaneously SQL, XSS and command injection land on search and render endpoints.",
        durationSec: 16,
        attackType: "sqli",
        attackShare: 0.7,
        rate: 8,
        pathPool: ["/api/search?q=", "/api/render?template=", "/api/export?format=", "/search?term="],
        alarm: { title: "Polyglot payloads — multi-class injection signatures matching", severity: "high" },
      },
      {
        id: "mutate",
        label: "Mutation fuzzing",
        desc: "Character mutations of known-bad payloads probe for bypasses.",
        durationSec: 16,
        attackType: "xss",
        attackShare: 0.65,
        rate: 9,
        pathPool: ["/search?q=", "/api/comments", "/api/search?q=", "/api/render?template="],
        milestone: "Mutation fuzzing — obfuscated variants of known payloads",
      },
      {
        id: "storm",
        label: "Polyglot storm",
        desc: "All classes fuse into a full-speed storm across the API tier.",
        durationSec: 16,
        attackType: "cmdi",
        attackShare: 0.85,
        rate: 13,
        pathPool: ["/api/search?q=", "/api/render?template=", "/api/export?format=", "/api/convert?cmd="],
        incident: { title: "Multi-class injection storm across the API tier", severity: "critical" },
      },
    ],
  },
];

export function drillScenarioById(id: string): DrillScenario | null {
  return DRILL_SCENARIOS.find((s) => s.id === id) ?? null;
}

export function randomDrillScenarioId(): string {
  return DRILL_SCENARIOS[Math.floor(Math.random() * DRILL_SCENARIOS.length)].id;
}

// ============================================================================
// Drill report — structured export archived in the console and rendered as
// Markdown, JSON, or a printable page.
// ============================================================================

export interface DrillReportStage {
  idx: number;
  label: string;
  desc: string;
  durationSec: number;
  attackType: string | null;
  attackShare: number;
  rate: number;
  milestone: string | null;
  alarm: string | null;
  incident: string | null;
}

export interface DrillReport {
  id: string;
  app: string;
  exportedAt: string;
  target: string;
  mode: WafMode;
  scenario: {
    id: string;
    name: string;
    tagline: string;
    difficulty: string;
    attackTypes: string[];
    totalSec: number;
  };
  outcome: "running" | "paused" | "completed" | "aborted";
  startedAt: string;
  finishedAt: string | null;
  durationSec: number;
  stats: DrillStats;
  blockedRatePct: number;
  attackStopRatePct: number;
  /** Scoring rubric — target vs achieved; absent on reports archived before the rubric shipped. */
  rubric?: {
    targetStopRate: number;
    targetBlockedRate: number;
    achievedStopRate: number;
    pass: boolean;
  };
  stages: DrillReportStage[];
  events: Array<{ t: string; tone: string; text: string }>;
  bans: Array<{ ip: string; reason: string; source: string; country: string; addedAt: string; hits: number }>;
}

function fmtSec(total: number): string {
  const s = Math.max(0, Math.round(total));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Builds a structured report for a drill (live, completed, or aborted). */
export function buildDrillReport(
  scenario: DrillScenario,
  drill: DrillState,
  bans: BlockedIp[],
  mode: WafMode,
  target: string,
  outcome?: "completed" | "aborted",
  id?: string,
): DrillReport {
  const final = outcome ?? (drill.done ? ("completed" as const) : drill.paused ? ("paused" as const) : ("running" as const));
  const finishedTs =
    final === "completed" ? (drill.doneAt ?? drill.lastTickAt) : final === "aborted" ? Date.now() : null;
  const blockedRatePct = drill.stats.requests ? Math.round((drill.stats.blocked / drill.stats.requests) * 100) : 0;
  const attackStopRatePct = drill.stats.attacks ? Math.round((drill.stats.blocked / drill.stats.attacks) * 100) : 0;
  return {
    id: id ?? `rpt-${Date.now().toString(36)}`,
    app: "WebGuard SOC Console",
    exportedAt: new Date().toISOString(),
    target,
    mode,
    scenario: {
      id: scenario.id,
      name: scenario.name,
      tagline: scenario.tagline,
      difficulty: scenario.difficulty,
      attackTypes: scenario.attackTypes.map((t) => ATTACK_LABELS[t]),
      totalSec: scenarioTotalSec(scenario),
    },
    outcome: final,
    startedAt: new Date(drill.startedAt).toISOString(),
    finishedAt: finishedTs ? new Date(finishedTs).toISOString() : null,
    durationSec: finishedTs ? Math.round((finishedTs - drill.startedAt) / 1000) : Math.round((Date.now() - drill.startedAt) / 1000),
    stats: { ...drill.stats },
    blockedRatePct,
    attackStopRatePct,
    rubric: {
      targetStopRate: drillTargetStopRate(scenario),
      targetBlockedRate: drillTargetBlockRate(scenario),
      achievedStopRate: attackStopRatePct,
      pass: attackStopRatePct >= drillTargetStopRate(scenario),
    },
    stages: scenario.stages.map((st, i) => ({
      idx: i + 1,
      label: st.label,
      desc: st.desc,
      durationSec: st.durationSec,
      attackType: st.attackType ? ATTACK_LABELS[st.attackType] : null,
      attackShare: st.attackShare,
      rate: st.rate,
      milestone: st.milestone ?? null,
      alarm: st.alarm ? st.alarm.title : null,
      incident: st.incident ? st.incident.title : null,
    })),
    events: drill.events.map((e) => ({
      t: `+${fmtSec((e.t - drill.startedAt) / 1000)}`,
      tone: e.tone,
      text: e.text,
    })),
    bans: bans.map((b) => ({
      ip: b.ip,
      reason: b.reason,
      source: b.source,
      country: b.country ?? "—",
      addedAt: new Date(b.addedAt).toISOString(),
      hits: b.hits,
    })),
  };
}

/** Renders a report as Markdown for download or viewing. */
export function drillReportMarkdown(r: DrillReport): string {
  const l: string[] = [];
  l.push("# WebGuard Attack Drill Report");
  l.push("");
  l.push(`**Scenario:** ${r.scenario.name}`);
  l.push(`**Difficulty:** ${r.scenario.difficulty} · **Planned:** ${fmtSec(r.scenario.totalSec)} · **Elapsed:** ${fmtSec(r.durationSec)}`);
  l.push(`**Outcome:** ${r.outcome.toUpperCase()} · **Firewall mode:** ${r.mode.toUpperCase()}`);
  l.push(`**Target:** ${r.target}`);
  l.push(`**Started:** ${new Date(r.startedAt).toLocaleString()}`);
  l.push(`**Finished:** ${r.finishedAt ? new Date(r.finishedAt).toLocaleString() : "—"}`);
  l.push("");
  l.push(`> ${r.scenario.tagline}`);
  l.push("");
  l.push("## Campaign summary");
  l.push("");
  l.push("| Metric | Value |");
  l.push("| --- | --- |");
  l.push(`| Requests | ${r.stats.requests.toLocaleString()} |`);
  l.push(`| Attacks classified | ${r.stats.attacks.toLocaleString()} |`);
  l.push(`| Blocked at edge | ${r.stats.blocked.toLocaleString()} (${r.blockedRatePct}% of all) |`);
  l.push(`| Attack stop rate | ${r.attackStopRatePct}% |`);
  l.push(`| Alarms raised | ${r.stats.alarms} |`);
  l.push(`| Incidents opened | ${r.stats.incidents} |`);
  l.push(`| Canary trips | ${r.stats.canaryTrips} |`);
  l.push(`| Edge bans added | ${r.stats.bans} |`);
  if (r.rubric) {
    l.push("");
    l.push("## Rubric & verdict");
    l.push("");
    l.push("| Criterion | Target | Achieved | Verdict |");
    l.push("| --- | --- | --- | --- |");
    l.push(`| Attack stop rate | ≥${r.rubric.targetStopRate}% | ${r.attackStopRatePct}% | ${r.rubric.pass ? "✅ PASS" : "❌ FAIL"} |`);
    l.push(`| Edge block rate | ≥${r.rubric.targetBlockedRate}% | ${r.blockedRatePct}% | — |`);
    l.push("");
    l.push(`**Verdict: ${r.rubric.pass ? "PASS" : "FAIL"}**`);
  }
  const mix = r.stats.attackMix ?? {};
  if (Object.keys(mix).length > 0) {
    l.push("");
    l.push("## Attack mix");
    l.push("");
    for (const [type, n] of Object.entries(mix).sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))) {
      l.push(`- ${ATTACK_LABELS[type as AttackType] ?? type}: ${n}`);
    }
  }
  l.push("");
  l.push("## Stage timeline");
  l.push("");
  for (const st of r.stages) {
    l.push(`### ${st.idx}. ${st.label} — ${fmtSec(st.durationSec)} (${st.attackType ?? "benign"} · ${Math.round(st.attackShare * 100)}% hostile @ ${st.rate} rps)`);
    l.push(st.desc);
    if (st.milestone) l.push(`- Milestone: ${st.milestone}`);
    if (st.alarm) l.push(`- Alarm raised: ${st.alarm}`);
    if (st.incident) l.push(`- Incident opened: ${st.incident}`);
    l.push("");
  }
  l.push("## Event feed");
  l.push("");
  for (const e of r.events) {
    l.push(`- [${e.t}] ${e.tone.toUpperCase()} — ${e.text}`);
  }
  l.push("");
  if (r.bans.length > 0) {
    l.push("## Blocked IPs added during the drill");
    l.push("");
    l.push("| IP | Source | Country | Hits | Reason |");
    l.push("| --- | --- | --- | --- | --- |");
    for (const b of r.bans) {
      l.push(`| ${b.ip} | ${b.source} | ${b.country} | ${b.hits} | ${b.reason} |`);
    }
    l.push("");
  }
  l.push("---");
  l.push(`Generated by WebGuard SOC Console · ${new Date(r.exportedAt).toLocaleString()}`);
  return l.join("\n");
}

// ============================================================================
// Scoring rubric — per-difficulty targets evaluated against every run
// ============================================================================

export function drillTargetStopRate(s: DrillScenario): number {
  return s.difficulty === "Basic" ? 90 : s.difficulty === "Moderate" ? 95 : 98;
}

export function drillTargetBlockRate(s: DrillScenario): number {
  return s.difficulty === "Basic" ? 95 : s.difficulty === "Moderate" ? 97 : 99;
}

/** True when a run met its attack-stop-rate target (the primary rubric criterion). */
export function drillVerdictPass(s: DrillScenario, attackStopRatePct: number): boolean {
  return attackStopRatePct >= drillTargetStopRate(s);
}

export function seedDrillReports(_now: number): DrillReport[] {
  return [];
}

