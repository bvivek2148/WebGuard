// ============================================================================
// WebGuard — shared type definitions for the WAF & SOC simulation
// ============================================================================

export type WafMode = "blocking" | "detection" | "off";
export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS";
export type AttackType =
  | "sqli"
  | "xss"
  | "cmdi"
  | "path-traversal"
  | "high-entropy"
  | "bot"
  | "scanner";
export type RuleAction = "block" | "challenge" | "log" | "disable";
export type Severity = "critical" | "high" | "medium" | "low";
export type AlarmState = "active" | "acknowledged" | "snoozed" | "resolved";

/** OWASP Top 10 (2021) categories the audit radar plots. */
export type OwaspAxis = "injection" | "access" | "crypto" | "misconfig" | "design";
export type IncidentStage = "investigating" | "mitigated" | "resolved";
export type PlaybookId = "quarantine" | "throttle" | "lockdown";

// ============================================================================
// Live-traffic filter state (shared between TrafficTab and the command palette)
// ============================================================================

export type TrafficVerdict = "all" | "benign" | "threat" | "blocked" | "throttled";

export interface TrafficFilters {
  query: string;
  status: number; // 0 = all statuses
  verdict: TrafficVerdict;
  method: "all" | HttpMethod;
  attack: "all" | AttackType;
}

export const DEFAULT_TRAFFIC_FILTERS: TrafficFilters = {
  query: "",
  status: 0,
  verdict: "all",
  method: "all",
  attack: "all",
};

export interface GeoPoint {
  lat: number;
  lon: number;
  city: string;
  country: string;
  code: string;
}

export interface AttackSpec {
  type: AttackType;
  label: string;
  severity: Severity;
  ruleId: string;
  method: HttpMethod;
  path: string;
  payload: string;
  match: string; // malicious substring used for highlighting
  entropyFloor: number;
  description: string;
}

export interface RequestLog {
  id: string;
  ts: number;
  status: number;
  method: HttpMethod;
  path: string;
  ip: string;
  countryCode: string;
  country: string;
  lat: number;
  lon: number;
  city: string;
  latency: number; // ms
  threatScore: number; // 0..100
  attackType: AttackType | null;
  ruleId: string | null;
  blocked: boolean;
  throttled: boolean;
  entropy: number; // bits / char
  ua: string;
  payload: string | null;
  matched: string | null;
  headers: Record<string, string>;
}

export interface SeriesPoint {
  t: number;
  label: string;
  rps: number;
  blocked: number;
  attacks: number;
}

export interface StressPoint {
  t: number;
  waf: number;
  app: number;
  lb: number;
  db: number;
}

export interface AuditFinding {
  id: string;
  pillar: string;
  title: string;
  severity: Severity;
  evidence: string;
  explanation: string;
  patch: string;
  patched: boolean;
  /** OWASP Top 10 axis this finding contributes to (set by the scanner). */
  axis?: OwaspAxis;
}

export interface ComparisonRow {
  control: string;
  before: string;
  after: string;
  fixed: boolean;
}

export interface RadarAxis {
  axis: string;
  value: number; // 0..100 threat density
}

export interface AuditState {
  status: "idle" | "running" | "done";
  progress: number; // 0..100 scan progress
  score: number; // posture score 0..100
  findings: AuditFinding[];
  comparison: ComparisonRow[];
  radar: RadarAxis[];
  verified: boolean; // re-scan completed with WAF active
  /** Unshielded posture score of the latest scan — drives the before/after copy. */
  baselineScore: number;
  /** Threat radar of the latest scan while unshielded (restored when WAF flips off). */
  baselineRadar: RadarAxis[];
  /** Diff from the most recent completed scan — what was newly registered. */
  lastDelta: { ts: number; added: number; known: number; newIds: string[] } | null;
}

export interface Alarm {
  id: string;
  severity: Severity;
  title: string;
  source: string;
  ts: number;
  state: AlarmState;
  detail: string;
  ruleId: string;
  /** Machine-readable source of the alarm — enables one-click block / incident triage. */
  sourceIp?: string;
  countryCode?: string;
}

export interface Incident {
  id: string;
  title: string;
  vector: string;
  severity: Severity;
  sourceIp: string;
  country: string;
  stage: IncidentStage;
  openedAt: number;
  closedAt: number | null; // set when the incident reaches “resolved”
  detail: string;
  playbook: PlaybookId | null;
}

export interface CanaryToken {
  id: string;
  key: string;
  placement: string;
  trips: number;
  lastIp: string | null;
  banned: boolean;
  createdAt: number;
}

export interface CanaryTrip {
  id: string;
  tokenId: string;
  ip: string;
  ts: number;
}

// ============================================================================
// Vulnerability / issue register — everything discovered lands here
// ============================================================================

export type FindingSource = "audit" | "live" | "canary" | "manual";
export type FindingStatus = "open" | "investigating" | "patched" | "fixed";

export interface VulnFinding {
  id: string;
  title: string;
  severity: Severity;
  source: FindingSource;
  status: FindingStatus;
  discoveredAt: number;
  lastSeen: number;
  count: number; // observed occurrences / attempts
  evidence: string;
  patch: string;
  ruleId: string | null;
  path: string | null;
  pillar: string | null; // audit pillar id when sourced from a scan
  /** Free-form triage notes — editable from the register. */
  notes?: string;
  /** Assignee / owner of the finding. */
  owner?: string;
  /** Free-form grouping tags. */
  tags?: string[];
}

// ============================================================================
// Access control — IP blocklist + custom edge rules
// ============================================================================

export type BanSource = "manual" | "auto" | "canary";

/**
 * Trusted sources — IPs / CIDRs that bypass all enforcement (allowlist).
 * Requests from allowlisted sources are always passed through untouched.
 */
export interface AllowedIp {
  id: string;
  ip: string; // exact IP or CIDR (e.g. 203.0.113.0/24)
  label: string; // e.g. "Office VPN", "CI runner"
  addedAt: number;
  hits: number; // requests that were allowed through
}

export interface BlockedIp {
  id: string;
  ip: string; // exact IP or CIDR (e.g. 91.134.22.0/24)
  reason: string;
  source: BanSource;
  country: string;
  countryCode: string;
  addedAt: number;
  hits: number;
  active: boolean;
  expiresAt: number | null;
}

export type CustomRuleMatch = "path" | "ip" | "country" | "ua" | "header";

export interface CustomRule {
  id: string;
  name: string;
  matchType: CustomRuleMatch;
  matchValue: string;
  action: RuleAction;
  enabled: boolean;
  hits: number;
}

export interface RuleSetting {
  id: string;
  label: string;
  ruleIds: string;
  action: RuleAction;
}

export interface Settings {
  sensitivity: number; // 0.50..0.99
  rateLimitRpm: number; // 10..1000
}

export interface Thresholds {
  fivexx: number; // % 5xx spike trigger
  ddos: number; // req/s burst trigger
  entropy: number; // bits/char anomaly trigger
}

export type TraceVerdict = "pass" | "block" | "throttle" | "info";

export interface TraceStep {
  stage: string;
  durationUs: number;
  verdict: TraceVerdict;
  detail: string;
}

export interface SandboxResult {
  id: string;
  ts: number;
  method: string;
  path: string;
  status: number;
  verdict: "ALLOWED" | "BLOCKED" | "THROTTLED";
  threatScore: number;
  matchedRule: string | null;
  entropy: number;
  latencyMs: number;
  payload: string;
  trace: TraceStep[];
  headers: Record<string, string>; // headers the request carried
}

/** A user-saved request template in the sandbox payload library. */
export interface SavedProbe {
  id: string;
  label: string;
  method: HttpMethod;
  path: string;
  payload: string;
}

export interface CopilotTriage {
  open: number;
  critical: number;
  high: number;
  items: Array<{ title: string; severity: Severity; patch: string; path: string | null }>;
}

export interface CopilotContext {
  kind: "log" | "incident" | "sandbox" | "triage";
  title: string;
  attackType: AttackType | null;
  ip: string;
  country: string;
  severity: Severity;
  payload: string;
  ruleId: string | null;
  threatScore: number;
  path: string;
  triage?: CopilotTriage;
}

export interface CopilotIntel {
  intent: string;
  attackBreakdown: string[];
  rootCause: string;
  postMortem: string;
  code: {
    language: string;
    label: string;
    snippet: string;
  }[];
}

export interface CopilotState {
  open: boolean;
  generating: boolean;
  context: CopilotContext | null;
}

export interface NodeHealth {
  id: string;
  label: string;
  sublabel: string;
  rps: number;
  heapMb: number;
  latencyMs: number;
  stress: number; // 0..1
}

// ============================================================================
// Scan history + alert integrations
// ============================================================================

export interface AuditHistoryEntry {
  id: string;
  ts: number;
  score: number;
  grade: string;
  shielded: boolean;
  findings: number;
  /** The target URL that was scanned in this run. */
  target: string;
  /** Full audit findings snapshot at scan completion. */
  auditFindings?: AuditFinding[];
  /** OWASP radar axes at scan completion. */
  auditRadar?: RadarAxis[];
  /** Before/after comparison matrix rows. */
  comparison?: ComparisonRow[];
  /** Unshielded baseline score when this scan ran. */
  baselineScore?: number;
  /** Threat radar axes when unshielded. */
  baselineRadar?: RadarAxis[];
  /** Scan statistics captured at completion. */
  scanStats?: { probes: number; endpoints: number; durationMs: number; confidence: number };
}

export type IntegrationId = "slack" | "pagerduty" | "email" | "webhook";

export interface IntegrationChannel {
  id: IntegrationId;
  label: string;
  hint: string;
  enabled: boolean;
  target: string;
  placeholder: string;
}

export interface DispatchEvent {
  id: string;
  channel: IntegrationId;
  event: string;
  ts: number;
  ok: boolean;
}

// ============================================================================
// OWASP / attack metadata (kept here to avoid circular imports)
// ============================================================================

export const ATTACK_LABELS: Record<AttackType, string> = {
  sqli: "SQL Injection",
  xss: "Cross-Site Scripting",
  cmdi: "Command Injection",
  "path-traversal": "Path Traversal",
  "high-entropy": "High-Entropy Payload",
  bot: "Bad Bot",
  scanner: "Recon Scanner",
};

export const SEVERITY_META: Record<
  Severity,
  { label: string; color: string; badge: string; glow: string }
> = {
  critical: {
    label: "CRITICAL",
    color: "#f43f5e",
    badge: "bg-wg-rose/15 text-wg-rose border-wg-rose/30",
    glow: "shadow-[0_0_18px_rgba(244,63,94,0.45)]",
  },
  high: {
    label: "HIGH",
    color: "#fb923c",
    badge: "bg-wg-orange/15 text-wg-orange border-wg-orange/30",
    glow: "shadow-[0_0_14px_rgba(251,146,60,0.35)]",
  },
  medium: {
    label: "MEDIUM",
    color: "#facc15",
    badge: "bg-wg-amber/15 text-wg-amber border-wg-amber/30",
    glow: "shadow-[0_0_12px_rgba(250,204,21,0.3)]",
  },
  low: {
    label: "LOW",
    color: "#38bdf8",
    badge: "bg-wg-sky/15 text-wg-sky border-wg-sky/30",
    glow: "shadow-[0_0_10px_rgba(56,189,248,0.25)]",
  },
};
