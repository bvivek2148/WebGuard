import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import type { Dispatch, ReactNode } from "react";
import { toast } from "sonner";
import {
  ATTACK_ORIGINS,
  ATTACK_SPEC_BY_TYPE,
  BASELINE_FINDINGS,
  BASELINE_RADAR,
  BENIGN_ORIGINS,
  CLEARED_RADAR,
  COMPARISON,
  EMPTY_RADAR,
  gradeForScore,
  SAFE_PATHS,
  SEED_RULES,
  USER_AGENTS,
  copilotIntel,
  originIp,
  pickAttackType,
  pickOrigin,
  seedAlarms,
  seedBlocklist,
  seedCanaries,
  seedCanaryTrips,
  seedFindings,
  seedIncidents,
  seedIntegrations,
  SEED_CUSTOM_RULES,
} from "./data";
import {
  DRILL_AUTO_ADVANCE_MS,
  DEFAULT_DRILL_SCHEDULE,
  buildDrillReport,
  drillScenarioById,
  emptyDrillStats,
  randomDrillScenarioId,
  scenarioTotalSec,
  seedDrillReports,
  stageIndexAt,
} from "./drills";
import type { DrillHistoryEntry, DrillReport, DrillSchedule, DrillState, QueuedDrill } from "./drills";
import type {
  Alarm,
  AlarmState,
  AllowedIp,
  AuditFinding,
  AuditHistoryEntry,
  AuditState,
  AttackSpec,
  AttackType,
  BlockedIp,
  CanaryToken,
  CanaryTrip,
  CopilotContext,
  CopilotState,
  CustomRule,
  DispatchEvent,
  FindingStatus,
  Incident,
  IncidentStage,
  IntegrationChannel,
  IntegrationId,
  PlaybookId,
  RequestLog,
  RuleAction,
  RadarAxis,
  RuleSetting,
  SandboxResult,
  SavedProbe,
  SeriesPoint,
  Settings,
  Severity,
  StressPoint,
  Thresholds,
  VulnFinding,
  WafMode,
} from "./types";
import { ATTACK_LABELS, SEVERITY_META } from "./types";

// ============================================================================
// Helpers
// ============================================================================

let idCounter = 0;
export function uid(prefix = "id"): string {
  idCounter += 1;
  const rnd = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${Date.now().toString(36)}-${rnd}-${idCounter}`;
}

export function rand(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

export function randInt(min: number, max: number): number {
  return Math.floor(rand(min, max + 1));
}

export function shannonEntropy(input: string): number {
  if (!input) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function fmtClock(ts: number): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

export function timeAgo(ts: number): string {
  const s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ${m % 60}m ago`;
}

export function greatCircle(
  from: { lat: number; lon: number },
  to: { lat: number; lon: number },
  steps = 48,
): Array<[number, number]> {
  const rad = Math.PI / 180;
  const lat1 = from.lat * rad;
  const lon1 = from.lon * rad;
  const lat2 = to.lat * rad;
  const lon2 = to.lon * rad;
  const dLat = lat2 - lat1;
  const dLon = lon2 - lon1;
  const sinDLat = Math.sin(dLat / 2);
  const sinDLon = Math.sin(dLon / 2);
  const a = sinDLat * sinDLat + Math.cos(lat1) * Math.cos(lat2) * sinDLon * sinDLon;
  const d = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const points: Array<[number, number]> = [];
  for (let i = 0; i <= steps; i++) {
    const f = i / steps;
    const A = Math.sin((1 - f) * d) / Math.max(Math.sin(d), 1e-9);
    const B = Math.sin(f * d) / Math.max(Math.sin(d), 1e-9);
    const x = A * Math.cos(lat1) * Math.cos(lon1) + B * Math.cos(lat2) * Math.cos(lon2);
    const y = A * Math.cos(lat1) * Math.sin(lon1) + B * Math.cos(lat2) * Math.sin(lon2);
    const z = A * Math.sin(lat1) + B * Math.sin(lat2);
    points.push([Math.atan2(z, Math.sqrt(x * x + y * y)) / rad, Math.atan2(y, x) / rad]);
  }
  return points;
}

// ============================================================================
// State
// ============================================================================

export interface WafState {
  generation: number; // bumped on RESET_STATE so effects can re-arm
  sessionStartedAt: number; // when this SOC session began (not persisted)
  mode: WafMode;
  target: string;
  seq: number;
  logs: RequestLog[];
  series: SeriesPoint[];
  totalRequests: number;
  totalBlocked: number;
  totalAttacks: number;
  bucket: { requests: number; blocked: number; attacks: number };
  latencyAccum: number;
  latencyCount: number;
  audit: AuditState;
  alarms: Alarm[];
  thresholds: Thresholds;
  incidents: Incident[];
  canaries: CanaryToken[];
  rules: RuleSetting[];
  settings: Settings;
  sandbox: SandboxResult[];
  auditHistory: AuditHistoryEntry[];
  integrations: IntegrationChannel[];
  dispatchLog: DispatchEvent[];
  copilot: CopilotState;
  stress: Record<string, number>;
  stressSeries: StressPoint[];
  underAttack: boolean;
  findings: VulnFinding[];
  blocklist: BlockedIp[];
  allowlist: AllowedIp[];
  customRules: CustomRule[];
  savedProbes: SavedProbe[];
  canaryTrips: CanaryTrip[];
  ipHits: Record<string, { n: number; last: number }>;
  banAutomation: { enabled: boolean; threshold: number; expireHours: number | null };
  geoBlock: string[];
  /** Rule suggested by the sandbox bypass sweep — shown as a pending draft in the Policy Engine */
  policySuggestion: CustomRule | null;
  /** Live attack drill (scripted scenario) — null when no drill is running */
  drill: DrillState | null;
  /** Completed drills kept for the Exercises history */
  drillHistory: DrillHistoryEntry[];
  /** Scenarios queued to auto-start when the current drill finishes (or when idle). */
  drillQueue: QueuedDrill[];
  /** When true, a completed drill automatically re-queues itself and repeats. */
  drillLoop: boolean;
  /** Repeating-cadence auto-run schedule. */
  schedule: DrillSchedule;
  /** Archived drill reports (built on completion/abort) — reopened from the console. */
  drillReports: DrillReport[];
}

export type WafAction =
  | { type: "RESET_STATE" }
  | { type: "RESTORE_STATE"; snapshot: Partial<PersistedState> }
  | { type: "SET_MODE"; mode: WafMode }
  | { type: "SET_TARGET"; target: string }
  | { type: "TICK" }
  | { type: "BUCKET" }
  | { type: "ADD_ALARM"; alarm: Alarm }
  | { type: "INJECT_LOG"; log: RequestLog }
  | { type: "START_AUDIT"; findings: AuditFinding[]; radar: RadarAxis[]; score: number }
  | { type: "AUDIT_PROGRESS"; delta: number }
  | { type: "ACK_ALARM"; id: string }
  | { type: "SNOOZE_ALARM"; id: string }
  | { type: "RESOLVE_ALARM"; id: string }
  | { type: "SET_THRESHOLD"; key: keyof Thresholds; value: number }
  | { type: "SET_RULE"; id: string; action: RuleAction }
  | { type: "SET_SETTING"; key: keyof Settings; value: number }
  | { type: "ADD_INCIDENT"; incident: Incident }
  | { type: "SET_INCIDENT_STAGE"; id: string; stage: IncidentStage }
  | { type: "RUN_PLAYBOOK"; id: string; playbook: PlaybookId }
  | { type: "TRIP_CANARY"; id: string; ip: string }
  | { type: "TOGGLE_CANARY"; id: string }
  | { type: "ADD_CANARY"; token: CanaryToken }
  | { type: "REMOVE_CANARY"; id: string }
  | { type: "ADD_SANDBOX"; result: SandboxResult }
  | { type: "CLEAR_SANDBOX" }
  | { type: "ADD_FINDING"; finding: VulnFinding }
  | { type: "REMOVE_FINDING"; id: string }
  | { type: "UPDATE_FINDING"; id: string; patch: Partial<Pick<VulnFinding, "title" | "severity" | "notes" | "owner" | "tags">> }
  | { type: "SET_FINDING_STATUS"; id: string; status: FindingStatus }
  | { type: "ADD_BLOCKED_IP"; entry: BlockedIp }
  | { type: "REMOVE_BLOCKED_IP"; id: string }
  | { type: "ADD_ALLOWED_IP"; entry: AllowedIp }
  | { type: "REMOVE_ALLOWED_IP"; id: string }
  | { type: "ADD_CUSTOM_RULE"; rule: CustomRule }
  | { type: "REMOVE_CUSTOM_RULE"; id: string }
  | { type: "ADD_SAVED_PROBE"; probe: SavedProbe }
  | { type: "REMOVE_SAVED_PROBE"; id: string }
  | { type: "TOGGLE_CUSTOM_RULE"; id: string }
  | { type: "SET_CUSTOM_RULE_ACTION"; id: string; action: RuleAction }
  | { type: "SUGGEST_CUSTOM_RULE"; rule: CustomRule }
  | { type: "CLEAR_POLICY_SUGGESTION" }
  | { type: "SET_BAN_AUTOMATION"; patch: Partial<{ enabled: boolean; threshold: number; expireHours: number | null }> }
  | { type: "TOGGLE_GEO_BLOCK"; code: string }
  | { type: "ACK_ALL_ALARMS" }
  | { type: "RESOLVE_ALL_ALARMS" }
  | { type: "SET_INTEGRATION_TARGET"; id: IntegrationId; target: string }
  | { type: "TOGGLE_INTEGRATION"; id: IntegrationId }
  | { type: "DISPATCH"; channel: IntegrationId; event: string }
  | { type: "OPEN_COPILOT"; context: CopilotContext }
  | { type: "CLOSE_COPILOT" }
  | { type: "COPILOT_DONE" }
  | { type: "START_DRILL"; scenarioId: string }
  | { type: "TOGGLE_DRILL_PAUSE" }
  | { type: "TOGGLE_DRILL_ISOLATION" }
  | { type: "QUEUE_DRILL"; scenarioId: string }
  | { type: "REMOVE_QUEUED_DRILL"; qid: string }
  | { type: "TOGGLE_DRILL_LOOP" }
  | { type: "SET_DRILL_SCHEDULE"; patch: Partial<DrillSchedule> }
  | { type: "STOP_DRILL" }
  | { type: "STOP_DRILL_AND_ARCHIVE" }
  | { type: "DISMISS_DRILL" }
  | { type: "DELETE_AUDIT_HISTORY"; id: string }
  | { type: "CLEAR_AUDIT_HISTORY" };

// ============================================================================
// Log synthesis
// ============================================================================

const SAFE_METHODS = ["GET", "GET", "GET", "POST", "PUT", "DELETE", "PATCH"] as const;

function ruleActionFor(state: { rules: RuleSetting[] }, type: AttackType): RuleAction {
  const mapId: Record<AttackType, string> = {
    sqli: "sqli",
    xss: "xss",
    cmdi: "cmdi",
    "path-traversal": "path-traversal",
    "high-entropy": "sqli", // entropy classifier is global; use default block unless disabled globally
    bot: "bots",
    scanner: "bots",
  };
  const rule = state.rules.find((r) => r.id === mapId[type]);
  return rule?.action ?? "block";
}

function synthesizeLog(ts: number, mode: WafMode, seq: number, overLimit: boolean): RequestLog {
  const isAttack = Math.random() < 0.24;
  let spec: AttackSpec | null = null;
  let origin;
  if (isAttack) {
    const type = pickAttackType();
    spec = ATTACK_SPEC_BY_TYPE[type];
    origin = pickOrigin(ATTACK_ORIGINS);
  } else {
    origin = pickOrigin(BENIGN_ORIGINS);
  }
  const ip = originIp(origin);
  const method = spec ? spec.method : (SAFE_METHODS[Math.floor(Math.random() * SAFE_METHODS.length)] as RequestLog["method"]);
  const path = spec ? spec.path : SAFE_PATHS[Math.floor(Math.random() * SAFE_PATHS.length)];
  const payload = spec ? spec.payload : Math.random() < 0.35 ? "q=" + Math.random().toString(36).slice(2, 10) : null;
  const entropy = payload ? shannonEntropy(payload) : rand(0.6, 2.4);
  const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  const attackAction = spec ? ruleActionFor({ rules: SEED_RULES_DEFAULT }, spec.type) : "block";
  // NOTE: rule gating is applied in the reducer with the real rules; here we only
  // synthesize the raw request. The reducer derives status/verdict.

  void attackAction;
  void overLimit;
  void seq;

  const threatScore = spec
    ? Math.min(99, Math.round(64 + entropy * 5.5 + rand(0, 8)))
    : Math.round(rand(0, 18));

  let status = 200;
  let blocked = false;
  let throttled = false;
  let latency: number;

  if (spec) {
    if (mode === "blocking") {
      blocked = true;
      status = 403;
      latency = rand(0.2, 1.4);
    } else if (mode === "detection") {
      status = 200;
      latency = rand(3, 26);
    } else {
      status = 200;
      latency = rand(2, 18);
    }
  } else {
    const r = Math.random();
    if (r < 0.012) {
      status = 500;
      latency = rand(60, 420);
    } else if (r < 0.03) {
      status = 404;
      latency = rand(0.8, 4.5);
    } else if (r < 0.05) {
      status = 301;
      latency = rand(0.4, 2.4);
    } else {
      // Edge-terminated requests ride the fast path: sub-3.5 ms
      status = 200;
      latency = rand(0.4, 3.4);
    }
    if (status === 429) throttled = true;
  }

  const headers: Record<string, string> = {
    Host: "shop.example.com",
    "User-Agent": ua,
    Accept: "*/*",
  };

  return {
    id: `req-${ts.toString(36)}-${seq}`,
    ts,
    status: throttled ? 429 : status,
    method,
    path,
    ip,
    countryCode: origin.geo.code,
    country: origin.geo.country,
    lat: origin.geo.lat,
    lon: origin.geo.lon,
    city: origin.geo.city,
    latency: Math.round(latency * 100) / 100,
    threatScore,
    attackType: spec ? spec.type : null,
    ruleId: spec ? (spec.type === "high-entropy" ? "ML-ENTROPY-001" : spec.ruleId) : null,
    blocked,
    throttled,
    entropy: Math.round(entropy * 100) / 100,
    ua,
    payload,
    matched: spec ? spec.match : null,
    headers,
  };
}

/**
 * Drill-mode log synthesis — same shape as synthesizeLog but with a forced
 * attack spec (or null for a benign request), so scripted stages can flood
 * the pipeline with a specific attack class at a controlled rate.
 */
function synthesizeDrillLog(
  ts: number,
  mode: WafMode,
  seq: number,
  spec: AttackSpec | null,
  pathPool?: string[],
): RequestLog {
  const origin = spec ? pickOrigin(ATTACK_ORIGINS) : pickOrigin(BENIGN_ORIGINS);
  const ip = originIp(origin);
  const method = spec ? spec.method : (SAFE_METHODS[Math.floor(Math.random() * SAFE_METHODS.length)] as RequestLog["method"]);
  const path =
    pathPool && pathPool.length > 0
      ? pathPool[Math.floor(Math.random() * pathPool.length)]
      : spec
        ? spec.path
        : SAFE_PATHS[Math.floor(Math.random() * SAFE_PATHS.length)];
  const payload = spec ? spec.payload : Math.random() < 0.35 ? "q=" + Math.random().toString(36).slice(2, 10) : null;
  const entropy = payload ? shannonEntropy(payload) : rand(0.6, 2.4);
  const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
  const threatScore = spec
    ? Math.min(99, Math.round(64 + entropy * 5.5 + rand(0, 8)))
    : Math.round(rand(0, 18));

  let status = 200;
  let blocked = false;
  const throttled = false;
  let latency: number;

  if (spec) {
    if (mode === "blocking") {
      blocked = true;
      status = 403;
      latency = rand(0.2, 1.4);
    } else if (mode === "detection") {
      status = 200;
      latency = rand(3, 26);
    } else {
      status = 200;
      latency = rand(2, 18);
    }
  } else {
    const r = Math.random();
    if (r < 0.012) {
      status = 500;
      latency = rand(60, 420);
    } else if (r < 0.03) {
      status = 404;
      latency = rand(0.8, 4.5);
    } else if (r < 0.05) {
      status = 301;
      latency = rand(0.4, 2.4);
    } else {
      status = 200;
      latency = rand(0.4, 3.4);
    }
  }

  const headers: Record<string, string> = {
    Host: "shop.example.com",
    "User-Agent": ua,
    Accept: "*/*",
  };

  return {
    id: `req-${ts.toString(36)}-${seq}`,
    ts,
    status: throttled ? 429 : status,
    method,
    path,
    ip,
    countryCode: origin.geo.code,
    country: origin.geo.country,
    lat: origin.geo.lat,
    lon: origin.geo.lon,
    city: origin.geo.city,
    latency: Math.round(latency * 100) / 100,
    threatScore,
    attackType: spec ? spec.type : null,
    ruleId: spec ? (spec.type === "high-entropy" ? "ML-ENTROPY-001" : spec.ruleId) : null,
    blocked,
    throttled,
    entropy: Math.round(entropy * 100) / 100,
    ua,
    payload,
    matched: spec ? spec.match : null,
    headers,
  };
}

// Placeholder rules used only during seed synthesis (never in live reducer).
const SEED_RULES_DEFAULT: RuleSetting[] = SEED_RULES;

// ============================================================================
// Access-control helpers
// ============================================================================

function subnetOf(ip: string): string {
  const parts = ip.split(".");
  return parts.length === 4 ? parts.slice(0, 3).join(".") : ip;
}

function ipMatches(entry: string, ip: string): boolean {
  if (entry.endsWith("/24")) return ip.startsWith(entry.replace("/24", ""));
  return entry === ip;
}

function matchesCustomRule(rule: CustomRule, log: RequestLog): boolean {
  const v = rule.matchValue.toLowerCase();
  switch (rule.matchType) {
    case "path":
      return log.path.toLowerCase().includes(v);
    case "ip":
      return ipMatches(rule.matchValue, log.ip);
    case "country":
      return log.countryCode.toLowerCase() === v;
    case "ua":
      return log.ua.toLowerCase().includes(v);
    case "header":
      return Object.values(log.headers).some((h) => h.toLowerCase().includes(v));
    default:
      return false;
  }
}

export const AUDIT_BASELINE_SCORE = 28;

/** Builds a fresh drill state (used by manual starts, the scheduler, and auto-advance). */
function makeDrill(scenarioId: string, startedAt: number, scheduled: boolean): DrillState {
  const scenario = drillScenarioById(scenarioId);
  const name = scenario?.name ?? scenarioId;
  return {
    scenarioId,
    startedAt,
    stageIdx: -1,
    paused: false,
    done: false,
    isolated: false,
    events: [
      { id: uid("DX"), t: startedAt, text: `${scheduled ? "Scheduled drill starting" : "Drill started"} — ${name}`, tone: "info" },
    ],
    stats: emptyDrillStats(),
    lastTickAt: startedAt,
  };
}

export function buildInitialState(): WafState {
  const now = Date.now();
  const logs: RequestLog[] = [];
  // ~70s of history so charts/map/stream are alive on first paint
  for (let i = 64; i >= 0; i--) {
    const ts = now - i * 1050;
    logs.push(synthesizeLog(ts, "off", 1000 - i, false));
  }
  const series: SeriesPoint[] = [];
  for (let i = 59; i >= 0; i--) {
    const bucketStart = now - i * 1000;
    const window = logs.filter((l) => l.ts >= bucketStart - 1000 && l.ts < bucketStart + 500);
    series.push({
      t: bucketStart,
      label: new Date(bucketStart).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }),
      rps: window.length,
      blocked: window.filter((l) => l.blocked).length,
      attacks: window.filter((l) => l.attackType).length,
    });
  }

  return {
    generation: 0,
    sessionStartedAt: now,
    mode: "off",
    target: "http://localhost:8080",
    seq: 2000,
    logs,
    series,
    totalRequests: logs.length + 214_800,
    totalBlocked: 12_441,
    totalAttacks: 34_872,
    bucket: { requests: 0, blocked: 0, attacks: 0 },
    latencyAccum: logs.reduce((s, l) => s + l.latency, 0),
    latencyCount: logs.length,
    audit: {
      status: "idle",
      progress: 0,
      score: 0,
      findings: BASELINE_FINDINGS,
      comparison: COMPARISON,
      radar: EMPTY_RADAR,
      verified: false,
      baselineScore: AUDIT_BASELINE_SCORE,
      baselineRadar: BASELINE_RADAR,
      lastDelta: null,
    },
    alarms: seedAlarms(now),
    thresholds: { fivexx: 15, ddos: 120, entropy: 4.2 },
    incidents: seedIncidents(now),
    canaries: seedCanaries(now),
    rules: SEED_RULES.map((r) => ({ ...r })),
    settings: { sensitivity: 0.85, rateLimitRpm: 600 },
    sandbox: [],
    copilot: { open: false, generating: false, context: null },
    drill: null,
    drillQueue: [],
    drillLoop: false,
    schedule: { ...DEFAULT_DRILL_SCHEDULE },
    drillReports: seedDrillReports(now),
    drillHistory: [
      {
        id: "DL-SEED-1",
        scenarioId: "recon-scout",
        startedAt: now - 7_200_000,
        finishedAt: now - 7_194_000,
        outcome: "completed" as const,
        stats: { requests: 238, blocked: 102, attacks: 131, alarms: 3, incidents: 0, canaryTrips: 2, bans: 4 },
      },
      {
        id: "DL-SEED-2",
        scenarioId: "cred-stuffing",
        startedAt: now - 28_800_000,
        finishedAt: now - 28_794_500,
        outcome: "completed" as const,
        stats: { requests: 402, blocked: 141, attacks: 214, alarms: 4, incidents: 1, canaryTrips: 0, bans: 6 },
      },
    ],
    stress: { clients: 0.15, "edge-dns": 0.12, lb: 0.3, waf: 0.4, app: 0.35, db: 0.22 },
    underAttack: true,
    findings: seedFindings(now),
    blocklist: seedBlocklist(now),
    allowlist: [
      {
        id: "ALW-SEED-1",
        ip: "203.0.113.0/24",
        label: "Office VPN",
        addedAt: now - 1_209_600_000,
        hits: 1_842,
      },
      {
        id: "ALW-SEED-2",
        ip: "10.20.0.0/16",
        label: "CI runner pool",
        addedAt: now - 604_800_000,
        hits: 9_214,
      },
    ],
    customRules: SEED_CUSTOM_RULES.map((r) => ({ ...r })),
    savedProbes: [
      {
        id: "SP-SEED-1",
        label: "SQLi tautology probe",
        method: "GET",
        path: "/api/search?id=1",
        payload: "id=1' OR 1=1--",
      },
      {
        id: "SP-SEED-2",
        label: "Encoded path traversal",
        method: "GET",
        path: "/api/download",
        payload: "file=..%2F..%2F..%2Fetc%2Fpasswd",
      },
    ],
    canaryTrips: seedCanaryTrips(now),
    ipHits: {},
    banAutomation: { enabled: true, threshold: 6, expireHours: null },
    geoBlock: [],
    policySuggestion: null,
    auditHistory: [
      {
        id: "AH-SEED",
        ts: now - 7_200_000,
        score: AUDIT_BASELINE_SCORE,
        grade: "F",
        shielded: false,
        findings: BASELINE_FINDINGS.length,
        target: "http://localhost:8080",
      },
    ],
    integrations: seedIntegrations(),
    stressSeries: [],
    dispatchLog: [
      {
        id: "DX-SEED",
        channel: "slack" as IntegrationId,
        event: "Critical alarm — SQLi burst on /api/search",
        ts: now - 600_000,
        ok: true,
      },
    ],
  };
}

// ============================================================================
// Local persistence — the console survives reloads so a demo can be resumed
// exactly where it was left off. Only durable control state is saved; the
// live log / chart streams are re-seeded fresh on every load.
// ============================================================================

const PERSIST_KEY = "webguard.soc.v1";

const PERSISTED_KEYS = [
  "mode",
  "target",
  "seq",
  "totalRequests",
  "totalBlocked",
  "totalAttacks",
  "audit",
  "auditHistory",
  "alarms",
  "thresholds",
  "incidents",
  "canaries",
  "canaryTrips",
  "rules",
  "settings",
  "sandbox",
  "findings",
  "blocklist",
  "allowlist",
  "customRules",
  "savedProbes",
  "geoBlock",
  "banAutomation",
  "policySuggestion",
  "integrations",
  "dispatchLog",
  "drillHistory",
  "drillQueue",
  "drillLoop",
  "schedule",
  "drillReports",
] as const;

export type PersistedState = Pick<WafState, (typeof PERSISTED_KEYS)[number]>;

function pickPersisted(state: WafState): PersistedState {
  const out = {} as PersistedState;
  for (const key of PERSISTED_KEYS) (out as Record<string, unknown>)[key] = state[key];
  return out;
}

/** Durable subset of the console state — used for the JSON export/snapshot feature. */
export function serializePersistedState(state: WafState): PersistedState {
  return pickPersisted(state);
}

/** Write an imported snapshot straight into localStorage so a reload keeps it. */
export function persistSnapshot(snapshot: PersistedState): void {
  try {
    localStorage.setItem(PERSIST_KEY, JSON.stringify({ v: 1, savedAt: Date.now(), state: snapshot }));
  } catch {
    /* ignore */
  }
}

function saveState(state: WafState): void {
  try {
    localStorage.setItem(PERSIST_KEY, JSON.stringify({ v: 1, savedAt: Date.now(), state: pickPersisted(state) }));
  } catch {
    /* storage unavailable (private mode / quota) — the console just won't persist */
  }
}

export function clearSavedState(): void {
  try {
    localStorage.removeItem(PERSIST_KEY);
  } catch {
    /* ignore */
  }
}

function loadInitialState(): WafState {
  const base = buildInitialState();
  try {
    const raw = localStorage.getItem(PERSIST_KEY);
    if (!raw) return base;
    const parsed = JSON.parse(raw) as { v?: number; state?: Partial<PersistedState> };
    if (parsed?.v !== 1 || !parsed.state) return base;
    const saved = parsed.state;
    const merged: WafState = { ...base, ...saved };
    // Deep-merge audit so stale snapshots missing nested fields (radar, comparison, etc.) don't produce undefined.
    if (saved.audit) {
      merged.audit = { ...base.audit, ...saved.audit };
    }
    // Guard the persisted audit so a stale mid-run scan can never wedge the UI.
    if (merged.audit?.status === "running") merged.audit = { ...merged.audit, status: "done" };
    return merged;
  } catch {
    return base;
  }
}

// ============================================================================
// Reducer
// ============================================================================

function computeStress(logs: RequestLog[]): { stress: Record<string, number>; underAttack: boolean } {
  const now = Date.now();
  let reqs = 0;
  let attacks = 0;
  let blocked = 0;
  for (const l of logs) {
    if (now - l.ts <= 12_000) {
      reqs++;
      if (l.attackType) attacks++;
      if (l.blocked) blocked++;
    }
  }
  const rps = reqs / 12;
  return {
    stress: {
      clients: 0.12 + Math.min(0.3, rps / 200),
      "edge-dns": 0.1 + Math.min(0.25, rps / 300),
      lb: Math.min(1, 0.22 + rps / 90),
      waf: Math.min(1, 0.3 + attacks / 3.5),
      app: Math.min(1, 0.25 + blocked / 3),
      db: 0.18 + Math.min(0.4, attacks / 12),
    },
    underAttack: attacks > 0,
  };
}

export function reducer(state: WafState, action: WafAction): WafState {
  switch (action.type) {
    case "RESET_STATE": {
      const fresh = buildInitialState();
      return { ...fresh, generation: state.generation + 1, sessionStartedAt: Date.now() };
    }

    case "RESTORE_STATE": {
      // Merge the imported snapshot over a fresh baseline — missing keys keep
      // their defaults, and a mid-run audit can never wedge the UI.
      const merged: WafState = { ...buildInitialState(), ...action.snapshot, generation: state.generation + 1 };
      if (merged.audit?.status === "running") merged.audit = { ...merged.audit, status: "done" };
      return merged;
    }

    case "SET_MODE": {
      const mode = action.mode;
      let audit = state.audit;
      let findings = state.findings;
      if (audit.status === "done") {
        const shielded = mode === "blocking";
        audit = {
          ...audit,
          score: shielded ? 100 : audit.baselineScore,
          findings: audit.findings.map((f) => ({ ...f, patched: shielded })),
          radar: shielded ? CLEARED_RADAR : audit.baselineRadar,
          verified: shielded,
        };
        // Mirror the posture change into the vulnerability register.
        findings = findings.map((f) =>
          f.source === "audit"
            ? { ...f, status: shielded ? ("patched" as FindingStatus) : ("open" as FindingStatus) }
            : f,
        );
      }
      return { ...state, mode, audit, findings };
    }

    case "SET_TARGET":
      return { ...state, target: action.target };

    case "SET_DRILL_SCHEDULE": {
      const enabled = action.patch.enabled ?? state.schedule.enabled;
      const nextRunAt =
        action.patch.nextRunAt !== undefined
          ? action.patch.nextRunAt
          : state.schedule.nextRunAt;
      return {
        ...state,
        schedule: {
          ...state.schedule,
          ...action.patch,
          // Enabling without a run time schedules the first run immediately.
          nextRunAt: enabled && nextRunAt === null ? Date.now() : nextRunAt,
        },
      };
    }

    case "STOP_DRILL_AND_ARCHIVE": {
      const drill = state.drill;
      if (!drill || drill.done) return { ...state, drill: null };
      const entry: DrillHistoryEntry = {
        id: uid("DL"),
        scenarioId: drill.scenarioId,
        startedAt: drill.startedAt,
        finishedAt: Date.now(),
        outcome: "aborted",
        stats: drill.stats,
      };
      const abortedScenario = drillScenarioById(drill.scenarioId);
      const abortedReport = abortedScenario
        ? buildDrillReport(
            abortedScenario,
            drill,
            state.blocklist.filter((b) => b.addedAt >= drill.startedAt),
            state.mode,
            state.target,
            "aborted",
          )
        : null;
      return {
        ...state,
        drill: null,
        drillHistory: [entry, ...state.drillHistory].slice(0, 20),
        drillReports: abortedReport
          ? [abortedReport, ...state.drillReports].slice(0, 15)
          : state.drillReports,
      };
    }

    case "TICK": {
      const seq = state.seq + 1;
      const nowTs = Date.now();

      // ====================================================================
      // Drill orchestration — when a drill is active it takes over request
      // generation and stages a scripted attack scenario through the real
      // enforcement pipeline below.
      // ====================================================================
      let drill = state.drill;
      let drillQueue = state.drillQueue;
      const drillLoop = state.drillLoop;
      let schedule = state.schedule;
      let drillReports = state.drillReports;
      let drillHistory = state.drillHistory;
      const raws: RequestLog[] = [];
      // Drill stage milestones can raise alarms/incidents — declared once at the
      // case level so the enforcement pipeline below builds on them instead of
      // shadowing and dropping them.
      let alarms = state.alarms;
      let incidents = state.incidents;
      let drillStats = drill ? { ...drill.stats } : null;
      let finalizeHistory: Omit<DrillHistoryEntry, "stats"> | null = null;

      if (drill) {
        const scenario = drillScenarioById(drill.scenarioId);
        if (!scenario) {
          drill = null;
        } else if (drill.done) {
          // Results screen — auto-advance to the next queued/looped/scheduled
          // drill after a short window so the operator can read the summary.
          const scheduleDue =
            schedule.enabled && schedule.nextRunAt !== null && nowTs >= schedule.nextRunAt;
          if (
            (drillQueue.length > 0 || drillLoop || scheduleDue) &&
            nowTs - (drill.doneAt ?? drill.lastTickAt) >= DRILL_AUTO_ADVANCE_MS
          ) {
            let nextId: string | null = null;
            if (drillQueue.length > 0) {
              nextId = drillQueue[0].scenarioId;
              drillQueue = drillQueue.slice(1);
            } else if (drillLoop) {
              nextId = scenario.id;
            } else if (scheduleDue) {
              nextId =
                schedule.scenarioId === "random" ? randomDrillScenarioId() : schedule.scenarioId;
              schedule = {
                ...schedule,
                nextRunAt: nowTs + schedule.intervalMin * 60_000,
              };
            }
            if (nextId) {
              drill = makeDrill(nextId, nowTs, true);
              drillStats = { ...drill.stats };
              // One benign request bridges the transition; the new drill's own
              // stage traffic starts on the next tick.
              raws.push(synthesizeDrillLog(nowTs, state.mode, seq, null));
            }
          } else {
            // Finished — keep the stream alive with benign baseline only.
            raws.push(synthesizeDrillLog(nowTs, state.mode, seq, null));
          }
        } else if (drill.paused) {
          // Paused — keep the stream alive with benign baseline only.
          raws.push(synthesizeDrillLog(nowTs, state.mode, seq, null));
        } else {
          const totalSec = scenarioTotalSec(scenario);
          const elapsedSec = (nowTs - drill.startedAt) / 1000;
          const stageIdx = stageIndexAt(scenario, elapsedSec);
          const stage = scenario.stages[stageIdx];

          // ---- stage transitions: milestone events + staged alarms/incidents ----
          if (stageIdx !== drill.stageIdx) {
            const events = [...drill.events];
            if (stage.milestone) {
              events.push({ id: uid("DX"), t: nowTs, text: stage.milestone, tone: "info" });
            }
            if (stage.alarm) {
              alarms = [
                {
                  id: uid("AL"),
                  severity: stage.alarm.severity,
                  title: stage.alarm.title,
                  source: `drill · ${scenario.name} · ${stage.label}`,
                  ts: nowTs,
                  detail: `Stage '${stage.label}' of drill '${scenario.name}' triggered the signature engine. ${
                    state.mode === "blocking" ? "Dropped with 403 before reaching origin." : "Logged — flip the firewall to BLOCKING to enforce."
                  }`,
                  ruleId: stage.attackType ? (ATTACK_SPEC_BY_TYPE[stage.attackType]?.ruleId ?? "-") : "-",
                  sourceIp: "drill",
                  countryCode: "—",
                  state: "active" as const,
                },
                ...alarms,
              ].slice(0, 40);
              events.push({ id: uid("DX"), t: nowTs, text: `Alarm raised — ${stage.alarm.title}`, tone: "alarm" });
              if (drillStats) drillStats = { ...drillStats, alarms: drillStats.alarms + 1 };
            }
            if (stage.incident) {
              incidents = [
                {
                  id: uid("INC"),
                  title: stage.incident.title,
                  vector: stage.attackType ? ATTACK_LABELS[stage.attackType] : "Drill scenario",
                  severity: stage.incident.severity,
                  sourceIp: "drill",
                  country: "—",
                  stage: "investigating" as const,
                  openedAt: nowTs,
                  closedAt: null,
                  detail: `Opened by drill '${scenario.name}' at stage '${stage.label}'. ${
                    state.mode === "blocking" ? "Edge enforcement active — attacks dropped with 403." : "Edge not blocking — recommend switching to BLOCKING."
                  }`,
                  playbook: null,
                },
                ...incidents,
              ].slice(0, 24);
              events.push({ id: uid("DX"), t: nowTs, text: `Incident opened — ${stage.incident.title}`, tone: "incident" });
              if (drillStats) drillStats = { ...drillStats, incidents: drillStats.incidents + 1 };
            }
            events.push({
              id: uid("DX"),
              t: nowTs,
              text: `Stage ${stageIdx + 1}/${scenario.stages.length} — ${stage.label}`,
              tone: "info",
            });
            drill = { ...drill, stageIdx, events };
          }

          if (elapsedSec >= totalSec) {
            // Scenario complete — finalize results and keep them on screen.
            drill = {
              ...drill,
              done: true,
              doneAt: nowTs,
              events: [
                ...drill.events,
                { id: uid("DX"), t: nowTs, text: `Drill complete — ${scenario.name} finished`, tone: "done" },
              ],
            };
            finalizeHistory = {
              id: uid("DL"),
              scenarioId: scenario.id,
              startedAt: drill.startedAt,
              finishedAt: nowTs,
              outcome: "completed",
            };
            raws.push(synthesizeDrillLog(nowTs, state.mode, seq, null));
          } else {
            // Emit this stage's traffic — `rate` is per second, we tick ~3×/s.
            // Isolation forces the full share to attacks (pure campaign, no
            // benign blend) so the drill reads as an unambiguous attack test.
            const perTick = Math.max(1, Math.round(stage.rate / 3));
            for (let i = 0; i < perTick; i++) {
              const isAttack =
                stage.attackType !== null && (drill.isolated || Math.random() < stage.attackShare);
              const spec = isAttack ? ATTACK_SPEC_BY_TYPE[stage.attackType!] : null;
              raws.push(synthesizeDrillLog(nowTs, state.mode, seq + i, spec, stage.pathPool));
            }
          }
        }
      } else if (drillQueue.length > 0) {
        // Scheduler: the console is idle and scenarios are queued — auto-start
        // the head of the queue so scheduled campaigns run unattended.
        const next = drillQueue[0];
        drillQueue = drillQueue.slice(1);
        drill = makeDrill(next.scenarioId, nowTs, true);
        drillStats = { ...drill.stats };
        raws.push(synthesizeDrillLog(nowTs, state.mode, seq, null));
      } else if (schedule.enabled && schedule.nextRunAt !== null && nowTs >= schedule.nextRunAt) {
        // Repeating cadence: the console is idle and the next auto-run is due.
        const scenarioId =
          schedule.scenarioId === "random" ? randomDrillScenarioId() : schedule.scenarioId;
        // Always bump the schedule so a bad scenario id can never hot-loop.
        schedule = { ...schedule, nextRunAt: nowTs + schedule.intervalMin * 60_000 };
        if (drillScenarioById(scenarioId)) {
          drill = makeDrill(scenarioId, nowTs, true);
          drillStats = { ...drill.stats };
          raws.push(synthesizeDrillLog(nowTs, state.mode, seq, null));
        }
      } else {
        const overLimit = state.bucket.requests >= Math.max(1, Math.round(state.settings.rateLimitRpm / 60));
        raws.push(synthesizeLog(nowTs, state.mode, seq, overLimit));
      }

      // ====================================================================
      // Per-request enforcement pipeline — every generated request (normal or
      // drill) runs the full chain: allowlist, custom rules, geo, blocklist,
      // verdict, rate limiting, auto-ban, findings, alarms, incidents, canaries.
      // ====================================================================
      let log = raws[0] ?? synthesizeLog(nowTs, state.mode, seq, false);
      let logs = state.logs;
      let customRules = state.customRules;
      let blocklist = state.blocklist;
      // Expire temporary bans (e.g. 24h manual bans) that have run out.
      if (blocklist.some((b) => b.active && b.expiresAt && b.expiresAt < nowTs)) {
        blocklist = blocklist.map((b) =>
          b.active && b.expiresAt && b.expiresAt < nowTs ? { ...b, active: false } : b,
        );
      }
      let findings = state.findings;
      let ipHits = state.ipHits;
      let canaryTrips = state.canaryTrips;
      let allowlist = state.allowlist;
      let canaries = state.canaries;
      let totalAttacks = state.totalAttacks;
      let totalBlocked = state.totalBlocked;
      let bucket = { ...state.bucket };
      let latencyAccum = state.latencyAccum;
      let latencyCount = state.latencyCount;
      let totalRequests = state.totalRequests;

      for (const raw of raws) {
        log = raw;
        const bansBefore = blocklist.length;

        // ---- allowlist (trusted sources bypass ALL enforcement) ----
        const trusted = allowlist.find((a) => ipMatches(a.ip, raw.ip));
      const allowlisted = trusted !== undefined && state.mode !== "off";
      if (allowlisted) {
        allowlist = allowlist.map((a) => (a.id === trusted.id ? { ...a, hits: a.hits + 1 } : a));
        log = {
          ...raw,
          status: 200,
          blocked: false,
          throttled: false,
          latency: rand(0.4, 3.2),
          attackType: null,
          ruleId: "ALLOWLIST",
          matched: null,
          threatScore: 0,
        };
      }

      // ---- custom edge rules (path / IP / country / UA / header) ----
      if (!allowlisted) {
        for (const rule of customRules) {
          if (!rule.enabled || !matchesCustomRule(rule, raw)) continue;
          customRules = customRules.map((r) => (r.id === rule.id ? { ...r, hits: r.hits + 1 } : r));
          if (state.mode === "blocking" && (rule.action === "block" || rule.action === "challenge")) {
            log = { ...log, status: 403, blocked: true, latency: rand(0.2, 1.2), ruleId: rule.id };
          }
        }
      }

      // ---- geo-blocking (country deny-list) ----
      if (!allowlisted && state.mode !== "off" && state.geoBlock.includes(raw.countryCode) && !log.blocked) {
        log = { ...log, status: 403, blocked: true, latency: rand(0.2, 1.0), ruleId: "GEO-BLOCK" };
      }

      // ---- IP blocklist enforcement ----
      const ban = allowlisted ? undefined : blocklist.find((b) => b.active && ipMatches(b.ip, raw.ip));
      if (ban && state.mode === "blocking" && !log.blocked) {
        log = { ...log, status: 403, blocked: true, latency: rand(0.2, 1.0), ruleId: "IP-BLOCKLIST" };
        blocklist = blocklist.map((b) => (b.id === ban.id ? { ...b, hits: b.hits + 1 } : b));
      }

      // ---- apply live WAF verdict (uses the *real* rules) ----
      if (raw.attackType && !allowlisted) {
        const actionType = ruleActionFor(state, raw.attackType);
        if (actionType === "disable") {
          log = { ...raw, status: 200, blocked: false, ruleId: null };
        } else if (actionType === "log") {
          log = { ...raw, status: 200, blocked: false };
        } else {
          // block | challenge
          if (state.mode === "blocking") {
            log = { ...raw, status: 403, blocked: true, latency: rand(0.2, 1.4) };
          } else if (state.mode === "detection") {
            log = { ...raw, status: 200, blocked: false };
          } else {
            log = { ...raw, status: 200, blocked: false };
          }
        }
      }

      // ---- rate limiting ----
      let throttled = false;
      if (state.mode !== "off" && !allowlisted && state.bucket.requests >= Math.max(1, Math.round(state.settings.rateLimitRpm / 60))) {
        throttled = true;
      }
      if (throttled && !(log.attackType === "bot")) {
        log = { ...log, status: 429, throttled: true, blocked: false, latency: rand(0.1, 0.6) };
      }

      // ---- per-IP hit tracking → auto-ban hostile /24s ----
      if (log.blocked && state.banAutomation.enabled) {
        const subnet = subnetOf(log.ip);
        const prev = ipHits[subnet] ?? { n: 0, last: 0 };
        ipHits = { ...ipHits, [subnet]: { n: prev.n + 1, last: log.ts } };
        if (prev.n + 1 >= state.banAutomation.threshold && !blocklist.some((b) => b.ip === `${subnet}.0/24`)) {
          const expireMs = state.banAutomation.expireHours ? Date.now() + state.banAutomation.expireHours * 3_600_000 : null;
          blocklist = [
            {
              id: uid("BAN"),
              ip: `${subnet}.0/24`,
              reason: `Auto-ban — ${prev.n + 1}+ blocked requests from subnet (threshold ${state.banAutomation.threshold})`,
              source: "auto" as const,
              country: log.country,
              countryCode: log.countryCode,
              addedAt: log.ts,
              hits: 0,
              active: true,
              expiresAt: expireMs,
            },
            ...blocklist,
          ].slice(0, 80);
          ipHits = { ...ipHits, [subnet]: { n: 0, last: log.ts } };
        }
      }

      // ---- live threat observations → vulnerability register ----
      if (log.attackType && log.ruleId) {
        const key = `live:${log.ruleId}:${log.path}`;
        const existing = findings.find((f) => f.id === key);
        if (existing) {
          findings = findings.map((f) =>
            f.id === key ? { ...f, count: f.count + 1, lastSeen: log.ts } : f,
          );
        } else {
          const spec = ATTACK_SPEC_BY_TYPE[log.attackType];
          findings = [
            {
              id: key,
              title: `${ATTACK_LABELS[log.attackType]} against ${log.path}`,
              severity: spec.severity,
              source: "live" as const,
              status: "open" as const,
              discoveredAt: log.ts,
              lastSeen: log.ts,
              count: 1,
              evidence: `${log.method} ${log.path}\nrule ${log.ruleId} · ${log.ip} (${log.country}) · entropy ${log.entropy.toFixed(2)} bits/char\nverdict: ${log.blocked ? "403 BLOCKED at edge" : "logged (not blocked)"}`,
              patch: `Enforce ${spec.ruleId} at the edge · reject payload pattern '${spec.match}'${spec.type === "bot" || spec.type === "scanner" ? " · CAPTCHA automated clients" : ""}`,
              ruleId: log.ruleId,
              path: log.path,
              pillar: null,
            },
            ...findings,
          ].slice(0, 80);
        }
      }

      if (log.attackType && state.mode !== "off") {
        totalAttacks += 1;
        const sev = ATTACK_SPEC_BY_TYPE[log.attackType].severity;
        const chance =
          sev === "critical" ? 1 : sev === "high" ? 0.45 : sev === "medium" ? 0.18 : 0.08;
        if (Math.random() < chance && alarms.length < 40) {
          const label = ATTACK_LABELS[log.attackType];
          const alarm: Alarm = {
            id: uid("AL"),
            severity: sev,
            title: `${label} — ${log.path}`,
            source: `${log.ip} · ${log.city}`,
            ts: log.ts,
            state: "active",
            detail: `Rule ${log.ruleId} matched ${label.toLowerCase()} traffic. ${
              log.blocked ? "Dropped with 403 before reaching origin." : "Logged — origin processed the request."
            }`,
            ruleId: log.ruleId ?? "-",
            sourceIp: log.ip,
            countryCode: log.countryCode,
          };
          alarms = [alarm, ...alarms].slice(0, 40);
          if (drillStats) drillStats = { ...drillStats, alarms: drillStats.alarms + 1 };
        }
        // new incidents occasionally
        if (Math.random() < 0.028 && incidents.length < 24) {
          const label = ATTACK_LABELS[log.attackType];
          incidents = [
            {
              id: uid("INC"),
              title: `${label} burst from ${log.ip}`,
              vector: label,
              severity: ATTACK_SPEC_BY_TYPE[log.attackType].severity,
              sourceIp: log.ip,
              country: log.countryCode,
              stage: "investigating",
              openedAt: log.ts,
              closedAt: null,
              detail: `${label.toLowerCase()} traffic observed against ${log.path}. ${log.blocked ? "All attempts blocked at the edge." : "Observed in log-only mode — origin exposed."}`,
              playbook: null,
            },
            ...incidents,
          ];
          if (drillStats) drillStats = { ...drillStats, incidents: drillStats.incidents + 1 };
        }
        // canary trips → auto-ban the offender on the 3rd trip
        const canaryTarget = canaries.find((c) => !c.banned);
        if (Math.random() < 0.05 && canaryTarget) {
          const trips = canaryTarget.trips + 1;
          canaries = canaries.map((c) =>
            c.id === canaryTarget.id ? { ...c, trips, lastIp: log.ip, banned: trips >= 3 } : c,
          );
          canaryTrips = [
            { id: uid("CT"), tokenId: canaryTarget.id, ip: log.ip, ts: log.ts },
            ...canaryTrips,
          ].slice(0, 40);
          if (drillStats) drillStats = { ...drillStats, canaryTrips: drillStats.canaryTrips + 1 };

          if (trips >= 3 && !blocklist.some((b) => b.ip === log.ip)) {
            blocklist = [
              {
              id: uid("BAN"),
              ip: log.ip,
              reason: `Canary tripped ×3 — ${canaryTarget.placement}`,
              source: "canary" as const,
              country: log.country,
              countryCode: log.countryCode,
              addedAt: log.ts,
              hits: 0,
              active: true,
              expiresAt: null,
            },
            ...blocklist,
          ].slice(0, 80);
          }
        }
      }
      if (log.blocked) totalBlocked += 1;

      // Drill counters — accumulated across every request this tick.
      if (drillStats) {
        const mix = { ...(drillStats.attackMix ?? {}) };
        if (log.attackType) mix[log.attackType] = (mix[log.attackType] ?? 0) + 1;
        drillStats = {
          ...drillStats,
          requests: drillStats.requests + 1,
          attacks: drillStats.attacks + (log.attackType ? 1 : 0),
          blocked: drillStats.blocked + (log.blocked ? 1 : 0),
          bans: drillStats.bans + Math.max(0, blocklist.length - bansBefore),
          attackMix: mix,
        };
      }

      logs = [log, ...logs].slice(0, 240);
      bucket = {
        requests: bucket.requests + 1,
        blocked: bucket.blocked + (log.blocked ? 1 : 0),
        attacks: bucket.attacks + (log.attackType ? 1 : 0),
      };
      latencyAccum += log.latency;
      latencyCount += 1;
      totalRequests += 1;
      } // end per-request loop

      const { stress, underAttack } = computeStress(logs);

      if (finalizeHistory && drill) {
        drillHistory = [
          { ...finalizeHistory, stats: drillStats ?? emptyDrillStats() },
          ...state.drillHistory,
        ].slice(0, 20);
        // Archive a structured report for the console's report gallery.
        const completedScenario = drillScenarioById(drill.scenarioId);
        if (completedScenario) {
          drillReports = [
            buildDrillReport(
              completedScenario,
              drill,
              blocklist.filter((b) => b.addedAt >= drill.startedAt),
              state.mode,
              state.target,
              "completed",
            ),
            ...state.drillReports,
          ].slice(0, 15);
        }
      }

      return {
        ...state,
        seq: seq + raws.length - 1,
        drill: drill ? { ...drill, stats: drillStats ?? drill.stats, lastTickAt: nowTs } : null,
        drillQueue,
        schedule,
        drillReports,
        drillHistory,
        logs,
        alarms,
        incidents,
        canaries,
        totalRequests,
        totalBlocked,
        totalAttacks,
        bucket,
        latencyAccum,
        latencyCount,
        stress,
        underAttack,
        customRules,
        blocklist,
        allowlist,
        findings,
        ipHits,
        canaryTrips,
      };
    }

    case "BUCKET": {
      const point: SeriesPoint = {
        t: Date.now(),
        label: new Date().toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }),
        rps: state.bucket.requests,
        blocked: state.bucket.blocked,
        attacks: state.bucket.attacks,
      };
      const stressPoint: StressPoint = {
        t: Date.now(),
        waf: state.stress.waf,
        app: state.stress.app,
        lb: state.stress.lb,
        db: state.stress.db,
      };
      return {
        ...state,
        series: [...state.series, point].slice(-70),
        stressSeries: [...state.stressSeries, stressPoint].slice(-60),
        bucket: { requests: 0, blocked: 0, attacks: 0 },
      };
    }

    case "ADD_ALARM":
      return { ...state, alarms: [action.alarm, ...state.alarms].slice(0, 40) };

    case "INJECT_LOG":
      return {
        ...state,
        logs: [action.log, ...state.logs].slice(0, 240),
        totalRequests: state.totalRequests + 1,
        totalBlocked: state.totalBlocked + (action.log.blocked ? 1 : 0),
        totalAttacks: state.totalAttacks + (action.log.attackType ? 1 : 0),
      };

    case "START_AUDIT":
      // The scan's findings/radar/score are generated at dispatch time (seeded
      // by target + run nonce) and stashed here so the animated progress and the
      // completed result always describe the same scan. baseline* keeps the
      // unshielded posture so toggling the firewall off restores it exactly.
      return {
        ...state,
        audit: {
          ...state.audit,
          status: "running",
          progress: 0,
          score: 0,
          verified: false,
          findings: action.findings.map((f) => ({ ...f, patched: false })),
          radar: action.radar,
          baselineScore: action.score,
          baselineRadar: action.radar,
          lastDelta: null,
        },
      };

    case "AUDIT_PROGRESS": {
      if (state.audit.status !== "running") return state;
      const progress = Math.min(100, state.audit.progress + action.delta);
      if (progress >= 100) {
        const shielded = state.mode === "blocking";
        // Every scan result lands in the vulnerability register (deduped by id).
        // Count how many of these ids were NOT already tracked → the dynamic
        // "newly discovered" delta surfaced in the UI after every scan.
        const knownIds = new Set(state.findings.map((f) => f.id));
        const auditEntries: VulnFinding[] = state.audit.findings.map((f) => ({
          id: `audit:${f.id}`,
          title: f.title,
          severity: f.severity,
          source: "audit",
          status: (shielded ? "patched" : "open") as FindingStatus,
          discoveredAt: Date.now(),
          lastSeen: Date.now(),
          count: 1,
          evidence: f.evidence,
          patch: f.patch,
          ruleId: f.id,
          path: null,
          pillar: f.pillar,
        }));
        const newIds = auditEntries.filter((f) => !knownIds.has(f.id)).map((f) => f.id.replace("audit:", ""));
        const findings = [
          ...auditEntries,
          ...state.findings.filter((f) => !f.id.startsWith("audit:")),
        ].slice(0, 80);
        const score = shielded ? 100 : state.audit.baselineScore;
        const probes = state.audit.findings.length * 47 + 312;
        const endpoints = 18 + (state.audit.findings.length % 7);
        const durationMs = 1860 + ((state.audit.findings.length * 53) % 240);
        const confidence = Math.max(96, 99.2 - state.audit.findings.length * 0.08);
        const entry: AuditHistoryEntry = {
          id: uid("AH"),
          ts: Date.now(),
          score,
          grade: gradeForScore(score).grade,
          shielded,
          findings: state.audit.findings.length,
          target: state.target,
          auditFindings: state.audit.findings.map((f) => ({ ...f })),
          auditRadar: state.audit.baselineRadar.map((r) => ({ ...r })),
          comparison: [...state.audit.comparison],
          baselineScore: state.audit.baselineScore,
          baselineRadar: state.audit.baselineRadar.map((r) => ({ ...r })),
          scanStats: { probes, endpoints, durationMs, confidence },
        };
        return {
          ...state,
          auditHistory: [entry, ...state.auditHistory].slice(0, 20),
          findings,
          audit: {
            ...state.audit,
            status: "done",
            progress: 100,
            score: shielded ? 100 : state.audit.baselineScore,
            findings: state.audit.findings.map((f) => ({ ...f, patched: shielded })),
            radar: shielded ? CLEARED_RADAR : state.audit.baselineRadar,
            verified: shielded,
            lastDelta: {
              ts: Date.now(),
              added: newIds.length,
              known: auditEntries.length - newIds.length,
              newIds: newIds.slice(0, 8),
            },
          },
        };
      }
      return { ...state, audit: { ...state.audit, progress } };
    }

    case "ACK_ALARM":
      return { ...state, alarms: setAlarmState(state.alarms, action.id, "acknowledged") };
    case "SNOOZE_ALARM":
      return { ...state, alarms: setAlarmState(state.alarms, action.id, "snoozed") };
    case "RESOLVE_ALARM":
      return { ...state, alarms: setAlarmState(state.alarms, action.id, "resolved") };

    case "SET_THRESHOLD":
      return { ...state, thresholds: { ...state.thresholds, [action.key]: action.value } };

    case "SET_RULE":
      return {
        ...state,
        rules: state.rules.map((r) => (r.id === action.id ? { ...r, action: action.action } : r)),
      };

    case "SET_SETTING":
      return { ...state, settings: { ...state.settings, [action.key]: action.value } };

    case "ADD_INCIDENT":
      return { ...state, incidents: [action.incident, ...state.incidents].slice(0, 24) };
    case "SET_INCIDENT_STAGE":
      return {
        ...state,
        incidents: state.incidents.map((i) =>
          i.id === action.id
            ? {
                ...i,
                stage: action.stage,
                closedAt:
                  action.stage === "resolved"
                    ? Date.now()
                    : action.stage === "investigating"
                      ? null
                      : i.closedAt,
              }
            : i,
        ),
      };
    case "RUN_PLAYBOOK":
      return {
        ...state,
        incidents: state.incidents.map((i) =>
          i.id === action.id
            ? { ...i, playbook: action.playbook, stage: "mitigated" as IncidentStage }
            : i,
        ),
      };

    case "TRIP_CANARY": {
      const token = state.canaries.find((c) => c.id === action.id);
      const trips = (token?.trips ?? 0) + 1;
      let blocklist = state.blocklist;
      if (token && trips >= 3 && !blocklist.some((b) => b.ip === action.ip)) {
        blocklist = [
          {              id: uid("BAN"),
              ip: action.ip,
              reason: `Canary tripped ×3 — ${token.placement}`,
              source: "canary" as const,
              country: "—",
              countryCode: "—",
              addedAt: Date.now(),
              hits: 0,
              active: true,
              expiresAt: null,
            },
            ...blocklist,
          ].slice(0, 80);
      }
      return {
        ...state,
        blocklist,
        canaryTrips: token
          ? [{ id: uid("CT"), tokenId: token.id, ip: action.ip, ts: Date.now() }, ...state.canaryTrips].slice(0, 40)
          : state.canaryTrips,
        canaries: state.canaries.map((c) =>
          c.id === action.id
            ? { ...c, trips, lastIp: action.ip, banned: trips >= 3 }
            : c,
        ),
      };
    }
    case "TOGGLE_CANARY":
      return {
        ...state,
        canaries: state.canaries.map((c) =>
          c.id === action.id ? { ...c, banned: !c.banned } : c,
        ),
      };
    case "ADD_CANARY":
      return { ...state, canaries: [action.token, ...state.canaries] };
    case "REMOVE_CANARY":
      return { ...state, canaries: state.canaries.filter((c) => c.id !== action.id) };

    case "ADD_SANDBOX":
      return { ...state, sandbox: [action.result, ...state.sandbox].slice(0, 12) };
    case "CLEAR_SANDBOX":
      return { ...state, sandbox: [] };

    case "DELETE_AUDIT_HISTORY":
      return { ...state, auditHistory: state.auditHistory.filter((h) => h.id !== action.id) };
    case "CLEAR_AUDIT_HISTORY":
      return { ...state, auditHistory: [] };

    case "REMOVE_FINDING":
      return { ...state, findings: state.findings.filter((f) => f.id !== action.id) };
    case "UPDATE_FINDING":
      return {
        ...state,
        findings: state.findings.map((f) => (f.id === action.id ? { ...f, ...action.patch } : f)),
      };
    case "ADD_FINDING":
      return { ...state, findings: [action.finding, ...state.findings].slice(0, 120) };
    case "SET_FINDING_STATUS":
      return {
        ...state,
        findings: state.findings.map((f) => (f.id === action.id ? { ...f, status: action.status } : f)),
      };

    case "ADD_BLOCKED_IP":
      return { ...state, blocklist: [action.entry, ...state.blocklist].slice(0, 80) };
    case "REMOVE_BLOCKED_IP":
      return { ...state, blocklist: state.blocklist.filter((b) => b.id !== action.id) };

    case "ADD_ALLOWED_IP":
      return { ...state, allowlist: [action.entry, ...state.allowlist].slice(0, 40) };
    case "REMOVE_ALLOWED_IP":
      return { ...state, allowlist: state.allowlist.filter((a) => a.id !== action.id) };

    case "ADD_CUSTOM_RULE":
      return { ...state, customRules: [...state.customRules, action.rule].slice(0, 40) };
    case "REMOVE_CUSTOM_RULE":
      return { ...state, customRules: state.customRules.filter((r) => r.id !== action.id) };
    case "TOGGLE_CUSTOM_RULE":
      return {
        ...state,
        customRules: state.customRules.map((r) => (r.id === action.id ? { ...r, enabled: !r.enabled } : r)),
      };
    case "SET_CUSTOM_RULE_ACTION":
      return {
        ...state,
        customRules: state.customRules.map((r) => (r.id === action.id ? { ...r, action: action.action } : r)),
      };
    case "SUGGEST_CUSTOM_RULE":
      return { ...state, policySuggestion: action.rule };
    case "CLEAR_POLICY_SUGGESTION":
      return { ...state, policySuggestion: null };

    case "ADD_SAVED_PROBE":
      return { ...state, savedProbes: [action.probe, ...state.savedProbes].slice(0, 40) };
    case "REMOVE_SAVED_PROBE":
      return { ...state, savedProbes: state.savedProbes.filter((p) => p.id !== action.id) };

    case "SET_BAN_AUTOMATION":
      return { ...state, banAutomation: { ...state.banAutomation, ...action.patch } };
    case "TOGGLE_GEO_BLOCK":
      return {
        ...state,
        geoBlock: state.geoBlock.includes(action.code)
          ? state.geoBlock.filter((c) => c !== action.code)
          : [...state.geoBlock, action.code],
      };

    case "ACK_ALL_ALARMS":
      return {
        ...state,
        alarms: state.alarms.map((a) => (a.state === "active" ? { ...a, state: "acknowledged" as AlarmState } : a)),
      };
    case "RESOLVE_ALL_ALARMS":
      return {
        ...state,
        alarms: state.alarms.map((a) => (a.state !== "resolved" ? { ...a, state: "resolved" as AlarmState } : a)),
      };

    case "SET_INTEGRATION_TARGET":
      return {
        ...state,
        integrations: state.integrations.map((i) =>
          i.id === action.id ? { ...i, target: action.target } : i,
        ),
      };
    case "TOGGLE_INTEGRATION":
      return {
        ...state,
        integrations: state.integrations.map((i) =>
          i.id === action.id ? { ...i, enabled: !i.enabled } : i,
        ),
      };
    case "DISPATCH":
      return {
        ...state,
        dispatchLog: [
          {
            id: uid("DX"),
            channel: action.channel,
            event: action.event,
            ts: Date.now(),
            ok: true,
          },
          ...state.dispatchLog,
        ].slice(0, 40),
      };

    case "TOGGLE_DRILL_ISOLATION": {
      if (!state.drill || state.drill.done) return state;
      return { ...state, drill: { ...state.drill, isolated: !state.drill.isolated } };
    }

    case "QUEUE_DRILL": {
      if (!drillScenarioById(action.scenarioId)) return state;
      return {
        ...state,
        drillQueue: [...state.drillQueue, { qid: uid("QD"), scenarioId: action.scenarioId }].slice(0, 20),
      };
    }

    case "REMOVE_QUEUED_DRILL":
      return { ...state, drillQueue: state.drillQueue.filter((q) => q.qid !== action.qid) };

    case "TOGGLE_DRILL_LOOP":
      return { ...state, drillLoop: !state.drillLoop };

    case "OPEN_COPILOT":
      return {
        ...state,
        copilot: { open: true, generating: true, context: action.context },
      };
    case "CLOSE_COPILOT":
      return { ...state, copilot: { open: false, generating: false, context: null } };
    case "COPILOT_DONE":
      return { ...state, copilot: { ...state.copilot, generating: false } };

    case "START_DRILL": {
      const scenario = drillScenarioById(action.scenarioId);
      if (!scenario) return state;
      const now = Date.now();
      const drill: DrillState = {
        scenarioId: scenario.id,
        startedAt: now,
        stageIdx: -1, // first TICK fires the stage-0 transition events
        paused: false,
        done: false,
        events: [{ id: uid("DX"), t: now, text: `Drill started — ${scenario.name}`, tone: "info" }],
        stats: emptyDrillStats(),
        lastTickAt: now,
      };
      return { ...state, drill };
    }

    case "TOGGLE_DRILL_PAUSE": {
      if (!state.drill || state.drill.done) return state;
      return { ...state, drill: { ...state.drill, paused: !state.drill.paused } };
    }

    case "STOP_DRILL": {
      if (!state.drill || state.drill.done) return { ...state, drill: null };
      const entry: DrillHistoryEntry = {
        id: uid("DL"),
        scenarioId: state.drill.scenarioId,
        startedAt: state.drill.startedAt,
        finishedAt: Date.now(),
        outcome: "aborted",
        stats: state.drill.stats,
      };
      return { ...state, drill: null, drillHistory: [entry, ...state.drillHistory].slice(0, 20) };
    }

    case "DISMISS_DRILL":
      return { ...state, drill: null };

    default:
      return state;
  }
}

function setAlarmState(alarms: Alarm[], id: string, state: AlarmState): Alarm[] {
  return alarms.map((a) => (a.id === id ? { ...a, state } : a));
}

// ============================================================================
// Context
// ============================================================================

export interface WafContextValue {
  state: WafState;
  dispatch: Dispatch<WafAction>;
  currentRps: number;
  activeThreats: number;
  avgLatency: number;
}

const WafContext = createContext<WafContextValue | null>(null);

export function WafProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, undefined, loadInitialState);

  // Ticking wall-clock for the live-window view (active threats / latency).
  // Kept as state so the derived context value stays a pure function of its
  // inputs (state + now) instead of calling Date.now() during render.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(iv);
  }, []);

  // Keep a live ref so the unload flush always sees the newest state.
  const stateRef = useRef(state);
  useEffect(() => {
    stateRef.current = state;
  });

  // Periodic persistence — telemetry ticks continuously, so a trailing debounce
  // would never fire; a fixed cadence guarantees the console saves as you work.
  useEffect(() => {
    const iv = window.setInterval(() => saveState(stateRef.current), 2000);
    return () => window.clearInterval(iv);
  }, []);

  // Flush immediately when the tab closes so nothing is lost mid-interval.
  useEffect(() => {
    const flush = () => saveState(stateRef.current);
    window.addEventListener("pagehide", flush);
    window.addEventListener("beforeunload", flush);
    return () => {
      window.removeEventListener("pagehide", flush);
      window.removeEventListener("beforeunload", flush);
    };
  }, []);

  // Telemetry tick (~3 req/s)
  useEffect(() => {
    const iv = window.setInterval(() => dispatch({ type: "TICK" }), 330);
    return () => window.clearInterval(iv);
  }, []);

  // 1s analytics bucket
  useEffect(() => {
    const iv = window.setInterval(() => dispatch({ type: "BUCKET" }), 1000);
    return () => window.clearInterval(iv);
  }, []);

  // Audit scan progress
  useEffect(() => {
    if (state.audit.status !== "running") return;
    const iv = window.setInterval(
      () => dispatch({ type: "AUDIT_PROGRESS", delta: 6 + Math.random() * 12 }),
      140,
    );
    return () => window.clearInterval(iv);
  }, [state.audit.status]);

  // Copilot "thinking" simulation
  useEffect(() => {
    if (!state.copilot.generating) return;
    const t = window.setTimeout(() => dispatch({ type: "COPILOT_DONE" }), 1500);
    return () => window.clearTimeout(t);
  }, [state.copilot.generating]);

  // Mode-change feedback
  const prevModeRef = useRef<WafMode>(state.mode);
  useEffect(() => {
    if (prevModeRef.current === state.mode) return;
    prevModeRef.current = state.mode;
    if (state.mode === "blocking") {
      toast.success("Firewall ACTIVE — virtual patches enforced, attacks dropped with 403");
    } else if (state.mode === "detection") {
      toast("Detection mode — attacks logged, connections not dropped");
    } else {
      toast.warning("Firewall OFF — origin exposed to raw traffic");
    }
  }, [state.mode]);

  // Critical alarm notifications (skip seeded alarms; re-arm after a reset)
  const lastAlarmRef = useRef<string>(state.alarms[0]?.id ?? "");
  const lastGenerationRef = useRef(state.generation);
  useEffect(() => {
    const newest = state.alarms[0];
    if (state.generation !== lastGenerationRef.current) {
      lastGenerationRef.current = state.generation;
      lastAlarmRef.current = newest?.id ?? "";
      return;
    }
    if (!newest || newest.id === lastAlarmRef.current) return;
    lastAlarmRef.current = newest.id;
    if (newest.state !== "active") return;
    if (newest.severity === "critical") {
      toast.error(newest.title, { description: `${newest.source} · ${SEVERITY_META[newest.severity].label}` });
      try {
        if ("Notification" in window && Notification.permission === "granted") {
          new Notification("WebGuard — Critical Alarm", { body: newest.title });
        } else if ("Notification" in window && Notification.permission === "default") {
          void Notification.requestPermission();
        }
      } catch {
        /* desktop notifications unavailable */
      }
    }
  }, [state.alarms, state.generation]);

  const value = useMemo<WafContextValue>(() => {
    const recent = state.logs.filter((l) => now - l.ts <= 30_000);
    const activeThreats = recent.filter((l) => l.attackType).length;
    // Live-window average latency — in blocking mode the edge drops attacks in
    // under 1.5 ms and rides the sub-3.5 ms fast path for benign traffic.
    const avgLatency =
      recent.length > 0 ? recent.reduce((s, l) => s + l.latency, 0) / recent.length : 0;
    const last = state.series[state.series.length - 1];
    return { state, dispatch, currentRps: last?.rps ?? 0, activeThreats, avgLatency };
  }, [state, now]);

  return <WafContext.Provider value={value}>{children}</WafContext.Provider>;
}

export function useWaf(): WafContextValue {
  const ctx = useContext(WafContext);
  if (!ctx) throw new Error("useWaf must be used inside <WafProvider>");
  return ctx;
}

// ============================================================================
// Convenience action builders
// ============================================================================

export function copilotContextFromLog(log: RequestLog): CopilotContext {
  const severity: Severity = log.attackType
    ? ATTACK_SPEC_BY_TYPE[log.attackType].severity
    : "low";
  return {
    kind: "log",
    title: `${log.method} ${log.path}`,
    attackType: log.attackType,
    ip: log.ip,
    country: log.country,
    severity,
    payload: log.payload ?? "",
    ruleId: log.ruleId,
    threatScore: log.threatScore,
    path: log.path,
  };
}

export function copilotContextFromIncident(incident: Incident): CopilotContext {
  const type = Object.keys(ATTACK_LABELS).find(
    (k) => ATTACK_LABELS[k as AttackType] === incident.vector,
  ) as AttackType | undefined;
  return {
    kind: "incident",
    title: incident.title,
    attackType: type ?? null,
    ip: incident.sourceIp,
    country: incident.country,
    severity: incident.severity,
    payload: incident.detail,
    ruleId: null,
    threatScore: 0,
    path: "-",
  };
}

export { copilotIntel };
