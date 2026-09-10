```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ██╗    ██╗███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗       │
│   ██║    ██║██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗      │
│   ██║ █╗ ██║█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║      │
│   ██║███╗██║██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║      │
│   ╚███╔███╔╝███████╗██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝      │
│    ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝       │
│                                                                              │
│   AI-Powered Web Application Firewall · Real-Time Security Operations Center │
└──────────────────────────────────────────────────────────────────────────────┘
```

# WebGuard Nexus — AI-Powered WAF & Real-Time SOC Console

**WebGuard** is a fully interactive, production-grade **Web Application Firewall (WAF)** and **Security Operations Center (SOC)** dashboard. It ships with a built-in **realistic mock telemetry simulator**, so every screen, chart, and button is alive without a live backend — the perfect tool to demo, teach, or blueprint an edge-security product.

> **The killer feature:** a complete **Audit → Shield → Verify** lifecycle. Baseline-scan a target with the WAF off (**Grade F · 28/100**), flip the firewall to **BLOCKING**, re-scan, and watch the posture jump to **100/100 (Grade A+)** with a side-by-side before/after proof. Flip the firewall back off and the site instantly reverts to its raw, vulnerable baseline.

---

## Table of Contents

1. [Key Features](#key-features)
2. [The Core Workflow: Audit → Shield → Verify](#the-core-workflow-audit--shield--verify)
3. [60-Second Demo Script](#60-second-demo-script)
4. [Architecture Overview](#architecture-overview)
5. [Screens & Modules](#screens--modules)
6. [The Telemetry Simulator](#the-telemetry-simulator)
7. [The Enforcement Pipeline](#the-enforcement-pipeline)
8. [Firewall Modes](#firewall-modes)
9. [Attack Drills & Simulation Mode](#attack-drills--simulation-mode)
10. [Vulnerability Lab](#vulnerability-lab--interactive-attack-simulation)
12. [Manual Findings & Triage](#manual-findings--triage)
12. [Data Model Reference](#data-model-reference)
13. [OWASP & Compliance Alignment](#owasp--compliance-alignment)
14. [Command Palette & Shortcuts](#command-palette--shortcuts)
15. [Save Points & Persistence](#save-points--persistence)
16. [Tech Stack](#tech-stack)
17. [Project Structure](#project-structure)
18. [Getting Started](#getting-started)
19. [Environment Variables](#environment-variables)
20. [State & Persistence Architecture](#state--persistence-architecture)
21. [Testing](#testing)
22. [Authentication](#authentication)
23. [Convex Backend](#convex-backend)
24. [Frontend Conventions](#frontend-conventions)
25. [Deployment](#deployment)
26. [Development Workflow](#development-workflow)
27. [Troubleshooting](#troubleshooting)
28. [FAQ](#faq)
29. [Glossary](#glossary)
30. [Roadmap & Extension Ideas](#roadmap--extension-ideas)

---

## Key Features

### Core capabilities

- **End-to-end security lifecycle** — baseline audit → shield activation → verification re-scan → instant revert, all in one flow.
- **6-pillar vulnerability scanner** — Security Headers, CORS Configuration, Cookie Security Flags, Server Fingerprinting & Info Leaks, Parameter Injection Surface, and Rate Limiting / DoS Resilience. 14 itemized defects, each with raw HTTP evidence, exploit explanation, CVSS score, CWE reference, priority, and the exact virtual patch required.
- **Posture scoring** — animated 0–100 gauge (Red **F** → Emerald **A+**), OWASP Top 10 threat radar, severity donut, posture trend chart, and CVSS-weighted exposure factor.
- **Live SOC traffic stream** — virtualized high-speed request table: timestamp, status badge (200 OK / 403 Forbidden / 429 Throttled / 5xx), method, path, client IP with country flag, latency, and AI threat-score pill.
- **Real-time analytics** — synchronized Recharts throughput area chart, traffic velocity (RPS), average ingress latency, blocked/attack counters, and a live animated **threat attack map** with geo-plotted attack origins.
- **3-state firewall controller** — `BLOCKING (ACTIVE)`, `DETECTION (LOG ONLY)`, `OFF (UNPROTECTED)` from the global TopBar.
- **Full SOC tooling** — alerts queue (ack / snooze / resolve), incident tracker with runnable playbooks, IP blocklist + allowlist, geo-blocking, custom policy engine, canary tokens with auto-ban, request sandbox, and edge health monitoring.
- **Vulnerability Lab** — interactive hands-on attack simulation with 4 site templates, 13 vulnerability types, 6 multi-step attack chains, custom vulnerability mode, and WAF before/after comparison.
- **Attack Drills** — scripted multi-stage attack simulations with pause, isolation, queueing, looping, cron-style scheduling, report archive, and drill comparison.
- **AI Copilot drawer** — context-aware assistant for triage, drill analysis, and traffic inspection.
- **Manual findings & triage** — log anything the automation misses, assign owners, tag, annotate, copy as JSON, and remove mistakes.
- **Resilient demo state** — `localStorage` persistence, 4 save-point slots, and JSON snapshot export/import.
- **Fully responsive** — every screen aligned and usable from mobile to ultra-wide, with a compact mobile header and collapsible navigation.

### Why it's different

| Typical dashboard | WebGuard |
|---|---|
| Static mock data | **Live simulated telemetry** — the stream, charts, and map move on their own |
| Screenshots pretend to work | **Every button works** — firewall toggles, alarms, drills, sandbox, copilot |
| One score | **A verifiable story** — Audit → Shield → Verify with before/after proof |
| No consequences | **Flip the firewall off** and the site is instantly vulnerable again |

---

## The Core Workflow: Audit → Shield → Verify

The product's centerpiece, demonstrated end-to-end:

1. **Baseline Vulnerability Audit (WAF OFF)** — enter a target URL (default `http://localhost:8080`) and run the audit. WebGuard scans across the 6 security pillars and reports a baseline score (**28/100 — Grade F**) with 14 itemized critical defects and the OWASP Top 10 threat radar.
2. **Permission & Shield Activation** — toggle the firewall to **BLOCKING**. The simulated reverse proxy applies virtual patches — injects security headers, hardens CORS, cloaks server banners, shields injection points — and enables AI threat inspection.
3. **Verification Re-Scan (WAF ON)** — click **Re-Scan Website** and the score leaps to **100/100 (Grade A+)**. The **Before vs. After Comparison Matrix** proves every missing header was injected, CORS hardened, banners cloaked, and injection entry points shielded.
4. **Toggling Firewall OFF** — instantly returns the target to its raw, vulnerable baseline (Grade F). Audit findings revert to `OPEN` in the vulnerability register; re-activating moves them all back to `PATCHED`.

Every scan is recorded in **Scan History**, and each re-scan pushes genuinely new findings into the register when the scan surface expands — re-scans aren't just replays.

---

## 60-Second Demo Script

Use this as a presenter's walkthrough of the killer feature:

1. **Open** the console → **Vulnerability Audit** tab.
2. **Run Audit** on the default `http://localhost:8080` → watch the scan steps complete, Grade **F** / 28/100.
3. Expand a finding — show the **raw HTTP evidence**, the **why it matters** explanation, and the **virtual patch**.
4. Click **ACTIVATE FIREWALL** (or use the TopBar mode switch) → **BLOCKING**.
5. **Re-Scan Website** → posture **100/100 · A+** · all findings `PATCHED`.
6. Show the **Before vs. After Comparison Matrix** — headers, CORS, cookies, banner cloaking, rate limits.
7. **Toggle the firewall OFF** → posture collapses back to **F** — the origin is exposed again.
8. Bonus: open **Attack Drills**, launch *SQLi Siege*, and watch the live stream eat `403`s while the firewall is on.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Browser (React 19)                              │
│                                                                              │
│  ┌──────────────┐   ┌───────────────────┐   ┌──────────────────────────────┐ │
│  │   TopBar     │   │  SOC Tabs (15+)   │   │  Copilot Drawer · ⌘K Palette │ │
│  │ target·mode· │   │ overview→drills   │   │                              │ │
│  │ latency·rps  │   └────────┬──────────┘   └──────────────┬───────────────┘ │
│  └──────┬───────┘            │                             │                │
│         │        ┌───────────▼─────────────────────────────▼──────────┐     │
│         │        │              useWaf() provider                     │     │
│         │        │         (src/waf/components/provider)              │     │
│         │        └───────────┬────────────────────────────────────────┘     │
│         ▼                    ▼                                             │
│  ┌──────────────────────────────────────────────┐                          │
│  │             engine.tsx — reducer              │                          │
│  │  • TICK loop (~3×/s)  • log synthesis         │                          │
│  │  • enforcement pipeline  • drill orchestration│                          │
│  │  • alarms / incidents / findings / canaries   │                          │
│  └───────┬──────────────────────┬───────────────┘                          │
│          ▼                      ▼                                           │
│  ┌───────────────┐      ┌───────────────────┐                              │
│  │ data.ts       │      │ drills.ts         │                              │
│  │ findings·pill-│      │ scenarios·reports │                              │
│  │ ars·attacks·  │      │ schedules         │                              │
│  │ origins·audit │      └───────────────────┘                              │
│  └───────────────┘                                                        │
│          ▼                                                                 │
│  ┌──────────────────────────────────────────────┐                          │
│  │ localStorage (webguard.soc.v1) · save points │                          │
│  └──────────────────────────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Data flow:** the reducer owns all SOC state. Every ~330 ms a `TICK` synthesizes 1–N requests (normal or drill-driven), pushes each through the enforcement pipeline, and updates logs, series, alarms, incidents, findings, stress, and counters in one atomic update. Components subscribe via `useWaf()` and re-render reactively — no duplicated server-side state.

---

## Screens & Modules

| Tab | What it does |
|---|---|
| **Overview** | Live attack map, posture snapshot, traffic throughput, active threats, quick actions, and drill status. |
| **Live Traffic** | Virtualized stream of every simulated request — filters for query, status, verdict (benign/threat/blocked/throttled), method, and attack class — with per-request details. |
| **Edge Health** | Latency, RPS, error rates, and stress across clients / DNS / LB / WAF / app / DB. |
| **Vulnerability Audit** | The scanner: run/re-run audits, 6-pillar accordion of findings, posture gauge, OWASP radar, severity profile, scan history, before/after matrix, and JSON/CSV/HTML report export. |
| **Findings & Vulnerabilities** | The unified vulnerability register — everything from scans, live telemetry, canary trips, and manual entry — with status/severity/source filters, aging exposure, triage details (owner, tags, notes), per-finding JSON copy, and register export. |
| **Canary Tokens** | Deploy honeypot tokens; tripped tokens track the offender and auto-ban after 3 trips. |
| **Request Sandbox** | Build and fire raw HTTP probes (or replay findings) and inspect how the edge treats them. Includes **Vulnerability Lab** sub-tab for interactive attack simulation. |
| **Alerts** | Real-time alarm queue with severity, source, rule ID, ack / snooze / resolve, and one-click block or incident triage. |
| **Incidents** | Track incidents through `investigating → mitigated → resolved` with runnable playbooks (quarantine, throttle, lockdown). |
| **IP Blocklist & Rules** | Manual / auto / canary bans, allowlist, geo-blocking, and ban-automation thresholds. |
| **Policy Engine** | Custom edge rules matching path, IP, country, user-agent, or header — block / challenge / log / disable with live hit counters. |
| **Attack Drills** | Scripted attack simulations with pause, isolation, queue, loop, cron-style schedule, report archive, compare drills, and attack-mix charts. |
| **Integrations & Webhooks** | Simulated Slack / email / PagerDuty channels, dispatch log, and channel toggles. |
| **AI Copilot (drawer)** | Context-aware assistant — triage the register, analyze drills, inspect traffic — in a dynamic resizable panel. |

The global **TopBar** hosts the target URL input, the 3-state firewall controller, live latency / RPS / active-threat indicators, the Copilot quick-launch, search (⌘K command palette), and the profile menu.

---

## The Telemetry Simulator

No backend required — everything is simulated client-side:

- **Request synthesis** — the engine generates realistic HTTP requests at ~3 ticks/second with real-world distributions: geolocated client IPs (city, country, flag, lat/lon), user agents, paths, payloads, and Shannon-entropy scores.
- **Attack classes** — SQLi, XSS, command injection, path traversal, high-entropy payloads, bad bots, and recon scanners, each with its own signature, rule ID, and severity.
- **Mode-aware behavior** — in `BLOCKING`, attacks die with `403` at sub-2 ms edge latency; in `DETECTION` they pass through and are logged; in `OFF` they hit the origin raw.
- **Seeded history** — ~70 seconds of backfilled traffic so charts, the map, and the stream are alive on first paint, plus seeded alarms, incidents, findings, bans, canaries, and drill reports.
- **Self-balancing** — latency, RPS, error rates (5xx/404/301), and threat density all follow plausible distributions, and attack volume reacts to the firewall state.

---

## The Enforcement Pipeline

Every generated request (normal or drill) runs the full chain, in order:

```
1. Allowlist          trusted IPs/CIDRs bypass ALL enforcement (mode-aware)
2. Custom edge rules  path / IP / country / UA / header matches (block|challenge|log|disable)
3. Geo-blocking       country deny-list → 403
4. IP blocklist       manual / auto / canary bans → 403
5. WAF verdict        per-rule action (sqli, xss, cmdi, traversal, entropy, bots)
6. Rate limiting      global RPM cap → 429 Throttled
7. Auto-ban           repeated blocked hits from a /24 → auto-ban entry
8. Side effects       live findings, alarms, incidents, canary trips, counters
```

Results flow into the vulnerability register (live findings with evidence + patch), the alerts queue, incidents, canary trips, and the drill stats — one pipeline, one source of truth.

---

## Firewall Modes

| Mode | Behavior | Effect on attacks |
|---|---|---|
| **BLOCKING (ACTIVE)** | Full edge enforcement — virtual patches live, rules enforced | Dropped with **403** before reaching origin |
| **DETECTION (LOG ONLY)** | Inspect + log, never drop | Pass through with **200** and a logged threat score |
| **OFF (UNPROTECTED)** | Bypass the WAF entirely | Hit the origin raw — posture collapses to baseline |

Changing modes mid-session instantly re-scores the audit (100 when blocking, baseline when off) and flips audit findings between `PATCHED` and `OPEN` in the register.

---

## Attack Drills & Simulation Mode

The **Drills** module plays scripted, multi-stage attack scenarios over real time through the real enforcement pipeline:

- **Scenario library** — SQLi Siege, DDoS Storm, Credential Stuffing, XSS & Evasion Sweep, API Abuse, RCE Probe, Insider Recon, JWT Forge & Session Hijack, SSRF Pivot & File Exfil, Slowloris Weakening, Polyglot Payload Replay, plus Recon Scout.
- **Stage-based scripting** — each scenario is a sequence of stages with attack type, rate (requests/sec), attack share, path pools, milestones, and optional alarms/incidents that fire at stage transitions.
- **Live control** — start / pause / resume / stop drills, and **isolate drill traffic** (pure attack campaign, no benign blend) so the drill reads as an unambiguous attack test.
- **Scheduling & looping** — queue multiple scenarios, loop a finished drill automatically, or run on a repeating cron-style interval; the console auto-advances between runs.
- **Reports & history** — every completed/aborted drill is archived as a structured report (requests, blocked, attacks, alarms, incidents, canary trips, bans) with attack-mix breakdowns and drill-to-drill comparison.

Drill traffic uses the same signatures, rules, blocklists, and rate limiters as normal traffic — so drills genuinely test the firewall configuration you have active.

---

## Vulnerability Lab — Interactive Attack Simulation

The **Vulnerability Lab** is a hands-on security training environment built into the Request Sandbox. Users can build a vulnerable website, craft real attacks, watch exploitation unfold, then toggle WebGuard to see the WAF block them — all in the browser with zero backend.

### Site Builder

Choose from 4 pre-built vulnerable website templates, each with realistic form fields:

| Template | Description | Exposed Vulnerabilities |
|---|---|---|
| **Login Portal** | Authentication endpoint | SQL Injection (Login Bypass), Credential Brute Force |
| **Contact Form** | User submission form | Stored XSS, Email Header Injection, Open Redirect |
| **Search Page** | Query endpoint | Reflected XSS, SQL Injection (Data Exfiltration) |
| **API Endpoint** | REST API | IDOR, SQLi (API Parameter), SSRF, Command Injection |

Each template has toggleable vulnerabilities — lock/unlock individual vulns to customize the attack surface. The site security posture score and grade update in real-time as vulns are enabled or attacks succeed.

### 13 Vulnerability Types

| Vulnerability | CWE | OWASP | Severity |
|---|---|---|---|
| SQL Injection (Login Bypass) | CWE-89 | A03:2021 Injection | Critical |
| SQL Injection (Data Exfiltration) | CWE-89 | A03:2021 Injection | Critical |
| SQL Injection (API Parameter) | CWE-89 | A03:2021 Injection | Critical |
| Reflected XSS | CWE-79 | A03:2021 Injection | High |
| Stored XSS | CWE-79 | A03:2021 Injection | High |
| Credential Brute Force | CWE-307 | A07:2021 Auth Failures | High |
| OS Command Injection | CWE-78 | A03:2021 Injection | Critical |
| Path Traversal | CWE-22 | A01:2021 Broken Access | High |
| SSRF | CWE-918 | A10:2021 SSRF | Critical |
| JWT Token Forgery | CWE-347 | A02:2021 Crypto Failures | Critical |
| IDOR | CWE-639 | A01:2021 Broken Access | High |
| Open Redirect | CWE-601 | A01:2021 Broken Access | Medium |
| CSRF | CWE-352 | A01:2021 Broken Access | Medium |
| Email Header Injection | CWE-74 | A03:2021 Injection | Medium |

### Attack Chains (Multi-Step Exploits)

Pre-built attack chains that demonstrate real-world kill chains — each step feeds into the next:

| Chain | Steps | Difficulty | Final Impact |
|---|---|---|---|
| **SQLi → RCE** | Extract DB → read files → deploy webshell → reverse shell | Advanced | Full server compromise |
| **XSS → Session Hijacking** | Inject script → steal cookies → IDOR pivot → JWT forge | Intermediate | All sessions + admin backdoor |
| **SSRF → Internal Network Pivot** | Cloud metadata → IAM creds → internal DB → admin panel | Advanced | Full network compromise |
| **Brute Force → Lateral Movement** | Crack password → enumerate users → phishing → persistent backdoor | Intermediate | All accounts + financial data |
| **SQLi → Data Exfiltration → CSRF** | Map DB → extract PII → dump hashes → modify payments | Intermediate | Data integrity compromised |
| **Path Traversal → Config Leak → Full Compromise** | Read files → extract secrets → SSH key theft | Beginner | Lateral movement to other infrastructure |

Each chain runs step-by-step with animated progress tracking. Every step result (blocked or exploited) is visible in real-time.

### Custom Vulnerability Mode

Define your own vulnerabilities for advanced testing:
- **Name** the vulnerability and set severity (Critical / High / Medium / Low)
- **Write** a custom test payload
- **Launch** it against the simulated site
- **Toggle WAF** to see WebGuard detect and block it

Built-in examples: Insecure Deserialization, XML External Entity (XXE), Prototype Pollution, NoSQL Injection.

### WAF Protection Toggle

The core demo flow applied to hands-on attacks:

1. **WAF OFF** — launch an attack and see it succeed (exploitation response, stolen data, bypassed auth)
2. **Toggle WAF ON** — the same attack now returns 403 with WebGuard virtual patch explanation
3. **Before/After Comparison** — expand any result to see the exact HTTP exchange and what WebGuard blocked

### Data Integration

Every lab attack automatically flows into other SOC sections:
- **Live Traffic** — attack requests appear in the live stream with threat scores and verdicts
- **Findings & Vulnerabilities** — successful exploits (WAF OFF) are logged as open findings with evidence, CWE, and patch recommendations
- **Request Sandbox** — lab results coexist with regular sandbox runs

### Export & Reporting

All lab data supports multi-format export: **JSON** (structured), **CSV** (spreadsheet), **HTML** (styled printable report).

---

## Manual Findings & Triage

The vulnerability register is fully open to human input:

- **Add finding** (Findings tab header or the Audit tab toolbar) — log any issue the automation missed with title, severity, status, pillar, path, rule ID, occurrence count, evidence, patch, owner, tags, and notes. Six **quick-start templates** prefill common cases in one click (Missing HSTS, Open admin panel, Exposed `.env`, Weak TLS cipher, Verbose errors, IDOR).
- **Triage details** — every finding (manual or discovered) can be assigned an **owner**, grouped with **#tags**, and annotated with **notes**; the register search matches titles, paths, rule IDs, patches, owners, tags, and notes.
- **Copy as JSON** — export any single finding as pretty-printed JSON from its expanded card, or download the whole register.
- **Remove** — manually-added entries can be deleted from their expanded card if logged by mistake.

---

## Data Model Reference

### `VulnFinding` — the vulnerability register

| Field | Type | Notes |
|---|---|---|
| `id` | `string` | Unique (`MAN-*` for manual, `live:*` for telemetry, seed ids) |
| `title` | `string` | Human-readable issue summary |
| `severity` | `critical \| high \| medium \| low` | Drives color, CVSS, priority |
| `source` | `audit \| live \| canary \| manual` | Where the register learned about it |
| `status` | `open \| investigating \| patched \| fixed` | Lifecycle state |
| `discoveredAt` / `lastSeen` | `number` (epoch ms) | Drives aging exposure |
| `count` | `number` | Observed occurrences / attempts |
| `evidence` / `patch` | `string` | Raw proof + recommended remediation |
| `ruleId` / `path` / `pillar` | `string \| null` | Matching context |
| `owner` / `tags` / `notes` | optional | Human triage metadata |

### `RequestLog` — live traffic

`id, ts, status, method, path, ip, countryCode, country, lat, lon, city, latency, threatScore, attackType, ruleId, blocked, throttled, entropy, ua, payload, matched, headers`

### State machines

| Concept | States |
|---|---|
| Firewall mode | `blocking` · `detection` · `off` |
| Finding status | `open` → `investigating` → `patched` / `fixed` → (reopen) |
| Finding source | `audit` · `live` · `canary` · `manual` |
| Alarm state | `active` → `acknowledged` · `snoozed` → `resolved` |
| Incident stage | `investigating` → `mitigated` → `resolved` |
| Playbook | `quarantine` · `throttle` · `lockdown` |
| Rule action | `block` · `challenge` · `log` · `disable` |
| Ban source | `manual` · `auto` · `canary` |

### HTTP status semantics used by the stream

| Status | Meaning in WebGuard |
|---|---|
| `200 OK` | Passed / benign (or attack in DETECTION mode) |
| `301` | Redirect observed on a normal path |
| `403 Forbidden` | Blocked at the edge — attack, geo, blocklist, or custom rule |
| `404 Not Found` | Origin miss |
| `429 Throttled` | Rate limit enforced |
| `500 Error` | Origin fault |

### Posture grades

| Score | Grade | Color |
|---|---|---|
| 95–100 | **A+** | Emerald |
| 90–94 | **A** | Emerald |
| 80–89 | **B** | Lime |
| 70–79 | **C** | Yellow |
| 60–69 | **D** | Orange |
| < 60 | **F** | Rose |

---

## OWASP & Compliance Alignment

The scanner's findings map onto recognized frameworks:

| Audit pillar | OWASP Top 10 | Representative CWE |
|---|---|---|
| Security Headers | A05 — Security Misconfiguration | CWE-693, CWE-525 |
| CORS Configuration | A01 / A05 — Broken Access Control & Misconfig | CWE-942 |
| Cookie Security Flags | A05 — Security Misconfiguration | CWE-614, CWE-1004 |
| Server Fingerprinting | A05 — Info Leak | CWE-200, CWE-548, CWE-209, CWE-540 |
| Parameter Injection Surface | A03 — Injection | CWE-89, CWE-79, CWE-77, CWE-22, CWE-78 |
| Rate Limiting & DoS | A04 — Insecure Design | CWE-770, CWE-307, CWE-640 |

Compliance controls surfaced in the audit: **PCI-DSS** Req 6.5/6.6, **OWASP ASVS** V3/V14, **ISO 27001** A.12.6.1, and OWASP Top 10 A01/A05.

---

## Command Palette & Shortcuts

| Shortcut | Action |
|---|---|
| **⌘K / Ctrl+K** | Open the global command palette (jump to any tab, run quick actions) |
| **Esc** | Close palette / dialogs / overlays |

The palette indexes every SOC module and common actions (run audit, toggle firewall mode, open drills, dispatch integrations, and more).

---

## Save Points & Persistence

- **4 save-point slots** — capture named snapshots of the full persisted state and restore them any time (great for switching demo scenarios).
- **Auto-persistence** — durable control state (mode, target, audit, findings, rules, blocklist, drills, reports…) is written to `localStorage` (`webguard.soc.v1`) on every change and re-hydrated on load.
- **JSON export/import** — download the entire console state as JSON and re-import it on any machine.
- **Live streams** (logs/charts) are re-seeded fresh on every load — only control state is restored.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Build tool | Vite |
| Language | TypeScript (strict) |
| Framework | React 19 |
| Routing | React Router v7 (`react-router`) |
| Styling | Tailwind CSS v4 (oklch tokens) |
| UI kit | shadcn/ui primitives |
| Icons | Lucide |
| Charts | Recharts |
| Animations | Framer Motion |
| Toasts | Sonner |
| Backend & database | Convex |
| Auth | Convex Auth (email OTP + anonymous) |
| 3D graphics | Three.js |
| Package manager | Bun |
| Tests | Vitest + Testing Library |

---

## Project Structure

```
src/
├── main.tsx                  # App bootstrap + React Router config
├── index.css                 # Tailwind directives + design tokens (theme)
├── pages/
│   ├── Landing.tsx           # Public landing page
│   ├── LandingSections.tsx   # Landing page sections
│   ├── Auth.tsx              # Sign-in / sign-up
│   ├── Dashboard.tsx         # Protected authenticated shell (SOC console)
│   └── NotFound.tsx
├── components/               # Shared UI (shadcn/ui primitives in ui/)
├── hooks/
│   ├── use-auth.ts           # MUST-use auth hook
│   └── use-mobile.ts
├── convex/                   # Convex backend (auth, schema, users)
└── waf/                      # ⚙️ The WebGuard engine & SOC
    ├── engine.tsx            # Reducer, telemetry synthesis, enforcement pipeline
    ├── types.ts              # All shared WAF/SOC types
    ├── data.ts               # Findings, pillars, attacks, origins, seed data
    ├── drills.ts             # Attack drill scenarios, reports, scheduling
    ├── components/           # One component per tab + TopBar, Copilot, etc.
    └── *.test.ts(x)          # Unit tests for engine, audit-gen, gauge, provider
```

The heart of the app lives in `src/waf`:

- **`engine.tsx`** — the single `reducer` owning all SOC state: log synthesis, the per-request enforcement pipeline, drill orchestration, alarm/incident/finding generation, and persistence.
- **`data.ts`** — static catalogs: the 14 baseline findings, 6 pillars, comparison matrix, attack specs, origin geos, seed rules, and `generateAudit()`.
- **`drills.ts`** — drill scenario definitions (stages, rates, attack mixes), report building, and the repeating schedule.
- **`components/`** — the SOC tabs, TopBar, sidebar, command palette (⌘K), Copilot drawer, threat map, and shared atoms.

---

## Getting Started

```bash
# Install dependencies (Bun is required)
bun install

# Run the dev server
bun run dev

# Typecheck (no emit)
bun tsc -b --noEmit

# Run the full test suite
bun test            # or: bun vitest run

# Run a single test file
bun vitest run src/waf/engine.test.ts

# Lint
bun run lint

# Format
bun run format

# Production build
bun run build
```

> WebGuard is fully functional with **no backend**: the SOC console runs entirely on the client-side simulator. Convex is used for authentication (email OTP / anonymous) and user records only — the WAF data itself is simulated and persisted to `localStorage`.

---

## Environment Variables

The project is set up with project-specific `CONVEX_DEPLOYMENT` and `VITE_CONVEX_URL` environment variables on the client side. The Convex server has its own environment variables for auth: `JWKS`, `JWT_PRIVATE_KEY`, and `SITE_URL`.

> **Do not edit `.env` files directly** — manage secrets through the Freebuff/Keys UI.

---

## State & Persistence Architecture

- **One reducer, one store** — all SOC state lives in `engine.tsx` (`WafState`) and is consumed via the `useWaf()` hook. React components never duplicate server-like state.
- **Reactive by construction** — live streams (logs, series, alarms, incidents, findings) are derived from the same reducer, so charts, tables, and badges always agree.
- **Local persistence** — durable control state is saved to `localStorage` (`webguard.soc.v1`) on every change and re-hydrated on load, so a demo resumes exactly where it left off. Live log/chart streams are re-seeded fresh on reload.
- **Snapshot export/import** — the full persisted state can be serialized to JSON for sharing or restoring.
- **Reset** — the console can be reset to a fresh seeded session at any time.

---

## Testing

```bash
bun vitest run              # whole suite
bun vitest run src/waf      # WAF engine + components only
```

Coverage focuses on the pieces that matter:

- `engine.test.ts` — reducer behavior (mode transitions, audit state, findings, drills).
- `auditGen.test.ts` — deterministic audit generation (score, radar, findings).
- `provider.test.tsx` — the `useWaf` provider wiring.
- `PostureGauge.test.tsx` / `useNow.test.ts` — gauge rendering and the live clock hook.

---

## Authentication

Auth is already fully configured and **must not be modified**:

- Email OTP + anonymous sign-in via Convex Auth (`src/convex/auth/emailOtp.ts`, `src/convex/auth.ts`, `src/convex/auth.config.ts` — **DO NOT MODIFY**).
- The `/auth` page handles all login/sign-up flows and supports `?returnTo=<route>`.
- Protected routes use `RequireAuth`, which redirects signed-out users to `/auth?returnTo=<current route>`.
- The `/dashboard` route is the protected authenticated shell hosting the WebGuard console; after sign-in, users land on the dashboard.

**Always** fetch the current user through the hook:

```typescript
import { useAuth } from "@/hooks/use-auth";
const { isLoading, isAuthenticated, user, signIn, signOut } = useAuth();
```

---

## Convex Backend

- Schema lives in `src/convex/schema.ts` (auth tables + `users`). `schemaValidation` stays `false`.
- Document IDs are `Id<"TableName">` / `Doc<"TableName">` — never plain `string`.
- Anything involving external connections goes in a **Convex action** with `"use node"` at the top; queries/mutations live in separate files.
- Import Convex files with the `@/` alias (e.g. `@/convex/_generated/api`).
- Never add return-type validators.

---

## Frontend Conventions

- Pages live in `src/pages`, components in `src/components` (primitives under `src/components/ui`).
- Prefer shadcn/ui primitives; keep clickable elements with `cursor-pointer`.
- **Mobile-first responsive** — every screen is tested from small phones to ultra-wide; the dashboard uses a collapsible sidebar and a compact header on mobile.
- **No nested cards, no shadows** — thin borders and the project's `wg-*` token system instead.
- Theme tokens are defined in `src/index.css` (oklch) and consumed through Tailwind utilities — avoid hardcoded colors.
- Use **Sonner** toasts for all confirmations/results: `toast("…")`.
- Large dialogs scroll internally (`max-h-[88vh] overflow-y-auto`) so content never gets cut off.
- Animate with Framer Motion (`motion`), including fade/slide and entrance animations on the landing page.

---

## Deployment

```bash
bun run build        # type-checks (tsc -b) then builds to dist/
```

- The build output is static — host it on any CDN/static host.
- Convex needs to be deployed for auth to work in production (`bunx convex deploy`), with `CONVEX_DEPLOYMENT` / `VITE_CONVEX_URL` configured.
- The WAF console itself needs no server: it runs entirely in the browser.

---

## Development Workflow

1. **Plan** — map the change to the reducer action you need, or add a new action in `engine.tsx` (`WafAction` union + reducer case).
2. **Implement** — UI lives in `src/waf/components`; seed/static data lives in `data.ts`; drill content lives in `drills.ts`.
3. **Verify** — `bun tsc -b --noEmit` and `bun vitest run`; add a reducer/audit test for new logic.
4. **Style** — use the existing `wg-*` tokens and shadcn primitives; keep it responsive, no nested cards, no shadows.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Blank preview | Check for TypeScript errors: `bun tsc -b --noEmit`; verify `src/main.tsx` imports `./index.css`. |
| Console looks empty / no traffic | Confirm the reducer tick loop is running (live stream refreshes ~3×/s). Reload the page — state re-seeds. |
| Persisted state feels stale | Reset the console from the UI, or clear `localStorage` key `webguard.soc.v1`. |
| Audit stuck at "running" | Persisted mid-run audits are force-completed on load; run a fresh audit. |
| Drill not advancing | Check the drill isn't paused or finished; queued/looped drills auto-advance after the results window. |
| Convex auth issues | Ensure Convex env vars (`CONVEX_DEPLOYMENT`, `VITE_CONVEX_URL`, `JWKS`, `JWT_PRIVATE_KEY`, `SITE_URL`) are configured in the Keys UI. |

---

## FAQ

**Does WebGuard need a real backend?** No. The telemetry, attacks, WAF enforcement, and drills are all simulated client-side. Convex is only used for authentication.

**Can I point it at a real website?** The audit is simulated — it demonstrates the product's behavior and lifecycle rather than scanning an actual target. It's designed as a production-grade frontend experience, not a live scanner.

**Where does the "AI" come from?** The AI threat scoring (entropy-based classification, threat-score pills) and the Copilot assistant are simulated in-app; the architecture is ready to swap in a real inference API through the Convex action layer.

**What survives a reload?** All durable control state via `localStorage` — mode, target, audit, findings, rules, blocklists, drills, reports. Live streams re-seed fresh.

**Can I export results?** Yes — audit reports (JSON / CSV / HTML), the full vulnerability register (JSON), single findings (JSON), and complete console snapshots.

---

## Glossary

| Term | Meaning |
|---|---|
| **WAF** | Web Application Firewall — filters traffic between clients and the origin |
| **SOC** | Security Operations Center — the console monitoring and responding to threats |
| **Posture score** | 0–100 health grade of the target (F → A+) |
| **Virtual patch** | A shield applied at the edge that closes a vulnerability without changing app code |
| **RPS** | Requests per second — traffic velocity |
| **Entropy** | Shannon bits/char of a payload — high entropy flags obfuscated attacks |
| **Canary** | A honeypot token that trips when an attacker touches it |
| **Playbook** | A predefined incident response procedure (quarantine / throttle / lockdown) |
| **Drill** | A scripted attack scenario run through the real enforcement pipeline |
| **403** | The edge blocking a request — the WAF's "drop" response |

---

## Roadmap & Extension Ideas

- **Real AI engine** — wire the Copilot and threat scoring to a real LLM/inference API via a Convex action.
- **Live scanning** — connect the audit to real fetch-based header/CORS checks for genuine targets.
- **Multi-tenant workspaces** — scope targets, findings, and teams per organization in Convex.
- **Slack/PagerDuty delivery** — turn simulated integrations into real webhooks.
- **Compliance export** — generate PCI-DSS / SOC 2 / ISO-ready PDF reports from the audit data.
- **Time-travel & replay** — scrub through the telemetry timeline to replay incidents frame by frame.

---

**WebGuard Nexus** — built to demo, teach, and blueprint a production WAF/SOC experience, entirely self-contained in the browser.
