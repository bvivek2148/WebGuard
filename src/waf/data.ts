import type {
  Alarm,
  AttackSpec,
  AttackType,
  AuditFinding,
  BlockedIp,
  CanaryToken,
  CanaryTrip,
  ComparisonRow,
  CopilotIntel,
  CustomRule,
  GeoPoint,
  Incident,
  IntegrationChannel,
  OwaspAxis,
  RadarAxis,
  RuleSetting,
  Severity,
  VulnFinding,
} from "./types";

// ============================================================================
// Geographic origins
// ============================================================================

export interface Origin {
  geo: GeoPoint;
  weight: number;
  ipPrefixes: string[];
  asn: string;
  isp: string;
  reputation: number; // 0 (clean) .. 100 (hostile)
}

export const ATTACK_ORIGINS: Origin[] = [
  {
    geo: { lat: 50.11, lon: 8.68, city: "Frankfurt", country: "Germany", code: "DE" },
    weight: 0.24,
    ipPrefixes: ["91.134", "185.220", "45.155", "89.248", "94.142"],
    asn: "AS51167",
    isp: "Contabo GmbH",
    reputation: 78,
  },
  {
    geo: { lat: 37.34, lon: -121.89, city: "San Jose", country: "United States", code: "US" },
    weight: 0.18,
    ipPrefixes: ["104.223", "192.81", "45.63", "66.42", "23.94"],
    asn: "AS20473",
    isp: "Choopa / Vultr",
    reputation: 64,
  },
  {
    geo: { lat: 1.35, lon: 103.82, city: "Singapore", country: "Singapore", code: "SG" },
    weight: 0.17,
    ipPrefixes: ["128.199", "159.65", "139.59", "167.71", "178.128"],
    asn: "AS14061",
    isp: "DigitalOcean",
    reputation: 71,
  },
  {
    geo: { lat: 35.68, lon: 139.65, city: "Tokyo", country: "Japan", code: "JP" },
    weight: 0.14,
    ipPrefixes: ["103.5", "45.32", "133.242", "210.140", "118.27"],
    asn: "AS2497",
    isp: "IIJ / Sakura",
    reputation: 58,
  },
  {
    geo: { lat: -33.87, lon: 151.21, city: "Sydney", country: "Australia", code: "AU" },
    weight: 0.12,
    ipPrefixes: ["139.99", "103.10", "45.76", "27.50", "115.42"],
    asn: "AS38895",
    isp: "OVH AU",
    reputation: 52,
  },
  {
    geo: { lat: 55.75, lon: 37.62, city: "Moscow", country: "Russia", code: "RU" },
    weight: 0.15,
    ipPrefixes: ["5.45", "46.161", "95.213", "185.86", "193.106"],
    asn: "AS197695",
    isp: "Reg.ru / RUVDS",
    reputation: 88,
  },
];

export const BENIGN_ORIGINS: Origin[] = [
  { geo: { lat: 40.71, lon: -74.01, city: "New York", country: "United States", code: "US" }, weight: 0.22, ipPrefixes: ["73.221", "68.45", "100.36"], asn: "AS3356", isp: "Verizon Fios", reputation: 6 },
  { geo: { lat: 51.51, lon: -0.13, city: "London", country: "United Kingdom", code: "GB" }, weight: 0.18, ipPrefixes: ["81.131", "86.17", "92.40"], asn: "AS12576", isp: "EE Broadband", reputation: 4 },
  { geo: { lat: 43.65, lon: -79.38, city: "Toronto", country: "Canada", code: "CA" }, weight: 0.12, ipPrefixes: ["99.235", "70.49", "174.88"], asn: "AS577", isp: "Bell Canada", reputation: 3 },
  { geo: { lat: -23.55, lon: -46.63, city: "São Paulo", country: "Brazil", code: "BR" }, weight: 0.1, ipPrefixes: ["177.220", "189.70", "201.23"], asn: "AS28573", isp: "Claro Brasil", reputation: 11 },
  { geo: { lat: 12.97, lon: 77.59, city: "Bengaluru", country: "India", code: "IN" }, weight: 0.14, ipPrefixes: ["49.207", "103.85", "122.171"], asn: "AS9829", isp: "Bharti Airtel", reputation: 9 },
  { geo: { lat: 52.37, lon: 4.9, city: "Amsterdam", country: "Netherlands", code: "NL" }, weight: 0.12, ipPrefixes: ["84.82", "145.5", "37.120"], asn: "AS20857", isp: "Signet B.V.", reputation: 7 },
  { geo: { lat: 48.86, lon: 2.35, city: "Paris", country: "France", code: "FR" }, weight: 0.12, ipPrefixes: ["91.174", "86.207", "176.133"], asn: "AS3215", isp: "Orange France", reputation: 5 },
];

export const SERVER_ORIGIN: GeoPoint = {
  lat: 39.03,
  lon: -77.47,
  city: "Ashburn",
  country: "United States",
  code: "US",
};

export function pickOrigin<T extends Origin>(pool: T[]): T {
  const total = pool.reduce((sum, o) => sum + o.weight, 0);
  let r = Math.random() * total;
  for (const o of pool) {
    r -= o.weight;
    if (r <= 0) return o;
  }
  return pool[0];
}

export function originIp(o: Origin): string {
  const prefix = o.ipPrefixes[Math.floor(Math.random() * o.ipPrefixes.length)];
  const tail = [1, 2, 3].map(() => Math.floor(Math.random() * 255)).join(".");
  return `${prefix}.${tail}`;
}

export const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
  "curl/8.5.0",
  "Go-http-client/1.1",
  "python-requests/2.31.0",
  "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
  "Mozilla/5.0 (Windows NT 6.1; WOW64) Trident/7.0; rv:11.0 like Gecko",
  "libwww-perl/6.68",
];

// ============================================================================
// Attack catalog
// ============================================================================

export const ATTACK_SPECS: AttackSpec[] = [
  {
    type: "sqli",
    label: "SQL Injection",
    severity: "critical",
    ruleId: "OWASP-CRIT-942100",
    method: "GET",
    path: "/api/search?id=1' OR 1=1--",
    payload: "id=1' OR 1=1--",
    match: "OR 1=1",
    entropyFloor: 3.1,
    description:
      "Attacker injects SQL predicates into an unsanitized query parameter to bypass authentication or exfiltrate the entire users table.",
  },
  {
    type: "xss",
    label: "Cross-Site Scripting",
    severity: "high",
    ruleId: "OWASP-CRIT-941100",
    method: "GET",
    path: "/search?q=<script>alert(document.cookie)</script>",
    payload: "q=<script>alert(document.cookie)</script>",
    match: "<script>",
    entropyFloor: 2.6,
    description:
      "Reflected script payload in search query. If echoed unescaped, the attacker can steal session cookies from any visitor.",
  },
  {
    type: "cmdi",
    label: "Command Injection",
    severity: "critical",
    ruleId: "OWASP-CRIT-932160",
    method: "POST",
    path: "/api/ping",
    payload: "host=8.8.8.8;cat /etc/passwd",
    match: "cat /etc/passwd",
    entropyFloor: 3.4,
    description:
      "Semicolon-chained OS command appended to a host parameter, attempting to read /etc/passwd from the origin server.",
  },
  {
    type: "path-traversal",
    label: "Path Traversal",
    severity: "high",
    ruleId: "OWASP-CRIT-930120",
    method: "GET",
    path: "/api/download?file=../../../../etc/passwd",
    payload: "file=../../../../etc/passwd",
    match: "../../",
    entropyFloor: 2.2,
    description:
      "Dot-dot-slash sequences climb out of the uploads directory to retrieve arbitrary server files.",
  },
  {
    type: "high-entropy",
    label: "High-Entropy Payload",
    severity: "high",
    ruleId: "ML-ENTROPY-001",
    method: "POST",
    path: "/api/upload",
    payload: "file=UEsDBAoAAAAAADxQZ1hF4v1zFgAAABYAAAAIABwAY2hvZGVsZXhwb3NlZF9maWxlLnR4dFVUCQADQ29sYWNrZQ==",
    match: "UEsDBAo",
    entropyFloor: 4.6,
    description:
      "Base64-encoded blob with a PK/ZIP magic header — classic staging for webshell upload via disguised archives.",
  },
  {
    type: "bot",
    label: "Bad Bot",
    severity: "medium",
    ruleId: "BOT-BLOCK-001",
    method: "GET",
    path: "/wp-login.php",
    payload: "",
    match: "wp-login",
    entropyFloor: 1.2,
    description:
      "Headless bot hammering WordPress login endpoints with a spoofed UA — credential stuffing precursor.",
  },
  {
    type: "scanner",
    label: "Recon Scanner",
    severity: "medium",
    ruleId: "SCAN-DETECT-002",
    method: "GET",
    path: "/.env",
    payload: "",
    match: ".env",
    entropyFloor: 1.1,
    description:
      "Automated reconnaissance probing for leaked environment files, backup archives, and admin panels.",
  },
];

export const ATTACK_SPEC_BY_TYPE: Record<AttackType, AttackSpec> = Object.fromEntries(
  ATTACK_SPECS.map((s) => [s.type, s]),
) as Record<AttackType, AttackSpec>;

export const ATTACK_WEIGHTS: [AttackType, number][] = [
  ["sqli", 0.2],
  ["xss", 0.2],
  ["cmdi", 0.13],
  ["path-traversal", 0.13],
  ["high-entropy", 0.16],
  ["bot", 0.1],
  ["scanner", 0.08],
];

export function pickAttackType(): AttackType {
  const total = ATTACK_WEIGHTS.reduce((s, [, w]) => s + w, 0);
  let r = Math.random() * total;
  for (const [type, w] of ATTACK_WEIGHTS) {
    r -= w;
    if (r <= 0) return type;
  }
  return "sqli";
}

export const SAFE_PATHS = [
  "/",
  "/login",
  "/api/session",
  "/api/products",
  "/api/products/42",
  "/api/products?category=waf",
  "/assets/app.js",
  "/assets/logo.svg",
  "/api/users/me",
  "/api/orders?page=2",
  "/api/cart",
  "/api/checkout",
  "/graphql",
  "/blog/top-10-waf-features",
  "/images/hero.png",
  "/api/search?q=firewall",
];

// ============================================================================
// Vulnerability audit data
// ============================================================================

export interface PillarDef {
  id: string;
  title: string;
  icon: string;
  summary: string;
}

export const PILLARS: PillarDef[] = [
  { id: "headers", title: "Security Headers", icon: "FileLock", summary: "Response-hardening headers missing or weak" },
  { id: "cors", title: "CORS Configuration", icon: "Share2", summary: "Reflected / wildcard origins with credentials" },
  { id: "cookies", title: "Cookie Security Flags", icon: "Cookie", summary: "Session cookies exposed to JS and the wire" },
  { id: "fingerprint", title: "Server Fingerprinting", icon: "Fingerprint", summary: "Banners, error pages & dotfiles leaking stack info" },
  { id: "injection", title: "Parameter Injection Surface", icon: "Bug", summary: "Unvalidated reflection & injection points" },
  { id: "ratelimit", title: "Rate Limiting & DoS", icon: "Gauge", summary: "No throttling on auth & OTP endpoints" },
];

const BASE_FINDINGS: Omit<AuditFinding, "patched">[] = [
  // Pillar 1 — headers (6)
  {
    id: "HDR-01",
    pillar: "headers",
    title: "Missing HSTS header",
    severity: "high",
    evidence: "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.33\nContent-Type: text/html; charset=UTF-8",
    explanation:
      "No Strict-Transport-Security header. Clients may fall back to plain HTTP, enabling downgrade and man-in-the-middle attacks even after HTTPS is established.",
    patch: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  },
  {
    id: "HDR-02",
    pillar: "headers",
    title: "No Content-Security-Policy",
    severity: "high",
    evidence: "HTTP/1.1 200 OK\nContent-Type: text/html\n(no Content-Security-Policy header present)",
    explanation:
      "Without a CSP, any successful XSS executes with full page privileges — the browser has no allow-list to reject injected scripts.",
    patch: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'",
  },
  {
    id: "HDR-03",
    pillar: "headers",
    title: "Missing X-Frame-Options",
    severity: "medium",
    evidence: "HTTP/1.1 200 OK\n(no X-Frame-Options header present)",
    explanation: "The application can be embedded in a rogue <iframe>, enabling clickjacking overlays that trick users into destructive actions.",
    patch: "X-Frame-Options: DENY",
  },
  {
    id: "HDR-04",
    pillar: "headers",
    title: "Missing X-Content-Type-Options",
    severity: "medium",
    evidence: "HTTP/1.1 200 OK\nContent-Type: text/html",
    explanation: "Old browsers may sniff HTML inside user-uploaded files, turning stored content into executable scripts (MIME confusion).",
    patch: "X-Content-Type-Options: nosniff",
  },
  {
    id: "HDR-05",
    pillar: "headers",
    title: "Missing Referrer-Policy",
    severity: "low",
    evidence: "HTTP/1.1 200 OK\n(no Referrer-Policy header present)",
    explanation: "Full URLs — including session tokens in query strings — leak to third-party origins through the Referer header.",
    patch: "Referrer-Policy: strict-origin-when-cross-origin",
  },
  {
    id: "HDR-06",
    pillar: "headers",
    title: "Missing Permissions-Policy",
    severity: "low",
    evidence: "HTTP/1.1 200 OK\n(no Permissions-Policy header present)",
    explanation: "Embedded or compromised content can invoke camera, microphone, geolocation, and USB APIs without explicit consent controls.",
    patch: "Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=()",
  },
  // Pillar 2 — CORS (2)
  {
    id: "CORS-01",
    pillar: "cors",
    title: "Reflected Origin header with credentials",
    severity: "high",
    evidence: "GET /api/me — Origin: https://evil.example\nAccess-Control-Allow-Origin: https://evil.example (reflected)\nAccess-Control-Allow-Credentials: true",
    explanation:
      "The server copies any Origin it receives into Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true. Any attacker-controlled page can then make credentialed cross-origin reads and exfiltrate the responses — a direct account-takeover primitive (CWE-942).",
    patch: "Origin allow-list (scheme + host validated) instead of reflection, with Vary: Origin and credentials only for trusted origins",
  },
  {
    id: "CORS-02",
    pillar: "cors",
    title: "Permissive preflight & methods",
    severity: "medium",
    evidence: "Access-Control-Max-Age: 86400\nAccess-Control-Allow-Headers: *",
    explanation: "Allowing arbitrary headers and long preflight caching widens the set of credentialed requests browsers will forward on the attacker's behalf.",
    patch: "Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token\nAccess-Control-Max-Age: 600",
  },
  // Pillar 3 — cookies (2)
  {
    id: "CK-01",
    pillar: "cookies",
    title: "Session cookie missing HttpOnly",
    severity: "high",
    evidence: "Set-Cookie: PHPSESSID=abc123def456; path=/",
    explanation: "The session ID is readable from JavaScript. One reflected XSS is enough to steal the entire session via document.cookie.",
    patch: "Set-Cookie: PHPSESSID=abc123def456; path=/; HttpOnly; SameSite=Strict",
  },
  {
    id: "CK-02",
    pillar: "cookies",
    title: "Cookie missing Secure & SameSite",
    severity: "medium",
    evidence: "Set-Cookie: session=xyz789; path=/; HttpOnly",
    explanation: "Without Secure the cookie travels over HTTP; without SameSite the browser sends it on cross-site requests, enabling CSRF.",
    patch: "Set-Cookie: session=xyz789; path=/; HttpOnly; Secure; SameSite=Lax",
  },
  // Pillar 4 — fingerprinting (1)
  {
    id: "FP-01",
    pillar: "fingerprint",
    title: "Apache & PHP version banners exposed",
    severity: "medium",
    evidence: "Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.33",
    explanation:
      "Version banners let scanners fingerprint the exact stack and look up public CVEs (Apache 2.4.41, PHP 7.4 EOL) before sending a single exploit.",
    patch: "Server: WebGuard Edge\nX-Powered-By: (stripped)",
  },
  // Pillar 5 — injection (2)
  {
    id: "INJ-01",
    pillar: "injection",
    title: "Reflected SQL parameter in /api/search",
    severity: "critical",
    evidence: "GET /api/search?id=1' OR 1=1-- HTTP/1.1\n200 OK — 1,482 rows returned\nSELECT * FROM products WHERE id = '1' OR 1=1--'",
    explanation:
      "The id parameter is concatenated into SQL without parameterization. ' OR 1=1-- flips the WHERE clause into a tautology and dumps the table.",
    patch: "Virtual patch: parameterized query + input validation (^[0-9]+$) + OWASP CRS rule 942100 enforced at edge",
  },
  {
    id: "INJ-02",
    pillar: "injection",
    title: "Unescaped XSS reflection in /search",
    severity: "high",
    evidence: "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\n200 OK — <script>alert(document.cookie)</script> echoed in <h1>",
    explanation: "User input is echoed into the DOM without encoding, giving attackers a direct script execution channel.",
    patch: "Virtual patch: context-aware output encoding + OWASP CRS rule 941100 enforced at edge",
  },
  // Pillar 6 — rate limiting (1)
  {
    id: "RL-01",
    pillar: "ratelimit",
    title: "No rate limiting on /api/login",
    severity: "critical",
    evidence: "POST /api/login — 200 OK\n(no RateLimit-* headers)\n12,400 requests from 91.134.22.7 in 90s — all processed",
    explanation:
      "The login endpoint accepts unlimited attempts, enabling credential stuffing and distributed brute-force with no lockout or throttling.",
    patch: "Virtual patch: 10 req/min per IP + progressive lockout + CAPTCHA challenge above threshold",
  },
  // Pillar 1 — extra header hardening (1)
  {
    id: "HDR-07",
    pillar: "headers",
    title: "Authenticated pages cacheable by shared proxies",
    severity: "medium",
    evidence: "HTTP/1.1 200 OK\nCache-Control: private, max-age=3600\nSet-Cookie: session=xyz789; path=/",
    explanation:
      "Sensitive account pages carry private, max-age=3600 instead of no-store. A shared proxy or browser cache can replay post-logout account HTML, leaking order history, PII, and CSRF tokens to the next user on the same machine (CWE-525).",
    patch: "Cache-Control: no-store, private on all authenticated responses",
  },
  // Pillar 2 — CORS hardening (1)
  {
    id: "CORS-03",
    pillar: "cors",
    title: "CORS allow-list accepts 'null' origin",
    severity: "medium",
    evidence: "GET /api/me — Origin: null\nAccess-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true",
    explanation:
      "The allow-list matches the literal origin 'null', which sandboxed iframes, file:// documents, and redirect chains produce. Any of those contexts can issue credentialed reads against the API and read the responses.",
    patch: "Reject Origin: null with 403 and remove it from the allow-list (Vary: Origin preserved)",
  },
  // Pillar 3 — cookie hardening (1)
  {
    id: "CK-03",
    pillar: "cookies",
    title: "Session cookie lacks __Host- prefix",
    severity: "low",
    evidence: "Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
    explanation:
      "The cookie is otherwise well-scoped but lacks the __Host- prefix, so a subdomain takeover or sibling host can inject an identically-named cookie that wins for the parent domain. The prefix binds the cookie to host-only scope (cookie shadowing defense).",
    patch: "Set-Cookie: __Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
  },
  // Pillar 4 — fingerprinting & info leaks (3)
  {
    id: "FP-02",
    pillar: "fingerprint",
    title: "Directory listing on /uploads",
    severity: "medium",
    evidence: "GET /uploads/ HTTP/1.1 → 200 OK\nIndex of /uploads\n../\nbackup.sql            2026-01-12 12:04  4.2 MB\ncustomer_export.xlsx   2026-02-03 09:41  1.1 MB",
    explanation:
      "Apache autoindex is enabled, so any browser can browse the uploads tree and download backup dumps and exports that were never linked anywhere (CWE-548).",
    patch: "Virtual patch: disable directory indexes and 403 any path ending in '/' that resolves to a directory",
  },
  {
    id: "FP-03",
    pillar: "fingerprint",
    title: "Verbose error pages leak stack traces",
    severity: "medium",
    evidence: "POST /api/login → 500 Internal Server Error\nPDOException: SQLSTATE[42000] Syntax error\nin /var/www/html/app/db.php on line 42\nSQL: SELECT * FROM users WHERE email = 'a@a.com'",
    explanation:
      "display_errors is on in production. Stack traces reveal the framework, file layout, and full SQL — everything an attacker needs to craft targeted exploits (CWE-209).",
    patch: "Virtual patch: rewrite 5xx bodies to a generic page and log the full trace server-side only",
  },
  {
    id: "FP-04",
    pillar: "fingerprint",
    title: "Source repository (.git) exposed",
    severity: "high",
    evidence: "GET /.git/config HTTP/1.1 → 200 OK\n[core]\n\trepositoryformatversion = 0\n\t[remote \"origin\"]\n\turl = https://github.com/acme/storefront.git",
    explanation:
      "The .git directory is served over HTTP, letting anyone dump the entire source history — including credentials and secrets that were ever committed (CWE-540).",
    patch: "Virtual patch: 403 all dotfiles and /.git/* paths at the edge, plus deny rules in the origin config",
  },
  // Pillar 5 — injection surface (3)
  {
    id: "INJ-03",
    pillar: "injection",
    title: "Blind time-based SQLi in /api/orders sort",
    severity: "high",
    evidence: "GET /api/orders?sort=name;SELECT+SLEEP(5)-- HTTP/1.1\nresponse time: 5.03s (baseline 38ms)",
    explanation:
      "The sort parameter is interpolated into an ORDER BY clause. A time-based SLEEP probe confirms blind injection — data can be extracted one character at a time with no error output (CWE-89).",
    patch: "Virtual patch: whitelist sort keys + reject semicolons and control characters + CRS 942100 at edge",
  },
  {
    id: "INJ-04",
    pillar: "injection",
    title: "Path traversal in /api/download",
    severity: "high",
    evidence: "GET /api/download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\n200 OK — root:x:0:0:root:/root:/bin/bash (first 3 lines returned)",
    explanation:
      "The file parameter is joined to the uploads root without canonicalization, so encoded dot-dot segments escape the sandbox and read arbitrary server files (CWE-22).",
    patch: "Virtual patch: canonicalize + reject traversal sequences + CRS 930120 at edge",
  },
  {
    id: "INJ-05",
    pillar: "injection",
    title: "OS command injection in /api/ping",
    severity: "critical",
    evidence: "POST /api/ping\nhost=8.8.8.8;cat /etc/passwd\n200 OK — root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    explanation:
      "The host parameter is passed to a shell without validation. Semicolon-chained commands execute with the web server's privileges — full host compromise (CWE-78).",
    patch: "Virtual patch: allow-list host charset (IP/hostname only) + CRS 932160 at edge",
  },
  // Pillar 6 — rate limiting (2)
  {
    id: "RL-02",
    pillar: "ratelimit",
    title: "No throttling on /api/forgot-password",
    severity: "medium",
    evidence: "POST /api/forgot-password — 200 OK\n3,812 requests from 45.155.204.8 in 5 minutes — all processed",
    explanation:
      "The password-reset endpoint answers unlimited requests, enabling account enumeration (valid vs invalid emails) and mailbox flooding that drowns genuine reset emails.",
    patch: "Virtual patch: 5 req/min per IP + per-account cooldown + identical responses for valid/invalid emails",
  },
  {
    id: "RL-03",
    pillar: "ratelimit",
    title: "Unlimited 2FA code verification attempts",
    severity: "high",
    evidence: "POST /api/verify-otp — 200 OK\n38,000 attempts from 185.220.101.9 over 3h — a 6-digit code was brute-forced",
    explanation:
      "Verification codes are checked without attempt limits, so a 6-digit OTP (10^6 space) is practically brute-forceable in hours — the second factor is defeated entirely.",
    patch: "Virtual patch: 3 attempts then lock + expiring codes + IP rate limit + progressive backoff",
  },
];

/**
 * The canonical first-scan baseline (the classic 14 defects) — used for the
 * pre-scan seeded state and the seeded scan-history entry. Later scans are
 * generated dynamically from the full FINDING_POOL below.
 */
const CLASSIC_FINDING_IDS = [
  "HDR-01", "HDR-02", "HDR-03", "HDR-04", "HDR-05", "HDR-06",
  "CORS-01", "CORS-02",
  "CK-01", "CK-02",
  "FP-01",
  "INJ-01", "INJ-02",
  "RL-01",
];

export const BASELINE_FINDINGS: AuditFinding[] = BASE_FINDINGS
  .filter((f) => CLASSIC_FINDING_IDS.includes(f.id))
  .map((f) => ({ ...f, patched: false }));

/** Every id the scanner can ever produce — guards against phantom findings. */
export const FINDING_POOL_ID_SET = new Set(BASE_FINDINGS.map((f) => f.id));

export const COMPARISON: ComparisonRow[] = [
  { control: "Strict-Transport-Security", before: "Missing", after: "max-age=31536000; includeSubDomains; preload", fixed: true },
  { control: "Content-Security-Policy", before: "Missing", after: "default-src 'self'; script-src 'self'; frame-ancestors 'self'", fixed: true },
  { control: "X-Frame-Options", before: "Missing", after: "DENY", fixed: true },
  { control: "X-Content-Type-Options", before: "Missing", after: "nosniff", fixed: true },
  { control: "Referrer-Policy", before: "Missing", after: "strict-origin-when-cross-origin", fixed: true },
  { control: "Permissions-Policy", before: "Missing", after: "camera=(), microphone=(), geolocation=()", fixed: true },
  { control: "CORS", before: "Reflected Origin + credentials", after: "Origin allow-list + Vary: Origin", fixed: true },
  { control: "Server banner", before: "Apache/2.4.41 (Ubuntu) · PHP/7.4.33", after: "WebGuard Edge (cloaked)", fixed: true },
  { control: "Session cookie", before: "PHPSESSID=…; path=/", after: "HttpOnly; Secure; SameSite=Strict; __Host-", fixed: true },
  { control: "Injection surface", before: "Raw SQL concat / unsanitized reflection", after: "Parameterized queries + CRS 942100/941100", fixed: true },
  { control: "Rate limiting", before: "Unlimited /api/login attempts", after: "10 req/min + CAPTCHA escalation", fixed: true },
  { control: "Cache-Control (auth pages)", before: "private, max-age=3600", after: "no-store", fixed: true },
  { control: "Directory listing", before: "Enabled on /uploads", after: "Disabled (autoindex off)", fixed: true },
  { control: "Error pages", before: "Stack traces + SQL leaked", after: "Generic 500, traces server-side", fixed: true },
  { control: ".git / dotfile exposure", before: "GET /.git/config → 200", after: "403 at the edge", fixed: true },
];

// ============================================================================
// Dynamic scan generation — every Run Audit draws a fresh (target-seeded +
// randomized) subset from the finding pool, so re-scans genuinely surface
// vulnerabilities that were not in the register before. The score and the
// OWASP threat radar are derived from what this scan actually found.
// ============================================================================

/** Always-present findings so no scan can ever look trivially "clean". */
const CORE_FINDING_IDS = new Set(["HDR-01", "HDR-02", "CORS-01", "CK-01", "FP-01", "INJ-01", "INJ-02", "RL-01"]);

/** FNV-1a string hash → stable target-derived seed. */
export function hashSeed(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** Small deterministic PRNG (mulberry32) so a given seed always yields the same scan. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle<T>(arr: T[], rng: () => number): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

const SEVERITY_PENALTY: Record<Severity, number> = { critical: 9, high: 6, medium: 4, low: 1.5 };
const AXIS_CONTRIBUTION: Record<Severity, number> = { critical: 34, high: 22, medium: 13, low: 6 };

/** OWASP radar axes in display order — aligned with BASELINE_RADAR. */
export const RADAR_KEYS: { axis: string; key: OwaspAxis }[] = [
  { axis: "Injection", key: "injection" },
  { axis: "Broken Access Control", key: "access" },
  { axis: "Cryptographic Failures", key: "crypto" },
  { axis: "Security Misconfigurations", key: "misconfig" },
  { axis: "Insecure Design", key: "design" },
];

/** Pillar → OWASP axis fallback for pool entries without an explicit axis. */
function inferAxis(f: Pick<AuditFinding, "pillar">): OwaspAxis {
  switch (f.pillar) {
    case "injection":
      return "injection";
    case "cors":
      return "access";
    case "cookies":
      return "crypto";
    case "ratelimit":
      return "design";
    default:
      return "misconfig";
  }
}

/** Posture score derived from the findings this scan actually discovered. */
export function scoreForFindings(findings: AuditFinding[]): number {
  const penalty = findings.reduce((s, f) => s + SEVERITY_PENALTY[f.severity], 0);
  return Math.max(5, Math.min(100, Math.round(100 - penalty)));
}

/** OWASP threat radar derived from the discovered findings' severity + axis. */
export function radarForFindings(findings: AuditFinding[]): RadarAxis[] {
  const sums: Record<OwaspAxis, number> = { injection: 0, access: 0, crypto: 0, misconfig: 0, design: 0 };
  const present = new Set<OwaspAxis>();
  for (const f of findings) {
    const axis = f.axis ?? inferAxis(f);
    present.add(axis);
    sums[axis] += AXIS_CONTRIBUTION[f.severity];
  }
  return RADAR_KEYS.map(({ axis, key }) => ({
    axis,
    value: present.has(key) ? Math.min(100, Math.round(sums[key])) : 6,
  }));
}

/**
 * Build one scan's findings: the 8 core defects always land, and each optional
 * pool finding is included with ~55% probability. Seeding the PRNG with the
 * target hash + a run nonce means the same target tends to resurface the same
 * families while every click still varies the exact set discovered.
 */
export function generateAudit(
  target: string,
  runNonce?: number,
): { findings: AuditFinding[]; score: number; radar: RadarAxis[] } {
  const seed = hashSeed(target) ^ (runNonce ?? Math.floor(Math.random() * 0x7fffffff));
  const rng = mulberry32(seed);
  const selected: typeof BASE_FINDINGS = [];
  const extras: typeof BASE_FINDINGS = [];
  for (const f of BASE_FINDINGS) (CORE_FINDING_IDS.has(f.id) ? selected : extras).push(f);
  for (const f of shuffle(extras, rng)) {
    if (rng() < 0.55) selected.push(f);
  }
  const sevRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  selected.sort((a, b) => a.pillar.localeCompare(b.pillar) || sevRank[a.severity] - sevRank[b.severity]);
  const findings: AuditFinding[] = selected.map((f) => ({ ...f, patched: false }));
  return { findings, score: scoreForFindings(findings), radar: radarForFindings(findings) };
}

export const BASELINE_RADAR: RadarAxis[] = [
  { axis: "Injection", value: 92 },
  { axis: "Broken Access Control", value: 78 },
  { axis: "Cryptographic Failures", value: 65 },
  { axis: "Security Misconfigurations", value: 84 },
  { axis: "Insecure Design", value: 58 },
];

export const CLEARED_RADAR: RadarAxis[] = BASELINE_RADAR.map((r) => ({ ...r, value: Math.round(r.value * 0.09) }));

export const EMPTY_RADAR: RadarAxis[] = BASELINE_RADAR.map((r) => ({ ...r, value: 0 }));

// ============================================================================
// Copilot intelligence
// ============================================================================

export function copilotIntel(attackType: AttackType | null): CopilotIntel {
  if (!attackType) {
    return {
      intent: "Normal application traffic",
      attackBreakdown: [
        "The request matches no known malicious signature.",
        "Shannon entropy and TF-IDF classifier both scored below the decision boundary.",
        "The client passed IP reputation, rate-limit, and honeytoken checks.",
      ],
      rootCause: "No vulnerability exercised — this is a legitimate user request that should reach the origin unchanged.",
      postMortem:
        "Executive summary: no security event. The request was validated against all six inspection stages and classified as benign with high confidence. No action required; traffic continues to flow at nominal latency.",
      code: [],
    };
  }
  const spec = ATTACK_SPEC_BY_TYPE[attackType];
  const perType: Record<AttackType, Omit<CopilotIntel, "code">> = {
    sqli: {
      intent: "Data exfiltration / authentication bypass",
      attackBreakdown: [
        `Payload '${spec.payload}' exploits string concatenation in the ${spec.path} endpoint.`,
        "The single-quote breaks out of the SQL string literal; the OR 1=1 tautology neutralizes the WHERE clause.",
        "Blind or error-based variants can dump the full users table one byte at a time.",
      ],
      rootCause:
        "The origin builds SQL by string concatenation ('SELECT * FROM products WHERE id = \" + id + \"'). Parameterized queries or ORMs with bound parameters eliminate the injection class entirely.",
      postMortem:
        "An unauthenticated attacker probed the search endpoint with SQL tautologies in an attempt to dump the product catalog and enumerate credentials. WebGuard's CRS rule 942100 matched and dropped the request at the edge before it reached the origin. No data was exposed; the virtual patch remains active and the origin should be migrated to parameterized queries as the permanent fix.",
    },
    xss: {
      intent: "Session hijacking / client-side compromise",
      attackBreakdown: [
        `Reflected <script> payload injected via ${spec.path}.`,
        "If echoed unescaped, the script runs in the victim's browser origin and can read document.cookie.",
        "The attacker chains this with social engineering to target operators and customers.",
      ],
      rootCause:
        "The origin echoes query parameters into HTML without context-aware encoding. React/Next auto-escape, but server-rendered templates and dangerouslySetInnerHTML-style sinks do not.",
      postMortem:
        "A script-bearing search query was submitted to probe reflection points in the application. WebGuard blocked the request under rule 941100 before the payload reached any user's browser. The edge virtual patch encodes output at the proxy layer while the development team replaces the reflection sink with framework-native escaping.",
    },
    cmdi: {
      intent: "Remote code execution / server takeover",
      attackBreakdown: [
        `Payload '${spec.payload}' chains an OS command after a legitimate host value using ';'.`,
        "The target endpoint pipes the parameter into system() or shell_exec(), executing 'cat /etc/passwd' on the origin host.",
        "Successful exploitation escalates from data read to full shell access on the origin.",
      ],
      rootCause:
        "The origin passes user input to an OS shell. Command execution should never receive raw input: use an allow-listed argument array with execFile/spawn and no shell interpretation.",
      postMortem:
        "An attacker attempted remote command execution against the diagnostics endpoint by chaining /etc/passwd exfiltration after a benign hostname. WebGuard rule 932160 flagged the shell metacharacters and dropped the connection with 403. The origin process was never reached; the endpoint should be rewritten to avoid shell invocation.",
    },
    "path-traversal": {
      intent: "Arbitrary file read",
      attackBreakdown: [
        `Dot-dot-slash traversal '${spec.payload}' climbs beyond the intended uploads directory.`,
        "Each ../ resolves one directory level; ../../../../etc/passwd lands on the filesystem root.",
        "Scanners automate this across every file parameter to map the origin's filesystem.",
      ],
      rootCause:
        "The origin joins user input directly onto a filesystem path. Canonicalize the resolved path and verify it stays inside the configured document root before opening any file.",
      postMortem:
        "Automated reconnaissance attempted to retrieve /etc/passwd through the file download endpoint. WebGuard rule 930120 detected the traversal sequence and returned 403. Filesystem access was never granted; the origin should canonicalize paths and enforce a sandboxed base directory.",
    },
    "high-entropy": {
      intent: "Webshell / malware staging",
      attackBreakdown: [
        "Base64 blob with a PK (ZIP) magic header disguised as a benign upload.",
        "High Shannon entropy indicates encoded/compressed content — legitimate text payloads rarely exceed 4.5 bits/char.",
        "Deployed via a second request, the archive extracts into a PHP webshell on the origin.",
      ],
      rootCause:
        "The origin accepts binary uploads without content inspection. Entropy analysis plus magic-byte and MIME validation at the proxy catches encoded payloads that signature rules miss.",
      postMortem:
        "An encoded archive was uploaded to the file ingestion endpoint in a staging pattern consistent with webshell deployment. The ML entropy classifier scored 6.1 bits/char against a 0.85 decision boundary and WebGuard quarantined the payload. No file reached the origin; upload validation and content-type allow-listing are recommended as permanent controls.",
    },
    bot: {
      intent: "Credential stuffing / brute force",
      attackBreakdown: [
        "Headless client hammering /wp-login.php with spoofed browser fingerprints.",
        "Rapid identical request patterns and missing JavaScript challenge evidence mark this as automated.",
        "Account lockouts get bypassed by rotating IPs across the /24 subnet.",
      ],
      rootCause:
        "Login endpoints without rate limiting or bot challenges are free to brute-force. Detection-mode WAFs that log instead of act give attackers unlimited attempts.",
      postMortem:
        "A bot farm targeted the authentication endpoint at sustained velocity. WebGuard identified the automated pattern and applied the configured challenge policy; sustained offenders were throttled with 429 responses. No credentials were compromised.",
    },
    scanner: {
      intent: "Pre-attack reconnaissance",
      attackBreakdown: [
        "Probing /.env, /.git/config, /phpmyadmin/ and similar high-value files.",
        "Single requests from many IPs — classic distributed recon designed to evade naive rate limits.",
        "Feeds a target map used to sequence the actual exploit later.",
      ],
      rootCause:
        "Exposed configuration files and default admin panels are the payoff. Scanning succeeds when the origin answers 200 with real content; the WAF should cloak or deny these paths outright.",
      postMortem:
        "Distributed reconnaissance probed for exposed configuration and admin endpoints. WebGuard's scanner fingerprinting returned 403 for all sensitive paths. The origin should remove any stray .env / .git artifacts and relocate admin panels off default paths.",
    },
  };
  return {
    ...perType[attackType],
    code: codeSnippets(attackType),
  };
}

function codeSnippets(attackType: AttackType): CopilotIntel["code"] {
  if (attackType === "sqli") {
    return [
      {
        language: "python",
        label: "Python (psycopg2)",
        snippet: `# Parameterized query — never concatenate user input
cursor.execute(
    "SELECT * FROM products WHERE id = %s",
    (request_id,),   # bound parameter, driver escapes it
)`,
      },
      {
        language: "node",
        label: "Node.js / Express",
        snippet: `// Use bound parameters (pg / mysql2)
const rows = await pool.query(
  "SELECT * FROM products WHERE id = $1",
  [req.query.id],   // parameterized — safe by construction
);`,
      },
      {
        language: "php",
        label: "PHP (PDO)",
        snippet: `// PDO prepared statement
$stmt = $pdo->prepare("SELECT * FROM products WHERE id = ?");
$stmt->execute([$_GET['id']]);   // never inline into SQL`,
      },
      {
        language: "java",
        label: "Java (Spring)",
        snippet: `// JdbcTemplate binds parameters safely
List<Product> products = jdbc.query(
    "SELECT * FROM products WHERE id = ?",
    (rs, i) -> new Product(rs),
    requestId   // bound argument
);`,
      },
    ];
  }
  if (attackType === "xss") {
    return [
      {
        language: "python",
        label: "Python (Jinja2)",
        snippet: `# Jinja2 auto-escapes by default — never use |safe on user data
return render_template("search.html", q=user_input)
# In template: <h1>{{ q }}</h1>  → escaped automatically`,
      },
      {
        language: "node",
        label: "Node.js / Express",
        snippet: `// React/Next auto-escape text children
return <h1>{searchQuery}</h1>;   // safe
// Avoid: <div dangerouslySetInnerHTML={{ __html: searchQuery }} />`,
      },
      {
        language: "php",
        label: "PHP (htmlspecialchars)",
        snippet: `<?php echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8'); ?>`,
      },
      {
        language: "java",
        label: "Java (Spring / Thymeleaf)",
        snippet: `// Thymeleaf escapes text by default
<h1 th:text="\${searchQuery}">results</h1>
// Never use th:utext for user-supplied values`,
      },
    ];
  }
  if (attackType === "cmdi") {
    return [
      {
        language: "python",
        label: "Python (subprocess)",
        snippet: `# subprocess.run with a LIST — no shell interpretation
import subprocess
subprocess.run(["ping", "-c", "1", host], check=False)
# NEVER: subprocess.run(f"ping -c 1 {host}", shell=True)`,
      },
      {
        language: "node",
        label: "Node.js (execFile)",
        snippet: `// execFile — no shell involved
const { execFile } = require("node:child_process");
execFile("ping", ["-c", "1", host], cb);
// NEVER: exec(\`ping -c 1 \${host}\`)`,
      },
      {
        language: "php",
        label: "PHP (escapeshellarg)",
        snippet: `<?php
// Whitelist + shell-arg escaping as a last resort
$host = escapeshellarg(filter_var($_POST['host'], FILTER_VALIDATE_IP));
$out = shell_exec("ping -c 1 " . $host);`,
      },
      {
        language: "java",
        label: "Java (ProcessBuilder)",
        snippet: `// ProcessBuilder takes a command list — no shell
Process p = new ProcessBuilder("ping", "-c", "1", host).start();
// NEVER: Runtime.getRuntime().exec("ping -c 1 " + host)`,
      },
    ];
  }
  return [
    {
      language: "generic",
      label: "Proxy-level patch",
      snippet: `# WebGuard virtual patch (already active)
# 1. Canonicalize + sandbox file paths
# 2. Reject dot-dot-slash sequences, encoded variants (%2e%2e/)
# 3. Validate magic bytes + MIME allow-list on uploads
# 4. Serve CAPTCHA to automated clients on sensitive paths`,
    },
  ];
}

// ============================================================================
// Seed data: alarms, incidents, canaries, rules
// ============================================================================

export const SEED_RULES: RuleSetting[] = [
  { id: "sqli", label: "SQL Injection", ruleIds: "942100 · 942110", action: "block" },
  { id: "xss", label: "Cross-Site Scripting", ruleIds: "941100 · 941130", action: "block" },
  { id: "cmdi", label: "Command Injection", ruleIds: "932160 · 932170", action: "block" },
  { id: "path-traversal", label: "Path Traversal", ruleIds: "930120 · 930110", action: "block" },
  { id: "bots", label: "Bad Bot Crawlers", ruleIds: "BOT-001 · SCAN-002", action: "challenge" },
];

export function seedAlarms(now: number): Alarm[] {
  return [
    {
      id: "AL-1001",
      severity: "critical",
      title: "SQLi burst on /api/search — 41 attempts in 60s",
      source: "91.134.22.7 · Frankfurt",
      ts: now - 42_000,
      state: "active",
      detail: "OWASP-CRIT-942100 matched 41 requests carrying ' OR 1=1-- tautologies. Origin untouched; all dropped with 403.",
      ruleId: "OWASP-CRIT-942100",
      sourceIp: "91.134.22.7",
      countryCode: "DE",
    },
    {
      id: "AL-1002",
      severity: "high",
      title: "Command injection probe on /api/ping",
      source: "45.155.4.12 · Frankfurt",
      ts: now - 118_000,
      state: "acknowledged",
      detail: "Rule 932160 flagged ';cat /etc/passwd' payload chained after a benign host parameter.",
      ruleId: "OWASP-CRIT-932160",
      sourceIp: "45.155.4.12",
      countryCode: "DE",
    },
    {
      id: "AL-1003",
      severity: "high",
      title: "High-entropy archive upload quarantined",
      source: "159.65.81.9 · Singapore",
      ts: now - 264_000,
      state: "active",
      detail: "ML classifier scored 6.1 bits/char (threshold 0.85) on a Base64 blob with PK magic header.",
      ruleId: "ML-ENTROPY-001",
      sourceIp: "159.65.81.9",
      countryCode: "SG",
    },
    {
      id: "AL-1004",
      severity: "medium",
      title: "Distributed scanner sweep detected",
      source: "Multi-origin · 7 /24 blocks",
      ts: now - 540_000,
      state: "snoozed",
      detail: "Probes for /.env, /.git/config and /phpmyadmin/ from rotating IPs across 7 subnets.",
      ruleId: "SCAN-DETECT-002",
      sourceIp: "103.5.140.22",
      countryCode: "JP",
    },
    {
      id: "AL-1005",
      severity: "low",
      title: "Rate threshold approached on /api/login",
      source: "92.40.19.8 · London",
      ts: now - 900_000,
      state: "resolved",
      detail: "Login attempts reached 78% of the configured 10 req/min policy before normalizing.",
      ruleId: "RL-POLICY-001",
      sourceIp: "92.40.19.8",
      countryCode: "GB",
    },
    // historical — resolved noise that fills the 12h volume chart
    { id: "AL-1006", severity: "medium", title: "XSS sweep against /search", source: "185.220.101.34 · Berlin", ts: now - 3_600_000, state: "resolved", detail: "Script-bearing query strings probed across 12 parameter names; all reflected payloads neutralised.", ruleId: "OWASP-CRIT-941100", sourceIp: "185.220.101.34", countryCode: "DE" },
    { id: "AL-1007", severity: "high", title: "Credential stuffing ramp on /api/login", source: "45.155.4.12 · Frankfurt", ts: now - 5_400_000, state: "resolved", detail: "Velocity climbed to 4.2 req/s from a single session before the bot policy throttled the source.", ruleId: "BOT-POLICY-003", sourceIp: "45.155.4.12", countryCode: "DE" },
    { id: "AL-1008", severity: "low", title: "Sensitive-path probe /.env", source: "103.5.140.22 · Tokyo", ts: now - 7_200_000, state: "resolved", detail: "Single .env lookup from a known scanner subnet; response cloaked, source logged.", ruleId: "SCAN-DETECT-002", sourceIp: "103.5.140.22", countryCode: "JP" },
    { id: "AL-1009", severity: "critical", title: "Command injection chain on /api/ping", source: "128.199.44.2 · Singapore", ts: now - 9_000_000, state: "resolved", detail: "Semicolon-chained shell metacharacters; 9 variants blocked by OWASP-CRIT-932160 in 90s.", ruleId: "OWASP-CRIT-932160", sourceIp: "128.199.44.2", countryCode: "SG" },
    { id: "AL-1010", severity: "medium", title: "JWT tampering attempts blocked", source: "133.242.7.101 · Tokyo", ts: now - 10_800_000, state: "resolved", detail: "Signature-forged tokens rejected by the edge JWKS validator across /api/v2 endpoints.", ruleId: "JWT-VALID-004", sourceIp: "133.242.7.101", countryCode: "JP" },
  ];
}

export function seedIncidents(now: number): Incident[] {
  return [
    {
      id: "INC-501",
      title: "Credential stuffing campaign against /api/login",
      vector: "Bad Bot",
      severity: "critical",
      sourceIp: "45.155.4.12",
      country: "DE",
      stage: "investigating",
      openedAt: now - 90_000,
      closedAt: null,
      detail: "Distributed botnet rotating IPs across three /24 blocks. 2,180 attempts in 12 minutes; 9 accounts locked.",
      playbook: null,
    },
    {
      id: "INC-502",
      title: "Reflected XSS probe on /search",
      vector: "Cross-Site Scripting",
      severity: "high",
      sourceIp: "128.199.44.2",
      country: "SG",
      stage: "mitigated",
      openedAt: now - 340_000,
      closedAt: null,
      detail: "Script-bearing queries reflected off the search endpoint. Edge encoding patch deployed; origin fix pending.",
      playbook: "lockdown",
    },
    {
      id: "INC-503",
      title: "Webshell staging upload detected",
      vector: "High-Entropy Payload",
      severity: "high",
      sourceIp: "159.65.81.9",
      country: "SG",
      stage: "investigating",
      openedAt: now - 700_000,
      closedAt: null,
      detail: "Base64 PK archive matched entropy classifier. Upload sandboxing reviewed — no file reached origin.",
      playbook: null,
    },
    {
      id: "INC-504",
      title: "Path traversal sweep of download API",
      vector: "Path Traversal",
      severity: "medium",
      sourceIp: "133.242.7.101",
      country: "JP",
      stage: "resolved",
      openedAt: now - 3_600_000,
      closedAt: now - 2_940_000,
      detail: "../../../../etc/passwd probes against /api/download. All 14 requests blocked by rule 930120.",
      playbook: "quarantine",
    },
    {
      id: "INC-505",
      title: "Recon scan of admin infrastructure",
      vector: "Recon Scanner",
      severity: "low",
      sourceIp: "103.5.140.22",
      country: "JP",
      stage: "resolved",
      openedAt: now - 8_600_000,
      closedAt: now - 7_980_000,
      detail: "Scan of /.env, /backup/ and default admin paths. Sensitive paths now return 403 by policy.",
      playbook: null,
    },
  ];
}

export function seedCanaries(now: number): CanaryToken[] {
  return [
    { id: "CAN-001", key: "<!-- wg-canary:a3f9c2 -->", placement: "HTML comment (homepage)", trips: 3, lastIp: "91.134.22.7", banned: true, createdAt: now - 86_400_000 },
    { id: "CAN-002", key: '<input type="hidden" name="wg_trap" value="f7e1b4">', placement: "Hidden form input (login)", trips: 1, lastIp: "159.65.81.9", banned: false, createdAt: now - 43_200_000 },
    { id: "CAN-003", key: "X-WebGuard-Canary: 88d1a0e2", placement: "Custom response header", trips: 2, lastIp: "45.155.4.12", banned: false, createdAt: now - 21_600_000 },
  ];
}

export function seedCanaryTrips(now: number): CanaryTrip[] {
  return [
    { id: "CT-01", tokenId: "CAN-001", ip: "91.134.22.7", ts: now - 86_000_000 },
    { id: "CT-02", tokenId: "CAN-001", ip: "91.134.23.9", ts: now - 86_000_040 },
    { id: "CT-03", tokenId: "CAN-001", ip: "91.134.22.7", ts: now - 85_999_980 },
    { id: "CT-04", tokenId: "CAN-002", ip: "159.65.81.9", ts: now - 2_100_000 },
    { id: "CT-05", tokenId: "CAN-003", ip: "45.155.4.12", ts: now - 900_000 },
  ];
}

// ============================================================================
// Seed data: vulnerability register + access control
// ============================================================================

export function seedFindings(now: number): VulnFinding[] {
  return [
    {
      id: "audit:HDR-01",
      title: "Missing HSTS header",
      severity: "high",
      source: "audit",
      status: "open",
      discoveredAt: now - 7_200_000,
      lastSeen: now - 7_200_000,
      count: 1,
      evidence: "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)\n(no Strict-Transport-Security header present)",
      patch: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      ruleId: "HDR-01",
      path: null,
      pillar: "headers",
    },
    {
      id: "audit:INJ-01",
      title: "Reflected SQL parameter in /api/search",
      severity: "critical",
      source: "audit",
      status: "open",
      discoveredAt: now - 7_200_000,
      lastSeen: now - 7_200_000,
      count: 1,
      evidence: "GET /api/search?id=1' OR 1=1-- HTTP/1.1\n200 OK — 1,482 rows returned",
      patch: "Virtual patch: parameterized query + input validation (^[0-9]+$) + OWASP CRS rule 942100 enforced at edge",
      ruleId: "INJ-01",
      path: "/api/search",
      pillar: "injection",
    },
    {
      id: "live:OWASP-CRIT-942100:/api/search",
      title: "SQL Injection against /api/search",
      severity: "critical",
      source: "live",
      status: "open",
      discoveredAt: now - 300_000,
      lastSeen: now - 45_000,
      count: 41,
      evidence: "GET /api/search?id=1' OR 1=1--\nrule OWASP-CRIT-942100 · 91.134.22.7 (Germany) · entropy 3.42 bits/char\nverdict: 403 BLOCKED at edge",
      patch: "Enforce OWASP-CRIT-942100 at the edge · reject payload pattern 'OR 1=1'",
      ruleId: "OWASP-CRIT-942100",
      path: "/api/search",
      pillar: null,
    },
    {
      id: "live:ML-ENTROPY-001:/api/upload",
      title: "High-Entropy Payload against /api/upload",
      severity: "high",
      source: "live",
      status: "investigating",
      discoveredAt: now - 600_000,
      lastSeen: now - 264_000,
      count: 3,
      evidence: "POST /api/upload\nrule ML-ENTROPY-001 · 159.65.81.9 (Singapore) · entropy 6.10 bits/char\nverdict: 403 BLOCKED at edge",
      patch: "Enforce ML-ENTROPY-001 at the edge · reject payload pattern 'UEsDBAo'",
      ruleId: "ML-ENTROPY-001",
      path: "/api/upload",
      pillar: null,
    },
    {
      id: "audit:RL-01",
      title: "No rate limiting on /api/login",
      severity: "critical",
      source: "audit",
      status: "open",
      discoveredAt: now - 7_200_000,
      lastSeen: now - 7_200_000,
      count: 1,
      evidence: "POST /api/login — 200 OK\n12,400 requests from 91.134.22.7 in 90s — all processed",
      patch: "Virtual patch: 10 req/min per IP + progressive lockout + CAPTCHA challenge above threshold",
      ruleId: "RL-01",
      path: "/api/login",
      pillar: "ratelimit",
    },
  ];
}

export function seedBlocklist(now: number): BlockedIp[] {
  return [
    { id: "BAN-001", ip: "91.134.22.0/24", reason: "Auto-ban — 6+ blocked requests from subnet", source: "auto", country: "Germany", countryCode: "DE", addedAt: now - 360_000, hits: 14, active: true, expiresAt: null },
    { id: "BAN-002", ip: "45.155.4.12", reason: "Canary tripped ×3 — HTML comment (homepage)", source: "canary", country: "Germany", countryCode: "DE", addedAt: now - 86_000_000, hits: 5, active: true, expiresAt: null },
    { id: "BAN-003", ip: "159.65.81.9", reason: "Manual ban — repeated webshell upload attempts", source: "manual", country: "Singapore", countryCode: "SG", addedAt: now - 1_800_000, hits: 3, active: true, expiresAt: null },
    { id: "BAN-004", ip: "103.5.140.0/24", reason: "Auto-ban — distributed recon sweep", source: "auto", country: "Japan", countryCode: "JP", addedAt: now - 5_400_000, hits: 22, active: true, expiresAt: null },
  ];
}

export const SEED_CUSTOM_RULES: CustomRule[] = [
  { id: "CR-01", name: "Block /admin panel", matchType: "path", matchValue: "/admin", action: "block", enabled: true, hits: 312 },
  { id: "CR-02", name: "Deny curl tooling", matchType: "ua", matchValue: "curl", action: "block", enabled: true, hits: 48 },
  { id: "CR-03", name: "Challenge RU datacenter traffic", matchType: "country", matchValue: "ru", action: "challenge", enabled: true, hits: 97 },
  { id: "CR-04", name: "Block PHP file requests", matchType: "path", matchValue: ".php", action: "block", enabled: false, hits: 0 },
];

export function seedIntegrations(): IntegrationChannel[] {
  return [
    {
      id: "slack",
      label: "Slack",
      hint: "Critical alarms + incident auto-open alerts",
      enabled: true,
      target: "https://hooks.slack.com/services/T000000/B000000/xxxxxxxx",
      placeholder: "https://hooks.slack.com/services/…",
    },
    {
      id: "pagerduty",
      label: "PagerDuty",
      hint: "Escalate high & critical incidents to on-call",
      enabled: false,
      target: "",
      placeholder: "Integration key (Events API v2)…",
    },
    {
      id: "email",
      label: "Email digest",
      hint: "Daily posture summary + weekly vulnerability digest",
      enabled: false,
      target: "soc@example.com",
      placeholder: "soc@example.com",
    },
    {
      id: "webhook",
      label: "Generic webhook",
      hint: "POST JSON for every blocked request (sampled)",
      enabled: true,
      target: "https://collector.example.com/wg-events",
      placeholder: "https://your-endpoint.example.com/events",
    },
  ];
}

export const PLAYBOOKS: {
  id: "quarantine" | "throttle" | "lockdown";
  name: string;
  description: string;
  icon: string;
}[] = [
  {
    id: "quarantine",
    name: "Subnet /24 Quarantine",
    description: "Ban the entire /24 IP block at the edge. Drops 100% of traffic from the subnet for 24h.",
    icon: "ShieldBan",
  },
  {
    id: "throttle",
    name: "Aggressive Path Throttling",
    description: "Cut the target path's rate limit to 5 req/min and escalate repeat offenders to CAPTCHA.",
    icon: "TimerReset",
  },
  {
    id: "lockdown",
    name: "Parameter Lockdown",
    description: "Deploy an instant virtual patch that strict-validates the offending parameter and rejects payloads.",
    icon: "Lock",
  },
];

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function gradeForScore(score: number): { grade: string; color: string; label: string } {
  if (score >= 95) return { grade: "A+", color: "#34d399", label: "Excellent" };
  if (score >= 90) return { grade: "A", color: "#34d399", label: "Excellent" };
  if (score >= 80) return { grade: "B", color: "#a3e635", label: "Good" };
  if (score >= 70) return { grade: "C", color: "#facc15", label: "Fair" };
  if (score >= 60) return { grade: "D", color: "#fb923c", label: "Weak" };
  return { grade: "F", color: "#f43f5e", label: "Critical" };
}
