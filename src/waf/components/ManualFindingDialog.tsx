import { useState } from "react";
import type { ReactNode } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { PILLARS } from "../data";
import { uid, useWaf } from "../engine";
import type { FindingStatus, Severity, VulnFinding } from "../types";
import { SEVERITY_META } from "../types";
import { ClipboardPlus, Wand2 } from "lucide-react";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const STATUSES: Array<{ id: FindingStatus; label: string }> = [
  { id: "open", label: "Open" },
  { id: "investigating", label: "Investigating" },
  { id: "patched", label: "Patched" },
  { id: "fixed", label: "Fixed" },
];

interface ManualFindingDraft {
  title: string;
  severity: Severity;
  status: FindingStatus;
  pillar: string;
  path: string;
  ruleId: string;
  count: string;
  evidence: string;
  patch: string;
  owner: string;
  tags: string;
  notes: string;
}

const EMPTY: ManualFindingDraft = {
  title: "",
  severity: "high",
  status: "open",
  pillar: "custom",
  path: "",
  ruleId: "",
  count: "1",
  evidence: "",
  patch: "",
  owner: "",
  tags: "",
  notes: "",
};

const PRESETS: Array<{ label: string; draft: Partial<ManualFindingDraft> }> = [
  {
    label: "Missing HSTS",
    draft: {
      title: "Missing Strict-Transport-Security header on production",
      severity: "high",
      pillar: "headers",
      path: "/",
      ruleId: "HDR-HSTS",
      evidence: "GET / HTTP/1.1\nHTTP/1.1 200 OK\n(no Strict-Transport-Security header present)",
      patch: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
  },
  {
    label: "Open admin panel",
    draft: {
      title: "Unauthenticated admin panel reachable",
      severity: "critical",
      pillar: "access",
      path: "/admin/",
      ruleId: "ACL-ADMIN",
      evidence: "GET /admin/ HTTP/1.1\nHTTP/1.1 200 OK\n(no authentication challenge returned)",
      patch: "Require authentication + MFA on /admin/* · deny from edge with 403 unless allowlisted",
    },
  },
  {
    label: "Exposed .env",
    draft: {
      title: "Backup / dotfile leak — .env accessible",
      severity: "critical",
      pillar: "fingerprint",
      path: "/.env.bak",
      ruleId: "FP-DOTFILE",
      evidence: "GET /.env.bak HTTP/1.1\nHTTP/1.1 200 OK\nContent-Type: application/octet-stream",
      patch: "Block dotfiles & backups at the edge · rule: path starts with /. reject 403",
    },
  },
  {
    label: "Weak TLS cipher",
    draft: {
      title: "TLS 1.0 / weak cipher suite allowed",
      severity: "medium",
      pillar: "crypto",
      path: "/",
      ruleId: "TLS-CIPHER",
      evidence: "Handshake offered: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (TLS 1.0)",
      patch: "Disable TLS < 1.2 at the edge · enforce TLS_ECDHE_* suites only",
    },
  },
  {
    label: "Verbose errors",
    draft: {
      title: "Verbose stack traces leaked to clients",
      severity: "medium",
      pillar: "fingerprint",
      path: "/api/orders/999999",
      ruleId: "FP-STACK",
      evidence: "GET /api/orders/999999 HTTP/1.1\nHTTP/1.1 500\n... at App\\Controllers\\OrderController.php:142",
      patch: "Strip server stack traces · generic error pages · log full details server-side only",
    },
  },
  {
    label: "IDOR",
    draft: {
      title: "Insecure direct object reference on resource endpoint",
      severity: "high",
      pillar: "access",
      path: "/api/download?id=",
      ruleId: "ACL-IDOR",
      evidence: "GET /api/download?id=1042 HTTP/1.1\nHTTP/1.1 200 OK (no ownership check on id)",
      patch: "Enforce object-ownership checks · rate-limit + challenge on enumeration patterns",
    },
  },
];

export function ManualFindingDialog({
  trigger,
  className,
}: {
  /** Custom trigger node (rendered inside a DialogTrigger). Defaults to a styled button. */
  trigger?: ReactNode;
  className?: string;
}) {
  const { dispatch } = useWaf();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<ManualFindingDraft>(EMPTY);
  const [error, setError] = useState<string | null>(null);

  const set = <K extends keyof ManualFindingDraft>(key: K, value: ManualFindingDraft[K]) => {
    setDraft((d) => ({ ...d, [key]: value }));
    if (key === "title" && value) setError(null);
  };

  const applyPreset = (p: (typeof PRESETS)[number]) => {
    setDraft((d) => ({ ...EMPTY, ...p.draft, title: d.title || p.draft.title || "" }));
    setError(null);
  };

  const reset = () => {
    setDraft(EMPTY);
    setError(null);
  };

  const submit = () => {
    const title = draft.title.trim();
    if (!title) {
      setError("Give the finding a title so the register stays readable.");
      return;
    }
    const count = Math.max(1, Math.min(999_999, parseInt(draft.count, 10) || 1));
    const now = Date.now();
    const owner = draft.owner.trim();
    const tags = draft.tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .slice(0, 12);
    const notes = draft.notes.trim();
    const finding: VulnFinding = {
      id: uid("MAN"),
      title,
      severity: draft.severity,
      source: "manual",
      status: draft.status,
      discoveredAt: now,
      lastSeen: now,
      count,
      evidence:
        draft.evidence.trim() ||
        `Manually logged by the security team\nTarget: ${"WebGuard console"}\nNo raw HTTP evidence captured — finding reported out-of-band.`,
      patch:
        draft.patch.trim() ||
        "Review the affected control and apply the fix at the origin, then mark this finding FIXED.",
      ruleId: draft.ruleId.trim() || null,
      path: draft.path.trim() || null,
      pillar: draft.pillar === "custom" ? null : draft.pillar,
      ...(owner ? { owner } : {}),
      ...(tags.length > 0 ? { tags } : {}),
      ...(notes ? { notes } : {}),
    };
    dispatch({ type: "ADD_FINDING", finding });
    toast.success("Manual finding added to the register", {
      description: `${finding.title} · ${SEVERITY_META[finding.severity].label} · source MANUAL`,
    });
    setOpen(false);
    reset();
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) reset();
      }}
    >
      <DialogTrigger asChild>
        {trigger ?? (
          <Button
            variant="outline"
            size="sm"
            className={cn(
              "h-8 gap-1.5 border-wg-amber/40 bg-wg-amber/10 text-wg-amber hover:bg-wg-amber/20 hover:text-wg-amber",
              className,
            )}
          >
            <ClipboardPlus className="size-3.5" /> Add finding
          </Button>
        )}
      </DialogTrigger>

      <DialogContent className="max-h-[88vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ClipboardPlus className="size-4 text-wg-amber" /> Add finding manually
          </DialogTitle>
          <DialogDescription>
            Anything the scanner missed — or anything you know about that isn't in the automated register — can be logged
            here with source MANUAL so it stays in the same triage pipeline.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          {/* quick presets */}
          <div>
            <p className="mb-1.5 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
              <Wand2 className="size-3" /> Quick start templates
            </p>
            <div className="flex flex-wrap gap-1.5">
              {PRESETS.map((p) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => applyPreset(p)}
                  className="rounded-md border border-border/50 bg-muted/40 px-2 py-1 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-wg-amber/40 hover:bg-wg-amber/10 hover:text-wg-amber"
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <Label htmlFor="mf-title" className="text-[11px] font-semibold text-foreground/80">
                Finding title <span className="text-wg-rose">*</span>
              </Label>
              <Input
                id="mf-title"
                value={draft.title}
                onChange={(e) => set("title", e.target.value)}
                placeholder="e.g. Broken object-level authorization on /api/orders/:id"
                className={cn(
                  "mt-1 h-9 border-border/60 bg-muted/40 text-xs focus-visible:ring-amber-400/40",
                  error && "border-wg-rose/60",
                )}
              />
              {error && <p className="mt-1 text-[10px] font-medium text-wg-rose">{error}</p>}
            </div>

            <div>
              <Label htmlFor="mf-sev" className="text-[11px] font-semibold text-foreground/80">
                Severity
              </Label>
              <Select value={draft.severity} onValueChange={(v) => set("severity", v as Severity)}>
                <SelectTrigger id="mf-sev" size="sm" className="mt-1 w-full border-border/60 bg-muted/40 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      <span className="flex items-center gap-2">
                        <span className="size-2 rounded-full" style={{ background: SEVERITY_META[s].color }} />
                        {SEVERITY_META[s].label}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="mf-status" className="text-[11px] font-semibold text-foreground/80">
                Status
              </Label>
              <Select value={draft.status} onValueChange={(v) => set("status", v as FindingStatus)}>
                <SelectTrigger id="mf-status" size="sm" className="mt-1 w-full border-border/60 bg-muted/40 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STATUSES.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="mf-pillar" className="text-[11px] font-semibold text-foreground/80">
                Audit pillar
              </Label>
              <Select value={draft.pillar} onValueChange={(v) => set("pillar", v)}>
                <SelectTrigger id="mf-pillar" size="sm" className="mt-1 w-full border-border/60 bg-muted/40 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="custom">Custom / unclassified</SelectItem>
                  {PILLARS.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.title}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="mf-count" className="text-[11px] font-semibold text-foreground/80">
                Occurrences
              </Label>
              <Input
                id="mf-count"
                type="number"
                min={1}
                value={draft.count}
                onChange={(e) => set("count", e.target.value)}
                className="mt-1 h-9 border-border/60 bg-muted/40 text-xs focus-visible:ring-amber-400/40"
              />
            </div>

            <div className="sm:col-span-2">
              <Label htmlFor="mf-path" className="text-[11px] font-semibold text-foreground/80">
                Affected path <span className="font-normal text-muted-foreground/60">(optional)</span>
              </Label>
              <Input
                id="mf-path"
                value={draft.path}
                onChange={(e) => set("path", e.target.value)}
                placeholder="/api/orders/:id"
                className="mt-1 h-9 border-border/60 bg-muted/40 font-mono text-xs focus-visible:ring-amber-400/40"
              />
            </div>

            <div className="sm:col-span-2">
              <Label htmlFor="mf-rule" className="text-[11px] font-semibold text-foreground/80">
                Rule ID <span className="font-normal text-muted-foreground/60">(optional)</span>
              </Label>
              <Input
                id="mf-rule"
                value={draft.ruleId}
                onChange={(e) => set("ruleId", e.target.value)}
                placeholder="ACL-IDOR · WG-0001 · CVE-2024-0001"
                className="mt-1 h-9 border-border/60 bg-muted/40 font-mono text-xs focus-visible:ring-amber-400/40"
              />
            </div>

            <div>
              <Label htmlFor="mf-owner" className="text-[11px] font-semibold text-foreground/80">
                Owner <span className="font-normal text-muted-foreground/60">(optional)</span>
              </Label>
              <Input
                id="mf-owner"
                value={draft.owner}
                onChange={(e) => set("owner", e.target.value)}
                placeholder="e.g. @maya · SRE squad"
                className="mt-1 h-9 border-border/60 bg-muted/40 text-xs focus-visible:ring-amber-400/40"
              />
            </div>

            <div>
              <Label htmlFor="mf-tags" className="text-[11px] font-semibold text-foreground/80">
                Tags <span className="font-normal text-muted-foreground/60">(optional, comma-separated)</span>
              </Label>
              <Input
                id="mf-tags"
                value={draft.tags}
                onChange={(e) => set("tags", e.target.value)}
                placeholder="api, owasp-a01, pci"
                className="mt-1 h-9 border-border/60 bg-muted/40 text-xs focus-visible:ring-amber-400/40"
              />
            </div>

            <div className="sm:col-span-2">
              <Label htmlFor="mf-notes" className="text-[11px] font-semibold text-foreground/80">
                Triage notes <span className="font-normal text-muted-foreground/60">(optional)</span>
              </Label>
              <Textarea
                id="mf-notes"
                value={draft.notes}
                onChange={(e) => set("notes", e.target.value)}
                placeholder={"Context for the team handling this — reproduction steps, blast radius, affected tenants…"}
                className="mt-1 h-20 w-full border-border/60 bg-muted/40 text-xs focus-visible:ring-amber-400/40"
              />
            </div>

            <div>
              <Label htmlFor="mf-evidence" className="text-[11px] font-semibold text-foreground/80">
                Evidence <span className="font-normal text-muted-foreground/60">(optional)</span>
              </Label>
              <Textarea
                id="mf-evidence"
                value={draft.evidence}
                onChange={(e) => set("evidence", e.target.value)}
                placeholder={"Raw HTTP / proof of concept, e.g.\nGET /api/orders/1042 HTTP/1.1\nHTTP/1.1 200 OK"}
                className="mt-1 h-24 w-full border-border/60 bg-muted/40 font-mono text-[11px] focus-visible:ring-amber-400/40"
              />
            </div>

            <div>
              <Label htmlFor="mf-patch" className="text-[11px] font-semibold text-foreground/80">
                Recommended patch <span className="font-normal text-muted-foreground/60">(optional)</span>
              </Label>
              <Textarea
                id="mf-patch"
                value={draft.patch}
                onChange={(e) => set("patch", e.target.value)}
                placeholder={"How should WebGuard / the team close this?\nenforce ownership checks · block path at edge · fix at origin"}
                className="mt-1 h-24 w-full border-border/60 bg-muted/40 font-mono text-[11px] focus-visible:ring-amber-400/40"
              />
            </div>
          </div>

          <div className="rounded-lg border border-border/40 bg-muted/30 px-3 py-2 text-[10px] leading-relaxed text-muted-foreground">
            Manual findings appear in the register with a <Badge variant="outline" className="mx-0.5 h-4 border-border/40 bg-muted/50 px-1 text-[9px] text-muted-foreground">MANUAL</Badge>{" "}
            source badge, feed the severity mix and aging-exposure panels, and can be deleted from their expanded card if
            logged by mistake.
          </div>
        </div>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost" size="sm" className="text-muted-foreground">
              Cancel
            </Button>
          </DialogClose>
          <Button
            size="sm"
            className="gap-1.5 border-wg-amber/40 bg-wg-amber/15 text-wg-amber hover:bg-wg-amber/25 hover:text-wg-amber"
            onClick={submit}
          >
            <ClipboardPlus className="size-3.5" /> Add to register
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
