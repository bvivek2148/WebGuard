import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle } from "@/components/ui/drawer";
import { cn } from "@/lib/utils";
import { copilotIntel } from "../data";
import { copilotContextFromIncident, uid, useWaf } from "../engine";
import type { WafState } from "../engine";
import { ATTACK_LABELS, SEVERITY_META } from "../types";
import type { CopilotContext, CopilotTriage, Severity } from "../types";
import { flagEmoji, SeverityBadge } from "./shared";
import { BrainCircuit, Bug, CheckCircle2, Code2, Copy, Crosshair, Download, FileSearch, ListChecks, Loader2, Lock, Send, ShieldBan, Sparkles, TerminalSquare, Wrench, X } from "lucide-react";

const MIN_W = 380;
const MAX_W = 780;
const WIDTH_KEY = "webguard.copilot.width";

function clampWidth(w: number): number {
  return Math.min(MAX_W, Math.max(MIN_W, Math.round(w)));
}

function savedWidth(): number | null {
  try {
    const v = Number(localStorage.getItem(WIDTH_KEY));
    return Number.isFinite(v) && v >= MIN_W && v <= MAX_W ? v : null;
  } catch {
    return null;
  }
}

const STAGES = ["intent", "breakdown", "rootcause", "postmortem", "code"] as const;

interface ChatMsg {
  role: "user" | "ai";
  text: string;
}

export function CopilotDrawer() {
  const { state, dispatch } = useWaf();
  const { open, generating, context } = state.copilot;
  const [reveal, setReveal] = useState(0);
  const [codeTab, setCodeTab] = useState(0);
  const [chat, setChat] = useState<ChatMsg[]>([]);
  const [draft, setDraft] = useState("");
  const [thinking, setThinking] = useState(false);
  const chatEndRef = useRef<HTMLDivElement | null>(null);

  // Dynamic, resizable width — remembers the operator's preference
  const [width, setWidth] = useState<number>(() => savedWidth() ?? (state.copilot.context?.kind === "triage" ? 580 : 460));
  const widthRef = useRef(width);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  useEffect(() => {
    widthRef.current = width;
  }, [width]);

  const onResizePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    const startX = e.clientX;
    const startW = widthRef.current;
    const move = (ev: PointerEvent) => {
      setWidth(clampWidth(startW + (startX - ev.clientX)));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      try {
        localStorage.setItem(WIDTH_KEY, String(widthRef.current));
      } catch {
        /* ignore */
      }
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const intel = useMemo(() => copilotIntel(context?.attackType ?? null), [context]);

  // Reset chat when a new context arrives — adjusting state during render is
  // the rule-compliant replacement for setState-in-effect on prop change.
  const [prevTitle, setPrevTitle] = useState<string | undefined>(context?.title);
  if (prevTitle !== context?.title) {
    setPrevTitle(context?.title);
    setChat([]);
    setDraft("");
    setThinking(false);
  }

  // Auto-scroll the chat to the newest message
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [chat, thinking]);

  const ask = (q: string) => {
    const question = q.trim();
    if (!question || !context || thinking) return;
    setChat((c) => [...c, { role: "user", text: question }]);
    setDraft("");
    setThinking(true);
    window.setTimeout(() => {
      setChat((c) => [...c, { role: "ai", text: copilotReply(question, context, intel) }]);
      setThinking(false);
    }, 650);
  };

  const copyText = (text: string, label: string) => {
    navigator.clipboard
      .writeText(text)
      .then(() => toast.success(`${label} copied to clipboard`))
      .catch(() => toast.error("Clipboard unavailable"));
  };

  // Reset the stage reveal when the drawer's open/generating posture changes.
  const [prevPosture, setPrevPosture] = useState({ open, generating });
  if (prevPosture.open !== open || prevPosture.generating !== generating) {
    setPrevPosture({ open, generating });
    setCodeTab(0);
    setReveal(open && !generating ? STAGES.length : 0);
  }

  // Progressive stage reveal while a copilot response is generating.
  useEffect(() => {
    if (!open || !generating) return;
    let i = 0;
    const iv = window.setInterval(() => {
      i += 1;
      setReveal(i);
      if (i >= STAGES.length) window.clearInterval(iv);
    }, 420);
    return () => window.clearInterval(iv);
  }, [open, generating]);

  const sev = context ? SEVERITY_META[context.severity] : null;

  return (
    <Drawer
      open={open}
      onOpenChange={(o) => {
        if (!o) dispatch({ type: "CLOSE_COPILOT" });
      }}
      direction="right"
    >
      <DrawerContent
        className="border-l border-border/60 bg-background"
        style={{ width, maxWidth: "min(100vw - 1rem, 92vw)" }}
      >
        {/* resize handle — drag to make the drawer dynamic */}
        <div
          role="separator"
          aria-orientation="vertical"
          title="Drag to resize"
          onPointerDown={onResizePointerDown}
          className="absolute inset-y-0 -left-1 z-20 w-3 cursor-ew-resize touch-none select-none after:absolute after:inset-y-0 after:left-1 after:w-px after:bg-border/60 after:transition-colors hover:after:bg-wg-cyan/70 active:after:bg-wg-cyan"
        />
        <DrawerHeader className="flex-row items-center justify-between border-b border-border/60 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-lg bg-wg-cyan/15 text-wg-cyan">
              <Sparkles className="size-4" />
            </div>
            <div>
              <DrawerTitle className="text-sm">WebGuard AI Copilot</DrawerTitle>
              <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-muted-foreground">Gemini-powered threat analysis</span>
                <span className="flex items-center gap-1 rounded border border-wg-cyan/30 bg-wg-cyan/10 px-1.5 py-px font-mono text-[9px] font-semibold text-wg-cyan">
                  gemini-2.5-pro
                </span>
                <span className="flex items-center gap-1 rounded border border-wg-emerald/30 bg-wg-emerald/10 px-1.5 py-px font-mono text-[9px] font-semibold text-wg-emerald">
                  99.2% conf
                </span>
              </div>
            </div>
          </div>
          <Button variant="ghost" size="icon-sm" onClick={() => dispatch({ type: "CLOSE_COPILOT" })}>
            <X className="size-4" />
          </Button>
        </DrawerHeader>

        <div className="flex-1 overflow-y-auto px-4 py-4">
          {!context?.title ? (
            <EmptyCopilot onPick={(ctx) => dispatch({ type: "OPEN_COPILOT", context: ctx })} state={state} />
          ) : context.kind === "triage" && context.triage ? (
            <TriagePanel triage={context.triage} title={context.title} generating={generating} />
          ) : (
            <div className="flex flex-col gap-4">
              {/* context header */}
              <div className="rounded-xl border border-border/60 bg-card/60 p-3.5">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                    {context.kind === "incident" ? "Incident" : context.kind === "sandbox" ? "Sandbox run" : "Request"}
                  </p>
                  {sev && (
                    <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-bold tracking-wider", sev.badge)}>
                      {sev.label}
                    </span>
                  )}
                </div>
                <p className="mt-1.5 wg-mono truncate text-[13px] text-foreground">{context.title}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <span className="text-sm leading-none">{flagEmoji(context.country)}</span> {context.ip} · {context.country}
                  </span>
                  {context.threatScore > 0 && (
                    <span className="font-mono text-wg-rose">threat {context.threatScore}/100</span>
                  )}
                  {context.ruleId && <span className="font-mono text-muted-foreground">rule {context.ruleId}</span>}
                </div>
                {context.payload && (
                  <pre className="mt-2.5 max-h-24 overflow-auto rounded-lg border border-wg-rose/20 bg-wg-rose/[0.06] p-2.5 wg-mono text-[11px] text-wg-rose/90">
                    {context.payload}
                  </pre>
                )}
              </div>

              {generating && reveal < STAGES.length ? (
                <div className="flex flex-col gap-2.5 rounded-xl border border-border/50 bg-card/40 p-4">
                  <div className="flex items-center gap-2 text-xs text-wg-cyan">
                    <Loader2 className="size-3.5 animate-spin" />
                    Inspecting payload against 6-stage pipeline…
                  </div>
                  {/* pipeline progress */}
                  <div className="flex gap-1">
                    {STAGES.map((s, i) => (
                      <div
                        key={s}
                        className={cn("h-1 flex-1 rounded-full transition-colors", i < Math.min(reveal, STAGES.length) ? "bg-wg-cyan" : "bg-border/50")}
                      />
                    ))}
                  </div>
                  {STAGES.slice(0, Math.min(reveal, STAGES.length - 1)).map((s, i) => (
                    <div key={s} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                      <CheckCircle2 className="size-3 text-emerald-400" />
                      {["Signature match", "Entropy classifier", "Origin reputation", "Behavior graph", "Root-cause trace"][i]}
                    </div>
                  ))}
                </div>
              ) : (
                <>
                  {/* intent */}
                  {reveal >= 1 && (
                    <Stage icon={<Crosshair className="size-3.5" />} title="Attack intent">
                      <p className="text-[13px] font-medium text-wg-rose">{intel.intent}</p>
                      {context.attackType && (
                        <p className="mt-0.5 text-[11px] text-muted-foreground">
                          Classified as <span className="text-wg-rose">{ATTACK_LABELS[context.attackType]}</span> with{" "}
                          {context.threatScore || 91}% confidence
                        </p>
                      )}
                    </Stage>
                  )}
                  {/* breakdown */}
                  {reveal >= 2 && (
                    <Stage icon={<FileSearch className="size-3.5" />} title="Payload breakdown">
                      <ul className="flex flex-col gap-1.5">
                        {intel.attackBreakdown.map((b) => (
                          <li key={b} className="flex gap-2 text-xs leading-relaxed text-foreground/80">
                            <span className="mt-1.5 size-1 shrink-0 rounded-full bg-cyan-400" />
                            {b}
                          </li>
                        ))}
                      </ul>
                    </Stage>
                  )}
                  {/* root cause */}
                  {reveal >= 3 && (
                    <Stage
                      icon={<TerminalSquare className="size-3.5" />}
                      title="Root cause"
                      action={
                        <button type="button" onClick={() => copyText(intel.rootCause, "Root cause")} className="text-muted-foreground transition-colors hover:text-wg-cyan">
                          <Copy className="size-3" />
                        </button>
                      }
                    >
                      <p className="text-xs leading-relaxed text-foreground/80">{intel.rootCause}</p>
                    </Stage>
                  )}
                  {/* post mortem */}
                  {reveal >= 4 && (
                    <Stage
                      icon={<BrainCircuit className="size-3.5" />}
                      title="Executive summary"
                      action={
                        <button type="button" onClick={() => copyText(intel.postMortem, "Executive summary")} className="text-muted-foreground transition-colors hover:text-wg-cyan">
                          <Copy className="size-3" />
                        </button>
                      }
                    >
                      <p className="text-xs leading-relaxed text-foreground/80">{intel.postMortem}</p>
                    </Stage>
                  )}
                  {/* code */}
                  {reveal >= 5 && intel.code.length > 0 && (
                    <Stage
                      icon={<Code2 className="size-3.5" />}
                      title="Remediation code"
                      action={
                        <button
                          type="button"
                          onClick={() => intel.code[codeTab] && copyText(intel.code[codeTab].snippet, `${intel.code[codeTab].label} snippet`)}
                          className="text-muted-foreground transition-colors hover:text-wg-cyan"
                        >
                          <Copy className="size-3" />
                        </button>
                      }
                    >
                      <div className="flex flex-wrap gap-1.5">
                        {intel.code.map((c, i) => (
                          <button
                            key={c.language}
                            type="button"
                            onClick={() => setCodeTab(i)}
                            className={cn(
                              "rounded-md border px-2 py-1 text-[10px] font-medium transition-colors",
                              codeTab === i
                                ? "border-wg-cyan/50 bg-wg-cyan/10 text-wg-cyan"
                                : "border-border/60 text-muted-foreground hover:text-foreground",
                            )}
                          >
                            {c.label}
                          </button>
                        ))}
                      </div>
                      {intel.code[codeTab] && (
                        <pre className="mt-2 overflow-auto rounded-lg border border-border/50 bg-muted/70 p-3 wg-mono text-[11px] text-wg-emerald/90">
                          {intel.code[codeTab].snippet}
                        </pre>
                      )}
                    </Stage>
                  )}
                </>
              )}

              {/* quick actions */}
              {reveal >= STAGES.length && !generating && (
                <QuickActions context={context} />
              )}
            </div>
          )}
        </div>

        {/* follow-up chat — only once an analysis exists */}
        {context?.title && reveal >= STAGES.length && !generating && (
          <div className="flex min-h-[200px] flex-col border-t border-border/60" style={{ maxHeight: Math.max(300, Math.min(width * 0.85, window.innerHeight * 0.7)) }}>
            <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-0.5 px-4 pt-2.5 pb-1">
              <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground/70">
                Ask a follow-up
              </p>
              <span className="font-mono text-[9px] text-muted-foreground/60">context-aware · instant</span>
            </div>
            <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto overscroll-contain px-4 py-1.5">
              {chat.map((m, i) => (
                <div key={i} className={cn("flex", m.role === "user" ? "justify-end" : "justify-start")}>
                  <div
                    className={cn(
                      "rounded-xl px-3 py-2 text-xs leading-relaxed",
                      m.role === "user"
                        ? "rounded-br-sm border border-wg-cyan/30 bg-wg-cyan/10 text-foreground"
                        : "rounded-bl-sm border border-border/40 bg-card/60 text-foreground/90",
                    )}
                    style={{ maxWidth: Math.round(width * 0.82) }}
                  >
                    {m.text}
                  </div>
                </div>
              ))}
              {thinking && (
                <div className="flex items-center gap-2 text-[11px] text-wg-cyan">
                  <Loader2 className="size-3 animate-spin" /> Analyzing context…
                </div>
              )}
              <div ref={chatEndRef} />
            </div>
            <div className="flex flex-col gap-1.5 px-4 pb-2.5">
              <div className="flex flex-wrap gap-1">
                {["How do I stop this?", "Why did it happen?", "What is the risk?", "What next?"].map((c) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => ask(c)}
                    className="rounded-md border border-border/50 bg-muted/40 px-2.5 py-1 text-[11px] text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan"
                  >
                    {c}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-1.5">
                <input
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && ask(draft)}
                  placeholder="Ask about this analysis…"
                  className="h-8 flex-1 rounded-lg border border-border/60 bg-muted/40 px-2.5 text-xs text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-wg-cyan/50"
                />
                <Button size="sm" className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 px-2.5 text-wg-cyan hover:bg-wg-cyan/20" onClick={() => ask(draft)} disabled={thinking}>
                  <Send className="size-3.5" />
                </Button>
              </div>
            </div>
          </div>
        )}

        <div className="border-t border-border/60 px-4 py-2.5">
          <p className="text-center text-[10px] text-muted-foreground">
            Analysis generated by the WebGuard telemetry simulator · no external calls made
          </p>
        </div>
      </DrawerContent>
    </Drawer>
  );
}

// ============================================================================
// Empty state with one-click analysis targets
// ============================================================================

function EmptyCopilot({ state, onPick }: { state: WafState; onPick: (ctx: CopilotContext) => void }) {
  const open = state.findings.filter((f) => f.status === "open" || f.status === "investigating");
  const critical = open.filter((f) => f.severity === "critical").length;
  const high = open.filter((f) => f.severity === "high").length;
  const latestIncident = state.incidents[0] ?? null;

  const chips: Array<{ label: string; sub: string; icon: React.ReactNode; tone: string; onClick: () => void; disabled?: boolean }> = [
    {
      label: `Triage ${open.length} open findings`,
      sub: "Prioritize the register by exploitability",
      icon: <ListChecks className="size-3.5" />,
      tone: "text-wg-violet",
      onClick: () =>
        onPick({
          kind: "triage",
          title: `Posture triage — ${open.length} unresolved findings`,
          attackType: null,
          ip: "-",
          country: "-",
          severity: critical > 0 ? "critical" : high > 0 ? "high" : "low",
          payload: "",
          ruleId: null,
          threatScore: 0,
          path: "-",
          triage: {
            open: open.length,
            critical,
            high,
            items: open.slice(0, 8).map((f) => ({ title: f.title, severity: f.severity, patch: f.patch, path: f.path })),
          },
        }),
    },
    {
      label: latestIncident ? `Analyze latest incident` : "No incidents yet",
      sub: latestIncident ? latestIncident.title : "Simulate an incident to analyze it",
      icon: <Bug className="size-3.5" />,
      tone: "text-wg-rose",
      onClick: () => latestIncident && onPick(copilotContextFromIncident(latestIncident)),
      disabled: !latestIncident,
    },
    {
      label: "Explain current SOC posture",
      sub: "Mode, exposure, and recommended next step",
      icon: <ShieldBan className="size-3.5" />,
      tone: "text-wg-cyan",
      onClick: () =>
        onPick({
          kind: "log",
          title: "Current SOC posture",
          attackType: null,
          ip: "-",
          country: "-",
          severity: open.length > 0 ? (critical > 0 ? "critical" : "high") : "low",
          payload: "",
          ruleId: null,
          threatScore: 0,
          path: "-",
        }),
    },
    {
      label: "Review live traffic threats",
      sub: "Most recent hostile request in the stream",
      icon: <Crosshair className="size-3.5" />,
      tone: "text-wg-amber",
      onClick: () => {
        const hostile = [...state.logs].find((l) => l.attackType);
        if (hostile) {
          onPick({
            kind: "log",
            title: `${ATTACK_LABELS[hostile.attackType!]} — ${hostile.path}`,
            attackType: hostile.attackType,
            ip: hostile.ip,
            country: hostile.countryCode,
            severity: hostile.attackType === "sqli" || hostile.attackType === "cmdi" ? "critical" : hostile.attackType === "xss" || hostile.attackType === "path-traversal" || hostile.attackType === "high-entropy" ? "high" : "medium",
            payload: hostile.payload ?? "",
            ruleId: hostile.ruleId,
            threatScore: hostile.threatScore,
            path: hostile.path,
          });
        }
      },
    },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-xl border border-border/60 bg-card/60 p-4">
        <p className="text-sm font-medium text-foreground">Ready to analyze</p>
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
          Select any request in the Traffic stream, an incident, or a sandbox run — or pick a target below and
          WebGuard will break down attack intent, root cause, and remediation code.
        </p>
      </div>

      <div className="flex flex-col gap-1.5">
        {chips.map((c) => (
          <button
            key={c.label}
            type="button"
            disabled={c.disabled}
            onClick={c.onClick}
            className="flex items-start gap-2.5 rounded-lg border border-border/40 bg-card/40 p-2.5 text-left transition-colors hover:border-wg-cyan/40 hover:bg-muted/40 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <span className={cn("mt-0.5", c.tone)}>{c.icon}</span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-medium text-foreground">{c.label}</span>
              <span className="block truncate text-[10px] text-muted-foreground">{c.sub}</span>
            </span>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-2 text-center">
        {[
          { label: "Logs inspected", value: "12.4M" },
          { label: "Pipeline stages", value: "6" },
          { label: "Avg analysis", value: "0.9s" },
          { label: "Confidence", value: "99.2%" },
        ].map((s) => (
          <div key={s.label} className="rounded-lg border border-border/40 bg-card/40 p-3">
            <p className="font-mono text-sm font-semibold text-wg-cyan">{s.value}</p>
            <p className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{s.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// One-click response actions from an analysis
// ============================================================================

function QuickActions({ context }: { context: CopilotContext }) {
  const { state, dispatch } = useWaf();

  const blockIp = () => {
    const ip = context.ip;
    if (!ip || ip === "-") {
      toast.error("No source IP on this context");
      return;
    }
    if (state.blocklist.some((b) => b.ip === ip && b.active)) {
      toast.info("Source already blocked");
      return;
    }
    dispatch({
      type: "ADD_BLOCKED_IP",
      entry: {
        id: uid("BAN"),
        ip,
        reason: `Copilot triage — ${context.title.split(" — ")[0] ?? context.title}`,
        source: "manual",
        country: context.country,
        countryCode: context.country,
        addedAt: Date.now(),
        hits: 0,
        active: true,
        expiresAt: null,
      },
    });
    toast.success(`Blocked ${ip} at the edge`);
  };

  const applyPatches = () => {
    dispatch({ type: "SET_MODE", mode: "blocking" });
    toast.success("Edge patches applied — firewall now BLOCKING", { description: "Re-scan the target to verify 100/100" });
  };

  const escalate = () => {
    dispatch({
      type: "ADD_INCIDENT",
      incident: {
        id: uid("INC"),
        title: context.title,
        vector: context.attackType ? ATTACK_LABELS[context.attackType] : context.title.split(" — ")[0] ?? "Suspicious activity",
        severity: context.severity,
        sourceIp: context.ip === "-" ? "0.0.0.0" : context.ip,
        country: context.country === "-" ? "DE" : context.country,
        stage: "investigating",
        openedAt: Date.now(),
        closedAt: null,
        detail: `Escalated from Copilot analysis: ${context.title}. ${context.ruleId ? `Matched rule ${context.ruleId}.` : ""}`,
        playbook: null,
      },
    });
    toast.success("Incident opened — run a playbook to contain it");
  };

  const exportAnalysis = () => {
    const intel = copilotIntel(context.attackType ?? null);
    const blob = new Blob([JSON.stringify({ context, intel, generatedAt: new Date().toISOString() }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `webguard-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Analysis exported as JSON");
  };

  return (
    <div className="rounded-xl border border-border/50 bg-card/50 p-3.5">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-wg-emerald">
          <Wrench className="size-3.5" />
        </span>
        <h4 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Quick actions</h4>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {context.ip && context.ip !== "-" && (
          <button
            type="button"
            onClick={blockIp}
            className="flex items-center gap-1.5 rounded-lg border border-wg-rose/40 bg-wg-rose/10 px-2.5 py-1.5 text-[11px] font-medium text-wg-rose transition-colors hover:bg-wg-rose/20"
          >
            <ShieldBan className="size-3.5" /> Block {context.ip}
          </button>
        )}
        <button
          type="button"
          onClick={applyPatches}
          className="flex items-center gap-1.5 rounded-lg border border-wg-emerald/40 bg-wg-emerald/10 px-2.5 py-1.5 text-[11px] font-medium text-wg-emerald transition-colors hover:bg-wg-emerald/20"
        >
          <Lock className="size-3.5" /> Apply edge patches
        </button>
        <button
          type="button"
          onClick={escalate}
          className="flex items-center gap-1.5 rounded-lg border border-wg-amber/40 bg-wg-amber/10 px-2.5 py-1.5 text-[11px] font-medium text-wg-amber transition-colors hover:bg-wg-amber/20"
        >
          <Bug className="size-3.5" /> Open incident
        </button>
        <button
          type="button"
          onClick={exportAnalysis}
          className="flex items-center gap-1.5 rounded-lg border border-border/60 bg-muted/40 px-2.5 py-1.5 text-[11px] font-medium text-muted-foreground transition-colors hover:text-foreground"
        >
          <Download className="size-3.5" /> Export analysis
        </button>
      </div>
    </div>
  );
}

function TriagePanel({
  triage,
  title,
  generating,
}: {
  triage: CopilotTriage;
  title: string;
  generating: boolean;
}) {
  const order: Severity[] = ["critical", "high", "medium", "low"];
  const items = [...triage.items].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-xl border border-border/60 bg-card/60 p-3.5">
        <div className="flex items-center justify-between gap-2">
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Posture triage</p>
          {triage.open > 0 && (
            <span className="flex items-center gap-1 rounded border border-wg-rose/40 bg-wg-rose/10 px-1.5 py-0.5 text-[9px] font-bold tracking-wider text-wg-rose">
              <span className="size-1 animate-pulse rounded-full bg-rose-400" /> LIVE REGISTER
            </span>
          )}
        </div>
        <p className="mt-1.5 wg-mono truncate text-[13px] text-foreground">{title}</p>
      </div>

      {generating ? (
        <div className="flex flex-col gap-2.5 rounded-xl border border-border/50 bg-card/40 p-4">
          <div className="flex items-center gap-2 text-xs text-wg-cyan">
            <Loader2 className="size-3.5 animate-spin" />
            Prioritizing {triage.open} open findings by exploitability…
          </div>
          {["Severity clustering", "Patch coverage check", "Exploitability ranking", "Runbook assembly"].map((s) => (
            <div key={s} className="flex items-center gap-2 text-[11px] text-muted-foreground">
              <CheckCircle2 className="size-3 text-emerald-400" /> {s}
            </div>
          ))}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-2">
            <TriageStat label="Open" value={triage.open} tone="text-wg-rose" />
            <TriageStat label="Critical" value={triage.critical} tone="text-wg-orange" />
            <TriageStat label="High" value={triage.high} tone="text-wg-amber" />
          </div>

          <Stage icon={<ListChecks className="size-3.5" />} title="Priority queue — fix order">
            <div className="flex flex-col gap-2">
              {items.length === 0 && (
                <p className="text-xs text-wg-emerald">No open findings — posture is clean. Run an audit to refresh.</p>
              )}
              {items.map((f, i) => (
                <div key={f.title} className="rounded-lg border border-border/40 bg-muted/30 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[10px] font-bold text-muted-foreground">{i + 1}</span>
                    <p className="min-w-0 flex-1 truncate text-xs font-medium text-foreground">{f.title}</p>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  {f.path && <p className="mt-1 truncate font-mono text-[10px] text-wg-cyan">{f.path}</p>}
                  <p className="mt-1 wg-mono text-[10px] leading-relaxed text-wg-emerald/90">{f.patch}</p>
                </div>
              ))}
            </div>
          </Stage>

          <Stage icon={<Wrench className="size-3.5" />} title="Recommended runbook">
            <ol className="flex flex-col gap-2">
              {[
                "Flip the firewall to BLOCKING — every open class is already covered by an edge virtual patch.",
                "Re-scan the target with the firewall active to verify the posture score climbs to 100.",
                "Ship the origin-side fixes from the remediation snippets, then mark findings FIXED.",
                "Re-run the audit weekly; auto-bans and canary trips keep the blocklist fresh.",
              ].map((s, i) => (
                <li key={i} className="flex gap-2 text-xs leading-relaxed text-foreground/80">
                  <span className="flex size-4 shrink-0 items-center justify-center rounded-full bg-wg-cyan/15 font-mono text-[9px] font-bold text-wg-cyan">
                    {i + 1}
                  </span>
                  {s}
                </li>
              ))}
            </ol>
          </Stage>
        </>
      )}
    </div>
  );
}

function TriageStat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-lg border border-border/40 bg-card/40 p-3 text-center">
      <p className={cn("font-mono text-xl font-bold", tone)}>{value}</p>
      <p className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  );
}

function Stage({
  icon,
  title,
  children,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-border/50 bg-card/50 p-3.5">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-wg-cyan">{icon}</span>
          <h4 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{title}</h4>
        </div>
        {action}
      </div>
      {children}
    </div>
  );
}

// ============================================================================
// Scripted, context-aware follow-up answers
// ============================================================================

function copilotReply(q: string, context: CopilotContext, intel: ReturnType<typeof copilotIntel>): string {
  const t = q.toLowerCase();
  const type = context.attackType ? ATTACK_LABELS[context.attackType] : context.title.split(" — ")[0] ?? "this activity";
  const ip = context.ip !== "-" ? context.ip : "the source";

  if (/block|ban|stop|drop|deny/i.test(t)) {
    return `Recommended: block ${ip} at the edge right now — the quick action above does it in one click. ${context.ruleId ? `Rule ${context.ruleId} is already matching; blocking converts it from detection into enforcement (403 before origin).` : "With the firewall in BLOCKING mode, this class of traffic never reaches your origin."} For long-term coverage, keep the edge patch and re-scan to verify.`;
  }
  if (/patch|fix|remedi|mitigat|resolve/i.test(t)) {
    return `Ship the ${intel.code[0]?.label ?? "primary"} remediation snippet above, then apply edge patches (BLOCKING mode) as an instant mitigation. Re-run the audit to confirm the score moves ${context.severity === "critical" || context.severity === "high" ? "from F-grade to A+" : "back to a clean register"}.`;
  }
  if (/why|intent|goal|motiv|explain/i.test(t)) {
    return `${intel.intent} ${intel.rootCause} In practice, ${type.toLowerCase()} traffic like this is usually automated scanning or a targeted probe — the edge treats it identically: detect, score, block.`;
  }
  if (/risk|severity|danger|critical|impact/i.test(t)) {
    return `Severity is ${context.severity.toUpperCase()} with a threat score of ${context.threatScore || 91}/100. ${context.severity === "critical" || context.severity === "high" ? "If this reaches the origin unblocked it can lead to data exposure or service compromise — act now." : "Impact is limited, but persistence across attempts raises it — keep monitoring and consider an auto-ban rule."}`;
  }
  if (/next|recommend|suggest|what now|action|priority/i.test(t)) {
    return `1) ${ip !== "the source" ? `Block ${ip}` : "Block the source IP"}. 2) Keep the firewall in BLOCKING so the edge patch is enforced. 3) ${intel.code[0] ? `Deploy the ${intel.code[0].label} fix at the origin` : "Deploy the remediation snippet at the origin"}. 4) Re-scan to verify, then mark the finding FIXED in the register.`;
  }
  return `On ${type} from ${ip}: ${intel.intent} Root cause — ${intel.rootCause} I'd rate it ${context.severity.toUpperCase()} and recommend applying the edge patch now (BLOCKING mode), then fixing at the origin with the remediation snippet above.`;
}
