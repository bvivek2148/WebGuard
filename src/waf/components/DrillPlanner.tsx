import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import { DRILL_SCENARIOS, drillScenarioById, scenarioTotalSec } from "../drills";
import { SectionTitle } from "./shared";
import { toast } from "sonner";
import {
  ArrowDown,
  ArrowUp,
  CalendarClock,
  Copy,
  FolderPlus,
  ListChecks,
  ListPlus,
  Play,
  Save,
  Timer,
  Trash2,
  X,
} from "lucide-react";

// ============================================================================
// Scenario planner — build multi-scenario drill batches and save them as
// reusable plans (persisted to localStorage, independent of the WAF state).
// ============================================================================

export interface DrillPlanItem {
  scenarioId: string;
  repeats: number;
}

export interface DrillPlan {
  id: string;
  name: string;
  items: DrillPlanItem[];
  createdAt: number;
}

const PLANS_KEY = "webguard-drill-plans-v1";

function loadPlans(): DrillPlan[] {
  try {
    const raw = localStorage.getItem(PLANS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as { plans?: DrillPlan[] } | DrillPlan[];
    const list = Array.isArray(parsed) ? parsed : parsed.plans;
    if (!Array.isArray(list)) return [];
    return list
      .filter((p) => p && typeof p.id === "string" && Array.isArray(p.items))
      .map((p) => ({ id: p.id, name: p.name ?? "Untitled plan", items: p.items, createdAt: p.createdAt ?? Date.now() }));
  } catch {
    return [];
  }
}

function savePlans(plans: DrillPlan[]): void {
  try {
    localStorage.setItem(PLANS_KEY, JSON.stringify({ v: 1, plans }));
  } catch {
    /* storage unavailable — plans just won't persist */
  }
}

export function clearDrillPlans(): void {
  try {
    localStorage.removeItem(PLANS_KEY);
  } catch {
    /* noop */
  }
}

function useDrillPlans() {
  const [plans, setPlans] = useState<DrillPlan[]>(() => loadPlans());
  useEffect(() => {
    savePlans(plans);
  }, [plans]);
  return {
    plans,
    addPlan: (plan: DrillPlan) => setPlans((prev) => [plan, ...prev].slice(0, 12)),
    deletePlan: (id: string) => setPlans((prev) => prev.filter((p) => p.id !== id)),
    duplicatePlan: (id: string) =>
      setPlans((prev) => {
        const src = prev.find((p) => p.id === id);
        if (!src) return prev;
        const copy: DrillPlan = {
          ...src,
          id: `plan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
          name: `${src.name} (copy)`,
          createdAt: Date.now(),
        };
        return [copy, ...prev].slice(0, 12);
      }),
  };
}

function fmtSec(total: number): string {
  const s = Math.max(0, Math.round(total));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function planDurationSec(items: DrillPlanItem[]): number {
  return items.reduce((acc, it) => {
    const s = drillScenarioById(it.scenarioId);
    return acc + (s ? scenarioTotalSec(s) * it.repeats : 0);
  }, 0);
}

export function DrillPlanner() {
  const { dispatch } = useWaf();
  const { plans, addPlan, deletePlan, duplicatePlan } = useDrillPlans();
  const [draft, setDraft] = useState<DrillPlanItem[]>([]);
  const [pick, setPick] = useState<string>(DRILL_SCENARIOS[0]?.id ?? "");
  const [repeats, setRepeats] = useState(1);
  const [name, setName] = useState("");

  const addToDraft = () => {
    if (!drillScenarioById(pick)) return;
    setDraft((prev) => [...prev, { scenarioId: pick, repeats }]);
  };

  const move = (idx: number, dir: -1 | 1) => {
    setDraft((prev) => {
      const next = [...prev];
      const target = idx + dir;
      if (target < 0 || target >= next.length) return prev;
      [next[idx], next[target]] = [next[target], next[idx]];
      return next;
    });
  };

  const saveDraft = () => {
    if (draft.length === 0) {
      toast.error("Add at least one scenario to the plan");
      return;
    }
    const plan: DrillPlan = {
      id: `plan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      name: name.trim() || `Plan ${plans.length + 1}`,
      items: draft,
      createdAt: Date.now(),
    };
    addPlan(plan);
    setDraft([]);
    setName("");
    toast.success(`Plan saved — ${plan.name}`, { description: `${plan.items.length} scenario(s) · ${fmtSec(planDurationSec(plan.items))} total` });
  };

  const runPlan = (plan: DrillPlan) => {
    const total = plan.items.reduce((n, it) => n + it.repeats, 0);
    for (const it of plan.items) {
      for (let i = 0; i < it.repeats; i++) {
        dispatch({ type: "QUEUE_DRILL", scenarioId: it.scenarioId });
      }
    }
    toast.success(`Plan launched — ${plan.name}`, {
      description: `${total} campaign(s) queued · starts automatically and advances through the list`,
    });
  };

  const draftDuration = planDurationSec(draft);

  return (
    <div className="flex flex-col gap-3">
      <SectionTitle
        title="Scenario planner"
        sub="Batch scenarios into a single exercise, save it as a reusable plan, and replay it anytime"
        right={
          <span className="flex items-center gap-1.5 rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            <FolderPlus className="size-3 text-wg-violet" /> {plans.length} saved
          </span>
        }
      />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* ---- builder ---- */}
        <div className="wg-panel flex flex-col gap-3 p-4">
          <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
            <ListPlus className="size-3 text-wg-cyan" /> Build a batch
          </p>

          <div className="flex flex-wrap items-end gap-2">
            <div className="flex min-w-[190px] flex-1 flex-col gap-1.5">
              <span className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Scenario</span>
              <select
                value={pick}
                onChange={(e) => setPick(e.target.value)}
                className="h-8 rounded-lg border border-border/50 bg-muted/40 px-2 text-xs text-foreground outline-none transition-colors focus:border-wg-cyan/50"
              >
                {DRILL_SCENARIOS.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} · {s.difficulty}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted-foreground/70">Repeats</span>
              <div className="flex items-center gap-1 rounded-lg border border-border/50 bg-muted/40 p-0.5">
                {[1, 2, 3, 5].map((n) => (
                  <button
                    key={n}
                    type="button"
                    onClick={() => setRepeats(n)}
                    className={cn(
                      "rounded-md px-2 py-1 font-mono text-[10px] font-semibold transition-colors",
                      repeats === n ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {n}×
                  </button>
                ))}
              </div>
            </div>
            <Button
              size="sm"
              className="h-8 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20"
              onClick={addToDraft}
            >
              <ListPlus className="size-3.5" /> Add
            </Button>
          </div>

          {/* draft */}
          <div className="flex flex-col gap-1.5">
            {draft.length === 0 ? (
              <div className="rounded-lg border border-dashed border-border/50 px-3 py-4 text-center text-[11px] text-muted-foreground">
                Nothing in this batch yet — pick a scenario, choose repeats, and add it.
              </div>
            ) : (
              draft.map((it, idx) => {
                const s = drillScenarioById(it.scenarioId);
                return (
                  <div key={`${it.scenarioId}-${idx}`} className="flex items-center gap-2 rounded-lg border border-border/40 bg-card/40 px-2.5 py-1.5">
                    <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-wg-cyan/10 font-mono text-[9px] font-bold text-wg-cyan">
                      {idx + 1}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-[11px] font-semibold text-foreground">
                      {s?.name ?? it.scenarioId}
                      <span className="ml-2 font-mono text-[9px] font-normal text-muted-foreground">
                        {s ? fmtSec(scenarioTotalSec(s)) : "—"} · {it.repeats}×
                      </span>
                    </span>
                    <div className="flex shrink-0 items-center gap-0.5">
                      <button
                        type="button"
                        onClick={() => move(idx, -1)}
                        disabled={idx === 0}
                        className="flex size-6 items-center justify-center rounded-md border border-border/50 text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan disabled:opacity-30"
                        title="Move up"
                      >
                        <ArrowUp className="size-3" />
                      </button>
                      <button
                        type="button"
                        onClick={() => move(idx, 1)}
                        disabled={idx === draft.length - 1}
                        className="flex size-6 items-center justify-center rounded-md border border-border/50 text-muted-foreground transition-colors hover:border-wg-cyan/40 hover:text-wg-cyan disabled:opacity-30"
                        title="Move down"
                      >
                        <ArrowDown className="size-3" />
                      </button>
                      <button
                        type="button"
                        onClick={() => setDraft((prev) => prev.filter((_, i) => i !== idx))}
                        className="flex size-6 items-center justify-center rounded-md border border-border/50 text-muted-foreground transition-colors hover:border-wg-rose/40 hover:text-wg-rose"
                        title="Remove"
                      >
                        <X className="size-3" />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 border-t border-border/40 pt-3">
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="h-8 max-w-[220px] border-border/50 bg-muted/40 text-xs"
              placeholder="Plan name (e.g. Q3 readiness)"
              spellCheck={false}
            />
            <span className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground">
              <Timer className="size-3 text-wg-cyan" /> {fmtSec(draftDuration)} total
            </span>
            <Button
              size="sm"
              className="ml-auto h-8 gap-1.5 border-wg-violet/40 bg-wg-violet/10 text-wg-violet hover:bg-wg-violet/20"
              onClick={saveDraft}
              disabled={draft.length === 0}
            >
              <Save className="size-3.5" /> Save plan
            </Button>
          </div>
        </div>

        {/* ---- saved plans ---- */}
        <div className="wg-panel flex flex-col gap-2 p-4">
          <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
            <FolderPlus className="size-3 text-wg-violet" /> Saved plans
          </p>
          {plans.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border/50 px-3 py-6 text-center text-[11px] text-muted-foreground">
              No plans saved yet. Build a batch on the left, then hit{" "}
              <span className="font-semibold text-foreground/70">Save plan</span> to keep it here for one-click replay.
            </div>
          ) : (
            <div className="flex max-h-80 flex-col gap-2 overflow-y-auto overscroll-contain pr-1">
              {plans.map((p) => {
                const total = p.items.reduce((n, it) => n + it.repeats, 0);
                return (
                  <div key={p.id} className="rounded-lg border border-border/40 bg-card/40 p-2.5">
                    <div className="flex items-center gap-2">
                      <ListChecks className="size-3.5 shrink-0 text-wg-violet" />
                      <p className="min-w-0 flex-1 truncate text-xs font-semibold text-foreground">{p.name}</p>
                      <span className="shrink-0 font-mono text-[9px] text-muted-foreground">
                        {total} campaign{total === 1 ? "" : "s"} · {fmtSec(planDurationSec(p.items))}
                      </span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {p.items.map((it, i) => {
                        const s = drillScenarioById(it.scenarioId);
                        return (
                          <span key={i} className="flex items-center gap-1 rounded border border-border/50 bg-muted/40 px-1.5 py-0.5 text-[9px] text-foreground/75">
                            <span className="font-mono text-[8px] text-wg-cyan">{i + 1}</span>
                            {s?.name ?? it.scenarioId}
                            {it.repeats > 1 && <span className="font-mono text-[8px] text-muted-foreground">×{it.repeats}</span>}
                          </span>
                        );
                      })}
                    </div>
                    <div className="mt-2 flex items-center gap-1.5">
                      <Button
                        size="sm"
                        className="h-7 flex-1 gap-1.5 border-wg-cyan/40 bg-wg-cyan/10 text-wg-cyan hover:bg-wg-cyan/20"
                        onClick={() => runPlan(p)}
                      >
                        <Play className="size-3" /> Run plan
                      </Button>
                      <button
                        type="button"
                        onClick={() => duplicatePlan(p.id)}
                        className="flex size-7 items-center justify-center rounded-md border border-border/50 text-muted-foreground transition-colors hover:border-wg-violet/40 hover:text-wg-violet"
                        title="Duplicate plan"
                      >
                        <Copy className="size-3" />
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          deletePlan(p.id);
                          toast.info(`Plan deleted — ${p.name}`);
                        }}
                        className="flex size-7 items-center justify-center rounded-md border border-border/50 text-muted-foreground transition-colors hover:border-wg-rose/40 hover:text-wg-rose"
                        title="Delete plan"
                      >
                        <Trash2 className="size-3" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <p className="mt-auto flex items-center gap-1.5 border-t border-border/40 pt-2 text-[9px] text-muted-foreground/80">
            <CalendarClock className="size-3 text-wg-amber" />
            Running a plan queues every campaign in order — the console auto-advances when each one finishes.
          </p>
        </div>
      </div>
    </div>
  );
}
