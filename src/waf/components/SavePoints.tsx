import { useState } from "react";
import { DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import { useWaf } from "../engine";
import { persistSnapshot, serializePersistedState } from "../engine";
import type { PersistedState } from "../engine";
import { toast } from "sonner";
import { Bookmark, BookmarkPlus, Pencil, Plus, Save, Trash2 } from "lucide-react";

// ============================================================================
// Save points — named presets of the whole console state kept in localStorage.
// Save the current session under a name, then restore any preset with one click
// (great for switching between demo scenarios without exporting files).
// ============================================================================

export interface SavePoint {
  id: string;
  name: string;
  savedAt: number;
  state: PersistedState;
}

const SAVEPOINTS_KEY = "webguard-savepoints-v1";
const MAX_SLOTS = 4;

function loadSavePoints(): SavePoint[] {
  try {
    const raw = localStorage.getItem(SAVEPOINTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as { savePoints?: SavePoint[] } | SavePoint[];
    const list = Array.isArray(parsed) ? parsed : parsed.savePoints;
    if (!Array.isArray(list)) return [];
    return list
      .filter((s) => s && typeof s.id === "string" && s.state && typeof s.state === "object")
      .map((s) => ({
        id: s.id,
        name: s.name ?? "Untitled save point",
        savedAt: s.savedAt ?? Date.now(),
        state: s.state,
      }))
      .slice(0, MAX_SLOTS);
  } catch {
    return [];
  }
}

function persistSavePoints(points: SavePoint[]): void {
  try {
    localStorage.setItem(SAVEPOINTS_KEY, JSON.stringify({ v: 1, savePoints: points }));
  } catch {
    /* storage unavailable — save points just won't persist */
  }
}

function modeLabel(mode: string): string {
  return mode === "blocking" ? "Blocking" : mode === "detection" ? "Detection" : "Unprotected";
}

export function SavePoints() {
  const { state, dispatch } = useWaf();
  const [points, setPoints] = useState<SavePoint[]>(loadSavePoints);

  const saveCurrent = (slotId?: string) => {
    const snapshot = serializePersistedState(state);
    const now = new Date().getTime();
    const autoName = `${modeLabel(snapshot.mode)} · ${new Date(now).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    const next: SavePoint[] = slotId
      ? points.map((p) => (p.id === slotId ? { ...p, name: p.name, savedAt: now, state: snapshot } : p))
      : [...points, { id: `sp-${now}`, name: autoName, savedAt: now, state: snapshot }].slice(0, MAX_SLOTS);
    setPoints(next);
    persistSavePoints(next);
    toast.success(slotId ? "Save point updated" : "Save point created", {
      description: slotId ? points.find((p) => p.id === slotId)?.name ?? "Slot updated" : autoName,
    });
  };

  const loadPoint = (p: SavePoint) => {
    dispatch({ type: "RESTORE_STATE", snapshot: p.state });
    persistSnapshot(p.state);
    toast.success("Save point restored", {
      description: `${p.name} — mode, blocklist, rules, findings, incidents and drills reloaded`,
    });
  };

  const removePoint = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    const next = points.filter((p) => p.id !== id);
    setPoints(next);
    persistSavePoints(next);
    toast.info("Save point deleted");
  };

  const renamePoint = (p: SavePoint, e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    const name = window.prompt("Name this save point", p.name);
    if (name === null) return;
    const trimmed = name.trim();
    if (!trimmed) return;
    const next = points.map((x) => (x.id === p.id ? { ...x, name: trimmed } : x));
    setPoints(next);
    persistSavePoints(next);
    toast.success("Save point renamed", { description: trimmed });
  };

  const overwritePoint = (p: SavePoint, e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    saveCurrent(p.id);
  };

  const full = points.length >= MAX_SLOTS;

  return (
    <>
      <DropdownMenuLabel className="flex items-center justify-between text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1.5 uppercase tracking-wider">
          <Bookmark className="size-3" /> Save points
        </span>
        <span className="font-mono">
          {points.length}/{MAX_SLOTS}
        </span>
      </DropdownMenuLabel>

      {points.length === 0 ? (
        <div className="px-3 py-1.5 text-[10px] leading-relaxed text-muted-foreground/70">
          No save points yet. Save the current session below, then restore it any time with one click.
        </div>
      ) : (
        points.map((p) => (
          <DropdownMenuItem
            key={p.id}
            onClick={() => loadPoint(p)}
            className="gap-2 py-1.5 text-xs"
            title={`Restore “${p.name}” — click the row, overwrite with Save, rename with Pencil`}
          >
            <Bookmark className="size-3 text-wg-violet" />
            <span className="min-w-0 flex-1 truncate">{p.name}</span>
            <span className="shrink-0 font-mono text-[9px] text-muted-foreground/60">
              {new Date(p.savedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </span>
            <span className="flex shrink-0 items-center gap-0.5">
              <button
                type="button"
                onClick={(e) => overwritePoint(p, e)}
                className="flex size-5 items-center justify-center rounded text-muted-foreground/60 transition-colors hover:bg-muted/60 hover:text-wg-cyan"
                title="Overwrite with current state"
              >
                <Save className="size-3" />
              </button>
              <button
                type="button"
                onClick={(e) => renamePoint(p, e)}
                className="flex size-5 items-center justify-center rounded text-muted-foreground/60 transition-colors hover:bg-muted/60 hover:text-wg-amber"
                title="Rename"
              >
                <Pencil className="size-3" />
              </button>
              <button
                type="button"
                onClick={(e) => removePoint(p.id, e)}
                className="flex size-5 items-center justify-center rounded text-muted-foreground/60 transition-colors hover:bg-muted/60 hover:text-wg-rose"
                title="Delete save point"
              >
                <Trash2 className="size-3" />
              </button>
            </span>
          </DropdownMenuItem>
        ))
      )}

      <DropdownMenuSeparator />

      <DropdownMenuItem
        onClick={() => (full ? toast.info("Save points full", { description: "Delete or overwrite an existing save point first" }) : saveCurrent())}
        className={cn("gap-2 text-xs", full && "text-muted-foreground/60")}
        title={full ? "All slots used — overwrite or delete one first" : "Save the current console state as a named preset"}
      >
        {full ? <Save className="size-3.5" /> : <Plus className="size-3.5" />}
        {full ? "Save points full — free a slot first" : "Save current as save point"}
      </DropdownMenuItem>
      <DropdownMenuItem
        onClick={() => {
          const name = window.prompt("Name for a new save point", `Demo · ${modeLabel(state.mode)}`);
          if (name === null) return;
          const trimmed = name.trim();
          if (!trimmed) return;
          const snapshot = serializePersistedState(state);
          const now = new Date().getTime();
          const next: SavePoint[] = [...points, { id: `sp-${now}`, name: trimmed, savedAt: now, state: snapshot }].slice(0, MAX_SLOTS);
          setPoints(next);
          persistSavePoints(next);
          toast.success("Save point created", { description: trimmed });
        }}
        className={cn("gap-2 text-xs", full && "hidden")}
      >
        <BookmarkPlus className="size-3.5" /> Save current with a custom name
      </DropdownMenuItem>
    </>
  );
}
