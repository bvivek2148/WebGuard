import { toast } from "sonner";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  FileDown,
  FileJson,
  FileText,
  Table2,
  Download,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Trigger a browser download from a string payload. */
function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Escape a value for CSV. */
function escCsv(s: string): string {
  return `"${s.replace(/"/g, '""')}"`;
}

// ---------------------------------------------------------------------------
// Format-specific exporters
// ---------------------------------------------------------------------------

export interface ExportableData {
  /** Human-readable label (e.g. "Audit scan", "SOC data"). */
  label: string;
  /** Filename stem (without extension). */
  filename: string;

  /** JSON data — if provided, "JSON" format is available. */
  jsonData?: unknown;
  /** CSV rows (first row = header) — if provided, "CSV" format is available. */
  csvRows?: string[][];
  /** Pre-rendered HTML string — if provided, "HTML" format is available. */
  htmlContent?: string;
}

export type ExportFormat = "json" | "csv" | "html";

function exportAs(format: ExportFormat, data: ExportableData) {
  const stem = data.filename.replace(/[^a-zA-Z0-9_-]/g, "-");

  switch (format) {
    case "json": {
      if (!data.jsonData) return;
      const str = JSON.stringify(data.jsonData, null, 2);
      downloadBlob(str, `${stem}.json`, "application/json");
      toast.success(`${data.label} exported as JSON`);
      break;
    }
    case "csv": {
      if (!data.csvRows) return;
      const csv = data.csvRows.map((row) => row.map(escCsv).join(",")).join("\n");
      downloadBlob(csv, `${stem}.csv`, "text/csv");
      toast.success(`${data.label} exported as CSV`);
      break;
    }
    case "html": {
      if (!data.htmlContent) return;
      downloadBlob(data.htmlContent, `${stem}.html`, "text/html");
      toast.success(`${data.label} exported as HTML`);
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Available formats helper
// ---------------------------------------------------------------------------
function availableFormats(data: ExportableData): ExportFormat[] {
  const f: ExportFormat[] = [];
  if (data.jsonData !== undefined) f.push("json");
  if (data.csvRows !== undefined) f.push("csv");
  if (data.htmlContent !== undefined) f.push("html");
  return f;
}

// ---------------------------------------------------------------------------
// ExportMenu component
// ---------------------------------------------------------------------------

export function ExportMenu({
  data,
  triggerClassName,
  triggerLabel,
  compact,
}: {
  data: ExportableData;
  triggerClassName?: string;
  triggerLabel?: string;
  compact?: boolean;
}) {
  const formats = availableFormats(data);

  if (formats.length === 0) return null;

  // Single-format shortcut: if only one format is available, export directly.
  if (formats.length === 1) {
    return (
      <Button
        variant="outline"
        size="sm"
        className={cn("h-7 gap-1.5 text-[10px]", triggerClassName)}
        onClick={() => exportAs(formats[0], data)}
      >
        <FileDown className="size-3" />
        {triggerLabel ?? `Export ${formats[0].toUpperCase()}`}
      </Button>
    );
  }

  // Multi-format dropdown
  const FORMAT_META: Record<ExportFormat, { icon: typeof FileJson; label: string; hint: string }> = {
    json: { icon: FileJson, label: "JSON", hint: "Structured data for programmatic use" },
    csv: { icon: Table2, label: "CSV", hint: "Spreadsheet-compatible tabular data" },
    html: { icon: FileText, label: "HTML", hint: "Styled, printable report" },
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className={cn("h-7 gap-1.5 text-[10px]", triggerClassName)}
        >
          <Download className="size-3" />
          {triggerLabel ?? "Export"}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="text-[10px] text-muted-foreground">
          Export {data.label}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {formats.map((fmt) => {
          const meta = FORMAT_META[fmt];
          const Icon = meta.icon;
          return (
            <DropdownMenuItem
              key={fmt}
              onClick={() => exportAs(fmt, data)}
              className="flex items-center gap-2.5 cursor-pointer"
            >
              <Icon className="size-3.5 text-muted-foreground" />
              <div className="flex flex-col">
                <span className="text-xs font-semibold">{meta.label}</span>
                <span className="text-[9px] text-muted-foreground">{meta.hint}</span>
              </div>
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ---------------------------------------------------------------------------
// Bulk ExportMenu (for "Export all" style actions)
// ---------------------------------------------------------------------------

export function BulkExportMenu({
  data,
  triggerClassName,
  triggerLabel,
}: {
  data: ExportableData;
  triggerClassName?: string;
  triggerLabel?: string;
}) {
  return (
    <ExportMenu
      data={data}
      triggerClassName={triggerClassName}
      triggerLabel={triggerLabel ?? "Export all"}
    />
  );
}
