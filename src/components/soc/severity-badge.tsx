/** Severity + status chips, driven entirely by design-system tokens. */
import { cn } from "@/lib/utils";
import type { IncidentStatus, Severity } from "@/lib/analyzer/types";

const SEVERITY_CLASSES: Record<Severity, string> = {
  CRITICAL: "bg-critical text-critical-foreground",
  HIGH: "bg-high text-high-foreground",
  MEDIUM: "bg-medium text-medium-foreground",
  LOW: "bg-low text-low-foreground",
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const key = (severity as Severity) in SEVERITY_CLASSES ? (severity as Severity) : "LOW";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm px-2 py-0.5 font-mono text-[0.65rem] font-semibold tracking-widest uppercase",
        SEVERITY_CLASSES[key],
        className,
      )}
    >
      {severity}
    </span>
  );
}

const STATUS_CLASSES: Record<IncidentStatus, string> = {
  NEW: "border-primary/60 text-primary",
  INVESTIGATING: "border-medium/60 text-medium",
  RESOLVED: "border-border text-muted-foreground",
};

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const key = (status as IncidentStatus) in STATUS_CLASSES ? (status as IncidentStatus) : "NEW";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border bg-transparent px-2 py-0.5 font-mono text-[0.65rem] tracking-widest uppercase",
        STATUS_CLASSES[key],
        className,
      )}
    >
      {status}
    </span>
  );
}
