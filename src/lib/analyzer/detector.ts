/**
 * Detection engine.
 *
 * Runs every rule over the parsed events and returns the resulting incidents,
 * ordered by severity so the most urgent alerts appear first, plus the summary
 * statistics the dashboard shows.
 */

import { DEFAULT_CONFIG, RULES, type DetectionConfig } from "./rules";
import type { Incident, ParsedEvent, Severity } from "./types";

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export interface AnalysisStats {
  totalEvents: number;
  totalAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  uniqueSourceIps: number;
  failedLogins: number;
  successfulLogins: number;
}

export interface AnalysisResult {
  incidents: Incident[];
  stats: AnalysisStats;
}

export function runDetection(
  events: ParsedEvent[],
  config: DetectionConfig = DEFAULT_CONFIG,
): Incident[] {
  const incidents = RULES.flatMap((rule) => {
    try {
      return rule(events, config);
    } catch (error) {
      // A broken rule must never take the whole analysis down.
      console.error("Detection rule failed", error);
      return [];
    }
  });

  return incidents.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      b.attemptCount - a.attemptCount ||
      a.alertType.localeCompare(b.alertType),
  );
}

export function summarise(events: ParsedEvent[], incidents: Incident[]): AnalysisStats {
  return {
    totalEvents: events.length,
    totalAlerts: incidents.length,
    criticalAlerts: incidents.filter((i) => i.severity === "CRITICAL").length,
    highAlerts: incidents.filter((i) => i.severity === "HIGH").length,
    uniqueSourceIps: new Set(events.map((e) => e.sourceIp).filter(Boolean)).size,
    failedLogins: events.filter((e) => e.eventType === "FAILED_LOGIN" || e.eventType === "INVALID_USER").length,
    successfulLogins: events.filter((e) => e.eventType === "SUCCESSFUL_LOGIN").length,
  };
}

export function analyse(events: ParsedEvent[], config: DetectionConfig = DEFAULT_CONFIG): AnalysisResult {
  const incidents = runDetection(events, config);
  return { incidents, stats: summarise(events, incidents) };
}
