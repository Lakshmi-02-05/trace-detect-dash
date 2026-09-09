/**
 * Server functions: the API layer of the analyzer.
 *
 * Everything that touches the database lives here so the browser never talks
 * to the database directly with raw input. Each function validates its input
 * with zod, and all database access uses the client library's parameterised
 * queries (no string-built SQL).
 */

import { createServerFn } from "@tanstack/react-start";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";
import type { Database } from "@/integrations/supabase/types";
import { parseAuthLog } from "./analyzer/parser";
import { analyse } from "./analyzer/detector";
import { DEFAULT_CONFIG } from "./analyzer/rules";

/** Hard limits that protect the server from oversized or hostile uploads. */
export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024; // 2 MB
export const MAX_EVENTS_STORED = 5000;
const ALLOWED_EXTENSIONS = [".log", ".txt"];

function db() {
  return createClient<Database>(
    process.env["SUPABASE_URL"]!,
    process.env["SUPABASE_PUBLISHABLE_KEY"]!,
    { auth: { storage: undefined, persistSession: false, autoRefreshToken: false } },
  );
}

/**
 * Filenames are only ever used as a label. We strip any directory component so
 * a name like "../../etc/passwd" cannot be used for path traversal, and we
 * keep it short.
 */
export function sanitiseFilename(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "upload.log";
  return base.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120) || "upload.log";
}

export function isAllowedFilename(name: string): boolean {
  const lower = sanitiseFilename(name).toLowerCase();
  return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

const uploadSchema = z.object({
  filename: z.string().min(1).max(255),
  content: z.string().min(1).max(MAX_UPLOAD_BYTES),
});

/**
 * POST /api/logs/upload equivalent.
 * Parses the log, runs detection, and stores events + incidents.
 */
export const uploadLog = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => uploadSchema.parse(data))
  .handler(async ({ data }) => {
    const filename = sanitiseFilename(data.filename);
    if (!isAllowedFilename(filename)) {
      throw new Error("Only .log and .txt files are accepted.");
    }
    // Reject binary-looking content (NUL bytes) - auth logs are plain text.
    if (data.content.includes("\u0000")) {
      throw new Error("The file does not look like a plain-text log.");
    }

    const parsed = parseAuthLog(data.content);
    if (parsed.events.length === 0) {
      throw new Error("No recognisable authentication events were found in this file.");
    }

    const { incidents } = analyse(parsed.events, DEFAULT_CONFIG);
    const supabase = db();

    const { data: upload, error: uploadError } = await supabase
      .from("uploads")
      .insert({
        filename,
        total_lines: parsed.totalLines,
        parsed_lines: parsed.events.length,
        malformed_lines: parsed.malformed.length,
      })
      .select("id")
      .single();
    if (uploadError || !upload) throw new Error("Could not save the upload.");

    const eventRows = parsed.events.slice(0, MAX_EVENTS_STORED).map((e) => ({
      upload_id: upload.id,
      occurred_at: e.occurredAt,
      username: e.username,
      source_ip: e.sourceIp,
      event_type: e.eventType,
      status: e.status,
      message: e.message.slice(0, 2000),
      line_number: e.lineNumber,
    }));
    const { error: eventsError } = await supabase.from("log_events").insert(eventRows);
    if (eventsError) throw new Error("Could not save the parsed events.");

    if (incidents.length > 0) {
      const { error: incidentError } = await supabase.from("incidents").insert(
        incidents.map((i) => ({
          upload_id: upload.id,
          rule_id: i.ruleId,
          alert_type: i.alertType,
          severity: i.severity,
          source_ip: i.sourceIp,
          usernames: i.usernames,
          attempt_count: i.attemptCount,
          first_seen: i.firstSeen,
          last_seen: i.lastSeen,
          reason: i.reason,
          recommended_action: i.recommendedAction,
          evidence: i.evidence.map((line) => line.slice(0, 2000)),
        })),
      );
      if (incidentError) throw new Error("Could not save the detected alerts.");
    }

    return {
      uploadId: upload.id,
      filename,
      totalLines: parsed.totalLines,
      parsedLines: parsed.events.length,
      malformedLines: parsed.malformed.length,
      alertCount: incidents.length,
    };
  });

/** GET /api/stats + /api/events + /api/alerts, in one dashboard payload. */
export const getDashboard = createServerFn({ method: "GET" }).handler(async () => {
  const supabase = db();

  const [eventsRes, alertsRes, uploadsRes] = await Promise.all([
    supabase
      .from("log_events")
      .select("id,occurred_at,username,source_ip,event_type,status,message,line_number")
      .order("occurred_at", { ascending: false })
      .limit(500),
    supabase
      .from("incidents")
      .select(
        "id,rule_id,alert_type,severity,source_ip,usernames,attempt_count,first_seen,last_seen,status,detected_at",
      )
      .order("detected_at", { ascending: false })
      .limit(200),
    supabase
      .from("uploads")
      .select("id,filename,total_lines,parsed_lines,malformed_lines,created_at")
      .order("created_at", { ascending: false })
      .limit(10),
  ]);

  if (eventsRes.error || alertsRes.error || uploadsRes.error) {
    return { events: [], alerts: [], uploads: [], stats: null, error: "Could not load dashboard data." as const };
  }

  const events = eventsRes.data ?? [];
  const alerts = alertsRes.data ?? [];

  // Counters. Kept here so the dashboard is a dumb renderer.
  const failedLogins = events.filter((e) => e.event_type === "FAILED_LOGIN" || e.event_type === "INVALID_USER").length;
  const successfulLogins = events.filter((e) => e.event_type === "SUCCESSFUL_LOGIN").length;

  const ipCounts = new Map<string, { ip: string; events: number; failures: number }>();
  for (const e of events) {
    if (!e.source_ip) continue;
    const entry = ipCounts.get(e.source_ip) ?? { ip: e.source_ip, events: 0, failures: 0 };
    entry.events += 1;
    if (e.status === "FAILURE") entry.failures += 1;
    ipCounts.set(e.source_ip, entry);
  }

  return {
    events,
    alerts,
    uploads: uploadsRes.data ?? [],
    error: null,
    stats: {
      totalEvents: events.length,
      totalAlerts: alerts.length,
      criticalAlerts: alerts.filter((a) => a.severity === "CRITICAL").length,
      highAlerts: alerts.filter((a) => a.severity === "HIGH").length,
      uniqueSourceIps: ipCounts.size,
      failedLogins,
      successfulLogins,
      severityCounts: {
        CRITICAL: alerts.filter((a) => a.severity === "CRITICAL").length,
        HIGH: alerts.filter((a) => a.severity === "HIGH").length,
        MEDIUM: alerts.filter((a) => a.severity === "MEDIUM").length,
        LOW: alerts.filter((a) => a.severity === "LOW").length,
      },
      topIps: [...ipCounts.values()].sort((a, b) => b.failures - a.failures || b.events - a.events).slice(0, 6),
    },
  };
});

/** GET /api/alerts/:id — full incident detail plus its evidence. */
export const getAlert = createServerFn({ method: "GET" })
  .inputValidator((data: unknown) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data }) => {
    const supabase = db();
    const { data: alert, error } = await supabase
      .from("incidents")
      .select("*")
      .eq("id", data.id)
      .maybeSingle();
    if (error) throw new Error("Could not load the alert.");
    return alert;
  });

/** PATCH /api/alerts/:id/status — the triage workflow. */
export const setAlertStatus = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) =>
    z
      .object({ id: z.string().uuid(), status: z.enum(["NEW", "INVESTIGATING", "RESOLVED"]) })
      .parse(data),
  )
  .handler(async ({ data }) => {
    const supabase = db();
    const { error } = await supabase.from("incidents").update({ status: data.status }).eq("id", data.id);
    if (error) throw new Error("Could not update the alert status.");
    return { id: data.id, status: data.status };
  });

/** Configuration the UI displays, so thresholds are never hard-coded twice. */
export const getDetectionConfig = createServerFn({ method: "GET" }).handler(async () => DEFAULT_CONFIG);
