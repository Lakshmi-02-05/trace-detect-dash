/**
 * Shared types for the log analyzer.
 *
 * These types are pure data (no database, no browser APIs) so the parser and
 * the detection engine can be unit-tested on their own.
 */

/** What kind of authentication activity a log line represents. */
export type EventType =
  | "FAILED_LOGIN"
  | "SUCCESSFUL_LOGIN"
  | "INVALID_USER"
  | "SUDO_SUCCESS"
  | "SUDO_FAILURE"
  | "SESSION_OPENED"
  | "SESSION_CLOSED"
  | "CONNECTION_CLOSED"
  | "OTHER";

/** Outcome of the event, used for the dashboard counters. */
export type EventStatus = "SUCCESS" | "FAILURE" | "INFO";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type IncidentStatus = "NEW" | "INVESTIGATING" | "RESOLVED";

/** One successfully parsed line of an auth log. */
export interface ParsedEvent {
  /** 1-based line number in the uploaded file (useful as evidence). */
  lineNumber: number;
  /** ISO timestamp, or null when the line had no readable timestamp. */
  occurredAt: string | null;
  /** Epoch milliseconds, convenience field for time-window maths. */
  timeMs: number | null;
  username: string | null;
  sourceIp: string | null;
  eventType: EventType;
  status: EventStatus;
  /** The original log line, kept verbatim as evidence. Never executed. */
  message: string;
}

/** A line we could not understand, kept for transparency. */
export interface MalformedLine {
  lineNumber: number;
  raw: string;
  reason: string;
}

export interface ParseResult {
  events: ParsedEvent[];
  malformed: MalformedLine[];
  totalLines: number;
}

/** A detected security incident (alert). */
export interface Incident {
  ruleId: string;
  alertType: string;
  severity: Severity;
  sourceIp: string | null;
  usernames: string[];
  attemptCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  /** Plain-language explanation of why this was flagged. */
  reason: string;
  /** What an analyst should do next. */
  recommendedAction: string;
  /** Original log lines that support the finding. */
  evidence: string[];
}
