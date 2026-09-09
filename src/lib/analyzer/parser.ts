/**
 * Linux auth.log parser.
 *
 * A typical line looks like:
 *   Sep  9 13:20:01 web-01 sshd[2841]: Failed password for invalid user root from 192.168.1.20 port 44212 ssh2
 *
 * The parser is deliberately defensive: any line it cannot understand is
 * recorded as "malformed" instead of throwing. Log content is treated as data
 * only - it is never evaluated, executed, or interpolated into SQL.
 */

import type { EventStatus, EventType, MalformedLine, ParsedEvent, ParseResult } from "./types";

/** Syslog header: month, day, time, host, process[pid], message */
const SYSLOG_RE =
  /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\S+)\s+([A-Za-z0-9._/-]+)(?:\[(\d+)\])?:\s*(.*)$/;

/** ISO-8601 (rsyslog / journald style) header. */
const ISO_RE =
  /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([A-Za-z0-9._/-]+)(?:\[(\d+)\])?:\s*(.*)$/;

const MONTHS: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
const IPV6 = /\b([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})\b/;

/** Extract the source IP from a message body, if one is present. */
export function extractIp(body: string): string | null {
  const fromMatch = body.match(/from\s+(\S+)/i);
  const candidate = fromMatch?.[1] ?? body;
  const v4 = candidate.match(IPV4)?.[1] ?? body.match(IPV4)?.[1];
  if (v4) {
    // Reject impossible octets rather than trusting the log blindly.
    const octets = v4.split(".").map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) return v4;
  }
  const v6 = candidate.match(IPV6)?.[1];
  if (v6 && v6.includes(":")) return v6;
  return null;

}

/** Extract the username a message refers to, if any. */
export function extractUsername(body: string): string | null {
  const patterns = [
    /for invalid user\s+([^\s]+)/i,
    /invalid user\s+([^\s]+)/i,
    /(?:password|publickey) for\s+([^\s]+)\s+from/i,
    /Accepted \w+ for\s+([^\s]+)/i,
    /user=([^\s]+)/i,
    /USER=([^\s]+)/,
    /for user\s+([^\s]+)/i,
    /session (?:opened|closed) for user\s+([^\s(]+)/i,
    /^\s*([A-Za-z0-9._-]+)\s*:\s*(?:TTY|user NOT in sudoers)/,
  ];
  for (const re of patterns) {
    const m = body.match(re);
    if (m?.[1]) return m[1].replace(/[:,]$/, "");
  }
  return null;
}

/** Classify a message body into an event type + outcome. */
export function classify(process: string, body: string): { eventType: EventType; status: EventStatus } {
  const b = body.toLowerCase();

  if (process.startsWith("sudo") || b.includes("sudo:")) {
    if (b.includes("authentication failure") || b.includes("incorrect password") || b.includes("not in the sudoers")) {
      return { eventType: "SUDO_FAILURE", status: "FAILURE" };
    }
    if (b.includes("command=")) return { eventType: "SUDO_SUCCESS", status: "SUCCESS" };
  }

  if (b.includes("invalid user") || b.includes("unknown user")) {
    return { eventType: "INVALID_USER", status: "FAILURE" };
  }
  if (b.startsWith("failed password") || b.includes("failed password") || b.includes("authentication failure")) {
    return { eventType: "FAILED_LOGIN", status: "FAILURE" };
  }
  if (b.includes("accepted password") || b.includes("accepted publickey")) {
    return { eventType: "SUCCESSFUL_LOGIN", status: "SUCCESS" };
  }
  if (b.includes("session opened for user")) return { eventType: "SESSION_OPENED", status: "INFO" };
  if (b.includes("session closed for user")) return { eventType: "SESSION_CLOSED", status: "INFO" };
  if (b.includes("connection closed") || b.includes("disconnected from")) {
    return { eventType: "CONNECTION_CLOSED", status: "INFO" };
  }
  return { eventType: "OTHER", status: "INFO" };
}

function buildSyslogDate(
  month: string,
  day: string,
  hh: string,
  mm: string,
  ss: string,
  referenceYear: number,
): Date | null {
  const monthIndex = MONTHS[month];
  if (monthIndex === undefined) return null;
  const date = new Date(
    Date.UTC(referenceYear, monthIndex, Number(day), Number(hh), Number(mm), Number(ss)),
  );
  return Number.isNaN(date.getTime()) ? null : date;
}

export interface ParseOptions {
  /**
   * Syslog lines have no year. We assume this one (defaults to the current
   * year) so time windows can be calculated.
   */
  referenceYear?: number;
}

/**
 * Parse a whole auth.log file into events + malformed lines.
 * Blank lines are skipped silently; anything else that fails is reported.
 */
export function parseAuthLog(content: string, options: ParseOptions = {}): ParseResult {
  const referenceYear = options.referenceYear ?? new Date().getUTCFullYear();
  const lines = content.split(/\r?\n/);
  const events: ParsedEvent[] = [];
  const malformed: MalformedLine[] = [];
  let totalLines = 0;

  lines.forEach((raw, index) => {
    const lineNumber = index + 1;
    if (raw.trim() === "") return;
    totalLines += 1;

    let occurredAt: string | null = null;
    let timeMs: number | null = null;
    let process = "";
    let body = "";

    const syslog = raw.match(SYSLOG_RE);
    const iso = syslog ? null : raw.match(ISO_RE);

    if (syslog) {
      const [, month, day, hh, mm, ss, , proc, , rest] = syslog;
      const date = buildSyslogDate(month, day, hh, mm, ss, referenceYear);
      if (date) {
        occurredAt = date.toISOString();
        timeMs = date.getTime();
      }
      process = proc;
      body = rest;
    } else if (iso) {
      const [, stamp, , proc, , rest] = iso;
      const date = new Date(stamp);
      if (!Number.isNaN(date.getTime())) {
        occurredAt = date.toISOString();
        timeMs = date.getTime();
      }
      process = proc;
      body = rest;
    } else {
      malformed.push({ lineNumber, raw, reason: "Line does not match a known syslog format" });
      return;
    }

    if (body.trim() === "") {
      malformed.push({ lineNumber, raw, reason: "Log line has no message body" });
      return;
    }

    const { eventType, status } = classify(process, body);
    events.push({
      lineNumber,
      occurredAt,
      timeMs,
      username: extractUsername(body),
      sourceIp: extractIp(body),
      eventType,
      status,
      message: raw,
    });
  });

  return { events, malformed, totalLines };
}
