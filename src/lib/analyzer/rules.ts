/**
 * Detection rules.
 *
 * Each rule is a small pure function: it receives the parsed events plus the
 * configuration, and returns zero or more incidents. Keeping them separate
 * makes each rule easy to read and easy to unit-test in isolation.
 */

import type { Incident, ParsedEvent, Severity } from "./types";

export interface DetectionConfig {
  /** Failed logins from one IP needed to call it a brute force attempt. */
  bruteForceThreshold: number;
  /** Sliding time window for the brute force count, in minutes. */
  bruteForceWindowMinutes: number;
  /** Failures that must precede a success for the "success after failures" rule. */
  successAfterFailuresThreshold: number;
  /** How soon after the failures the success must happen, in minutes. */
  successAfterFailuresWindowMinutes: number;
  /** Failed sudo attempts by one user before we alert. */
  sudoFailureThreshold: number;
  /** Sudo commands by one user before the volume looks unusual. */
  sudoVolumeThreshold: number;
  /** Distinct usernames tried by one IP before we call it user enumeration. */
  multiUserThreshold: number;
  /** Hours (UTC) considered outside normal working time. */
  offHoursStart: number;
  offHoursEnd: number;
}

export const DEFAULT_CONFIG: DetectionConfig = {
  bruteForceThreshold: 5,
  bruteForceWindowMinutes: 15,
  successAfterFailuresThreshold: 3,
  successAfterFailuresWindowMinutes: 10,
  sudoFailureThreshold: 3,
  sudoVolumeThreshold: 8,
  multiUserThreshold: 3,
  offHoursStart: 0,
  offHoursEnd: 5,
};

const FAILURE_TYPES = new Set(["FAILED_LOGIN", "INVALID_USER"]);

/** Group events by a key, ignoring events with no key. */
function groupBy<T>(items: T[], key: (item: T) => string | null): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (!k) continue;
    const bucket = map.get(k);
    if (bucket) bucket.push(item);
    else map.set(k, [item]);
  }
  return map;
}

function sortByTime(events: ParsedEvent[]): ParsedEvent[] {
  return [...events].sort((a, b) => (a.timeMs ?? 0) - (b.timeMs ?? 0) || a.lineNumber - b.lineNumber);
}

function evidenceOf(events: ParsedEvent[], limit = 6): string[] {
  return events.slice(0, limit).map((e) => `line ${e.lineNumber}: ${e.message}`);
}

function uniqueUsernames(events: ParsedEvent[]): string[] {
  return [...new Set(events.map((e) => e.username).filter((u): u is string => Boolean(u)))];
}

function span(events: ParsedEvent[]): { firstSeen: string | null; lastSeen: string | null } {
  const stamps = events.map((e) => e.occurredAt).filter((s): s is string => Boolean(s));
  return { firstSeen: stamps[0] ?? null, lastSeen: stamps[stamps.length - 1] ?? null };
}

/**
 * Rule 1 - Brute force.
 * Counts failed authentications per source IP inside a sliding time window.
 */
export function detectBruteForce(events: ParsedEvent[], config: DetectionConfig): Incident[] {
  const incidents: Incident[] = [];
  const windowMs = config.bruteForceWindowMinutes * 60_000;

  for (const [ip, ipEvents] of groupBy(events, (e) => e.sourceIp)) {
    const failures = sortByTime(ipEvents.filter((e) => FAILURE_TYPES.has(e.eventType)));
    if (failures.length < config.bruteForceThreshold) continue;

    // Find the densest window of failures for this IP.
    let best: ParsedEvent[] = [];
    for (let start = 0; start < failures.length; start += 1) {
      const startTime = failures[start]?.timeMs;
      const window = failures.filter((e, i) => {
        if (i < start) return false;
        if (startTime == null || e.timeMs == null) return true; // no timestamps: count all
        return e.timeMs - startTime <= windowMs;
      });
      if (window.length > best.length) best = window;
    }
    if (best.length < config.bruteForceThreshold) continue;

    const count = best.length;
    const severity: Severity = count >= 20 ? "CRITICAL" : count >= 10 ? "HIGH" : "MEDIUM";
    const users = uniqueUsernames(best);

    incidents.push({
      ruleId: "brute_force",
      alertType: "Possible Brute Force Attack",
      severity,
      sourceIp: ip,
      usernames: users,
      attemptCount: count,
      ...span(best),
      reason:
        `${count} failed authentication attempts were detected from ${ip} within a ` +
        `${config.bruteForceWindowMinutes}-minute window (threshold: ${config.bruteForceThreshold}). ` +
        `Severity is ${severity} because the attempt volume ` +
        (count >= 20
          ? "is very high and indicates an automated password-guessing tool."
          : count >= 10
            ? "is well above the threshold and looks automated."
            : "exceeds the configured threshold for normal user error."),
      recommendedAction:
        `Investigate ${ip} and review authentication activity for the affected ` +
        `account${users.length === 1 ? "" : "s"}. Consider blocking the IP and enforcing rate limiting or key-based SSH.`,
      evidence: evidenceOf(best),
    });
  }
  return incidents;
}

/**
 * Rule 2 - Successful login shortly after repeated failures.
 * This is the classic sign that a password-guessing attempt succeeded.
 */
export function detectSuccessAfterFailures(events: ParsedEvent[], config: DetectionConfig): Incident[] {
  const incidents: Incident[] = [];
  const windowMs = config.successAfterFailuresWindowMinutes * 60_000;

  for (const [ip, ipEvents] of groupBy(events, (e) => e.sourceIp)) {
    const ordered = sortByTime(ipEvents);
    for (const success of ordered.filter((e) => e.eventType === "SUCCESSFUL_LOGIN")) {
      const preceding = ordered.filter((e) => {
        if (!FAILURE_TYPES.has(e.eventType)) return false;
        if (e.timeMs == null || success.timeMs == null) return e.lineNumber < success.lineNumber;
        return e.timeMs <= success.timeMs && success.timeMs - e.timeMs <= windowMs;
      });
      if (preceding.length < config.successAfterFailuresThreshold) continue;

      const severity: Severity = preceding.length >= config.bruteForceThreshold ? "CRITICAL" : "HIGH";
      incidents.push({
        ruleId: "success_after_failures",
        alertType: "Successful Login After Repeated Failures",
        severity,
        sourceIp: ip,
        usernames: uniqueUsernames([success, ...preceding]),
        attemptCount: preceding.length,
        firstSeen: preceding[0]?.occurredAt ?? null,
        lastSeen: success.occurredAt,
        reason:
          `A successful login from ${ip}${success.username ? ` as "${success.username}"` : ""} followed ` +
          `${preceding.length} failed attempts within ${config.successAfterFailuresWindowMinutes} minutes. ` +
          `Severity is ${severity} because the account may now be under attacker control` +
          (severity === "CRITICAL" ? " and the preceding failures already met the brute force threshold." : "."),
        recommendedAction:
          "Treat the account as potentially compromised: reset its credentials, terminate active sessions, " +
          "and review what the session did after login (sudo use, new keys, file changes).",
        evidence: evidenceOf([...preceding.slice(-4), success]),
      });
    }
  }
  return incidents;
}

/**
 * Rule 3 - Suspicious sudo activity.
 * Flags repeated failed sudo attempts and unusually high sudo command volume.
 */
export function detectSuspiciousSudo(events: ParsedEvent[], config: DetectionConfig): Incident[] {
  const incidents: Incident[] = [];
  const sudoEvents = events.filter((e) => e.eventType === "SUDO_FAILURE" || e.eventType === "SUDO_SUCCESS");

  for (const [user, userEvents] of groupBy(sudoEvents, (e) => e.username)) {
    const ordered = sortByTime(userEvents);
    const failures = ordered.filter((e) => e.eventType === "SUDO_FAILURE");
    const successes = ordered.filter((e) => e.eventType === "SUDO_SUCCESS");

    if (failures.length >= config.sudoFailureThreshold) {
      const severity: Severity = failures.length >= config.sudoFailureThreshold * 2 ? "HIGH" : "MEDIUM";
      incidents.push({
        ruleId: "suspicious_sudo",
        alertType: "Suspicious Sudo Activity",
        severity,
        sourceIp: failures[0]?.sourceIp ?? null,
        usernames: [user],
        attemptCount: failures.length,
        ...span(failures),
        reason:
          `"${user}" triggered ${failures.length} failed sudo events (wrong password or not in sudoers). ` +
          `Severity is ${severity} because repeated privilege-escalation failures suggest either a misconfigured ` +
          `account or an attacker probing for root access.`,
        recommendedAction:
          `Confirm with the owner of "${user}" whether the activity was expected, and review the sudoers ` +
          "configuration and the commands attempted.",
        evidence: evidenceOf(failures),
      });
    }

    if (successes.length >= config.sudoVolumeThreshold) {
      incidents.push({
        ruleId: "sudo_volume",
        alertType: "Unusual Volume of Sudo Commands",
        severity: "MEDIUM",
        sourceIp: successes[0]?.sourceIp ?? null,
        usernames: [user],
        attemptCount: successes.length,
        ...span(successes),
        reason:
          `"${user}" ran ${successes.length} sudo commands (threshold: ${config.sudoVolumeThreshold}). ` +
          "Severity is MEDIUM because high privileged-command volume is often legitimate administration, " +
          "but is also typical of post-compromise activity.",
        recommendedAction:
          "Review the sudo command list for persistence or data-access commands (user creation, key changes, " +
          "log deletion) and confirm the activity with the account owner.",
        evidence: evidenceOf(successes),
      });
    }
  }
  return incidents;
}

/**
 * Rule 4 - One IP targeting multiple usernames (user enumeration).
 */
export function detectMultipleUserTargeting(events: ParsedEvent[], config: DetectionConfig): Incident[] {
  const incidents: Incident[] = [];

  for (const [ip, ipEvents] of groupBy(events, (e) => e.sourceIp)) {
    const attempts = sortByTime(
      ipEvents.filter((e) => FAILURE_TYPES.has(e.eventType) || e.eventType === "SUCCESSFUL_LOGIN"),
    );
    const users = uniqueUsernames(attempts);
    if (users.length < config.multiUserThreshold) continue;

    const severity: Severity = users.length >= config.multiUserThreshold * 2 ? "HIGH" : "MEDIUM";
    incidents.push({
      ruleId: "multi_user_targeting",
      alertType: "Multiple User Targeting (Enumeration)",
      severity,
      sourceIp: ip,
      usernames: users,
      attemptCount: attempts.length,
      ...span(attempts),
      reason:
        `${ip} attempted authentication against ${users.length} different usernames ` +
        `(${users.slice(0, 6).join(", ")}${users.length > 6 ? ", ..." : ""}). ` +
        `Severity is ${severity} because a single legitimate user rarely tries many accounts, ` +
        "so this looks like username enumeration.",
      recommendedAction:
        `Block or rate-limit ${ip}, then check whether any of the targeted accounts exist and were accessed successfully.`,
      evidence: evidenceOf(attempts),
    });
  }
  return incidents;
}

/**
 * Rule 5 - Abnormal login activity.
 * Successful logins during configured off-hours, and successful logins from an
 * IP that only ever appears once (no prior history in the file).
 */
export function detectAbnormalLogins(events: ParsedEvent[], config: DetectionConfig): Incident[] {
  const incidents: Incident[] = [];
  const successes = events.filter((e) => e.eventType === "SUCCESSFUL_LOGIN");

  const offHours = successes.filter((e) => {
    if (!e.occurredAt) return false;
    const hour = new Date(e.occurredAt).getUTCHours();
    return hour >= config.offHoursStart && hour <= config.offHoursEnd;
  });

  for (const [ip, ipEvents] of groupBy(offHours, (e) => e.sourceIp)) {
    const ordered = sortByTime(ipEvents);
    incidents.push({
      ruleId: "abnormal_login_hours",
      alertType: "Login Outside Normal Hours",
      severity: "LOW",
      sourceIp: ip,
      usernames: uniqueUsernames(ordered),
      attemptCount: ordered.length,
      ...span(ordered),
      reason:
        `${ordered.length} successful login(s) from ${ip} occurred between ` +
        `${String(config.offHoursStart).padStart(2, "0")}:00 and ${String(config.offHoursEnd).padStart(2, "0")}:59 UTC. ` +
        "Severity is LOW because off-hours access is unusual but frequently legitimate (on-call work, other time zones).",
      recommendedAction:
        "Confirm the login was expected. If the account owner does not recognise it, escalate and reset credentials.",
      evidence: evidenceOf(ordered),
    });
  }
  return incidents;
}

export type RuleFn = (events: ParsedEvent[], config: DetectionConfig) => Incident[];

/** All rules, run in order by the detection engine. */
export const RULES: RuleFn[] = [
  detectBruteForce,
  detectSuccessAfterFailures,
  detectSuspiciousSudo,
  detectMultipleUserTargeting,
  detectAbnormalLogins,
];
