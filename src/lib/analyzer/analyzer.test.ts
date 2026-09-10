/**
 * Tests for the parser and for every detection rule.
 * Run with: bunx vitest run
 */

import { describe, expect, it } from "vitest";
import { extractIp, extractUsername, parseAuthLog } from "./parser";
import {
  DEFAULT_CONFIG,
  detectAbnormalLogins,
  detectBruteForce,
  detectMultipleUserTargeting,
  detectSuccessAfterFailures,
  detectSuspiciousSudo,
} from "./rules";
import { analyse } from "./detector";

const YEAR = 2026;
const parse = (lines: string[]) => parseAuthLog(lines.join("\n"), { referenceYear: YEAR }).events;

function failedLogins(ip: string, count: number, user = "root", startSecond = 0) {
  return Array.from({ length: count }, (_, i) => {
    const total = startSecond + i * 2;
    const mm = String(Math.floor(total / 60)).padStart(2, "0");
    const ss = String(total % 60).padStart(2, "0");
    return `Sep  9 11:${mm}:${ss} web-01 sshd[15${i}]: Failed password for ${user} from ${ip} port 4421${i} ssh2`;
  });
}

describe("parser", () => {
  it("parses a standard sshd failure line", () => {
    const [event] = parse(["Sep  9 11:04:01 web-01 sshd[1502]: Failed password for invalid user root from 192.168.1.20 port 44212 ssh2"]);
    expect(event?.eventType).toBe("INVALID_USER");
    expect(event?.status).toBe("FAILURE");
    expect(event?.username).toBe("root");
    expect(event?.sourceIp).toBe("192.168.1.20");
    expect(event?.occurredAt).toBe("2026-09-09T11:04:01.000Z");
  });

  it("parses successful logins and sudo commands", () => {
    const events = parse([
      "Sep  9 08:12:03 web-01 sshd[1042]: Accepted password for deploy from 10.0.0.15 port 51422 ssh2",
      "Sep  9 08:14:51 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
    ]);
    expect(events[0]?.eventType).toBe("SUCCESSFUL_LOGIN");
    expect(events[1]?.eventType).toBe("SUDO_SUCCESS");
    expect(events[1]?.username).toBe("deploy");
  });

  it("records malformed lines instead of throwing, and skips blank lines", () => {
    const result = parseAuthLog(["", "total garbage line", "Sep  9 11:04:01 web-01 sshd[1]: Failed password for root from 10.0.0.9 port 1 ssh2"].join("\n"), {
      referenceYear: YEAR,
    });
    expect(result.events).toHaveLength(1);
    expect(result.malformed).toHaveLength(1);
    expect(result.totalLines).toBe(2);
  });

  it("ignores impossible IP addresses", () => {
    expect(extractIp("Failed password for root from 999.1.1.1 port 22 ssh2")).toBeNull();
    expect(extractUsername("pam_unix(sudo:auth): authentication failure; user=svc_backup")).toBe("svc_backup");
  });
});

describe("rule: brute force", () => {
  it("fires once the threshold is reached inside the window", () => {
    const incidents = detectBruteForce(parse(failedLogins("192.168.1.20", 6)), DEFAULT_CONFIG);
    expect(incidents).toHaveLength(1);
    expect(incidents[0]?.severity).toBe("MEDIUM");
    expect(incidents[0]?.attemptCount).toBe(6);
  });

  it("escalates severity with volume", () => {
    expect(detectBruteForce(parse(failedLogins("10.1.1.1", 12)), DEFAULT_CONFIG)[0]?.severity).toBe("HIGH");
    expect(detectBruteForce(parse(failedLogins("10.1.1.2", 22)), DEFAULT_CONFIG)[0]?.severity).toBe("CRITICAL");
  });

  it("does not fire below the threshold", () => {
    expect(detectBruteForce(parse(failedLogins("10.2.2.2", 4)), DEFAULT_CONFIG)).toHaveLength(0);
  });

  it("does not fire when failures are spread beyond the window", () => {
    const spread = [
      "Sep  9 01:00:00 web-01 sshd[1]: Failed password for root from 10.3.3.3 port 1 ssh2",
      "Sep  9 02:00:00 web-01 sshd[2]: Failed password for root from 10.3.3.3 port 2 ssh2",
      "Sep  9 03:00:00 web-01 sshd[3]: Failed password for root from 10.3.3.3 port 3 ssh2",
      "Sep  9 04:00:00 web-01 sshd[4]: Failed password for root from 10.3.3.3 port 4 ssh2",
      "Sep  9 05:00:00 web-01 sshd[5]: Failed password for root from 10.3.3.3 port 5 ssh2",
    ];
    expect(detectBruteForce(parse(spread), DEFAULT_CONFIG)).toHaveLength(0);
  });
});

describe("rule: successful login after failures", () => {
  it("flags a success that follows repeated failures from the same IP", () => {
    const events = parse([
      ...failedLogins("203.0.113.45", 5, "svc_backup"),
      "Sep  9 11:00:20 web-01 sshd[1707]: Accepted password for svc_backup from 203.0.113.45 port 33042 ssh2",
    ]);
    const incidents = detectSuccessAfterFailures(events, DEFAULT_CONFIG);
    expect(incidents).toHaveLength(1);
    expect(incidents[0]?.severity).toBe("CRITICAL");
    expect(incidents[0]?.usernames).toContain("svc_backup");
  });

  it("ignores a success with only one prior failure", () => {
    const events = parse([
      "Sep  9 09:05:17 web-01 sshd[1191]: Failed password for alice from 10.0.0.24 port 49190 ssh2",
      "Sep  9 09:05:29 web-01 sshd[1191]: Accepted password for alice from 10.0.0.24 port 49190 ssh2",
    ]);
    expect(detectSuccessAfterFailures(events, DEFAULT_CONFIG)).toHaveLength(0);
  });
});

describe("rule: suspicious sudo activity", () => {
  it("flags repeated failed sudo attempts", () => {
    const events = parse([
      "Sep  9 12:22:40 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=svc_backup uid=1004 euid=0 tty=/dev/pts/2 ruser=svc_backup rhost=  user=svc_backup",
      "Sep  9 12:22:52 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=svc_backup uid=1004 euid=0 tty=/dev/pts/2 ruser=svc_backup rhost=  user=svc_backup",
      "Sep  9 12:23:05 web-01 sudo:   svc_backup : user NOT in the sudoers file ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
    ]);
    const incidents = detectSuspiciousSudo(events, DEFAULT_CONFIG);
    expect(incidents.some((i) => i.ruleId === "suspicious_sudo")).toBe(true);
  });

  it("flags unusually high sudo command volume", () => {
    const events = parse(
      Array.from(
        { length: 9 },
        (_, i) =>
          `Sep  9 14:0${i}:00 web-01 sudo:   alice : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/echo ${i}`,
      ),
    );
    const incidents = detectSuspiciousSudo(events, DEFAULT_CONFIG);
    expect(incidents.some((i) => i.ruleId === "sudo_volume")).toBe(true);
  });

  it("stays quiet for a couple of normal sudo commands", () => {
    const events = parse([
      "Sep  9 08:14:51 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
    ]);
    expect(detectSuspiciousSudo(events, DEFAULT_CONFIG)).toHaveLength(0);
  });
});

describe("rule: multiple user targeting", () => {
  it("fires when one IP tries several usernames", () => {
    const events = parse([
      "Sep  9 13:40:11 web-01 sshd[1901]: Invalid user admin from 198.51.100.7 port 60122",
      "Sep  9 13:40:13 web-01 sshd[1902]: Invalid user support from 198.51.100.7 port 60126",
      "Sep  9 13:40:15 web-01 sshd[1903]: Invalid user info from 198.51.100.7 port 60130",
    ]);
    const incidents = detectMultipleUserTargeting(events, DEFAULT_CONFIG);
    expect(incidents).toHaveLength(1);
    expect(incidents[0]?.usernames).toHaveLength(3);
  });

  it("does not fire for a single user retrying", () => {
    expect(detectMultipleUserTargeting(parse(failedLogins("10.9.9.9", 6, "alice")), DEFAULT_CONFIG)).toHaveLength(0);
  });
});

describe("rule: abnormal login activity", () => {
  it("flags an off-hours successful login", () => {
    const events = parse([
      "Sep 10 02:13:48 web-01 sshd[2340]: Accepted password for alice from 45.33.22.101 port 41022 ssh2",
    ]);
    const incidents = detectAbnormalLogins(events, DEFAULT_CONFIG);
    expect(incidents).toHaveLength(1);
    expect(incidents[0]?.severity).toBe("LOW");
  });

  it("does not flag a daytime login", () => {
    const events = parse([
      "Sep 10 09:13:48 web-01 sshd[2340]: Accepted password for alice from 45.33.22.101 port 41022 ssh2",
    ]);
    expect(detectAbnormalLogins(events, DEFAULT_CONFIG)).toHaveLength(0);
  });
});

describe("engine", () => {
  it("orders alerts by severity and summarises counts", () => {
    const events = parse([
      ...failedLogins("192.168.1.20", 22),
      "Sep 10 02:13:48 web-01 sshd[2340]: Accepted password for alice from 45.33.22.101 port 41022 ssh2",
    ]);
    const { incidents, stats } = analyse(events);
    expect(incidents[0]?.severity).toBe("CRITICAL");
    expect(stats.failedLogins).toBe(22);
    expect(stats.successfulLogins).toBe(1);
    expect(stats.uniqueSourceIps).toBe(2);
  });
});
