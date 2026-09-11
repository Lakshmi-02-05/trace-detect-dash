# SOC Incident Detection & Log Analyzer

A beginner-to-intermediate **mini-SIEM**. Upload a Linux authentication log
(`auth.log`), and the app parses it, applies rule-based detection, classifies
each finding by severity, stores everything, and presents it on a dark
SOC-style dashboard with an alert triage workflow.

Everything happens on the uploaded log data. The app never scans networks,
contacts external hosts, or executes anything found inside a log file.

---

## Problem statement

Linux authentication logs contain the earliest evidence of account attacks:
password guessing, username enumeration, and privilege-escalation attempts.
Read line by line, that evidence is invisible — a busy server produces
thousands of lines a day. A junior SOC analyst needs three things: the raw
events, a small set of trustworthy detection rules, and a queue of alerts with
enough context to triage. This project builds exactly that.

## Architecture

```text
Browser (dashboard)
  │  reads the file locally, sends its text
  ▼
Server functions  (src/lib/soc.functions.ts)   ← validation, the API layer
  │
  ├─ parser    (src/lib/analyzer/parser.ts)    ← auth.log → structured events
  ├─ rules     (src/lib/analyzer/rules.ts)     ← 5 detection rules + thresholds
  └─ detector  (src/lib/analyzer/detector.ts)  ← runs rules, sorts, summarises
  │
  ▼
Database (Lovable Cloud / Postgres)
  uploads · log_events · incidents
```

The analysis core (`parser`, `rules`, `detector`) is pure data-in / data-out
code with no database or browser dependencies, which is why it can be
unit-tested on its own.

### Where the files live

```text
src/
├── lib/analyzer/
│   ├── types.ts        # shared shapes: ParsedEvent, Incident, Severity
│   ├── parser.ts       # syslog + ISO parsing, IP/username extraction
│   ├── rules.ts        # one function per detection rule + DEFAULT_CONFIG
│   ├── detector.ts     # runs all rules, orders alerts, computes stats
│   └── analyzer.test.ts# tests for the parser and every rule
├── lib/soc.functions.ts# the API: upload, dashboard, alert detail, status
├── routes/index.tsx    # SOC dashboard
├── routes/alerts.$id.tsx # incident detail + triage
└── components/soc/severity-badge.tsx
public/sample_auth.log  # realistic sample: normal + suspicious activity
```

## Features

- Upload `.log` / `.txt` authentication logs (2 MB limit) or analyze the bundled sample
- Parsing of timestamp, username, source IP, event type, status, raw message
- Five rule-based detections with severity and a written justification
- Dashboard: total events, total alerts, critical, high, unique source IPs, failed and successful logins
- Severity distribution chart, top suspicious IPs, event timeline, alert queue, parsed-event table
- Incident detail view with evidence lines and recommended analyst action
- Triage workflow: NEW → INVESTIGATING → RESOLVED
- Malformed lines are counted and skipped rather than crashing the analysis

## Technologies used

React + TanStack Start (routing, SSR, server functions), TypeScript, Tailwind CSS,
Recharts, Postgres (Lovable Cloud), Zod for input validation, Vitest for tests.

> Note: the original brief specified Express + Python + SQLite. This project runs
> on a React/TanStack stack with a hosted Postgres database, so the parser and
> detection engine are written in TypeScript instead of Python and the storage
> layer is Postgres instead of SQLite. The design — separate parser, rule set,
> detection engine, API layer, dashboard — is unchanged.

## Detection rules

| Rule | Fires when | Severity |
| --- | --- | --- |
| Brute force | ≥ 5 failed authentications from one IP inside a 15-minute sliding window | MEDIUM (5–9), HIGH (10–19), CRITICAL (≥ 20) |
| Successful login after failures | A success from an IP that had ≥ 3 failures in the previous 10 minutes | HIGH, or CRITICAL when the failures also met the brute force threshold |
| Suspicious sudo activity | ≥ 3 failed sudo events for one user (wrong password / not in sudoers) | MEDIUM, HIGH at double the threshold |
| Unusual sudo volume | ≥ 8 successful sudo commands by one user | MEDIUM |
| Multiple user targeting | One IP attempts ≥ 3 distinct usernames | MEDIUM, HIGH at ≥ 6 usernames |
| Abnormal login activity | Successful login between 00:00 and 05:59 UTC | LOW |

Thresholds live in one place — `DEFAULT_CONFIG` in `src/lib/analyzer/rules.ts` —
so they can be tuned without touching rule logic.

### Severity reasoning

Severity is never a bare label: each incident stores a `reason` explaining the
counts and the window that produced it, and a `recommended_action`. LOW means
"unusual but often legitimate", CRITICAL means "assume compromise and act now".

## API

Implemented as typed server functions in `src/lib/soc.functions.ts`, which map
to the REST-style operations from the brief:

| Operation | Server function |
| --- | --- |
| `POST /api/logs/upload` | `uploadLog({ filename, content })` |
| `GET /api/events` + `GET /api/alerts` + `GET /api/stats` | `getDashboard()` |
| `GET /api/alerts/:id` | `getAlert({ id })` |
| `PATCH /api/alerts/:id/status` | `setAlertStatus({ id, status })` |
| Detection thresholds | `getDetectionConfig()` |

## Database

Three tables:

- `uploads` — one row per analyzed file: filename, total / parsed / malformed line counts
- `log_events` — one row per parsed line: time, username, source IP, event type, status, raw message, line number
- `incidents` — one row per alert: rule id, alert type, severity, source IP, usernames, attempt count, first/last seen, reason, recommended action, evidence lines, status (`NEW` / `INVESTIGATING` / `RESOLVED`)

## How to install and run

The project runs in Lovable — the preview is always live, so there is nothing to
install to use it. To work on it locally:

```bash
bun install      # or: npm install
bun run dev      # dev server on http://localhost:8080
```

Then open the app, click **Analyze sample log**, or **Upload auth.log** and pick
your own file.

## Example alert

```text
ALERT: Possible Brute Force Attack
Severity: HIGH
Source IP: 192.168.1.20
Failed Attempts: 17

Reason:
17 failed authentication attempts were detected from 192.168.1.20 within a
15-minute window (threshold: 5). Severity is HIGH because the attempt volume
is well above the threshold and looks automated.

Recommended Action:
Investigate 192.168.1.20 and review authentication activity for the affected
accounts. Consider blocking the IP and enforcing rate limiting or key-based SSH.
```

## Testing

```bash
bunx vitest run
```

18 tests cover the parser (standard sshd lines, sudo lines, malformed input,
invalid IPs) and every detection rule, including the negative cases: failures
spread beyond the window, a single retry, one user retrying, normal sudo use,
and daytime logins.

## Screenshots

_Add screenshots here:_

- `docs/dashboard.png` — full SOC dashboard with counters and charts
- `docs/alert-detail.png` — incident detail with evidence and triage buttons

## Security considerations

- Uploads validated twice (browser and server): extension allow-list, 2 MB size cap, rejection of binary content
- Filenames sanitised to a base name, so `../../etc/passwd` cannot traverse paths
- Log content is treated strictly as data: never evaluated, executed, or concatenated into SQL
- All database access uses parameterised client queries
- Row-level security is enabled on every table
- Errors return short messages; internal details stay in server logs
- Stored messages and evidence lines are length-capped to bound the data kept

## Future improvements

- Configurable thresholds in the UI, saved per user
- GeoIP and threat-intel enrichment of source IPs (offline data sets)
- Correlation across uploads to spot slow, long-running attacks
- Analyst notes and an audit trail on each incident
- Sigma-style rule definitions loaded from files instead of code
- Export incidents as CSV or JSON for reporting

## What I Learned

**SOC workflow.** A SOC turns raw telemetry into decisions: collect → parse →
detect → triage → respond. Building each step made clear that detection is the
smallest part; presenting context so a human can decide quickly is the hard part.

**Log analysis.** Linux auth logs are semi-structured. Real files mix syslog and
ISO timestamps, multiple processes (`sshd`, `sudo`, `CRON`, `pam_unix`), and
truncated lines, so a parser must degrade gracefully instead of throwing.

**SIEM concepts.** A SIEM is normalisation + a rule engine + storage + a console.
Splitting the code that way (parser / rules / detector / API / dashboard) made
each piece replaceable and testable.

**IOC identification.** The indicators here are simple and durable: repeated
failures from one source IP, a success immediately after failures, one IP
sweeping many usernames, and privilege-escalation failures.

**Rule-based detection.** Rules are explainable and cheap, but threshold-bound:
too low and analysts drown in false positives, too high and slow attacks pass.
That is why every threshold is configuration, not a hard-coded number.

**Incident triage.** Statuses (NEW / INVESTIGATING / RESOLVED) exist so work is
not repeated and nothing is silently dropped.

**Severity classification.** Severity must be justified. Storing the reason
alongside the level forced each rule to state what the evidence actually shows.

**REST APIs.** Clear operation boundaries (upload, list, detail, status update),
validation at the boundary, and never trusting client input.

**Databases and SQL safety.** Schema design for events versus derived incidents,
indexes on the columns used for lookups, and parameterised queries — untrusted
log text must never reach a query as SQL.

**Linux authentication logs.** Which messages `sshd` and `sudo` emit, the
difference between "invalid user" and "failed password", and why session
open/close lines matter when reconstructing an attacker's timeline.
