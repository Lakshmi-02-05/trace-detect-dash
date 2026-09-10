/**
 * SOC dashboard.
 *
 * Reads everything through the server functions in src/lib/soc.functions.ts and
 * renders it: counters, severity distribution, top suspicious IPs, an event
 * timeline, the recent alert queue, and the raw parsed event table.
 */

import { createFileRoute, Link } from "@tanstack/react-router";
import { queryOptions, useQueryClient, useSuspenseQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { SeverityBadge, StatusBadge } from "@/components/soc/severity-badge";
import { getDashboard, uploadLog, MAX_UPLOAD_BYTES } from "@/lib/soc.functions";
import { DEFAULT_CONFIG } from "@/lib/analyzer/rules";

const dashboardQuery = queryOptions({
  queryKey: ["dashboard"],
  queryFn: () => getDashboard(),
});

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SOC Dashboard — Incident Detection & Log Analyzer" },
      {
        name: "description",
        content:
          "Live SOC dashboard for uploaded Linux auth.log files: event counters, severity distribution, top suspicious IPs and the alert queue.",
      },
      { property: "og:title", content: "SOC Dashboard — Incident Detection & Log Analyzer" },
      {
        property: "og:description",
        content: "Event counters, severity distribution, top suspicious IPs and the alert triage queue.",
      },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(dashboardQuery),
  component: Dashboard,
});

const ALLOWED_TYPES = [".log", ".txt"];

function Dashboard() {
  const { data } = useSuspenseQuery(dashboardQuery);
  const queryClient = useQueryClient();
  const fileInput = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);

  const stats = data.stats;

  /** Client-side validation happens first; the server validates again. */
  async function handleFile(file: File) {
    const lower = file.name.toLowerCase();
    if (!ALLOWED_TYPES.some((ext) => lower.endsWith(ext))) {
      toast.error("Please choose a .log or .txt file.");
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      toast.error("That file is larger than 2 MB.");
      return;
    }
    setBusy(true);
    try {
      const content = await file.text();
      const result = await uploadLog({ data: { filename: file.name, content } });
      toast.success(
        `${result.parsedLines} events parsed, ${result.alertCount} alerts raised` +
          (result.malformedLines ? `, ${result.malformedLines} unreadable lines skipped` : ""),
      );
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "That file could not be analyzed.");
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  async function analyseSample() {
    setBusy(true);
    try {
      const content = await fetch("/sample_auth.log").then((res) => res.text());
      const result = await uploadLog({ data: { filename: "sample_auth.log", content } });
      toast.success(`Sample analyzed: ${result.alertCount} alerts raised`);
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "The sample could not be analyzed.");
    } finally {
      setBusy(false);
    }
  }

  const severityData = stats
    ? (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((key) => ({
        name: key,
        value: stats.severityCounts[key],
      }))
    : [];
  const severityColors: Record<string, string> = {
    CRITICAL: "var(--critical)",
    HIGH: "var(--high)",
    MEDIUM: "var(--medium)",
    LOW: "var(--low)",
  };

  // Timeline: events grouped per hour of the day.
  const timeline = (() => {
    const buckets = new Map<string, { hour: string; events: number; failures: number }>();
    for (const event of data.events) {
      if (!event.occurred_at) continue;
      const d = new Date(event.occurred_at);
      const hour = `${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")} ${String(d.getUTCHours()).padStart(2, "0")}h`;
      const entry = buckets.get(hour) ?? { hour, events: 0, failures: 0 };
      entry.events += 1;
      if (event.status === "FAILURE") entry.failures += 1;
      buckets.set(hour, entry);
    }
    return [...buckets.values()].sort((a, b) => a.hour.localeCompare(b.hour));
  })();

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-panel/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-5">
          <div>
            <p className="mono-label">Security Operations Center</p>
            <h1 className="font-mono text-xl font-semibold tracking-tight">
              Incident Detection &amp; Log Analyzer
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <input
              ref={fileInput}
              type="file"
              accept=".log,.txt"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void handleFile(file);
              }}
            />
            <Button variant="secondary" disabled={busy} onClick={() => void analyseSample()}>
              Analyze sample log
            </Button>
            <Button disabled={busy} onClick={() => fileInput.current?.click()}>
              {busy ? "Analyzing…" : "Upload auth.log"}
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {data.error && (
          <p className="panel px-4 py-3 text-sm text-destructive">{data.error}</p>
        )}

        {/* Counters */}
        <section className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
          <Metric label="Total events" value={stats?.totalEvents ?? 0} />
          <Metric label="Total alerts" value={stats?.totalAlerts ?? 0} />
          <Metric label="Critical" value={stats?.criticalAlerts ?? 0} tone="critical" />
          <Metric label="High" value={stats?.highAlerts ?? 0} tone="high" />
          <Metric label="Unique IPs" value={stats?.uniqueSourceIps ?? 0} />
          <Metric label="Failed logins" value={stats?.failedLogins ?? 0} tone="critical" />
          <Metric label="Successful logins" value={stats?.successfulLogins ?? 0} tone="ok" />
        </section>

        <section className="grid gap-4 lg:grid-cols-3">
          {/* Severity distribution */}
          <div className="panel p-5">
            <p className="mono-label">Severity distribution</p>
            {severityData.some((d) => d.value > 0) ? (
              <div className="mt-2 h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={78} stroke="none">
                      {severityData.map((entry) => (
                        <Cell key={entry.name} fill={severityColors[entry.name]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "var(--popover)",
                        border: "1px solid var(--border)",
                        borderRadius: "0.5rem",
                        fontSize: "0.8rem",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <Empty>No alerts yet</Empty>
            )}
            <ul className="mt-2 space-y-1">
              {severityData.map((entry) => (
                <li key={entry.name} className="flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2">
                    <span className="size-2 rounded-full" style={{ background: severityColors[entry.name] }} />
                    {entry.name}
                  </span>
                  <span className="font-mono">{entry.value}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Top suspicious IPs */}
          <div className="panel p-5">
            <p className="mono-label">Top suspicious source IPs</p>
            {stats?.topIps.length ? (
              <ul className="mt-3 space-y-3">
                {stats.topIps.map((ip) => (
                  <li key={ip.ip}>
                    <div className="flex items-center justify-between font-mono text-sm">
                      <span>{ip.ip}</span>
                      <span className="text-muted-foreground">
                        {ip.failures} failed / {ip.events} events
                      </span>
                    </div>
                    <div className="mt-1 h-1.5 rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-critical"
                        style={{
                          width: `${Math.max(4, (ip.failures / Math.max(1, stats.topIps[0]?.failures ?? 1)) * 100)}%`,
                        }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>No source IPs yet</Empty>
            )}
          </div>

          {/* Event timeline */}
          <div className="panel p-5">
            <p className="mono-label">Event timeline (UTC, per hour)</p>
            {timeline.length ? (
              <div className="mt-3 h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={timeline}>
                    <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} interval="preserveStartEnd" />
                    <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} width={24} />
                    <Tooltip
                      contentStyle={{
                        background: "var(--popover)",
                        border: "1px solid var(--border)",
                        borderRadius: "0.5rem",
                        fontSize: "0.8rem",
                      }}
                    />
                    <Bar dataKey="events" fill="var(--primary)" radius={[2, 2, 0, 0]} />
                    <Bar dataKey="failures" fill="var(--critical)" radius={[2, 2, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <Empty>No events yet</Empty>
            )}
          </div>
        </section>

        {/* Alert queue */}
        <section className="panel">
          <div className="flex items-center justify-between border-b border-border px-5 py-3">
            <p className="mono-label">Recent security alerts</p>
            <p className="font-mono text-xs text-muted-foreground">
              brute force threshold: {DEFAULT_CONFIG.bruteForceThreshold} fails /{" "}
              {DEFAULT_CONFIG.bruteForceWindowMinutes} min
            </p>
          </div>
          {data.alerts.length ? (
            <ul className="divide-y divide-border">
              {data.alerts.map((alert) => (
                <li key={alert.id}>
                  <Link
                    to="/alerts/$id"
                    params={{ id: alert.id }}
                    className="flex flex-wrap items-center gap-3 px-5 py-3 transition-colors hover:bg-secondary/60"
                  >
                    <SeverityBadge severity={alert.severity} />
                    <span className="flex-1 text-sm font-medium">{alert.alert_type}</span>
                    <span className="font-mono text-xs text-muted-foreground">{alert.source_ip ?? "—"}</span>
                    <span className="font-mono text-xs text-muted-foreground">{alert.attempt_count} attempts</span>
                    <StatusBadge status={alert.status} />
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <div className="px-5 py-10">
              <Empty>
                Upload an <code className="font-mono">auth.log</code> file, or analyze the bundled sample, to see alerts.
              </Empty>
            </div>
          )}
        </section>

        {/* Parsed events */}
        <section className="panel">
          <p className="mono-label border-b border-border px-5 py-3">Parsed events (latest 500)</p>
          <div className="max-h-96 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-panel text-muted-foreground">
                <tr>
                  <th className="px-5 py-2 font-medium">Time (UTC)</th>
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Source IP</th>
                  <th className="px-3 py-2 font-medium">Event</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-5 py-2 font-medium">Message</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {data.events.map((event) => (
                  <tr key={event.id} className="border-t border-border/60">
                    <td className="px-5 py-2 whitespace-nowrap">
                      {event.occurred_at ? event.occurred_at.replace("T", " ").slice(0, 19) : "—"}
                    </td>
                    <td className="px-3 py-2">{event.username ?? "—"}</td>
                    <td className="px-3 py-2">{event.source_ip ?? "—"}</td>
                    <td className="px-3 py-2">{event.event_type}</td>
                    <td className="px-3 py-2">
                      <span
                        className={
                          event.status === "FAILURE"
                            ? "text-critical"
                            : event.status === "SUCCESS"
                              ? "text-ok"
                              : "text-muted-foreground"
                        }
                      >
                        {event.status}
                      </span>
                    </td>
                    <td className="max-w-md truncate px-5 py-2 text-muted-foreground">{event.message}</td>
                  </tr>
                ))}
                {data.events.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-5 py-8 text-center text-muted-foreground">
                      No parsed events yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <p className="pb-6 text-xs text-muted-foreground">
          All analysis runs on the uploaded log data only. No scanning or connections to external systems, and log
          contents are never executed.
        </p>
      </main>
    </div>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "critical" | "high" | "ok";
}) {
  const toneClass =
    tone === "critical" ? "text-critical" : tone === "high" ? "text-high" : tone === "ok" ? "text-ok" : "text-foreground";
  return (
    <div className="panel px-4 py-3">
      <p className="mono-label">{label}</p>
      <p className={`mt-1 font-mono text-2xl font-semibold ${toneClass}`}>{value}</p>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="mt-4 text-sm text-muted-foreground">{children}</p>;
}
