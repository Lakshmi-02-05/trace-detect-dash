/**
 * Incident detail / triage page.
 *
 * Shows everything an analyst needs to make a decision: what fired, why it
 * fired, the original log lines as evidence, and the recommended action. The
 * status buttons drive the NEW -> INVESTIGATING -> RESOLVED workflow.
 */

import { createFileRoute, Link, useParams } from "@tanstack/react-router";
import { queryOptions, useQueryClient, useSuspenseQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SeverityBadge, StatusBadge } from "@/components/soc/severity-badge";
import { getAlert, setAlertStatus } from "@/lib/soc.functions";
import type { IncidentStatus } from "@/lib/analyzer/types";

const alertQuery = (id: string) =>
  queryOptions({
    queryKey: ["alert", id],
    queryFn: () => getAlert({ data: { id } }),
  });

export const Route = createFileRoute("/alerts/$id")({
  head: () => ({
    meta: [
      { title: "Alert Details — SOC Log Analyzer" },
      {
        name: "description",
        content:
          "Full incident detail: severity reasoning, source IP, affected accounts, log evidence and the recommended analyst action.",
      },
      { property: "og:title", content: "Alert Details — SOC Log Analyzer" },
      {
        property: "og:description",
        content: "Severity reasoning, log evidence and recommended action for a detected security incident.",
      },
      { name: "robots", content: "noindex" },
    ],
  }),
  loader: ({ context, params }) => context.queryClient.ensureQueryData(alertQuery(params.id)),
  component: AlertDetail,
});

const STATUSES: IncidentStatus[] = ["NEW", "INVESTIGATING", "RESOLVED"];

function AlertDetail() {
  const { id } = useParams({ from: "/alerts/$id" });
  const { data: alert } = useSuspenseQuery(alertQuery(id));
  const queryClient = useQueryClient();

  if (!alert) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-16">
        <p className="text-sm text-muted-foreground">This alert no longer exists.</p>
        <Link to="/" className="mt-4 inline-block text-sm text-primary underline">
          Back to dashboard
        </Link>
      </div>
    );
  }

  async function updateStatus(status: IncidentStatus) {
    try {
      await setAlertStatus({ data: { id, status } });
      toast.success(`Alert marked ${status.toLowerCase()}`);
      await queryClient.invalidateQueries({ queryKey: ["alert", id] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    } catch {
      toast.error("Could not update the alert status.");
    }
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-panel/80 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center gap-3 px-6 py-4">
          <Link to="/" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="size-4" /> Dashboard
          </Link>
        </div>
      </header>

      <main className="mx-auto max-w-5xl space-y-5 px-6 py-6">
        <div className="panel p-6">
          <div className="flex flex-wrap items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <span className="mono-label">{alert.rule_id}</span>
          </div>
          <h1 className="mt-3 text-2xl font-semibold tracking-tight">ALERT: {alert.alert_type}</h1>

          <dl className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Source IP" value={alert.source_ip ?? "—"} mono />
            <Field
              label={alert.usernames.length > 1 ? "Usernames" : "Username"}
              value={alert.usernames.length ? alert.usernames.join(", ") : "—"}
              mono
            />
            <Field label="Attempts" value={String(alert.attempt_count)} mono />
            <Field label="First seen (UTC)" value={formatTime(alert.first_seen)} mono />
            <Field label="Last seen (UTC)" value={formatTime(alert.last_seen)} mono />
            <Field label="Detected at (UTC)" value={formatTime(alert.detected_at)} mono />
          </dl>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <section className="panel p-6">
            <p className="mono-label">Why it was detected</p>
            <p className="mt-2 text-sm leading-relaxed">{alert.reason}</p>
          </section>
          <section className="panel p-6">
            <p className="mono-label">Recommended analyst action</p>
            <p className="mt-2 text-sm leading-relaxed">{alert.recommended_action}</p>
          </section>
        </div>

        <section className="panel p-6">
          <p className="mono-label">Evidence from the original log</p>
          <pre className="mt-3 overflow-x-auto rounded-md bg-background/60 p-4 font-mono text-xs leading-relaxed text-muted-foreground">
            {alert.evidence.length ? alert.evidence.join("\n") : "No evidence lines were stored."}
          </pre>
        </section>

        <section className="panel flex flex-wrap items-center gap-3 p-6">
          <p className="mono-label">Investigation status</p>
          <div className="flex gap-2">
            {STATUSES.map((status) => (
              <Button
                key={status}
                size="sm"
                variant={alert.status === status ? "default" : "secondary"}
                onClick={() => void updateStatus(status)}
              >
                {status}
              </Button>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}

function formatTime(value: string | null) {
  return value ? value.replace("T", " ").slice(0, 19) : "—";
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="mono-label">{label}</dt>
      <dd className={`mt-1 text-sm ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}
