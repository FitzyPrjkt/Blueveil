import { useMemo, useState } from "react";
import {
  parseAlert,
  parseDetection,
  parseEvidence,
  parseIncident,
  parseTelemetryEvent,
} from "../contracts";
import type { Evidence, Incident } from "../contracts";
import { DataTable, type Column } from "../components/DataTable";
import { Drawer } from "../components/Drawer";
import { SummaryStrip } from "../components/SummaryStrip";
import {
  SeverityBadge,
  StatusBadge,
  incidentTone,
} from "../components/StatusBadge";
import {
  EmptyState,
  ErrorState,
  Field,
  HeadingSkeleton,
  TableSkeleton,
} from "../components/States";
import {
  StatusTimeline,
  type TimelineStep,
} from "../components/StatusTimeline";
import { fmtTime, listOf, useApiList } from "./hooks";

const LIFECYCLE = [
  "INCIDENT_STATUS_OPEN",
  "INCIDENT_STATUS_INVESTIGATING",
  "INCIDENT_STATUS_CONTAINED",
  "INCIDENT_STATUS_RESOLVED",
  "INCIDENT_STATUS_CLOSED",
];

const COLUMNS: Column<Incident>[] = [
  {
    key: "severity",
    header: "Severity",
    sortable: true,
    render: (r) => <SeverityBadge severity={r.severity} />,
  },
  {
    key: "title",
    header: "Incident",
    sortable: true,
    sortValue: (r) => r.title,
    render: (r) => (
      <span>
        <span style={{ fontWeight: 600 }}>{r.title}</span>
        <br />
        <span className="mono" style={{ color: "var(--bv-muted)" }}>
          {r.id}
        </span>
      </span>
    ),
  },
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status,
    render: (r) => (
      <StatusBadge value={r.status} tone={incidentTone(r.status)} />
    ),
  },
  {
    key: "alert_ids",
    header: "Alerts",
    numeric: true,
    sortable: true,
    sortValue: (r) => r.alert_ids.length,
    render: (r) => <span className="tabular">{r.alert_ids.length}</span>,
  },
  {
    key: "updated_at",
    header: "Updated",
    sortable: true,
    sortValue: (r) => r.updated_at,
    render: (r) => <span className="tabular">{fmtTime(r.updated_at)}</span>,
  },
];

export function Incidents({ focusAlertId }: { focusAlertId: string | null }) {
  const incidents = useApiList("/api/v1/incidents", parseIncident);
  const alerts = useApiList("/api/v1/alerts", parseAlert);
  const detections = useApiList("/api/v1/detections", parseDetection);
  const telemetry = useApiList("/api/v1/telemetry", parseTelemetryEvent);
  const evidence = useApiList("/api/v1/evidence", parseEvidence);
  const [selected, setSelected] = useState<Incident | null>(null);

  // Deep-link: Findings passes an alert id; resolve its incident once loaded.
  const resolved = useMemo(() => {
    const list = listOf(incidents);
    if (!focusAlertId || !list) return null;
    return list.find((i) => i.alert_ids.includes(focusAlertId)) ?? null;
  }, [focusAlertId, incidents]);
  const shown = selected ?? resolved;

  const loading = [incidents, alerts, detections, telemetry, evidence].some(
    (s) => s.kind === "loading",
  );
  const backendError = [
    incidents,
    alerts,
    detections,
    telemetry,
    evidence,
  ].find((s) => s.kind === "backend-error");
  const invalid = [incidents, alerts, detections, telemetry, evidence].find(
    (s) => s.kind === "invalid",
  );

  const alertById = useMemo(
    () => new Map((listOf(alerts) ?? []).map((a) => [a.id, a])),
    [alerts],
  );
  const detById = useMemo(
    () => new Map((listOf(detections) ?? []).map((d) => [d.id, d])),
    [detections],
  );
  const telById = useMemo(
    () => new Map((listOf(telemetry) ?? []).map((t) => [t.id, t])),
    [telemetry],
  );
  const evByIncident = useMemo(() => {
    const m = new Map<string, Evidence[]>();
    for (const e of listOf(evidence) ?? []) {
      const list = m.get(e.incident_id) ?? [];
      list.push(e);
      m.set(e.incident_id, list);
    }
    return m;
  }, [evidence]);

  const lifecycleSteps = (inc: Incident): TimelineStep[] => {
    const idx = LIFECYCLE.indexOf(inc.status);
    return LIFECYCLE.map((s, i) => ({
      key: s,
      title: s.replace("INCIDENT_STATUS_", ""),
      meta: i === idx ? `Current since ${fmtTime(inc.updated_at)}` : undefined,
      state: i < idx ? "done" : i === idx ? "now" : "todo",
    }));
  };

  return (
    <>
      <h1 className="page-title">Incidents</h1>
      <p className="page-sub">
        Correlated alert groups. Lifecycle is read-only — no mutation API
        exists.
      </p>
      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={4} />
        </>
      )}
      {backendError?.kind === "backend-error" && (
        <ErrorState title="Backend error" message={backendError.message} />
      )}
      {invalid?.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message={`The backend returned data outside the contract: ${invalid.message}`}
        />
      )}
      {!loading &&
        !backendError &&
        !invalid &&
        (listOf(incidents) ?? []).length === 0 && (
          <div className="panel">
            <EmptyState
              icon="incidents"
              title="No incidents"
              description="Incidents will appear here when alerts are correlated into an incident."
            />
          </div>
        )}
      {!loading &&
        !backendError &&
        !invalid &&
        (listOf(incidents) ?? []).length > 0 && (
          <>
            {(() => {
              const list = listOf(incidents) ?? [];
              return (
                <SummaryStrip
                  statement="Open incidents need owners; aging ones need decisions."
                  stats={[
                    {
                      label: "Open",
                      value: String(
                        list.filter((i) => i.status === "INCIDENT_STATUS_OPEN")
                          .length,
                      ),
                    },
                    {
                      label: "Investigating",
                      value: String(
                        list.filter(
                          (i) => i.status === "INCIDENT_STATUS_INVESTIGATING",
                        ).length,
                      ),
                    },
                    {
                      label: "Resolved + closed",
                      value: String(
                        list.filter(
                          (i) =>
                            i.status === "INCIDENT_STATUS_RESOLVED" ||
                            i.status === "INCIDENT_STATUS_CLOSED",
                        ).length,
                      ),
                    },
                  ]}
                />
              );
            })()}
            <DataTable
              columns={COLUMNS}
              rows={listOf(incidents) ?? []}
              onRowClick={setSelected}
              rowLabel={(r) => `Incident ${r.title}`}
              empty={<></>}
            />
          </>
        )}
      {shown && (
        <Drawer title={shown.title} onClose={() => setSelected(null)}>
          <dl className="field-grid">
            <Field label="Summary">{shown.summary ?? "—"}</Field>
            <div className="field-group">
              <h4 className="group-head">Identity</h4>
              <Field label="Incident ID">
                <span className="mono">{shown.id}</span>
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">Risk</h4>
              <Field label="Severity">
                <SeverityBadge severity={shown.severity} />
              </Field>
              <Field label="Status">
                <StatusBadge
                  value={shown.status}
                  tone={incidentTone(shown.status)}
                />
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">History</h4>
              <Field label="Created">
                <span className="tabular">{fmtTime(shown.created_at)}</span>
              </Field>
              <Field label="Updated">
                <span className="tabular">{fmtTime(shown.updated_at)}</span>
              </Field>
            </div>
          </dl>
          <h3 className="section-title">Lifecycle</h3>
          <StatusTimeline steps={lifecycleSteps(shown)} />
          <h3 className="section-title">
            Incident → Alert → Detection → Telemetry
          </h3>
          {shown.alert_ids.map((aid) => {
            const a = alertById.get(aid);
            if (!a) return null;
            const det = detById.get(a.detection_ids[0] ?? "");
            const assets = (det?.telemetry_event_ids ?? [])
              .map((id) => telById.get(id)?.asset_id)
              .filter((x): x is string => !!x);
            return (
              <div key={aid} className="verdict-card">
                <div style={{ fontWeight: 600 }}>{a.title}</div>
                <div
                  className="mono"
                  style={{ color: "var(--bv-muted)", fontSize: 12 }}
                >
                  {aid} →{" "}
                  {det
                    ? `${det.rule_name} (${det.rule_id})`
                    : "unknown detection"}
                  {assets.length > 0 && ` → ${[...new Set(assets)].join(", ")}`}
                </div>
              </div>
            );
          })}
          <h3 className="section-title">
            Evidence ({evByIncident.get(shown.id)?.length ?? 0})
          </h3>
          {(evByIncident.get(shown.id) ?? []).map((e) => (
            <div key={e.id} className="link-row">
              <span className="mono">{e.id}</span>
              <span style={{ color: "var(--bv-muted)" }}>
                {e.type.replace("EVIDENCE_TYPE_", "")}
              </span>
            </div>
          ))}
          {(evByIncident.get(shown.id) ?? []).length === 0 && (
            <p className="page-sub">No evidence recorded for this incident.</p>
          )}
        </Drawer>
      )}
    </>
  );
}
