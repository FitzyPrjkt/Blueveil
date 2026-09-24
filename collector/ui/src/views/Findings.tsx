import { useMemo, useState } from "react";
import {
  ALERT_STATUSES,
  SEVERITIES,
  parseAlert,
  parseDetection,
  parseTelemetryEvent,
} from "../contracts";
import type { Alert, Detection, TelemetryEvent } from "../contracts";
import { DataTable, type Column } from "../components/DataTable";
import { Drawer } from "../components/Drawer";
import { FilterBar } from "../components/FilterBar";
import { SeverityBadge, StatusBadge } from "../components/StatusBadge";
import { SummaryStrip } from "../components/SummaryStrip";
import {
  EmptyState,
  ErrorState,
  Field,
  HeadingSkeleton,
  TableSkeleton,
} from "../components/States";
import { fmtTime, listOf, useApiList } from "./hooks";
import { alertAgeDays } from "./overviewAgg";

interface FindingRow extends Alert {
  rule: string;
  target: string;
}

function joinRows(
  alerts: Alert[],
  detections: Detection[],
  telemetry: TelemetryEvent[],
): FindingRow[] {
  const detById = new Map(detections.map((d) => [d.id, d]));
  const telById = new Map(telemetry.map((t) => [t.id, t]));
  return alerts.map((a) => {
    const det = detById.get(a.detection_ids[0] ?? "");
    const assets = (det?.telemetry_event_ids ?? [])
      .map((id) => telById.get(id)?.asset_id)
      .filter((x): x is string => !!x);
    return {
      ...a,
      rule: det ? `${det.rule_name} (${det.rule_id})` : "—",
      target: assets.length > 0 ? [...new Set(assets)].join(", ") : "—",
    };
  });
}

const COLUMNS: Column<FindingRow>[] = [
  {
    key: "severity",
    header: "Severity",
    sortable: true,
    sortValue: (r) => SEVERITIES.indexOf(r.severity),
    render: (r) => <SeverityBadge severity={r.severity} />,
  },
  {
    key: "title",
    header: "Finding",
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
    key: "rule",
    header: "Rule",
    sortable: true,
    sortValue: (r) => r.rule,
    render: (r) => r.rule,
  },
  {
    key: "target",
    header: "Target",
    sortable: true,
    sortValue: (r) => r.target,
    render: (r) => <span className="mono">{r.target}</span>,
  },
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status,
    render: (r) => (
      <StatusBadge
        value={r.status}
        tone={r.status === "ALERT_STATUS_OPEN" ? "warn" : "neutral"}
      />
    ),
  },
  {
    key: "created_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.created_at,
    render: (r) => <span className="tabular">{fmtTime(r.created_at)}</span>,
  },
];

export function Findings({
  onOpenIncident,
  initialSeverity,
  initialStatus,
  initialSort,
}: {
  onOpenIncident: (id: string) => void;
  initialSeverity?: string;
  initialStatus?: string;
  initialSort?: string;
}) {
  const alerts = useApiList("/api/v1/alerts", parseAlert);
  const detections = useApiList("/api/v1/detections", parseDetection);
  const telemetry = useApiList("/api/v1/telemetry", parseTelemetryEvent);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState(
    initialSeverity && (SEVERITIES as string[]).includes(initialSeverity)
      ? initialSeverity
      : "ALL",
  );
  const [status, setStatus] = useState(
    initialStatus && (ALERT_STATUSES as string[]).includes(initialStatus)
      ? initialStatus
      : "ALL",
  );
  const [target, setTarget] = useState("ALL");
  const [selected, setSelected] = useState<FindingRow | null>(null);
  // initialSort=oldest pre-sorts by creation time ascending (oldest first).
  const oldestFirst = initialSort === "oldest";

  const loading =
    alerts.kind === "loading" ||
    detections.kind === "loading" ||
    telemetry.kind === "loading";
  const backendError =
    (alerts.kind === "backend-error" && alerts.message) ||
    (detections.kind === "backend-error" && detections.message) ||
    (telemetry.kind === "backend-error" && telemetry.message) ||
    null;
  const invalid =
    (alerts.kind === "invalid" && alerts.message) ||
    (detections.kind === "invalid" && detections.message) ||
    (telemetry.kind === "invalid" && telemetry.message) ||
    null;

  const rows = useMemo(() => {
    const a = listOf(alerts);
    const d = listOf(detections);
    const t = listOf(telemetry);
    if (!a || !d || !t) return null;
    const q = search.trim().toLowerCase();
    return joinRows(a, d, t).filter((r) => {
      if (severity !== "ALL" && r.severity !== severity) return false;
      if (status !== "ALL" && r.status !== status) return false;
      if (target !== "ALL" && r.target !== target) return false;
      if (
        q &&
        !(
          r.title.toLowerCase().includes(q) ||
          r.id.toLowerCase().includes(q) ||
          r.rule.toLowerCase().includes(q)
        )
      )
        return false;
      return true;
    });
  }, [alerts, detections, telemetry, search, severity, status, target]);

  const targets = useMemo(() => {
    const a = listOf(alerts);
    const d = listOf(detections);
    const t = listOf(telemetry);
    if (!a || !d || !t) return [];
    return [...new Set(joinRows(a, d, t).map((r) => r.target))].sort();
  }, [alerts, detections, telemetry]);

  const hasActive =
    search !== "" || severity !== "ALL" || status !== "ALL" || target !== "ALL";
  const clear = () => {
    setSearch("");
    setSeverity("ALL");
    setStatus("ALL");
    setTarget("ALL");
  };

  return (
    <>
      <h1 className="page-title">Findings</h1>
      <p className="page-sub">
        Alerts raised by detection rules. Select a row for provenance.
      </p>
      {rows !== null &&
        (() => {
          const all = joinRows(
            listOf(alerts) ?? [],
            listOf(detections) ?? [],
            listOf(telemetry) ?? [],
          );
          const open = all.filter(
            (r) =>
              r.status === "ALERT_STATUS_OPEN" ||
              r.status === "ALERT_STATUS_ACKNOWLEDGED",
          );
          const crit = open.filter(
            (r) => r.severity === "SEVERITY_CRITICAL",
          ).length;
          const oldest = open.reduce(
            (m, r) => Math.max(m, alertAgeDays(r, Date.now())),
            0,
          );
          return (
            <SummaryStrip
              statement="Critical findings need a decision first; the rest can wait for triage."
              stats={[
                { label: "Open", value: String(open.length) },
                { label: "Critical", value: String(crit) },
                {
                  label: "Oldest (days)",
                  value: open.length === 0 ? "—" : String(oldest),
                },
              ]}
            />
          );
        })()}
      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={6} />
        </>
      )}
      {backendError && (
        <ErrorState title="Backend error" message={backendError} />
      )}
      {invalid && (
        <ErrorState
          title="Invalid data"
          message={`The backend returned data outside the contract: ${invalid}`}
        />
      )}
      {!loading &&
        !backendError &&
        !invalid &&
        rows !== null &&
        listOf(alerts)?.length === 0 && (
          <div className="panel">
            <EmptyState
              icon="findings"
              title="No findings"
              description="Findings will appear here when detection rules match telemetry."
            />
          </div>
        )}
      {!loading &&
        !backendError &&
        !invalid &&
        rows !== null &&
        (listOf(alerts) ?? []).length > 0 && (
          <>
            <FilterBar
              search={search}
              onSearch={setSearch}
              searchLabel="Search findings"
              searchPlaceholder="Search title, id, or rule…  ( / )"
              selects={[
                {
                  label: "Severity",
                  value: severity,
                  options: [
                    { value: "ALL", label: "All severities" },
                    ...SEVERITIES.map((s) => ({
                      value: s,
                      label: s.replace("SEVERITY_", ""),
                    })),
                  ],
                  onChange: setSeverity,
                },
                {
                  label: "Status",
                  value: status,
                  options: [
                    { value: "ALL", label: "All statuses" },
                    ...ALERT_STATUSES.map((s) => ({
                      value: s,
                      label: s.replace("ALERT_STATUS_", ""),
                    })),
                  ],
                  onChange: setStatus,
                },
                {
                  label: "Target",
                  value: target,
                  options: [
                    { value: "ALL", label: "All targets" },
                    ...targets.map((t) => ({ value: t, label: t })),
                  ],
                  onChange: setTarget,
                },
              ]}
              onClear={clear}
              hasActive={hasActive}
            />
            {rows.length === 0 ? (
              <div className="panel">
                <EmptyState
                  icon="findings"
                  title="No matching findings"
                  description="No findings match the current search and filters. Widen the criteria to see more."
                  action={{ label: "Clear filters", onClick: clear }}
                />
              </div>
            ) : (
              <DataTable
                columns={COLUMNS}
                rows={rows}
                onRowClick={setSelected}
                rowLabel={(r) => `Finding ${r.title}`}
                empty={<></>}
                initialSortKey={oldestFirst ? "created_at" : null}
                initialSortDir={1}
              />
            )}
          </>
        )}
      {selected && (
        <Drawer title={selected.title} onClose={() => setSelected(null)}>
          <dl className="field-grid">
            <div className="field-group">
              <h4 className="group-head">Identity</h4>
              <Field label="Rule">{selected.rule}</Field>
              <Field label="Target">
                <span className="mono">{selected.target}</span>
              </Field>
              <Field label="Alert ID">
                <span className="mono">{selected.id}</span>
              </Field>
              <Field label="Detections">
                <span className="mono">
                  {selected.detection_ids.join(", ")}
                </span>
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">Risk</h4>
              <Field label="Severity">
                <SeverityBadge severity={selected.severity} />
              </Field>
              <Field label="Status">
                <StatusBadge
                  value={selected.status}
                  tone={
                    selected.status === "ALERT_STATUS_OPEN" ? "warn" : "neutral"
                  }
                />
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">History</h4>
              <Field label="Created">
                <span className="tabular">{fmtTime(selected.created_at)}</span>
              </Field>
              <Field label="Updated">
                <span className="tabular">{fmtTime(selected.updated_at)}</span>
              </Field>
            </div>
          </dl>
          <p className="page-sub" style={{ marginTop: 16 }}>
            Incidents group related alerts. This alert may belong to an incident
            on the Incidents view.
          </p>
          <button className="btn" onClick={() => onOpenIncident(selected.id)}>
            Look up incident by alert
          </button>
        </Drawer>
      )}
    </>
  );
}
