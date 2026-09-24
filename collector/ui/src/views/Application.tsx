import { useMemo, useState } from "react";
import {
  parseApplicationObservation,
  parseAsset,
  parseAssetRelationship,
} from "../contracts";
import type { ApplicationObservation } from "../contracts";
import { DataTable, type Column } from "../components/DataTable";
import { Drawer } from "../components/Drawer";
import { FilterBar } from "../components/FilterBar";
import { StatusBadge } from "../components/StatusBadge";
import { SummaryStrip } from "../components/SummaryStrip";
import {
  EmptyState,
  ErrorState,
  Field,
  HeadingSkeleton,
  TableSkeleton,
} from "../components/States";
import { fmtTime, listOf, useApiList } from "./hooks";

const COLUMNS: Column<ApplicationObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "method",
    header: "Method",
    sortable: true,
    sortValue: (r) => r.method,
    render: (r) => <span className="mono">{r.method}</span>,
  },
  {
    key: "host",
    header: "Host",
    sortable: true,
    sortValue: (r) => r.host,
    render: (r) => <span className="mono">{r.host}</span>,
  },
  {
    key: "path",
    header: "Path",
    sortable: true,
    sortValue: (r) => r.path,
    render: (r) => <span className="mono">{r.path}</span>,
  },
  {
    key: "status_code",
    header: "Status",
    sortable: true,
    sortValue: (r) => String(r.status_code ?? ""),
    render: (r) => {
      if (r.status_code === undefined) return "—";
      const s = r.status_code;
      const tone = s >= 500 ? "bad" : s >= 400 ? "warn" : "neutral";
      return <StatusBadge value={String(s)} tone={tone as never} />;
    },
  },
  {
    key: "content_type",
    header: "Content Type",
    sortable: true,
    sortValue: (r) => r.content_type ?? "",
    render: (r) => r.content_type ?? "—",
  },
  {
    key: "detected",
    header: "Detected",
    sortable: true,
    sortValue: (r) => (r.detected ? "1" : "0"),
    render: (r) =>
      r.detected ? (
        <StatusBadge value="DETECTED" tone="bad" />
      ) : (
        <span className="muted">—</span>
      ),
  },
];

function ApplicationDetail({
  row,
  onClose,
}: {
  row: ApplicationObservation;
  onClose: () => void;
}) {
  const assets = useApiList("/api/v1/assets", parseAsset);
  const rels = useApiList(
    "/api/v1/application/relationships",
    parseAssetRelationship,
  );
  const assetMap = useMemo(() => {
    const m = new Map<string, string>();
    const list = listOf(assets);
    if (list) for (const a of list) m.set(a.name, a.id);
    return m;
  }, [assets]);

  return (
    <Drawer title={row.id} onClose={onClose}>
      <div className="field-grid">
        <Field label="API Version">{row.api_version ?? "—"}</Field>
        <Field label="Content Type">{row.content_type ?? "—"}</Field>
        <Field label="Direction">{row.direction ?? "—"}</Field>
        <div className="field-group">
          <h4 className="group-head">Identity</h4>
          <Field label="Method">{row.method}</Field>
          <Field label="Host">{row.host}</Field>
          <Field label="Path">{row.path}</Field>
          <Field label="Route">{row.route ?? "—"}</Field>
          <Field label="Source">{row.source}</Field>
        </div>
        <div className="field-group">
          <h4 className="group-head">Risk</h4>
          <Field label="Status">{row.status_code ?? "—"}</Field>
          <Field label="Auth outcome">{row.auth_outcome ?? "—"}</Field>
          <Field label="Severity">
            {row.severity.replace("SEVERITY_", "")}
          </Field>
          <Field label="Detected">{row.detected ? "Yes" : "No"}</Field>
        </div>
        <div className="field-group">
          <h4 className="group-head">History</h4>
          <Field label="Time">{fmtTime(row.occurred_at)}</Field>
        </div>
      </div>

      <h3 className="detail-section">Asset</h3>
      {assets.kind === "loading" ? (
        <HeadingSkeleton />
      ) : (
        <div className="field-grid">
          <Field label="URL asset">
            {assetMap.get(`https://${row.host}${row.path}`) ||
            assetMap.get(`http://${row.host}${row.path}`) ? (
              <span className="mono">
                {row.host}
                {row.path}
              </span>
            ) : (
              <span className="muted">
                No URL asset observed for {row.host}
                {row.path} — telemetry preserved.
              </span>
            )}
          </Field>
          <Field label="Host asset">
            {assetMap.get(row.host) ? (
              <span className="mono">
                {row.host} → {assetMap.get(row.host)}
              </span>
            ) : (
              <span className="muted">
                No asset for host {row.host} — external or unobserved.
              </span>
            )}
          </Field>
        </div>
      )}

      <h3 className="detail-section">Detection</h3>
      {row.detected ? (
        <p className="muted">
          This observation triggered a deterministic rule. See Findings for
          alert and incident. Provenance: source {row.source}, rule and
          threshold/policy recorded in detection attributes, evidence preserved.
        </p>
      ) : (
        <p className="muted">
          No detection. Observation, not a vulnerability — most HTTP telemetry
          is not a finding.
        </p>
      )}

      <h3 className="detail-section">Relationships</h3>
      {rels.kind === "loading" ? (
        <HeadingSkeleton />
      ) : rels.kind === "ready" || rels.kind === "empty" ? (
        (() => {
          const list = listOf(rels) ?? [];
          const linked = list.filter((r) => r.source === row.source);
          if (linked.length === 0)
            return (
              <p className="muted">
                No application relationships recorded for this source.
              </p>
            );
          return (
            <ul className="link-list">
              {linked.slice(0, 8).map((r) => (
                <li key={`${r.parent_id}-${r.child_id}`} className="mono">
                  {r.parent_id} → {r.child_id}{" "}
                  <span className="muted">
                    ({r.kind} · {r.source})
                  </span>
                </li>
              ))}
            </ul>
          );
        })()
      ) : null}
    </Drawer>
  );
}

export function Application() {
  const obs = useApiList(
    "/api/v1/application/observations",
    parseApplicationObservation,
  );
  const [q, setQ] = useState("");
  const [method, setMethod] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [host, setHost] = useState("ALL");
  const [detectedOnly, setDetectedOnly] = useState(false);
  const [selected, setSelected] = useState<ApplicationObservation | null>(null);

  const rows = useMemo(() => {
    const list = listOf(obs);
    if (!list) return null;
    let out = list;
    if (q.trim()) {
      const needle = q.toLowerCase();
      out = out.filter((r) =>
        `${r.host} ${r.path} ${r.method} ${r.id}`
          .toLowerCase()
          .includes(needle),
      );
    }
    if (method !== "ALL") out = out.filter((r) => r.method === method);
    if (status !== "ALL")
      out = out.filter((r) => String(r.status_code ?? "") === status);
    if (host !== "ALL") out = out.filter((r) => r.host === host);
    if (detectedOnly) out = out.filter((r) => r.detected);
    return out;
  }, [obs, q, method, status, host, detectedOnly]);

  const loading = obs.kind === "loading";
  const backendError = obs.kind === "backend-error" ? obs.message : null;
  const invalid = obs.kind === "invalid" ? obs.message : null;
  const total = listOf(obs)?.length ?? 0;

  // Derive host options from data
  const hostOptions = useMemo(() => {
    const list = listOf(obs);
    if (!list) return ["ALL"];
    const set = new Set<string>();
    for (const r of list) set.add(r.host);
    return ["ALL", ...Array.from(set).sort()];
  }, [obs]);

  const clearFilters = () => {
    setQ("");
    setMethod("ALL");
    setStatus("ALL");
    setHost("ALL");
    setDetectedOnly(false);
  };

  return (
    <div className="view">
      <h1 className="page-title">Application</h1>
      <p className="page-sub">
        HTTP/API observations — deterministic detection only when thresholds or
        policy fire. Most rows are not findings.
      </p>

      <FilterBar
        search={q}
        onSearch={setQ}
        searchLabel="Search application"
        searchPlaceholder="host, path, or method…"
        selects={[
          {
            label: "Method",
            value: method,
            options: [
              "ALL",
              "GET",
              "POST",
              "PUT",
              "DELETE",
              "PATCH",
              "TRACE",
            ].map((v) => ({ value: v, label: v })),
            onChange: setMethod,
          },
          {
            label: "Status",
            value: status,
            options: ["ALL", "200", "401", "500"].map((v) => ({
              value: v,
              label: v,
            })),
            onChange: setStatus,
          },
          {
            label: "Host",
            value: host,
            options: hostOptions.map((v) => ({ value: v, label: v })),
            onChange: setHost,
          },
        ]}
        onClear={clearFilters}
        hasActive={
          q !== "" ||
          method !== "ALL" ||
          status !== "ALL" ||
          host !== "ALL" ||
          detectedOnly
        }
      />
      <label
        style={{
          display: "flex",
          gap: 8,
          alignItems: "center",
          margin: "8px 0 12px",
        }}
      >
        <input
          type="checkbox"
          checked={detectedOnly}
          onChange={(e) => setDetectedOnly(e.target.checked)}
        />{" "}
        Detected only
      </label>

      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={5} />
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
      {!loading && !backendError && !invalid && total === 0 && (
        <div className="panel">
          <EmptyState
            icon="application"
            title="No application observations"
            description="HTTP/API telemetry will appear here when observations are ingested."
          />
        </div>
      )}
      {!loading &&
        !backendError &&
        !invalid &&
        total > 0 &&
        rows &&
        rows.length === 0 && (
          <div className="panel">
            <EmptyState
              icon="application"
              title="No matching observations"
              description="No rows match the current filters."
              action={{ label: "Clear filters", onClick: clearFilters }}
            />
          </div>
        )}
      {!loading && !backendError && !invalid && rows && rows.length > 0 && (
        <>
          {(() => {
            const all = listOf(obs) ?? [];
            return (
              <SummaryStrip
                statement="Server errors deserve a look first; the rest is observed traffic."
                stats={[
                  { label: "Observations", value: String(all.length) },
                  {
                    label: "Server errors",
                    value: String(
                      all.filter((r) => (r.status_code ?? 0) >= 500).length,
                    ),
                  },
                  {
                    label: "Without status",
                    value: String(
                      all.filter((r) => r.status_code === undefined).length,
                    ),
                  },
                ]}
              />
            );
          })()}
          <DataTable
            columns={COLUMNS}
            rows={rows}
            onRowClick={setSelected}
            rowLabel={(r) => `Open ${r.id}`}
            empty="No observations"
          />
        </>
      )}
      {selected && (
        <ApplicationDetail row={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
