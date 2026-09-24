import { useMemo, useState } from "react";
import {
  parseCloudObservation,
  parseContainerObservation,
  parseEndpointObservation,
  parseServerObservation,
} from "../contracts";
import type {
  CloudObservation,
  ContainerObservation,
  EndpointObservation,
  ServerObservation,
} from "../contracts";
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

type Tab = "endpoint" | "server" | "container" | "cloud";

const endpointCols: Column<EndpointObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "host",
    header: "Host",
    sortable: true,
    sortValue: (r) => r.host,
    render: (r) => r.host,
  },
  {
    key: "process",
    header: "Process",
    sortable: true,
    sortValue: (r) => r.process,
    render: (r) => r.process,
  },
  {
    key: "user",
    header: "User",
    sortable: true,
    sortValue: (r) => r.user ?? "",
    render: (r) => r.user ?? "—",
  },
  {
    key: "action",
    header: "Action",
    sortable: true,
    sortValue: (r) => r.action,
    render: (r) => r.action,
  },
  {
    key: "result",
    header: "Result",
    sortable: true,
    sortValue: (r) => r.result,
    render: (r) => r.result || "—",
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

const serverCols: Column<ServerObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "hostname",
    header: "Host",
    sortable: true,
    sortValue: (r) => r.hostname,
    render: (r) => r.hostname,
  },
  {
    key: "service",
    header: "Service",
    sortable: true,
    sortValue: (r) => r.service,
    render: (r) => r.service,
  },
  {
    key: "action",
    header: "Action",
    sortable: true,
    sortValue: (r) => r.action,
    render: (r) => r.action || "—",
  },
  {
    key: "result",
    header: "Result",
    sortable: true,
    sortValue: (r) => r.result,
    render: (r) => r.result || "—",
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

const containerCols: Column<ContainerObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "cluster",
    header: "Cluster",
    sortable: true,
    sortValue: (r) => r.cluster,
    render: (r) => r.cluster || "—",
  },
  {
    key: "namespace",
    header: "Namespace",
    sortable: true,
    sortValue: (r) => r.namespace,
    render: (r) => r.namespace || "—",
  },
  {
    key: "container_id",
    header: "Container/Image",
    sortable: true,
    sortValue: (r) => r.container_id,
    render: (r) => (
      <span className="mono">
        {r.container_id.slice(0, 8)}
        <br />
        {r.image}
      </span>
    ),
  },
  {
    key: "privileged",
    header: "Runtime Flags",
    sortable: true,
    sortValue: (r) => (r.privileged ? "1" : "0"),
    render: (r) =>
      [
        r.privileged && "privileged",
        r.host_network && "host_network",
        r.host_pid && "host_pid",
      ]
        .filter(Boolean)
        .join(", ") || "—",
  },
  {
    key: "result",
    header: "Result",
    sortable: true,
    sortValue: (r) => r.result,
    render: (r) => r.result || "—",
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

const cloudCols: Column<CloudObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "provider",
    header: "Provider",
    sortable: true,
    sortValue: (r) => r.provider,
    render: (r) => r.provider,
  },
  {
    key: "account",
    header: "Account",
    sortable: true,
    sortValue: (r) => r.account,
    render: (r) => r.account || "—",
  },
  {
    key: "region",
    header: "Region",
    sortable: true,
    sortValue: (r) => r.region,
    render: (r) => r.region || "—",
  },
  {
    key: "principal",
    header: "Principal",
    sortable: true,
    sortValue: (r) => r.principal,
    render: (r) => r.principal || "—",
  },
  {
    key: "action",
    header: "Action",
    sortable: true,
    sortValue: (r) => r.action,
    render: (r) => r.action,
  },
  {
    key: "result",
    header: "Result",
    sortable: true,
    sortValue: (r) => r.result,
    render: (r) => (
      <StatusBadge
        value={r.result.toUpperCase()}
        tone={r.result === "denied" ? "bad" : "neutral"}
      />
    ),
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

const IDENTITY_KEYS = new Set([
  "id",
  "name",
  "title",
  "principal",
  "user",
  "asset",
  "asset_id",
  "source",
  "sensor",
  "type",
  "kind",
  "category",
  "ecosystem",
  "namespace",
  "host",
  "hostname",
  "path",
  "route",
  "method",
  "service",
  "image",
  "container",
  "container_id",
  "cluster",
  "provider",
  "account",
  "region",
  "target",
  "operation",
  "rule",
  "rule_name",
  "control",
  "campaign",
  "vendor",
  "assessor",
  "recommender",
  "digest",
  "sha256",
]);

const RISK_KEYS = new Set([
  "severity",
  "status",
  "verdict",
  "outcome",
  "result",
  "detected",
  "failure_reason",
  "risk",
  "risk_basis",
  "privileged",
  "host_network",
  "host_pid",
  "approval",
  "approval_required",
  "approved",
  "coverage",
]);

const HISTORY_KEYS = new Set([
  "created",
  "updated",
  "occurred",
  "observed",
  "collected",
  "validated",
  "requested",
  "recommended",
  "started",
  "finished",
  "first_seen",
  "last_seen",
  "expires",
  "expired",
]);

type FieldGroup = "identity" | "risk" | "history";

function groupFor(label: string, value: unknown): FieldGroup | null {
  const k = label.toLowerCase().replace(/[\s-]+/g, "_");
  if (IDENTITY_KEYS.has(k)) return "identity";
  if (RISK_KEYS.has(k)) return "risk";
  if (HISTORY_KEYS.has(k)) return "history";
  if (k === "id" || k.endsWith("_id")) return "identity";
  if (k.endsWith("_type") || k.endsWith("_kind")) return "identity";
  if (k.endsWith("_at") || k.endsWith("_time") || k === "time")
    return "history";
  const tokens = k.split("_");
  if (tokens.includes("age") || tokens.includes("duration")) return "history";
  if (k.includes("approv")) return "risk";
  if (typeof value === "number" || typeof value === "boolean") return "risk";
  return null;
}

function groupDetailFields(entries: [string, unknown][]): {
  ungrouped: [string, unknown][];
  identity: [string, unknown][];
  risk: [string, unknown][];
  history: [string, unknown][];
} {
  const groups = {
    ungrouped: [] as [string, unknown][],
    identity: [] as [string, unknown][],
    risk: [] as [string, unknown][],
    history: [] as [string, unknown][],
  };
  for (const [k, v] of entries) {
    const g = groupFor(k, v);
    if (g === null) groups.ungrouped.push([k, v]);
    else groups[g].push([k, v]);
  }
  return groups;
}

function Detail({
  row,
  onClose,
}: {
  row: { id: string; source: string; detected: boolean; [k: string]: unknown };
  onClose: () => void;
}) {
  const groups = groupDetailFields(Object.entries(row));
  return (
    <Drawer title={row.id as string} onClose={onClose}>
      <div className="field-grid">
        {groups.ungrouped.map(([k, v]) => (
          <Field key={k} label={k}>
            {String(v ?? "—")}
          </Field>
        ))}
        {groups.identity.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Identity</h4>
            {groups.identity.map(([k, v]) => (
              <Field key={k} label={k}>
                {String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
        {groups.risk.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Risk</h4>
            {groups.risk.map(([k, v]) => (
              <Field key={k} label={k}>
                {String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
        {groups.history.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">History</h4>
            {groups.history.map(([k, v]) => (
              <Field key={k} label={k}>
                {String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
      </div>
      <h3 className="detail-section">Detection</h3>
      {row.detected ? (
        <p className="muted">
          This observation triggered a deterministic rule. See Findings for
          alert and incident. Provenance preserved.
        </p>
      ) : (
        <p className="muted">No detection. Observation, not a finding.</p>
      )}
    </Drawer>
  );
}

export function Infrastructure() {
  const [tab, setTab] = useState<Tab>("endpoint");
  const [q, setQ] = useState("");
  const [detectedOnly, setDetectedOnly] = useState(false);
  const endpoint = useApiList(
    "/api/v1/endpoint/observations",
    parseEndpointObservation,
  );
  const server = useApiList(
    "/api/v1/server/observations",
    parseServerObservation,
  );
  const container = useApiList(
    "/api/v1/container/observations",
    parseContainerObservation,
  );
  const cloud = useApiList("/api/v1/cloud/observations", parseCloudObservation);
  const [selected, setSelected] = useState<any | null>(null);

  const current = { endpoint, server, container, cloud }[tab];
  const loading = current.kind === "loading";
  const backendError =
    current.kind === "backend-error" ? current.message : null;
  const invalid = current.kind === "invalid" ? current.message : null;
  const total = listOf(current as never)?.length ?? 0;

  const rows = useMemo(() => {
    const list = listOf(current as never) as unknown[] | null;
    if (!list) return null;
    let out: unknown[] = list;
    if (q.trim()) {
      const needle = q.toLowerCase();
      out = out.filter((r) => JSON.stringify(r).toLowerCase().includes(needle));
    }
    if (detectedOnly)
      out = out.filter((r) => (r as { detected: boolean }).detected);
    return out;
  }, [current, q, detectedOnly]);

  const clearFilters = () => {
    setQ("");
    setDetectedOnly(false);
  };

  return (
    <div className="view">
      <h1 className="page-title">Infrastructure</h1>
      <p className="page-sub">
        Endpoint, server, container, and cloud observations — defensive,
        deterministic.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {(["endpoint", "server", "container", "cloud"] as Tab[]).map((t) => (
          <button
            key={t}
            className={`btn${tab === t ? " active" : ""}`}
            onClick={() => {
              setTab(t);
              setSelected(null);
            }}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      <FilterBar
        search={q}
        onSearch={setQ}
        searchLabel={`Search ${tab}`}
        searchPlaceholder="host, process, service…"
        selects={[]}
        onClear={clearFilters}
        hasActive={q !== "" || detectedOnly}
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
            icon="infrastructure"
            title={`No ${tab} observations`}
            description={`${tab.charAt(0).toUpperCase() + tab.slice(1)} telemetry will appear when a configured source emits events.`}
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
              icon="infrastructure"
              title="No matching observations"
              description="No rows match the current filters."
              action={{ label: "Clear filters", onClick: clearFilters }}
            />
          </div>
        )}
      {!loading && !backendError && !invalid && rows && rows.length > 0 && (
        <>
          {(() => {
            const endpoints = listOf(endpoint) ?? [];
            const servers = listOf(server) ?? [];
            const containers = listOf(container) ?? [];
            const clouds = listOf(cloud) ?? [];
            const total =
              endpoints.length +
              servers.length +
              containers.length +
              clouds.length;
            const detected =
              endpoints.filter((r) => r.detected).length +
              servers.filter((r) => r.detected).length +
              containers.filter((r) => r.detected).length +
              clouds.filter((r) => r.detected).length;
            return (
              <SummaryStrip
                statement="Privileged containers and detected actions deserve a look first."
                stats={[
                  { label: "Total", value: String(total) },
                  { label: "Detected", value: String(detected) },
                  {
                    label: "Privileged containers",
                    value: String(
                      containers.filter((r) => r.privileged).length,
                    ),
                  },
                ]}
              />
            );
          })()}
          {tab === "endpoint" && (
            <DataTable
              columns={endpointCols}
              rows={rows as EndpointObservation[]}
              onRowClick={(r) => setSelected(r)}
              rowLabel={(r) => `Open ${r.id}`}
              empty="No observations"
            />
          )}
          {tab === "server" && (
            <DataTable
              columns={serverCols}
              rows={rows as ServerObservation[]}
              onRowClick={(r) => setSelected(r)}
              rowLabel={(r) => `Open ${r.id}`}
              empty="No observations"
            />
          )}
          {tab === "container" && (
            <DataTable
              columns={containerCols}
              rows={rows as ContainerObservation[]}
              onRowClick={(r) => setSelected(r)}
              rowLabel={(r) => `Open ${r.id}`}
              empty="No observations"
            />
          )}
          {tab === "cloud" && (
            <DataTable
              columns={cloudCols}
              rows={rows as CloudObservation[]}
              onRowClick={(r) => setSelected(r)}
              rowLabel={(r) => `Open ${r.id}`}
              empty="No observations"
            />
          )}
        </>
      )}
      {selected !== null && (
        <Detail row={selected as never} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
