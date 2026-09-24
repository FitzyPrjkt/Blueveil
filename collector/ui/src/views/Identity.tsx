import { useMemo, useState } from "react";
import {
  parseAuthObservation,
  parseDataObservation,
  parseIdentityObservation,
} from "../contracts";
import type {
  AuthObservation,
  DataObservation,
  IdentityObservation,
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

type Tab = "identity" | "authentication" | "data";

const identityCols: Column<IdentityObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "principal",
    header: "Principal",
    sortable: true,
    sortValue: (r) => r.principal,
    render: (r) => r.principal,
  },
  {
    key: "action",
    header: "Action",
    sortable: true,
    sortValue: (r) => r.action,
    render: (r) => r.action,
  },
  {
    key: "target",
    header: "Target",
    sortable: true,
    sortValue: (r) => r.target ?? "",
    render: (r) => r.target ?? "—",
  },
  {
    key: "result",
    header: "Result",
    sortable: true,
    sortValue: (r) => r.result ?? "",
    render: (r) => r.result ?? "—",
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

const authCols: Column<AuthObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "principal",
    header: "Principal",
    sortable: true,
    sortValue: (r) => r.principal,
    render: (r) => r.principal,
  },
  {
    key: "method",
    header: "Method",
    sortable: true,
    sortValue: (r) => r.method ?? "",
    render: (r) => r.method ?? "—",
  },
  {
    key: "provider",
    header: "Provider",
    sortable: true,
    sortValue: (r) => r.provider ?? "",
    render: (r) => r.provider ?? "—",
  },
  {
    key: "outcome",
    header: "Outcome",
    sortable: true,
    sortValue: (r) => r.outcome,
    render: (r) => (
      <StatusBadge
        value={r.outcome.toUpperCase()}
        tone={
          r.outcome === "failure" || r.outcome === "denied" ? "bad" : "neutral"
        }
      />
    ),
  },
  {
    key: "source",
    header: "Source",
    sortable: true,
    sortValue: (r) => r.source,
    render: (r) => r.source,
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

const dataCols: Column<DataObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "store",
    header: "Store",
    sortable: true,
    sortValue: (r) => r.store ?? "",
    render: (r) => r.store ?? "—",
  },
  {
    key: "resource",
    header: "Resource",
    sortable: true,
    sortValue: (r) => r.resource,
    render: (r) => r.resource,
  },
  {
    key: "principal",
    header: "Principal",
    sortable: true,
    sortValue: (r) => r.principal ?? "",
    render: (r) => r.principal ?? "—",
  },
  {
    key: "action",
    header: "Action",
    sortable: true,
    sortValue: (r) => r.action,
    render: (r) => r.action,
  },
  {
    key: "classification",
    header: "Classification",
    sortable: true,
    sortValue: (r) => r.classification ?? "",
    render: (r) => r.classification ?? "—",
  },
  {
    key: "result",
    header: "Result",
    sortable: true,
    sortValue: (r) => r.result ?? "",
    render: (r) => r.result ?? "—",
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
          alert and incident. Provenance: source {row.source}, rule and
          policy/threshold recorded in detection attributes, evidence preserved.
        </p>
      ) : (
        <p className="muted">
          No detection. Observation, not a finding — most identity telemetry is
          ordinary activity.
        </p>
      )}
    </Drawer>
  );
}

const EMPTY_COPY: Record<Tab, { title: string; description: string }> = {
  identity: {
    title: "No identity observations",
    description:
      "Identity telemetry will appear when a configured source emits events.",
  },
  authentication: {
    title: "No authentication observations",
    description:
      "Authentication telemetry will appear when a configured source emits events.",
  },
  data: {
    title: "No data observations",
    description:
      "Data-security telemetry will appear when a configured source emits events.",
  },
};

export function Identity() {
  const [tab, setTab] = useState<Tab>("identity");
  const [q, setQ] = useState("");
  const [outcome, setOutcome] = useState("ALL");
  const [action, setAction] = useState("ALL");
  const [detectedOnly, setDetectedOnly] = useState(false);
  const identity = useApiList(
    "/api/v1/identity/observations",
    parseIdentityObservation,
  );
  const auth = useApiList(
    "/api/v1/authentication/observations",
    parseAuthObservation,
  );
  const data = useApiList("/api/v1/data/observations", parseDataObservation);
  const [selected, setSelected] = useState<unknown | null>(null);

  const current = { identity, authentication: auth, data }[tab];
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
    if (tab === "authentication" && outcome !== "ALL") {
      out = out.filter((r) => (r as AuthObservation).outcome === outcome);
    }
    if (tab !== "authentication" && action !== "ALL") {
      out = out.filter(
        (r) =>
          (r as IdentityObservation).action === action ||
          (r as DataObservation).action === action,
      );
    }
    if (detectedOnly)
      out = out.filter((r) => (r as { detected: boolean }).detected);
    return out;
  }, [current, q, outcome, action, detectedOnly, tab]);

  // Action vocabularies mirror the backend filters (validIdentityAction /
  // validDataAction): the state was previously dead on non-auth tabs.
  const ACTION_OPTIONS: Record<Tab, string[]> = {
    identity: [
      "ALL",
      "login",
      "logout",
      "role_change",
      "group_change",
      "account_create",
      "account_disable",
      "account_enable",
      "permission_change",
    ],
    authentication: ["ALL"],
    data: [
      "ALL",
      "read",
      "write",
      "delete",
      "export",
      "access",
      "permission_change",
    ],
  };

  const selects =
    tab === "authentication"
      ? [
          {
            label: "Outcome",
            value: outcome,
            options: ["ALL", "success", "failure", "denied"].map((v) => ({
              value: v,
              label: v,
            })),
            onChange: setOutcome,
          },
        ]
      : [
          {
            label: "Action",
            value: action,
            options: ACTION_OPTIONS[tab].map((v) => ({ value: v, label: v })),
            onChange: setAction,
          },
        ];

  const clearFilters = () => {
    setQ("");
    setOutcome("ALL");
    setAction("ALL");
    setDetectedOnly(false);
  };

  return (
    <div className="view">
      <h1 className="page-title">Identity</h1>
      <p className="page-sub">
        Identity, authentication, and data-security observations — defensive,
        deterministic. Most rows are not findings.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {(["identity", "authentication", "data"] as Tab[]).map((t) => (
          <button
            key={t}
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
        searchLabel="Search identity"
        searchPlaceholder="principal, resource, action…"
        selects={selects}
        onClear={clearFilters}
        hasActive={
          q !== "" || outcome !== "ALL" || action !== "ALL" || detectedOnly
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
            icon="identity"
            title={EMPTY_COPY[tab].title}
            description={EMPTY_COPY[tab].description}
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
              icon="identity"
              title="No matching observations"
              description="No rows match the current filters."
              action={{ label: "Clear filters", onClick: clearFilters }}
            />
          </div>
        )}
      {!loading && !backendError && !invalid && rows && rows.length > 0 && (
        <>
          {(() => {
            const identities = listOf(identity) ?? [];
            const auths = listOf(auth) ?? [];
            const datas = listOf(data) ?? [];
            const detected =
              identities.filter((r) => r.detected).length +
              auths.filter((r) => r.detected).length +
              datas.filter((r) => r.detected).length;
            return (
              <SummaryStrip
                statement="Failed logins deserve a look first; absence of identity data is not safety."
                stats={[
                  { label: "Auth observations", value: String(auths.length) },
                  {
                    label: "Failed",
                    value: String(
                      auths.filter(
                        (r) =>
                          r.outcome === "failure" || r.outcome === "denied",
                      ).length,
                    ),
                  },
                  { label: "Detected", value: String(detected) },
                ]}
              />
            );
          })()}
          {tab === "identity" && (
            <DataTable
              columns={identityCols}
              rows={rows as IdentityObservation[]}
              onRowClick={setSelected}
              rowLabel={(r) => `Open ${r.id}`}
              empty="No observations"
            />
          )}
          {tab === "authentication" && (
            <DataTable
              columns={authCols}
              rows={rows as AuthObservation[]}
              onRowClick={setSelected}
              rowLabel={(r) => `Open ${r.id}`}
              empty="No observations"
            />
          )}
          {tab === "data" && (
            <DataTable
              columns={dataCols}
              rows={rows as DataObservation[]}
              onRowClick={setSelected}
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
