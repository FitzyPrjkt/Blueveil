import { useMemo, useState } from "react";
import {
  parseArchEdge,
  parseArchNode,
  parseGRCAssessment,
  parseGRCControl,
  parseResilienceRow,
} from "../contracts";
import type {
  ArchEdge,
  ArchNode,
  GRCAssessment,
  GRCControl,
  ResilienceRow,
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

type Tab = "controls" | "assessments" | "architecture" | "resilience";

function toneFor(status: string): "info" | "warn" | "bad" | "low" | "neutral" {
  if (status === "COMPLIANT" || status === "READY") return "low";
  if (
    status === "NON_COMPLIANT" ||
    status === "FAILED" ||
    status === "NOT_READY"
  )
    return "bad";
  if (status === "PARTIALLY_COMPLIANT" || status === "DEGRADED") return "warn";
  return "neutral";
}

const controlCols: Column<GRCControl>[] = [
  {
    key: "id",
    header: "Control",
    sortable: true,
    sortValue: (r) => r.id,
    render: (r) => <span className="mono">{r.id}</span>,
  },
  {
    key: "title",
    header: "Title",
    sortable: true,
    sortValue: (r) => r.title,
    render: (r) => r.title,
  },
  {
    key: "domain",
    header: "Domain",
    sortable: true,
    sortValue: (r) => r.domain,
    render: (r) => r.domain,
  },
  {
    key: "implementation",
    header: "Implementation",
    sortable: true,
    sortValue: (r) => r.implementation,
    render: (r) => r.implementation || "—",
  },
];

const assessmentCols: Column<GRCAssessment>[] = [
  {
    key: "control_id",
    header: "Control",
    sortable: true,
    sortValue: (r) => r.control_id,
    render: (r) => <span className="mono">{r.control_id}</span>,
  },
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status,
    render: (r) => <StatusBadge value={r.status} tone={toneFor(r.status)} />,
  },
  {
    key: "target",
    header: "Target",
    sortable: true,
    sortValue: (r) => r.target,
    render: (r) => <span className="mono">{r.target}</span>,
  },
  {
    key: "risk",
    header: "Risk",
    sortable: true,
    sortValue: (r) => r.risk,
    render: (r) => r.risk || "—",
  },
  {
    key: "observed_at",
    header: "Observed",
    sortable: true,
    sortValue: (r) => r.observed_at,
    render: (r) => <span className="mono">{fmtTime(r.observed_at)}</span>,
  },
];

const nodeCols: Column<NodeRow>[] = [
  {
    key: "name",
    header: "System",
    sortable: true,
    sortValue: (r) => r.name,
    render: (r) => <span className="mono">{r.name}</span>,
  },
  {
    key: "kind",
    header: "Kind",
    sortable: true,
    sortValue: (r) => r.kind,
    render: (r) => r.kind,
  },
  {
    key: "boundary",
    header: "Boundary",
    sortable: true,
    sortValue: (r) => r.boundary,
    render: (r) => r.boundary || "—",
  },
];

type EdgeRow = ArchEdge & { id: string };
type NodeRow = ArchNode & { id: string };

const edgeCols: Column<EdgeRow>[] = [
  {
    key: "parent_id",
    header: "From",
    sortable: true,
    sortValue: (r) => r.parent_id,
    render: (r) => <span className="mono">{r.parent_id}</span>,
  },
  {
    key: "kind",
    header: "Relationship",
    sortable: true,
    sortValue: (r) => r.kind,
    render: (r) => <span className="mono">{r.kind}</span>,
  },
  {
    key: "child_id",
    header: "To",
    sortable: true,
    sortValue: (r) => r.child_id,
    render: (r) => <span className="mono">{r.child_id}</span>,
  },
];

const resilienceCols: Column<ResilienceRow>[] = [
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
    render: (r) => <StatusBadge value={r.status} tone={toneFor(r.status)} />,
  },
  {
    key: "observed_at",
    header: "Observed",
    sortable: true,
    sortValue: (r) => r.observed_at,
    render: (r) => <span className="mono">{fmtTime(r.observed_at)}</span>,
  },
];

const ASSESSMENT_STATUSES = [
  "ALL",
  "COMPLIANT",
  "PARTIALLY_COMPLIANT",
  "NON_COMPLIANT",
  "NOT_ASSESSED",
  "NOT_APPLICABLE",
  "UNKNOWN",
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
  row: { id?: string; [k: string]: unknown };
  onClose: () => void;
}) {
  const groups = groupDetailFields(Object.entries(row));
  return (
    <Drawer title={(row.id as string) ?? "detail"} onClose={onClose}>
      <div className="field-grid">
        {groups.ungrouped.map(([k, v]) => (
          <Field key={k} label={k}>
            {Array.isArray(v) ? v.join(", ") || "—" : String(v ?? "—")}
          </Field>
        ))}
        {groups.identity.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Identity</h4>
            {groups.identity.map(([k, v]) => (
              <Field key={k} label={k}>
                {Array.isArray(v) ? v.join(", ") || "—" : String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
        {groups.risk.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Risk</h4>
            {groups.risk.map(([k, v]) => (
              <Field key={k} label={k}>
                {Array.isArray(v) ? v.join(", ") || "—" : String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
        {groups.history.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">History</h4>
            {groups.history.map(([k, v]) => (
              <Field key={k} label={k}>
                {Array.isArray(v) ? v.join(", ") || "—" : String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
      </div>
      <h3 className="detail-section">Provenance</h3>
      <p className="muted">
        Explicit assessment record. Statuses describe what was assessed — never
        a guarantee about anything unobserved.
      </p>
    </Drawer>
  );
}

export function Governance() {
  const [tab, setTab] = useState<Tab>("controls");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("ALL");
  const controls = useApiList("/api/v1/grc/controls", parseGRCControl);
  const assessments = useApiList("/api/v1/grc/assessments", parseGRCAssessment);
  const nodes = useApiList("/api/v1/architecture/assets", parseArchNode);
  const edges = useApiList("/api/v1/architecture/relationships", parseArchEdge);
  const posture = useApiList("/api/v1/resilience/posture", parseResilienceRow);
  const [selected, setSelected] = useState<unknown | null>(null);

  const controlRows = useMemo(() => {
    const list = listOf(controls);
    if (!list) return null;
    if (!q.trim()) return list;
    const needle = q.toLowerCase();
    return list.filter((r) =>
      `${r.id} ${r.title} ${r.domain}`.toLowerCase().includes(needle),
    );
  }, [controls, q]);

  const assessmentRows = useMemo(() => {
    const list = listOf(assessments);
    if (!list) return null;
    let out = list;
    if (status !== "ALL") out = out.filter((r) => r.status === status);
    if (q.trim()) {
      const needle = q.toLowerCase();
      out = out.filter((r) =>
        `${r.control_id} ${r.target} ${r.assessor}`
          .toLowerCase()
          .includes(needle),
      );
    }
    return out;
  }, [assessments, status, q]);

  const loading =
    tab === "controls"
      ? controls.kind === "loading"
      : tab === "assessments"
        ? assessments.kind === "loading"
        : tab === "architecture"
          ? nodes.kind === "loading" || edges.kind === "loading"
          : posture.kind === "loading";

  return (
    <div className="view">
      <h1 className="page-title">Governance</h1>
      <p className="page-sub">
        Controls, assessments, architecture context, and resilience posture.
        Stated statuses only — nothing here certifies or remediates.{" "}
        <a href="#/report">Download report →</a>
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {(
          [
            ["controls", "Controls"],
            ["assessments", "Assessments"],
            ["architecture", "Architecture"],
            ["resilience", "Resilience"],
          ] as [Tab, string][]
        ).map(([t, label]) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            onClick={() => {
              setTab(t);
              setSelected(null);
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {(tab === "controls" || tab === "assessments") && (
        <FilterBar
          search={q}
          onSearch={setQ}
          searchLabel={
            tab === "controls" ? "Search controls" : "Search assessments"
          }
          searchPlaceholder="id, title, target…"
          selects={
            tab === "assessments"
              ? [
                  {
                    label: "Status",
                    value: status,
                    options: ASSESSMENT_STATUSES.map((v) => ({
                      value: v,
                      label: v,
                    })),
                    onChange: setStatus,
                  },
                ]
              : []
          }
          onClear={() => {
            setQ("");
            setStatus("ALL");
          }}
          hasActive={q !== "" || status !== "ALL"}
        />
      )}

      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={5} />
        </>
      )}

      {!loading && tab === "controls" && (
        <>
          {(() => {
            const ctrls = listOf(controls);
            const asses = listOf(assessments);
            if (!ctrls || ctrls.length === 0 || !asses) return null;
            return (
              <SummaryStrip
                statement="Controls with no passing assessment are the compliance gap."
                stats={[
                  { label: "Controls", value: String(ctrls.length) },
                  { label: "Assessments", value: String(asses.length) },
                  {
                    label: "Failing",
                    value: String(
                      asses.filter(
                        (r) =>
                          r.status === "NON_COMPLIANT" ||
                          r.status === "FAILED" ||
                          r.status === "NOT_READY",
                      ).length,
                    ),
                  },
                ]}
              />
            );
          })()}
          <ControlsBody rows={controlRows} state={controls} />
        </>
      )}
      {!loading && tab === "assessments" && (
        <AssessmentsBody
          rows={assessmentRows}
          state={assessments}
          onSelect={setSelected}
        />
      )}
      {!loading && tab === "architecture" && (
        <ArchitectureBody nodes={nodes} edges={edges} />
      )}
      {!loading && tab === "resilience" && <ResilienceBody state={posture} />}

      {selected !== null && (
        <Detail row={selected as never} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function ControlsBody({
  rows,
  state,
}: {
  rows: GRCControl[] | null;
  state: ReturnType<typeof useApiList<GRCControl>>;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="governance"
          title="No controls"
          description="The control catalog is empty. Controls come from a versioned baseline."
        />
      </div>
    );
  return (
    <DataTable
      columns={controlCols}
      rows={rows}
      rowLabel={(r) => `Control ${r.id}`}
      empty="No controls"
    />
  );
}

function AssessmentsBody({
  rows,
  state,
  onSelect,
}: {
  rows: GRCAssessment[] | null;
  state: ReturnType<typeof useApiList<GRCAssessment>>;
  onSelect: (r: unknown) => void;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="governance"
          title="No assessments"
          description="Assessments appear here when controls are explicitly assessed with evidence."
        />
      </div>
    );
  return (
    <DataTable
      columns={assessmentCols}
      rows={rows}
      onRowClick={onSelect}
      rowLabel={(r) => `Assessment ${r.id}`}
      empty="No assessments"
    />
  );
}

function ArchitectureBody({
  nodes,
  edges,
}: {
  nodes: ReturnType<typeof useApiList<ArchNode>>;
  edges: ReturnType<typeof useApiList<ArchEdge>>;
}) {
  if (
    nodes.kind === "backend-error" ||
    nodes.kind === "invalid" ||
    edges.kind === "backend-error" ||
    edges.kind === "invalid"
  )
    return (
      <ErrorState
        title="Backend error"
        message={
          (nodes.kind !== "loading" &&
          nodes.kind !== "ready" &&
          nodes.kind !== "empty"
            ? nodes.message
            : "Could not load architecture.") as string
        }
      />
    );
  const nodeList = listOf(nodes);
  const edgeList = listOf(edges);
  const nodeRows: NodeRow[] | null =
    nodeList === null ? null : nodeList.map((r) => ({ ...r, id: r.asset_id }));
  const edgeRows: EdgeRow[] | null =
    edgeList === null
      ? null
      : edgeList.map((r, i) => ({
          ...r,
          id: `${r.parent_id}>${r.child_id}>${r.kind}>${i}`,
        }));
  if (
    (!nodeRows || nodeRows.length === 0) &&
    (!edgeRows || edgeRows.length === 0)
  )
    return (
      <div className="panel">
        <EmptyState
          icon="governance"
          title="No architecture data"
          description="Systems and relationships appear here from the asset inventory."
        />
      </div>
    );
  return (
    <>
      <h3>Systems</h3>
      {nodeRows && nodeRows.length > 0 ? (
        <DataTable
          columns={nodeCols}
          rows={nodeRows}
          rowLabel={(r) => `System ${r.asset_id}`}
          empty="No systems"
        />
      ) : (
        <p className="muted">No systems.</p>
      )}
      <h3>Relationships</h3>
      {edgeRows && edgeRows.length > 0 ? (
        <DataTable
          columns={edgeCols}
          rows={edgeRows.map((e, i) => ({
            ...e,
            id: `${e.parent_id}>${e.child_id}>${e.kind}>${i}`,
          }))}
          rowLabel={(r) => `Relationship ${r.parent_id} ${r.kind}`}
          empty="No relationships"
        />
      ) : (
        <p className="muted">No relationships.</p>
      )}
      <p className="muted">
        Tables only: topology shown is exactly what the inventory states.
      </p>
    </>
  );
}

function ResilienceBody({
  state,
}: {
  state: ReturnType<typeof useApiList<ResilienceRow>>;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  const rows = listOf(state);
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="governance"
          title="No resilience posture"
          description="Posture rows appear here when resilience is explicitly assessed."
        />
      </div>
    );
  return (
    <>
      <DataTable
        columns={resilienceCols}
        rows={rows}
        rowLabel={(r) => `Posture ${r.id}`}
        empty="No resilience posture"
      />
      <p className="muted">
        Observed means a source emitted it; declared means stated without
        observation; not assessed means no evidence either way. No scores.
      </p>
    </>
  );
}
