import { useMemo, useState } from "react";
import {
  parseForensicArtifactRow,
  parseHuntRow,
  parseTimelineRow,
} from "../contracts";
import type { ForensicArtifactRow, HuntRow, TimelineRow } from "../contracts";
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

type Tab = "hunting" | "timeline" | "forensics";
type ForensicsTab = "all" | "endpoint" | "network" | "cloud" | "identity";

const huntCols: Column<HuntRow>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "id",
    header: "Event ID",
    sortable: true,
    sortValue: (r) => r.id,
    render: (r) => <span className="mono">{r.id}</span>,
  },
  {
    key: "event_type",
    header: "Event Type",
    sortable: true,
    sortValue: (r) => r.event_type,
    render: (r) => <span className="mono">{r.event_type}</span>,
  },
  {
    key: "source",
    header: "Source",
    sortable: true,
    sortValue: (r) => r.source,
    render: (r) => r.source,
  },
  {
    key: "kind",
    header: "Result",
    sortable: true,
    sortValue: (r) => r.kind,
    render: (r) => <StatusBadge value={r.kind} tone="neutral" />,
  },
];

const timelineCols: Column<TimelineRow>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "kind",
    header: "Kind",
    sortable: true,
    sortValue: (r) => r.kind,
    render: (r) => r.kind,
  },
  {
    key: "id",
    header: "ID",
    sortable: true,
    sortValue: (r) => r.id,
    render: (r) => <span className="mono">{r.id}</span>,
  },
  {
    key: "summary",
    header: "Summary",
    sortable: true,
    sortValue: (r) => r.summary,
    render: (r) => r.summary,
  },
];

type ArtifactTableRow = ForensicArtifactRow & { id: string };

const artifactCols: Column<ArtifactTableRow>[] = [
  {
    key: "observed_at",
    header: "Observed",
    sortable: true,
    sortValue: (r) => r.observed_at,
    render: (r) => <span className="mono">{fmtTime(r.observed_at)}</span>,
  },
  {
    key: "type",
    header: "Type",
    sortable: true,
    sortValue: (r) => r.type,
    render: (r) => <StatusBadge value={r.type} tone="neutral" />,
  },
  {
    key: "event_id",
    header: "Event",
    sortable: true,
    sortValue: (r) => r.event_id,
    render: (r) => <span className="mono">{r.event_id}</span>,
  },
  {
    key: "asset_id",
    header: "Asset",
    sortable: true,
    sortValue: (r) => r.asset_id,
    render: (r) => <span className="mono">{r.asset_id}</span>,
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

function formatDetailValue(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object" && v !== null) return JSON.stringify(v);
  return String(v ?? "—");
}

function Detail({
  row,
  onClose,
}: {
  row: { id?: string; event_id?: string; [k: string]: unknown };
  onClose: () => void;
}) {
  const title = (row.id ?? row.event_id ?? "detail") as string;
  const groups = groupDetailFields(Object.entries(row));
  return (
    <Drawer title={title} onClose={onClose}>
      <div className="field-grid">
        {groups.ungrouped.map(([k, v]) => (
          <Field key={k} label={k}>
            {formatDetailValue(v)}
          </Field>
        ))}
        {groups.identity.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Identity</h4>
            {groups.identity.map(([k, v]) => (
              <Field key={k} label={k}>
                {formatDetailValue(v)}
              </Field>
            ))}
          </div>
        )}
        {groups.risk.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Risk</h4>
            {groups.risk.map(([k, v]) => (
              <Field key={k} label={k}>
                {formatDetailValue(v)}
              </Field>
            ))}
          </div>
        )}
        {groups.history.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">History</h4>
            {groups.history.map(([k, v]) => (
              <Field key={k} label={k}>
                {formatDetailValue(v)}
              </Field>
            ))}
          </div>
        )}
      </div>
      <h3 className="detail-section">Provenance</h3>
      <p className="muted">
        Read-only investigation data from persisted telemetry and evidence.
        Ordering is presentation, not causality.
      </p>
    </Drawer>
  );
}

const FORENSICS_PATHS: Record<ForensicsTab, string> = {
  all: "/api/v1/forensics/artifacts",
  endpoint: "/api/v1/forensics/endpoint",
  network: "/api/v1/forensics/network",
  cloud: "/api/v1/forensics/cloud",
  identity: "/api/v1/forensics/identity",
};

export function Investigations() {
  const [tab, setTab] = useState<Tab>("hunting");
  const [forensicsTab, setForensicsTab] = useState<ForensicsTab>("all");
  const [q, setQ] = useState("");
  const hunting = useApiList("/api/v1/hunting/events", parseHuntRow);
  const timeline = useApiList("/api/v1/hunting/timeline", parseTimelineRow);
  const forensics = useApiList(
    FORENSICS_PATHS[forensicsTab],
    parseForensicArtifactRow,
  );
  const [selected, setSelected] = useState<unknown | null>(null);

  const huntRows = useMemo(() => {
    const list = listOf(hunting);
    if (!list) return null;
    if (!q.trim()) return list;
    const needle = q.toLowerCase();
    return list.filter((r) =>
      `${r.id} ${r.source} ${r.asset_id} ${r.event_type}`
        .toLowerCase()
        .includes(needle),
    );
  }, [hunting, q]);

  const loading =
    tab === "hunting"
      ? hunting.kind === "loading"
      : tab === "timeline"
        ? timeline.kind === "loading"
        : forensics.kind === "loading";

  return (
    <div className="view">
      <h1 className="page-title">Investigations</h1>
      <p className="page-sub">
        Threat hunting, unified timelines, and metadata-level forensics over
        persisted observations. Read-only; ordering is not causality.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {(
          [
            ["hunting", "Hunting"],
            ["timeline", "Timeline"],
            ["forensics", "Forensics"],
          ] as [Tab, string][]
        ).map(([t, label]) => (
          <button
            key={t}
            onClick={() => {
              setTab(t);
              setSelected(null);
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "forensics" && (
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          {(
            [
              ["all", "All"],
              ["endpoint", "Endpoint"],
              ["network", "Network"],
              ["cloud", "Cloud"],
              ["identity", "Identity"],
            ] as [ForensicsTab, string][]
          ).map(([t, label]) => (
            <button
              key={t}
              onClick={() => {
                setForensicsTab(t);
                setSelected(null);
              }}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {tab !== "timeline" && (
        <FilterBar
          search={q}
          onSearch={setQ}
          searchLabel={
            tab === "hunting" ? "Search hunting" : "Search forensics"
          }
          searchPlaceholder="id, source, asset…"
          selects={[]}
          onClear={() => setQ("")}
          hasActive={q !== ""}
        />
      )}

      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={5} />
        </>
      )}

      {!loading && tab === "hunting" && (
        <>
          {(() => {
            const hunts = listOf(hunting);
            const entries = listOf(timeline);
            const artifacts = listOf(forensics);
            if (!hunts || hunts.length === 0 || !entries || !artifacts)
              return null;
            return (
              <SummaryStrip
                statement="Open hypotheses wait on evidence — see what is still unattributed."
                stats={[
                  { label: "Hunting events", value: String(hunts.length) },
                  { label: "Timeline entries", value: String(entries.length) },
                  {
                    label: "Forensic artifacts",
                    value: String(artifacts.length),
                  },
                ]}
              />
            );
          })()}
          <HuntingBody rows={huntRows} state={hunting} onSelect={setSelected} />
        </>
      )}
      {!loading && tab === "timeline" && (
        <TimelineBody state={timeline} onSelect={setSelected} />
      )}
      {!loading && tab === "forensics" && (
        <ForensicsBody state={forensics} onSelect={setSelected} />
      )}

      {selected !== null && (
        <Detail row={selected as never} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function HuntingBody({
  rows,
  state,
  onSelect,
}: {
  rows: HuntRow[] | null;
  state: ReturnType<typeof useApiList<HuntRow>>;
  onSelect: (r: unknown) => void;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="investigations"
          title="No hunting results"
          description="Persisted telemetry matching the query will appear here."
        />
      </div>
    );
  return (
    <DataTable
      columns={huntCols}
      rows={rows}
      onRowClick={onSelect}
      rowLabel={(r) => `Open ${r.id}`}
      empty="No hunting results"
    />
  );
}

function TimelineBody({
  state,
  onSelect,
}: {
  state: ReturnType<typeof useApiList<TimelineRow>>;
  onSelect: (r: unknown) => void;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  const rows = listOf(state);
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="investigations"
          title="No timeline entries"
          description="Telemetry, detections, and evidence will order here by occurred_at."
        />
      </div>
    );
  return (
    <DataTable
      columns={timelineCols}
      rows={rows}
      onRowClick={onSelect}
      rowLabel={(r) => `Open ${r.id}`}
      empty="No timeline entries"
    />
  );
}

function ForensicsBody({
  state,
  onSelect,
}: {
  state: ReturnType<typeof useApiList<ForensicArtifactRow>>;
  onSelect: (r: unknown) => void;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  const list = listOf(state);
  if (!list || list.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="investigations"
          title="No forensic artifacts"
          description="Classified metadata artifacts will appear here."
        />
      </div>
    );
  const rows = list.map((r) => ({ ...r, id: r.event_id }));
  return (
    <DataTable
      columns={artifactCols}
      rows={rows}
      onRowClick={onSelect}
      rowLabel={(r) => `Open ${r.event_id}`}
      empty="No forensic artifacts"
    />
  );
}
