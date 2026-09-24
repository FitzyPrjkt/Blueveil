import { useMemo, useState } from "react";
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  parseAsset,
  parseAssetRelationship,
} from "../contracts";
import type { Asset, AssetRelationship } from "../contracts";
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
import {
  StatusTimeline,
  type TimelineStep,
} from "../components/StatusTimeline";
import { fmtTime, listOf, useApiList, useApiObject } from "./hooks";
import { assetCoverage } from "./overviewAgg";

function assetTone(s: string): "info" | "warn" | "bad" | "low" | "neutral" {
  if (s === "ASSET_STATUS_STALE") return "warn";
  if (s === "ASSET_STATUS_DISCOVERED") return "info";
  return "neutral"; // ACTIVE and RETIRED are states, not judgments
}

function shortType(t: string): string {
  return t.replace("ASSET_TYPE_", "");
}

const COLUMNS: Column<Asset>[] = [
  {
    key: "type",
    header: "Type",
    sortable: true,
    sortValue: (r) => r.type,
    render: (r) => <span className="mono">{shortType(r.type)}</span>,
  },
  {
    key: "name",
    header: "Name / Identifier",
    sortable: true,
    sortValue: (r) => r.name,
    render: (r) => (
      <span>
        <span style={{ fontWeight: 600 }}>{r.name}</span>
        <br />
        <span className="mono" style={{ color: "var(--bv-muted)" }}>
          {r.id}
        </span>
      </span>
    ),
  },
  {
    key: "environment",
    header: "Environment",
    sortable: true,
    sortValue: (r) => r.environment ?? "",
    render: (r) => r.environment || "—",
  },
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status ?? "",
    render: (r) =>
      r.status ? (
        <StatusBadge value={r.status} tone={assetTone(r.status)} />
      ) : (
        <span style={{ color: "var(--bv-muted)" }}>unknown</span>
      ),
  },
  {
    key: "first_seen",
    header: "First Seen",
    sortable: true,
    sortValue: (r) => r.first_seen ?? "",
    render: (r) => (
      <span className="tabular">
        {r.first_seen ? fmtTime(r.first_seen) : "—"}
      </span>
    ),
  },
  {
    key: "last_seen",
    header: "Last Seen",
    sortable: true,
    sortValue: (r) => r.last_seen ?? "",
    render: (r) => (
      <span className="tabular">
        {r.last_seen ? fmtTime(r.last_seen) : "—"}
      </span>
    ),
  },
];

const LIFECYCLE = [
  "ASSET_STATUS_DISCOVERED",
  "ASSET_STATUS_ACTIVE",
  "ASSET_STATUS_STALE",
  "ASSET_STATUS_RETIRED",
];

export function Assets({ initialStatus }: { initialStatus?: string }) {
  const assets = useApiList("/api/v1/assets", parseAsset);
  const [search, setSearch] = useState("");
  const [type, setType] = useState("ALL");
  const [status, setStatus] = useState(
    initialStatus && LIFECYCLE.includes(initialStatus) ? initialStatus : "ALL",
  );
  // STALE via query maps to the dedicated stale-only toggle, not the select.
  const [staleOnly, setStaleOnly] = useState(
    initialStatus === "ASSET_STATUS_STALE",
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const rows = useMemo(() => {
    const list = listOf(assets);
    if (!list) return null;
    const q = search.trim().toLowerCase();
    return list.filter((a) => {
      if (type !== "ALL" && a.type !== type) return false;
      if (status !== "ALL" && (a.status ?? "") !== status) return false;
      if (staleOnly && a.status !== "ASSET_STATUS_STALE") return false;
      if (
        q &&
        !(
          a.name.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q) ||
          (a.environment ?? "").toLowerCase().includes(q)
        )
      )
        return false;
      return true;
    });
  }, [assets, search, type, status, staleOnly]);

  const loading = assets.kind === "loading";
  const backendError = assets.kind === "backend-error" ? assets.message : null;
  const invalid = assets.kind === "invalid" ? assets.message : null;
  const total = (listOf(assets) ?? []).length;
  const hasActive =
    search !== "" || type !== "ALL" || status !== "ALL" || staleOnly;
  const clearFilters = () => {
    setSearch("");
    setType("ALL");
    setStatus("ALL");
    setStaleOnly(false);
  };

  return (
    <>
      <h1 className="page-title">Assets</h1>
      <p className="page-sub">
        Observed inventory. Discovery means observed — never safe, never dead
        when stale.
      </p>
      {(() => {
        const list = listOf(assets);
        if (!list) return null;
        const cov = assetCoverage(list);
        return (
          <SummaryStrip
            statement="Stale assets are unobserved, not dead — verify before removing."
            stats={[
              { label: "Monitored", value: String(cov.monitored) },
              { label: "Active", value: String(cov.active) },
              { label: "Stale", value: String(cov.stale) },
            ]}
          />
        );
      })()}
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
            icon="assets"
            title="No assets"
            description="Assets will appear here when observations are ingested — from telemetry sweeps, inventory, or scanner adapters."
          />
        </div>
      )}
      {!loading && !backendError && !invalid && total > 0 && rows !== null && (
        <>
          <FilterBar
            search={search}
            onSearch={setSearch}
            searchLabel="Search assets"
            searchPlaceholder="Search name, id, or environment…"
            selects={[
              {
                label: "Type",
                value: type,
                options: [
                  { value: "ALL", label: "All types" },
                  ...ASSET_TYPES.map((t) => ({
                    value: t,
                    label: shortType(t),
                  })),
                ],
                onChange: setType,
              },
              {
                label: "Status",
                value: status,
                options: [
                  { value: "ALL", label: "All statuses" },
                  ...ASSET_STATUSES.map((s) => ({
                    value: s,
                    label: s.replace("ASSET_STATUS_", ""),
                  })),
                ],
                onChange: setStatus,
              },
            ]}
            onClear={clearFilters}
            hasActive={hasActive}
          />
          <label
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              fontSize: 13,
              color: "var(--bv-muted)",
              marginBottom: 12,
            }}
          >
            <input
              type="checkbox"
              checked={staleOnly}
              onChange={(e) => setStaleOnly(e.target.checked)}
            />
            Stale only (unobserved lately — not dead)
          </label>
          {rows.length === 0 ? (
            <div className="panel">
              <EmptyState
                icon="assets"
                title="No matching assets"
                description="No assets match the current search and filters."
                action={{ label: "Clear filters", onClick: clearFilters }}
              />
            </div>
          ) : (
            <DataTable
              columns={COLUMNS}
              rows={rows}
              onRowClick={(r) => setSelectedId(r.id)}
              rowLabel={(r) => `Asset ${r.name}`}
              empty={<></>}
            />
          )}
        </>
      )}
      {selectedId && (
        <AssetDetail id={selectedId} onClose={() => setSelectedId(null)} />
      )}
    </>
  );
}

function lifecycleSteps(status: string | undefined): TimelineStep[] {
  // The backend lifecycle branches (STALE→ACTIVE revival, ACTIVE→RETIRED
  // skip): only the current state is marked. Earlier display positions are
  // NOT marked done (the asset may never have visited them) and later ones
  // are NOT marked todo-as-future (they may never happen). Display order
  // only — not a progression.
  const idx = LIFECYCLE.indexOf(status ?? "");
  return LIFECYCLE.map((s, i) => ({
    key: s,
    title: s.replace("ASSET_STATUS_", ""),
    state: i === idx ? "now" : "todo",
  }));
}

function AssetDetail({ id, onClose }: { id: string; onClose: () => void }) {
  return (
    <Drawer title={id} onClose={onClose}>
      <AssetDetailBody id={id} />
    </Drawer>
  );
}

function AssetDetailBody({ id }: { id: string }) {
  const assetState = useApiObject(`/api/v1/assets/${id}`, parseAsset);
  const rels = useApiObject(
    `/api/v1/assets/${id}/relationships`,
    parseRelationshipBundle,
  );
  const telemetry = useApiList(
    `/api/v1/assets/${id}/telemetry`,
    parseTelemetryLite,
  );
  const findings = useApiObject(
    `/api/v1/assets/${id}/findings`,
    parseFindingsBundle,
  );
  const allAssets = useApiList("/api/v1/assets", parseAsset);

  if (assetState.kind === "loading") return <HeadingSkeleton />;
  if (assetState.kind === "backend-error")
    return <ErrorState title="Backend error" message={assetState.message} />;
  if (assetState.kind === "invalid")
    return (
      <ErrorState
        title="Invalid data"
        message="Asset record outside the contract."
      />
    );
  const a = assetState.data;
  const names = new Map(
    (listOf(allAssets) ?? []).map((x) => [x.id, x.name] as const),
  );

  return (
    <>
      <dl className="field-grid">
        <div className="field-group">
          <h4 className="group-head">Identity</h4>
          <Field label="Name">{a.name}</Field>
          <Field label="Type">
            <span className="mono">{shortType(a.type)}</span>
          </Field>
          <Field label="Environment">{a.environment || "—"}</Field>
          <Field label="Identifiers">
            <span className="mono">
              {(a.identifiers ?? [])
                .map((x) => `${x.type}:${x.value}`)
                .join(", ") || "—"}
            </span>
          </Field>
          {a.attributes && Object.keys(a.attributes).length > 0 && (
            <Field label="Attributes">
              <span className="mono">
                {Object.entries(a.attributes)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(", ")}
              </span>
            </Field>
          )}
        </div>
        <div className="field-group">
          <h4 className="group-head">Risk</h4>
          <Field label="Status">
            {a.status ? (
              <StatusBadge value={a.status} tone={assetTone(a.status)} />
            ) : (
              <span style={{ color: "var(--bv-muted)" }}>
                unknown (legacy record)
              </span>
            )}
          </Field>
        </div>
        <div className="field-group">
          <h4 className="group-head">History</h4>
          <Field label="First seen">
            <span className="tabular">
              {a.first_seen ? fmtTime(a.first_seen) : "—"}
            </span>
          </Field>
          <Field label="Last seen">
            <span className="tabular">
              {a.last_seen ? fmtTime(a.last_seen) : "—"}
            </span>
          </Field>
        </div>
      </dl>

      <h3 className="section-title">Lifecycle</h3>
      <StatusTimeline steps={lifecycleSteps(a.status)} />
      {a.status === "ASSET_STATUS_STALE" && (
        <p className="page-sub">
          Stale means unobserved lately — not dead, not compromised, not safe.
        </p>
      )}

      <h3 className="section-title">Relationships</h3>
      {rels.kind === "loading" && <TableSkeleton rows={2} />}
      {rels.kind === "backend-error" && (
        <ErrorState title="Backend error" message={rels.message} />
      )}
      {rels.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message="Relationship record outside the contract."
        />
      )}
      {rels.kind === "ready" && (
        <RelationshipList rels={rels.data} names={names} />
      )}
      {(telemetry.kind === "empty" ||
        (telemetry.kind === "ready" && telemetry.data.length === 0)) &&
        null}

      <h3 className="section-title">Telemetry ({telemetryCount(telemetry)})</h3>
      {telemetry.kind === "loading" && <TableSkeleton rows={2} />}
      {telemetry.kind === "backend-error" && (
        <ErrorState title="Backend error" message={telemetry.message} />
      )}
      {telemetry.kind === "ready" &&
        telemetry.data.map((t) => (
          <div key={t.id} className="link-row">
            <span className="mono">{t.id}</span>
            <span style={{ color: "var(--bv-muted)" }}>{t.event_type}</span>
            <span className="tabular" style={{ marginLeft: "auto" }}>
              {fmtTime(t.occurred_at)}
            </span>
          </div>
        ))}
      {(telemetry.kind === "empty" ||
        (telemetry.kind === "ready" && telemetry.data.length === 0)) && (
        <p className="page-sub">No telemetry references this asset.</p>
      )}

      <h3 className="section-title">Findings &amp; Incidents</h3>
      {findings.kind === "loading" && <TableSkeleton rows={2} />}
      {findings.kind === "backend-error" && (
        <ErrorState title="Backend error" message={findings.message} />
      )}
      {findings.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message="Findings bundle outside the contract."
        />
      )}
      {findings.kind === "ready" && <FindingsBundleView view={findings.data} />}
      {findings.kind === "ready" &&
        findings.data.alerts.length === 0 &&
        findings.data.incidents.length === 0 && (
          <p className="page-sub">
            Nothing linked — absence of findings proves nothing about this
            asset.
          </p>
        )}
    </>
  );
}

// Lightweight local shapes: full telemetry/detection parsers live in
// contracts.ts; the detail view needs only these projections.
interface TelemetryLite {
  id: string;
  event_type: string;
  occurred_at: string;
}

function parseTelemetryLite(v: unknown): TelemetryLite {
  const o = v as Record<string, unknown>;
  if (
    typeof o["id"] !== "string" ||
    typeof o["event_type"] !== "string" ||
    typeof o["occurred_at"] !== "string"
  ) {
    throw new Error("telemetry lite shape mismatch");
  }
  return {
    id: o["id"] as string,
    event_type: o["event_type"] as string,
    occurred_at: o["occurred_at"] as string,
  };
}

function telemetryCount(s: { kind: string; data?: TelemetryLite[] }): number {
  return s.kind === "ready" && s.data ? s.data.length : 0;
}

interface FindingsBundle {
  alerts: { id: string; title: string }[];
  incidents: { id: string; title: string }[];
  detections: { id: string; title: string }[];
}

function FindingsBundleView({ view }: { view: FindingsBundle }) {
  return (
    <>
      {view.alerts.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 0 }}>
            Alerts ({view.alerts.length})
          </div>
          {view.alerts.map((a) => (
            <div key={a.id} className="link-row">
              <span className="mono">{a.id}</span>
              <span>{a.title}</span>
            </div>
          ))}
        </>
      )}
      {view.incidents.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 12 }}>
            Incidents ({view.incidents.length})
          </div>
          {view.incidents.map((i) => (
            <div key={i.id} className="link-row">
              <span className="mono">{i.id}</span>
              <span>{i.title}</span>
            </div>
          ))}
        </>
      )}
      {view.detections.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 12 }}>
            Detections ({view.detections.length})
          </div>
          {view.detections.map((d) => (
            <div key={d.id} className="link-row">
              <span className="mono">{d.id}</span>
              <span>{d.title}</span>
            </div>
          ))}
        </>
      )}
    </>
  );
}

function parseFindingsBundle(v: unknown): FindingsBundle {
  const o = v as Record<string, unknown>;
  const pick = (key: string) => {
    const arr = o[key];
    if (!Array.isArray(arr))
      throw new Error(`findings bundle .${key} must be an array`);
    return arr.map((item) => {
      const io = item as Record<string, unknown>;
      if (typeof io["id"] !== "string" || typeof io["title"] !== "string") {
        throw new Error(`findings bundle ${key} item shape mismatch`);
      }
      return { id: io["id"] as string, title: io["title"] as string };
    });
  };
  return {
    alerts: pick("alerts"),
    incidents: pick("incidents"),
    detections: pick("detections"),
  };
}

function parseRelationshipBundle(v: unknown): {
  parents: AssetRelationship[];
  children: AssetRelationship[];
} {
  const o = v as Record<string, unknown>;
  const conv = (key: string): AssetRelationship[] => {
    const arr = o[key];
    if (!Array.isArray(arr))
      throw new Error(`relationships .${key} must be an array`);
    return arr.map((item) => parseAssetRelationship(item));
  };
  return { parents: conv("parents"), children: conv("children") };
}

function RelationshipList({
  rels,
  names,
}: {
  rels: { parents: AssetRelationship[]; children: AssetRelationship[] };
  names: Map<string, string>;
}) {
  if (rels.parents.length === 0 && rels.children.length === 0) {
    return <p className="page-sub">No recorded relationships.</p>;
  }
  const label = (id: string) => names.get(id) ?? id;
  return (
    <>
      {rels.parents.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 0 }}>
            Contained by
          </div>
          {rels.parents.map((r) => (
            <div key={`${r.parent_id}>${r.child_id}`} className="link-row">
              <span className="mono">{label(r.parent_id)}</span>
              <span style={{ color: "var(--bv-muted)" }}>
                {r.kind} · {r.source}
              </span>
            </div>
          ))}
        </>
      )}
      {rels.children.length > 0 && (
        <>
          <div
            className="section-title"
            style={{ marginTop: rels.parents.length > 0 ? 12 : 0 }}
          >
            Contains
          </div>
          {rels.children.map((r) => (
            <div key={`${r.parent_id}>${r.child_id}`} className="link-row">
              <span className="mono">{label(r.child_id)}</span>
              <span style={{ color: "var(--bv-muted)" }}>
                {r.kind} · {r.source}
              </span>
            </div>
          ))}
        </>
      )}
    </>
  );
}
