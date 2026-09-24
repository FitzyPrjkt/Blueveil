import { useMemo, useState } from "react";
import {
  parseAsset,
  parseAssetRelationship,
  parseNetworkObservation,
} from "../contracts";
import type { NetworkObservation } from "../contracts";
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

const COLUMNS: Column<NetworkObservation>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "src_ip",
    header: "Source",
    sortable: true,
    sortValue: (r) => r.src_ip,
    render: (r) => (
      <span className="mono">
        {r.src_ip}
        {r.src_port !== undefined ? `:${r.src_port}` : ""}
      </span>
    ),
  },
  {
    key: "dst_ip",
    header: "Destination",
    sortable: true,
    sortValue: (r) => r.dst_ip,
    render: (r) => (
      <span className="mono">
        {r.dst_ip}
        {r.dst_port !== undefined ? `:${r.dst_port}` : ""}
      </span>
    ),
  },
  {
    key: "protocol",
    header: "Protocol",
    sortable: true,
    sortValue: (r) => r.protocol ?? "",
    render: (r) => r.protocol ?? "—",
  },
  {
    key: "verdict",
    header: "Verdict",
    sortable: true,
    sortValue: (r) => r.verdict ?? "",
    render: (r) => {
      if (!r.verdict) return "—";
      const tone = r.verdict === "denied" ? "bad" : "neutral";
      return (
        <StatusBadge value={r.verdict.toUpperCase()} tone={tone as never} />
      );
    },
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

function NetworkDetail({
  row,
  onClose,
}: {
  row: NetworkObservation;
  onClose: () => void;
}) {
  const assets = useApiList("/api/v1/assets", parseAsset);
  const rels = useApiList(
    "/api/v1/network/relationships",
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
        <Field label="Protocol">{row.protocol ?? "—"}</Field>
        <Field label="Direction">{row.direction ?? "—"}</Field>
        <div className="field-group">
          <h4 className="group-head">Identity</h4>
          <Field label="Source">
            {row.src_ip}
            {row.src_port !== undefined ? `:${row.src_port}` : ""} →{" "}
            {row.dst_ip}
            {row.dst_port !== undefined ? `:${row.dst_port}` : ""}
          </Field>
          <Field label="Source sensor">{row.source}</Field>
        </div>
        <div className="field-group">
          <h4 className="group-head">Risk</h4>
          <Field label="Verdict">{row.verdict ?? "—"}</Field>
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

      <h3 className="detail-section">Asset correlation</h3>
      {assets.kind === "loading" ? (
        <HeadingSkeleton />
      ) : (
        <div className="field-grid">
          <Field label="Source asset">
            {assetMap.get(row.src_ip) ? (
              <span className="mono">
                {row.src_ip} → {assetMap.get(row.src_ip)}
              </span>
            ) : (
              <span className="muted">
                No asset observed for {row.src_ip} — telemetry preserved without
                linkage.
              </span>
            )}
          </Field>
          <Field label="Destination asset">
            {assetMap.get(row.dst_ip) ? (
              <span className="mono">
                {row.dst_ip} → {assetMap.get(row.dst_ip)}
              </span>
            ) : (
              <span className="muted">
                No asset observed for {row.dst_ip} — external or unobserved.
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
          policy/threshold recorded in detection attributes, evidence preserved.
        </p>
      ) : (
        <p className="muted">
          No detection. Observation, not an alert — most network telemetry is
          not a finding.
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
                No COMMUNICATES_WITH edges recorded for this source.
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

export function Network() {
  const obs = useApiList(
    "/api/v1/network/observations",
    parseNetworkObservation,
  );
  const [q, setQ] = useState("");
  const [protocol, setProtocol] = useState("ALL");
  const [verdict, setVerdict] = useState("ALL");
  const [detectedOnly, setDetectedOnly] = useState(false);
  const [selected, setSelected] = useState<NetworkObservation | null>(null);

  const rows = useMemo(() => {
    const list = listOf(obs);
    if (!list) return null;
    let out = list;
    if (q.trim()) {
      const needle = q.toLowerCase();
      out = out.filter((r) =>
        `${r.src_ip} ${r.dst_ip} ${r.id}`.toLowerCase().includes(needle),
      );
    }
    if (protocol !== "ALL")
      out = out.filter((r) => (r.protocol ?? "") === protocol);
    if (verdict !== "ALL")
      out = out.filter((r) => (r.verdict ?? "") === verdict);
    if (detectedOnly) out = out.filter((r) => r.detected);
    return out;
  }, [obs, q, protocol, verdict, detectedOnly]);

  const loading = obs.kind === "loading";
  const backendError = obs.kind === "backend-error" ? obs.message : null;
  const invalid = obs.kind === "invalid" ? obs.message : null;
  const total = listOf(obs)?.length ?? 0;

  const clearFilters = () => {
    setQ("");
    setProtocol("ALL");
    setVerdict("ALL");
    setDetectedOnly(false);
  };

  return (
    <div className="view">
      <h1 className="page-title">Network</h1>
      <p className="page-sub">
        Observed connections — deterministic detection only when policy or
        thresholds fire. Most rows are not findings.
      </p>

      <FilterBar
        search={q}
        onSearch={setQ}
        searchLabel="Search network"
        searchPlaceholder="source or destination IP…"
        selects={[
          {
            label: "Protocol",
            value: protocol,
            options: ["ALL", "TCP", "UDP", "ICMP", "ICMPV6", "SCTP"].map(
              (v) => ({ value: v, label: v }),
            ),
            onChange: setProtocol,
          },
          {
            label: "Verdict",
            value: verdict,
            options: ["ALL", "allowed", "denied"].map((v) => ({
              value: v,
              label: v,
            })),
            onChange: setVerdict,
          },
        ]}
        onClear={clearFilters}
        hasActive={
          q !== "" || protocol !== "ALL" || verdict !== "ALL" || detectedOnly
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
            icon="network"
            title="No network observations"
            description="Network telemetry will appear here when observations are ingested."
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
              icon="network"
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
                statement="Most rows are telemetry, not findings — denied and detected rows deserve a look."
                stats={[
                  { label: "Observations", value: String(all.length) },
                  {
                    label: "Denied",
                    value: String(
                      all.filter((r) => r.verdict === "denied").length,
                    ),
                  },
                  {
                    label: "Detected",
                    value: String(all.filter((r) => r.detected).length),
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
        <NetworkDetail row={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
