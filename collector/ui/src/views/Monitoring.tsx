import { useEffect, useMemo, useState } from "react";
import {
  parseDetectionRuleMeta,
  parseIOCMatchRow,
  parseIOCEntry,
  parseMonitoringCorrelation,
  parseMonitoringEvent,
  parseRuleHealthRow,
} from "../contracts";
import type {
  DetectionRuleMeta,
  IOCEntry,
  IOCMatchRow,
  MonitoringCorrelation,
  MonitoringEvent,
  RuleHealthRow,
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
import { ApiError, apiFetch } from "../api";
import { fmtTime, listOf, useApiList } from "./hooks";

type Tab = "events" | "correlations" | "rules" | "health" | "threatintel";

type Envelope<T> =
  | { kind: "loading" }
  | { kind: "ready"; status?: string; rows: T[] }
  | { kind: "empty" }
  | { kind: "backend-error"; message: string }
  | { kind: "invalid"; message: string };

// useEnvelope fetches {status?, data[]} shapes where rows may be empty
// while status stays meaningful (e.g. honest "unavailable").
function useEnvelope<T>(
  path: string | null,
  parse: (v: unknown) => T,
): Envelope<T> {
  const [state, setState] = useState<Envelope<T>>({ kind: "loading" });
  useEffect(() => {
    if (!path) {
      setState({ kind: "empty" });
      return;
    }
    let cancelled = false;
    setState({ kind: "loading" });
    (async () => {
      try {
        const res = await apiFetch(path);
        let body: unknown;
        try {
          body = await res.json();
        } catch {
          throw new ApiError(
            "INVALID",
            `non-JSON response from ${path}`,
            res.status,
          );
        }
        if (!res.ok) {
          const err = (body as { error?: { code?: string; message?: string } })
            .error;
          throw new ApiError(
            err?.code ?? "BACKEND",
            err?.message ?? `request failed: ${path}`,
            res.status,
          );
        }
        const obj = body as { data?: unknown; status?: unknown };
        if (!Array.isArray(obj?.data))
          throw new ApiError("INVALID", `bad envelope from ${path}`, 200);
        const rows = obj.data.map((item, i) => {
          try {
            return parse(item);
          } catch (e) {
            throw new ApiError(
              "INVALID",
              `item ${i} from ${path}: ${(e as Error).message}`,
              200,
            );
          }
        });
        if (!cancelled)
          setState({
            kind: "ready",
            status: typeof obj.status === "string" ? obj.status : undefined,
            rows,
          });
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError) {
          if (e.code === "INVALID")
            setState({ kind: "invalid", message: e.message });
          else setState({ kind: "backend-error", message: e.message });
        } else {
          setState({ kind: "backend-error", message: String(e) });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [path, parse]);
  return state;
}

const eventCols: Column<MonitoringEvent>[] = [
  {
    key: "occurred_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "source",
    header: "Source",
    sortable: true,
    sortValue: (r) => r.source,
    render: (r) => r.source,
  },
  {
    key: "event_type",
    header: "Event Type",
    sortable: true,
    sortValue: (r) => r.event_type,
    render: (r) => <span className="mono">{r.event_type}</span>,
  },
  {
    key: "asset_id",
    header: "Asset",
    sortable: true,
    sortValue: (r) => r.asset_id,
    render: (r) => <span className="mono">{r.asset_id}</span>,
  },
  {
    key: "severity",
    header: "Severity",
    sortable: true,
    sortValue: (r) => r.severity,
    render: (r) => r.severity.replace("SEVERITY_", ""),
  },
  {
    key: "id",
    header: "Event ID",
    sortable: true,
    sortValue: (r) => r.id,
    render: (r) => <span className="mono">{r.id}</span>,
  },
];

const corrCols: Column<MonitoringCorrelation>[] = [
  {
    key: "observed_at",
    header: "Time",
    sortable: true,
    sortValue: (r) => r.observed_at,
    render: (r) => <span className="mono">{fmtTime(r.observed_at)}</span>,
  },
  {
    key: "type",
    header: "Type",
    sortable: true,
    sortValue: (r) => r.type,
    render: (r) => <span className="mono">{r.type}</span>,
  },
  {
    key: "principal",
    header: "Asset/Principal",
    sortable: true,
    sortValue: (r) => r.principal || r.asset_id,
    render: (r) => r.principal || r.asset_id || "—",
  },
  {
    key: "event_ids",
    header: "Events",
    sortable: true,
    sortValue: (r) => String(r.event_ids.length),
    render: (r) => String(r.event_ids.length),
  },
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status,
    render: (r) => <StatusBadge value={r.status} tone="neutral" />,
  },
];

const ruleCols: Column<DetectionRuleMeta>[] = [
  {
    key: "id",
    header: "Rule",
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
    key: "severity_basis",
    header: "Severity",
    sortable: true,
    sortValue: (r) => r.severity_basis,
    render: (r) => r.severity_basis,
  },
  {
    key: "stateful",
    header: "State",
    sortable: true,
    sortValue: (r) => (r.stateful ? "stateful" : "stateless"),
    render: (r) => (r.stateful ? "stateful" : "stateless"),
  },
  {
    key: "enabled",
    header: "Enabled",
    sortable: true,
    sortValue: (r) => (r.enabled ? "1" : "0"),
    render: (r) => (r.enabled ? "yes" : "no"),
  },
];

type HealthTableRow = RuleHealthRow & { id: string };

const healthCols: Column<HealthTableRow>[] = [
  {
    key: "rule_id",
    header: "Rule",
    sortable: true,
    sortValue: (r) => r.rule_id,
    render: (r) => <span className="mono">{r.rule_id}</span>,
  },
  {
    key: "enabled",
    header: "Enabled",
    sortable: true,
    sortValue: (r) => (r.enabled ? "1" : "0"),
    render: (r) => (r.enabled ? "yes" : "no"),
  },
  {
    key: "evaluated",
    header: "Evaluations",
    sortable: true,
    sortValue: (r) => r.evaluated,
    render: (r) => String(r.evaluated),
  },
  {
    key: "detections",
    header: "Detections",
    sortable: true,
    sortValue: (r) => r.detections,
    render: (r) => String(r.detections),
  },
  {
    key: "errors",
    header: "Errors",
    sortable: true,
    sortValue: (r) => r.errors,
    render: (r) => String(r.errors),
  },
];

const matchCols: Column<IOCMatchRow>[] = [
  {
    key: "occurred_at",
    header: "Observed",
    sortable: true,
    sortValue: (r) => r.occurred_at,
    render: (r) => <span className="mono">{fmtTime(r.occurred_at)}</span>,
  },
  {
    key: "kind",
    header: "IOC Type",
    sortable: true,
    sortValue: (r) => r.kind,
    render: (r) => r.kind,
  },
  {
    key: "indicator",
    header: "Match",
    sortable: true,
    sortValue: (r) => r.indicator,
    render: (r) => <span className="mono">{r.indicator}</span>,
  },
  {
    key: "matched_field",
    header: "Field",
    sortable: true,
    sortValue: (r) => r.matched_field,
    render: (r) => <span className="mono">{r.matched_field}</span>,
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

function Detail({
  row,
  onClose,
}: {
  row: { id: string; [k: string]: unknown };
  onClose: () => void;
}) {
  const groups = groupDetailFields(Object.entries(row));
  return (
    <Drawer title={row.id as string} onClose={onClose}>
      <div className="field-grid">
        {groups.ungrouped.map(([k, v]) => (
          <Field key={k} label={k}>
            {Array.isArray(v) ? v.join(", ") : String(v ?? "—")}
          </Field>
        ))}
        {groups.identity.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Identity</h4>
            {groups.identity.map(([k, v]) => (
              <Field key={k} label={k}>
                {Array.isArray(v) ? v.join(", ") : String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
        {groups.risk.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">Risk</h4>
            {groups.risk.map(([k, v]) => (
              <Field key={k} label={k}>
                {Array.isArray(v) ? v.join(", ") : String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
        {groups.history.length > 0 && (
          <div className="field-group">
            <h4 className="group-head">History</h4>
            {groups.history.map(([k, v]) => (
              <Field key={k} label={k}>
                {Array.isArray(v) ? v.join(", ") : String(v ?? "—")}
              </Field>
            ))}
          </div>
        )}
      </div>
      <h3 className="detail-section">Provenance</h3>
      <p className="muted">
        Observed linkage from persisted telemetry. A correlation or match
        describes what was seen together — never a verdict about intent.
      </p>
    </Drawer>
  );
}

const EVENT_TYPES = [
  "ALL",
  "auth.activity",
  "identity.activity",
  "data.activity",
  "net.connection",
  "http.request",
  "endpoint.activity",
  "server.activity",
  "container.activity",
  "cloud.activity",
  "waf.request_blocked",
];

export function Monitoring() {
  const [tab, setTab] = useState<Tab>("events");
  const [q, setQ] = useState("");
  const [eventType, setEventType] = useState("ALL");
  const events = useApiList("/api/v1/monitoring/events", parseMonitoringEvent);
  const correlations = useApiList(
    "/api/v1/monitoring/correlations",
    parseMonitoringCorrelation,
  );
  const rules = useApiList("/api/v1/detection-rules", parseDetectionRuleMeta);
  const health = useEnvelope(
    "/api/v1/detection-rules/health",
    parseRuleHealthRow,
  );
  const iocs = useEnvelope("/api/v1/threat-intelligence/iocs", parseIOCEntry);
  const matches = useEnvelope(
    "/api/v1/threat-intelligence/matches",
    parseIOCMatchRow,
  );
  const [selected, setSelected] = useState<unknown | null>(null);

  const eventRows = useMemo(() => {
    const list = listOf(events);
    if (!list) return null;
    let out = list;
    if (eventType !== "ALL")
      out = out.filter((r) => r.event_type === eventType);
    if (q.trim()) {
      const needle = q.toLowerCase();
      out = out.filter((r) =>
        `${r.id} ${r.source} ${r.asset_id} ${r.event_type}`
          .toLowerCase()
          .includes(needle),
      );
    }
    return out;
  }, [events, eventType, q]);

  const corrRows = useMemo(() => {
    const list = listOf(correlations);
    if (!list) return null;
    if (!q.trim()) return list;
    const needle = q.toLowerCase();
    return list.filter((r) =>
      `${r.id} ${r.type} ${r.principal} ${r.asset_id}`
        .toLowerCase()
        .includes(needle),
    );
  }, [correlations, q]);

  const matchRows = useMemo(() => {
    if (matches.kind !== "ready") return null;
    if (!q.trim()) return matches.rows;
    const needle = q.toLowerCase();
    return matches.rows.filter((r) =>
      `${r.indicator} ${r.kind} ${r.event_id}`.toLowerCase().includes(needle),
    );
  }, [matches, q]);

  const loading =
    tab === "events"
      ? events.kind === "loading"
      : tab === "correlations"
        ? correlations.kind === "loading"
        : tab === "rules"
          ? rules.kind === "loading"
          : tab === "health"
            ? health.kind === "loading"
            : matches.kind === "loading" || iocs.kind === "loading";

  return (
    <div className="view">
      <h1 className="page-title">Monitoring</h1>
      <p className="page-sub">
        Security event search, explicit correlations, rule engineering, and
        offline threat-intel observations. Descriptive, never verdicts.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {(
          [
            ["events", "Events"],
            ["correlations", "Correlations"],
            ["rules", "Rules"],
            ["health", "Health"],
            ["threatintel", "Threat Intel"],
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

      {(tab === "events" ||
        tab === "correlations" ||
        tab === "threatintel") && (
        <FilterBar
          search={q}
          onSearch={setQ}
          searchLabel={
            tab === "events"
              ? "Search events"
              : tab === "correlations"
                ? "Search correlations"
                : "Search matches"
          }
          searchPlaceholder="id, source, asset…"
          selects={
            tab === "events"
              ? [
                  {
                    label: "Event type",
                    value: eventType,
                    options: EVENT_TYPES.map((v) => ({ value: v, label: v })),
                    onChange: setEventType,
                  },
                ]
              : []
          }
          onClear={() => {
            setQ("");
            setEventType("ALL");
          }}
          hasActive={q !== "" || eventType !== "ALL"}
        />
      )}

      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={5} />
        </>
      )}

      {!loading && tab === "events" && (
        <>
          {(() => {
            const evts = listOf(events);
            const rls = listOf(rules);
            if (!evts || evts.length === 0 || !rls) return null;
            if (matches.kind !== "ready") return null;
            return (
              <SummaryStrip
                statement="Threat-intel matches deserve a look first; rules are only as good as their health."
                stats={[
                  { label: "Events", value: String(evts.length) },
                  { label: "Rules", value: String(rls.length) },
                  { label: "TI matches", value: String(matches.rows.length) },
                ]}
              />
            );
          })()}
          <EventsBody rows={eventRows} state={events} onSelect={setSelected} />
        </>
      )}
      {!loading && tab === "correlations" && (
        <CorrelationsBody
          rows={corrRows}
          state={correlations}
          onSelect={setSelected}
        />
      )}
      {!loading && tab === "rules" && <RulesBody state={rules} />}
      {!loading && tab === "health" && <HealthBody state={health} />}
      {!loading && tab === "threatintel" && (
        <ThreatIntelBody
          iocs={iocs}
          matches={matches}
          rows={matchRows}
          onSelect={setSelected}
        />
      )}

      {selected !== null && (
        <Detail row={selected as never} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function EventsBody({
  rows,
  state,
  onSelect,
}: {
  rows: MonitoringEvent[] | null;
  state: ReturnType<typeof useApiList<MonitoringEvent>>;
  onSelect: (r: unknown) => void;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return (
      <ErrorState
        title={state.kind === "invalid" ? "Invalid data" : "Backend error"}
        message={
          state.kind === "invalid"
            ? `The backend returned data outside the contract: ${state.message}`
            : state.message
        }
      />
    );
  if (!rows)
    return (
      <ErrorState title="Backend error" message="Could not load events." />
    );
  if (rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="monitoring"
          title="No monitoring events"
          description="Persisted telemetry will appear here once the collector ingests observations."
        />
      </div>
    );
  return (
    <DataTable
      columns={eventCols}
      rows={rows}
      onRowClick={onSelect}
      rowLabel={(r) => `Open ${r.id}`}
      empty="No events"
    />
  );
}

function CorrelationsBody({
  rows,
  state,
  onSelect,
}: {
  rows: MonitoringCorrelation[] | null;
  state: ReturnType<typeof useApiList<MonitoringCorrelation>>;
  onSelect: (r: unknown) => void;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return (
      <ErrorState
        title={state.kind === "invalid" ? "Invalid data" : "Backend error"}
        message={
          state.kind === "invalid"
            ? `The backend returned data outside the contract: ${state.message}`
            : state.message
        }
      />
    );
  if (!rows)
    return (
      <ErrorState
        title="Backend error"
        message="Could not load correlations."
      />
    );
  if (rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="monitoring"
          title="No correlations"
          description="Explicitly linked activity will appear here once observed together."
        />
      </div>
    );
  return (
    <DataTable
      columns={corrCols}
      rows={rows}
      onRowClick={onSelect}
      rowLabel={(r) => `Open ${r.id}`}
      empty="No correlations"
    />
  );
}

function RulesBody({
  state,
}: {
  state: ReturnType<typeof useApiList<DetectionRuleMeta>>;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  const rows = listOf(state);
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="monitoring"
          title="No detection rules"
          description="The rule catalogue is empty."
        />
      </div>
    );
  return (
    <DataTable
      columns={ruleCols}
      rows={rows}
      rowLabel={(r) => `Open ${r.id}`}
      empty="No rules"
    />
  );
}

function HealthBody({ state }: { state: Envelope<RuleHealthRow> }) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  if (state.kind !== "ready") return null;
  if (state.status === "unavailable")
    return (
      <div className="panel">
        <EmptyState
          icon="monitoring"
          title="Rule health not available"
          description="Live engine counters exist only in the collecting process. This read-only view reports their absence instead of inventing metrics."
        />
      </div>
    );
  if (state.rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="monitoring"
          title="No rule health rows"
          description="No evaluations have been recorded."
        />
      </div>
    );
  const rows: HealthTableRow[] = state.rows.map((r) => ({
    ...r,
    id: r.rule_id,
  }));
  return (
    <DataTable
      columns={healthCols}
      rows={rows}
      rowLabel={(r) => `Open ${r.rule_id}`}
      empty="No health rows"
    />
  );
}

function ThreatIntelBody({
  iocs,
  matches,
  rows,
  onSelect,
}: {
  iocs: Envelope<IOCEntry>;
  matches: Envelope<IOCMatchRow>;
  rows: IOCMatchRow[] | null;
  onSelect: (r: unknown) => void;
}) {
  if (matches.kind === "backend-error" || matches.kind === "invalid")
    return (
      <ErrorState
        title={matches.kind === "invalid" ? "Invalid data" : "Backend error"}
        message={matches.message}
      />
    );
  if (matches.kind !== "ready" || iocs.kind !== "ready") return null;
  if (matches.status === "unavailable" || iocs.status === "unavailable")
    return (
      <div className="panel">
        <EmptyState
          icon="monitoring"
          title="Threat intelligence not configured"
          description="No offline IOC set is configured (serve --ioc-set). Nothing is matched and nothing is claimed."
        />
      </div>
    );
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="monitoring"
          title="No IOC matches"
          description="Configured-indicator observations will appear here when telemetry exactly holds a listed value."
        />
      </div>
    );
  return (
    <>
      <p className="muted">
        Configured IOC matches observed — an observation of a listed string,
        never a verdict.
      </p>
      <DataTable
        columns={matchCols}
        rows={rows}
        onRowClick={onSelect}
        rowLabel={(r) => `Open ${r.id}`}
        empty="No matches"
      />
    </>
  );
}

export type { IOCEntry };
