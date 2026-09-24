import { useMemo, useState } from "react";
import {
  parseContinuousCheck,
  parsePostureHistoryEntry,
  parseSupplyComponent,
  parseSupplyDependency,
  parseSupplyLink,
  parseSupplyPolicy,
  parseSupplySBOM,
  parseVendor,
  parseVendorAssessment,
} from "../contracts";
import type {
  PostureHistoryEntry,
  SupplyComponent,
  SupplyDependency,
  SupplyLink,
  SupplyPolicy,
  SupplySBOM,
  Vendor,
  VendorAssessment,
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

type Tab =
  "components" | "sboms" | "policies" | "third-party" | "continuous" | "links";

function toneFor(v: string): "info" | "warn" | "bad" | "low" | "neutral" {
  if (v === "VERIFIED" || v === "REVIEWED" || v === "PASS") return "low";
  if (v === "POLICY_VIOLATION" || v === "FAIL") return "bad";
  if (v === "OUTDATED" || v === "UNSUPPORTED") return "warn";
  return "neutral";
}

const componentCols: Column<SupplyComponent>[] = [
  {
    key: "name",
    header: "Component",
    sortable: true,
    sortValue: (r) => r.name,
    render: (r) => <span className="mono">{r.name}</span>,
  },
  {
    key: "ecosystem",
    header: "Ecosystem",
    sortable: true,
    sortValue: (r) => r.ecosystem,
    render: (r) => r.ecosystem,
  },
  {
    key: "version",
    header: "Version",
    sortable: true,
    sortValue: (r) => r.version,
    render: (r) => <span className="mono">{r.version || "—"}</span>,
  },
  {
    key: "license",
    header: "License",
    sortable: true,
    sortValue: (r) => r.license,
    render: (r) => (r.license ? r.license : "—"),
  },
  {
    key: "provenance",
    header: "Provenance",
    sortable: true,
    sortValue: (r) => r.provenance,
    render: (r) => r.provenance,
  },
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status,
    render: (r) => <StatusBadge value={r.status} tone={toneFor(r.status)} />,
  },
];

const sbomCols: Column<SupplySBOM>[] = [
  {
    key: "id",
    header: "SBOM",
    sortable: true,
    sortValue: (r) => r.id,
    render: (r) => <span className="mono">{r.id}</span>,
  },
  {
    key: "format",
    header: "Format",
    sortable: true,
    sortValue: (r) => r.format,
    render: (r) => r.format,
  },
  {
    key: "component_ids",
    header: "Components",
    sortable: true,
    sortValue: (r) => String(r.component_ids.length),
    render: (r) => String(r.component_ids.length),
  },
  {
    key: "generated_at",
    header: "Generated",
    sortable: true,
    sortValue: (r) => r.generated_at,
    render: (r) => <span className="mono">{fmtTime(r.generated_at)}</span>,
  },
];

const policyCols: Column<SupplyPolicy>[] = [
  {
    key: "id",
    header: "Policy",
    sortable: true,
    sortValue: (r) => r.id,
    render: (r) => <span className="mono">{r.id}</span>,
  },
  {
    key: "name",
    header: "Name",
    sortable: true,
    sortValue: (r) => r.name,
    render: (r) => r.name,
  },
];

const vendorCols: Column<Vendor>[] = [
  {
    key: "name",
    header: "Vendor",
    sortable: true,
    sortValue: (r) => r.name,
    render: (r) => r.name,
  },
  {
    key: "service",
    header: "Service",
    sortable: true,
    sortValue: (r) => r.service,
    render: (r) => r.service,
  },
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status,
    render: (r) => <StatusBadge value={r.status} tone={toneFor(r.status)} />,
  },
];

const assessmentCols: Column<VendorAssessment>[] = [
  {
    key: "vendor_id",
    header: "Vendor",
    sortable: true,
    sortValue: (r) => r.vendor_id,
    render: (r) => <span className="mono">{r.vendor_id}</span>,
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

const linkCols: Column<SupplyLink>[] = [
  {
    key: "control_id",
    header: "Control",
    sortable: true,
    sortValue: (r) => r.control_id,
    render: (r) => <span className="mono">{r.control_id}</span>,
  },
  {
    key: "subject_kind",
    header: "Subject kind",
    sortable: true,
    sortValue: (r) => r.subject_kind,
    render: (r) => r.subject_kind,
  },
  {
    key: "subject_id",
    header: "Subject",
    sortable: true,
    sortValue: (r) => r.subject_id,
    render: (r) => <span className="mono">{r.subject_id}</span>,
  },
];

const COMPONENT_STATUSES = [
  "ALL",
  "OBSERVED",
  "VERIFIED",
  "OUTDATED",
  "UNSUPPORTED",
  "POLICY_VIOLATION",
  "NOT_ASSESSED",
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
  edges,
  onClose,
}: {
  row: { id?: string; [k: string]: unknown };
  edges: { children: SupplyDependency[]; parents: SupplyDependency[] } | null;
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
      {edges !== null && (
        <>
          <h3 className="detail-section">Depends on</h3>
          {edges.children.length === 0 ? (
            <p className="muted">No declared outgoing edges.</p>
          ) : (
            <ul>
              {edges.children.map((e) => (
                <li key={`${e.parent_id}>${e.child_id}>${e.kind}`}>
                  <span className="mono">{e.kind}</span>{" "}
                  <span className="mono">{e.child_id}</span>
                </li>
              ))}
            </ul>
          )}
          <h3 className="detail-section">Used by</h3>
          {edges.parents.length === 0 ? (
            <p className="muted">No declared incoming edges.</p>
          ) : (
            <ul>
              {edges.parents.map((e) => (
                <li key={`${e.parent_id}>${e.child_id}>${e.kind}`}>
                  <span className="mono">{e.kind}</span>{" "}
                  <span className="mono">{e.parent_id}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      <h3 className="detail-section">Provenance</h3>
      <p className="muted">
        Declared or observed metadata only. Licenses render as declared — never
        enriched. Absence of information is not a verdict.
      </p>
    </Drawer>
  );
}

export function SupplyChain() {
  const [tab, setTab] = useState<Tab>("components");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("ALL");
  const components = useApiList(
    "/api/v1/supply-chain/components",
    parseSupplyComponent,
  );
  const sboms = useApiList("/api/v1/supply-chain/sboms", parseSupplySBOM);
  const policies = useApiList(
    "/api/v1/supply-chain/policies",
    parseSupplyPolicy,
  );
  const vendors = useApiList("/api/v1/third-party/vendors", parseVendor);
  const assessments = useApiList(
    "/api/v1/third-party/assessments",
    parseVendorAssessment,
  );
  const links = useApiList("/api/v1/supply-chain/links", parseSupplyLink);
  const checks = useApiList(
    "/api/v1/continuous-security/checks",
    parseContinuousCheck,
  );
  const history = useApiList(
    "/api/v1/continuous-security/history",
    parsePostureHistoryEntry,
  );
  const [selected, setSelected] = useState<SupplyComponent | null>(null);
  const selectedId = selected?.id ?? null;
  const depChildren = useApiList(
    selectedId ? `/api/v1/supply-chain/dependencies?parent=${selectedId}` : "",
    parseSupplyDependency,
  );
  const depParents = useApiList(
    selectedId ? `/api/v1/supply-chain/dependencies?child=${selectedId}` : "",
    parseSupplyDependency,
  );

  const componentRows = useMemo(() => {
    const list = listOf(components);
    if (!list) return null;
    let out = list;
    if (status !== "ALL") out = out.filter((r) => r.status === status);
    if (q.trim()) {
      const needle = q.toLowerCase();
      out = out.filter((r) =>
        `${r.name} ${r.ecosystem} ${r.version} ${r.license}`
          .toLowerCase()
          .includes(needle),
      );
    }
    return out;
  }, [components, status, q]);

  const edges = useMemo(() => {
    if (selectedId === null) return null;
    const kids = listOf(depChildren);
    const pars = listOf(depParents);
    if (kids === null || pars === null) return null;
    return { children: kids, parents: pars };
  }, [selectedId, depChildren, depParents]);

  const loading =
    tab === "components"
      ? components.kind === "loading"
      : tab === "sboms"
        ? sboms.kind === "loading"
        : tab === "policies"
          ? policies.kind === "loading"
          : tab === "third-party"
            ? vendors.kind === "loading" || assessments.kind === "loading"
            : tab === "continuous"
              ? checks.kind === "loading" || history.kind === "loading"
              : links.kind === "loading";

  return (
    <div className="view">
      <h1 className="page-title">Supply Chain</h1>
      <p className="page-sub">
        Components, SBOM records, policies, third parties, continuous checks,
        and control links. Declared metadata only — nothing here installs,
        grades, or certifies.
      </p>
      {(() => {
        const list = listOf(components);
        const pols = listOf(policies);
        if (!list || !pols) return null;
        const viol = list.filter((c) => c.status === "POLICY_VIOLATION").length;
        const old = list.filter(
          (c) => c.status === "OUTDATED" || c.status === "UNSUPPORTED",
        ).length;
        return (
          <SummaryStrip
            statement={
              old === 0
                ? "No outdated or unsupported components right now."
                : `${old} outdated or unsupported component${old === 1 ? "" : "s"} raise supply-chain risk.`
            }
            stats={[
              { label: "Components", value: String(list.length) },
              { label: "In violation", value: String(viol) },
              { label: "Policies", value: String(pols.length) },
            ]}
          />
        );
      })()}
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {(
          [
            ["components", "Components"],
            ["sboms", "SBOMs"],
            ["policies", "Policies"],
            ["third-party", "Third Party"],
            ["continuous", "Continuous"],
            ["links", "Links"],
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

      {tab === "components" && (
        <FilterBar
          search={q}
          onSearch={setQ}
          searchLabel="Search components"
          searchPlaceholder="name, ecosystem, license…"
          selects={[
            {
              label: "Status",
              value: status,
              options: COMPONENT_STATUSES.map((v) => ({
                value: v,
                label: v,
              })),
              onChange: setStatus,
            },
          ]}
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

      {!loading && tab === "components" && (
        <ComponentsBody
          rows={componentRows}
          state={components}
          onSelect={setSelected}
        />
      )}
      {!loading && tab === "sboms" && <SBOMsBody state={sboms} />}
      {!loading && tab === "policies" && <PoliciesBody state={policies} />}
      {!loading && tab === "third-party" && (
        <ThirdPartyBody vendors={vendors} assessments={assessments} />
      )}
      {!loading && tab === "continuous" && (
        <ContinuousBody checks={checks} history={history} />
      )}
      {!loading && tab === "links" && <LinksBody state={links} />}

      {selected !== null && (
        <Detail
          row={selected as never}
          edges={edges}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

function ComponentsBody({
  rows,
  state,
  onSelect,
}: {
  rows: SupplyComponent[] | null;
  state: ReturnType<typeof useApiList<SupplyComponent>>;
  onSelect: (r: SupplyComponent) => void;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="supply-chain"
          title="No components"
          description="Components appear here from explicit declarations or the supply-chain lab."
        />
      </div>
    );
  return (
    <DataTable
      columns={componentCols}
      rows={rows}
      onRowClick={onSelect}
      rowLabel={(r) => `Component ${r.name}`}
      empty="No components"
    />
  );
}

function SBOMsBody({
  state,
}: {
  state: ReturnType<typeof useApiList<SupplySBOM>>;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  const rows = listOf(state);
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="supply-chain"
          title="No SBOM records"
          description="SBOM metadata records appear here when declared."
        />
      </div>
    );
  return (
    <DataTable
      columns={sbomCols}
      rows={rows}
      rowLabel={(r) => `SBOM ${r.id}`}
      empty="No SBOM records"
    />
  );
}

function PoliciesBody({
  state,
}: {
  state: ReturnType<typeof useApiList<SupplyPolicy>>;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  const rows = listOf(state);
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="supply-chain"
          title="No policies"
          description="Declarative supply-chain policies appear here."
        />
      </div>
    );
  return (
    <>
      <DataTable
        columns={policyCols}
        rows={rows}
        rowLabel={(r) => `Policy ${r.id}`}
        empty="No policies"
      />
      <p className="muted">
        Policies are data, never code: evaluation only compares declared
        metadata.
      </p>
    </>
  );
}

function ThirdPartyBody({
  vendors,
  assessments,
}: {
  vendors: ReturnType<typeof useApiList<Vendor>>;
  assessments: ReturnType<typeof useApiList<VendorAssessment>>;
}) {
  if (
    vendors.kind === "backend-error" ||
    vendors.kind === "invalid" ||
    assessments.kind === "backend-error" ||
    assessments.kind === "invalid"
  )
    return (
      <ErrorState
        title="Backend error"
        message="Could not load third parties."
      />
    );
  const vendorRows = listOf(vendors);
  const assessmentRows = listOf(assessments);
  if (
    (!vendorRows || vendorRows.length === 0) &&
    (!assessmentRows || assessmentRows.length === 0)
  )
    return (
      <div className="panel">
        <EmptyState
          icon="supply-chain"
          title="No third parties"
          description="Declared vendors and their assessments appear here."
        />
      </div>
    );
  return (
    <>
      <h3>Vendors</h3>
      {vendorRows && vendorRows.length > 0 ? (
        <DataTable
          columns={vendorCols}
          rows={vendorRows}
          rowLabel={(r) => `Vendor ${r.name}`}
          empty="No vendors"
        />
      ) : (
        <p className="muted">No vendors.</p>
      )}
      <h3>Assessments</h3>
      {assessmentRows && assessmentRows.length > 0 ? (
        <DataTable
          columns={assessmentCols}
          rows={assessmentRows}
          rowLabel={(r) => `Assessment ${r.id}`}
          empty="No assessments"
        />
      ) : (
        <p className="muted">No assessments.</p>
      )}
      <p className="muted">
        Assessments record what was reviewed — never a certification of the
        vendor.
      </p>
    </>
  );
}

type CheckRow = ReturnType<typeof parseContinuousCheck> & { id: string };

const checkCols: Column<CheckRow>[] = [
  {
    key: "rule_id",
    header: "Check",
    sortable: true,
    sortValue: (r) => r.rule_id,
    render: (r) => <span className="mono">{r.rule_id}</span>,
  },
  {
    key: "subject_id",
    header: "Subject",
    sortable: true,
    sortValue: (r) => r.subject_id,
    render: (r) => <span className="mono">{r.subject_id}</span>,
  },
  {
    key: "outcome",
    header: "Outcome",
    sortable: true,
    sortValue: (r) => r.outcome,
    render: (r) => <StatusBadge value={r.outcome} tone={toneFor(r.outcome)} />,
  },
  {
    key: "basis",
    header: "Basis",
    sortable: false,
    render: (r) => r.basis,
  },
];

function ContinuousBody({
  checks,
  history,
}: {
  checks: ReturnType<
    typeof useApiList<ReturnType<typeof parseContinuousCheck>>
  >;
  history: ReturnType<typeof useApiList<PostureHistoryEntry>>;
}) {
  if (
    checks.kind === "backend-error" ||
    checks.kind === "invalid" ||
    history.kind === "backend-error" ||
    history.kind === "invalid"
  )
    return (
      <ErrorState title="Backend error" message="Could not load checks." />
    );
  const rawChecks = listOf(checks);
  const historyRows = listOf(history);
  const checkRows: CheckRow[] | null =
    rawChecks === null
      ? null
      : rawChecks.map((r) => ({ ...r, id: `${r.rule_id}>${r.subject_id}` }));
  return (
    <>
      <h3>Checks</h3>
      {checkRows && checkRows.length > 0 ? (
        <DataTable
          columns={checkCols}
          rows={checkRows}
          rowLabel={(r) => `Check ${r.rule_id}`}
          empty="No checks"
        />
      ) : (
        <p className="muted">No checks.</p>
      )}
      <h3>History</h3>
      {historyRows && historyRows.length > 0 ? (
        <DataTable
          columns={[
            {
              key: "occurred_at",
              header: "When",
              sortable: true,
              sortValue: (r: PostureHistoryEntry) => r.occurred_at,
              render: (r: PostureHistoryEntry) => (
                <span className="mono">{fmtTime(r.occurred_at)}</span>
              ),
            },
            {
              key: "kind",
              header: "Kind",
              sortable: true,
              sortValue: (r: PostureHistoryEntry) => r.kind,
              render: (r: PostureHistoryEntry) => r.kind,
            },
            {
              key: "summary",
              header: "Summary",
              sortable: false,
              render: (r: PostureHistoryEntry) => r.summary,
            },
          ]}
          rows={historyRows}
          rowLabel={(r: PostureHistoryEntry) => `History ${r.id}`}
          empty="No history"
        />
      ) : (
        <p className="muted">No history.</p>
      )}
      <p className="muted">
        Outcomes are observations with basis — never verdicts, never scores.
      </p>
    </>
  );
}

function LinksBody({
  state,
}: {
  state: ReturnType<typeof useApiList<SupplyLink>>;
}) {
  if (state.kind === "backend-error" || state.kind === "invalid")
    return <ErrorState title="Backend error" message={state.message} />;
  const rows = listOf(state);
  if (!rows || rows.length === 0)
    return (
      <div className="panel">
        <EmptyState
          icon="supply-chain"
          title="No links"
          description="Explicit control-to-subject citations appear here."
        />
      </div>
    );
  return (
    <DataTable
      columns={linkCols}
      rows={rows}
      rowLabel={(r) => `Link ${r.id}`}
      empty="No links"
    />
  );
}
