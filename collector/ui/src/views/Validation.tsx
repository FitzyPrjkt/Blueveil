import { useMemo, useState } from "react";
import {
  VERDICTS,
  VERDICT_MEANINGS,
  parsePurpleTeamExercise,
  parseValidationCampaign,
  parseValidationResult,
} from "../contracts";
import type {
  PurpleTeamExercise,
  ValidationCampaign,
  ValidationResult,
} from "../contracts";
import { DataTable, type Column } from "../components/DataTable";
import { Drawer } from "../components/Drawer";
import { FilterBar } from "../components/FilterBar";
import { SummaryStrip } from "../components/SummaryStrip";
import {
  StatusBadge,
  exerciseTone,
  verdictTone,
} from "../components/StatusBadge";
import {
  EmptyState,
  ErrorState,
  Field,
  HeadingSkeleton,
  TableSkeleton,
} from "../components/States";
import { fmtTime, listOf, useApiList } from "./hooks";

const COLUMNS: Column<ValidationResult>[] = [
  {
    key: "verdict",
    header: "Verdict",
    sortable: true,
    sortValue: (r) => r.verdict,
    render: (r) => (
      <StatusBadge value={r.verdict} tone={verdictTone(r.verdict)} />
    ),
  },
  {
    key: "control_id",
    header: "Control",
    sortable: true,
    sortValue: (r) => r.control_id,
    render: (r) => <span className="mono">{r.control_id}</span>,
  },
  {
    key: "provider",
    header: "Provider",
    sortable: true,
    sortValue: (r) => r.provider,
    render: (r) => <span className="mono">{r.provider}</span>,
  },
  {
    // Backend ValidationResult carries no target (it lives on the
    // request/campaign): label the column for what it shows.
    key: "request_id",
    header: "Request",
    sortable: true,
    sortValue: (r) => r.request_id,
    render: (r) => <span className="mono">{r.request_id}</span>,
  },
  {
    key: "validated_at",
    header: "Validated",
    sortable: true,
    sortValue: (r) => r.validated_at,
    render: (r) => <span className="tabular">{fmtTime(r.validated_at)}</span>,
  },
];

type ValidationTab = "results" | "campaigns" | "history" | "purple";

export function Validation() {
  const [tab, setTab] = useState<ValidationTab>("results");
  return (
    <>
      <h1 className="page-title">Validation</h1>
      <p className="page-sub">
        Control validation outcomes, verbatim. Absence of findings never implies
        success.
      </p>
      <div
        role="tablist"
        aria-label="Validation sections"
        style={{ display: "flex", gap: 8, marginBottom: 12 }}
      >
        {(
          [
            ["results", "Results"],
            ["campaigns", "Campaigns"],
            ["history", "History"],
            ["purple", "Purple Team"],
          ] as [ValidationTab, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === "results" && <ResultsTab />}
      {tab === "campaigns" && <CampaignsTab />}
      {tab === "history" && <HistoryTab />}
      {tab === "purple" && <PurpleTeamTab />}
    </>
  );
}

function ResultsTab() {
  const results = useApiList(
    "/api/v1/validation-results",
    parseValidationResult,
  );
  const campaigns = useApiList(
    "/api/v1/validation/campaigns",
    parseValidationCampaign,
  );
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState("ALL");
  const [selected, setSelected] = useState<ValidationResult | null>(null);

  const rows = useMemo(() => {
    const list = listOf(results);
    if (!list) return null;
    const q = search.trim().toLowerCase();
    return list.filter((r) => {
      if (verdict !== "ALL" && r.verdict !== verdict) return false;
      if (
        q &&
        !(
          r.control_id.toLowerCase().includes(q) ||
          r.provider.toLowerCase().includes(q) ||
          r.id.toLowerCase().includes(q)
        )
      )
        return false;
      return true;
    });
  }, [results, search, verdict]);

  const hasActive = search !== "" || verdict !== "ALL";
  const clearFilters = () => {
    setSearch("");
    setVerdict("ALL");
  };

  const loading = results.kind === "loading";
  const backendError =
    results.kind === "backend-error" ? results.message : null;
  const invalid = results.kind === "invalid" ? results.message : null;

  return (
    <>
      {results.kind === "loading" && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={4} />
        </>
      )}
      {results.kind === "backend-error" && (
        <ErrorState title="Backend error" message={results.message} />
      )}
      {results.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message={`The backend returned data outside the contract: ${results.message}`}
        />
      )}
      {!loading &&
        !backendError &&
        !invalid &&
        rows !== null &&
        (listOf(results) ?? []).length === 0 && (
          <div className="panel">
            <EmptyState
              icon="validation"
              title="No validation results"
              description="Validation results will appear here when controls are validated through a provider."
            />
          </div>
        )}
      {!loading &&
        !backendError &&
        !invalid &&
        rows !== null &&
        (listOf(results) ?? []).length > 0 && (
          <>
            {(() => {
              const list = listOf(results) ?? [];
              const camps = listOf(campaigns);
              if (camps === null) return null;
              return (
                <SummaryStrip
                  statement="Undetected executions are the gap between assumed and real defense."
                  stats={[
                    { label: "Campaigns", value: String(camps.length) },
                    {
                      label: "Completed",
                      value: String(
                        camps.filter((c) => c.status === "COMPLETED").length,
                      ),
                    },
                    { label: "Results", value: String(list.length) },
                    {
                      label: "Undetected",
                      value: String(
                        list.filter(
                          (r) =>
                            r.verdict ===
                            "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED",
                        ).length,
                      ),
                    },
                  ]}
                />
              );
            })()}
            <div className="panel">
              <div
                className="panel-body"
                style={{ display: "flex", flexWrap: "wrap", gap: 8 }}
              >
                {VERDICTS.map((v) => (
                  <StatusBadge key={v} value={v} tone={verdictTone(v)} />
                ))}
              </div>
            </div>
            <FilterBar
              search={search}
              onSearch={setSearch}
              searchLabel="Search validation results"
              searchPlaceholder="Search control, provider, or id…"
              selects={[
                {
                  label: "Verdict",
                  value: verdict,
                  options: [
                    { value: "ALL", label: "All verdicts" },
                    ...VERDICTS.map((v) => ({
                      value: v,
                      label: v.replace("VALIDATION_VERDICT_", ""),
                    })),
                  ],
                  onChange: setVerdict,
                },
              ]}
              onClear={clearFilters}
              hasActive={hasActive}
            />
            {rows.length === 0 ? (
              <div className="panel">
                <EmptyState
                  icon="validation"
                  title="No matching results"
                  description="No validation results match the current search and filters."
                  action={{ label: "Clear filters", onClick: clearFilters }}
                />
              </div>
            ) : (
              <DataTable
                columns={COLUMNS}
                rows={rows}
                onRowClick={setSelected}
                rowLabel={(r) => `Validation ${r.id}`}
                empty={<></>}
              />
            )}
          </>
        )}
      {selected && (
        <Drawer title={selected.id} onClose={() => setSelected(null)}>
          <div style={{ marginBottom: 4 }}>
            <StatusBadge
              value={selected.verdict}
              tone={verdictTone(selected.verdict)}
            />
          </div>
          <p style={{ fontSize: 13, color: "var(--bv-ink-soft)" }}>
            {VERDICT_MEANINGS[selected.verdict]}
          </p>
          {selected.verdict === "VALIDATION_VERDICT_NOT_TESTED" && (
            <div className="error-box" style={{ marginTop: 12 }}>
              <h3>Validation was not performed</h3>
              <p>
                This result records that no validation ran — it must never be
                read as secure.
              </p>
            </div>
          )}
          {selected.verdict === "VALIDATION_VERDICT_UNKNOWN" && (
            <div className="error-box" style={{ marginTop: 12 }}>
              <h3>Inconclusive result</h3>
              <p>
                Validation ran without a determinate outcome. Treat the control
                as unvalidated.
              </p>
            </div>
          )}
          <dl className="field-grid" style={{ marginTop: 12 }}>
            <Field label="Note">{selected.note || "—"}</Field>
            <div className="field-group">
              <h4 className="group-head">Identity</h4>
              <Field label="Control">
                <span className="mono">{selected.control_id}</span>
              </Field>
              <Field label="Provider">
                <span className="mono">{selected.provider}</span>
              </Field>
              <Field label="Request">
                <span className="mono">{selected.request_id}</span>
              </Field>
              <Field label="Evidence">
                <span className="mono">
                  {(selected.evidence_ids ?? []).join(", ") || "—"}
                </span>
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">History</h4>
              <Field label="Validated">
                <span className="tabular">
                  {fmtTime(selected.validated_at)}
                </span>
              </Field>
            </div>
          </dl>
        </Drawer>
      )}
    </>
  );
}

const CAMPAIGN_COLUMNS: Column<ValidationCampaign>[] = [
  {
    key: "name",
    header: "Campaign",
    sortable: true,
    sortValue: (r) => r.name,
    render: (r) => <span className="mono">{r.name}</span>,
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
        tone={r.status === "COMPLETED" ? "neutral" : "warn"}
      />
    ),
  },
  {
    key: "total",
    header: "Cases",
    sortable: true,
    sortValue: (r) => r.summary.total,
    render: (r) => <span className="tabular">{r.summary.total}</span>,
  },
];

function CampaignsTab() {
  const campaigns = useApiList(
    "/api/v1/validation/campaigns",
    parseValidationCampaign,
  );
  const [selected, setSelected] = useState<ValidationCampaign | null>(null);
  const rows = useMemo(() => listOf(campaigns), [campaigns]);
  const loading = campaigns.kind === "loading";

  return (
    <>
      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={3} />
        </>
      )}
      {campaigns.kind === "backend-error" && (
        <ErrorState title="Backend error" message={campaigns.message} />
      )}
      {campaigns.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message={`The backend returned data outside the contract: ${campaigns.message}`}
        />
      )}
      {!loading &&
        campaigns.kind !== "backend-error" &&
        campaigns.kind !== "invalid" &&
        (rows ?? []).length === 0 && (
          <div className="panel">
            <EmptyState
              icon="validation"
              title="No validation campaigns"
              description="Campaigns appear here when a validation campaign is executed and persisted."
            />
          </div>
        )}
      {!loading &&
        campaigns.kind !== "backend-error" &&
        campaigns.kind !== "invalid" &&
        rows !== null &&
        rows.length > 0 && (
          <DataTable
            columns={CAMPAIGN_COLUMNS}
            rows={rows}
            onRowClick={setSelected}
            rowLabel={(r) => `Campaign ${r.id}`}
            empty={<></>}
          />
        )}
      {selected && (
        <Drawer title={selected.id} onClose={() => setSelected(null)}>
          <div style={{ marginBottom: 4 }}>
            <StatusBadge
              value={selected.status}
              tone={selected.status === "COMPLETED" ? "neutral" : "warn"}
            />
          </div>
          <p style={{ fontSize: 13, color: "var(--bv-ink-soft)" }}>
            {selected.description || selected.name}
          </p>
          <dl className="field-grid" style={{ marginTop: 12 }}>
            <div className="field-group">
              <h4 className="group-head">Identity</h4>
              <Field label="Target">
                <span className="mono">{selected.target}</span>
              </Field>
              <Field label="Provider">
                <span className="mono">{selected.provider}</span>
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">Risk</h4>
              <Field label="Cases">
                <span className="tabular">{selected.summary.total}</span>
              </Field>
              <Field label="Provider errors">
                <span className="tabular">
                  {selected.summary.provider_errors}
                </span>
              </Field>
              <Field label="Not tested">
                <span className="tabular">{selected.summary.not_tested}</span>
              </Field>
              <Field label="Rate limited">
                <span className="tabular">{selected.summary.rate_limited}</span>
              </Field>
              <Field label="Unknown">
                <span className="tabular">{selected.summary.unknown}</span>
              </Field>
            </div>
          </dl>
          <h3>Results by verdict</h3>
          <dl className="field-grid">
            {Object.entries(selected.summary.by_verdict).map(([v, n]) => (
              <Field key={v} label={v.replace("VALIDATION_VERDICT_", "")}>
                <span className="tabular">{n}</span>
              </Field>
            ))}
          </dl>
          <p style={{ fontSize: 13, color: "var(--bv-ink-soft)" }}>
            Counts only — no derived metrics. A campaign of NOT_TESTED results
            is not successful.
          </p>
        </Drawer>
      )}
    </>
  );
}

function HistoryTab() {
  const results = useApiList(
    "/api/v1/validation/history",
    parseValidationResult,
  );
  const [search, setSearch] = useState("");
  const rows = useMemo(() => {
    const list = listOf(results);
    if (!list) return null;
    const q = search.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (r) =>
        r.control_id.toLowerCase().includes(q) ||
        r.provider.toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q),
    );
  }, [results, search]);
  const loading = results.kind === "loading";

  return (
    <>
      <FilterBar
        search={search}
        onSearch={setSearch}
        searchLabel="Search validation history"
        searchPlaceholder="Search control, provider, or id…"
        selects={[]}
        onClear={() => setSearch("")}
        hasActive={search !== ""}
      />
      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={4} />
        </>
      )}
      {results.kind === "backend-error" && (
        <ErrorState title="Backend error" message={results.message} />
      )}
      {results.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message={`The backend returned data outside the contract: ${results.message}`}
        />
      )}
      {!loading &&
        results.kind !== "backend-error" &&
        results.kind !== "invalid" &&
        rows !== null &&
        rows.length === 0 && (
          <div className="panel">
            <EmptyState
              icon="validation"
              title="No validation history"
              description="Historical validation results will appear here once persisted."
            />
          </div>
        )}
      {!loading &&
        results.kind !== "backend-error" &&
        results.kind !== "invalid" &&
        rows !== null &&
        rows.length > 0 && (
          <DataTable
            columns={RESULT_COLUMNS}
            rows={rows}
            rowLabel={(r) => `Validation ${r.id}`}
            empty={<></>}
          />
        )}
    </>
  );
}

const RESULT_COLUMNS: Column<ValidationResult>[] = [
  {
    key: "verdict",
    header: "Verdict",
    sortable: true,
    sortValue: (r) => r.verdict,
    render: (r) => (
      <StatusBadge value={r.verdict} tone={verdictTone(r.verdict)} />
    ),
  },
  {
    key: "control_id",
    header: "Control",
    sortable: true,
    sortValue: (r) => r.control_id,
    render: (r) => <span className="mono">{r.control_id}</span>,
  },
  {
    key: "provider",
    header: "Provider",
    sortable: true,
    sortValue: (r) => r.provider,
    render: (r) => <span className="mono">{r.provider}</span>,
  },
  {
    key: "validated_at",
    header: "Validated",
    sortable: true,
    sortValue: (r) => r.validated_at,
    render: (r) => <span className="tabular">{fmtTime(r.validated_at)}</span>,
  },
];

const EXERCISE_COLUMNS: Column<PurpleTeamExercise>[] = [
  {
    key: "name",
    header: "Exercise",
    sortable: true,
    sortValue: (r) => r.name,
    render: (r) => <span className="mono">{r.name}</span>,
  },
  {
    key: "campaign_id",
    header: "Campaign",
    sortable: true,
    sortValue: (r) => r.campaign_id,
    render: (r) => <span className="mono">{r.campaign_id}</span>,
  },
  {
    key: "entries",
    header: "Cases",
    sortable: true,
    sortValue: (r) => r.entries.length,
    render: (r) => <span className="tabular">{r.entries.length}</span>,
  },
];

function PurpleTeamTab() {
  const exercises = useApiList(
    "/api/v1/purple-team/exercises",
    parsePurpleTeamExercise,
  );
  const [selected, setSelected] = useState<PurpleTeamExercise | null>(null);
  const rows = useMemo(() => listOf(exercises), [exercises]);
  const loading = exercises.kind === "loading";

  return (
    <>
      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={3} />
        </>
      )}
      {exercises.kind === "backend-error" && (
        <ErrorState title="Backend error" message={exercises.message} />
      )}
      {exercises.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message={`The backend returned data outside the contract: ${exercises.message}`}
        />
      )}
      {!loading &&
        exercises.kind !== "backend-error" &&
        exercises.kind !== "invalid" &&
        (rows ?? []).length === 0 && (
          <div className="panel">
            <EmptyState
              icon="validation"
              title="No purple-team exercises"
              description="Exercises appear here when a campaign is correlated with its telemetry and evidence."
            />
          </div>
        )}
      {!loading &&
        exercises.kind !== "backend-error" &&
        exercises.kind !== "invalid" &&
        rows !== null &&
        rows.length > 0 && (
          <DataTable
            columns={EXERCISE_COLUMNS}
            rows={rows}
            onRowClick={setSelected}
            rowLabel={(r) => `Exercise ${r.id}`}
            empty={<></>}
          />
        )}
      {selected && (
        <Drawer title={selected.id} onClose={() => setSelected(null)}>
          <p style={{ fontSize: 13, color: "var(--bv-ink-soft)" }}>
            Validation scenarios observed against controls. Entries describe
            what was observed — never attacks or compromises.
          </p>
          <dl className="field-grid" style={{ marginTop: 12 }}>
            <div className="field-group">
              <h4 className="group-head">Identity</h4>
              <Field label="Campaign">
                <span className="mono">{selected.campaign_id}</span>
              </Field>
              <Field label="Source">
                <span className="mono">{selected.source}</span>
              </Field>
            </div>
          </dl>
          {selected.entries.map((e) => (
            <div key={e.case_id} style={{ marginTop: 12 }}>
              <h3>
                <span className="mono">{e.case_id}</span>{" "}
                <StatusBadge value={e.status} tone={exerciseTone(e.status)} />{" "}
                <span className="mono">{e.verdict}</span>
              </h3>
              <dl className="field-grid">
                <Field label="Request">
                  <span className="mono">{e.request_id}</span>
                </Field>
                <Field label="Result">
                  <span className="mono">{e.result_id}</span>
                </Field>
                <Field label="Telemetry">
                  <span className="mono">
                    {e.telemetry_ids.join(", ") || "—"}
                  </span>
                </Field>
                <Field label="Detections">
                  <span className="mono">
                    {e.detection_ids.join(", ") || "—"}
                  </span>
                </Field>
                <Field label="Alerts">
                  <span className="mono">{e.alert_ids.join(", ") || "—"}</span>
                </Field>
                <Field label="Incidents">
                  <span className="mono">
                    {e.incident_ids.join(", ") || "—"}
                  </span>
                </Field>
                <Field label="Evidence">
                  <span className="mono">
                    {e.evidence_ids.join(", ") || "—"}
                  </span>
                </Field>
              </dl>
            </div>
          ))}
        </Drawer>
      )}
    </>
  );
}
