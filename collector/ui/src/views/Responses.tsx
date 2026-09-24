import { useMemo, useState } from "react";
import {
  parseApproval,
  parseExecution,
  parseRecommendation,
  parseVerification,
} from "../contracts";
import type { ResponseRecommendation } from "../contracts";
import { DataTable, type Column } from "../components/DataTable";
import { Drawer } from "../components/Drawer";
import { StatusBadge, responseTone } from "../components/StatusBadge";
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
import { fmtTime, listOf, useApiList } from "./hooks";

const CHAIN = [
  "RESPONSE_STATUS_PROPOSED",
  "RESPONSE_STATUS_PENDING_APPROVAL",
  "RESPONSE_STATUS_APPROVED",
  "RESPONSE_STATUS_EXECUTING",
  "RESPONSE_STATUS_EXECUTED",
  "RESPONSE_STATUS_VERIFIED",
] as const;

const TERMINAL_TONE: Record<string, "low" | "bad" | "warn" | "neutral"> = {
  RESPONSE_STATUS_DENIED: "bad",
  RESPONSE_STATUS_EXECUTION_FAILED: "bad",
  RESPONSE_STATUS_VERIFICATION_FAILED: "bad",
  RESPONSE_STATUS_VERIFICATION_UNKNOWN: "warn",
  RESPONSE_STATUS_VERIFIED: "low",
};

const COLUMNS: Column<ResponseRecommendation>[] = [
  {
    key: "status",
    header: "Status",
    sortable: true,
    sortValue: (r) => r.status,
    render: (r) => (
      <StatusBadge value={r.status} tone={responseTone(r.status)} />
    ),
  },
  {
    key: "operation",
    header: "Operation",
    sortable: true,
    sortValue: (r) => r.operation,
    render: (r) => (
      <span className="mono">{r.operation.replace("OPERATION_TYPE_", "")}</span>
    ),
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
    render: (r) => (
      <span className="mono">{r.risk.replace("RISK_LEVEL_", "")}</span>
    ),
  },
  {
    key: "recommended_at",
    header: "Recommended",
    sortable: true,
    sortValue: (r) => r.recommended_at,
    render: (r) => <span className="tabular">{fmtTime(r.recommended_at)}</span>,
  },
];

function stepsFor(status: string, at: string): TimelineStep[] {
  if (
    status in TERMINAL_TONE &&
    !(CHAIN as readonly string[]).includes(status)
  ) {
    return [
      { key: "proposed", title: "Proposed", state: "done" },
      {
        key: "end",
        title: status.replace("RESPONSE_STATUS_", ""),
        meta: fmtTime(at),
        state: "now",
      },
    ];
  }
  const idx = (CHAIN as readonly string[]).indexOf(status);
  return CHAIN.map((s, i) => ({
    key: s,
    title: s.replace("RESPONSE_STATUS_", ""),
    meta: i === idx ? fmtTime(at) : undefined,
    state: i < idx ? "done" : i === idx ? "now" : "todo",
  }));
}

export function Responses() {
  const recs = useApiList("/api/v1/recommendations", parseRecommendation);
  const approvals = useApiList("/api/v1/approvals", parseApproval);
  const executions = useApiList("/api/v1/executions", parseExecution);
  const verifications = useApiList("/api/v1/verifications", parseVerification);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const loading = [recs, approvals, executions, verifications].some(
    (s) => s.kind === "loading",
  );
  const backendError = [recs, approvals, executions, verifications].find(
    (s) => s.kind === "backend-error",
  );
  const invalid = [recs, approvals, executions, verifications].find(
    (s) => s.kind === "invalid",
  );

  const byRec = useMemo(() => {
    const m = new Map<
      string,
      {
        approval?: string;
        execution?: string;
        verification?: string;
        verified?: string;
      }
    >();
    if (approvals.kind === "ready") {
      for (const a of approvals.data) {
        const e = m.get(a.recommendation_id) ?? {};
        e.approval = `${a.approver} · ${fmtTime(a.approved_at)}`;
        m.set(a.recommendation_id, e);
      }
    }
    const execById = new Map(
      executions.kind === "ready" ? executions.data.map((e) => [e.id, e]) : [],
    );
    if (executions.kind === "ready") {
      for (const e of executions.data) {
        const entry = m.get(e.recommendation_id) ?? {};
        entry.execution = `${e.success ? "succeeded" : "failed"} · ${fmtTime(e.finished_at)}`;
        m.set(e.recommendation_id, entry);
      }
    }
    if (verifications.kind === "ready") {
      for (const v of verifications.data) {
        const exec = execById.get(v.execution_id);
        if (!exec) continue;
        const entry = m.get(exec.recommendation_id) ?? {};
        entry.verification = `${v.outcome.replace("VERIFICATION_OUTCOME_", "")} · ${fmtTime(v.verified_at)}`;
        entry.verified = v.detail;
        m.set(exec.recommendation_id, entry);
      }
    }
    return m;
  }, [approvals, executions, verifications]);

  const selected = selectedId
    ? ((listOf(recs) ?? []).find((r) => r.id === selectedId) ?? null)
    : null;
  const linked = selected ? byRec.get(selected.id) : undefined;

  return (
    <>
      <h1 className="page-title">Responses</h1>
      <p className="page-sub">
        Gated response lifecycle, read-only. This view can never authorize or
        execute anything.
      </p>
      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={3} />
        </>
      )}
      {backendError?.kind === "backend-error" && (
        <ErrorState title="Backend error" message={backendError.message} />
      )}
      {invalid?.kind === "invalid" && (
        <ErrorState
          title="Invalid data"
          message={`The backend returned data outside the contract: ${invalid.message}`}
        />
      )}
      {!loading &&
        !backendError &&
        !invalid &&
        (listOf(recs) ?? []).length === 0 && (
          <div className="panel">
            <EmptyState
              icon="responses"
              title="No responses"
              description="Response recommendations will appear here when incidents flow through the gated response path."
            />
          </div>
        )}
      {!loading &&
        !backendError &&
        !invalid &&
        (listOf(recs) ?? []).length > 0 && (
          <>
            {(() => {
              const list = listOf(recs) ?? [];
              return (
                <SummaryStrip
                  statement="Pending approvals block response; failed executions need review."
                  stats={[
                    {
                      label: "Pending approval",
                      value: String(
                        list.filter(
                          (r) =>
                            r.status === "RESPONSE_STATUS_PENDING_APPROVAL",
                        ).length,
                      ),
                    },
                    {
                      label: "Executing",
                      value: String(
                        list.filter(
                          (r) => r.status === "RESPONSE_STATUS_EXECUTING",
                        ).length,
                      ),
                    },
                    {
                      label: "Verified",
                      value: String(
                        list.filter(
                          (r) => r.status === "RESPONSE_STATUS_VERIFIED",
                        ).length,
                      ),
                    },
                    {
                      label: "Failed",
                      value: String(
                        list.filter(
                          (r) =>
                            r.status === "RESPONSE_STATUS_DENIED" ||
                            r.status === "RESPONSE_STATUS_EXECUTION_FAILED" ||
                            r.status === "RESPONSE_STATUS_VERIFICATION_FAILED",
                        ).length,
                      ),
                    },
                  ]}
                />
              );
            })()}
            <DataTable
              columns={COLUMNS}
              rows={listOf(recs) ?? []}
              onRowClick={(r) => setSelectedId(r.id)}
              rowLabel={(r) => `Response ${r.id}`}
              empty={<></>}
            />
          </>
        )}
      {selected && (
        <Drawer title={selected.id} onClose={() => setSelectedId(null)}>
          <dl className="field-grid">
            <Field label="Reason">{selected.reason}</Field>
            {linked?.verified && (
              <Field label="Verification detail">{linked.verified}</Field>
            )}
            <div className="field-group">
              <h4 className="group-head">Identity</h4>
              <Field label="Operation">
                <span className="mono">{selected.operation}</span>
              </Field>
              <Field label="Target">
                <span className="mono">{selected.target}</span>
              </Field>
              <Field label="Recommended by">
                <span className="mono">{selected.recommended_by}</span>
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">Risk</h4>
              <Field label="Status">
                <StatusBadge
                  value={selected.status}
                  tone={responseTone(selected.status)}
                />
              </Field>
              <Field label="Risk">
                <span className="mono">{selected.risk}</span>
              </Field>
              <Field label="Approval required">
                {selected.approval_required ? "Yes" : "No"}
              </Field>
              {linked?.approval && (
                <Field label="Approval">{linked.approval}</Field>
              )}
              {linked?.execution && (
                <Field label="Execution">{linked.execution}</Field>
              )}
              {linked?.verification && (
                <Field label="Verification">{linked.verification}</Field>
              )}
            </div>
          </dl>
          <h3 className="section-title">Lifecycle</h3>
          <StatusTimeline
            steps={stepsFor(selected.status, selected.recommended_at)}
          />
        </Drawer>
      )}
    </>
  );
}
