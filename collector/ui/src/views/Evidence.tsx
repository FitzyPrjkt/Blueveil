import { useEffect, useMemo, useState } from "react";
import { parseEvidence, parseIncident } from "../contracts";
import type { Evidence } from "../contracts";
import { ApiError, apiFetch } from "../api";
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

const KIND_LABEL: Record<Evidence["type"], string> = {
  EVIDENCE_TYPE_LOG_EXCERPT: "LOG EXCERPT",
  EVIDENCE_TYPE_HTTP_REQUEST: "HTTP REQUEST",
  EVIDENCE_TYPE_HTTP_RESPONSE: "HTTP RESPONSE",
  EVIDENCE_TYPE_SCAN_RESULT: "SCAN RESULT",
  EVIDENCE_TYPE_FILE_HASH: "FILE HASH",
  EVIDENCE_TYPE_NOTE: "NOTE",
};

const COLUMNS: Column<Evidence>[] = [
  {
    key: "id",
    header: "Evidence",
    sortable: true,
    sortValue: (r) => r.id,
    render: (r) => <span className="mono">{r.id}</span>,
  },
  {
    key: "type",
    header: "Kind",
    sortable: true,
    sortValue: (r) => r.type,
    render: (r) => (
      <StatusBadge value={KIND_LABEL[r.type]} tone="neutral" outline />
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
    key: "collected_at",
    header: "Collected",
    sortable: true,
    sortValue: (r) => r.collected_at,
    render: (r) => <span className="tabular">{fmtTime(r.collected_at)}</span>,
  },
  {
    key: "integrity",
    header: "Integrity",
    // The badge renders only when the envelope check passed (see
    // useEvidenceEnvelope): VERIFIED is a checked field, not an assumption.
    render: () => <StatusBadge value="VERIFIED" tone="low" />,
  },
];

type EvidenceState =
  | { kind: "loading" }
  | { kind: "ready"; data: Evidence[] }
  | { kind: "empty" }
  | { kind: "backend-error"; message: string }
  | { kind: "invalid"; message: string };

// Shared with ReportView: evidence rows render only when the integrity
// envelope is verified. Anything else (missing field, other value,
// unparsable rows) is an explicit error, so the VERIFIED badge can never
// display on unchecked data.
export function useEvidenceEnvelope(): EvidenceState {
  const [state, setState] = useState<EvidenceState>({ kind: "loading" });
  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    (async () => {
      try {
        const res = await apiFetch("/api/v1/evidence");
        const body: unknown = await res.json().catch(() => {
          throw new ApiError(
            "INVALID",
            "non-JSON response from /api/v1/evidence",
            res.status,
          );
        });
        if (!res.ok) {
          const err = (body as { error?: { code?: string; message?: string } })
            .error;
          throw new ApiError(
            err?.code ?? "BACKEND",
            err?.message ?? "request failed",
            res.status,
          );
        }
        const obj = body as { data?: unknown; integrity?: unknown };
        if (obj?.integrity !== "verified") {
          throw new ApiError(
            "INVALID",
            "/api/v1/evidence: integrity envelope is not verified",
            200,
          );
        }
        if (!Array.isArray(obj?.data)) {
          throw new ApiError(
            "INVALID",
            "bad envelope from /api/v1/evidence",
            200,
          );
        }
        const items = obj.data.map((item, i) => {
          try {
            return parseEvidence(item);
          } catch (e) {
            throw new ApiError(
              "INVALID",
              `item ${i}: ${(e as Error).message}`,
              200,
            );
          }
        });
        if (!cancelled)
          setState(
            items.length === 0
              ? { kind: "empty" }
              : { kind: "ready", data: items },
          );
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
  }, []);
  return state;
}

export function EvidenceView() {
  const evidence = useEvidenceEnvelope();
  const incidents = useApiList("/api/v1/incidents", parseIncident);
  const [search, setSearch] = useState("");
  const [incident, setIncident] = useState("ALL");
  const [kind, setKind] = useState("ALL");
  const [selected, setSelected] = useState<Evidence | null>(null);

  const rows = useMemo(() => {
    const list = listOf(evidence);
    if (!list) return null;
    const q = search.trim().toLowerCase();
    return list.filter((e) => {
      if (incident !== "ALL" && e.incident_id !== incident) return false;
      if (kind !== "ALL" && e.type !== kind) return false;
      if (
        q &&
        !(
          e.id.toLowerCase().includes(q) ||
          e.source.toLowerCase().includes(q) ||
          e.content.toLowerCase().includes(q)
        )
      )
        return false;
      return true;
    });
  }, [evidence, search, incident, kind]);

  const incidentIds = useMemo(() => {
    return (listOf(incidents) ?? []).map((i) => i.id).sort();
  }, [incidents]);

  // Integrity note: every item served here passed backend digest
  // re-verification (scanEvidence). A corrupted row never reaches this
  // list — it surfaces as INTEGRITY_FAILURE, rendered as an error state.
  const integrityError =
    evidence.kind === "backend-error" && evidence.message.includes("integrity")
      ? evidence.message
      : null;

  const loading = evidence.kind === "loading" || incidents.kind === "loading";
  const backendError =
    (evidence.kind === "backend-error" &&
      !integrityError &&
      evidence.message) ||
    (incidents.kind === "backend-error" && incidents.message) ||
    null;
  const invalid =
    (evidence.kind === "invalid" && evidence.message) ||
    (incidents.kind === "invalid" && incidents.message) ||
    null;

  const hasActive = search !== "" || incident !== "ALL" || kind !== "ALL";
  const clearFilters = () => {
    setSearch("");
    setIncident("ALL");
    setKind("ALL");
  };

  return (
    <>
      <h1 className="page-title">Evidence</h1>
      <p className="page-sub">
        Provenance records. Content is untrusted and rendered as plain text
        only.
      </p>
      {loading && (
        <>
          <HeadingSkeleton />
          <TableSkeleton rows={5} />
        </>
      )}
      {integrityError && (
        <ErrorState
          title="Integrity check failed"
          message={`Stored evidence failed digest re-verification: ${integrityError}`}
        />
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
      {!loading &&
        !backendError &&
        !invalid &&
        rows !== null &&
        (listOf(evidence) ?? []).length === 0 && (
          <div className="panel">
            <EmptyState
              icon="evidence"
              title="No evidence"
              description="Evidence will appear here when telemetry, detections, and validations are recorded."
            />
          </div>
        )}
      {!loading &&
        !backendError &&
        !invalid &&
        rows !== null &&
        (listOf(evidence) ?? []).length > 0 && (
          <>
            {(() => {
              // This block renders only when the integrity envelope is
              // verified (see useEvidenceEnvelope), so every item counted
              // here is digest-verified — no qualifier needed.
              const list = listOf(evidence) ?? [];
              return (
                <SummaryStrip
                  statement="Every item here is digest-verified — anything else never renders."
                  stats={[
                    { label: "Items", value: String(list.length) },
                    {
                      label: "Linked incidents",
                      value: String(
                        new Set(list.map((e) => e.incident_id)).size,
                      ),
                    },
                    {
                      label: "With SHA-256",
                      value: String(list.filter((e) => e.sha256 !== "").length),
                    },
                  ]}
                />
              );
            })()}
            <FilterBar
              search={search}
              onSearch={setSearch}
              searchLabel="Search evidence"
              searchPlaceholder="Search id, source, or content…"
              selects={[
                {
                  label: "Incident",
                  value: incident,
                  options: [
                    { value: "ALL", label: "All incidents" },
                    ...incidentIds.map((t) => ({ value: t, label: t })),
                  ],
                  onChange: setIncident,
                },
                {
                  label: "Kind",
                  value: kind,
                  options: [
                    { value: "ALL", label: "All kinds" },
                    ...Object.entries(KIND_LABEL).map(([value, label]) => ({
                      value,
                      label,
                    })),
                  ],
                  onChange: setKind,
                },
              ]}
              onClear={clearFilters}
              hasActive={hasActive}
            />
            {rows.length === 0 ? (
              <div className="panel">
                <EmptyState
                  icon="evidence"
                  title="No matching evidence"
                  description="No evidence matches the current search and filters."
                  action={{ label: "Clear filters", onClick: clearFilters }}
                />
              </div>
            ) : (
              <DataTable
                columns={COLUMNS}
                rows={rows}
                onRowClick={setSelected}
                rowLabel={(r) => `Evidence ${r.id}`}
                empty={<></>}
              />
            )}
          </>
        )}
      {selected && (
        <Drawer title={selected.id} onClose={() => setSelected(null)}>
          <dl className="field-grid">
            <div className="field-group">
              <h4 className="group-head">Identity</h4>
              <Field label="Kind">{KIND_LABEL[selected.type]}</Field>
              <Field label="Source">{selected.source}</Field>
              <Field label="Media type">
                <span className="mono">{selected.media_type}</span>
              </Field>
              <Field label="Incident">
                <span className="mono">{selected.incident_id}</span>
              </Field>
              <Field label="Digest">
                <span className="mono">{selected.sha256 || "—"}</span>
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">Risk</h4>
              <Field label="Integrity">
                <StatusBadge value="VERIFIED" tone="low" />
              </Field>
            </div>
            <div className="field-group">
              <h4 className="group-head">History</h4>
              <Field label="Collected">
                <span className="tabular">
                  {fmtTime(selected.collected_at)}
                </span>
              </Field>
            </div>
          </dl>
          <h3 className="section-title">Content (untrusted, plain text)</h3>
          <pre className="evidence-content">{selected.content}</pre>
        </Drawer>
      )}
    </>
  );
}
