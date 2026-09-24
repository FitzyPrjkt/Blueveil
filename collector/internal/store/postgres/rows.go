// Row mapping: canonical protobuf types to PostgreSQL columns and back,
// mirroring the SQLite mapping exactly (same TEXT/RFC3339/JSON encodings,
// same re-validation on every read). Timestamps persist as RFC 3339 UTC
// text (nanos preserved); enums as numbers; maps and id lists as JSON.
package postgres

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/asset"
	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/store"
)

func encodeTime(ts *timestamppb.Timestamp) string {
	return ts.AsTime().UTC().Format(time.RFC3339Nano)
}

// encodeTimeNull renders an optional timestamp, or NULL when absent.
func encodeTimeNull(ts *timestamppb.Timestamp) any {
	if ts == nil {
		return nil
	}
	return encodeTime(ts)
}

func decodeTime(s, what string) (*timestamppb.Timestamp, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s timestamp %q: %v", store.ErrCorrupted, what, s, err)
	}
	out := timestamppb.New(t.UTC())
	if out == nil {
		return nil, fmt.Errorf("%w: %s timestamp out of range", store.ErrCorrupted, what)
	}
	return out, nil
}

func encodeMap(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	data, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func decodeMap(s, what string) (map[string]string, error) {
	if s == "" || s == "{}" {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("%w: %s attributes: %v", store.ErrCorrupted, what, err)
	}
	return m, nil
}

func encodeList(ids []string) string {
	if len(ids) == 0 {
		return "[]"
	}
	data, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func decodeList(s, what string) ([]string, error) {
	if s == "" || s == "[]" {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(s), &ids); err != nil {
		return nil, fmt.Errorf("%w: %s ids: %v", store.ErrCorrupted, what, err)
	}
	return ids, nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func strOrEmpty(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isDuplicate reports UNIQUE-constraint violations across drivers.
// ---------------------------------------------------------------------------
// Telemetry.
// ---------------------------------------------------------------------------

func scanTelemetry(scan func(...any) error) (*v1.TelemetryEvent, error) {
	var e v1.TelemetryEvent
	var occurred, attrs string
	var identity sql.NullString
	var sev int32
	if err := scan(&e.Id, &occurred, &e.Source, &e.AssetId, &identity, &e.EventType, &sev, &attrs, &e.Raw); err != nil {
		return nil, err
	}
	ts, err := decodeTime(occurred, "telemetry.occurred_at")
	if err != nil {
		return nil, err
	}
	e.OccurredAt = ts
	e.IdentityId = strOrEmpty(identity)
	e.Severity = v1.Severity(sev)
	e.Attributes, err = decodeMap(attrs, "telemetry")
	if err != nil {
		return nil, err
	}
	if verr := contract.ValidateTelemetryEvent(&e); verr != nil {
		return nil, fmt.Errorf("%w: stored telemetry: %v", store.ErrCorrupted, verr)
	}
	return &e, nil
}

// ---------------------------------------------------------------------------
// Detection.
// ---------------------------------------------------------------------------

func scanDetection(scan func(...any) error) (*v1.Detection, error) {
	var d v1.Detection
	var eventIDs, detected, attrs string
	var descNull sql.NullString
	var sev int32
	var conf float64
	if err := scan(&d.Id, &d.RuleId, &d.RuleName, &eventIDs, &detected, &sev, &conf, &d.Title, &descNull, &attrs); err != nil {
		return nil, err
	}
	ts, err := decodeTime(detected, "detection.detected_at")
	if err != nil {
		return nil, err
	}
	d.DetectedAt = ts
	d.TelemetryEventIds, err = decodeList(eventIDs, "detection")
	if err != nil {
		return nil, err
	}
	d.Severity = v1.Severity(sev)
	d.Confidence = conf
	d.Description = strOrEmpty(descNull)
	d.Attributes, err = decodeMap(attrs, "detection")
	if err != nil {
		return nil, err
	}
	if verr := contract.ValidateDetection(&d); verr != nil {
		return nil, fmt.Errorf("%w: stored detection: %v", store.ErrCorrupted, verr)
	}
	return &d, nil
}

// ---------------------------------------------------------------------------
// Alert.
// ---------------------------------------------------------------------------

func scanAlert(scan func(...any) error) (*v1.Alert, error) {
	var a v1.Alert
	var detIDs, created, updated string
	var status, sev int32
	if err := scan(&a.Id, &detIDs, &status, &sev, &created, &updated, &a.Title); err != nil {
		return nil, err
	}
	var err error
	a.DetectionIds, err = decodeList(detIDs, "alert")
	if err != nil {
		return nil, err
	}
	a.Status = v1.AlertStatus(status)
	a.Severity = v1.Severity(sev)
	if a.CreatedAt, err = decodeTime(created, "alert.created_at"); err != nil {
		return nil, err
	}
	if a.UpdatedAt, err = decodeTime(updated, "alert.updated_at"); err != nil {
		return nil, err
	}
	if verr := contract.ValidateAlert(&a); verr != nil {
		return nil, fmt.Errorf("%w: stored alert: %v", store.ErrCorrupted, verr)
	}
	return &a, nil
}

// ---------------------------------------------------------------------------
// Incident.
// ---------------------------------------------------------------------------

func scanIncident(scan func(...any) error) (*v1.Incident, error) {
	var in v1.Incident
	var alertIDs, created, updated string
	var summaryNull sql.NullString
	var status, sev int32
	if err := scan(&in.Id, &alertIDs, &status, &sev, &created, &updated, &in.Title, &summaryNull); err != nil {
		return nil, err
	}
	var err error
	in.AlertIds, err = decodeList(alertIDs, "incident")
	if err != nil {
		return nil, err
	}
	in.Status = v1.IncidentStatus(status)
	in.Severity = v1.Severity(sev)
	if in.CreatedAt, err = decodeTime(created, "incident.created_at"); err != nil {
		return nil, err
	}
	if in.UpdatedAt, err = decodeTime(updated, "incident.updated_at"); err != nil {
		return nil, err
	}
	in.Summary = strOrEmpty(summaryNull)
	if verr := contract.ValidateIncident(&in); verr != nil {
		return nil, fmt.Errorf("%w: stored incident: %v", store.ErrCorrupted, verr)
	}
	return &in, nil
}

// ---------------------------------------------------------------------------
// Evidence (digest re-verified on every read).
// ---------------------------------------------------------------------------

func scanEvidence(scan func(...any) error) (*v1.Evidence, error) {
	var e v1.Evidence
	var collected string
	var shaNull sql.NullString
	var typ int32
	if err := scan(&e.Id, &e.IncidentId, &typ, &collected, &e.Source, &e.MediaType, &shaNull, &e.Content); err != nil {
		return nil, err
	}
	var err error
	e.Type = v1.EvidenceType(typ)
	if e.CollectedAt, err = decodeTime(collected, "evidence.collected_at"); err != nil {
		return nil, err
	}
	e.Sha256 = strOrEmpty(shaNull)
	if verr := contract.ValidateEvidence(&e); verr != nil {
		return nil, fmt.Errorf("%w: stored evidence: %v", store.ErrCorrupted, verr)
	}
	if !evidence.Verify(&e) {
		return nil, fmt.Errorf("%w: evidence %q digest mismatch (stored content altered)", store.ErrCorrupted, e.GetId())
	}
	return &e, nil
}

// ---------------------------------------------------------------------------
// Response records.
// ---------------------------------------------------------------------------

func scanRecommendation(scan func(...any) error) (*v1.ResponseRecommendation, error) {
	var r v1.ResponseRecommendation
	var recommended string
	var op, risk, status, approval int32
	if err := scan(&r.Id, &r.IncidentId, &op, &r.Target, &risk, &r.Reason, &status, &recommended, &r.RecommendedBy, &approval); err != nil {
		return nil, err
	}
	var err error
	r.Operation = v1.OperationType(op)
	r.Risk = v1.RiskLevel(risk)
	r.Status = v1.ResponseStatus(status)
	if r.RecommendedAt, err = decodeTime(recommended, "recommendation.recommended_at"); err != nil {
		return nil, err
	}
	r.ApprovalRequired = approval != 0
	if verr := contract.ValidateResponseRecommendation(&r); verr != nil {
		return nil, fmt.Errorf("%w: stored recommendation: %v", store.ErrCorrupted, verr)
	}
	return &r, nil
}

func scanApproval(scan func(...any) error) (*v1.ResponseApproval, error) {
	var a v1.ResponseApproval
	var approved string
	var expiresNull sql.NullString
	var op, risk int32
	if err := scan(&a.Id, &a.RecommendationId, &op, &a.Target, &risk, &a.Approver, &approved, &expiresNull, &a.Reason); err != nil {
		return nil, err
	}
	var err error
	a.Operation = v1.OperationType(op)
	a.Risk = v1.RiskLevel(risk)
	if a.ApprovedAt, err = decodeTime(approved, "approval.approved_at"); err != nil {
		return nil, err
	}
	if expires := strOrEmpty(expiresNull); expires != "" {
		if a.ExpiresAt, err = decodeTime(expires, "approval.expires_at"); err != nil {
			return nil, err
		}
	}
	if verr := contract.ValidateResponseApproval(&a); verr != nil {
		return nil, fmt.Errorf("%w: stored approval: %v", store.ErrCorrupted, verr)
	}
	return &a, nil
}

func scanExecution(scan func(...any) error) (*v1.ResponseExecution, error) {
	var e v1.ResponseExecution
	var started, finished string
	var approvalNull sql.NullString
	var op, success int32
	if err := scan(&e.Id, &e.RecommendationId, &approvalNull, &op, &e.Target, &started, &finished, &success, &e.Detail); err != nil {
		return nil, err
	}
	var err error
	e.ApprovalId = strOrEmpty(approvalNull)
	e.Operation = v1.OperationType(op)
	if e.StartedAt, err = decodeTime(started, "execution.started_at"); err != nil {
		return nil, err
	}
	if e.FinishedAt, err = decodeTime(finished, "execution.finished_at"); err != nil {
		return nil, err
	}
	e.Success = success != 0
	if verr := contract.ValidateResponseExecution(&e); verr != nil {
		return nil, fmt.Errorf("%w: stored execution: %v", store.ErrCorrupted, verr)
	}
	return &e, nil
}

func scanVerification(scan func(...any) error) (*v1.ResponseVerification, error) {
	var v v1.ResponseVerification
	var verified string
	var outcome int32
	if err := scan(&v.Id, &v.ExecutionId, &outcome, &verified, &v.Detail); err != nil {
		return nil, err
	}
	var err error
	v.Outcome = v1.VerificationOutcome(outcome)
	if v.VerifiedAt, err = decodeTime(verified, "verification.verified_at"); err != nil {
		return nil, err
	}
	if verr := contract.ValidateResponseVerification(&v); verr != nil {
		return nil, fmt.Errorf("%w: stored verification: %v", store.ErrCorrupted, verr)
	}
	return &v, nil
}

// ---------------------------------------------------------------------------
// Validation records.
// ---------------------------------------------------------------------------

func scanValidationRequest(scan func(...any) error) (*v1.ValidationRequest, error) {
	var r v1.ValidationRequest
	var ctxJSON, requested string
	if err := scan(&r.Id, &r.ControlId, &r.Target, &ctxJSON, &requested); err != nil {
		return nil, err
	}
	var err error
	r.Context, err = decodeMap(ctxJSON, "validation-request")
	if err != nil {
		return nil, err
	}
	if r.RequestedAt, err = decodeTime(requested, "validation-request.requested_at"); err != nil {
		return nil, err
	}
	if verr := contract.ValidateValidationRequest(&r); verr != nil {
		return nil, fmt.Errorf("%w: stored validation request: %v", store.ErrCorrupted, verr)
	}
	return &r, nil
}

func scanValidationResult(scan func(...any) error) (*v1.ValidationResult, error) {
	var r v1.ValidationResult
	var validated, evidenceIDs string
	var providerVerNull, noteNull sql.NullString
	var verdict int32
	if err := scan(&r.Id, &r.RequestId, &r.ControlId, &r.Provider, &providerVerNull, &r.ContractVersion, &verdict, &validated, &evidenceIDs, &noteNull); err != nil {
		return nil, err
	}
	var err error
	r.ProviderVersion = strOrEmpty(providerVerNull)
	r.Verdict = v1.ValidationVerdict(verdict)
	if r.ValidatedAt, err = decodeTime(validated, "validation-result.validated_at"); err != nil {
		return nil, err
	}
	r.EvidenceIds, err = decodeList(evidenceIDs, "validation-result")
	if err != nil {
		return nil, err
	}
	r.Note = strOrEmpty(noteNull)
	if verr := contract.ValidateValidationResult(&r); verr != nil {
		return nil, fmt.Errorf("%w: stored validation result: %v", store.ErrCorrupted, verr)
	}
	return &r, nil
}

// ---------------------------------------------------------------------------
// Asset.
// ---------------------------------------------------------------------------

func scanAsset(scan func(...any) error) (*v1.Asset, error) {
	var a v1.Asset
	var identifiers, attrs string
	var firstSeenNull, lastSeenNull sql.NullString
	var typ, sev, status int32
	if err := scan(&a.Id, &typ, &a.Name, &identifiers, &sev, &a.Environment, &status, &firstSeenNull, &lastSeenNull, &attrs); err != nil {
		return nil, err
	}
	var err error
	a.Type = v1.AssetType(typ)
	a.Identifiers, err = decodeIdentifiers(identifiers)
	if err != nil {
		return nil, err
	}
	if sev != 0 {
		a.Criticality = v1.Severity(sev)
	}
	a.Status = v1.AssetStatus(status)
	if firstSeen := strOrEmpty(firstSeenNull); firstSeen != "" {
		if a.FirstSeen, err = decodeTime(firstSeen, "asset.first_seen"); err != nil {
			return nil, err
		}
	}
	if lastSeen := strOrEmpty(lastSeenNull); lastSeen != "" {
		if a.LastSeen, err = decodeTime(lastSeen, "asset.last_seen"); err != nil {
			return nil, err
		}
	}
	a.Attributes, err = decodeMap(attrs, "asset")
	if err != nil {
		return nil, err
	}
	if verr := contract.ValidateAsset(&a); verr != nil {
		return nil, fmt.Errorf("%w: stored asset: %v", store.ErrCorrupted, verr)
	}
	// Canonical form is part of identity (ID = hash of type+canonical):
	// a tampered name that still validates must fail closed here.
	if verr := asset.CheckCanonical(&a); verr != nil {
		return nil, fmt.Errorf("%w: stored asset: %v", store.ErrCorrupted, verr)
	}
	return &a, nil
}

func decodeIdentifiers(s string) ([]*v1.AssetIdentifier, error) {
	if s == "" || s == "[]" {
		return nil, nil
	}
	var items []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(s), &items); err != nil {
		return nil, fmt.Errorf("%w: asset identifiers: %v", store.ErrCorrupted, err)
	}
	out := make([]*v1.AssetIdentifier, 0, len(items))
	for _, it := range items {
		out = append(out, &v1.AssetIdentifier{Type: it.Type, Value: it.Value})
	}
	return out, nil
}

func encodeIdentifiers(ids []*v1.AssetIdentifier) string {
	if len(ids) == 0 {
		return "[]"
	}
	type wire struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	plain := make([]wire, 0, len(ids))
	for _, id := range ids {
		plain = append(plain, wire{Type: id.GetType(), Value: id.GetValue()})
	}
	data, err := json.Marshal(plain)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// ---------------------------------------------------------------------------
// Audit.
// ---------------------------------------------------------------------------

func scanAudit(scan func(...any) error) (store.AuditEntry, error) {
	var e store.AuditEntry
	var decided string
	var op, risk int32
	var decision string
	if err := scan(&e.ID, &decided, &e.Actor, &op, &risk, &decision, &e.Reason, &e.Result, &e.ResponseID, &e.Phase); err != nil {
		return store.AuditEntry{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, decided)
	if err != nil {
		return store.AuditEntry{}, fmt.Errorf("%w: audit timestamp %q: %v", store.ErrCorrupted, decided, err)
	}
	e.DecidedAt = t.UTC()
	e.Operation = v1.OperationType(op)
	e.Risk = v1.RiskLevel(risk)
	e.Decision = decision
	if verr := e.Validate(); verr != nil {
		return store.AuditEntry{}, fmt.Errorf("%w: stored audit: %v", store.ErrCorrupted, verr)
	}
	return e, nil
}
