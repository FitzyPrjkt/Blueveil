// Repository implementations over the versioned PostgreSQL schema. Every
// write validates the object first (invalid never becomes durable); every
// read re-validates (corruption surfaces explicitly). Duplicate ids and
// missing reads map to the store sentinel errors; anything else propagates
// with context. No UPDATE/DELETE statements exist for append-only entities
// — audit immutability is structural, greppable in this file. Placeholders
// are $n (pgx); otherwise semantics mirror the SQLite backend exactly.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"blueveil/collector/internal/asset"
	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/validation"
)

func cloneOf[T proto.Message](v T) T {
	return proto.Clone(v).(T)
}

// Backend returns every repository over this database, for the shared
// conformance suite and for production wiring alike.
func (d *DB) Backend() store.Backend {
	return backendOver(d.pool)
}

// backendOver wires every repository over one connection: the database
// for normal use, or a transaction for atomic batches.
func backendOver(c dbconn) store.Backend {
	return store.Backend{
		Telemetry:         &telemetryRepo{db: c},
		Detection:         &detectionRepo{db: c},
		Alert:             &alertRepo{db: c},
		Incident:          &incidentRepo{db: c},
		Evidence:          &evidenceRepo{db: c},
		Response:          &responseRepo{db: c},
		ResponseRecords:   &responseRecordRepo{db: c},
		Validation:        &validationRepo{db: c},
		Campaigns:         &campaignRepo{db: c},
		Exercises:         &exerciseRepo{db: c},
		Assessments:       &assessmentRepo{db: c},
		Resilience:        &resilienceRepo{db: c},
		Components:        &supplyComponentRepo{db: c},
		Dependencies:      &supplyDependencyRepo{db: c},
		SBOMs:             &supplySBOMRepo{db: c},
		Policies:          &supplyPolicyRepo{db: c},
		Vendors:           &supplyVendorRepo{db: c},
		VendorAssessments: &supplyVendorAssessmentRepo{db: c},
		SupplyLinks:       &supplyLinkRepo{db: c},
		Audit:             &auditRepo{db: c},
		Assets:            &assetRepo{db: c},
		Relationships:     &relationshipRepo{db: c},
	}
}

// ---------------------------------------------------------------------------
// Telemetry.
// ---------------------------------------------------------------------------

type telemetryRepo struct{ db dbconn }

func (r *telemetryRepo) Append(ctx context.Context, e *v1.TelemetryEvent) error {
	if err := contract.ValidateTelemetryEvent(e); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO telemetry_events (id, occurred_at, source, asset_id, identity_id, event_type, severity, attributes, raw)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.GetId(), encodeTime(e.GetOccurredAt()), e.GetSource(), e.GetAssetId(),
		nullString(e.GetIdentityId()), e.GetEventType(), int32(e.GetSeverity()),
		encodeMap(e.GetAttributes()), e.GetRaw())
	return mapWriteError(err, "telemetry", e.GetId())
}

func (r *telemetryRepo) Get(ctx context.Context, id string) (*v1.TelemetryEvent, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, occurred_at, source, asset_id, identity_id, event_type, severity, attributes, raw
		 FROM telemetry_events WHERE id = $1`, id)
	e, err := scanTelemetry(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "telemetry", id)
	}
	return e, nil
}

func (r *telemetryRepo) List(ctx context.Context) ([]*v1.TelemetryEvent, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, occurred_at, source, asset_id, identity_id, event_type, severity, attributes, raw
		 FROM telemetry_events ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list telemetry: %w", err)
	}
	defer rows.Close()
	var out []*v1.TelemetryEvent
	for rows.Next() {
		e, err := scanTelemetry(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Detection.
// ---------------------------------------------------------------------------

type detectionRepo struct{ db dbconn }

func (r *detectionRepo) Append(ctx context.Context, d *v1.Detection) error {
	if err := contract.ValidateDetection(d); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO detections (id, rule_id, rule_name, event_ids, detected_at, severity, confidence, title, description, attributes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		d.GetId(), d.GetRuleId(), d.GetRuleName(), encodeList(d.GetTelemetryEventIds()),
		encodeTime(d.GetDetectedAt()), int32(d.GetSeverity()), d.GetConfidence(),
		d.GetTitle(), nullString(d.GetDescription()), encodeMap(d.GetAttributes()))
	return mapWriteError(err, "detection", d.GetId())
}

func (r *detectionRepo) Get(ctx context.Context, id string) (*v1.Detection, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, rule_id, rule_name, event_ids, detected_at, severity, confidence, title, description, attributes
		 FROM detections WHERE id = $1`, id)
	d, err := scanDetection(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "detection", id)
	}
	return d, nil
}

func (r *detectionRepo) List(ctx context.Context) ([]*v1.Detection, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, rule_id, rule_name, event_ids, detected_at, severity, confidence, title, description, attributes
		 FROM detections ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list detections: %w", err)
	}
	defer rows.Close()
	var out []*v1.Detection
	for rows.Next() {
		d, err := scanDetection(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Alert.
// ---------------------------------------------------------------------------

type alertRepo struct{ db dbconn }

func (r *alertRepo) Append(ctx context.Context, a *v1.Alert) error {
	if err := contract.ValidateAlert(a); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO alerts (id, detection_ids, status, severity, created_at, updated_at, title)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		a.GetId(), encodeList(a.GetDetectionIds()), int32(a.GetStatus()), int32(a.GetSeverity()),
		encodeTime(a.GetCreatedAt()), encodeTime(a.GetUpdatedAt()), a.GetTitle())
	return mapWriteError(err, "alert", a.GetId())
}

func (r *alertRepo) Get(ctx context.Context, id string) (*v1.Alert, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, detection_ids, status, severity, created_at, updated_at, title
		 FROM alerts WHERE id = $1`, id)
	a, err := scanAlert(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "alert", id)
	}
	return a, nil
}

func (r *alertRepo) List(ctx context.Context) ([]*v1.Alert, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, detection_ids, status, severity, created_at, updated_at, title
		 FROM alerts ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list alerts: %w", err)
	}
	defer rows.Close()
	var out []*v1.Alert
	for rows.Next() {
		a, err := scanAlert(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Incident (lifecycle-mutable: Create once, Save replaces).
// ---------------------------------------------------------------------------

type incidentRepo struct{ db dbconn }

func (r *incidentRepo) Create(ctx context.Context, in *v1.Incident) error {
	if err := contract.ValidateIncident(in); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO incidents (id, alert_ids, status, severity, created_at, updated_at, title, summary)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		in.GetId(), encodeList(in.GetAlertIds()), int32(in.GetStatus()), int32(in.GetSeverity()),
		encodeTime(in.GetCreatedAt()), encodeTime(in.GetUpdatedAt()), in.GetTitle(),
		nullString(in.GetSummary()))
	return mapWriteError(err, "incident", in.GetId())
}

func (r *incidentRepo) Save(ctx context.Context, in *v1.Incident) error {
	if err := contract.ValidateIncident(in); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	res, err := r.db.Exec(ctx,
		`UPDATE incidents SET alert_ids = $1, status = $2, severity = $3, created_at = $4, updated_at = $5, title = $6, summary = $7
		 WHERE id = $8`,
		encodeList(in.GetAlertIds()), int32(in.GetStatus()), int32(in.GetSeverity()),
		encodeTime(in.GetCreatedAt()), encodeTime(in.GetUpdatedAt()), in.GetTitle(),
		nullString(in.GetSummary()), in.GetId())
	if err != nil {
		return fmt.Errorf("postgres: save incident %q: %w", in.GetId(), err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("%w: incident %q", store.ErrNotFound, in.GetId())
	}
	return nil
}

func (r *incidentRepo) Get(ctx context.Context, id string) (*v1.Incident, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, alert_ids, status, severity, created_at, updated_at, title, summary
		 FROM incidents WHERE id = $1`, id)
	in, err := scanIncident(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "incident", id)
	}
	return in, nil
}

func (r *incidentRepo) List(ctx context.Context) ([]*v1.Incident, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, alert_ids, status, severity, created_at, updated_at, title, summary
		 FROM incidents ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list incidents: %w", err)
	}
	defer rows.Close()
	var out []*v1.Incident
	for rows.Next() {
		in, err := scanIncident(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Evidence (append-only; digests re-verified on read in scanEvidence).
// ---------------------------------------------------------------------------

type evidenceRepo struct{ db dbconn }

func (r *evidenceRepo) Append(ctx context.Context, e *v1.Evidence) error {
	if err := contract.ValidateEvidence(e); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO evidence (id, incident_id, type, collected_at, source, media_type, sha256, content)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.GetId(), e.GetIncidentId(), int32(e.GetType()), encodeTime(e.GetCollectedAt()),
		e.GetSource(), e.GetMediaType(), nullString(e.GetSha256()), e.GetContent())
	if err != nil {
		if isDuplicate(err) {
			return fmt.Errorf("%w: evidence %q", store.ErrDuplicate, e.GetId())
		}
		return fmt.Errorf("postgres: write evidence %q: %w", e.GetId(), err)
	}
	return nil
}

func (r *evidenceRepo) Get(ctx context.Context, id string) (*v1.Evidence, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, incident_id, type, collected_at, source, media_type, sha256, content
		 FROM evidence WHERE id = $1`, id)
	e, err := scanEvidence(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "evidence", id)
	}
	return e, nil
}

func (r *evidenceRepo) List(ctx context.Context) ([]*v1.Evidence, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, incident_id, type, collected_at, source, media_type, sha256, content
		 FROM evidence ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list evidence: %w", err)
	}
	defer rows.Close()
	var out []*v1.Evidence
	for rows.Next() {
		e, err := scanEvidence(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *evidenceRepo) ListByIncident(ctx context.Context, incidentID string) ([]*v1.Evidence, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, incident_id, type, collected_at, source, media_type, sha256, content
		 FROM evidence WHERE incident_id = $1 ORDER BY id`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list evidence: %w", err)
	}
	defer rows.Close()
	var out []*v1.Evidence
	for rows.Next() {
		e, err := scanEvidence(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Response lifecycle + immutable records.
// ---------------------------------------------------------------------------

type responseRepo struct{ db dbconn }

func (r *responseRepo) Create(ctx context.Context, rec *v1.ResponseRecommendation) error {
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO response_recommendations (id, incident_id, operation, target, risk, reason, status, recommended_at, recommended_by, approval_required)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		rec.GetId(), rec.GetIncidentId(), int32(rec.GetOperation()), rec.GetTarget(),
		int32(rec.GetRisk()), rec.GetReason(), int32(rec.GetStatus()),
		encodeTime(rec.GetRecommendedAt()), rec.GetRecommendedBy(), boolInt(rec.GetApprovalRequired()))
	return mapWriteError(err, "recommendation", rec.GetId())
}

func (r *responseRepo) Save(ctx context.Context, rec *v1.ResponseRecommendation) error {
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	res, err := r.db.Exec(ctx,
		`UPDATE response_recommendations SET incident_id = $1, operation = $2, target = $3, risk = $4, reason = $5, status = $6, recommended_at = $7, recommended_by = $8, approval_required = $9
		 WHERE id = $10`,
		rec.GetIncidentId(), int32(rec.GetOperation()), rec.GetTarget(),
		int32(rec.GetRisk()), rec.GetReason(), int32(rec.GetStatus()),
		encodeTime(rec.GetRecommendedAt()), rec.GetRecommendedBy(), boolInt(rec.GetApprovalRequired()),
		rec.GetId())
	if err != nil {
		return fmt.Errorf("postgres: save recommendation %q: %w", rec.GetId(), err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("%w: recommendation %q", store.ErrNotFound, rec.GetId())
	}
	return nil
}

func (r *responseRepo) Get(ctx context.Context, id string) (*v1.ResponseRecommendation, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, incident_id, operation, target, risk, reason, status, recommended_at, recommended_by, approval_required
		 FROM response_recommendations WHERE id = $1`, id)
	rec, err := scanRecommendation(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "recommendation", id)
	}
	return rec, nil
}

func (r *responseRepo) List(ctx context.Context) ([]*v1.ResponseRecommendation, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, incident_id, operation, target, risk, reason, status, recommended_at, recommended_by, approval_required
		 FROM response_recommendations ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list recommendations: %w", err)
	}
	defer rows.Close()
	var out []*v1.ResponseRecommendation
	for rows.Next() {
		rec, err := scanRecommendation(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

type responseRecordRepo struct{ db dbconn }

func (r *responseRecordRepo) AppendApproval(ctx context.Context, a *v1.ResponseApproval) error {
	if err := contract.ValidateResponseApproval(a); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	var expires any
	if a.GetExpiresAt() != nil {
		expires = encodeTime(a.GetExpiresAt())
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO response_approvals (id, recommendation_id, operation, target, risk, approver, approved_at, expires_at, reason)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		a.GetId(), a.GetRecommendationId(), int32(a.GetOperation()), a.GetTarget(),
		int32(a.GetRisk()), a.GetApprover(), encodeTime(a.GetApprovedAt()), expires, a.GetReason())
	return mapWriteError(err, "approval", a.GetId())
}

func (r *responseRecordRepo) AppendExecution(ctx context.Context, e *v1.ResponseExecution) error {
	if err := contract.ValidateResponseExecution(e); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO response_executions (id, recommendation_id, approval_id, operation, target, started_at, finished_at, success, detail)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.GetId(), e.GetRecommendationId(), nullString(e.GetApprovalId()), int32(e.GetOperation()),
		e.GetTarget(), encodeTime(e.GetStartedAt()), encodeTime(e.GetFinishedAt()),
		boolInt(e.GetSuccess()), e.GetDetail())
	return mapWriteError(err, "execution", e.GetId())
}

func (r *responseRecordRepo) AppendVerification(ctx context.Context, v *v1.ResponseVerification) error {
	if err := contract.ValidateResponseVerification(v); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO response_verifications (id, execution_id, outcome, verified_at, detail)
		 VALUES ($1, $2, $3, $4, $5)`,
		v.GetId(), v.GetExecutionId(), int32(v.GetOutcome()), encodeTime(v.GetVerifiedAt()), v.GetDetail())
	return mapWriteError(err, "verification", v.GetId())
}

func (r *responseRecordRepo) GetApproval(ctx context.Context, id string) (*v1.ResponseApproval, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, recommendation_id, operation, target, risk, approver, approved_at, expires_at, reason
		 FROM response_approvals WHERE id = $1`, id)
	a, err := scanApproval(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "approval", id)
	}
	return a, nil
}

func (r *responseRecordRepo) GetExecution(ctx context.Context, id string) (*v1.ResponseExecution, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, recommendation_id, approval_id, operation, target, started_at, finished_at, success, detail
		 FROM response_executions WHERE id = $1`, id)
	e, err := scanExecution(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "execution", id)
	}
	return e, nil
}

func (r *responseRecordRepo) GetVerification(ctx context.Context, id string) (*v1.ResponseVerification, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, execution_id, outcome, verified_at, detail
		 FROM response_verifications WHERE id = $1`, id)
	v, err := scanVerification(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "verification", id)
	}
	return v, nil
}

func (r *responseRecordRepo) listRecords(ctx context.Context, table, cols string) (pgx.Rows, error) {
	return r.db.Query(ctx, `SELECT `+cols+` FROM `+table+` ORDER BY id`)
}

func (r *responseRecordRepo) ListApprovals(ctx context.Context) ([]*v1.ResponseApproval, error) {
	rows, err := r.listRecords(ctx, "response_approvals",
		"id, recommendation_id, operation, target, risk, approver, approved_at, expires_at, reason")
	if err != nil {
		return nil, fmt.Errorf("postgres: list approvals: %w", err)
	}
	defer rows.Close()
	var out []*v1.ResponseApproval
	for rows.Next() {
		a, err := scanApproval(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *responseRecordRepo) ListExecutions(ctx context.Context) ([]*v1.ResponseExecution, error) {
	rows, err := r.listRecords(ctx, "response_executions",
		"id, recommendation_id, approval_id, operation, target, started_at, finished_at, success, detail")
	if err != nil {
		return nil, fmt.Errorf("postgres: list executions: %w", err)
	}
	defer rows.Close()
	var out []*v1.ResponseExecution
	for rows.Next() {
		e, err := scanExecution(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *responseRecordRepo) ListVerifications(ctx context.Context) ([]*v1.ResponseVerification, error) {
	rows, err := r.listRecords(ctx, "response_verifications",
		"id, execution_id, outcome, verified_at, detail")
	if err != nil {
		return nil, fmt.Errorf("postgres: list verifications: %w", err)
	}
	defer rows.Close()
	var out []*v1.ResponseVerification
	for rows.Next() {
		v, err := scanVerification(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Validation records.
// ---------------------------------------------------------------------------

type validationRepo struct{ db dbconn }

func (r *validationRepo) AppendRequest(ctx context.Context, req *v1.ValidationRequest) error {
	if err := contract.ValidateValidationRequest(req); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO validation_requests (id, control_id, target, context, requested_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		req.GetId(), req.GetControlId(), req.GetTarget(),
		encodeMap(req.GetContext()), encodeTime(req.GetRequestedAt()))
	return mapWriteError(err, "validation request", req.GetId())
}

func (r *validationRepo) AppendResult(ctx context.Context, res *v1.ValidationResult) error {
	if err := contract.ValidateValidationResult(res); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO validation_results (id, request_id, control_id, provider, provider_version, contract_version, verdict, validated_at, evidence_ids, note)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		res.GetId(), res.GetRequestId(), res.GetControlId(), res.GetProvider(),
		nullString(res.GetProviderVersion()), res.GetContractVersion(), int32(res.GetVerdict()),
		encodeTime(res.GetValidatedAt()), encodeList(res.GetEvidenceIds()), nullString(res.GetNote()))
	return mapWriteError(err, "validation result", res.GetId())
}

func (r *validationRepo) GetRequest(ctx context.Context, id string) (*v1.ValidationRequest, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, control_id, target, context, requested_at FROM validation_requests WHERE id = $1`, id)
	req, err := scanValidationRequest(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "validation request", id)
	}
	return req, nil
}

func (r *validationRepo) GetResult(ctx context.Context, id string) (*v1.ValidationResult, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, request_id, control_id, provider, provider_version, contract_version, verdict, validated_at, evidence_ids, note
		 FROM validation_results WHERE id = $1`, id)
	res, err := scanValidationResult(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "validation result", id)
	}
	return res, nil
}

func (r *validationRepo) ListResults(ctx context.Context) ([]*v1.ValidationResult, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, request_id, control_id, provider, provider_version, contract_version, verdict, validated_at, evidence_ids, note
		 FROM validation_results ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list validation results: %w", err)
	}
	defer rows.Close()
	var out []*v1.ValidationResult
	for rows.Next() {
		res, err := scanValidationResult(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Audit (append-only: this file contains no UPDATE or DELETE statements for
// audit_entries — grep-auditable).
// ---------------------------------------------------------------------------

type auditRepo struct{ db dbconn }

func (r *auditRepo) Append(ctx context.Context, e store.AuditEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO audit_entries (id, decided_at, actor, operation, risk, decision, reason, result, response_id, phase)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		e.ID, e.DecidedAt.UTC().Format(time.RFC3339Nano), e.Actor, int32(e.Operation), int32(e.Risk),
		e.Decision, e.Reason, e.Result, e.ResponseID, e.Phase)
	return mapWriteError(err, "audit", e.ID)
}

func (r *auditRepo) Get(ctx context.Context, id string) (store.AuditEntry, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, decided_at, actor, operation, risk, decision, reason, result, response_id, phase
		 FROM audit_entries WHERE id = $1`, id)
	e, err := scanAudit(row.Scan)
	if err != nil {
		return store.AuditEntry{}, mapReadError(err, "audit", id)
	}
	return e, nil
}

func (r *auditRepo) List(ctx context.Context) ([]store.AuditEntry, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, decided_at, actor, operation, risk, decision, reason, result, response_id, phase
		 FROM audit_entries ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list audit: %w", err)
	}
	defer rows.Close()
	var out []store.AuditEntry
	for rows.Next() {
		e, err := scanAudit(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Assets (lifecycle-mutable) + relationships (append-only).
// ---------------------------------------------------------------------------

type assetRepo struct{ db dbconn }

func (r *assetRepo) Create(ctx context.Context, a *v1.Asset) error {
	if err := contract.ValidateAsset(a); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	if err := asset.CheckCanonical(a); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO assets (id, type, name, identifiers, criticality, environment, status, first_seen, last_seen, attributes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		a.GetId(), int32(a.GetType()), a.GetName(), encodeIdentifiers(a.GetIdentifiers()),
		int32(a.GetCriticality()), a.GetEnvironment(), int32(a.GetStatus()),
		encodeTimeNull(a.GetFirstSeen()), encodeTimeNull(a.GetLastSeen()),
		encodeMap(a.GetAttributes()))
	return mapWriteError(err, "asset", a.GetId())
}

func (r *assetRepo) Save(ctx context.Context, a *v1.Asset) error {
	if err := contract.ValidateAsset(a); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	if err := asset.CheckCanonical(a); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	res, err := r.db.Exec(ctx,
		`UPDATE assets SET type = $1, name = $2, identifiers = $3, criticality = $4, environment = $5, status = $6, first_seen = $7, last_seen = $8, attributes = $9
		 WHERE id = $10`,
		int32(a.GetType()), a.GetName(), encodeIdentifiers(a.GetIdentifiers()),
		int32(a.GetCriticality()), a.GetEnvironment(), int32(a.GetStatus()),
		encodeTimeNull(a.GetFirstSeen()), encodeTimeNull(a.GetLastSeen()),
		encodeMap(a.GetAttributes()), a.GetId())
	if err != nil {
		// UPDATE can hit UNIQUE(type,name): report the documented
		// ErrDuplicate, not a generic backend error.
		return mapWriteError(err, "asset", a.GetId())
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("%w: asset %q", store.ErrNotFound, a.GetId())
	}
	return nil
}

func (r *assetRepo) Get(ctx context.Context, id string) (*v1.Asset, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, type, name, identifiers, criticality, environment, status, first_seen, last_seen, attributes
		 FROM assets WHERE id = $1`, id)
	a, err := scanAsset(row.Scan)
	if err != nil {
		return nil, mapReadError(err, "asset", id)
	}
	return a, nil
}

func (r *assetRepo) listWhere(ctx context.Context, where, order string, args ...any) ([]*v1.Asset, error) {
	q := `SELECT id, type, name, identifiers, criticality, environment, status, first_seen, last_seen, attributes
		 FROM assets`
	if where != "" {
		q += " WHERE " + where
	}
	q += " ORDER BY " + order
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list assets: %w", err)
	}
	defer rows.Close()
	var out []*v1.Asset
	for rows.Next() {
		a, err := scanAsset(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *assetRepo) List(ctx context.Context) ([]*v1.Asset, error) {
	return r.listWhere(ctx, "", "id")
}

func (r *assetRepo) ListByType(ctx context.Context, typ v1.AssetType) ([]*v1.Asset, error) {
	return r.listWhere(ctx, "type = $1", "id", int32(typ))
}

func (r *assetRepo) ListByStatus(ctx context.Context, status v1.AssetStatus) ([]*v1.Asset, error) {
	return r.listWhere(ctx, "status = $1", "id", int32(status))
}

type relationshipRepo struct{ db dbconn }

func (r *relationshipRepo) Append(ctx context.Context, rel asset.Relationship) error {
	if err := rel.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO asset_relationships (parent_id, child_id, kind, source, observed_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		rel.ParentID, rel.ChildID, rel.Kind, rel.Source, rel.ObservedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		if isDuplicate(err) {
			return fmt.Errorf("%w: relationship %s→%s", store.ErrDuplicate, rel.ParentID, rel.ChildID)
		}
		return fmt.Errorf("postgres: write relationship: %w", err)
	}
	return nil
}

func (r *relationshipRepo) queryLinks(ctx context.Context, col, id string) ([]asset.Relationship, error) {
	// Column is internal (never user input): Parents/Children pass literals.
	rows, err := r.db.Query(ctx,
		`SELECT parent_id, child_id, kind, source, observed_at FROM asset_relationships WHERE `+col+` = $1 ORDER BY parent_id, child_id, kind`, id)
	if err != nil {
		return nil, fmt.Errorf("postgres: list relationships: %w", err)
	}
	defer rows.Close()
	var out []asset.Relationship
	for rows.Next() {
		var rel asset.Relationship
		var observed string
		if err := rows.Scan(&rel.ParentID, &rel.ChildID, &rel.Kind, &rel.Source, &observed); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan relationship: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, observed)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: relationship timestamp %q", store.ErrCorrupted, observed)
		}
		rel.ObservedAt = t.UTC()
		out = append(out, rel)
	}
	return out, rows.Err()
}

func (r *relationshipRepo) Children(ctx context.Context, parentID string) ([]asset.Relationship, error) {
	return r.queryLinks(ctx, "parent_id", parentID)
}

func (r *relationshipRepo) Parents(ctx context.Context, childID string) ([]asset.Relationship, error) {
	return r.queryLinks(ctx, "child_id", childID)
}

// ---------------------------------------------------------------------------
// Validation campaigns (lifecycle-mutable JSON) + purple-team exercises
// (append-only JSON). Payloads re-validate on read: corrupt bytes fail
// closed with ErrCorrupted, never as silently dropped rows.
// ---------------------------------------------------------------------------

type campaignRepo struct{ db dbconn }

func (r *campaignRepo) Create(ctx context.Context, c validation.Campaign) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("%w: campaign encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO validation_campaigns (id, payload) VALUES ($1, $2)`, c.ID(), string(payload))
	return mapWriteError(err, "campaign", c.ID())
}

func (r *campaignRepo) Save(ctx context.Context, c validation.Campaign) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("%w: campaign encode: %v", store.ErrInvalid, err)
	}
	res, err := r.db.Exec(ctx,
		`UPDATE validation_campaigns SET payload = $1 WHERE id = $2`, string(payload), c.ID())
	if err != nil {
		return mapWriteError(err, "campaign", c.ID())
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("%w: campaign %q", store.ErrNotFound, c.ID())
	}
	return nil
}

func (r *campaignRepo) Get(ctx context.Context, id string) (validation.Campaign, error) {
	var c validation.Campaign
	var payload string
	err := r.db.QueryRow(ctx,
		`SELECT payload FROM validation_campaigns WHERE id = $1`, id).Scan(&payload)
	if err != nil {
		return c, mapReadError(err, "campaign", id)
	}
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		return c, fmt.Errorf("%w: campaign %q payload: %v", store.ErrCorrupted, id, err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("%w: campaign %q: %v", store.ErrCorrupted, id, err)
	}
	return c, nil
}

func (r *campaignRepo) List(ctx context.Context) ([]validation.Campaign, error) {
	rows, err := r.db.Query(ctx, `SELECT payload FROM validation_campaigns ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list campaigns: %w", err)
	}
	defer rows.Close()
	var out []validation.Campaign
	for rows.Next() {
		var payload string
		var c validation.Campaign
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan campaign: %w", err)
		}
		if err := json.Unmarshal([]byte(payload), &c); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: campaign payload: %v", store.ErrCorrupted, err)
		}
		if err := c.Validate(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: stored campaign: %v", store.ErrCorrupted, err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type exerciseRepo struct{ db dbconn }

func (r *exerciseRepo) Create(ctx context.Context, e validation.Exercise) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("%w: exercise encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO purple_team_exercises (id, payload) VALUES ($1, $2)`, e.ID, string(payload))
	return mapWriteError(err, "exercise", e.ID)
}

func (r *exerciseRepo) Get(ctx context.Context, id string) (validation.Exercise, error) {
	var e validation.Exercise
	var payload string
	err := r.db.QueryRow(ctx,
		`SELECT payload FROM purple_team_exercises WHERE id = $1`, id).Scan(&payload)
	if err != nil {
		return e, mapReadError(err, "exercise", id)
	}
	if err := json.Unmarshal([]byte(payload), &e); err != nil {
		return e, fmt.Errorf("%w: exercise %q payload: %v", store.ErrCorrupted, id, err)
	}
	if err := e.Validate(); err != nil {
		return e, fmt.Errorf("%w: exercise %q: %w", store.ErrCorrupted, id, err)
	}
	return e, nil
}

func (r *exerciseRepo) List(ctx context.Context) ([]validation.Exercise, error) {
	rows, err := r.db.Query(ctx, `SELECT payload FROM purple_team_exercises ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list exercises: %w", err)
	}
	defer rows.Close()
	var out []validation.Exercise
	for rows.Next() {
		var payload string
		var e validation.Exercise
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan exercise: %w", err)
		}
		if err := json.Unmarshal([]byte(payload), &e); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: exercise payload: %v", store.ErrCorrupted, err)
		}
		if err := e.Validate(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: stored exercise payload: %w", store.ErrCorrupted, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// GRC assessments + resilience records (append-only JSON payloads keyed by
// deterministic id). Payloads re-validate on read: corrupt bytes fail
// closed with ErrCorrupted, never as silently dropped rows.
// ---------------------------------------------------------------------------

type assessmentRepo struct{ db dbconn }

func (r *assessmentRepo) Create(ctx context.Context, a grc.Assessment) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("%w: assessment encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO grc_assessments (id, payload) VALUES ($1, $2)`, a.ID(), string(payload))
	return mapWriteError(err, "assessment", a.ID())
}

func (r *assessmentRepo) Get(ctx context.Context, id string) (grc.Assessment, error) {
	var a grc.Assessment
	var payload string
	err := r.db.QueryRow(ctx,
		`SELECT payload FROM grc_assessments WHERE id = $1`, id).Scan(&payload)
	if err != nil {
		return a, mapReadError(err, "assessment", id)
	}
	if err := json.Unmarshal([]byte(payload), &a); err != nil {
		return a, fmt.Errorf("%w: assessment %q payload: %v", store.ErrCorrupted, id, err)
	}
	if err := a.Validate(); err != nil {
		return a, fmt.Errorf("%w: assessment %q: %v", store.ErrCorrupted, id, err)
	}
	return a, nil
}

func (r *assessmentRepo) List(ctx context.Context) ([]grc.Assessment, error) {
	rows, err := r.db.Query(ctx, `SELECT payload FROM grc_assessments ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list assessments: %w", err)
	}
	defer rows.Close()
	var out []grc.Assessment
	for rows.Next() {
		var payload string
		var a grc.Assessment
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan assessment: %w", err)
		}
		if err := json.Unmarshal([]byte(payload), &a); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: assessment payload: %v", store.ErrCorrupted, err)
		}
		if err := a.Validate(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: stored assessment: %v", store.ErrCorrupted, err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type resilienceRepo struct{ db dbconn }

func (r *resilienceRepo) Create(ctx context.Context, rec grc.ResilienceRecord) error {
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("%w: resilience encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO resilience_records (id, payload) VALUES ($1, $2)`, rec.ID, string(payload))
	return mapWriteError(err, "resilience record", rec.ID)
}

func (r *resilienceRepo) Get(ctx context.Context, id string) (grc.ResilienceRecord, error) {
	var rec grc.ResilienceRecord
	var payload string
	err := r.db.QueryRow(ctx,
		`SELECT payload FROM resilience_records WHERE id = $1`, id).Scan(&payload)
	if err != nil {
		return rec, mapReadError(err, "resilience record", id)
	}
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		return rec, fmt.Errorf("%w: resilience record %q payload: %v", store.ErrCorrupted, id, err)
	}
	if err := rec.Validate(); err != nil {
		return rec, fmt.Errorf("%w: resilience record %q: %w", store.ErrCorrupted, id, err)
	}
	return rec, nil
}

func (r *resilienceRepo) List(ctx context.Context) ([]grc.ResilienceRecord, error) {
	rows, err := r.db.Query(ctx, `SELECT payload FROM resilience_records ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list resilience records: %w", err)
	}
	defer rows.Close()
	var out []grc.ResilienceRecord
	for rows.Next() {
		var payload string
		var rec grc.ResilienceRecord
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan resilience record: %w", err)
		}
		if err := json.Unmarshal([]byte(payload), &rec); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: resilience payload: %v", store.ErrCorrupted, err)
		}
		if err := rec.Validate(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: stored resilience payload: %w", store.ErrCorrupted, err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Supply chain (append-only JSON payloads keyed by deterministic id).
// ---------------------------------------------------------------------------

type supplyComponentRepo struct{ db dbconn }

func (r *supplyComponentRepo) Create(ctx context.Context, c supplychain.Component) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("%w: component encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO supply_components (id, payload) VALUES ($1, $2)`, c.ID(), string(payload))
	return mapWriteError(err, "component", c.ID())
}

func supplyGet[T any](ctx context.Context, db dbconn, table, kind, id string, check func(*T) error) (T, error) {
	var zero T
	var payload string
	err := db.QueryRow(ctx, `SELECT payload FROM `+table+` WHERE id = $1`, id).Scan(&payload)
	if err != nil {
		return zero, mapReadError(err, kind, id)
	}
	var out T
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return zero, fmt.Errorf("%w: %s %q payload: %v", store.ErrCorrupted, kind, id, err)
	}
	if err := check(&out); err != nil {
		return zero, fmt.Errorf("%w: %s %q: %v", store.ErrCorrupted, kind, id, err)
	}
	return out, nil
}

func supplyList[T any](ctx context.Context, db dbconn, table, kind string, check func(*T) error) ([]T, error) {
	rows, err := db.Query(ctx, `SELECT payload FROM `+table+` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list %s: %w", table, err)
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var payload string
		var v T
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan %s: %w", table, err)
		}
		if err := json.Unmarshal([]byte(payload), &v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: %s payload: %v", store.ErrCorrupted, table, err)
		}
		if err := check(&v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: stored %s: %v", store.ErrCorrupted, table, err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *supplyComponentRepo) Get(ctx context.Context, id string) (supplychain.Component, error) {
	return supplyGet[supplychain.Component](ctx, r.db, "supply_components", "component", id,
		func(c *supplychain.Component) error { return c.Validate() })
}

func (r *supplyComponentRepo) List(ctx context.Context) ([]supplychain.Component, error) {
	return supplyList[supplychain.Component](ctx, r.db, "supply_components", "component",
		func(c *supplychain.Component) error { return c.Validate() })
}

type supplyDependencyRepo struct{ db dbconn }

func (r *supplyDependencyRepo) Append(ctx context.Context, d supplychain.Dependency) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("%w: dependency encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO supply_dependencies (parent_id, child_id, kind, payload) VALUES ($1, $2, $3, $4)`,
		d.ParentID, d.ChildID, string(d.Kind), string(payload))
	if err != nil {
		if isDuplicate(err) {
			return fmt.Errorf("%w: dependency %s→%s", store.ErrDuplicate, d.ParentID, d.ChildID)
		}
		return fmt.Errorf("postgres: write dependency: %w", err)
	}
	return nil
}

func (r *supplyDependencyRepo) links(ctx context.Context, col, id string) ([]supplychain.Dependency, error) {
	rows, err := r.db.Query(ctx,
		`SELECT payload FROM supply_dependencies WHERE `+col+` = $1 ORDER BY parent_id, child_id, kind`, id)
	if err != nil {
		return nil, fmt.Errorf("postgres: list dependencies: %w", err)
	}
	defer rows.Close()
	var out []supplychain.Dependency
	for rows.Next() {
		var payload string
		var d supplychain.Dependency
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan dependency: %w", err)
		}
		if err := json.Unmarshal([]byte(payload), &d); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: dependency payload: %v", store.ErrCorrupted, err)
		}
		if err := d.Validate(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: stored dependency: %v", store.ErrCorrupted, err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *supplyDependencyRepo) Children(ctx context.Context, parentID string) ([]supplychain.Dependency, error) {
	return r.links(ctx, "parent_id", parentID)
}

func (r *supplyDependencyRepo) Parents(ctx context.Context, childID string) ([]supplychain.Dependency, error) {
	return r.links(ctx, "child_id", childID)
}

type supplySBOMRepo struct{ db dbconn }

func (r *supplySBOMRepo) Create(ctx context.Context, s supplychain.SBOM) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("%w: sbom encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO supply_sboms (id, payload) VALUES ($1, $2)`, s.ID(), string(payload))
	return mapWriteError(err, "sbom", s.ID())
}

func (r *supplySBOMRepo) Get(ctx context.Context, id string) (supplychain.SBOM, error) {
	return supplyGet[supplychain.SBOM](ctx, r.db, "supply_sboms", "sbom", id,
		func(s *supplychain.SBOM) error { return s.Validate() })
}

func (r *supplySBOMRepo) List(ctx context.Context) ([]supplychain.SBOM, error) {
	return supplyList[supplychain.SBOM](ctx, r.db, "supply_sboms", "sbom",
		func(s *supplychain.SBOM) error { return s.Validate() })
}

type supplyPolicyRepo struct{ db dbconn }

func (r *supplyPolicyRepo) Create(ctx context.Context, p supplychain.SupplyPolicy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("%w: policy encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO supply_policies (id, payload) VALUES ($1, $2)`, p.ID, string(payload))
	return mapWriteError(err, "policy", p.ID)
}

func (r *supplyPolicyRepo) Get(ctx context.Context, id string) (supplychain.SupplyPolicy, error) {
	return supplyGet[supplychain.SupplyPolicy](ctx, r.db, "supply_policies", "policy", id,
		func(p *supplychain.SupplyPolicy) error { return p.Validate() })
}

func (r *supplyPolicyRepo) List(ctx context.Context) ([]supplychain.SupplyPolicy, error) {
	return supplyList[supplychain.SupplyPolicy](ctx, r.db, "supply_policies", "policy",
		func(p *supplychain.SupplyPolicy) error { return p.Validate() })
}

type supplyVendorRepo struct{ db dbconn }

func (r *supplyVendorRepo) Create(ctx context.Context, v supplychain.Vendor) error {
	if err := v.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: vendor encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO supply_vendors (id, payload) VALUES ($1, $2)`, v.ID(), string(payload))
	return mapWriteError(err, "vendor", v.ID())
}

func (r *supplyVendorRepo) Get(ctx context.Context, id string) (supplychain.Vendor, error) {
	return supplyGet[supplychain.Vendor](ctx, r.db, "supply_vendors", "vendor", id,
		func(v *supplychain.Vendor) error { return v.Validate() })
}

func (r *supplyVendorRepo) List(ctx context.Context) ([]supplychain.Vendor, error) {
	return supplyList[supplychain.Vendor](ctx, r.db, "supply_vendors", "vendor",
		func(v *supplychain.Vendor) error { return v.Validate() })
}

type supplyVendorAssessmentRepo struct{ db dbconn }

func (r *supplyVendorAssessmentRepo) Create(ctx context.Context, a supplychain.VendorAssessment) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("%w: vendor assessment encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO supply_vendor_assessments (id, payload) VALUES ($1, $2)`, a.ID(), string(payload))
	return mapWriteError(err, "vendor assessment", a.ID())
}

func (r *supplyVendorAssessmentRepo) Get(ctx context.Context, id string) (supplychain.VendorAssessment, error) {
	return supplyGet[supplychain.VendorAssessment](ctx, r.db, "supply_vendor_assessments", "vendor assessment", id,
		func(a *supplychain.VendorAssessment) error { return a.Validate() })
}

func (r *supplyVendorAssessmentRepo) List(ctx context.Context) ([]supplychain.VendorAssessment, error) {
	return supplyList[supplychain.VendorAssessment](ctx, r.db, "supply_vendor_assessments", "vendor assessment",
		func(a *supplychain.VendorAssessment) error { return a.Validate() })
}

type supplyLinkRepo struct{ db dbconn }

func (r *supplyLinkRepo) Create(ctx context.Context, l supplychain.SupplyLink) error {
	if err := l.Validate(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	payload, err := json.Marshal(l)
	if err != nil {
		return fmt.Errorf("%w: supply link encode: %v", store.ErrInvalid, err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO supply_links (id, payload) VALUES ($1, $2)`, l.ID(), string(payload))
	return mapWriteError(err, "supply link", l.ID())
}

func (r *supplyLinkRepo) List(ctx context.Context) ([]supplychain.SupplyLink, error) {
	return supplyList[supplychain.SupplyLink](ctx, r.db, "supply_links", "supply link",
		func(l *supplychain.SupplyLink) error { return l.Validate() })
}
