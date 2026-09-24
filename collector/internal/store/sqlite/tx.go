// Explicit transaction boundary: incident creation together with its
// initial evidence commits atomically, or rolls back entirely. This is the
// one cross-entity atomic unit the domain requires (an incident must never
// exist half-recorded while its first evidence fails). Anything failing
// inside returns an explicit error with nothing persisted.
package sqlite

import (
	"context"
	"fmt"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

// CreateIncidentWithEvidence stores the incident and its initial evidence in
// one transaction. Evidence must reference this incident; any failure rolls
// back the whole unit (tested: duplicate evidence id leaves no incident).
func CreateIncidentWithEvidence(ctx context.Context, db *DB, inc *v1.Incident, items []*v1.Evidence) error {
	if err := contract.ValidateIncident(inc); err != nil {
		return fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	for _, e := range items {
		if err := contract.ValidateEvidence(e); err != nil {
			return fmt.Errorf("%w: %w", store.ErrInvalid, err)
		}
		if e.GetIncidentId() != inc.GetId() {
			return fmt.Errorf("%w: evidence %q belongs to %q, not %q",
				store.ErrInvalid, e.GetId(), e.GetIncidentId(), inc.GetId())
		}
	}
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: tx begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO incidents (id, alert_ids, status, severity, created_at, updated_at, title, summary)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		inc.GetId(), encodeList(inc.GetAlertIds()), int32(inc.GetStatus()), int32(inc.GetSeverity()),
		encodeTime(inc.GetCreatedAt()), encodeTime(inc.GetUpdatedAt()), inc.GetTitle(),
		nullString(inc.GetSummary())); err != nil {
		return mapWriteErrorTx(err, "incident", inc.GetId())
	}
	for _, e := range items {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO evidence (id, incident_id, type, collected_at, source, media_type, sha256, content)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.GetId(), e.GetIncidentId(), int32(e.GetType()), encodeTime(e.GetCollectedAt()),
			e.GetSource(), e.GetMediaType(), nullString(e.GetSha256()), e.GetContent()); err != nil {
			return mapWriteErrorTx(err, "evidence", e.GetId())
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: tx commit: %w", err)
	}
	return nil
}

func mapWriteErrorTx(err error, kind, id string) error {
	if isDuplicate(err) {
		return fmt.Errorf("%w: %s %q", store.ErrDuplicate, kind, id)
	}
	return fmt.Errorf("sqlite: tx write %s %q: %w", kind, id, err)
}
