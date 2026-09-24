// Pipeline persistence: after a pipeline Run completes, accepted outputs
// move into repositories in dependency order (telemetry → detection →
// alert → incident → evidence). Every object is re-validated at this
// boundary even though producers already validated: invalid input (e.g. a
// hand-poisoned archive) aborts with nothing persisted. DB failures stay
// errors — never successful security states.
//
// Response/validation/audit records persist through their own repository
// calls (engine-owned), not here: the telemetry pipeline ends at evidence
// by architecture, and this helper does not extend it.
package sqlite

import (
	"context"
	"fmt"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

// PipelineOutputs is the durable subset of one pipeline run.
type PipelineOutputs struct {
	Telemetry  []*v1.TelemetryEvent
	Detections []*v1.Detection
	Alerts     []*v1.Alert
	Incidents  []*v1.Incident
	Evidence   []*v1.Evidence
}

// validateOutputs re-validates every object at the persistence boundary:
// invalid input (e.g. a hand-poisoned archive) aborts with nothing
// persisted.
func validateOutputs(out PipelineOutputs) error {
	for _, e := range out.Telemetry {
		if err := contract.ValidateTelemetryEvent(e); err != nil {
			return fmt.Errorf("%w: telemetry: %w", store.ErrInvalid, err)
		}
	}
	for _, d := range out.Detections {
		if err := contract.ValidateDetection(d); err != nil {
			return fmt.Errorf("%w: detection: %w", store.ErrInvalid, err)
		}
	}
	for _, a := range out.Alerts {
		if err := contract.ValidateAlert(a); err != nil {
			return fmt.Errorf("%w: alert: %w", store.ErrInvalid, err)
		}
	}
	for _, in := range out.Incidents {
		if err := contract.ValidateIncident(in); err != nil {
			return fmt.Errorf("%w: incident: %w", store.ErrInvalid, err)
		}
	}
	for _, e := range out.Evidence {
		if err := contract.ValidateEvidence(e); err != nil {
			return fmt.Errorf("%w: evidence: %w", store.ErrInvalid, err)
		}
	}
	return nil
}

// writeOutputs persists in FK-safe order over one backend. Callers needing
// atomicity use PersistRunTx; this helper is shared by both paths.
func writeOutputs(ctx context.Context, backend store.Backend, out PipelineOutputs) error {
	for _, e := range out.Telemetry {
		if err := backend.Telemetry.Append(ctx, e); err != nil {
			return fmt.Errorf("persist telemetry %q: %w", e.GetId(), err)
		}
	}
	for _, d := range out.Detections {
		if err := backend.Detection.Append(ctx, d); err != nil {
			return fmt.Errorf("persist detection %q: %w", d.GetId(), err)
		}
	}
	for _, a := range out.Alerts {
		if err := backend.Alert.Append(ctx, a); err != nil {
			return fmt.Errorf("persist alert %q: %w", a.GetId(), err)
		}
	}
	for _, in := range out.Incidents {
		if err := backend.Incident.Create(ctx, in); err != nil {
			return fmt.Errorf("persist incident %q: %w", in.GetId(), err)
		}
	}
	for _, e := range out.Evidence {
		if err := backend.Evidence.Append(ctx, e); err != nil {
			return fmt.Errorf("persist evidence %q: %w", e.GetId(), err)
		}
	}
	return nil
}

// PersistRun validates everything first, then writes in FK-safe order over
// any backend. Mid-write failures surface explicitly; callers needing a
// torn run to be impossible use PersistRunTx on SQLite.
func PersistRun(ctx context.Context, backend store.Backend, out PipelineOutputs) error {
	if err := validateOutputs(out); err != nil {
		return err
	}
	return writeOutputs(ctx, backend, out)
}

// PersistRunTx validates everything first, then writes the whole run in
// ONE transaction: a mid-batch failure rolls back telemetry, detections,
// alerts, incidents, and evidence together, so a restart never reads a
// half-run as complete.
func PersistRunTx(ctx context.Context, db *DB, out PipelineOutputs) error {
	if err := validateOutputs(out); err != nil {
		return err
	}
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: tx begin: %w", err)
	}
	defer tx.Rollback()
	if err := writeOutputs(ctx, backendOver(tx), out); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: tx commit: %w", err)
	}
	return nil
}
