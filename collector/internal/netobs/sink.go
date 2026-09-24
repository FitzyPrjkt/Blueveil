package netobs

import (
	"context"
	"errors"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

// CorrelatingSink observes every TelemetryEvent, and for net.connection
// events runs the asset correlation (resolve-or-observe + COMMUNICATES_WITH
// edge) without ever blocking telemetry: malformed network data fails
// closed via the correlator's explicit error, which the sink surfaces as
// an ingestion error so pipeline rejections stay visible. Non-network
// events pass through untouched. Relationships are persisted via the
// correlator's store; telemetry itself flows to downstream unchanged.
type CorrelatingSink struct {
	correlator *Correlator
	downstream Downstream
}

// Downstream is the next sink in the pipeline chain.
type Downstream interface {
	Emit(ctx context.Context, e *v1.TelemetryEvent) error
}

// NewCorrelatingSink validates its arguments; nil is a construction error.
func NewCorrelatingSink(correlator *Correlator, downstream Downstream) (*CorrelatingSink, error) {
	if correlator == nil {
		return nil, errors.New("netobs: correlator is nil")
	}
	if downstream == nil {
		return nil, errors.New("netobs: downstream is nil")
	}
	return &CorrelatingSink{correlator: correlator, downstream: downstream}, nil
}

// Emit correlates network observations, then forwards the original event.
// Duplicate relationships are idempotent (already recorded). Unresolved
// external endpoints are preserved without blocking. Malformed network
// observations fail explicitly.
func (s *CorrelatingSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	if e.GetEventType() == EventTypeConnection {
		if _, err := s.correlator.Correlate(ctx, e); err != nil {
			// Duplicate relationship is not an error — Correlate already
			// swallows ErrDuplicate and reports RelRecorded. Any other
			// error is a real normalization/correlation failure.
			if !errors.Is(err, store.ErrDuplicate) {
				return err
			}
		}
	}
	return s.downstream.Emit(ctx, e)
}
