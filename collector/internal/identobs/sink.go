// CorrelatingSink for identity/auth/data observations: redacts sensitive
// attributes in-place, correlates, then forwards the redacted event
// downstream untouched otherwise. Non-identity events pass through.
package identobs

import (
	"context"
	"errors"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

// Downstream is the next sink in the pipeline chain.
type Downstream interface {
	Emit(ctx context.Context, e *v1.TelemetryEvent) error
}

// CorrelatingSink observes identity/auth/data telemetry for asset
// correlation. Duplicate relationships are idempotent.
type CorrelatingSink struct {
	correlator *IdentCorrelator
	downstream Downstream
}

// NewCorrelatingSink validates its arguments; nil is a construction error.
func NewCorrelatingSink(correlator *IdentCorrelator, downstream Downstream) (*CorrelatingSink, error) {
	if correlator == nil {
		return nil, errors.New("identobs: correlator is nil")
	}
	if downstream == nil {
		return nil, errors.New("identobs: downstream is nil")
	}
	return &CorrelatingSink{correlator: correlator, downstream: downstream}, nil
}

// Emit redacts, correlates, then forwards. Malformed identity observations
// fail explicitly (fail-closed); anything else is a real error.
func (s *CorrelatingSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	switch e.GetEventType() {
	case EventTypeIdentityActivity, EventTypeAuthActivity, EventTypeDataActivity:
		for k := range e.GetAttributes() {
			if contract.SensitiveField(k) {
				delete(e.GetAttributes(), k)
			}
		}
		if _, err := s.correlator.Correlate(ctx, e); err != nil {
			if !errors.Is(err, store.ErrDuplicate) {
				return err
			}
		}
	}
	return s.downstream.Emit(ctx, e)
}
