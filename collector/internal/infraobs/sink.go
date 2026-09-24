package infraobs

import (
	"context"
	"errors"
	"strings"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

type Downstream interface {
	Emit(ctx context.Context, e *v1.TelemetryEvent) error
}

type CorrelatingSink struct {
	correlator *InfraCorrelator
	downstream Downstream
}

func NewCorrelatingSink(correlator *InfraCorrelator, downstream Downstream) (*CorrelatingSink, error) {
	if correlator == nil {
		return nil, errors.New("infraobs: correlator is nil")
	}
	if downstream == nil {
		return nil, errors.New("infraobs: downstream is nil")
	}
	return &CorrelatingSink{correlator: correlator, downstream: downstream}, nil
}

func (s *CorrelatingSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	switch e.GetEventType() {
	case EventTypeEndpointActivity, EventTypeServerActivity, EventTypeContainerActivity, EventTypeCloudActivity:
		// Redact sensitive attributes already done in Parse, but ensure stored event is redacted
		for k := range e.Attributes {
			low := strings.ToLower(k)
			if contract.SensitiveField(k) {
				delete(e.Attributes, k)
				continue
			}
			// Also redact command value
			if low == "endpoint.command" {
				e.Attributes[k] = redactCommand(e.Attributes[k])
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
