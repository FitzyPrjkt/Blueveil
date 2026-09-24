package httpobs

import (
	"context"
	"errors"
	"strings"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

// CorrelatingSink redacts sensitive HTTP attributes, correlates each
// http.request observation to asset inventory (URL/DOMAIN/APPLICATION/
// SERVICE), and forwards the (now redacted) event downstream. Non-HTTP
// events pass through untouched.
type CorrelatingSink struct {
	correlator *HTTPCorrelator
	downstream Downstream
}

type Downstream interface {
	Emit(ctx context.Context, e *v1.TelemetryEvent) error
}

func NewCorrelatingSink(correlator *HTTPCorrelator, downstream Downstream) (*CorrelatingSink, error) {
	if correlator == nil {
		return nil, errors.New("httpobs: correlator is nil")
	}
	if downstream == nil {
		return nil, errors.New("httpobs: downstream is nil")
	}
	return &CorrelatingSink{correlator: correlator, downstream: downstream}, nil
}

func (s *CorrelatingSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	if e.GetEventType() == EventTypeHTTPRequest {
		// Redact sensitive attributes in-place before persistence
		// (canonical fragments; raw_body is an HTTP-layer extra).
		for k := range e.Attributes {
			low := strings.ToLower(k)
			if contract.SensitiveField(k) || strings.Contains(low, rawBodyFragment) {
				delete(e.Attributes, k)
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
