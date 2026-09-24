// Package enrich adds deterministic, local collection metadata to an
// already-normalized TelemetryEvent. It performs no lookup, no inference,
// no threat intelligence: two keys under the blueveil.* namespace.
//
//   - blueveil.collector: the collecting instance (constructor-provided).
//   - blueveil.collected_at: collection time, RFC 3339 (clock-provided,
//     so tests pin it exactly).
//
// Rules: never overwrite a key the source already set (conflict = error);
// never invent values (zero clock = error). Enrichment failure is a
// pipeline rejection, not a detection.
package enrich

import (
	"errors"
	"fmt"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

// ErrEnrichment marks every enrichment failure.
var ErrEnrichment = errors.New("enrich: enrichment failure")

// Keys added by Enrich. Nothing else is ever added here.
const (
	KeyCollector   = "blueveil.collector"
	KeyCollectedAt = "blueveil.collected_at"
)

// Enricher is immutable after construction; the zero value is invalid.
type Enricher struct {
	collector string
	clock     func() time.Time
}

// New validates its inputs: empty collector name or nil clock is a
// construction error, never a silent default.
func New(collectorName string, clock func() time.Time) (Enricher, error) {
	if collectorName == "" {
		return Enricher{}, fmt.Errorf("%w: collector name is empty", ErrEnrichment)
	}
	if clock == nil {
		return Enricher{}, fmt.Errorf("%w: clock is nil", ErrEnrichment)
	}
	return Enricher{collector: collectorName, clock: clock}, nil
}

// CollectorName reports the configured collector identity.
func (e Enricher) CollectorName() string { return e.collector }

// Enrich stamps collection metadata onto event in place.
func (e Enricher) Enrich(event *v1.TelemetryEvent) error {
	if event == nil {
		return fmt.Errorf("%w: event is nil", ErrEnrichment)
	}
	now := e.clock()
	if now.IsZero() {
		return fmt.Errorf("%w: clock returned zero time (collection time unknown, not invented)", ErrEnrichment)
	}
	attrs := event.GetAttributes()
	if attrs == nil {
		attrs = make(map[string]string, 2)
	}
	add := map[string]string{
		KeyCollector:   e.collector,
		KeyCollectedAt: now.UTC().Format(time.RFC3339),
	}
	for k, v := range add {
		if _, exists := attrs[k]; exists {
			return fmt.Errorf("%w: refusing to overwrite source-provided %q", ErrEnrichment, k)
		}
		attrs[k] = v
	}
	event.Attributes = attrs
	return nil
}
