// Package normalize is the boundary RawEvent -> contract TelemetryEvent.
//
// The normalizer maps only fields the source actually provided, invents no
// metadata, performs no detection, and adds no fields outside the contract.
// Anything contract-invalid is rejected with an explicit error.
package normalize

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/source"
)

var (
	// ErrInvalidSourceEvent: the raw event is structurally unusable
	// (missing source-assigned identity: id, source, asset, type).
	ErrInvalidSourceEvent = errors.New("normalize: invalid source event")
	// ErrNormalization: a value could not be mapped (bad severity name,
	// out-of-range timestamp).
	ErrNormalization = errors.New("normalize: normalization failure")
	// ErrContractValidation: the mapped message failed the contract boundary.
	ErrContractValidation = errors.New("normalize: contract validation failure")
)

// Normalizer is stateless; construct with New.
type Normalizer struct{}

// New returns a Normalizer.
func New() Normalizer { return Normalizer{} }

// Normalize maps one raw event to a contract-valid *v1.TelemetryEvent.
// Empty optional fields (identity, attributes, raw) stay unset; empty
// severity or zero timestamp are passed through as unset so the contract
// boundary — not invented data — rejects them.
func (Normalizer) Normalize(raw source.RawEvent) (*v1.TelemetryEvent, error) {
	if raw.ID == "" || raw.Source == "" || raw.AssetID == "" || raw.EventType == "" {
		return nil, fmt.Errorf("%w: id/source/asset_id/event_type are required, got %+v",
			ErrInvalidSourceEvent, summarizeRaw(raw))
	}

	severity := v1.Severity_SEVERITY_UNSPECIFIED
	if raw.Severity != "" {
		v, ok := v1.Severity_value[raw.Severity]
		if !ok {
			return nil, fmt.Errorf("%w: unknown severity %q", ErrNormalization, raw.Severity)
		}
		severity = v1.Severity(v)
	}

	var occurredAt *timestamppb.Timestamp
	if !raw.OccurredAt.IsZero() {
		occurredAt = timestamppb.New(raw.OccurredAt)
		if occurredAt == nil {
			return nil, fmt.Errorf("%w: timestamp out of range %v", ErrNormalization, raw.OccurredAt)
		}
	}

	event := &v1.TelemetryEvent{
		Id:         raw.ID,
		OccurredAt: occurredAt,
		Source:     raw.Source,
		AssetId:    raw.AssetID,
		IdentityId: raw.IdentityID,
		EventType:  raw.EventType,
		Severity:   severity,
		Attributes: copyAttrs(raw.Attributes),
		Raw:        raw.Raw,
	}
	if err := contract.ValidateTelemetryEvent(event); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContractValidation, err)
	}
	return event, nil
}

type rawKeys struct {
	ID, Source, AssetID, EventType string
}

func summarizeRaw(r source.RawEvent) rawKeys {
	return rawKeys{ID: r.ID, Source: r.Source, AssetID: r.AssetID, EventType: r.EventType}
}

func copyAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
