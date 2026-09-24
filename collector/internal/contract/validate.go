// Package contract is the Go view of the Blueveil contract layer (v1).
//
// Message types live in v1/ and are generated from ../contracts/proto —
// DO NOT EDIT generated files; regenerate with the command in
// collector/README.md. This file holds only boundary validation and
// canonical-JSON helpers. Requiredness mirrors check_telemetry_event
// (Rust core) and telemetry_event.schema.json.
package contract

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

// requireTimestamp enforces a present AND well-formed timestamp.
// Nil-checks alone accept native-constructed garbage (negative seconds,
// out-of-range nanos); CheckValid rejects it explicitly.
func requireTimestamp(ts *timestamppb.Timestamp, what string) error {
	if ts == nil {
		return fmt.Errorf("contract: %s: missing", what)
	}
	if err := ts.CheckValid(); err != nil {
		return fmt.Errorf("contract: %s: invalid: %v", what, err)
	}
	return nil
}

// ContractVersion is the contract package this collector speaks.
const ContractVersion = "blueveil.contracts.v1"

// ValidateTelemetryEvent enforces the contract boundary for a normalized
// event: required fields present, enums explicit (never UNSPECIFIED).
func ValidateTelemetryEvent(e *v1.TelemetryEvent) error {
	if e == nil {
		return fmt.Errorf("contract: TelemetryEvent is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", e.GetId()},
		{"source", e.GetSource()},
		{"asset_id", e.GetAssetId()},
		{"event_type", e.GetEventType()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: TelemetryEvent.%s: empty", f.name)
		}
	}
	if err := requireTimestamp(e.GetOccurredAt(), "TelemetryEvent.occurred_at"); err != nil {
		return err
	}
	if err := checkSeverityValue(int32(e.GetSeverity()), "TelemetryEvent.severity"); err != nil {
		return err
	}
	return nil
}

// MarshalCanonical serializes with original (snake_case) field names,
// matching the canonical JSON form of the contract layer.
func MarshalCanonical(m proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
}

// UnmarshalStrict parses canonical JSON, rejecting unknown fields.
// Unknown enum names are rejected; missing fields default (proto3) and
// must be caught by ValidateTelemetryEvent afterwards.
func UnmarshalStrict(data []byte, m proto.Message) error {
	return protojson.UnmarshalOptions{DiscardUnknown: false}.Unmarshal(data, m)
}
