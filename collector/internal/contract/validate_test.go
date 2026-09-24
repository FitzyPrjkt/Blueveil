// Boundary tests: Step-2 fixtures are the vectors, generated protobuf types
// are the representation, contract validation is the gate.
package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	// Package dir is collector/internal/contract; fixtures live three levels up.
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "fixtures", rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return data
}

func TestValidFixtureCrossesBoundary(t *testing.T) {
	var e v1.TelemetryEvent
	if err := UnmarshalStrict(fixture(t, "telemetry/valid.json"), &e); err != nil {
		t.Fatalf("valid fixture must parse: %v", err)
	}
	if err := ValidateTelemetryEvent(&e); err != nil {
		t.Fatalf("valid fixture must validate: %v", err)
	}
	if e.GetId() != "evt-test-001" || e.GetSeverity() != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("field mapping drift: %+v", &e)
	}

	out, err := MarshalCanonical(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"occurred_at"`) || !strings.Contains(text, `"asset_id"`) {
		t.Fatalf("canonical JSON must use snake_case keys: %s", text)
	}
	if strings.Contains(text, "occurredAt") || strings.Contains(text, "assetId") {
		t.Fatalf("canonical JSON must not use camelCase keys: %s", text)
	}
	if !strings.Contains(text, `"SEVERITY_HIGH"`) {
		t.Fatalf("severity must serialize as enum name: %s", text)
	}
}

func TestInvalidFixtureRejectedAtBoundary(t *testing.T) {
	// Missing severity: proto3 parsing succeeds (defaults), so the
	// contract boundary — not the parser — must reject it.
	var e v1.TelemetryEvent
	if err := UnmarshalStrict(fixture(t, "telemetry/invalid.json"), &e); err != nil {
		t.Fatalf("missing-field fixture parses by proto3 rules: %v", err)
	}
	if err := ValidateTelemetryEvent(&e); err == nil {
		t.Fatal("boundary must reject the severity-less event")
	}
}

func TestUnknownEnumRejectedAtParse(t *testing.T) {
	var id v1.Identity
	if err := UnmarshalStrict(fixture(t, "identity/invalid.json"), &id); err == nil {
		t.Fatal("unknown enum IDENTITY_TYPE_ROOT must fail parsing")
	}
}

func TestCodegenCoversAllContractMessages(t *testing.T) {
	// Every Step-2 valid fixture must parse into its generated type:
	// proves codegen is complete and no schema drifted.
	parsers := map[string]func([]byte) error{
		"asset/valid.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.Asset{})
		},
		"identity/valid.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.Identity{})
		},
		"telemetry/valid.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.TelemetryEvent{})
		},
		"detection/valid.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.Detection{})
		},
		"alert/valid.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.Alert{})
		},
		"incident/valid.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.Incident{})
		},
		"evidence/valid.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.Evidence{})
		},
		"validation/valid_request.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.ValidationRequest{})
		},
		"validation/valid_result.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.ValidationResult{})
		},
		"validation/valid_result_not_tested.json": func(b []byte) error {
			return UnmarshalStrict(b, &v1.ValidationResult{})
		},
	}
	order := []string{
		"asset/valid.json", "identity/valid.json", "telemetry/valid.json",
		"detection/valid.json", "alert/valid.json", "incident/valid.json",
		"evidence/valid.json", "validation/valid_request.json",
		"validation/valid_result.json", "validation/valid_result_not_tested.json",
	}
	for _, f := range order {
		if err := parsers[f](fixture(t, f)); err != nil {
			t.Errorf("valid fixture %s must parse into generated type: %v", f, err)
		}
	}
}

func TestNoSecureVerdictInContract(t *testing.T) {
	foundNotTested := false
	for _, name := range v1.ValidationVerdict_name {
		if strings.Contains(name, "SECURE") {
			t.Fatalf("contract must never gain a SECURE verdict silently: %s", name)
		}
		if name == "VALIDATION_VERDICT_NOT_TESTED" {
			foundNotTested = true
		}
	}
	if !foundNotTested {
		t.Fatal("NOT_TESTED verdict missing from generated contract")
	}
}
