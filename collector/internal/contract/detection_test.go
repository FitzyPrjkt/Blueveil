// Detection/Alert validators checked against the Step-2 fixtures:
// valid fixtures must pass, invalid ones must fail. Same vectors the Rust
// core and the JSON Schemas use — three implementations, one contract.
package contract

import (
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestDetectionFixturesValidate(t *testing.T) {
	var good v1.Detection
	if err := UnmarshalStrict(fixture(t, "detection/valid.json"), &good); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateDetection(&good); err != nil {
		t.Fatalf("valid detection must validate: %v", err)
	}
	if good.GetConfidence() < 0.0 || good.GetConfidence() > 1.0 {
		t.Fatalf("fixture confidence out of range: %v", good.GetConfidence())
	}

	var bad v1.Detection
	if err := UnmarshalStrict(fixture(t, "detection/invalid.json"), &bad); err != nil {
		t.Fatalf("empty-list fixture parses by proto3 rules: %v", err)
	}
	if err := ValidateDetection(&bad); err == nil {
		t.Fatal("boundary must reject the event-less detection")
	}
}

func TestAlertFixturesValidate(t *testing.T) {
	var good v1.Alert
	if err := UnmarshalStrict(fixture(t, "alert/valid.json"), &good); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateAlert(&good); err != nil {
		t.Fatalf("valid alert must validate: %v", err)
	}
	if len(good.GetDetectionIds()) == 0 {
		t.Fatal("valid alert must reference its detection")
	}

	var bad v1.Alert
	if err := UnmarshalStrict(fixture(t, "alert/invalid.json"), &bad); err == nil {
		t.Fatalf("unknown alert status must fail parsing, got %+v", &bad)
	}
}
