// Incident/Evidence validators checked against the Step-2 fixtures.
package contract

import (
	v1 "blueveil/collector/internal/contract/v1"
	"testing"
)

func TestIncidentFixturesValidate(t *testing.T) {
	var good v1.Incident
	if err := UnmarshalStrict(fixture(t, "incident/valid.json"), &good); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateIncident(&good); err != nil {
		t.Fatalf("valid incident must validate: %v", err)
	}
	if len(good.GetAlertIds()) == 0 {
		t.Fatal("valid incident must reference its alerts")
	}

	var bad v1.Incident
	if err := UnmarshalStrict(fixture(t, "incident/invalid.json"), &bad); err == nil {
		t.Fatalf("bad timestamp must fail parsing, got %+v", &bad)
	}
}

func TestEvidenceFixturesValidate(t *testing.T) {
	var good v1.Evidence
	if err := UnmarshalStrict(fixture(t, "evidence/valid.json"), &good); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateEvidence(&good); err != nil {
		t.Fatalf("valid evidence must validate: %v", err)
	}
	if good.GetIncidentId() == "" || good.GetSha256() == "" {
		t.Fatal("valid evidence must carry linkage and digest")
	}

	var bad v1.Evidence
	if err := UnmarshalStrict(fixture(t, "evidence/invalid.json"), &bad); err != nil {
		t.Fatalf("bad-hash fixture parses by proto3 rules: %v", err)
	}
	if err := ValidateEvidence(&bad); err == nil {
		t.Fatal("boundary must reject the bad sha256")
	}
}
