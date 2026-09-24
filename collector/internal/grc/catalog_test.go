// RED: synthetic versioned baseline catalog + explicit mappings.
package grc

import (
	"testing"
)

func TestBaselineCatalog(t *testing.T) {
	fw := BaselineFramework()
	if fw.ID == "" || fw.Version == "" {
		t.Fatalf("framework identity required: %+v", fw)
	}
	if fw.Kind != FrameworkInternal {
		t.Fatalf("lab catalog must be marked internal, got %q", fw.Kind)
	}
	controls := BaselineControls()
	if len(controls) < 6 {
		t.Fatalf("baseline needs a small useful set, got %d", len(controls))
	}
	seen := map[string]bool{}
	domains := map[Domain]bool{}
	for _, c := range controls {
		if err := c.Validate(); err != nil {
			t.Errorf("catalog control invalid: %v", err)
		}
		if c.Framework != fw.ID || c.FrameworkVersion != fw.Version {
			t.Errorf("control %s must reference the baseline framework", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("duplicate control %s", c.ID)
		}
		seen[c.ID] = true
		domains[c.Domain] = true
	}
	if len(domains) < 3 {
		t.Errorf("catalog should span domains, got %v", domains)
	}
	// Deterministic order.
	again := BaselineControls()
	for i := range controls {
		if controls[i].ID != again[i].ID {
			t.Fatalf("catalog order unstable")
		}
	}
}

func TestControlMappingValidate(t *testing.T) {
	m := ControlMapping{ControlID: "AC-1", SourceType: SourceEvidence, SourceID: "ev-1"}
	if err := m.Validate(); err != nil {
		t.Fatalf("valid mapping: %v", err)
	}
	for name, mut := range map[string]func(*ControlMapping){
		"empty control": func(m *ControlMapping) { m.ControlID = "" },
		"bad source":    func(m *ControlMapping) { m.SourceType = "vibes" },
		"empty id":      func(m *ControlMapping) { m.SourceID = "" },
	} {
		bad := m
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Timestamp-only "mapping" has no representation: a mapping without a
	// real source id is rejected.
	bare := ControlMapping{ControlID: "AC-1", SourceType: SourceEvidence, SourceID: ""}
	if err := bare.Validate(); err == nil {
		t.Errorf("id-less mapping must be rejected")
	}
}

func TestMappingKindsBounded(t *testing.T) {
	for _, s := range []SourceType{
		SourceAsset, SourceTelemetry, SourceDetection, SourceAlert,
		SourceIncident, SourceEvidence, SourceValidationResult,
		SourceResponseAudit,
	} {
		if string(s) == "" {
			t.Errorf("empty source type")
		}
	}
}
