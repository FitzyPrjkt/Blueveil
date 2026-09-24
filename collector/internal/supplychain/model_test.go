// RED: bounded supply-chain component model — deterministic identity,
// no invented versions, no inferred vulnerability.
package supplychain

import (
	"testing"
	"time"
)

func TestComponentValidate(t *testing.T) {
	c := Component{
		Type: ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
		Version: "1.3.0", Digest: "sha256:abc123",
		Provenance: ProvenanceLockfile, Source: "seed-lab-supply-chain",
		ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		Status:     StatusObserved,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid component: %v", err)
	}
	for name, mut := range map[string]func(*Component){
		"empty name":      func(c *Component) { c.Name = "" },
		"empty ecosystem": func(c *Component) { c.Ecosystem = "" },
		"bad type":        func(c *Component) { c.Type = "firmware-blob" },
		"bad provenance":  func(c *Component) { c.Provenance = "vibes" },
		"bad status":      func(c *Component) { c.Status = "SECURE" },
		"empty source":    func(c *Component) { c.Source = "" },
		"zero time":       func(c *Component) { c.ObservedAt = time.Time{} },
		"status no basis": func(c *Component) { c.Status = StatusVerified },
	} {
		bad := c
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestComponentDeterministicID(t *testing.T) {
	mk := func() Component {
		return Component{
			Type: ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
			Version: "1.3.0", Provenance: ProvenanceManifest,
			Source: "s", ObservedAt: time.Now().UTC(), Status: StatusObserved,
		}
	}
	a, b := mk(), mk()
	if a.ID() == "" || a.ID() != b.ID() {
		t.Fatalf("component id must be deterministic")
	}
	other := mk()
	other.Version = "2.0.0"
	if other.ID() == a.ID() {
		t.Fatalf("different version must differ")
	}
	// Ecosystem case folds into the same identity.
	folded := mk()
	folded.Ecosystem = "NPM"
	if folded.ID() != a.ID() {
		t.Fatalf("ecosystem must normalize case")
	}
}

func TestComponentNoVersionInvented(t *testing.T) {
	c := Component{
		Type: ComponentPackage, Ecosystem: "pypi", Name: "requests",
		Provenance: ProvenanceManifest, Source: "s",
		ObservedAt: time.Now().UTC(), Status: StatusNotAssessed,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("versionless component must be allowed: %v", err)
	}
	if c.Version != "" {
		t.Fatalf("version must stay empty, not invented")
	}
}

func TestComponentStatusesBounded(t *testing.T) {
	for _, s := range []ComponentStatus{
		StatusObserved, StatusVerified, StatusOutdated, StatusUnsupported,
		StatusPolicyViolation, StatusNotAssessed, StatusUnknown,
	} {
		if string(s) == "" {
			t.Errorf("empty component status")
		}
	}
}
