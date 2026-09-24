// RED: continuous checks C1–C5 over persisted state. Deterministic,
// policy-driven, no compromise verdicts.
package supplychain

import (
	"testing"
	"time"
)

func contNow() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }

func contComp(ecosystem, name, version string) Component {
	return Component{
		Type: ComponentLibrary, Ecosystem: ecosystem, Name: name, Version: version,
		Provenance: ProvenanceLockfile, Source: "s", ObservedAt: contNow(),
		Status: StatusObserved,
	}
}

func TestCheckMissingSBOM(t *testing.T) {
	cfg := CheckConfig{RequireSBOM: true, Enabled: map[CheckID]bool{CheckIDMissingSBOM: true}}
	comps := []Component{contComp("npm", "left-pad", "1.0.0")}
	sboms := []SBOM{{Format: SBOMCycloneDX, FormatVersion: "1.6", ComponentIDs: []string{"other"}, GeneratedAt: contNow(), Source: "s"}}
	got := CheckMissingSBOM(comps[0], sboms, cfg)
	if got.Outcome != CheckFail {
		t.Fatalf("component without SBOM must fail: %+v", got)
	}
	if got.RuleID != CheckIDMissingSBOM || got.SubjectID == "" || got.Basis == "" {
		t.Fatalf("check identity/basis: %+v", got)
	}
	covered := []SBOM{{Format: SBOMCycloneDX, FormatVersion: "1.6", ComponentIDs: []string{comps[0].ID()}, GeneratedAt: contNow(), Source: "s"}}
	if got := CheckMissingSBOM(comps[0], covered, cfg); got.Outcome != CheckPass {
		t.Fatalf("covered component must pass: %+v", got)
	}
	// Disabled check reports disabled, never evaluates.
	cfg.Enabled[CheckIDMissingSBOM] = false
	if got := CheckMissingSBOM(comps[0], sboms, cfg); got.Outcome != CheckDisabled {
		t.Fatalf("disabled check must report disabled: %+v", got)
	}
}

func TestCheckProvenance(t *testing.T) {
	cfg := CheckConfig{
		RequireProvenance: true,
		AllowedProvenance: []Provenance{ProvenanceLockfile},
		Enabled:           map[CheckID]bool{CheckIDUnverifiedProvenance: true},
	}
	c := contComp("npm", "left-pad", "1.0.0")
	if got := CheckUnverifiedProvenance(c, cfg); got.Outcome != CheckPass {
		t.Fatalf("lockfile provenance must pass: %+v", got)
	}
	c.Provenance = ProvenanceManifest
	if got := CheckUnverifiedProvenance(c, cfg); got.Outcome != CheckFail {
		t.Fatalf("non-allowed provenance must fail: %+v", got)
	}
	cfg.RequireProvenance = false
	cfg.AllowedProvenance = nil
	if got := CheckUnverifiedProvenance(c, cfg); got.Outcome != CheckNotApplicable {
		t.Fatalf("unconfigured check must be not-applicable: %+v", got)
	}
}

func TestCheckPolicyViolation(t *testing.T) {
	pol := SupplyPolicy{
		ID: "pol-1", Name: "n", Source: "s",
		AllowedEcosystems: []string{"go"},
	}
	cfg := CheckConfig{Policies: []SupplyPolicy{pol}, Enabled: map[CheckID]bool{CheckIDPolicyViolation: true}}
	c := contComp("npm", "left-pad", "1.0.0")
	got := CheckPolicyViolation(c, cfg)
	if got.Outcome != CheckFail {
		t.Fatalf("policy mismatch must fail: %+v", got)
	}
	if got.Basis == "" {
		t.Fatalf("explicit basis required: %+v", got)
	}
	c2 := contComp("go", "mod", "1.0.0")
	if got := CheckPolicyViolation(c2, cfg); got.Outcome != CheckPass {
		t.Fatalf("matching component must pass: %+v", got)
	}
}

func TestCheckStaleVendor(t *testing.T) {
	now := contNow()
	cfg := CheckConfig{
		VendorWindow: 30 * 24 * time.Hour,
		Enabled:      map[CheckID]bool{CheckIDStaleVendor: true},
	}
	old := VendorAssessment{
		VendorID: "vend-1", Status: VendorReviewed, Assessor: "a",
		ObservedAt: now.Add(-40 * 24 * time.Hour),
	}
	if got := CheckStaleVendor("vend-1", []VendorAssessment{old}, cfg, now); got.Outcome != CheckFail {
		t.Fatalf("stale assessment must fail: %+v", got)
	}
	fresh := old
	fresh.ObservedAt = now
	if got := CheckStaleVendor("vend-1", []VendorAssessment{fresh}, cfg, now); got.Outcome != CheckPass {
		t.Fatalf("fresh assessment must pass: %+v", got)
	}
	if got := CheckStaleVendor("vend-9", nil, cfg, now); got.Outcome != CheckNotApplicable {
		t.Fatalf("missing assessment must be not-applicable, not failure: %+v", got)
	}
}

func TestCheckRegression(t *testing.T) {
	cfg := CheckConfig{Enabled: map[CheckID]bool{CheckIDRegression: true}}
	prev := map[string]ComponentStatus{"comp-1": StatusVerified}
	cur := contComp("npm", "x", "1.0.0")
	cur.Status = StatusObserved
	cur.StatusBasis = "downgraded in lab"
	if got := CheckRegression("comp-1", cur, prev, cfg); got.Outcome != CheckFail {
		t.Fatalf("verified→observed must fail: %+v", got)
	}
	same := cur
	same.Status = StatusVerified
	if got := CheckRegression("comp-1", same, prev, cfg); got.Outcome != CheckPass {
		t.Fatalf("unchanged status must pass: %+v", got)
	}
	better := cur
	better.Status = StatusVerified
	if got := CheckRegression("comp-1", better, prev, cfg); got.Outcome != CheckPass {
		t.Fatalf("improvement must pass: %+v", got)
	}
	if got := CheckRegression("comp-9", cur, prev, cfg); got.Outcome != CheckNotApplicable {
		t.Fatalf("unknown previous must be not-applicable: %+v", got)
	}
	// Arbitrary telemetry never feeds regression: unknown previous is
	// not-applicable even for weak current status.
	weak := cur
	weak.Status = StatusUnknown
	if got := CheckRegression("comp-9", weak, prev, cfg); got.Outcome != CheckNotApplicable {
		t.Fatalf("unknown previous must stay not-applicable: %+v", got)
	}
}

func TestCheckIDsStable(t *testing.T) {
	for id, want := range map[CheckID]string{
		CheckIDMissingSBOM:          "supply-missing-sbom",
		CheckIDUnverifiedProvenance: "supply-unverified-provenance",
		CheckIDPolicyViolation:      "supply-policy-violation",
		CheckIDStaleVendor:          "supply-stale-vendor-assessment",
		CheckIDRegression:           "supply-posture-regression",
	} {
		if string(id) != want {
			t.Errorf("check id drift: %q != %q", id, want)
		}
	}
}
