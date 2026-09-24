// RED: explicit dependency edges, SBOM metadata, declarative policy.
package supplychain

import (
	"testing"
	"time"
)

func TestDependencyValidate(t *testing.T) {
	d := Dependency{
		ParentID: "app-1", ParentKind: "APPLICATION",
		ChildID: "comp-1", Kind: DependencyDependsOn,
		Source:     "seed-lab-supply-chain",
		ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("valid dependency: %v", err)
	}
	for name, mut := range map[string]func(*Dependency){
		"empty parent": func(d *Dependency) { d.ParentID = "" },
		"empty child":  func(d *Dependency) { d.ChildID = "" },
		"self link":    func(d *Dependency) { d.ChildID = d.ParentID },
		"bad kind":     func(d *Dependency) { d.Kind = "VIBES_WITH" },
		"empty source": func(d *Dependency) { d.Source = "" },
		"zero time":    func(d *Dependency) { d.ObservedAt = time.Time{} },
	} {
		bad := d
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDependencyKindsBounded(t *testing.T) {
	for _, k := range []DependencyKind{
		DependencyDependsOn, DependencyContains, DependencyBuiltFrom,
		DependencyDerivedFrom,
	} {
		if string(k) == "" {
			t.Errorf("empty dependency kind")
		}
	}
}

func TestSBOMValidate(t *testing.T) {
	s := SBOM{
		Format: SBOMCycloneDX, FormatVersion: "1.6",
		ComponentIDs: []string{"comp-1", "comp-2"},
		GeneratedAt:  time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		Source:       "seed-lab-supply-chain", Digest: "sha256:abc",
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid sbom: %v", err)
	}
	if s.ID() == "" {
		t.Fatalf("sbom id required")
	}
	a, b := s.ID(), s
	b.ComponentIDs = []string{"comp-1"}
	if a == b.ID() {
		t.Fatalf("different component sets must differ")
	}
	for name, mut := range map[string]func(*SBOM){
		"bad format": func(s *SBOM) { s.Format = "PDF" },
		"no comps":   func(s *SBOM) { s.ComponentIDs = nil },
		"zero time":  func(s *SBOM) { s.GeneratedAt = time.Time{} },
		"empty src":  func(s *SBOM) { s.Source = "" },
	} {
		bad := s
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	p := SupplyPolicy{
		ID: "pol-1", Name: "lab policy", Source: "seed-lab-supply-chain",
		AllowedEcosystems: []string{"npm", "go"},
		AllowedLicenses:   []string{"MIT"},
		AllowedProvenance: []Provenance{ProvenanceLockfile},
		RequireDigest:     true,
		MinVersions:       map[string]string{"npm": "1.0.0"},
		RequireSBOM:       true,
		ApprovedRepos:     []string{"github.com/lab/*"},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	for name, mut := range map[string]func(*SupplyPolicy){
		"empty id":     func(p *SupplyPolicy) { p.ID = "" },
		"empty name":   func(p *SupplyPolicy) { p.Name = "" },
		"empty source": func(p *SupplyPolicy) { p.Source = "" },
	} {
		bad := p
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	empty := SupplyPolicy{ID: "pol-e", Name: "n", Source: "s"}
	if err := empty.Validate(); err != nil {
		t.Fatalf("empty policy (no constraints) must be allowed: %v", err)
	}
}

func TestPolicyEvaluate(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	mk := func() Component {
		return Component{
			Type: ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
			Version: "1.3.0", Digest: "sha256:abc", Provenance: ProvenanceLockfile,
			License: "MIT", Source: "s", ObservedAt: now, Status: StatusObserved,
		}
	}
	pol := SupplyPolicy{
		ID: "pol-1", Name: "n", Source: "s",
		AllowedEcosystems: []string{"npm"},
		AllowedLicenses:   []string{"MIT"},
		AllowedProvenance: []Provenance{ProvenanceLockfile},
		RequireDigest:     true,
		MinVersions:       map[string]string{"npm": "1.0.0"},
		Prohibited:        []string{"npm/evil"},
	}
	res := EvaluatePolicy(mk(), pol)
	if res.Verdict != PolicyOK {
		t.Fatalf("compliant component must pass: %+v", res)
	}
	if res.PolicyID != "pol-1" || res.ComponentID == "" {
		t.Fatalf("result identity: %+v", res)
	}
	// Ecosystem violation.
	bad := mk()
	bad.Ecosystem = "pypi"
	if res := EvaluatePolicy(bad, pol); res.Verdict != PolicyViolation {
		t.Fatalf("ecosystem mismatch must violate: %+v", res)
	}
	// Prohibited component.
	evil := mk()
	evil.Name = "evil"
	if res := EvaluatePolicy(evil, pol); res.Verdict != PolicyViolation {
		t.Fatalf("prohibited component must violate: %+v", res)
	}
	// Old version below minimum.
	old := mk()
	old.Version = "0.9.0"
	if res := EvaluatePolicy(old, pol); res.Verdict != PolicyViolation {
		t.Fatalf("below-minimum version must violate: %+v", res)
	}
	// Unparsable version is UNKNOWN, never a violation.
	weird := mk()
	weird.Version = "latest-ish"
	if res := EvaluatePolicy(weird, pol); res.Verdict != PolicyUnknown {
		t.Fatalf("unparsable version must be unknown: %+v", res)
	}
	// Missing digest where required.
	nodigest := mk()
	nodigest.Digest = ""
	if res := EvaluatePolicy(nodigest, pol); res.Verdict != PolicyViolation {
		t.Fatalf("missing required digest must violate: %+v", res)
	}
}
