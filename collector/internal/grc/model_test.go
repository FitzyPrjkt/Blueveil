// RED: bounded GRC model — requirements, controls, assessments, risk.
// No fabricated compliance: unknown stays unknown.
package grc

import (
	"strings"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
)

func TestRequirementValidate(t *testing.T) {
	r := Requirement{
		Framework: "BLUEVEIL-BASELINE", FrameworkVersion: "1.0.0-lab",
		ControlRef: "AC-1", Title: "t", Description: "d", Domain: DomainIdentity,
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid requirement: %v", err)
	}
	for name, mut := range map[string]func(*Requirement){
		"empty framework": func(r *Requirement) { r.Framework = "" },
		"empty control":   func(r *Requirement) { r.ControlRef = "" },
		"empty title":     func(r *Requirement) { r.Title = "" },
		"bad domain":      func(r *Requirement) { r.Domain = "mind-control" },
	} {
		bad := r
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if got := r.ID(); got == "" {
		t.Fatalf("requirement id required")
	}
	a, b := r.ID(), r
	b.ControlRef = "AC-2"
	if a == b.ID() {
		t.Fatalf("requirement id must be deterministic over inputs")
	}
}

func TestControlValidate(t *testing.T) {
	c := Control{
		ID: "AC-1", Title: "t", Description: "d", Domain: DomainIdentity,
		Framework: "BLUEVEIL-BASELINE", FrameworkVersion: "1.0.0-lab",
		Implementation: ImplImplemented,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid control: %v", err)
	}
	for name, mut := range map[string]func(*Control){
		"empty id":   func(c *Control) { c.ID = "" },
		"bad impl":   func(c *Control) { c.Implementation = "vibes" },
		"bad domain": func(c *Control) { c.Domain = "telepathy" },
		"empty fw":   func(c *Control) { c.Framework = "" },
	} {
		bad := c
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAssessmentValidate(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	a := Assessment{
		ControlID: "AC-1", Target: "seed-lab", Status: StatusCompliant,
		Assessor: "seed-lab-grc", ObservedAt: now,
		EvidenceIDs: []string{"ev-1"}, Basis: "validation vres-1 observed prevention",
		Risk: RiskLow, RiskBasis: "isolated lab target, prevention observed",
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("valid assessment: %v", err)
	}
	// Status without basis is fabrication — except NOT_ASSESSED/UNKNOWN.
	for _, s := range []AssessmentStatus{StatusCompliant, StatusPartiallyCompliant, StatusNonCompliant} {
		bad := a
		bad.Status = s
		bad.Basis = ""
		if err := bad.Validate(); err == nil {
			t.Errorf("%s without basis must be rejected", s)
		}
	}
	for name, mut := range map[string]func(*Assessment){
		"empty control": func(a *Assessment) { a.ControlID = "" },
		"bad status":    func(a *Assessment) { a.Status = "SECURE" },
		"secure banned": func(a *Assessment) { a.Status = "SAFE" },
		"zero time":     func(a *Assessment) { a.ObservedAt = time.Time{} },
		"risk no basis": func(a *Assessment) { a.Risk = RiskHigh; a.RiskBasis = "" },
		"bad risk":      func(a *Assessment) { a.Risk = "extreme" },
	} {
		bad := a
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if got := a.ID(); got == "" {
		t.Fatalf("assessment id required")
	}
}

func TestNotAssessedNeedsNoBasis(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	for _, s := range []AssessmentStatus{StatusNotAssessed, StatusNotApplicable, StatusUnknown} {
		a := Assessment{
			ControlID: "AC-9", Target: "seed-lab", Status: s,
			Assessor: "seed-lab-grc", ObservedAt: now,
		}
		if err := a.Validate(); err != nil {
			t.Errorf("%s without basis must be allowed: %v", s, err)
		}
	}
}

func TestRedactMetadata(t *testing.T) {
	in := map[string]string{
		"owner":         "lab-team",
		"auth.password": "hunter2",
		"api_key":       "key-secret",
		"note":          "clean",
	}
	// Every canonical fragment must drop, including keys the old
	// per-layer lists missed (e.g. authorization in identobs).
	for _, k := range contract.SensitiveFragments {
		in["meta.x-"+k] = "SECRET"
	}
	in["authorization"] = "Bearer SECRET"
	out := RedactMetadata(in)
	if _, ok := out["auth.password"]; ok {
		t.Errorf("password key must be dropped")
	}
	if _, ok := out["api_key"]; ok {
		t.Errorf("api_key must be dropped")
	}
	if _, ok := out["authorization"]; ok {
		t.Errorf("authorization must be dropped")
	}
	for k := range out {
		if strings.HasPrefix(k, "meta.x-") {
			t.Errorf("inventory key %q must be dropped", k)
		}
	}
	if out["owner"] != "lab-team" || out["note"] != "clean" {
		t.Errorf("clean keys must survive: %+v", out)
	}
	if _, ok := in["auth.password"]; !ok {
		t.Errorf("input must not be mutated")
	}
}

func TestAssessmentDeterministicID(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	mk := func() Assessment {
		return Assessment{
			ControlID: "AC-1", Target: "seed-lab", Status: StatusCompliant,
			Assessor: "seed-lab-grc", ObservedAt: now, Basis: "b",
		}
	}
	a, b := mk(), mk()
	if a.ID() == "" || a.ID() != b.ID() {
		t.Fatalf("assessment id must be deterministic")
	}
	other := mk()
	other.Status = StatusNonCompliant
	if other.ID() == a.ID() {
		t.Fatalf("different status must differ")
	}
}
