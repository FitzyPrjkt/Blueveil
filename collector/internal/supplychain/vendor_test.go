// RED: third-party vendor inventory + assessments. No fabricated
// certifications, no inferred trust.
package supplychain

import (
	"testing"
	"time"
)

func TestVendorValidate(t *testing.T) {
	v := Vendor{
		Name: "acme", Service: "dns", Category: "infrastructure",
		Environment: "lab", Status: VendorActive, Source: "seed-lab-supply-chain",
		ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
	}
	if err := v.Validate(); err != nil {
		t.Fatalf("valid vendor: %v", err)
	}
	if v.ID() == "" {
		t.Fatalf("vendor id required")
	}
	a, b := v.ID(), v
	b.Service = "other"
	if a == b.ID() {
		t.Fatalf("different service must differ")
	}
	for name, mut := range map[string]func(*Vendor){
		"empty name":    func(v *Vendor) { v.Name = "" },
		"empty service": func(v *Vendor) { v.Service = "" },
		"bad status":    func(v *Vendor) { v.Status = "TRUSTED" },
		"empty source":  func(v *Vendor) { v.Source = "" },
		"zero time":     func(v *Vendor) { v.ObservedAt = time.Time{} },
	} {
		bad := v
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestVendorAssessmentValidate(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	a := VendorAssessment{
		VendorID: "vend-1", Status: VendorReviewed, Assessor: "seed-lab-grc",
		ObservedAt: now, EvidenceIDs: []string{"ev-1"},
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("valid assessment: %v", err)
	}
	if a.ID() == "" {
		t.Fatalf("assessment id required")
	}
	for name, mut := range map[string]func(*VendorAssessment){
		"empty vendor": func(a *VendorAssessment) { a.VendorID = "" },
		"bad status":   func(a *VendorAssessment) { a.Status = "CERTIFIED_SECURE" },
		"empty assess": func(a *VendorAssessment) { a.Assessor = "" },
		"zero time":    func(a *VendorAssessment) { a.ObservedAt = time.Time{} },
	} {
		bad := a
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAssessmentStaleness(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	old := now.Add(-40 * 24 * time.Hour)
	if !IsAssessmentStale(old, 30*24*time.Hour, now) {
		t.Fatalf("40d old assessment must be stale past 30d window")
	}
	if IsAssessmentStale(now.Add(-time.Hour), 30*24*time.Hour, now) {
		t.Fatalf("fresh assessment must not be stale")
	}
	// Boundary is inclusive from the assessment instant.
	if !IsAssessmentStale(now.Add(-30*24*time.Hour), 30*24*time.Hour, now) {
		t.Fatalf("assessment exactly at window edge counts stale")
	}
}
