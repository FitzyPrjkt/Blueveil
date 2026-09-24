// RED: campaign + case model — deterministic IDs, bounded enums,
// declarative cases only.
package validation

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestCampaignValidate(t *testing.T) {
	c := Campaign{
		Name: "lab campaign", Description: "d", Target: "seed-lab",
		Provider: NativeProviderID, Source: "seed-lab-validation",
		Status: StatusDraft,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid campaign: %v", err)
	}
	zero := c
	zero.Status = 0
	if err := zero.Validate(); err == nil {
		t.Errorf("zero status must be rejected (unset is not a state)")
	}
	for name, mut := range map[string]func(*Campaign){
		"empty name":     func(c *Campaign) { c.Name = "" },
		"empty target":   func(c *Campaign) { c.Target = "" },
		"empty provider": func(c *Campaign) { c.Provider = "" },
		"empty source":   func(c *Campaign) { c.Source = "" },
	} {
		bad := c
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	badStatus := c
	badStatus.Status = CampaignStatus(99)
	if err := badStatus.Validate(); err == nil {
		t.Errorf("unknown status must be rejected")
	}
}

func TestCampaignDeterministicID(t *testing.T) {
	mk := func() Campaign {
		return Campaign{
			Name: "lab campaign", Description: "d", Target: "seed-lab",
			Provider: NativeProviderID, Source: "seed-lab-validation",
		}
	}
	a, b := mk(), mk()
	if a.ID() == "" || a.ID() != b.ID() {
		t.Fatalf("campaign id must be deterministic: %q %q", a.ID(), b.ID())
	}
	other := mk()
	other.Name = "other campaign"
	if other.ID() == a.ID() {
		t.Fatalf("different name must differ")
	}
}

func TestCaseValidate(t *testing.T) {
	c := ValidationCase{
		Title: "waf blocks lab probe", Domain: DomainNetwork, Target: "seed-lab",
		Expected: ExpectPrevent, Operation: v1.OperationType_OPERATION_TYPE_OBSERVE,
		Risk: v1.RiskLevel_RISK_LEVEL_LOW, Provider: NativeProviderID,
		Source: "seed-lab-validation",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid case: %v", err)
	}
	for name, mut := range map[string]func(*ValidationCase){
		"empty title":    func(c *ValidationCase) { c.Title = "" },
		"bad domain":     func(c *ValidationCase) { c.Domain = "exploit" },
		"empty target":   func(c *ValidationCase) { c.Target = "" },
		"bad expected":   func(c *ValidationCase) { c.Expected = "pwned" },
		"empty provider": func(c *ValidationCase) { c.Provider = "" },
		"empty source":   func(c *ValidationCase) { c.Source = "" },
	} {
		bad := c
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestCaseDeterministicID(t *testing.T) {
	mk := func() ValidationCase {
		return ValidationCase{
			Title: "t", Domain: DomainWAF, Target: "seed-lab",
			Expected: ExpectDetect, Operation: v1.OperationType_OPERATION_TYPE_OBSERVE,
			Risk: v1.RiskLevel_RISK_LEVEL_LOW, Provider: NativeProviderID,
			Source: "seed-lab-validation",
		}
	}
	a, b := mk(), mk()
	if a.ID() == "" || a.ID() != b.ID() {
		t.Fatalf("case id must be deterministic")
	}
}

func TestCampaignStatusStrings(t *testing.T) {
	// Bounded vocabulary only.
	for _, s := range []CampaignStatus{StatusDraft, StatusRunning, StatusCompleted, StatusFailed} {
		if s.String() == "" || s.String() == "UNKNOWN" {
			t.Errorf("status %d has no string", int(s))
		}
	}
}

func TestDomainVocabulary(t *testing.T) {
	for _, d := range []CaseDomain{
		DomainNetwork, DomainApplication, DomainEndpoint, DomainServer,
		DomainContainer, DomainCloud, DomainIdentity, DomainAuth,
		DomainData, DomainWAF,
	} {
		if string(d) == "" {
			t.Errorf("empty domain string")
		}
	}
	for _, e := range []ExpectedBehavior{ExpectPrevent, ExpectDetect, ExpectPreventAndDetect, ExpectObserve} {
		if string(e) == "" {
			t.Errorf("empty expected string")
		}
	}
}

func TestCampaignTimestamps(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	c := Campaign{
		Name: "n", Target: "t", Provider: NativeProviderID, Source: "s",
		Status:    StatusDraft,
		CreatedAt: now, StartedAt: now.Add(-time.Hour),
	}
	if err := c.Validate(); err == nil {
		t.Errorf("started-before-created must be rejected")
	}
	c.StartedAt = now
	c.CompletedAt = now.Add(-time.Minute)
	if err := c.Validate(); err == nil {
		t.Errorf("completed-before-started must be rejected")
	}
}
