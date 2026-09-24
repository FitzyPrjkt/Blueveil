package detect

import (
	"errors"
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestRegistryLifecycle(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(BlockHighSeverityRule{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(SourceCriticalRule{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(BlockHighSeverityRule{}); err == nil {
		t.Fatal("duplicate rule id must be rejected")
	}
	if err := reg.Register(nil); err == nil {
		t.Fatal("nil rule must be rejected")
	}
	got, ok := reg.Get("waf-block-high-severity")
	if !ok || got.ID() != "waf-block-high-severity" {
		t.Fatal("get must return the rule")
	}
	if _, ok := reg.Get("nope"); ok {
		t.Fatal("unknown id must miss")
	}
	list := reg.List()
	if len(list) != 2 || list[0].ID() != "waf-block-high-severity" || list[1].ID() != "source-declared-critical" {
		t.Fatalf("list must follow registration order: %v", list)
	}
}

// failRule proves evaluation errors stay loud.
type failRule struct{}

func (failRule) ID() string      { return "test-always-fails" }
func (failRule) Version() string { return "1" }
func (failRule) Name() string    { return "test" }
func (failRule) Description() string {
	return "test double"
}
func (failRule) Evaluate(_ *v1.TelemetryEvent) (Outcome, error) {
	return Outcome{}, errors.New("boom")
}

func TestEvaluateAllAbortsOnRuleError(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(BlockHighSeverityRule{}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(failRule{}); err != nil {
		t.Fatal(err)
	}
	matches, err := reg.EvaluateAll(blockedEvent("e", "a", v1.Severity_SEVERITY_HIGH, 0))
	if err == nil {
		t.Fatal("rule error must abort evaluation")
	}
	if matches != nil {
		t.Fatalf("aborted evaluation must yield no matches, got %v", matches)
	}
}
