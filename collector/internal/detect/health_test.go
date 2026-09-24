// RED: rule metadata catalog + engine health observability.
package detect

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func healthEvent(id, typ string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: "s", AssetId: "a", EventType: typ, Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{},
	}
}

func TestDescribeCoversRegisteredRules(t *testing.T) {
	eng, err := NewEngine(time.Now)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	for _, r := range []Rule{BlockHighSeverityRule{}, SourceCriticalRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatal(err)
		}
	}
	burst, _ := NewBlockBurstRule(3, 5*time.Minute, time.Now)
	if err := eng.RegisterRule(burst); err != nil {
		t.Fatal(err)
	}
	for _, r := range eng.Rules() {
		m := Describe(r)
		if m.ID == "" || m.Version == "" || m.Title == "" || m.Description == "" {
			t.Errorf("incomplete metadata for %s: %+v", r.ID(), m)
		}
		// Empty EventTypes is honest for catch-all rules
		// (source-declared-critical matches any type).
		if m.Domain == "" || m.SeverityBasis == "" || m.ConfidenceBasis == "" {
			t.Errorf("missing engineering fields for %s: %+v", r.ID(), m)
		}
		if !m.Enabled {
			t.Errorf("registered rule must report enabled: %s", r.ID())
		}
	}
	got := Describe(burst)
	if !got.Stateful || got.Threshold != 3 || got.Window != 5*time.Minute {
		t.Errorf("burst metadata must carry threshold/window: %+v", got)
	}
	got2 := Describe(BlockHighSeverityRule{})
	if got2.Stateful {
		t.Errorf("stateless rule must report Stateful=false: %+v", got2)
	}
}

func TestEngineHealthCounts(t *testing.T) {
	eng, err := NewEngine(time.Now)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.RegisterRule(BlockHighSeverityRule{}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Process(healthEvent("h1", "waf.request_allowed")); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Process(healthEvent("h2", "waf.request_blocked")); err != nil {
		// INFO severity: no match, still evaluated
		t.Fatal(err)
	}
	h := eng.Health()
	if len(h) != 1 {
		t.Fatalf("want 1 rule health row, got %+v", h)
	}
	if h[0].Evaluated != 2 || h[0].Detections != 0 || h[0].Errors != 0 {
		t.Fatalf("health counts wrong: %+v", h[0])
	}
	if h[0].RuleID != "waf-block-high-severity" || !h[0].Enabled {
		t.Fatalf("health identity wrong: %+v", h[0])
	}
}

func TestEngineRecordsRuleErrors(t *testing.T) {
	eng, err := NewEngine(time.Now)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.RegisterRule(failRule{}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Process(healthEvent("e9", "anything.at.all")); err == nil {
		t.Fatalf("rule error must still abort loudly")
	}
	h := eng.Health()
	if len(h) != 1 || h[0].Errors != 1 || h[0].Evaluated != 1 {
		t.Fatalf("error must be recorded without changing abort semantics: %+v", h)
	}
	errs := eng.RuleErrors("test-always-fails")
	if len(errs) != 1 || errs[0].EventID != "e9" {
		t.Fatalf("error events must carry event id: %+v", errs)
	}
}

func TestDisableEnable(t *testing.T) {
	eng, err := NewEngine(time.Now)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	r := BlockHighSeverityRule{}
	if err := eng.RegisterRule(r); err != nil {
		t.Fatal(err)
	}
	if err := eng.Disable("waf-block-high-severity"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if eng.Health()[0].Enabled {
		t.Fatalf("disabled rule must report Enabled=false")
	}
	// Disabled rules are skipped, not evaluated.
	if _, err := eng.Process(healthEvent("h1", "waf.request_allowed")); err != nil {
		t.Fatal(err)
	}
	if eng.Health()[0].Evaluated != 0 {
		t.Fatalf("disabled rule must not evaluate: %+v", eng.Health()[0])
	}
	if err := eng.Disable("no-such-rule"); err == nil {
		t.Errorf("disabling unknown rule must error")
	}
	if err := eng.Enable("waf-block-high-severity"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !eng.Health()[0].Enabled {
		t.Fatalf("re-enabled rule must report Enabled=true")
	}
}
