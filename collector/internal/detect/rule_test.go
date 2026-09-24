package detect

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

func at(minute int) *timestamppb.Timestamp {
	return timestamppb.New(time.Date(2026, 9, 12, 9, minute, 0, 0, time.UTC))
}

func blockedEvent(id, asset string, sev v1.Severity, minute int) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, Source: "lab-waf", AssetId: asset, EventType: "waf.request_blocked",
		Severity: sev, OccurredAt: at(minute),
	}
}

func TestBlockHighSeverityMatchesOnlyHighBlocked(t *testing.T) {
	rule := BlockHighSeverityRule{}
	if rule.ID() == "" || rule.Version() == "" || rule.Name() == "" || rule.Description() == "" {
		t.Fatal("rule identity must be stable and documented")
	}
	pos, err := rule.Evaluate(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	if err != nil || !pos.Matched {
		t.Fatalf("HIGH blocked must match: %+v %v", pos, err)
	}
	if pos.Severity != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("severity must be inherited, got %v", pos.Severity)
	}
	if len(pos.EventIDs) != 1 || pos.EventIDs[0] != "e1" {
		t.Fatalf("event relationship must be exact: %v", pos.EventIDs)
	}
	for _, neg := range []*v1.TelemetryEvent{
		blockedEvent("e2", "a", v1.Severity_SEVERITY_MEDIUM, 0), // below threshold
		blockedEvent("e3", "a", v1.Severity_SEVERITY_LOW, 0),
		{Id: "e4", Source: "lab-waf", AssetId: "a", EventType: "waf.request_allowed",
			Severity: v1.Severity_SEVERITY_HIGH, OccurredAt: at(0)}, // wrong type
	} {
		out, err := rule.Evaluate(neg)
		if err != nil || out.Matched {
			t.Fatalf("must not match %+v: %+v %v", neg, out, err)
		}
	}
	if _, err := rule.Evaluate(nil); err == nil {
		t.Fatal("nil event must error, not silently miss")
	}
	// Deterministic output: same input twice, same outcome.
	again, _ := rule.Evaluate(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	if again.Detail != pos.Detail || again.Title != pos.Title {
		t.Fatal("rule output must be deterministic")
	}
}

func TestSourceCriticalMatchesAnyCritical(t *testing.T) {
	rule := SourceCriticalRule{}
	pos, err := rule.Evaluate(&v1.TelemetryEvent{
		Id: "e1", Source: "lab", AssetId: "a", EventType: "anything.at.all",
		Severity: v1.Severity_SEVERITY_CRITICAL, OccurredAt: at(0),
	})
	if err != nil || !pos.Matched || pos.Severity != v1.Severity_SEVERITY_CRITICAL {
		t.Fatalf("CRITICAL must match with inherited severity: %+v %v", pos, err)
	}
	neg, err := rule.Evaluate(blockedEvent("e2", "a", v1.Severity_SEVERITY_HIGH, 0))
	if err != nil || neg.Matched {
		t.Fatal("HIGH must not match the critical rule")
	}
	if _, err := rule.Evaluate(nil); err == nil {
		t.Fatal("nil event must error")
	}
}

func TestBlockBurstFiresOncePerWindow(t *testing.T) {
	now := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	rule, err := NewBlockBurstRule(3, 5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	fire := func(id string, minute int, sev v1.Severity) Outcome {
		t.Helper()
		out, err := rule.Evaluate(blockedEvent(id, "asset-1", sev, minute))
		if err != nil {
			t.Fatalf("evaluate %s: %v", id, err)
		}
		return out
	}
	if out := fire("b1", 0, v1.Severity_SEVERITY_LOW); out.Matched {
		t.Fatal("1/3 must not fire")
	}
	if out := fire("b2", 1, v1.Severity_SEVERITY_MEDIUM); out.Matched {
		t.Fatal("2/3 must not fire")
	}
	hit := fire("b3", 2, v1.Severity_SEVERITY_HIGH)
	if !hit.Matched {
		t.Fatal("3/3 must fire")
	}
	if hit.Severity != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("severity must be the window peak, got %v", hit.Severity)
	}
	if len(hit.EventIDs) != 3 {
		t.Fatalf("all contributing events must be referenced: %v", hit.EventIDs)
	}
	// Still inside the window: suppressed, not a second detection.
	if out := fire("b4", 3, v1.Severity_SEVERITY_LOW); out.Matched {
		t.Fatal("must stay silent while the window holds >= threshold")
	}
	// Window slides past b1..b3: count drops, rule re-arms, fires again
	// with a NEW deterministic event set.
	hit2 := fire("b5", 8, v1.Severity_SEVERITY_LOW)
	_ = hit2
	out6 := fire("b6", 9, v1.Severity_SEVERITY_LOW)
	out7 := fire("b7", 10, v1.Severity_SEVERITY_LOW)
	if out6.Matched || !out7.Matched {
		t.Fatalf("re-arm sequence wrong: %+v %+v", out6, out7)
	}
	if len(out7.EventIDs) != 3 || out7.EventIDs[0] == "b1" {
		t.Fatalf("new window must reference new events: %v", out7.EventIDs)
	}
}

func TestBlockBurstSeparatesAssetsAndIgnoresOtherTypes(t *testing.T) {
	now := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	rule, _ := NewBlockBurstRule(2, 5*time.Minute, func() time.Time { return now })
	allowed := &v1.TelemetryEvent{
		Id: "x", Source: "lab-waf", AssetId: "a", EventType: "waf.request_allowed",
		Severity: v1.Severity_SEVERITY_INFO, OccurredAt: at(0),
	}
	if out, _ := rule.Evaluate(allowed); out.Matched {
		t.Fatal("allowed requests must not feed the burst window")
	}
	if out, _ := rule.Evaluate(blockedEvent("a1", "asset-A", v1.Severity_SEVERITY_LOW, 0)); out.Matched {
		t.Fatal("1/2 per asset must not fire")
	}
	// Other asset's event must not complete asset-A's window.
	if out, _ := rule.Evaluate(blockedEvent("b1", "asset-B", v1.Severity_SEVERITY_LOW, 1)); out.Matched {
		t.Fatal("cross-asset events must not mix")
	}
	if out, _ := rule.Evaluate(blockedEvent("a2", "asset-A", v1.Severity_SEVERITY_LOW, 2)); !out.Matched {
		t.Fatal("asset-A reached 2/2 and must fire")
	}
}

func TestBlockBurstConstructorRejectsNonsense(t *testing.T) {
	clock := func() time.Time { return time.Now() }
	if _, err := NewBlockBurstRule(0, time.Minute, clock); err == nil {
		t.Fatal("zero threshold must fail")
	}
	if _, err := NewBlockBurstRule(3, 0, clock); err == nil {
		t.Fatal("zero window must fail")
	}
	if _, err := NewBlockBurstRule(3, time.Minute, nil); err == nil {
		t.Fatal("nil clock must fail")
	}
}
