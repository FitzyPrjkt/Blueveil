package detect

import (
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

func testEngine(t *testing.T, rules ...Rule) *Engine {
	t.Helper()
	eng, err := NewEngine(func() time.Time {
		return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	for _, r := range rules {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatalf("register %s: %v", r.ID(), err)
		}
	}
	return eng
}

func TestProcessEmitsDetectionAndAlert(t *testing.T) {
	eng := testEngine(t, BlockHighSeverityRule{})
	res, err := eng.Process(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Detections) != 1 || len(res.Alerts) != 1 || res.Suppressed != 0 {
		t.Fatalf("one match → one detection + one alert: %+v", res)
	}
	det, alert := res.Detections[0], res.Alerts[0]
	if err := contract.ValidateDetection(det); err != nil {
		t.Fatalf("detection must validate: %v", err)
	}
	if err := contract.ValidateAlert(alert); err != nil {
		t.Fatalf("alert must validate: %v", err)
	}
	if det.GetRuleId() != "waf-block-high-severity" || det.GetRuleName() == "" {
		t.Fatalf("rule identity must be recorded: %+v", det)
	}
	if len(det.GetTelemetryEventIds()) != 1 || det.GetTelemetryEventIds()[0] != "e1" {
		t.Fatalf("event relationship must be exact: %v", det.GetTelemetryEventIds())
	}
	if det.GetSeverity() != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("severity must be inherited: %v", det.GetSeverity())
	}
	if det.GetConfidence() != 0.0 {
		t.Fatalf("boolean rules carry unmeasured confidence 0.0, got %v", det.GetConfidence())
	}
	if len(alert.GetDetectionIds()) != 1 || alert.GetDetectionIds()[0] != det.GetId() {
		t.Fatalf("alert must reference exactly its detection: %+v", alert)
	}
	if alert.GetSeverity() != det.GetSeverity() {
		t.Fatal("alert severity must follow its detection")
	}
}

func TestNoMatchYieldsNothing(t *testing.T) {
	eng := testEngine(t, BlockHighSeverityRule{}, SourceCriticalRule{})
	res, err := eng.Process(blockedEvent("e1", "a", v1.Severity_SEVERITY_LOW, 0))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Detections) != 0 || len(res.Alerts) != 0 {
		t.Fatalf("no match → no output: %+v", res)
	}
}

func TestOverlappingRulesEachEmit(t *testing.T) {
	// Blocked CRITICAL matches both rule 1 and rule 3: two rule identities,
	// two detections, two alerts. Deterministic and explainable.
	eng := testEngine(t, BlockHighSeverityRule{}, SourceCriticalRule{})
	res, err := eng.Process(blockedEvent("e1", "a", v1.Severity_SEVERITY_CRITICAL, 0))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Detections) != 2 || len(res.Alerts) != 2 {
		t.Fatalf("both rules must emit: %+v", res)
	}
	if res.Detections[0].GetId() == res.Detections[1].GetId() {
		t.Fatal("distinct rules must yield distinct detection ids")
	}
}

func TestDeduplicationSuppressesReemission(t *testing.T) {
	eng := testEngine(t, BlockHighSeverityRule{})
	event := blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0)
	first, err := eng.Process(event)
	if err != nil || len(first.Detections) != 1 {
		t.Fatalf("first: %+v %v", first, err)
	}
	second, err := eng.Process(event)
	if err != nil {
		t.Fatalf("reprocess: %v", err)
	}
	if len(second.Detections) != 0 || len(second.Alerts) != 0 || second.Suppressed != 1 {
		t.Fatalf("repeat must suppress, not re-emit: %+v", second)
	}
	if d, a, s := eng.Counts(); d != 1 || a != 1 || s != 1 {
		t.Fatalf("counts drift: %d %d %d", d, a, s)
	}
}

func TestDetectionIDsAreDeterministic(t *testing.T) {
	a := testEngine(t, BlockHighSeverityRule{})
	b := testEngine(t, BlockHighSeverityRule{})
	ra, _ := a.Process(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	rb, _ := b.Process(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	if ra.Detections[0].GetId() != rb.Detections[0].GetId() {
		t.Fatal("same match must yield same detection id across engines")
	}
}

func TestProcessRejectsInvalidTelemetry(t *testing.T) {
	eng := testEngine(t, BlockHighSeverityRule{})
	res, err := eng.Process(&v1.TelemetryEvent{})
	if !errors.Is(err, ErrInvalidTelemetry) {
		t.Fatalf("want ErrInvalidTelemetry, got %v", err)
	}
	if len(res.Detections) != 0 {
		t.Fatal("invalid telemetry must yield nothing")
	}
	if _, err := eng.Process(nil); !errors.Is(err, ErrInvalidTelemetry) {
		t.Fatalf("nil event: want ErrInvalidTelemetry, got %v", err)
	}
}

func TestProcessAbortsOnRuleError(t *testing.T) {
	eng := testEngine(t, failRule{})
	res, err := eng.Process(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	if !errors.Is(err, ErrRuleEvaluation) {
		t.Fatalf("want ErrRuleEvaluation, got %v", err)
	}
	if len(res.Detections) != 0 || len(res.Alerts) != 0 {
		t.Fatal("aborted evaluation must emit nothing (no false clearing)")
	}
}

func TestBuildDetectionRejectsBadMatches(t *testing.T) {
	rule := BlockHighSeverityRule{}
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	out, _ := rule.Evaluate(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	if _, err := BuildDetection(rule, Outcome{}, now); err == nil {
		t.Fatal("non-match must not build")
	}
	badIDs := out
	badIDs.EventIDs = nil
	if _, err := BuildDetection(rule, badIDs, now); err == nil {
		t.Fatal("event-less match must not build")
	}
	badSev := out
	badSev.Severity = v1.Severity_SEVERITY_UNSPECIFIED
	if _, err := BuildDetection(rule, badSev, now); err == nil {
		t.Fatal("unspecified severity must not build")
	}
	badConf := out
	badConf.Confidence = 2.0
	if _, err := BuildDetection(rule, badConf, now); err == nil {
		t.Fatal("out-of-range confidence must not build")
	}
	badNS := out
	badNS.Attrs = map[string]string{"blueveil.spoof": "x"}
	if _, err := BuildDetection(rule, badNS, now); err == nil {
		t.Fatal("rule attrs invading blueveil.* must be rejected")
	}
	if _, err := BuildDetection(rule, out, time.Time{}); err == nil {
		t.Fatal("zero timestamp must not build")
	}
	good, err := BuildDetection(rule, out, now)
	if err != nil {
		t.Fatalf("good match must build: %v", err)
	}
	if good.GetAttributes()["blueveil.rule_version"] != "1" ||
		good.GetAttributes()["blueveil.confidence_basis"] != ConfidenceBasis {
		t.Fatalf("builder provenance missing: %v", good.GetAttributes())
	}
}

func TestBuildAlertNeedsDetection(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	if _, err := BuildAlert(nil, now); err == nil {
		t.Fatal("nil detection must not alert")
	}
	rule := BlockHighSeverityRule{}
	out, _ := rule.Evaluate(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	det, err := BuildDetection(rule, out, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAlert(det, time.Time{}); err == nil {
		t.Fatal("zero timestamp must not alert")
	}
	alert, err := BuildAlert(det, now)
	if err != nil {
		t.Fatalf("good detection must alert: %v", err)
	}
	again, _ := BuildAlert(det, now)
	if alert.GetId() != again.GetId() {
		t.Fatal("alert ids must be deterministic per detection")
	}
}

func TestStoreCollectsPairs(t *testing.T) {
	var store Store
	eng := testEngine(t, BlockHighSeverityRule{})
	res, _ := eng.Process(blockedEvent("e1", "a", v1.Severity_SEVERITY_HIGH, 0))
	store.Add(res.Detections[0], res.Alerts[0])
	if d, a := store.Counts(); d != 1 || a != 1 {
		t.Fatalf("counts: %d %d", d, a)
	}
	if len(store.Detections()) != 1 || len(store.Alerts()) != 1 {
		t.Fatal("stored pairs must round-trip")
	}
}
