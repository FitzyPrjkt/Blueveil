// RED: T1 IOC match, T2 multi-stage correlation, T3 rule-error burst.
package detect

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/threatintel"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var threatBase = time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)

func threatEvt(id, typ string, minute int, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(threatBase.Add(time.Duration(minute) * time.Minute)),
		Source: "seed-lab-monitoring", AssetId: "seed-mon-01", EventType: typ,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func labIOCSet(t *testing.T) threatintel.Set {
	t.Helper()
	content := `[
	  {"kind":"ip","value":"203.0.113.7","source":"lab-ioc-v1"},
	  {"kind":"domain","value":"Malicious-Test.EXAMPLE.","source":"lab-ioc-v1"}
	]`
	p := filepath.Join(t.TempDir(), "iocs.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := threatintel.LoadSet(p, "lab-ioc-set", "v1")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestConfiguredIOCMatch(t *testing.T) {
	set := labIOCSet(t)
	r, err := NewConfiguredIOCMatchRule(set, v1.Severity_SEVERITY_HIGH, "lab-ioc-policy")
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	hit, err := r.Evaluate(threatEvt("t1", "net.connection", 0, map[string]string{
		"net.src_ip": "10.0.0.9", "net.dst_ip": "203.0.113.7"}))
	if err != nil || !hit.Matched {
		t.Fatalf("exact IOC must match: %+v %v", hit, err)
	}
	if hit.Severity != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("policy severity applies, got %v", hit.Severity)
	}
	if hit.Attrs["ioc_set"] != "lab-ioc-set" || hit.Attrs["ioc_version"] != "v1" {
		t.Fatalf("set provenance missing: %+v", hit.Attrs)
	}
	if hit.Attrs["indicator"] != "203.0.113.7" {
		t.Fatalf("indicator provenance missing: %+v", hit.Attrs)
	}
	// Near-miss must not match; unrelated must not match.
	for name, e := range map[string]*v1.TelemetryEvent{
		"near miss": threatEvt("t2", "net.connection", 0, map[string]string{"net.dst_ip": "203.0.113.70"}),
		"unrelated": threatEvt("t3", "auth.activity", 0, map[string]string{"auth.principal": "alice"}),
	} {
		out, err := r.Evaluate(e)
		if err != nil || out.Matched {
			t.Errorf("%s: must not match: %+v %v", name, out, err)
		}
	}
	// No hardcoded IOC=CRITICAL: severity comes only from policy.
	r2, err := NewConfiguredIOCMatchRule(set, v1.Severity_SEVERITY_LOW, "lab-low")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := r2.Evaluate(threatEvt("t4", "net.connection", 0, map[string]string{"net.dst_ip": "203.0.113.7"}))
	if !out.Matched || out.Severity != v1.Severity_SEVERITY_LOW {
		t.Fatalf("policy severity must flow through: %+v", out)
	}
	if _, err := NewConfiguredIOCMatchRule(set, v1.Severity_SEVERITY_UNSPECIFIED, "x"); err == nil {
		t.Errorf("unspecified severity must be rejected")
	}
	if _, err := NewConfiguredIOCMatchRule(threatintel.Set{}, v1.Severity_SEVERITY_HIGH, "x"); err == nil {
		t.Errorf("empty set must be rejected")
	}
	if _, err := r.Evaluate(nil); err == nil {
		t.Errorf("nil must error")
	}
}

func TestMultiStageCorrelatedActivity(t *testing.T) {
	clock := func() time.Time { return threatBase }
	r, err := NewMultiStageCorrelatedRule(2, 10*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mkAuth := func(id string, minute int, principal, outcome string) *v1.TelemetryEvent {
		return threatEvt(id, "auth.activity", minute, map[string]string{
			"auth.principal": principal, "auth.outcome": outcome})
	}
	mkChange := func(id string, minute int, principal string) *v1.TelemetryEvent {
		return threatEvt(id, "identity.activity", minute, map[string]string{
			"identity.principal": principal, "identity.action": "role_change"})
	}
	fires := 0
	for i, e := range []*v1.TelemetryEvent{
		mkAuth("m1", 0, "erin", "failure"),
		mkAuth("m2", 1, "erin", "failure"),
		mkAuth("m3", 2, "erin", "success"),
		mkChange("m4", 3, "erin"),
	} {
		out, err := r.Evaluate(e)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if out.Matched {
			fires++
			if len(out.EventIDs) != 3 {
				t.Errorf("want 2 failures + change, got %v", out.EventIDs)
			}
		}
	}
	if fires != 1 {
		t.Fatalf("want exactly one fire, got %d", fires)
	}
	// Different principal: no sequence.
	r2, _ := NewMultiStageCorrelatedRule(1, 10*time.Minute, clock)
	r2.Evaluate(mkAuth("n1", 0, "erin", "failure"))
	if out, _ := r2.Evaluate(mkChange("n2", 1, "mallory")); out.Matched {
		t.Fatalf("different principals must not complete a sequence")
	}
	// Successes alone never complete.
	r3, _ := NewMultiStageCorrelatedRule(1, 10*time.Minute, clock)
	r3.Evaluate(mkAuth("s1", 0, "erin", "success"))
	if out, _ := r3.Evaluate(mkChange("s2", 1, "erin")); out.Matched {
		t.Fatalf("success is not failure: no sequence")
	}
	// Re-arm after window.
	r4, _ := NewMultiStageCorrelatedRule(1, 5*time.Minute, clock)
	r4.Evaluate(mkAuth("w1", 0, "erin", "failure"))
	r4.Evaluate(mkChange("w2", 1, "erin"))
	r4.Evaluate(mkAuth("w3", 20, "erin", "failure"))
	if out, _ := r4.Evaluate(mkChange("w4", 21, "erin")); !out.Matched {
		t.Fatalf("re-arm after window must fire")
	}
	if _, err := NewMultiStageCorrelatedRule(0, 5*time.Minute, clock); err == nil {
		t.Errorf("zero threshold must be rejected")
	}
}

func TestRuleErrorBurstHelper(t *testing.T) {
	errs := []ErrorEvent{
		{RuleID: "boom", EventID: "e1", At: threatBase},
		{RuleID: "boom", EventID: "e2", At: threatBase.Add(time.Minute)},
		{RuleID: "boom", EventID: "e3", At: threatBase.Add(2 * time.Minute)},
		{RuleID: "other", EventID: "e4", At: threatBase.Add(3 * time.Minute)},
	}
	bursts := ErrorBursts(errs, "boom", 3, 5*time.Minute)
	if len(bursts) != 1 || len(bursts[0]) != 3 {
		t.Fatalf("want one 3-event burst, got %+v", bursts)
	}
	// Below threshold: nothing. Other rule isolated.
	if got := ErrorBursts(errs[:2], "boom", 3, 5*time.Minute); len(got) != 0 {
		t.Fatalf("below threshold must be silent: %+v", got)
	}
	if got := ErrorBursts(errs, "other", 2, 5*time.Minute); len(got) != 0 {
		t.Fatalf("single error below threshold 2 must be silent: %+v", got)
	}
	// Window expiry re-arms.
	spread := []ErrorEvent{
		{RuleID: "boom", EventID: "e1", At: threatBase},
		{RuleID: "boom", EventID: "e2", At: threatBase.Add(10 * time.Minute)},
		{RuleID: "boom", EventID: "e3", At: threatBase.Add(11 * time.Minute)},
		{RuleID: "boom", EventID: "e4", At: threatBase.Add(12 * time.Minute)},
	}
	if got := ErrorBursts(spread, "boom", 3, 5*time.Minute); len(got) != 1 {
		t.Fatalf("want re-armed burst after expiry, got %+v", got)
	}
	if _, err := NewRuleErrorBurstRule(nil, 3, 5*time.Minute); err == nil {
		t.Errorf("nil engine must be rejected")
	}
}

func TestRuleErrorBurstRuleBuildsDetection(t *testing.T) {
	eng, err := NewEngine(func() time.Time { return threatBase })
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RegisterRule(failRule{}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p2", "p3"} {
		_, _ = eng.Process(threatEvt(id, "anything.at.all", 0, map[string]string{}))
	}
	r, err := NewRuleErrorBurstRule(eng, 3, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID() != "detection-rule-error-burst" || r.Version() != "1" {
		t.Fatalf("rule identity: %s %s", r.ID(), r.Version())
	}
	dets, err := r.Detections(func() time.Time { return threatBase })
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("want 1 error-burst detection, got %d", len(dets))
	}
	d := dets[0]
	if d.GetRuleId() != "detection-rule-error-burst" {
		t.Fatalf("rule id: %s", d.GetRuleId())
	}
	if len(d.GetTelemetryEventIds()) != 3 {
		t.Fatalf("event linkage: %v", d.GetTelemetryEventIds())
	}
	if d.GetAttributes()["failing_rule"] != "test-always-fails" {
		t.Fatalf("provenance: %+v", d.GetAttributes())
	}
	// Idempotent: second call yields the same deterministic detection.
	again, _ := r.Detections(func() time.Time { return threatBase })
	if again[0].GetId() != d.GetId() {
		t.Fatalf("detection id unstable")
	}
}
