// RED: I1/A1/A2/D1 identity & data detections — explicit semantics only.
package detect

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var identBase = time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)

func identEvt(typ, id string, minute int, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(identBase.Add(time.Duration(minute) * time.Minute)),
		Source: "seed-lab-identity", AssetId: "seed-ident-01", EventType: typ,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func TestPrivilegeChangeMatches(t *testing.T) {
	r := IdentityPrivilegeChangeRule{}
	hit, err := r.Evaluate(identEvt("identity.activity", "i1", 0, map[string]string{
		"identity.principal": "alice", "identity.action": "role_change", "identity.target": "admin-role",
	}))
	if err != nil || !hit.Matched {
		t.Fatalf("role_change must match: %+v %v", hit, err)
	}
	if hit.Severity != v1.Severity_SEVERITY_INFO {
		t.Fatalf("severity inherits source, got %v", hit.Severity)
	}
	for name, e := range map[string]*v1.TelemetryEvent{
		"login is not privilege change": identEvt("identity.activity", "i2", 0, map[string]string{
			"identity.principal": "alice", "identity.action": "login"}),
		"username alone is nothing": identEvt("identity.activity", "i3", 0, map[string]string{
			"identity.principal": "root", "identity.action": "login"}),
		"wrong type": identEvt("auth.activity", "i4", 0, map[string]string{
			"auth.principal": "alice", "auth.outcome": "success"}),
	} {
		out, err := r.Evaluate(e)
		if err != nil || out.Matched {
			t.Errorf("%s: must not match: %+v %v", name, out, err)
		}
	}
	if _, err := r.Evaluate(nil); err == nil {
		t.Errorf("nil must error")
	}
	_ = r
}

func TestAuthFailureBurst(t *testing.T) {
	clock := func() time.Time { return identBase }
	r, err := NewIdentAuthFailureBurstRule(3, 5*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mk := func(id string, minute int, outcome, principal string) *v1.TelemetryEvent {
		return identEvt("auth.activity", id, minute, map[string]string{
			"auth.principal": principal, "auth.outcome": outcome})
	}
	fires := 0
	for i, c := range []struct {
		id, outcome, principal string
		minute                 int
	}{
		{"a1", "failure", "alice", 0}, {"a2", "failure", "alice", 1},
		{"a3", "success", "alice", 2}, {"a4", "failure", "alice", 3},
	} {
		out, err := r.Evaluate(mk(c.id, c.minute, c.outcome, c.principal))
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if out.Matched {
			fires++
			if out.Attrs["count"] != "3" || out.Attrs["threshold"] != "3" {
				t.Errorf("provenance: %+v", out.Attrs)
			}
		}
	}
	if fires != 1 {
		t.Fatalf("want exactly one fire, got %d", fires)
	}
	// Per-principal isolation: bob starts his own window.
	other := mk("b1", 3, "failure", "bob")
	if out, _ := r.Evaluate(other); out.Matched {
		t.Fatalf("other principal must not inherit the window")
	}
	// HTTP 401-shaped event without auth outcome must not count (wrong type).
	http401 := identEvt("http.request", "h1", 4, map[string]string{
		"http.method": "GET", "http.host": "x", "http.path": "/", "http.status_code": "401"})
	if out, _ := r.Evaluate(http401); out.Matched {
		t.Fatalf("http 401 without auth telemetry must not match")
	}
	// Re-arm: after window slides past, three new failures fire again.
	r2, _ := NewIdentAuthFailureBurstRule(2, 5*time.Minute, clock)
	r2.Evaluate(mk("c1", 0, "failure", "alice"))
	r2.Evaluate(mk("c2", 1, "failure", "alice"))
	r2.Evaluate(mk("c3", 2, "failure", "alice"))
	if out, _ := r2.Evaluate(mk("c4", 3, "failure", "alice")); out.Matched {
		t.Fatalf("still above threshold must stay silent")
	}
	r2.Evaluate(mk("c5", 10, "failure", "alice"))
	if out, _ := r2.Evaluate(mk("c6", 11, "failure", "alice")); !out.Matched {
		t.Fatalf("re-arm after window must fire")
	}
	if _, err := NewIdentAuthFailureBurstRule(0, 5*time.Minute, clock); err == nil {
		t.Errorf("zero threshold must be rejected")
	}
	if _, err := NewIdentAuthFailureBurstRule(3, 0, clock); err == nil {
		t.Errorf("zero window must be rejected")
	}
	if _, err := NewIdentAuthFailureBurstRule(3, 5*time.Minute, nil); err == nil {
		t.Errorf("nil clock must be rejected")
	}
}

func TestAuthDeniedBurstSeparated(t *testing.T) {
	clock := func() time.Time { return identBase }
	r, err := NewIdentAuthDeniedBurstRule(2, 5*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mk := func(id string, minute int, outcome string) *v1.TelemetryEvent {
		return identEvt("auth.activity", id, minute, map[string]string{
			"auth.principal": "alice", "auth.outcome": outcome})
	}
	// failures must not feed the denied window
	for _, c := range []struct {
		id      string
		minute  int
		outcome string
	}{{"d0", 0, "failure"}, {"d1", 1, "failure"}} {
		if out, _ := r.Evaluate(mk(c.id, c.minute, c.outcome)); out.Matched {
			t.Fatalf("failure must not feed denied rule")
		}
	}
	r2, _ := NewIdentAuthDeniedBurstRule(2, 5*time.Minute, clock)
	r2.Evaluate(mk("e0", 0, "denied"))
	if out, _ := r2.Evaluate(mk("e1", 1, "denied")); !out.Matched {
		t.Fatalf("two denied must fire")
	}
}

func TestDataPolicyViolation(t *testing.T) {
	r, err := NewSensitiveDataPolicyRule(SensitiveDataPolicy{
		Classifications: []string{"restricted"},
		Actions:         []string{"export"},
		Severity:        v1.Severity_SEVERITY_HIGH,
		Label:           "lab-restricted-export",
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	hit, err := r.Evaluate(identEvt("data.activity", "d1", 0, map[string]string{
		"data.resource": "customers", "data.action": "export", "data.classification": "restricted",
	}))
	if err != nil || !hit.Matched {
		t.Fatalf("policy match must fire: %+v %v", hit, err)
	}
	if hit.Severity != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("explicit policy severity applies, got %v", hit.Severity)
	}
	for name, e := range map[string]*v1.TelemetryEvent{
		"read is not export": identEvt("data.activity", "d2", 0, map[string]string{
			"data.resource": "customers", "data.action": "read", "data.classification": "restricted"}),
		"public export is not restricted": identEvt("data.activity", "d3", 0, map[string]string{
			"data.resource": "blog", "data.action": "export", "data.classification": "public"}),
		"read is not breach": identEvt("data.activity", "d4", 0, map[string]string{
			"data.resource": "customers", "data.action": "read"}),
	} {
		out, err := r.Evaluate(e)
		if err != nil || out.Matched {
			t.Errorf("%s: must not match: %+v %v", name, out, err)
		}
	}
	if _, err := NewSensitiveDataPolicyRule(SensitiveDataPolicy{}); err == nil {
		t.Errorf("empty policy must be rejected")
	}
	if _, err := NewSensitiveDataPolicyRule(SensitiveDataPolicy{
		Actions: []string{"exfiltrate"}, Severity: v1.Severity_SEVERITY_HIGH, Label: "x",
	}); err == nil {
		t.Errorf("unknown action must be rejected")
	}
}

func TestIdentRulesEngineIntegration(t *testing.T) {
	eng, err := NewEngine(func() time.Time { return identBase })
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	for _, r := range []Rule{IdentityPrivilegeChangeRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatal(err)
		}
	}
	burst, _ := NewIdentAuthFailureBurstRule(99, time.Hour, func() time.Time { return identBase })
	if err := eng.RegisterRule(burst); err != nil {
		t.Fatal(err)
	}
	normal := identEvt("auth.activity", "ok1", 0, map[string]string{
		"auth.principal": "alice", "auth.outcome": "success"})
	res, err := eng.Process(normal)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Detections) != 0 {
		t.Fatalf("ordinary auth must not alert: %+v", res)
	}
	bad := identEvt("identity.activity", "bad1", 1, map[string]string{
		"identity.principal": "alice", "identity.action": "permission_change", "identity.target": "admin-role"})
	res, err = eng.Process(bad)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Detections) != 1 || res.Detections[0].GetRuleId() != "identity-privilege-change" {
		t.Fatalf("want 1 privilege detection, got %+v", res)
	}
	res2, err := eng.Process(bad)
	if err != nil || len(res2.Detections) != 0 || res2.Suppressed != 1 {
		t.Fatalf("reprocess must suppress: %+v %v", res2, err)
	}
}
