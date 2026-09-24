// RED: application-layer detections
package detect

import (
	"fmt"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/httpobs"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var httpBase = time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)

func httpTelemetry(id, host, path string, status int, extra map[string]string) *v1.TelemetryEvent {
	attrs := map[string]string{"http.method": "GET", "http.host": host, "http.path": path}
	if status != 0 {
		attrs["http.status_code"] = fmt.Sprint(status)
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(httpBase), Source: "lab-http", AssetId: "seed-http-01",
		EventType: httpobs.EventTypeHTTPRequest, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func withMinute(e *v1.TelemetryEvent, minute int) *v1.TelemetryEvent {
	e.OccurredAt = timestamppb.New(httpBase.Add(time.Duration(minute) * time.Minute))
	return e
}

func mustHTTPBurst(t *testing.T) *HTTPErrorBurstRule {
	t.Helper()
	r, err := NewHTTPErrorBurstRule(3, 5*time.Minute, func() time.Time { return httpBase })
	if err != nil {
		t.Fatalf("burst ctor: %v", err)
	}
	return r
}

func TestHTTPErrorBurst(t *testing.T) {
	r := mustHTTPBurst(t)
	mk := func(id string, minute int) *v1.TelemetryEvent {
		return withMinute(httpTelemetry(id, "example.com", "/api/users", 500, nil), minute)
	}
	var fires []Outcome
	for i, m := range []int{0, 1, 2, 3} {
		out, err := r.Evaluate(mk("e"+fmt.Sprint(i), m))
		if err != nil {
			t.Fatalf("m=%d: %v", m, err)
		}
		if out.Matched {
			fires = append(fires, out)
		}
	}
	if len(fires) != 1 {
		t.Fatalf("want 1 fire at threshold, got %d", len(fires))
	}
	if fires[0].Attrs["count"] != "3" {
		t.Fatalf("count provenance: %+v", fires[0].Attrs)
	}
	other := withMinute(httpTelemetry("eX", "example.com", "/other", 500, nil), 2)
	if out, _ := r.Evaluate(other); out.Matched {
		t.Fatalf("different route must be separate window")
	}
	ok := withMinute(httpTelemetry("e200", "example.com", "/api/users", 200, nil), 4)
	if out, _ := r.Evaluate(ok); out.Matched {
		t.Fatalf("200 must not count")
	}
	r2 := mustHTTPBurst(t)
	for _, m := range []int{0, 1, 2} {
		r2.Evaluate(withMinute(httpTelemetry("a"+fmt.Sprint(m), "example.com", "/api/users", 500, nil), m))
	}
	r2.Evaluate(withMinute(httpTelemetry("a3", "example.com", "/api/users", 500, nil), 3))
	// Re-arm needs 3 new events after window expiry (cutoff 5)
	for _, m := range []int{10, 11} {
		if out, _ := r2.Evaluate(withMinute(httpTelemetry("b"+fmt.Sprint(m), "example.com", "/api/users", 500, nil), m)); out.Matched {
			t.Fatalf("must not fire before threshold at %d", m)
		}
	}
	if out, _ := r2.Evaluate(withMinute(httpTelemetry("b12", "example.com", "/api/users", 500, nil), 12)); !out.Matched {
		t.Fatalf("re-arm after window should fire at 12")
	}
}

func TestHTTPAuthBurst(t *testing.T) {
	clock := func() time.Time { return httpBase }
	r, err := NewAuthFailureBurstRule(3, 5*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mk := func(id string, minute int, outcome string) *v1.TelemetryEvent {
		return withMinute(httpTelemetry(id, "example.com", "/login", 401, map[string]string{"http.auth_outcome": outcome}), minute)
	}
	fires := 0
	for i, c := range []struct {
		id, outcome string
		minute      int
	}{
		{"a1", "failure", 0}, {"a2", "failure", 1}, {"a3", "success", 2}, {"a4", "failure", 3},
	} {
		out, err := r.Evaluate(mk(c.id, c.minute, c.outcome))
		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
		if out.Matched {
			fires++
		}
	}
	if fires != 1 {
		t.Fatalf("want 1 fire after 3 failures (success ignored), got %d", fires)
	}
	noOutcome := withMinute(httpTelemetry("no", "example.com", "/login", 401, nil), 5)
	if out, _ := r.Evaluate(noOutcome); out.Matched {
		t.Fatalf("401 without auth_outcome must not be failure")
	}
}

func TestAppPolicyViolation(t *testing.T) {
	r, err := NewAppPolicyViolationRule(AppPolicy{DisallowedMethods: []string{"TRACE"}, DisallowedRoutes: []string{"/admin"}, DisallowedContentTypes: []string{"text/html"}, Severity: v1.Severity_SEVERITY_HIGH})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if _, err := NewAppPolicyViolationRule(AppPolicy{DisallowedMethods: []string{"TRACE"}}); err == nil {
		t.Fatalf("policy without explicit severity must be rejected")
	}
	cases := map[string]struct {
		attrs map[string]string
		hit   bool
	}{
		"method":  {map[string]string{"http.method": "TRACE", "http.host": "example.com", "http.path": "/"}, true},
		"route":   {map[string]string{"http.method": "GET", "http.host": "example.com", "http.path": "/admin"}, true},
		"content": {map[string]string{"http.method": "GET", "http.host": "example.com", "http.path": "/", "http.content_type": "text/html"}, true},
		"params":  {map[string]string{"http.method": "GET", "http.host": "example.com", "http.path": "/", "http.content_type": "text/html; charset=utf-8"}, true},
		"ok":      {map[string]string{"http.method": "GET", "http.host": "example.com", "http.path": "/api"}, false},
	}
	for name, c := range cases {
		evt := &v1.TelemetryEvent{
			Id: "p1", OccurredAt: timestamppb.New(httpBase), Source: "lab-http", AssetId: "a1",
			EventType: httpobs.EventTypeHTTPRequest, Severity: v1.Severity_SEVERITY_INFO, Attributes: c.attrs,
		}
		out, err := r.Evaluate(evt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out.Matched != c.hit {
			t.Errorf("%s: matched=%v want %v", name, out.Matched, c.hit)
		}
		if out.Matched && out.Severity != v1.Severity_SEVERITY_HIGH {
			t.Errorf("%s: outcome must repeat policy severity, got %v", name, out.Severity)
		}
	}
	if _, err := NewAppPolicyViolationRule(AppPolicy{DisallowedMethods: []string{"FOO"}}); err == nil {
		t.Error("bad method must error")
	}
	if _, err := NewAppPolicyViolationRule(AppPolicy{}); err == nil {
		t.Error("empty policy must error")
	}
}

func TestHTTPBurstInvalidConfig(t *testing.T) {
	if _, err := NewHTTPErrorBurstRule(0, 5*time.Minute, func() time.Time { return httpBase }); err == nil {
		t.Error("zero threshold")
	}
	if _, err := NewAuthFailureBurstRule(3, 0, func() time.Time { return httpBase }); err == nil {
		t.Error("zero window")
	}
}
