// RED: monitoring/SIEM/rules/TI read endpoints.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func seedMonitoring(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := t.Context()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id string, minute int, typ, source, asset, sev string, attrs map[string]string) {
		sevv := v1.Severity_SEVERITY_INFO
		if sev == "HIGH" {
			sevv = v1.Severity_SEVERITY_HIGH
		}
		if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
			Id: id, OccurredAt: timestamppb.New(base.Add(time.Duration(minute) * time.Minute)),
			Source: source, AssetId: asset, EventType: typ, Severity: sevv, Attributes: attrs,
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	mk("m1", 0, "auth.activity", "seed-lab-monitoring", "seed-mon-01", "INFO",
		map[string]string{"auth.principal": "erin", "auth.outcome": "failure"})
	mk("m2", 1, "auth.activity", "seed-lab-monitoring", "seed-mon-01", "INFO",
		map[string]string{"auth.principal": "erin", "auth.outcome": "failure"})
	mk("m3", 2, "identity.activity", "seed-lab-monitoring", "seed-mon-01", "INFO",
		map[string]string{"identity.principal": "erin", "identity.action": "role_change"})
	mk("m4", 3, "net.connection", "seed-lab-monitoring", "seed-mon-01", "HIGH",
		map[string]string{"net.src_ip": "10.0.0.9", "net.dst_ip": "203.0.113.7"})
	if err := be.Detection.Append(ctx, &v1.Detection{
		Id: "det-m4", RuleId: "configured-ioc-match", RuleName: "Configured IOC match observed",
		TelemetryEventIds: []string{"m4"}, DetectedAt: timestamppb.New(base.Add(5 * time.Minute)),
		Severity: v1.Severity_SEVERITY_HIGH, Confidence: 0,
		Title: "Configured IOC match observed", Description: "lab",
	}); err != nil {
		t.Fatalf("detection: %v", err)
	}
	srv := NewServer(be)
	srv.SetHealthProvider(func() []detect.RuleHealth {
		return []detect.RuleHealth{
			{RuleID: "waf-block-high-severity", Version: "1", Name: "High-severity blocked request", Enabled: true, Evaluated: 4, Detections: 1},
		}
	})
	return srv
}

func TestMonitoringEventsFilters(t *testing.T) {
	srv := seedMonitoring(t)
	cases := map[string]struct {
		path string
		want []string
	}{
		"all":        {"/api/v1/monitoring/events", []string{"m1", "m2", "m3", "m4"}},
		"type":       {"/api/v1/monitoring/events?event_type=auth.activity", []string{"m1", "m2"}},
		"source":     {"/api/v1/monitoring/events?source=seed-lab-monitoring", []string{"m1", "m2", "m3", "m4"}},
		"severity":   {"/api/v1/monitoring/events?severity=HIGH", []string{"m4"}},
		"asset":      {"/api/v1/monitoring/events?asset=seed-mon-01", []string{"m1", "m2", "m3", "m4"}},
		"detected":   {"/api/v1/monitoring/events?detected=true", []string{"m4"}},
		"undetected": {"/api/v1/monitoring/events?detected=false", []string{"m1", "m2", "m3"}},
		"limit":      {"/api/v1/monitoring/events?limit=2", []string{"m1", "m2"}},
		"desc":       {"/api/v1/monitoring/events?order=desc", []string{"m4", "m3", "m2", "m1"}},
		"time range": {"/api/v1/monitoring/events?from=2026-09-12T09:01:00Z&to=2026-09-12T09:02:00Z", []string{"m2", "m3"}},
	}
	for name, c := range cases {
		code, body := apiGet(t, srv, c.path)
		if code != 200 {
			t.Errorf("%s: want 200, got %d %+v", name, code, body)
			continue
		}
		got := idsOf(t, body)
		if len(got) != len(c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: want %v, got %v", name, c.want, got)
				break
			}
		}
	}
	for name, path := range map[string]string{
		"bad severity": "/api/v1/monitoring/events?severity=BOGUS",
		"bad detected": "/api/v1/monitoring/events?detected=sometimes",
		"bad limit":    "/api/v1/monitoring/events?limit=-1",
		"bad order":    "/api/v1/monitoring/events?order=sideways",
		"bad from":     "/api/v1/monitoring/events?from=not-a-time",
		"bad range":    "/api/v1/monitoring/events?from=2026-09-12T09:05:00Z&to=2026-09-12T09:01:00Z",
	} {
		if code, _ := apiGet(t, srv, path); code != 400 {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
}

func TestMonitoringCorrelations(t *testing.T) {
	srv := seedMonitoring(t)
	code, body := apiGet(t, srv, "/api/v1/monitoring/correlations")
	if code != 200 {
		t.Fatalf("want 200, got %d %+v", code, body)
	}
	rows := body["data"].([]any)
	if len(rows) != 1 {
		t.Fatalf("want the erin C1 correlation, got %v", rows)
	}
	m := rows[0].(map[string]any)
	if m["type"] != "auth-to-identity-change" || m["status"] != "CORRELATED" {
		t.Fatalf("correlation shape wrong: %v", m)
	}
	if m["principal"] != "erin" {
		t.Fatalf("principal wrong: %v", m)
	}
	code, body = apiGet(t, srv, "/api/v1/monitoring/correlations?type=network-to-application")
	if code != 200 || dataLen(t, body) != 0 {
		t.Fatalf("type filter must narrow honestly")
	}
	if code, _ := apiGet(t, srv, "/api/v1/monitoring/correlations?type=bogus"); code != 400 {
		t.Fatalf("unknown correlation type must 400, got %d", code)
	}
}

func TestDetectionRulesEndpoints(t *testing.T) {
	srv := seedMonitoring(t)
	code, body := apiGet(t, srv, "/api/v1/detection-rules")
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	rows := body["data"].([]any)
	if len(rows) < 20 {
		t.Fatalf("catalog must list all known rules, got %d", len(rows))
	}
	for _, r := range rows {
		m := r.(map[string]any)
		for _, k := range []string{"id", "version", "title", "description", "domain", "severity_basis", "confidence_basis", "stateful", "enabled"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("rule metadata missing %s: %v", k, m)
			}
		}
		// event_types must always be an array (never null) so UI
		// parsers accept catch-all rules.
		if _, ok := m["event_types"].([]any); !ok {
			t.Fatalf("event_types must be an array: %v", m)
		}
	}
	code, body = apiGet(t, srv, "/api/v1/detection-rules?domain=network")
	if code != 200 {
		t.Fatalf("domain filter: %d", code)
	}
	for _, r := range body["data"].([]any) {
		if r.(map[string]any)["domain"] != "network" {
			t.Fatalf("domain filter leaked: %v", r)
		}
	}
	if code, _ := apiGet(t, srv, "/api/v1/detection-rules?enabled=sometimes"); code != 400 {
		t.Errorf("bad enabled must 400, got %d", code)
	}
	code, body = apiGet(t, srv, "/api/v1/detection-rules/health")
	if code != 200 {
		t.Fatalf("health: %d", code)
	}
	hrows := body["data"].([]any)
	if len(hrows) != 1 || hrows[0].(map[string]any)["rule_id"] != "waf-block-high-severity" {
		t.Fatalf("health must come from provider: %v", hrows)
	}
	// No provider: honest absence, never fabricated zeros-as-facts.
	plain := NewServer(mustBackend(t))
	code, body = apiGet(t, plain, "/api/v1/detection-rules/health")
	if code != 200 {
		t.Fatalf("health absent: %d", code)
	}
	if body["status"] != "unavailable" {
		t.Fatalf("health without provider must say unavailable: %v", body)
	}
}

func TestThreatIntelEndpointsWithoutSet(t *testing.T) {
	srv := seedMonitoring(t)
	code, body := apiGet(t, srv, "/api/v1/threat-intelligence/iocs")
	if code != 200 {
		t.Fatalf("iocs: %d", code)
	}
	if body["status"] != "unavailable" {
		t.Fatalf("iocs without set must say unavailable: %v", body)
	}
	code, body = apiGet(t, srv, "/api/v1/threat-intelligence/matches")
	if code != 200 || body["status"] != "unavailable" {
		t.Fatalf("matches without set must say unavailable: %d %+v", code, body)
	}
}

func TestMonitoringMethodGuard(t *testing.T) {
	srv := seedMonitoring(t)
	for _, p := range []string{"/api/v1/monitoring/events", "/api/v1/monitoring/correlations", "/api/v1/detection-rules", "/api/v1/detection-rules/health", "/api/v1/threat-intelligence/iocs", "/api/v1/threat-intelligence/matches"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != 405 {
			t.Errorf("POST %s: want 405, got %d", p, rec.Code)
		}
	}
}

func idsOf(t *testing.T, body map[string]any) []string {
	t.Helper()
	rows := body["data"].([]any)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.(map[string]any)["id"].(string))
	}
	return out
}

func mustBackend(t *testing.T) store.Backend {
	t.Helper()
	return store.NewMemoryBackend()
}
