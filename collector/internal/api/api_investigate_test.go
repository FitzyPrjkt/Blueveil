// RED: hunting/timeline/forensics/incident-timeline read endpoints.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func seedInvestigate(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := t.Context()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id string, minute int, typ, source, asset string, attrs map[string]string) {
		if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
			Id: id, OccurredAt: timestamppb.New(base.Add(time.Duration(minute) * time.Minute)),
			Source: source, AssetId: asset, EventType: typ, Severity: v1.Severity_SEVERITY_INFO,
			Attributes: attrs,
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	mk("g1", 0, "auth.activity", "seed-lab-investigation", "seed-inv-01",
		map[string]string{"auth.principal": "erin", "auth.outcome": "failure"})
	mk("g2", 1, "endpoint.activity", "seed-lab-investigation", "seed-inv-01",
		map[string]string{"endpoint.host": "web01", "endpoint.process": "agent", "endpoint.action": "process_start"})
	mk("g3", 2, "auth.activity", "seed-lab-investigation", "seed-inv-01",
		map[string]string{"auth.principal": "erin", "auth.outcome": "failure", "auth.password": "hunter2"})
	if err := be.Detection.Append(ctx, &v1.Detection{
		Id: "det-g1", RuleId: "ident-auth-failure-burst", RuleName: "Authentication failure burst",
		TelemetryEventIds: []string{"g1"}, DetectedAt: timestamppb.New(base.Add(5 * time.Minute)),
		Severity: v1.Severity_SEVERITY_INFO, Confidence: 0,
		Title: "Repeated authentication failures observed", Description: "lab",
	}); err != nil {
		t.Fatalf("detection: %v", err)
	}
	if err := be.Alert.Append(ctx, &v1.Alert{
		Id: "alert-g1", DetectionIds: []string{"det-g1"}, Status: v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity:  v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(base.Add(6 * time.Minute)),
		UpdatedAt: timestamppb.New(base.Add(6 * time.Minute)),
		Title:     "Alert: repeated failures",
	}); err != nil {
		t.Fatalf("alert: %v", err)
	}
	if err := be.Incident.Create(ctx, &v1.Incident{
		Id: "inc-g1", AlertIds: []string{"alert-g1"}, Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		Severity:  v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(base.Add(7 * time.Minute)),
		UpdatedAt: timestamppb.New(base.Add(7 * time.Minute)),
		Title:     "I1", Summary: "lab incident",
	}); err != nil {
		t.Fatalf("incident: %v", err)
	}
	if err := be.Evidence.Append(ctx, &v1.Evidence{
		Id: "ev-g1", IncidentId: "inc-g1", Type: v1.EvidenceType_EVIDENCE_TYPE_NOTE,
		CollectedAt: timestamppb.New(base.Add(8 * time.Minute)),
		Source:      "seed-lab-investigation", MediaType: "text/plain",
		Sha256: "abababababababababababababababababababababababababababababababab", Content: "note",
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	return NewServer(be)
}

func TestHuntingEvents(t *testing.T) {
	srv := seedInvestigate(t)
	cases := map[string]struct {
		path string
		want []string
	}{
		"all":       {"/api/v1/hunting/events", []string{"g1", "g2", "g3"}},
		"principal": {"/api/v1/hunting/events?principal=erin", []string{"g1", "g3"}},
		"keyword":   {"/api/v1/hunting/events?keyword=web01", []string{"g2"}},
		"type":      {"/api/v1/hunting/events?event_type=auth.activity", []string{"g1", "g3"}},
		"limit":     {"/api/v1/hunting/events?limit=1", []string{"g1"}},
		"empty":     {"/api/v1/hunting/events?keyword=zzz-no-such", []string{}},
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
	// Every row is tagged HUNT_RESULT, never CONFIRMED_ATTACK.
	_, body := apiGet(t, srv, "/api/v1/hunting/events?limit=1")
	row := body["data"].([]any)[0].(map[string]any)
	if row["kind"] != "HUNT_RESULT" {
		t.Errorf("hunt row kind must be HUNT_RESULT, got %v", row)
	}
	for name, path := range map[string]string{
		"bad limit": "/api/v1/hunting/events?limit=5000",
		"bad from":  "/api/v1/hunting/events?from=nope",
		"bad range": "/api/v1/hunting/events?from=2026-09-12T09:05:00Z&to=2026-09-12T09:01:00Z",
	} {
		if code, _ := apiGet(t, srv, path); code != 400 {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
}

func TestHuntingTimeline(t *testing.T) {
	srv := seedInvestigate(t)
	code, body := apiGet(t, srv, "/api/v1/hunting/timeline")
	if code != 200 {
		t.Fatalf("want 200, got %d %+v", code, body)
	}
	rows := body["data"].([]any)
	// 3 telemetry + 1 detection + 1 alert + 1 incident + 1 evidence.
	if len(rows) != 7 {
		t.Fatalf("want 7 timeline rows, got %d", len(rows))
	}
	first := rows[0].(map[string]any)
	if first["id"] != "g1" || first["kind"] != "telemetry" {
		t.Fatalf("timeline must start at earliest telemetry: %+v", first)
	}
	kinds := map[string]bool{}
	for _, r := range rows {
		kinds[r.(map[string]any)["kind"].(string)] = true
	}
	for _, k := range []string{"telemetry", "detection", "alert", "incident", "evidence"} {
		if !kinds[k] {
			t.Errorf("timeline missing kind %s", k)
		}
	}
}

func TestForensicsArtifacts(t *testing.T) {
	srv := seedInvestigate(t)
	code, body := apiGet(t, srv, "/api/v1/forensics/artifacts")
	if code != 200 || dataLen(t, body) != 3 {
		t.Fatalf("want 3 artifacts, got %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/forensics/endpoint")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 endpoint artifact, got %d %+v", code, body)
	}
	row := body["data"].([]any)[0].(map[string]any)
	if row["type"] != "PROCESS" {
		t.Fatalf("endpoint artifact type: %+v", row)
	}
	for name, path := range map[string]string{
		"network": "/api/v1/forensics/network",
		"cloud":   "/api/v1/forensics/cloud",
	} {
		if code, body := apiGet(t, srv, path); code != 200 || dataLen(t, body) != 0 {
			t.Errorf("%s: want 200 empty, got %d %+v", name, code, body)
		}
	}
	if code, body := apiGet(t, srv, "/api/v1/forensics/identity"); code != 200 || dataLen(t, body) != 2 {
		t.Errorf("identity: want 200 with 2 auth artifacts, got %d %+v", code, body)
	}
	// Redaction: the auth.password value must not appear anywhere.
	code, body = apiGet(t, srv, "/api/v1/forensics/identity")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("want 2 identity artifacts, got %d %+v", code, body)
	}
	for _, p := range []string{"/api/v1/forensics/artifacts", "/api/v1/hunting/events"} {
		_, b := apiGet(t, srv, p)
		for _, r := range b["data"].([]any) {
			s := string(mustJSON(t, r))
			if contains(s, "hunter2") {
				t.Errorf("secret leaked via %s", p)
			}
		}
	}
}

func TestIncidentTimeline(t *testing.T) {
	srv := seedInvestigate(t)
	code, body := apiGet(t, srv, "/api/v1/incidents/inc-g1/timeline")
	if code != 200 {
		t.Fatalf("want 200, got %d %+v", code, body)
	}
	rows := body["data"].([]any)
	// incident + its alert + detection + evidence + linked telemetry g1.
	if len(rows) != 5 {
		t.Fatalf("want 5 incident-scoped rows, got %d", len(rows))
	}
	if code, _ := apiGet(t, srv, "/api/v1/incidents/no-such/timeline"); code != 404 {
		t.Errorf("unknown incident must 404, got %d", code)
	}
}

func TestInvestigateMethodGuard(t *testing.T) {
	srv := seedInvestigate(t)
	for _, p := range []string{
		"/api/v1/hunting/events", "/api/v1/hunting/timeline",
		"/api/v1/forensics/artifacts", "/api/v1/forensics/endpoint",
		"/api/v1/forensics/network", "/api/v1/forensics/cloud",
		"/api/v1/forensics/identity", "/api/v1/incidents/inc-g1/timeline",
	} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != 405 {
			t.Errorf("POST %s: want 405, got %d", p, rec.Code)
		}
	}
}
