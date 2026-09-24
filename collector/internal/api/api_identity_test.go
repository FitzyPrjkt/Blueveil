// RED: identity/auth/data observation read endpoints.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func seedIdentity(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id string, minute int, typ string, attrs map[string]string) {
		if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
			Id: id, OccurredAt: timestamppb.New(base.Add(time.Duration(minute) * time.Minute)),
			Source: "seed-lab-identity", AssetId: "seed-ident-01",
			EventType: typ, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	mk("id1", 0, "identity.activity", map[string]string{
		"identity.principal": "alice", "identity.action": "login", "identity.result": "success"})
	mk("id2", 1, "identity.activity", map[string]string{
		"identity.principal": "alice", "identity.action": "role_change", "identity.target": "admin-role"})
	mk("a1", 2, "auth.activity", map[string]string{
		"auth.principal": "alice", "auth.outcome": "failure", "auth.authentication_method": "password"})
	mk("a2", 3, "auth.activity", map[string]string{
		"auth.principal": "bob", "auth.outcome": "success", "auth.authentication_method": "sso"})
	mk("d1", 4, "data.activity", map[string]string{
		"data.resource": "customers", "data.action": "export", "data.classification": "restricted", "data.principal": "alice"})
	mk("d2", 5, "data.activity", map[string]string{
		"data.resource": "blog", "data.action": "read", "data.classification": "public"})
	// Secret-bearing row: must come back redacted.
	mk("a3", 6, "auth.activity", map[string]string{
		"auth.principal": "carol", "auth.outcome": "failure", "auth.password": "hunter2"})
	if err := be.Detection.Append(ctx, &v1.Detection{
		Id: "det-a1", RuleId: "ident-auth-failure-burst", RuleName: "Authentication failure burst",
		TelemetryEventIds: []string{"a1"}, DetectedAt: timestamppb.New(base.Add(5 * time.Minute)),
		Severity: v1.Severity_SEVERITY_MEDIUM, Confidence: 0,
		Title: "Repeated authentication failures observed", Description: "lab",
	}); err != nil {
		t.Fatalf("detection: %v", err)
	}
	return NewServer(be)
}

func TestIdentityObservationsListAndFilters(t *testing.T) {
	srv := seedIdentity(t)
	code, body := apiGet(t, srv, "/api/v1/identity/observations")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("want 2 identity obs, got %d %+v", code, body)
	}
	rows := body["data"].([]any)
	if rows[0].(map[string]any)["id"] != "id1" || rows[1].(map[string]any)["id"] != "id2" {
		t.Fatalf("deterministic order violated: %v", rows)
	}
	cases := map[string]struct {
		path string
		want int
	}{
		"principal": {"/api/v1/identity/observations?principal=alice", 2},
		"action":    {"/api/v1/identity/observations?action=role_change", 1},
		"result":    {"/api/v1/identity/observations?result=success", 1},
	}
	for name, c := range cases {
		code, body := apiGet(t, srv, c.path)
		if code != 200 || dataLen(t, body) != c.want {
			t.Errorf("%s: want %d, got %d %+v", name, c.want, code, body)
		}
	}
	if code, _ := apiGet(t, srv, "/api/v1/identity/observations?action=hack"); code != 400 {
		t.Errorf("unknown action must 400, got %d", code)
	}
}

func TestAuthObservationsFiltersAndRedaction(t *testing.T) {
	srv := seedIdentity(t)
	code, body := apiGet(t, srv, "/api/v1/authentication/observations")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("want 2 auth obs (secret row skipped), got %d %+v", code, body)
	}
	for _, r := range body["data"].([]any) {
		m := r.(map[string]any)
		for k := range m {
			if k == "auth.password" || k == "password" {
				t.Fatalf("secret leaked in response: %v", m)
			}
		}
		if m["id"] == "a3" {
			t.Fatalf("secret-bearing row a3 must be dropped as corrupt, got row: %v", m)
		}
	}
	cases := map[string]struct {
		path string
		want int
	}{
		"outcome failure": {"/api/v1/authentication/observations?outcome=failure", 1},
		"principal":       {"/api/v1/authentication/observations?principal=bob", 1},
		"method":          {"/api/v1/authentication/observations?method=password", 1},
		"detected":        {"/api/v1/authentication/observations?detected=true", 1},
		"undetected":      {"/api/v1/authentication/observations?detected=false", 1},
	}
	for name, c := range cases {
		code, body := apiGet(t, srv, c.path)
		if code != 200 || dataLen(t, body) != c.want {
			t.Errorf("%s: want %d, got %d %+v", name, c.want, code, body)
		}
	}
	if code, _ := apiGet(t, srv, "/api/v1/authentication/observations?outcome=pwned"); code != 400 {
		t.Errorf("unknown outcome must 400, got %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/authentication/observations?detected=sometimes"); code != 400 {
		t.Errorf("bad detected must 400, got %d", code)
	}
}

func TestDataObservationsFilters(t *testing.T) {
	srv := seedIdentity(t)
	code, body := apiGet(t, srv, "/api/v1/data/observations")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("want 2 data obs, got %d %+v", code, body)
	}
	cases := map[string]struct {
		path string
		want int
	}{
		"store empty":     {"/api/v1/data/observations?store=lab-db", 0},
		"classification":  {"/api/v1/data/observations?classification=restricted", 1},
		"action":          {"/api/v1/data/observations?action=read", 1},
		"result empty ok": {"/api/v1/data/observations", 2},
	}
	for name, c := range cases {
		code, body := apiGet(t, srv, c.path)
		if code != 200 || dataLen(t, body) != c.want {
			t.Errorf("%s: want %d, got %d %+v", name, c.want, code, body)
		}
	}
	if code, _ := apiGet(t, srv, "/api/v1/data/observations?action=exfiltrate"); code != 400 {
		t.Errorf("unknown action must 400, got %d", code)
	}
}

func TestIdentityMethodGuard(t *testing.T) {
	srv := seedIdentity(t)
	for _, p := range []string{"/api/v1/identity/observations", "/api/v1/authentication/observations", "/api/v1/data/observations", "/api/v1/identity/relationships"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != 405 {
			t.Errorf("POST %s: want 405, got %d", p, rec.Code)
		}
	}
}
