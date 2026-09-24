// RED: application observation read endpoints.
package api

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/httpobs"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func seedApplication(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id string, minute int, host, path string, status int, extra map[string]string) {
		attrs := map[string]string{"http.method": "GET", "http.host": host, "http.path": path}
		if status != 0 {
			attrs["http.status_code"] = map[int]string{200: "200", 500: "500", 401: "401"}[status]
			if attrs["http.status_code"] == "" {
				attrs["http.status_code"] = "500"
			}
		}
		for k, v := range extra {
			attrs[k] = v
		}
		if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
			Id: id, OccurredAt: timestamppb.New(base.Add(time.Duration(minute) * time.Minute)),
			Source: "lab-http", AssetId: "seed-http-01", EventType: httpobs.EventTypeHTTPRequest,
			Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	mk("h1", 0, "example.com", "/api/users", 200, map[string]string{"http.route": "/api/users"})
	mk("h2", 1, "example.com", "/api/users", 500, nil)
	mk("h3", 2, "example.com", "/login", 401, map[string]string{"http.auth_outcome": "failure"})
	// WAF event to ensure http endpoint isolates event_type
	if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
		Id: "w1", OccurredAt: timestamppb.New(base.Add(3 * time.Minute)),
		Source: "lab-waf", AssetId: "seed-http-01", EventType: "waf.request_blocked",
		Severity: v1.Severity_SEVERITY_INFO, Attributes: map[string]string{},
	}); err != nil {
		t.Fatalf("append w1: %v", err)
	}
	// Add detection for h2
	if err := be.Detection.Append(ctx, &v1.Detection{
		Id: "det-h2", RuleId: "http-error-burst", RuleName: "HTTP error burst",
		TelemetryEventIds: []string{"h2"}, DetectedAt: timestamppb.New(base.Add(5 * time.Minute)),
		Severity: v1.Severity_SEVERITY_MEDIUM, Confidence: 0, Title: "HTTP error burst observed", Description: "lab",
	}); err != nil {
		t.Fatalf("detection: %v", err)
	}
	mgr, _ := asset.NewManager(be.Assets, memRelStore{be.Relationships}, time.Now)
	if _, _, err := mgr.Ingest(ctx, asset.Observation{Source: "test", Type: v1.AssetType_ASSET_TYPE_URL, Raw: "https://example.com/api/users", ObservedAt: base}); err != nil {
		t.Fatal(err)
	}
	hc, _ := httpobs.NewHTTPCorrelator(mgr, be.Relationships, httpobs.HTTPCorrelateConfig{AllowAutoCreate: true, AllowedHosts: []string{"example.com"}})
	for _, id := range []string{"h1", "h2"} {
		if e, _ := be.Telemetry.Get(ctx, id); e != nil {
			hc.Correlate(ctx, e)
		}
	}
	return NewServer(be)
}

func TestApplicationObservationsListAndOrder(t *testing.T) {
	srv := seedApplication(t)
	code, body := apiGet(t, srv, "/api/v1/application/observations")
	if code != 200 || dataLen(t, body) != 3 {
		t.Fatalf("want 3 app obs, got %d %+v", code, body)
	}
	rows := body["data"].([]any)
	if rows[0].(map[string]any)["id"] != "h1" {
		t.Fatalf("order: %v", rows[0])
	}
}

func TestApplicationFilters(t *testing.T) {
	srv := seedApplication(t)
	cases := map[string]struct {
		path string
		want int
	}{
		"method":   {"/api/v1/application/observations?method=GET", 3},
		"status":   {"/api/v1/application/observations?status=500", 1},
		"host":     {"/api/v1/application/observations?host=example.com", 3},
		"route":    {"/api/v1/application/observations?route=/api/users", 2},
		"detected": {"/api/v1/application/observations?detected=true", 1},
		"auth":     {"/api/v1/application/observations?auth=failure", 1},
	}
	for name, c := range cases {
		code, body := apiGet(t, srv, c.path)
		if code != 200 || dataLen(t, body) != c.want {
			t.Errorf("%s: want %d got %d %+v", name, c.want, code, body)
		}
	}
	for _, p := range []string{
		"/api/v1/application/observations?method=FOO",
		"/api/v1/application/observations?status=999",
	} {
		if code, _ := apiGet(t, srv, p); code != 400 {
			t.Errorf("%s: want 400 got %d", p, code)
		}
	}
}

func TestApplicationRelationships(t *testing.T) {
	srv := seedApplication(t)
	code, body := apiGet(t, srv, "/api/v1/application/relationships")
	if code != 200 {
		t.Fatalf("code %d %+v", code, body)
	}
	rows := body["data"].([]any)
	// At least one EXPOSES or SERVED_BY or CONTAINS from URL decompose
	if len(rows) == 0 {
		t.Fatalf("want at least one app relationship, got 0")
	}
}
