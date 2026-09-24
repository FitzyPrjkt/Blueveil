// RED: network observation + relationship read endpoints.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/netobs"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func seedNetwork(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id string, minute int, typ string, sev v1.Severity, attrs map[string]string) {
		if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
			Id: id, OccurredAt: timestamppb.New(base.Add(time.Duration(minute) * time.Minute)),
			Source: "lab-sensor", AssetId: "seed-net-01",
			EventType: typ, Severity: sev, Attributes: attrs,
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	mk("n1", 0, "net.connection", v1.Severity_SEVERITY_INFO, map[string]string{
		"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
		"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed"})
	mk("n2", 1, "net.connection", v1.Severity_SEVERITY_MEDIUM, map[string]string{
		"net.src_ip": "10.0.0.10", "net.dst_ip": "10.0.0.1",
		"net.dst_port": "53", "net.protocol": "UDP", "net.verdict": "denied"})
	mk("n3", 2, "net.connection", v1.Severity_SEVERITY_INFO, map[string]string{
		"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.2", "net.protocol": "TCP"})
	mk("w1", 3, "waf.request_blocked", v1.Severity_SEVERITY_HIGH, map[string]string{})
	if err := be.Detection.Append(ctx, &v1.Detection{
		Id: "det-n2", RuleId: "net-denied-repeated", RuleName: "Repeated denied network activity",
		TelemetryEventIds: []string{"n2"}, DetectedAt: timestamppb.New(base.Add(5 * time.Minute)),
		Severity: v1.Severity_SEVERITY_MEDIUM, Confidence: 0,
		Title: "Repeated denied network activity observed", Description: "lab",
	}); err != nil {
		t.Fatalf("detection: %v", err)
	}
	// Inventory: URL decompose yields a CONTAINS pair; correlator links IPs.
	mgr, err := asset.NewManager(be.Assets, memRelStore{be.Relationships}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.Ingest(ctx, asset.Observation{Source: "test",
		Type: v1.AssetType_ASSET_TYPE_URL, Raw: "https://example.com/x",
		ObservedAt: base}); err != nil {
		t.Fatal(err)
	}
	corr, err := netobs.NewCorrelator(mgr, be.Relationships,
		netobs.CorrelateConfig{AllowAutoCreate: true, LocalPrefixes: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"n1", "n2"} {
		e, err := be.Telemetry.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := corr.Correlate(ctx, e); err != nil {
			t.Fatalf("correlate %s: %v", id, err)
		}
	}
	return NewServer(be)
}

func dataLen(t *testing.T, body map[string]any) int {
	t.Helper()
	data, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("no data array: %v", body)
	}
	return len(data)
}

func TestNetworkObservationsListAndOrder(t *testing.T) {
	srv := seedNetwork(t)
	code, body := apiGet(t, srv, "/api/v1/network/observations")
	if code != 200 || dataLen(t, body) != 3 {
		t.Fatalf("want 3 net observations, got %d %+v", code, body)
	}
	rows := body["data"].([]any)
	if rows[0].(map[string]any)["id"] != "n1" || rows[2].(map[string]any)["id"] != "n3" {
		t.Fatalf("deterministic order violated: %v", rows)
	}
}

func TestNetworkObservationFilters(t *testing.T) {
	srv := seedNetwork(t)
	cases := map[string]struct {
		path string
		want int
	}{
		"protocol":     {"/api/v1/network/observations?protocol=UDP", 1},
		"protocol low": {"/api/v1/network/observations?protocol=tcp", 2},
		"src":          {"/api/v1/network/observations?src=10.0.0.9", 2},
		"dst":          {"/api/v1/network/observations?dst=10.0.0.1", 2},
		"verdict":      {"/api/v1/network/observations?verdict=denied", 1},
		"detected":     {"/api/v1/network/observations?detected=true", 1},
		"undetected":   {"/api/v1/network/observations?detected=false", 2},
		"combined":     {"/api/v1/network/observations?protocol=TCP&detected=false", 2},
	}
	for name, c := range cases {
		code, body := apiGet(t, srv, c.path)
		if code != 200 || dataLen(t, body) != c.want {
			t.Errorf("%s: want %d, got %d %+v", name, c.want, code, body)
		}
	}
	for name, path := range map[string]string{
		"bad verdict":  "/api/v1/network/observations?verdict=maybe",
		"bad src":      "/api/v1/network/observations?src=bogus",
		"bad dst":      "/api/v1/network/observations?dst=999.1.1.1",
		"bad protocol": "/api/v1/network/observations?protocol=GRE",
		"bad detected": "/api/v1/network/observations?detected=sometimes",
	} {
		if code, _ := apiGet(t, srv, path); code != 400 {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
}

func TestNetworkObservationsEmpty(t *testing.T) {
	srv := NewServer(store.NewMemoryBackend())
	code, body := apiGet(t, srv, "/api/v1/network/observations")
	if code != 200 || dataLen(t, body) != 0 {
		t.Fatalf("empty must be 200 []: %d %+v", code, body)
	}
}

func TestNetworkRelationships(t *testing.T) {
	srv := seedNetwork(t)
	code, body := apiGet(t, srv, "/api/v1/network/relationships")
	if code != 200 {
		t.Fatalf("code %d %+v", code, body)
	}
	rows := body["data"].([]any)
	if len(rows) != 2 {
		t.Fatalf("want 2 COMMUNICATES_WITH edges (CONTAINS excluded), got %d %v", len(rows), rows)
	}
	for _, r := range rows {
		m := r.(map[string]any)
		if m["kind"] != "COMMUNICATES_WITH" {
			t.Fatalf("kind leak: %v", m)
		}
		for _, k := range []string{"parent_id", "child_id", "source", "observed_at"} {
			if m[k] == nil || m[k] == "" {
				t.Fatalf("provenance field %s missing: %v", k, m)
			}
		}
	}
	// Deterministic order: sorted by parent then child.
	first := rows[0].(map[string]any)["parent_id"].(string)
	second := rows[1].(map[string]any)["parent_id"].(string)
	if first > second {
		t.Fatalf("order violated: %s before %s", first, second)
	}
	// Asset-scoped view.
	be := store.NewMemoryBackend()
	_ = be
	code, _ = apiGet(t, srv, "/api/v1/network/relationships?asset=no-such-id")
	if code != 404 {
		t.Fatalf("unknown asset must 404, got %d", code)
	}
}

func TestNetworkMethodGuard(t *testing.T) {
	srv := seedNetwork(t)
	for _, p := range []string{"/api/v1/network/observations", "/api/v1/network/relationships"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != 405 {
			t.Errorf("POST %s: want 405, got %d", p, rec.Code)
		}
	}
}
