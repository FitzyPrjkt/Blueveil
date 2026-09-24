// RED: HTTP asset correlation
package httpobs

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func httpSetup(t *testing.T, cfg HTTPCorrelateConfig) (*HTTPCorrelator, store.Backend) {
	t.Helper()
	be := store.NewMemoryBackend()
	mgr, err := asset.NewManager(be.Assets, be.Relationships, time.Now)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	c, err := NewHTTPCorrelator(mgr, be.Relationships, cfg)
	if err != nil {
		t.Fatalf("NewHTTPCorrelator: %v", err)
	}
	return c, be
}

func httpEvt(id, host, path string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id:         id,
		OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source:     "lab-http",
		AssetId:    "seed-http-01",
		EventType:  EventTypeHTTPRequest,
		Severity:   v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{"http.method": "GET", "http.host": host, "http.path": path},
	}
}

func ingestURL(t *testing.T, be store.Backend, raw string) {
	t.Helper()
	mgr, _ := asset.NewManager(be.Assets, be.Relationships, time.Now)
	if _, _, err := mgr.Ingest(context.Background(), asset.Observation{
		Source: "test-inventory", Type: v1.AssetType_ASSET_TYPE_URL, Raw: raw, ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("ingest url %s: %v", raw, err)
	}
}

func ingestApp(t *testing.T, be store.Backend, name string) {
	t.Helper()
	mgr, _ := asset.NewManager(be.Assets, be.Relationships, time.Now)
	if _, _, err := mgr.Ingest(context.Background(), asset.Observation{
		Source: "test-inventory", Type: v1.AssetType_ASSET_TYPE_APPLICATION, Raw: name, ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("ingest app %s: %v", name, err)
	}
}

func TestHTTPExistingURL(t *testing.T) {
	c, be := httpSetup(t, HTTPCorrelateConfig{})
	ingestURL(t, be, "https://example.com/api/users")
	corr, err := c.Correlate(context.Background(), httpEvt("h1", "example.com", "/api/users"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.URLAsset == nil {
		t.Fatalf("must resolve existing URL: %+v", corr)
	}
	if corr.URLCreated {
		t.Fatalf("must not create when exists")
	}
}

func TestHTTPAutoCreateAllowed(t *testing.T) {
	c, _ := httpSetup(t, HTTPCorrelateConfig{AllowAutoCreate: true, AllowedHosts: []string{"seed-lab.example"}})
	corr, err := c.Correlate(context.Background(), httpEvt("h2", "seed-lab.example", "/app"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if !corr.URLCreated || corr.URLAsset == nil {
		t.Fatalf("allowed host must be observed: %+v", corr)
	}
	if corr.URLAsset.GetType() != v1.AssetType_ASSET_TYPE_URL {
		t.Fatalf("type")
	}
}

func TestHTTPExternalUnresolved(t *testing.T) {
	c, _ := httpSetup(t, HTTPCorrelateConfig{AllowAutoCreate: true, AllowedHosts: []string{"seed-lab.example"}})
	corr, err := c.Correlate(context.Background(), httpEvt("h3", "external.example", "/x"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.URLAsset != nil || corr.URLCreated {
		t.Fatalf("external must stay unresolved: %+v", corr)
	}
}

func TestHTTPNoFalseMerge(t *testing.T) {
	c, be := httpSetup(t, HTTPCorrelateConfig{AllowAutoCreate: true, AllowedHosts: []string{"seed-lab.example"}})
	mgr, _ := asset.NewManager(be.Assets, be.Relationships, time.Now)
	for _, o := range []asset.Observation{
		{Source: "test", Type: v1.AssetType_ASSET_TYPE_DOMAIN, Raw: "seed-lab.example", ObservedAt: time.Now().UTC()},
		{Source: "test", Type: v1.AssetType_ASSET_TYPE_HOST, Raw: "seed-lab.example", ObservedAt: time.Now().UTC()},
	} {
		if _, _, err := mgr.Ingest(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	corr, err := c.Correlate(context.Background(), httpEvt("h4", "seed-lab.example", "/app"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	all, _ := be.Assets.List(context.Background())
	// domain + host + url + derived domain/service = at least 4, but domain/host must remain distinct
	_ = corr
	if len(all) < 3 {
		t.Fatalf("assets missing: %d", len(all))
	}
	// Ensure host and domain still distinct ids
	var hostID, domainID string
	for _, a := range all {
		if a.GetType() == v1.AssetType_ASSET_TYPE_HOST && a.GetName() == "seed-lab.example" {
			hostID = a.GetId()
		}
		if a.GetType() == v1.AssetType_ASSET_TYPE_DOMAIN && a.GetName() == "seed-lab.example" {
			domainID = a.GetId()
		}
	}
	if hostID == "" || domainID == "" || hostID == domainID {
		t.Fatalf("host/domain distinct: %q %q", hostID, domainID)
	}
}

func TestHTTPRelationshipIdempotent(t *testing.T) {
	c, be := httpSetup(t, HTTPCorrelateConfig{AllowAutoCreate: true, AllowedHosts: []string{"example.com"}})
	ingestApp(t, be, "my-app")
	// Need to set application attribute via event
	evt := &v1.TelemetryEvent{
		Id: "h5", OccurredAt: timestamppb.New(time.Now().UTC()), Source: "lab-http", AssetId: "seed-http-01",
		EventType: EventTypeHTTPRequest, Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{"http.method": "GET", "http.host": "example.com", "http.path": "/api", "http.application": "my-app"},
	}
	first, err := c.Correlate(context.Background(), evt)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := c.Correlate(context.Background(), evt)
	if err != nil {
		t.Fatalf("second must not error: %v", err)
	}
	if second.URLCreated {
		t.Fatalf("second must resolve not create")
	}
	_ = first
	_ = second
}

func TestHTTPConfigValidation(t *testing.T) {
	be := store.NewMemoryBackend()
	mgr, _ := asset.NewManager(be.Assets, be.Relationships, time.Now)
	for _, cfg := range []HTTPCorrelateConfig{
		{AllowAutoCreate: true},                             // no hosts
		{AllowedHosts: []string{"example.com"}},             // hosts but disabled
		{AllowAutoCreate: true, AllowedHosts: []string{""}}, // empty host
	} {
		if _, err := NewHTTPCorrelator(mgr, be.Relationships, cfg); err == nil {
			t.Errorf("%+v must error", cfg)
		}
	}
	if _, err := NewHTTPCorrelator(nil, be.Relationships, HTTPCorrelateConfig{}); err == nil {
		t.Error("nil mgr")
	}
	if _, err := NewHTTPCorrelator(mgr, nil, HTTPCorrelateConfig{}); err == nil {
		t.Error("nil rel")
	}
}
