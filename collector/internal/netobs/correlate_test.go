// RED: asset correlation for network observations.
package netobs

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testSetup(t *testing.T, cfg CorrelateConfig) (*Correlator, store.Backend) {
	t.Helper()
	be := store.NewMemoryBackend()
	mgr, err := asset.NewManager(be.Assets, be.Relationships, time.Now)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	c, err := NewCorrelator(mgr, be.Relationships, cfg)
	if err != nil {
		t.Fatalf("NewCorrelator: %v", err)
	}
	return c, be
}

func obsEvent(id, src, dst string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id:         id,
		OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 4, 0, 0, time.UTC)),
		Source:     "lab-sensor",
		AssetId:    "seed-net-01",
		EventType:  EventTypeConnection,
		Severity:   v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{"net.src_ip": src, "net.dst_ip": dst},
	}
}

func ingestIP(t *testing.T, be store.Backend, raw string) {
	t.Helper()
	mgr, err := asset.NewManager(be.Assets, be.Relationships, time.Now)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, _, err := mgr.Ingest(context.Background(), asset.Observation{
		Source: "test-inventory", Type: v1.AssetType_ASSET_TYPE_IP_ADDRESS,
		Raw: raw, ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("ingest %s: %v", raw, err)
	}
}

func TestCorrelateExistingAssets(t *testing.T) {
	c, be := testSetup(t, CorrelateConfig{})
	ingestIP(t, be, "10.0.0.9")
	ingestIP(t, be, "10.0.0.1")
	corr, err := c.Correlate(context.Background(), obsEvent("e1", "10.0.0.9", "10.0.0.1"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.SrcAsset == nil || corr.DstAsset == nil {
		t.Fatalf("both endpoints must resolve: %+v", corr)
	}
	if corr.SrcCreated || corr.DstCreated {
		t.Fatalf("must not create when assets exist: %+v", corr)
	}
	if !corr.RelRecorded {
		t.Fatalf("relationship must be recorded")
	}
	kids, err := be.Relationships.Children(context.Background(), corr.SrcAsset.GetId())
	if err != nil || len(kids) != 1 {
		t.Fatalf("children: %v %d", err, len(kids))
	}
	if kids[0].Kind != asset.RelationCommunicatesWith || kids[0].Source != "lab-sensor" {
		t.Fatalf("provenance: %+v", kids[0])
	}
}

func TestCorrelateAutoCreateLocal(t *testing.T) {
	c, _ := testSetup(t, CorrelateConfig{AllowAutoCreate: true, LocalPrefixes: []string{"127.0.0.0/8"}})
	corr, err := c.Correlate(context.Background(), obsEvent("e2", "127.0.0.1", "127.0.0.2"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if !corr.SrcCreated || !corr.DstCreated {
		t.Fatalf("local endpoints must be observed as assets: %+v", corr)
	}
	if corr.SrcAsset.GetType() != v1.AssetType_ASSET_TYPE_IP_ADDRESS {
		t.Fatalf("type: %v", corr.SrcAsset.GetType())
	}
	if corr.SrcAsset.GetAttributes()["blueveil.netobs_event"] != "e2" {
		t.Fatalf("provenance attr missing: %+v", corr.SrcAsset.GetAttributes())
	}
	if corr.SrcAsset.GetEnvironment() != "" {
		t.Fatalf("environment must stay unknown, got %q", corr.SrcAsset.GetEnvironment())
	}
}

func TestCorrelateExternalUnresolved(t *testing.T) {
	c, _ := testSetup(t, CorrelateConfig{AllowAutoCreate: true, LocalPrefixes: []string{"10.0.0.0/8"}})
	corr, err := c.Correlate(context.Background(), obsEvent("e3", "10.0.0.9", "203.0.113.7"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.DstAsset != nil || corr.DstCreated {
		t.Fatalf("external endpoint must stay unresolved: %+v", corr)
	}
	if corr.SrcAsset == nil || !corr.SrcCreated {
		t.Fatalf("local endpoint must be created: %+v", corr)
	}
	if corr.RelRecorded {
		t.Fatalf("no relationship without both endpoints")
	}
}

func TestCorrelateDisabledCreatesNothing(t *testing.T) {
	c, be := testSetup(t, CorrelateConfig{})
	corr, err := c.Correlate(context.Background(), obsEvent("e4", "10.0.0.9", "10.0.0.1"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.SrcAsset != nil || corr.DstAsset != nil || corr.RelRecorded {
		t.Fatalf("disabled correlator must not create or link: %+v", corr)
	}
	if n, _ := be.Assets.List(context.Background()); len(n) != 0 {
		t.Fatalf("assets created: %d", len(n))
	}
}

func TestCorrelateNoFalseMerge(t *testing.T) {
	c, be := testSetup(t, CorrelateConfig{AllowAutoCreate: true, LocalPrefixes: []string{"10.0.0.0/8"}})
	mgr, _ := asset.NewManager(be.Assets, be.Relationships, time.Now)
	for _, o := range []asset.Observation{
		{Source: "test-inventory", Type: v1.AssetType_ASSET_TYPE_DOMAIN, Raw: "example.com", ObservedAt: time.Now().UTC()},
		{Source: "test-inventory", Type: v1.AssetType_ASSET_TYPE_HOST, Raw: "web01", ObservedAt: time.Now().UTC()},
	} {
		if _, _, err := mgr.Ingest(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	corr, err := c.Correlate(context.Background(), obsEvent("e5", "10.0.0.9", "10.0.0.1"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	all, _ := be.Assets.List(context.Background())
	if len(all) != 4 {
		t.Fatalf("want 4 assets (2 inventory + 2 observed), got %d", len(all))
	}
	for _, a := range all {
		if a.GetType() == v1.AssetType_ASSET_TYPE_DOMAIN && a.GetName() != "example.com" {
			t.Fatalf("domain touched: %+v", a)
		}
	}
	_ = corr
}

func TestCorrelateSelfLinkSkipped(t *testing.T) {
	c, be := testSetup(t, CorrelateConfig{AllowAutoCreate: true, LocalPrefixes: []string{"127.0.0.0/8"}})
	corr, err := c.Correlate(context.Background(), obsEvent("e6", "127.0.0.1", "127.0.0.1"))
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.RelRecorded {
		t.Fatalf("self-link must be skipped")
	}
	kids, _ := be.Relationships.Children(context.Background(), corr.SrcAsset.GetId())
	if len(kids) != 0 {
		t.Fatalf("self relationship stored: %+v", kids)
	}
}

func TestCorrelateIdempotent(t *testing.T) {
	c, _ := testSetup(t, CorrelateConfig{AllowAutoCreate: true, LocalPrefixes: []string{"10.0.0.0/8"}})
	e := obsEvent("e7", "10.0.0.9", "10.0.0.1")
	first, err := c.Correlate(context.Background(), e)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := c.Correlate(context.Background(), e)
	if err != nil {
		t.Fatalf("second (duplicate relationship) must not error: %v", err)
	}
	if second.SrcCreated || second.DstCreated {
		t.Fatalf("second pass must resolve, not create")
	}
	if first.SrcAsset.GetId() != second.SrcAsset.GetId() {
		t.Fatalf("identity drift: %s vs %s", first.SrcAsset.GetId(), second.SrcAsset.GetId())
	}
}

func TestCorrelateConfigValidation(t *testing.T) {
	be := store.NewMemoryBackend()
	mgr, _ := asset.NewManager(be.Assets, be.Relationships, time.Now)
	for _, cfg := range []CorrelateConfig{
		{AllowAutoCreate: true}, // no prefixes
		{AllowAutoCreate: true, LocalPrefixes: []string{"not-cidr"}}, // bad cidr
		{LocalPrefixes: []string{"10.0.0.0/8"}},                      // prefixes but disabled
	} {
		if _, err := NewCorrelator(mgr, be.Relationships, cfg); err == nil {
			t.Errorf("%+v: expected config error", cfg)
		}
	}
	if _, err := NewCorrelator(nil, be.Relationships, CorrelateConfig{}); err == nil {
		t.Errorf("nil manager must error")
	}
	if _, err := NewCorrelator(mgr, nil, CorrelateConfig{}); err == nil {
		t.Errorf("nil rel store must error")
	}
}

func TestCorrelateMalformedEvent(t *testing.T) {
	c, _ := testSetup(t, CorrelateConfig{})
	if _, err := c.Correlate(context.Background(), obsEvent("e8", "bogus", "10.0.0.1")); err == nil {
		t.Fatalf("malformed observation must fail explicitly")
	}
}
