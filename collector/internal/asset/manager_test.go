package asset

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

// testStores is a minimal in-memory AssetStore/RelationshipStore for manager
// tests (the full contract lives in the shared storetest suite).
type testStores struct {
	mu     sync.Mutex
	assets map[string]*v1.Asset
	rels   []Relationship
}

func (s *testStores) Create(_ context.Context, a *v1.Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.assets[a.GetId()]; exists {
		return errors.New("store: duplicate id")
	}
	s.assets[a.GetId()] = a
	return nil
}

func (s *testStores) Save(_ context.Context, a *v1.Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.assets[a.GetId()]; !exists {
		return errors.New("store: not found")
	}
	s.assets[a.GetId()] = a
	return nil
}

func (s *testStores) Get(_ context.Context, id string) (*v1.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok {
		return nil, errors.New("store: not found")
	}
	return a, nil
}

func (s *testStores) Append(_ context.Context, r Relationship) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rels = append(s.rels, r)
	return nil
}

func testManager(t *testing.T) (*Manager, *testStores) {
	t.Helper()
	st := &testStores{assets: map[string]*v1.Asset{}}
	m, err := NewManager(st, st, func() time.Time { return lifeClock })
	if err != nil {
		t.Fatal(err)
	}
	return m, st
}

func TestIngestCreatesThenTouches(t *testing.T) {
	ctx := context.Background()
	m, _ := testManager(t)
	obs := Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_DOMAIN,
		Raw: "Example.COM.", ObservedAt: lifeClock, Environment: "lab",
	}
	a, created, err := m.Ingest(ctx, obs)
	if err != nil || !created {
		t.Fatalf("first ingest creates: %+v %v %v", a, created, err)
	}
	if a.GetStatus() != v1.AssetStatus_ASSET_STATUS_DISCOVERED {
		t.Fatalf("new assets are DISCOVERED: %v", a.GetStatus())
	}
	if a.GetName() != "example.com" || a.GetEnvironment() != "lab" {
		t.Fatalf("canonicalization/environment drift: %+v", a)
	}
	// Re-observation touches: same id, ACTIVE, last_seen advances.
	later := lifeClock.Add(2 * time.Hour)
	m2clock := m.clock
	m.clock = func() time.Time { return later }
	a2, created, err := m.Ingest(ctx, obs)
	m.clock = m2clock
	if err != nil || created {
		t.Fatalf("re-ingest touches: %+v %v %v", a2, created, err)
	}
	if a2.GetId() != a.GetId() {
		t.Fatal("identity must be stable across observations")
	}
	if a2.GetStatus() != v1.AssetStatus_ASSET_STATUS_ACTIVE {
		t.Fatalf("touch confirms DISCOVERED: %v", a2.GetStatus())
	}
	if !a2.GetLastSeen().AsTime().Equal(later) {
		t.Fatal("last_seen must advance")
	}
	if !a2.GetFirstSeen().AsTime().Equal(lifeClock) {
		t.Fatal("first_seen must never move")
	}
}

func TestIngestDecomposesURL(t *testing.T) {
	ctx := context.Background()
	m, st := testManager(t)
	u, created, err := m.Ingest(ctx, Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_URL,
		Raw: "https://seed-lab.example/app", ObservedAt: lifeClock, Environment: "lab",
	})
	if err != nil || !created {
		t.Fatalf("ingest: %v %v", err, created)
	}
	if u.GetType() != v1.AssetType_ASSET_TYPE_URL {
		t.Fatalf("ingested type drift: %+v", u)
	}
	if err != nil || !created {
		t.Fatalf("ingest: %v %v", err, created)
	}
	// Domain + service materialized alongside the URL.
	if len(st.assets) != 3 {
		t.Fatalf("want url+domain+service, got %d assets", len(st.assets))
	}
	if len(st.rels) != 2 {
		t.Fatalf("want 2 CONTAINS relations, got %+v", st.rels)
	}
	for id, a := range st.assets {
		if id != a.GetId() {
			t.Fatal("map key must equal asset id")
		}
	}
}

func TestResolvePrefersExactThenCanonical(t *testing.T) {
	ctx := context.Background()
	m, _ := testManager(t)
	a, _, err := m.Ingest(ctx, Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_IP_ADDRESS,
		Raw: "127.0.0.1", ObservedAt: lifeClock,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Exact id.
	if got, err := m.Resolve(ctx, a.GetId()); err != nil || got.GetId() != a.GetId() {
		t.Fatalf("exact resolve: %+v %v", got, err)
	}
	// Canonical spelling resolves.
	if got, err := m.Resolve(ctx, "127.0.0.1"); err != nil || got.GetId() != a.GetId() {
		t.Fatalf("canonical resolve: %+v %v", got, err)
	}
	// Unknown references yield nil, nil — telemetry never blocks.
	got, err := m.Resolve(ctx, "ghost-asset-99")
	if err != nil || got != nil {
		t.Fatalf("unknown must be (nil,nil): %+v %v", got, err)
	}
	// Host/domain spelling split is preserved, never merged.
	h, _, _ := m.Ingest(ctx, Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_HOST,
		Raw: "example.com", ObservedAt: lifeClock,
	})
	d, _, _ := m.Ingest(ctx, Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_DOMAIN,
		Raw: "example.com", ObservedAt: lifeClock,
	})
	if h.GetId() == d.GetId() {
		t.Fatal("host and domain must stay distinct assets")
	}
}

func TestManagerRejects(t *testing.T) {
	ctx := context.Background()
	if _, err := NewManager(nil, &testStores{}, lifeClockFn); err == nil {
		t.Fatal("nil asset store must fail")
	}
	if _, err := NewManager(&testStores{}, nil, lifeClockFn); err == nil {
		t.Fatal("nil rel store must fail")
	}
	if _, err := NewManager(&testStores{}, &testStores{}, nil); err == nil {
		t.Fatal("nil clock must fail")
	}
	m, _ := testManager(t)
	if _, _, err := m.Ingest(ctx, Observation{}); err == nil {
		t.Fatal("empty observation must fail")
	}
}

func lifeClockFn() time.Time { return lifeClock }
