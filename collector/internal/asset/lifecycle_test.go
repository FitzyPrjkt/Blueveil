package asset

import (
	"errors"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

var lifeClock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func TestLifecycleWalk(t *testing.T) {
	a, err := Normalize(Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_DOMAIN,
		Raw: "Example.COM.", ObservedAt: lifeClock, Environment: "lab",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if a.GetStatus() != v1.AssetStatus_ASSET_STATUS_DISCOVERED {
		t.Fatalf("new assets are DISCOVERED: %v", a.GetStatus())
	}
	if !a.GetFirstSeen().AsTime().Equal(a.GetLastSeen().AsTime()) {
		t.Fatal("first_seen == last_seen at creation")
	}
	chain := []v1.AssetStatus{
		v1.AssetStatus_ASSET_STATUS_ACTIVE,
		v1.AssetStatus_ASSET_STATUS_STALE,
		v1.AssetStatus_ASSET_STATUS_RETIRED,
	}
	for _, to := range chain {
		if err := Transition(a, to, lifeClock); err != nil {
			t.Fatalf("transition to %v: %v", to, err)
		}
		if a.GetStatus() != to {
			t.Fatalf("status drift: %v", a.GetStatus())
		}
	}
}

func TestLifecycleRevivalAndDismissal(t *testing.T) {
	mk := func() *v1.Asset {
		a, err := Normalize(Observation{
			Source: "test", Type: v1.AssetType_ASSET_TYPE_HOST,
			Raw: "web01", ObservedAt: lifeClock,
		})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := mk()
	// STALE revives to ACTIVE on re-observation.
	for _, to := range []v1.AssetStatus{
		v1.AssetStatus_ASSET_STATUS_ACTIVE, v1.AssetStatus_ASSET_STATUS_STALE,
	} {
		if err := Transition(a, to, lifeClock); err != nil {
			t.Fatal(err)
		}
	}
	if err := Touch(a, lifeClock.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a.GetStatus() != v1.AssetStatus_ASSET_STATUS_ACTIVE {
		t.Fatalf("touch revives STALE: %v", a.GetStatus())
	}
	if !a.GetLastSeen().AsTime().After(a.GetFirstSeen().AsTime()) {
		t.Fatal("last_seen must advance past first_seen")
	}
	// Direct dismissal ACTIVE → RETIRED is legal; anything from RETIRED is not.
	b := mk()
	_ = Transition(b, v1.AssetStatus_ASSET_STATUS_ACTIVE, lifeClock)
	if err := Transition(b, v1.AssetStatus_ASSET_STATUS_RETIRED, lifeClock); err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	if err := Transition(b, v1.AssetStatus_ASSET_STATUS_ACTIVE, lifeClock); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("RETIRED is terminal, got %v", err)
	}
}

func TestLifecycleRejects(t *testing.T) {
	a, _ := Normalize(Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_HOST,
		Raw: "web01", ObservedAt: lifeClock,
	})
	for name, to := range map[string]v1.AssetStatus{
		"skip":        v1.AssetStatus_ASSET_STATUS_STALE,
		"backwards":   v1.AssetStatus_ASSET_STATUS_DISCOVERED,
		"unspecified": v1.AssetStatus_ASSET_STATUS_UNSPECIFIED,
	} {
		if err := Transition(a, to, lifeClock); !errors.Is(err, ErrLifecycle) {
			t.Fatalf("%s: want ErrLifecycle, got %v", name, err)
		}
	}
	if err := Transition(a, v1.AssetStatus_ASSET_STATUS_ACTIVE, time.Time{}); err == nil {
		t.Fatal("zero timestamp must fail")
	}
	if err := Transition(nil, v1.AssetStatus_ASSET_STATUS_ACTIVE, lifeClock); err == nil {
		t.Fatal("nil asset must fail")
	}
	if err := Touch(a, time.Time{}); err == nil {
		t.Fatal("touch with zero time must fail")
	}
}

func TestNormalizeRejects(t *testing.T) {
	base := Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_DOMAIN,
		Raw: "example.com", ObservedAt: lifeClock, Environment: "lab",
		Attributes: map[string]string{"k": "v"},
	}
	if _, err := Normalize(base); err != nil {
		t.Fatalf("valid observation must normalize: %v", err)
	}
	bad := base
	bad.Source = ""
	if _, err := Normalize(bad); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("empty source: %v", err)
	}
	bad = base
	bad.Type = v1.AssetType_ASSET_TYPE_UNSPECIFIED
	if _, err := Normalize(bad); err == nil {
		t.Fatal("unspecified type must fail")
	}
	bad = base
	bad.Raw = "not a domain!!"
	if _, err := Normalize(bad); !errors.Is(err, ErrCanonicalize) {
		t.Fatalf("bad raw: %v", err)
	}
	bad = base
	bad.ObservedAt = time.Time{}
	if _, err := Normalize(bad); err == nil {
		t.Fatal("zero observed_at must fail")
	}
}

func TestDecomposeURL(t *testing.T) {
	u, err := Normalize(Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_URL,
		Raw: "https://Seed-Lab.Example/app", ObservedAt: lifeClock, Environment: "lab",
	})
	if err != nil {
		t.Fatal(err)
	}
	derived, rels := Decompose(u, "test", lifeClock)
	if len(derived) != 2 || len(rels) != 2 {
		t.Fatalf("want domain+service and 2 relations, got %d %+v", len(derived), rels)
	}
	byType := map[v1.AssetType]*v1.Asset{}
	for _, d := range derived {
		byType[d.GetType()] = d
		if d.GetStatus() != v1.AssetStatus_ASSET_STATUS_DISCOVERED {
			t.Fatalf("derived assets start DISCOVERED: %+v", d)
		}
		if d.GetAttributes()["blueveil.derived_from"] != u.GetId() {
			t.Fatalf("derivation provenance missing: %+v", d.GetAttributes())
		}
		if d.GetEnvironment() != "lab" {
			t.Fatalf("environment must inherit: %+v", d)
		}
	}
	dom := byType[v1.AssetType_ASSET_TYPE_DOMAIN]
	svc := byType[v1.AssetType_ASSET_TYPE_SERVICE]
	if dom == nil || dom.GetName() != "seed-lab.example" {
		t.Fatalf("domain decomposition: %+v", dom)
	}
	if svc == nil || svc.GetName() != "seed-lab.example:443" {
		t.Fatalf("service decomposition: %+v", svc)
	}
	for _, r := range rels {
		if r.Kind != RelationContains || r.Source != "test" || !r.ObservedAt.Equal(lifeClock) {
			t.Fatalf("relationship provenance drift: %+v", r)
		}
	}
	// Non-URLs decompose to nothing (not an error).
	h, _ := Normalize(Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_HOST,
		Raw: "web01", ObservedAt: lifeClock,
	})
	if d, r := Decompose(h, "test", lifeClock); len(d) != 0 || len(r) != 0 {
		t.Fatal("hosts do not decompose")
	}
	// Deterministic across runs.
	derived2, _ := Decompose(u, "test", lifeClock)
	for i := range derived {
		if derived[i].GetId() != derived2[i].GetId() {
			t.Fatal("decomposition must be deterministic")
		}
	}
}
