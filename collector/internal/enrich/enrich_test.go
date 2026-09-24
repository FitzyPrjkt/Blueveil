package enrich

import (
	"errors"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

var fixedClock = func() time.Time {
	return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
}

func TestEnrichIsDeterministic(t *testing.T) {
	en, err := New("e2e-collector", fixedClock)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	mk := func() *v1.TelemetryEvent {
		return &v1.TelemetryEvent{Id: "e", Source: "s", AssetId: "a", EventType: "t"}
	}
	a, b := mk(), mk()
	if err := en.Enrich(a); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if err := en.Enrich(b); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if a.GetAttributes()[KeyCollector] != "e2e-collector" ||
		a.GetAttributes()[KeyCollectedAt] != "2026-09-12T10:00:00Z" {
		t.Fatalf("enrichment values drift: %v", a.GetAttributes())
	}
	if a.GetAttributes()[KeyCollector] != b.GetAttributes()[KeyCollector] ||
		a.GetAttributes()[KeyCollectedAt] != b.GetAttributes()[KeyCollectedAt] {
		t.Fatal("enrichment must be deterministic")
	}
	// Only the two documented keys are ever added.
	if len(a.GetAttributes()) != 2 {
		t.Fatalf("enrichment added unexpected keys: %v", a.GetAttributes())
	}
}

func TestEnrichPreservesSourceAttributes(t *testing.T) {
	en, _ := New("c", fixedClock)
	e := &v1.TelemetryEvent{Attributes: map[string]string{"rule_id": "x"}}
	if err := en.Enrich(e); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if e.GetAttributes()["rule_id"] != "x" {
		t.Fatalf("source attribute lost: %v", e.GetAttributes())
	}
}

func TestEnrichRefusesOverwrite(t *testing.T) {
	en, _ := New("c", fixedClock)
	e := &v1.TelemetryEvent{Attributes: map[string]string{KeyCollector: "someone-else"}}
	if err := en.Enrich(e); !errors.Is(err, ErrEnrichment) {
		t.Fatalf("want ErrEnrichment on namespace conflict, got %v", err)
	}
}

func TestEnrichFailures(t *testing.T) {
	if _, err := New("", fixedClock); !errors.Is(err, ErrEnrichment) {
		t.Fatalf("empty collector name must fail, got %v", err)
	}
	if _, err := New("c", nil); !errors.Is(err, ErrEnrichment) {
		t.Fatalf("nil clock must fail, got %v", err)
	}
	en, _ := New("c", func() time.Time { return time.Time{} })
	if err := en.Enrich(&v1.TelemetryEvent{}); !errors.Is(err, ErrEnrichment) {
		t.Fatalf("zero clock must fail, got %v", err)
	}
	if err := en.Enrich(nil); !errors.Is(err, ErrEnrichment) {
		t.Fatalf("nil event must fail, got %v", err)
	}
}
