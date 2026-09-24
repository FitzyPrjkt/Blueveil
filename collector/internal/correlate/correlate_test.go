package correlate

import (
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestRelatedEventsShareIDUnrelatedDiffer(t *testing.T) {
	a := IDFor("lab-waf", "asset-web-01", "waf.request_blocked")
	b := IDFor("lab-waf", "asset-web-01", "waf.request_blocked")
	c := IDFor("lab-waf", "asset-web-01", "waf.request_allowed")
	if a != b {
		t.Fatal("same triple must yield same correlation id")
	}
	if a == c {
		t.Fatal("different triples must yield different correlation ids")
	}
	if len(a) != 16 {
		t.Fatalf("correlation id must be 16 hex chars, got %q", a)
	}
	for _, r := range a {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			t.Fatalf("correlation id must be hex, got %q", a)
		}
	}
}

func TestApplyStampsOnlyMissingKey(t *testing.T) {
	e := &v1.TelemetryEvent{Source: "s", AssetId: "a", EventType: "t"}
	Apply(e)
	want := IDFor("s", "a", "t")
	if e.GetAttributes()[AttributeKey] != want {
		t.Fatalf("got %v, want %s", e.GetAttributes(), want)
	}
	// Second apply is stable; source-provided value wins.
	Apply(e)
	if e.GetAttributes()[AttributeKey] != want {
		t.Fatal("re-apply must be stable")
	}
	f := &v1.TelemetryEvent{
		Source: "s", AssetId: "a", EventType: "t",
		Attributes: map[string]string{AttributeKey: "source-choice"},
	}
	Apply(f)
	if f.GetAttributes()[AttributeKey] != "source-choice" {
		t.Fatal("source-provided correlation id must win")
	}
	Apply(nil) // must not panic
}
