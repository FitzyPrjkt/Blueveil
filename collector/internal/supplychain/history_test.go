// RED: posture history derives time-ordered observations from stored
// state. No fabricated trends, no percentages.
package supplychain

import (
	"testing"
	"time"
)

func TestPostureHistory(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	comps := []Component{
		{
			Type: ComponentLibrary, Ecosystem: "npm", Name: "a",
			Version: "1.0.0", Provenance: ProvenanceLockfile, Source: "s",
			ObservedAt: now.Add(-time.Hour), Status: StatusObserved,
		},
		{
			Type: ComponentLibrary, Ecosystem: "npm", Name: "b",
			Version: "2.0.0", Provenance: ProvenanceManifest, Source: "s",
			ObservedAt: now, Status: StatusPolicyViolation, StatusBasis: "lab policy",
		},
	}
	assessments := []VendorAssessment{
		{VendorID: "vend-1", Status: VendorReviewed, Assessor: "a", ObservedAt: now.Add(-30 * time.Minute)},
	}
	got := PostureHistory(comps, assessments, nil)
	if len(got) != 3 {
		t.Fatalf("want 3 history rows, got %+v", got)
	}
	// Deterministic time order.
	for i := 1; i < len(got); i++ {
		if got[i].OccurredAt.Before(got[i-1].OccurredAt) {
			t.Fatalf("history must order by time: %+v", got)
		}
		if got[i].ID == "" || got[i].Kind == "" || got[i].SubjectID == "" || got[i].Summary == "" {
			t.Fatalf("history rows need identity: %+v", got[i])
		}
	}
	// Empty inputs, empty history — never a fabricated trend.
	if out := PostureHistory(nil, nil, nil); len(out) != 0 {
		t.Fatalf("empty inputs must yield empty history, got %+v", out)
	}
}
