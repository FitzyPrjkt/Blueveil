// RED: assessment + resilience repositories (memory backend).
package store

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/grc"
)

func testAssessment() grc.Assessment {
	return grc.Assessment{
		ControlID: "AC-1", Target: "seed-lab", Status: grc.StatusCompliant,
		Assessor: "seed-lab-grc", ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		EvidenceIDs: []string{"ev-1"}, Basis: "validation observed",
	}
}

func TestAssessmentRepository(t *testing.T) {
	ctx := context.Background()
	be := NewMemoryBackend()
	a := testAssessment()
	if err := be.Assessments.Create(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := be.Assessments.Create(ctx, a); err == nil {
		t.Fatalf("duplicate create must fail")
	}
	got, err := be.Assessments.Get(ctx, a.ID())
	if err != nil || got.Status != grc.StatusCompliant {
		t.Fatalf("get: %+v %v", got, err)
	}
	list, err := be.Assessments.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := be.Assessments.Get(ctx, "no-such"); err == nil {
		t.Fatalf("missing must error")
	}
	bad := a
	bad.Basis = ""
	if err := be.Assessments.Create(ctx, bad); err == nil {
		t.Fatalf("invalid must be rejected")
	}
}

func TestResilienceRepository(t *testing.T) {
	ctx := context.Background()
	be := NewMemoryBackend()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	rec, err := grc.AssessResilience(grc.ResilienceInput{
		Target: "seed-lab", Assessor: "seed-lab-grc", ObservedAt: now,
		BackupObserved: true, BackupAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Resilience.Create(ctx, rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := be.Resilience.Create(ctx, rec); err == nil {
		t.Fatalf("duplicate create must fail")
	}
	got, err := be.Resilience.Get(ctx, rec.ID)
	if err != nil || got.Status != grc.ResilienceDegraded {
		t.Fatalf("get: %+v %v", got, err)
	}
	list, err := be.Resilience.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
}
