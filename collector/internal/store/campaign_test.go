// RED: campaign + exercise repositories on the memory backend.
package store

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/validation"
)

func testCampaign() validation.Campaign {
	return validation.Campaign{
		Name: "lab", Description: "d", Target: "seed-lab",
		Provider: validation.NativeProviderID, Source: "seed-lab-validation",
		Status:    validation.StatusCompleted,
		CreatedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		CaseIDs:   []string{"vcase-a"}, ResultIDs: []string{"vres-a"},
	}
}

func TestCampaignRepository(t *testing.T) {
	ctx := context.Background()
	be := NewMemoryBackend()
	c := testCampaign()
	if err := be.Campaigns.Create(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := be.Campaigns.Create(ctx, c); err == nil {
		t.Fatalf("duplicate create must fail")
	}
	got, err := be.Campaigns.Get(ctx, c.ID())
	if err != nil || got.Name != "lab" || len(got.ResultIDs) != 1 {
		t.Fatalf("get: %+v %v", got, err)
	}
	c.Status = validation.StatusFailed
	if err := be.Campaigns.Save(ctx, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, _ = be.Campaigns.Get(ctx, c.ID())
	if got.Status != validation.StatusFailed {
		t.Fatalf("save must replace: %+v", got)
	}
	list, err := be.Campaigns.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := be.Campaigns.Get(ctx, "no-such"); err == nil {
		t.Fatalf("missing must error")
	}
	bad := c
	bad.Name = ""
	if err := be.Campaigns.Create(ctx, bad); err == nil {
		t.Fatalf("invalid must be rejected")
	}
}

func TestExerciseRepository(t *testing.T) {
	ctx := context.Background()
	be := NewMemoryBackend()
	ex, err := validation.BuildExercise(validation.ExerciseInput{
		CampaignID: "vcamp-a", Name: "lab ex", Source: "seed-lab-validation",
		Entries: []validation.ExerciseEntryInput{{
			CaseID: "vcase-1", RequestID: "vreq-1", ResultID: "vres-1",
			Verdict: 4, TelemetryIDs: []string{"evt-1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Exercises.Create(ctx, ex); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := be.Exercises.Create(ctx, ex); err == nil {
		t.Fatalf("duplicate create must fail")
	}
	got, err := be.Exercises.Get(ctx, ex.ID)
	if err != nil || len(got.Entries) != 1 {
		t.Fatalf("get: %+v %v", got, err)
	}
	list, err := be.Exercises.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
}
