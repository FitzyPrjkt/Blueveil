// RED: metadata-level resilience posture from explicit observations
// only. Incomplete evidence stays NOT_ASSESSED/UNKNOWN — never a score.
package grc

import (
	"testing"
	"time"
)

func TestResilienceReady(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	r := ResilienceInput{
		Target: "seed-lab", Assessor: "seed-lab-grc", ObservedAt: now,
		BackupObserved: true, BackupAt: now,
		RestoreTestObserved: true, RestoreTestAt: now,
		ProcedureDeclared: true,
	}
	rec, err := AssessResilience(r)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if rec.Status != ResilienceReady {
		t.Fatalf("full observations must be READY, got %s", rec.Status)
	}
	if rec.BackupAt.IsZero() || rec.RestoreTestAt.IsZero() {
		t.Fatalf("timestamps must carry through: %+v", rec)
	}
	if rec.ID == "" {
		t.Fatalf("record id required")
	}
}

func TestResilienceDegraded(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	r := ResilienceInput{
		Target: "seed-lab", Assessor: "seed-lab-grc", ObservedAt: now,
		BackupObserved: true, BackupAt: now,
	}
	rec, err := AssessResilience(r)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if rec.Status != ResilienceDegraded {
		t.Fatalf("partial observations must be DEGRADED, got %s", rec.Status)
	}
}

func TestResilienceNotAssessed(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	rec, err := AssessResilience(ResilienceInput{
		Target: "seed-lab", Assessor: "seed-lab-grc", ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if rec.Status != ResilienceNotAssessed {
		t.Fatalf("no observations must be NOT_ASSESSED, got %s", rec.Status)
	}
}

func TestResilienceRejects(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	base := ResilienceInput{Target: "t", Assessor: "a", ObservedAt: now, BackupObserved: true, BackupAt: now}
	for name, mut := range map[string]func(*ResilienceInput){
		"empty target":   func(r *ResilienceInput) { r.Target = "" },
		"empty assessor": func(r *ResilienceInput) { r.Assessor = "" },
		"zero time":      func(r *ResilienceInput) { r.ObservedAt = time.Time{} },
		// Claimed observation without a timestamp is fabrication.
		"backup no time":  func(r *ResilienceInput) { r.BackupAt = time.Time{} },
		"restore no time": func(r *ResilienceInput) { r.RestoreTestObserved = true },
	} {
		bad := base
		mut(&bad)
		if _, err := AssessResilience(bad); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestResilienceStatusesBounded(t *testing.T) {
	for _, s := range []ResilienceStatus{
		ResilienceReady, ResilienceDegraded, ResilienceNotReady,
		ResilienceNotAssessed, ResilienceUnknown,
	} {
		if string(s) == "" {
			t.Errorf("empty resilience status")
		}
	}
}
