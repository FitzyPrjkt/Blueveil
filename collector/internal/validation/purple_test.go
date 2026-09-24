// RED: purple-team exercise — explicit ID linkage only, neutral
// wording, deterministic IDs.
package validation

import (
	"errors"
	"strings"
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

var errProviderBoom = errors.New("boom: provider crashed")

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToUpper(s), sub)
}

func TestExerciseStatusMapping(t *testing.T) {
	cases := map[string]struct {
		verdict v1.ValidationVerdict
		perr    bool
		want    ExerciseStatus
	}{
		"prevented":   {v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED, false, StatusPrevented},
		"detected":    {v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED, false, StatusDetected},
		"both":        {v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED_AND_DETECTED, false, StatusPreventedAndDetected},
		"allowed det": {v1.ValidationVerdict_VALIDATION_VERDICT_ALLOWED_BUT_DETECTED, false, StatusAllowedButDetected},
		"allowed gap": {v1.ValidationVerdict_VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED, false, StatusAllowedAndNotDetected},
		"not tested":  {v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED, false, StatusNotTested},
		"rate limit":  {v1.ValidationVerdict_VALIDATION_VERDICT_RATE_LIMITED, false, StatusRateLimited},
		"unknown":     {v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN, false, StatusUnknownOutcome},
		"prov error":  {v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED, true, StatusProviderFailure},
	}
	for name, c := range cases {
		var perr error
		if c.perr {
			perr = errProviderBoom
		}
		if got := ExerciseStatusFor(c.verdict, perr); got != c.want {
			t.Errorf("%s: want %s, got %s", name, c.want, got)
		}
		if string(c.want) == "" {
			t.Errorf("%s: empty status string", name)
		}
	}
	// Neutral wording: no attack/compromise/breach language anywhere.
	for _, s := range []ExerciseStatus{
		StatusAttempted, StatusPrevented, StatusDetected, StatusPreventedAndDetected,
		StatusAllowedButDetected, StatusAllowedAndNotDetected, StatusNotTested,
		StatusRateLimited, StatusUnknownOutcome, StatusProviderFailure,
	} {
		for _, bad := range []string{"ATTACK", "COMPROMIS", "BREACH", "PWNED", "EXPLOIT"} {
			if containsFold(string(s), bad) {
				t.Errorf("status %q contains forbidden %q", s, bad)
			}
		}
	}
}

func TestExerciseBuild(t *testing.T) {
	ex, err := BuildExercise(ExerciseInput{
		CampaignID: "vcamp-abc",
		Name:       "lab exercise",
		Source:     "seed-lab-validation",
		Entries: []ExerciseEntryInput{
			{
				CaseID: "vcase-1", RequestID: "vreq-1", ResultID: "vres-1",
				Verdict:      v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
				TelemetryIDs: []string{"evt-1"}, DetectionIDs: []string{"det-1"},
				AlertIDs: []string{"alert-1"}, IncidentIDs: []string{"inc-1"},
				EvidenceIDs: []string{"ev-1"},
			},
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if ex.ID == "" {
		t.Fatalf("exercise id required")
	}
	if len(ex.Entries) != 1 || ex.Entries[0].Status != StatusDetected {
		t.Fatalf("entry status derived: %+v", ex.Entries)
	}
	again, err := BuildExercise(ExerciseInput{
		CampaignID: "vcamp-abc", Name: "lab exercise", Source: "seed-lab-validation",
		Entries: []ExerciseEntryInput{
			{
				CaseID: "vcase-1", RequestID: "vreq-1", ResultID: "vres-1",
				Verdict:      v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
				TelemetryIDs: []string{"evt-1"}, DetectionIDs: []string{"det-1"},
				AlertIDs: []string{"alert-1"}, IncidentIDs: []string{"inc-1"},
				EvidenceIDs: []string{"ev-1"},
			},
		},
	})
	if err != nil || again.ID != ex.ID {
		t.Fatalf("exercise id must be deterministic")
	}
}

func TestExerciseRejects(t *testing.T) {
	base := ExerciseEntryInput{
		CaseID: "vcase-1", RequestID: "vreq-1", ResultID: "vres-1",
		Verdict:      v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		TelemetryIDs: []string{"evt-1"},
	}
	for name, mut := range map[string]func(*ExerciseInput){
		"empty campaign": func(i *ExerciseInput) { i.CampaignID = "" },
		"empty name":     func(i *ExerciseInput) { i.Name = "" },
		"empty source":   func(i *ExerciseInput) { i.Source = "" },
		"no entries":     func(i *ExerciseInput) { i.Entries = nil },
	} {
		in := ExerciseInput{
			CampaignID: "vcamp-abc", Name: "n", Source: "s",
			Entries: []ExerciseEntryInput{base},
		}
		mut(&in)
		if _, err := BuildExercise(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	for name, mut := range map[string]func(*ExerciseEntryInput){
		"empty case":    func(e *ExerciseEntryInput) { e.CaseID = "" },
		"empty request": func(e *ExerciseEntryInput) { e.RequestID = "" },
		"empty result":  func(e *ExerciseEntryInput) { e.ResultID = "" },
		"no telemetry":  func(e *ExerciseEntryInput) { e.TelemetryIDs = nil },
	} {
		entry := base
		mut(&entry)
		_, err := BuildExercise(ExerciseInput{
			CampaignID: "vcamp-abc", Name: "n", Source: "s",
			Entries: []ExerciseEntryInput{entry},
		})
		if err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
