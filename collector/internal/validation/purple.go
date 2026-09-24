// Purple-team exercise model (13H.9): explicit correlation of a
// validation case to the telemetry/detection/alert/incident/evidence it
// observably produced. Every link is an explicit identifier supplied by
// the caller — timestamps alone never correlate. Wording is neutral:
// exercises describe what was observed, never attacks or compromises.
package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	v1 "blueveil/collector/internal/contract/v1"
)

// ExerciseStatus is the bounded neutral vocabulary for exercise entries.
type ExerciseStatus string

const (
	StatusAttempted             ExerciseStatus = "ATTEMPTED"
	StatusPrevented             ExerciseStatus = "PREVENTED"
	StatusDetected              ExerciseStatus = "DETECTED"
	StatusPreventedAndDetected  ExerciseStatus = "PREVENTED_AND_DETECTED"
	StatusAllowedButDetected    ExerciseStatus = "ALLOWED_BUT_DETECTED"
	StatusAllowedAndNotDetected ExerciseStatus = "ALLOWED_AND_NOT_DETECTED"
	StatusNotTested             ExerciseStatus = "NOT_TESTED"
	StatusRateLimited           ExerciseStatus = "RATE_LIMITED"
	StatusUnknownOutcome        ExerciseStatus = "UNKNOWN_OUTCOME"
	StatusProviderFailure       ExerciseStatus = "PROVIDER_FAILURE"
)

// ExerciseStatusFor maps a verdict (plus optional provider error) to the
// neutral exercise status. Provider failure always wins: a crashed
// provider says nothing about the control.
func ExerciseStatusFor(verdict v1.ValidationVerdict, providerErr error) ExerciseStatus {
	if providerErr != nil {
		return StatusProviderFailure
	}
	switch verdict {
	case v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED:
		return StatusPrevented
	case v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED:
		return StatusDetected
	case v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED_AND_DETECTED:
		return StatusPreventedAndDetected
	case v1.ValidationVerdict_VALIDATION_VERDICT_ALLOWED_BUT_DETECTED:
		return StatusAllowedButDetected
	case v1.ValidationVerdict_VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED:
		return StatusAllowedAndNotDetected
	case v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED:
		return StatusNotTested
	case v1.ValidationVerdict_VALIDATION_VERDICT_RATE_LIMITED:
		return StatusRateLimited
	case v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN:
		return StatusUnknownOutcome
	default:
		return StatusUnknownOutcome
	}
}

// ExerciseEntryInput is one explicitly linked case outcome.
type ExerciseEntryInput struct {
	CaseID       string
	RequestID    string
	ResultID     string
	Verdict      v1.ValidationVerdict
	ProviderErr  error
	TelemetryIDs []string
	DetectionIDs []string
	AlertIDs     []string
	IncidentIDs  []string
	EvidenceIDs  []string
}

// ExerciseInput builds one exercise.
type ExerciseInput struct {
	CampaignID string
	Name       string
	Source     string
	Entries    []ExerciseEntryInput
}

// ExerciseEntry is one correlated case outcome with derived status.
type ExerciseEntry struct {
	CaseID       string
	RequestID    string
	ResultID     string
	Verdict      v1.ValidationVerdict
	Status       ExerciseStatus
	TelemetryIDs []string
	DetectionIDs []string
	AlertIDs     []string
	IncidentIDs  []string
	EvidenceIDs  []string
}

// Exercise is the persisted purple-team record.
type Exercise struct {
	ID         string
	CampaignID string
	Name       string
	Source     string
	Entries    []ExerciseEntry
}

// validExerciseStatus reports whether s is a derived exercise status.
func validExerciseStatus(s ExerciseStatus) bool {
	switch s {
	case StatusAttempted, StatusPrevented, StatusDetected,
		StatusPreventedAndDetected, StatusAllowedButDetected,
		StatusAllowedAndNotDetected, StatusNotTested, StatusRateLimited,
		StatusUnknownOutcome, StatusProviderFailure:
		return true
	}
	return false
}

// Validate re-checks a persisted exercise: identity, campaign linkage,
// and every entry's linkage, verdict vocabulary, and derived status. A
// hand-edited payload that BuildExercise would reject fails closed here.
func (e Exercise) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("validation: exercise identity required")
	}
	if strings.TrimSpace(e.CampaignID) == "" {
		return fmt.Errorf("validation: exercise campaign required")
	}
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("validation: exercise name required")
	}
	if strings.TrimSpace(e.Source) == "" {
		return fmt.Errorf("validation: exercise source required")
	}
	if len(e.Entries) == 0 {
		return fmt.Errorf("validation: exercise needs at least one entry")
	}
	for i, en := range e.Entries {
		if strings.TrimSpace(en.CaseID) == "" {
			return fmt.Errorf("validation: exercise entry %d: case required", i)
		}
		if strings.TrimSpace(en.RequestID) == "" {
			return fmt.Errorf("validation: exercise entry %d: request required", i)
		}
		if strings.TrimSpace(en.ResultID) == "" {
			return fmt.Errorf("validation: exercise entry %d: result required", i)
		}
		if len(en.TelemetryIDs) == 0 {
			return fmt.Errorf("validation: exercise entry %d: telemetry linkage required", i)
		}
		if en.Verdict == v1.ValidationVerdict_VALIDATION_VERDICT_UNSPECIFIED {
			return fmt.Errorf("validation: exercise entry %d: explicit verdict required", i)
		}
		if _, known := v1.ValidationVerdict_name[int32(en.Verdict)]; !known {
			return fmt.Errorf("validation: exercise entry %d: verdict %d out of bounded vocabulary", i, int32(en.Verdict))
		}
		if !validExerciseStatus(en.Status) {
			return fmt.Errorf("validation: exercise entry %d: status %q out of bounded vocabulary", i, en.Status)
		}
	}
	return nil
}

// BuildExercise validates explicit linkage and derives neutral statuses.
// Exercise IDs are deterministic over campaign + ordered case/result ids.
func BuildExercise(in ExerciseInput) (Exercise, error) {
	var ex Exercise
	if strings.TrimSpace(in.CampaignID) == "" {
		return ex, fmt.Errorf("validation: exercise campaign required")
	}
	if strings.TrimSpace(in.Name) == "" {
		return ex, fmt.Errorf("validation: exercise name required")
	}
	if strings.TrimSpace(in.Source) == "" {
		return ex, fmt.Errorf("validation: exercise source required")
	}
	if len(in.Entries) == 0 {
		return ex, fmt.Errorf("validation: exercise needs at least one entry")
	}
	ex = Exercise{CampaignID: in.CampaignID, Name: in.Name, Source: in.Source}
	keyParts := []string{"blueveil-purple-exercise-v1", in.CampaignID, in.Name}
	for i, e := range in.Entries {
		if strings.TrimSpace(e.CaseID) == "" {
			return Exercise{}, fmt.Errorf("validation: exercise entry %d: case required", i)
		}
		if strings.TrimSpace(e.RequestID) == "" {
			return Exercise{}, fmt.Errorf("validation: exercise entry %d: request required", i)
		}
		if strings.TrimSpace(e.ResultID) == "" {
			return Exercise{}, fmt.Errorf("validation: exercise entry %d: result required", i)
		}
		if len(e.TelemetryIDs) == 0 {
			return Exercise{}, fmt.Errorf("validation: exercise entry %d: telemetry linkage required", i)
		}
		if e.Verdict == v1.ValidationVerdict_VALIDATION_VERDICT_UNSPECIFIED {
			return Exercise{}, fmt.Errorf("validation: exercise entry %d: explicit verdict required (UNSPECIFIED is not an outcome)", i)
		}
		if _, known := v1.ValidationVerdict_name[int32(e.Verdict)]; !known {
			return Exercise{}, fmt.Errorf("validation: exercise entry %d: verdict %d out of bounded vocabulary", i, int32(e.Verdict))
		}
		ex.Entries = append(ex.Entries, ExerciseEntry{
			CaseID: e.CaseID, RequestID: e.RequestID, ResultID: e.ResultID,
			Verdict: e.Verdict, Status: ExerciseStatusFor(e.Verdict, e.ProviderErr),
			TelemetryIDs: append([]string(nil), e.TelemetryIDs...),
			DetectionIDs: append([]string(nil), e.DetectionIDs...),
			AlertIDs:     append([]string(nil), e.AlertIDs...),
			IncidentIDs:  append([]string(nil), e.IncidentIDs...),
			EvidenceIDs:  append([]string(nil), e.EvidenceIDs...),
		})
		keyParts = append(keyParts, e.CaseID, e.ResultID)
	}
	sum := sha256.Sum256([]byte(strings.Join(keyParts, "\x1f")))
	ex.ID = "pex-" + hex.EncodeToString(sum[:])[:16]
	return ex, nil
}
