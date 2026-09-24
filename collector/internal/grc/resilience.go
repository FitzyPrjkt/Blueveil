// Metadata-level resilience posture (13I.10-12): declarative posture
// derived only from explicit observations. READY requires backup +
// restore-test + declared procedure all observed with timestamps.
// Partial evidence is DEGRADED; none is NOT_ASSESSED. No failover is
// executed, no infrastructure touched, no score computed.
package grc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ResilienceStatus is the bounded posture vocabulary.
type ResilienceStatus string

const (
	ResilienceReady       ResilienceStatus = "READY"
	ResilienceDegraded    ResilienceStatus = "DEGRADED"
	ResilienceNotReady    ResilienceStatus = "NOT_READY"
	ResilienceNotAssessed ResilienceStatus = "NOT_ASSESSED"
	ResilienceUnknown     ResilienceStatus = "UNKNOWN"
)

// ResilienceInput carries explicit observations. Every claimed
// observation needs its timestamp — a claim without one is fabrication
// and is rejected.
type ResilienceInput struct {
	Target              string
	Assessor            string
	ObservedAt          time.Time
	BackupObserved      bool
	BackupAt            time.Time
	RestoreTestObserved bool
	RestoreTestAt       time.Time
	ProcedureDeclared   bool
	Dependencies        []string
	EvidenceIDs         []string
	RetentionConfigured bool
	EncryptionObserved  bool
}

// ResilienceRecord is the assessed posture with provenance.
type ResilienceRecord struct {
	ID                  string
	Target              string
	Assessor            string
	ObservedAt          time.Time
	Status              ResilienceStatus
	BackupObserved      bool
	BackupAt            time.Time
	RestoreTestObserved bool
	RestoreTestAt       time.Time
	ProcedureDeclared   bool
	Dependencies        []string
	EvidenceIDs         []string
	RetentionConfigured bool
	EncryptionObserved  bool
}

// Validate enforces the same explicit-observation rules AssessResilience
// applies at construction, so hand-edited or corrupt records fail closed
// instead of reading back as healthy posture.
func (r ResilienceRecord) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("grc: resilience record identity required")
	}
	if strings.TrimSpace(r.Target) == "" {
		return fmt.Errorf("grc: resilience target required")
	}
	if strings.TrimSpace(r.Assessor) == "" {
		return fmt.Errorf("grc: resilience assessor/source required")
	}
	if r.ObservedAt.IsZero() {
		return fmt.Errorf("grc: resilience observed timestamp required")
	}
	switch r.Status {
	case ResilienceReady, ResilienceDegraded, ResilienceNotReady,
		ResilienceNotAssessed, ResilienceUnknown:
	default:
		return fmt.Errorf("grc: resilience status %q not in bounded vocabulary (no READY-by-default)", r.Status)
	}
	if r.BackupObserved && r.BackupAt.IsZero() {
		return fmt.Errorf("grc: claimed backup observation needs a timestamp")
	}
	if r.RestoreTestObserved && r.RestoreTestAt.IsZero() {
		return fmt.Errorf("grc: claimed restore-test observation needs a timestamp")
	}
	return nil
}

// AssessResilience derives posture deterministically from explicit
// observations only.
func AssessResilience(in ResilienceInput) (ResilienceRecord, error) {
	var rec ResilienceRecord
	if strings.TrimSpace(in.Target) == "" {
		return rec, fmt.Errorf("grc: resilience target required")
	}
	if strings.TrimSpace(in.Assessor) == "" {
		return rec, fmt.Errorf("grc: resilience assessor/source required")
	}
	if in.ObservedAt.IsZero() {
		return rec, fmt.Errorf("grc: resilience observed timestamp required")
	}
	if in.BackupObserved && in.BackupAt.IsZero() {
		return rec, fmt.Errorf("grc: claimed backup observation needs a timestamp")
	}
	if in.RestoreTestObserved && in.RestoreTestAt.IsZero() {
		return rec, fmt.Errorf("grc: claimed restore-test observation needs a timestamp")
	}
	rec = ResilienceRecord{
		Target: in.Target, Assessor: in.Assessor, ObservedAt: in.ObservedAt,
		BackupObserved: in.BackupObserved, BackupAt: in.BackupAt,
		RestoreTestObserved: in.RestoreTestObserved, RestoreTestAt: in.RestoreTestAt,
		ProcedureDeclared:   in.ProcedureDeclared,
		Dependencies:        append([]string(nil), in.Dependencies...),
		EvidenceIDs:         append([]string(nil), in.EvidenceIDs...),
		RetentionConfigured: in.RetentionConfigured,
		EncryptionObserved:  in.EncryptionObserved,
	}
	switch {
	case in.BackupObserved && in.RestoreTestObserved && in.ProcedureDeclared:
		rec.Status = ResilienceReady
	case in.BackupObserved || in.RestoreTestObserved || in.ProcedureDeclared:
		rec.Status = ResilienceDegraded
	default:
		rec.Status = ResilienceNotAssessed
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-grc-resilience-v1", in.Target, in.Assessor,
		in.ObservedAt.UTC().Format(time.RFC3339Nano), string(rec.Status),
	}, "\x1f")))
	rec.ID = "grsl-" + hex.EncodeToString(sum[:])[:16]
	return rec, nil
}
