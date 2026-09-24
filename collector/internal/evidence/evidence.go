// Package evidence builds provenance-preserving records from data the
// pipeline already holds: contributing telemetry, the detection, the alert.
// Content is always the canonical serialization of a real object — never
// synthesized screenshots, payloads, identities, or CVE-style artifacts.
//
// Integrity: every item carries hex(SHA-256(content)) via the standard
// library, and Verify recomputes it. That proves content matches its digest;
// it is NOT tamper-proof storage (there is no storage here at all).
//
// The layer is passive and data-only: observe, record, validate, hash.
// No execution, no blocking, no remediation, no external tools.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

var (
	// ErrEvidenceBuild: inputs could not become contract-valid Evidence
	// (nil input, broken linkage, missing referenced event, zero clock).
	ErrEvidenceBuild = errors.New("evidence: construction failure")
)

// Sources for derived (non-telemetry) evidence. Constants, documented.
const (
	SourceDetection = "blueveil-detect"
	SourceAlert     = "blueveil-detect"
	MediaJSON       = "application/json"
)

// digest returns lowercase hex SHA-256, deterministic for identical bytes.
func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Verify reports whether e's recorded digest matches its content. A false
// means the content was altered (or was never honestly digested).
func Verify(e *v1.Evidence) bool {
	if e == nil || e.GetSha256() == "" {
		return false
	}
	return digest([]byte(e.GetContent())) == e.GetSha256()
}

func evidenceID(incidentID, kind, refID string) string {
	sum := sha256.Sum256([]byte("blueveil-evidence-v1\x1f" + incidentID + "\x1f" + kind + "\x1f" + refID))
	return "ev-" + hex.EncodeToString(sum[:])[:16]
}

// BuildForAlert captures one evidence set for an alert inside an incident:
// one LOG_EXCERPT per contributing telemetry event (content = the event's
// canonical serialization), one NOTE for the detection and one for the
// alert. Every referenced id must be supplied; gaps are errors, never
// fabricated content.
func BuildForAlert(incidentID string, alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent, now time.Time) ([]*v1.Evidence, error) {
	if incidentID == "" {
		return nil, fmt.Errorf("%w: incident id is empty", ErrEvidenceBuild)
	}
	if alert == nil || det == nil {
		return nil, fmt.Errorf("%w: alert and detection are required", ErrEvidenceBuild)
	}
	if err := contract.ValidateAlert(alert); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvidenceBuild, err)
	}
	if err := contract.ValidateDetection(det); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvidenceBuild, err)
	}
	linked := false
	for _, id := range alert.GetDetectionIds() {
		if id == det.GetId() {
			linked = true
		}
	}
	if !linked {
		return nil, fmt.Errorf("%w: alert %q does not reference detection %q",
			ErrEvidenceBuild, alert.GetId(), det.GetId())
	}
	byID := make(map[string]*v1.TelemetryEvent, len(events))
	for _, e := range events {
		if e == nil {
			return nil, fmt.Errorf("%w: nil contributing event", ErrEvidenceBuild)
		}
		if err := contract.ValidateTelemetryEvent(e); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEvidenceBuild, err)
		}
		byID[e.GetId()] = e
	}
	for _, id := range det.GetTelemetryEventIds() {
		if _, ok := byID[id]; !ok {
			return nil, fmt.Errorf("%w: detection event %q not provided (refusing to fabricate)",
				ErrEvidenceBuild, id)
		}
	}
	if now.IsZero() {
		return nil, fmt.Errorf("%w: collection timestamp is zero", ErrEvidenceBuild)
	}

	mk := func(kind, refID string, typ v1.EvidenceType, source, content string) (*v1.Evidence, error) {
		ev, err := NewItem(incidentID, kind, refID, typ, source, content, now)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEvidenceBuild, err)
		}
		return ev, nil
	}

	var out []*v1.Evidence
	ids := det.GetTelemetryEventIds()
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	for _, id := range sorted {
		content, err := contract.MarshalCanonical(byID[id])
		if err != nil {
			return nil, fmt.Errorf("%w: serialize event %q: %v", ErrEvidenceBuild, id, err)
		}
		ev, err := mk("event", id, v1.EvidenceType_EVIDENCE_TYPE_LOG_EXCERPT, byID[id].GetSource(), string(content))
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	detContent, err := contract.MarshalCanonical(det)
	if err != nil {
		return nil, fmt.Errorf("%w: serialize detection: %v", ErrEvidenceBuild, err)
	}
	detEv, err := mk("detection", det.GetId(), v1.EvidenceType_EVIDENCE_TYPE_NOTE, SourceDetection, string(detContent))
	if err != nil {
		return nil, err
	}
	out = append(out, detEv)
	alertContent, err := contract.MarshalCanonical(alert)
	if err != nil {
		return nil, fmt.Errorf("%w: serialize alert: %v", ErrEvidenceBuild, err)
	}
	alertEv, err := mk("alert", alert.GetId(), v1.EvidenceType_EVIDENCE_TYPE_NOTE, SourceAlert, string(alertContent))
	if err != nil {
		return nil, err
	}
	out = append(out, alertEv)
	return out, nil
}

// NewItem builds one validated evidence item with a deterministic id and a
// SHA-256 digest of its content. Empty fields, zero timestamps, and invalid
// digests are construction errors — never defaulted or fabricated.
func NewItem(incidentID, kind, refID string, typ v1.EvidenceType, source, content string, now time.Time) (*v1.Evidence, error) {
	if incidentID == "" || kind == "" || refID == "" {
		return nil, fmt.Errorf("evidence identity is incomplete")
	}
	if now.IsZero() {
		return nil, fmt.Errorf("collection timestamp is zero")
	}
	collected := timestamppb.New(now)
	if collected == nil {
		return nil, fmt.Errorf("collection timestamp out of range")
	}
	ev := &v1.Evidence{
		Id:          evidenceID(incidentID, kind, refID),
		IncidentId:  incidentID,
		Type:        typ,
		CollectedAt: collected,
		Source:      source,
		MediaType:   MediaJSON,
		Sha256:      digest([]byte(content)),
		Content:     content,
	}
	if err := contract.ValidateEvidence(ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// Store is an in-memory evidence set keyed by deterministic id: the same
// logical item added twice is kept once (dedupe, reported). No persistence.
type Store struct {
	mu    sync.Mutex
	items map[string]*v1.Evidence
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{items: map[string]*v1.Evidence{}}
}

// Add inserts a copy of the item, returning false when its id was already
// stored. The store lazy-initializes so the zero value is usable.
func (s *Store) Add(e *v1.Evidence) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = map[string]*v1.Evidence{}
	}
	if _, exists := s.items[e.GetId()]; exists {
		return false
	}
	s.items[e.GetId()] = proto.Clone(e).(*v1.Evidence)
	return true
}

// Get returns a copy of the item for id, or false when absent. Copies keep
// callers from mutating stored evidence (which would defeat digest
// verification).
func (s *Store) Get(id string) (*v1.Evidence, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[id]
	if !ok {
		return nil, false
	}
	return proto.Clone(e).(*v1.Evidence), true
}

// List returns copies of all items in stable id order.
func (s *Store) List() []*v1.Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.items))
	for id := range s.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*v1.Evidence, 0, len(ids))
	for _, id := range ids {
		out = append(out, proto.Clone(s.items[id]).(*v1.Evidence))
	}
	return out
}

// Count returns the stored total.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}
