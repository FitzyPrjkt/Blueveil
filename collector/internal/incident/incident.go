// Package incident manages the Alert → Incident layer: deterministic
// construction, correlation, minimal lifecycle, in-memory records.
//
// An incident groups alerts that belong together and nothing else: no
// assignment, no escalation, no SLA, no remediation, no response. Invalid
// transitions are explicit errors, never silent normalization.
package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/correlate"
)

var (
	// ErrIncidentBuild: an alert/detection/event triple could not become a
	// contract-valid Incident (invalid input, broken linkage, zero clock).
	ErrIncidentBuild = errors.New("incident: construction failure")
	// ErrIncidentTransition: an illegal lifecycle move was attempted.
	ErrIncidentTransition = errors.New("incident: illegal transition")
	// ErrIncidentNotFound: no incident with the requested id is managed here.
	ErrIncidentNotFound = errors.New("incident: unknown incident")
)

// nextState is the entire lifecycle: one step forward, no skips, no way
// back, CLOSED is terminal. Anything else is ErrIncidentTransition.
var nextState = map[v1.IncidentStatus]v1.IncidentStatus{
	v1.IncidentStatus_INCIDENT_STATUS_OPEN:          v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING,
	v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING: v1.IncidentStatus_INCIDENT_STATUS_CONTAINED,
	v1.IncidentStatus_INCIDENT_STATUS_CONTAINED:     v1.IncidentStatus_INCIDENT_STATUS_RESOLVED,
	v1.IncidentStatus_INCIDENT_STATUS_RESOLVED:      v1.IncidentStatus_INCIDENT_STATUS_CLOSED,
}

type record struct {
	incident *v1.Incident
	alerts   map[string]bool
	rules    map[string]bool
	assets   map[string]bool
}

// Manager owns incident records. Clock provides lifecycle timestamps;
// a nil clock is a construction error (no invented time).
type Manager struct {
	mu    sync.Mutex
	clock func() time.Time
	byID  map[string]*record
	byKey map[string]string
}

// NewManager returns an empty manager.
func NewManager(clock func() time.Time) (*Manager, error) {
	if clock == nil {
		return nil, fmt.Errorf("incident: manager clock is nil")
	}
	return &Manager{clock: clock, byID: map[string]*record{}, byKey: map[string]string{}}, nil
}

// correlationKey prefers the explicit signal: when every contributing event
// carries the same non-empty blueveil.correlation_id, alerts group by it.
// Otherwise the safe baseline applies: one alert, one incident. No heuristic
// merging, ever.
func correlationKey(alert *v1.Alert, events []*v1.TelemetryEvent) string {
	shared := ""
	for i, e := range events {
		c := e.GetAttributes()[correlate.AttributeKey]
		if c == "" || (i > 0 && c != shared) {
			return "alert:" + alert.GetId()
		}
		shared = c
	}
	if shared == "" {
		return "alert:" + alert.GetId()
	}
	return "corr:" + shared
}

func incidentID(key string) string {
	sum := sha256.Sum256([]byte("blueveil-incident-v1\x1f" + key))
	return "inc-" + hex.EncodeToString(sum[:])[:16]
}

func summarize(alerts map[string]bool, rules map[string]bool, assets map[string]bool) string {
	return fmt.Sprintf("%d alert(s); rule(s): %s; asset(s): %s",
		len(alerts), strings.Join(sortedKeys(rules), ","), strings.Join(sortedKeys(assets), ","))
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Ingest folds one alert (with its detection and contributing events) into
// the matching incident, creating it when needed. Returns the incident
// (a copy) and whether it was created. Re-ingesting an attached alert is a
// no-op returning the unchanged incident.
func (m *Manager) Ingest(alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent) (*v1.Incident, bool, error) {
	if alert == nil || det == nil {
		return nil, false, fmt.Errorf("%w: alert and detection are required", ErrIncidentBuild)
	}
	if err := contract.ValidateAlert(alert); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrIncidentBuild, err)
	}
	if err := contract.ValidateDetection(det); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrIncidentBuild, err)
	}
	linked := false
	for _, id := range alert.GetDetectionIds() {
		if id == det.GetId() {
			linked = true
		}
	}
	if !linked {
		return nil, false, fmt.Errorf("%w: alert %q does not reference detection %q",
			ErrIncidentBuild, alert.GetId(), det.GetId())
	}
	byID := make(map[string]*v1.TelemetryEvent, len(events))
	for _, e := range events {
		if e == nil {
			return nil, false, fmt.Errorf("%w: nil contributing event", ErrIncidentBuild)
		}
		byID[e.GetId()] = e
	}
	for _, id := range det.GetTelemetryEventIds() {
		if _, ok := byID[id]; !ok {
			return nil, false, fmt.Errorf("%w: detection event %q not provided (refusing to fabricate)",
				ErrIncidentBuild, id)
		}
	}
	now := m.clock()
	if now.IsZero() {
		return nil, false, fmt.Errorf("%w: clock returned zero time", ErrIncidentBuild)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byID == nil {
		m.byID = map[string]*record{}
	}
	if m.byKey == nil {
		m.byKey = map[string]string{}
	}
	key := correlationKey(alert, events)
	if id, exists := m.byKey[key]; exists {
		rec := m.byID[id]
		if rec.alerts[alert.GetId()] {
			return proto.Clone(rec.incident).(*v1.Incident), false, nil
		}
		rec.alerts[alert.GetId()] = true
		rec.incident.AlertIds = append(rec.incident.AlertIds, alert.GetId())
		sort.Strings(rec.incident.AlertIds)
		rec.rules[det.GetRuleId()] = true
		for _, e := range events {
			rec.assets[e.GetAssetId()] = true
		}
		if alert.GetSeverity() > rec.incident.GetSeverity() {
			rec.incident.Severity = alert.GetSeverity()
		}
		rec.incident.UpdatedAt = timestamppb.New(now)
		rec.incident.Summary = summarize(rec.alerts, rec.rules, rec.assets)
		if err := contract.ValidateIncident(rec.incident); err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrIncidentBuild, err)
		}
		return proto.Clone(rec.incident).(*v1.Incident), false, nil
	}

	assets := map[string]bool{}
	for _, e := range events {
		assets[e.GetAssetId()] = true
	}
	inc := &v1.Incident{
		Id:        incidentID(key),
		AlertIds:  []string{alert.GetId()},
		Status:    v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		Severity:  alert.GetSeverity(),
		CreatedAt: timestamppb.New(now),
		UpdatedAt: timestamppb.New(now),
		Title:     "Incident: " + alert.GetTitle(),
		Summary: summarize(
			map[string]bool{alert.GetId(): true},
			map[string]bool{det.GetRuleId(): true},
			assets,
		),
	}
	if err := contract.ValidateIncident(inc); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrIncidentBuild, err)
	}
	m.byID[inc.GetId()] = &record{
		incident: inc,
		alerts:   map[string]bool{alert.GetId(): true},
		rules:    map[string]bool{det.GetRuleId(): true},
		assets:   assets,
	}
	m.byKey[key] = inc.GetId()
	return proto.Clone(inc).(*v1.Incident), true, nil
}

// Transition moves one incident exactly one lifecycle step forward,
// stamping updated_at. Anything else — skips, repeats, reversals, moves out
// of CLOSED, unknown ids — is an explicit error.
func (m *Manager) Transition(id string, to v1.IncidentStatus) (*v1.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrIncidentNotFound, id)
	}
	want, ok := nextState[rec.incident.GetStatus()]
	if !ok || want != to {
		return nil, fmt.Errorf("%w: %v → %v", ErrIncidentTransition, rec.incident.GetStatus(), to)
	}
	now := m.clock()
	if now.IsZero() {
		return nil, fmt.Errorf("%w: clock returned zero time", ErrIncidentBuild)
	}
	rec.incident.Status = to
	rec.incident.UpdatedAt = timestamppb.New(now)
	if err := contract.ValidateIncident(rec.incident); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIncidentBuild, err)
	}
	return proto.Clone(rec.incident).(*v1.Incident), nil
}

// Get returns a copy of the incident, or false when unknown.
func (m *Manager) Get(id string) (*v1.Incident, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return nil, false
	}
	return proto.Clone(rec.incident).(*v1.Incident), true
}

// List returns copies of all incidents in stable id order.
func (m *Manager) List() []*v1.Incident {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.byID))
	for id := range m.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*v1.Incident, 0, len(ids))
	for _, id := range ids {
		out = append(out, proto.Clone(m.byID[id].incident).(*v1.Incident))
	}
	return out
}
