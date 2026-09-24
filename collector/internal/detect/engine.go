// Detection engine: rule matches become contract-valid Detections, each new
// Detection becomes exactly one Alert. Deduplication is an in-memory set of
// emitted detection ids (documented limit: restart clears it; single
// instance only). A nil-match event yields nothing; any failure aborts
// loudly — never a silent no-detection.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

var (
	// ErrInvalidTelemetry: the event failed the contract boundary before any
	// rule ran.
	ErrInvalidTelemetry = errors.New("detect: invalid telemetry")
	// ErrRuleEvaluation: a rule failed; the event is aborted, not cleared.
	ErrRuleEvaluation = errors.New("detect: rule evaluation failure")
	// ErrDetectionBuild: a match could not become a contract-valid Detection.
	ErrDetectionBuild = errors.New("detect: detection construction failure")
	// ErrAlertBuild: a Detection could not become a contract-valid Alert.
	ErrAlertBuild = errors.New("detect: alert construction failure")
)

// ConfidenceBasis documents why every boolean-rule Detection carries
// confidence 0.0: no probabilistic estimate was derived, and none is
// pretended. Recorded in-band on every Detection this engine builds.
const ConfidenceBasis = "boolean-condition-unmeasured"

// Engine evaluates registered rules over canonical telemetry.
type Engine struct {
	mu           sync.Mutex
	registry     *Registry
	clock        func() time.Time
	seen         map[string]struct{}
	emittedDet   int
	emittedAlert int
	suppressed   int
	stats        map[string]*ruleStat
}

// ruleStat is the health record for one rule: evaluated and detection
// counts plus the error events that aborted loudly. Recording never
// changes evaluation semantics.
type ruleStat struct {
	evaluated  int
	detections int
	errors     int
	errEvents  []ErrorEvent
}

// ErrorEvent records one loud rule-evaluation failure with provenance.
// Severity is the failing event's own rating (source basis for any
// health detection built over these records).
type ErrorEvent struct {
	RuleID   string
	EventID  string
	At       time.Time
	Severity v1.Severity
	Err      string
}

// NewEngine returns an engine with its own empty registry; nil clock is a
// construction error (detections must not invent timestamps).
func NewEngine(clock func() time.Time) (*Engine, error) {
	if clock == nil {
		return nil, fmt.Errorf("detect: engine clock is nil")
	}
	return &Engine{registry: NewRegistry(), clock: clock, seen: map[string]struct{}{}, stats: map[string]*ruleStat{}}, nil
}

// RegisterRule delegates to the registry (duplicates rejected).
func (e *Engine) RegisterRule(rule Rule) error {
	return e.registry.Register(rule)
}

// Rules lists registered rules in order.
func (e *Engine) Rules() []Rule {
	return e.registry.List()
}

// Counts reports emitted detections, emitted alerts, and suppressed
// re-emissions. Mutex-guarded for direct use.
func (e *Engine) Counts() (detections, alerts, suppressed int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.emittedDet, e.emittedAlert, e.suppressed
}

// RuleHealth is the observability row for one registered rule: real
// counters only, never fabricated. Disabled rules report Enabled=false
// and stop accumulating evaluations. Threshold/Window/HasThreshold carry
// the live instance configuration for stateful rules.
type RuleHealth struct {
	RuleID       string
	Version      string
	Name         string
	Enabled      bool
	Evaluated    int
	Detections   int
	Errors       int
	Threshold    int
	Window       time.Duration
	HasThreshold bool
}

// Health returns one row per registered rule in registration order.
// Absent counters are zero because nothing happened, not because data
// was hidden: a rule with no evaluations reports Evaluated=0 honestly.
func (e *Engine) Health() []RuleHealth {
	e.mu.Lock()
	defer e.mu.Unlock()
	rules := e.registry.List()
	out := make([]RuleHealth, 0, len(rules))
	for _, rule := range rules {
		st := e.stats[rule.ID()]
		row := RuleHealth{RuleID: rule.ID(), Version: rule.Version(), Name: rule.Name(), Enabled: e.registry.IsEnabled(rule.ID())}
		if st != nil {
			row.Evaluated, row.Detections, row.Errors = st.evaluated, st.detections, st.errors
		}
		if t, ok := rule.(Thresholded); ok {
			row.Threshold, row.Window = t.ThresholdWindow()
			row.HasThreshold = true
		}
		out = append(out, row)
	}
	return out
}

// RuleErrors returns the recorded loud evaluation failures for one rule
// in recording order. Unknown rule ids yield an empty slice.
func (e *Engine) RuleErrors(ruleID string) []ErrorEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.stats[ruleID]
	if st == nil {
		return nil
	}
	return append([]ErrorEvent(nil), st.errEvents...)
}

// Disable takes a registered rule out of evaluation; Enable restores it.
// Both delegate to the registry (unknown ids are errors).
func (e *Engine) Disable(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.registry.Disable(id)
}

// Enable restores a disabled rule to evaluation.
func (e *Engine) Enable(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.registry.Enable(id)
}

// Result is one Process call's new output. Suppressed counts matches whose
// Detection was already emitted before.
type Result struct {
	Detections []*v1.Detection
	Alerts     []*v1.Alert
	Suppressed int
}

// Process evaluates one contract-valid event and emits new Detections and
// their Alerts. Invalid telemetry, rule errors, and construction failures
// all abort with explicit errors and zero output.
func (e *Engine) Process(event *v1.TelemetryEvent) (Result, error) {
	if err := contract.ValidateTelemetryEvent(event); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInvalidTelemetry, err)
	}
	now := e.clock()
	if now.IsZero() {
		return Result{}, fmt.Errorf("%w: clock returned zero time", ErrDetectionBuild)
	}
	var matches []Match
	for _, rule := range e.registry.List() {
		if !e.registry.IsEnabled(rule.ID()) {
			continue
		}
		e.mu.Lock()
		st := e.stats[rule.ID()]
		if st == nil {
			st = &ruleStat{}
			e.stats[rule.ID()] = st
		}
		st.evaluated++
		e.mu.Unlock()
		outcome, err := rule.Evaluate(event)
		if err != nil {
			e.mu.Lock()
			st.errors++
			st.errEvents = append(st.errEvents, ErrorEvent{RuleID: rule.ID(), EventID: event.GetId(), At: now, Severity: event.GetSeverity(), Err: err.Error()})
			e.mu.Unlock()
			return Result{}, fmt.Errorf("%w: rule %q evaluation: %v", ErrRuleEvaluation, rule.ID(), err)
		}
		if outcome.Matched {
			matches = append(matches, Match{Rule: rule, Outcome: outcome})
		}
	}
	var result Result
	for _, m := range matches {
		det, err := BuildDetection(m.Rule, m.Outcome, now)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrDetectionBuild, err)
		}
		alert, err := BuildAlert(det, now)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrAlertBuild, err)
		}
		e.mu.Lock()
		_, dup := e.seen[det.GetId()]
		if !dup {
			e.seen[det.GetId()] = struct{}{}
			e.emittedDet++
			e.emittedAlert++
			if st := e.stats[m.Rule.ID()]; st != nil {
				st.detections++
			}
		} else {
			e.suppressed++
			result.Suppressed++
		}
		e.mu.Unlock()
		if dup {
			continue
		}
		result.Detections = append(result.Detections, det)
		result.Alerts = append(result.Alerts, alert)
	}
	return result, nil
}

// detectionID deterministically identifies a match: same rule + same
// contributing events always yield the same id, in any process, any run.
func detectionID(ruleID string, eventIDs []string) string {
	sorted := append([]string(nil), eventIDs...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(ruleID + "\x1f" + strings.Join(sorted, "\x1f")))
	return "det-" + hex.EncodeToString(sum[:])[:16]
}

// BuildDetection turns one match into a contract-valid Detection. Rule
// attributes using the blueveil.* namespace are rejected: that namespace
// belongs to pipeline builders, and rules must not smuggle system metadata.
func BuildDetection(rule Rule, outcome Outcome, now time.Time) (*v1.Detection, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is nil")
	}
	if !outcome.Matched {
		return nil, fmt.Errorf("no match to build from")
	}
	if len(outcome.EventIDs) == 0 {
		return nil, fmt.Errorf("match references no events")
	}
	if _, known := v1.Severity_name[int32(outcome.Severity)]; !known ||
		outcome.Severity == v1.Severity_SEVERITY_UNSPECIFIED {
		return nil, fmt.Errorf("match severity must be explicit, got %v", int32(outcome.Severity))
	}
	if math.IsNaN(outcome.Confidence) || outcome.Confidence < 0.0 || outcome.Confidence > 1.0 {
		return nil, fmt.Errorf("match confidence %v out of [0.0, 1.0]", outcome.Confidence)
	}
	if now.IsZero() {
		return nil, fmt.Errorf("detection timestamp is zero")
	}
	attrs := map[string]string{
		"blueveil.rule_version":     rule.Version(),
		"blueveil.confidence_basis": ConfidenceBasis,
	}
	for k, v := range outcome.Attrs {
		if strings.HasPrefix(k, "blueveil.") {
			return nil, fmt.Errorf("rule attribute %q invades the blueveil.* namespace", k)
		}
		attrs[k] = v
	}
	ids := append([]string(nil), outcome.EventIDs...)
	sort.Strings(ids)
	det := &v1.Detection{
		Id:                detectionID(rule.ID(), ids),
		RuleId:            rule.ID(),
		RuleName:          rule.Name(),
		TelemetryEventIds: ids,
		DetectedAt:        timestamppb.New(now),
		Severity:          outcome.Severity,
		Confidence:        outcome.Confidence,
		Title:             outcome.Title,
		Description:       outcome.Detail,
		Attributes:        attrs,
	}
	if det.GetDetectedAt() == nil {
		return nil, fmt.Errorf("detection timestamp out of range")
	}
	if det.GetTitle() == "" || det.GetDescription() == "" {
		return nil, fmt.Errorf("detection needs title and detail")
	}
	if err := contract.ValidateDetection(det); err != nil {
		return nil, err
	}
	return det, nil
}

// BuildAlert turns one Detection into exactly one Alert (1:1, deterministic
// id). Nil or contract-invalid detections are construction errors; there is
// no alert without a detection.
func BuildAlert(det *v1.Detection, now time.Time) (*v1.Alert, error) {
	if det == nil {
		return nil, fmt.Errorf("detection is nil")
	}
	if err := contract.ValidateDetection(det); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, fmt.Errorf("alert timestamp is zero")
	}
	alert := &v1.Alert{
		Id:           "alert-" + det.GetId(),
		DetectionIds: []string{det.GetId()},
		Status:       v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity:     det.GetSeverity(),
		CreatedAt:    timestamppb.New(now),
		UpdatedAt:    timestamppb.New(now),
		Title:        "Alert: " + det.GetTitle(),
	}
	if alert.GetCreatedAt() == nil {
		return nil, fmt.Errorf("alert timestamp out of range")
	}
	if err := contract.ValidateAlert(alert); err != nil {
		return nil, err
	}
	return alert, nil
}

// Store collects emitted detections and alerts in memory for tests,
// self-test, and later handoff stages. No persistence implied.
type Store struct {
	mu         sync.Mutex
	detections []*v1.Detection
	alerts     []*v1.Alert
}

// Add records copies of one emitted detection/alert pair, so later caller
// mutation cannot rewrite stored output.
func (s *Store) Add(det *v1.Detection, alert *v1.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.detections = append(s.detections, proto.Clone(det).(*v1.Detection))
	s.alerts = append(s.alerts, proto.Clone(alert).(*v1.Alert))
}

// Detections returns copies of recorded detections.
func (s *Store) Detections() []*v1.Detection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*v1.Detection, 0, len(s.detections))
	for _, d := range s.detections {
		out = append(out, proto.Clone(d).(*v1.Detection))
	}
	return out
}

// Alerts returns copies of recorded alerts.
func (s *Store) Alerts() []*v1.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*v1.Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		out = append(out, proto.Clone(a).(*v1.Alert))
	}
	return out
}

// Counts returns recorded detection/alert totals.
func (s *Store) Counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.detections), len(s.alerts)
}
