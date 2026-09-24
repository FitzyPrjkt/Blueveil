// Threat-intel and multi-stage detections (Step 13F). Three rules:
//
// T1 matches persisted telemetry against an explicitly configured offline
// IOC set (exact membership only). A match means "configured IOC
// observed" — never malware, never compromise. Severity comes only from
// the IOC policy, never from IOC presence.
//
// T2 fires when an explicit auth-failure sequence for one principal is
// followed by an identity privilege change for the same principal inside
// a configured window. A completed sequence is observed correlated
// activity, never a confirmed attack.
//
// T3 aggregates repeated deterministic rule-evaluation errors per rule.
// It is an engine-health signal computed batch-style over recorded
// errors, never a compromise signal about any target.
package detect

import (
	"fmt"
	"sort"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/identobs"
	"blueveil/collector/internal/threatintel"
)

// ---------------------------------------------------------------------------
// Rule T1: configured IOC match (stateless).
// ---------------------------------------------------------------------------

// ConfiguredIOCMatchRule fires when one event exactly contains a
// configured offline indicator. First sorted match wins, deterministically.
type ConfiguredIOCMatchRule struct {
	set      threatintel.Set
	severity v1.Severity
	label    string
}

// NewConfiguredIOCMatchRule validates the policy: empty sets, unspecified
// severity, and unlabeled policies are construction errors. There is no
// hardcoded severity for IOC presence.
func NewConfiguredIOCMatchRule(set threatintel.Set, severity v1.Severity, label string) (*ConfiguredIOCMatchRule, error) {
	if len(set.Entries) == 0 {
		return nil, fmt.Errorf("detect: ioc-match needs a non-empty IOC set")
	}
	if _, known := v1.Severity_name[int32(severity)]; !known || severity == v1.Severity_SEVERITY_UNSPECIFIED {
		return nil, fmt.Errorf("detect: ioc-match explicit severity required, got %v", int32(severity))
	}
	if label == "" {
		return nil, fmt.Errorf("detect: ioc-match policy label required")
	}
	return &ConfiguredIOCMatchRule{set: set, severity: severity, label: label}, nil
}

func (ConfiguredIOCMatchRule) ID() string      { return "configured-ioc-match" }
func (ConfiguredIOCMatchRule) Version() string { return "1" }
func (ConfiguredIOCMatchRule) Name() string    { return "Configured IOC match observed" }
func (ConfiguredIOCMatchRule) Description() string {
	return "Matches telemetry exactly containing a configured offline indicator. " +
		"An observation of a configured string; not malware, not compromise."
}

func (r *ConfiguredIOCMatchRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	matches := threatintel.MatchEvent(event, r.set)
	if len(matches) == 0 {
		return Outcome{}, nil
	}
	m := matches[0]
	return Outcome{
		Matched:  true,
		Severity: r.severity,
		Title:    "Configured IOC match observed",
		Detail: fmt.Sprintf("event %s field %q exactly holds configured %s indicator %q from set %q (event %s)",
			event.GetId(), m.MatchedField, m.Kind, m.Indicator, r.set.ID, event.GetId()),
		EventIDs: []string{event.GetId()},
		Attrs: map[string]string{
			"ioc_set":     r.set.ID,
			"ioc_version": r.set.Version,
			"indicator":   m.Indicator,
			"ioc_kind":    m.Kind,
			"field":       m.MatchedField,
			"policy":      r.label,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule T2: multi-stage correlated activity (stateful, per principal).
// ---------------------------------------------------------------------------

type stageFailure struct {
	at time.Time
	id string
}

// MultiStageCorrelatedRule fires once when threshold explicit auth
// failures for one principal are followed by an identity privilege change
// for the same principal inside window (event time). Successes never
// count; other principals never join. Re-arms when the failure set moves
// on: a later change over a different in-window failure set fires again.
type MultiStageCorrelatedRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	failures  map[string][]stageFailure
	firedSets map[string]string
}

// NewMultiStageCorrelatedRule validates parameters; invalid is a
// construction error, never a silent default.
func NewMultiStageCorrelatedRule(threshold int, window time.Duration, clock func() time.Time) (*MultiStageCorrelatedRule, error) {
	if err := checkBurstParams(threshold, window, "multi-stage"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: multi-stage clock is nil")
	}
	return &MultiStageCorrelatedRule{threshold: threshold, window: window, clock: clock, failures: map[string][]stageFailure{}, firedSets: map[string]string{}}, nil
}

func (*MultiStageCorrelatedRule) ID() string      { return "multi-stage-correlated-activity" }
func (*MultiStageCorrelatedRule) Version() string { return "1" }
func (*MultiStageCorrelatedRule) Name() string    { return "Multi-stage correlated activity" }
func (*MultiStageCorrelatedRule) Description() string {
	return "Matches an auth-failure sequence for one principal followed by that principal's privilege change inside window. " +
		"Observed correlated activity; not a confirmed attack."
}

func (r *MultiStageCorrelatedRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if err := checkNetClock(r.clock, "multi-stage"); err != nil {
		return Outcome{}, err
	}
	switch event.GetEventType() {
	case identobs.EventTypeAuthActivity:
		obs, err := identobs.Parse(event)
		if err != nil {
			return Outcome{}, fmt.Errorf("detect: multi-stage: %w", err)
		}
		if obs.Auth.Outcome != "failure" {
			return Outcome{}, nil
		}
		if obs.OccurredAt.IsZero() {
			return Outcome{}, fmt.Errorf("detect: multi-stage needs occurred_at")
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.failures[obs.Auth.Principal] = append(r.failures[obs.Auth.Principal], stageFailure{at: obs.OccurredAt, id: event.GetId()})
		return Outcome{}, nil
	case identobs.EventTypeIdentityActivity:
		obs, err := identobs.Parse(event)
		if err != nil {
			return Outcome{}, fmt.Errorf("detect: multi-stage: %w", err)
		}
		if obs.Identity.Action != "role_change" && obs.Identity.Action != "permission_change" {
			return Outcome{}, nil
		}
		if obs.OccurredAt.IsZero() {
			return Outcome{}, fmt.Errorf("detect: multi-stage needs occurred_at")
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		kept := r.failures[obs.Identity.Principal][:0]
		for _, f := range r.failures[obs.Identity.Principal] {
			d := obs.OccurredAt.Sub(f.at)
			if d >= 0 && d <= r.window {
				kept = append(kept, f)
			}
		}
		r.failures[obs.Identity.Principal] = kept
		if len(kept) < r.threshold {
			return Outcome{}, nil
		}
		ids := make([]string, 0, len(kept)+1)
		for _, f := range kept {
			ids = append(ids, f.id)
		}
		sort.Strings(ids)
		setKey := joinStageIDs(ids)
		if r.firedSets[obs.Identity.Principal] == setKey {
			return Outcome{}, nil
		}
		r.firedSets[obs.Identity.Principal] = setKey
		ids = append(ids, event.GetId())
		sort.Strings(ids)
		return Outcome{
			Matched:  true,
			Severity: event.GetSeverity(),
			Title:    "Multi-stage correlated activity observed",
			Detail: fmt.Sprintf("%d auth failures for principal %q followed by privilege change within %v (threshold %d)",
				len(kept), obs.Identity.Principal, r.window, r.threshold),
			EventIDs: ids,
			Attrs: map[string]string{
				"threshold": fmt.Sprint(r.threshold),
				"window":    r.window.String(),
				"count":     fmt.Sprint(len(kept)),
				"principal": obs.Identity.Principal,
			},
		}, nil
	default:
		return Outcome{}, nil
	}
}

func joinStageIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += "\x1f"
		}
		out += id
	}
	return out
}

// ---------------------------------------------------------------------------
// Rule T3: detection-rule error burst (batch over recorded engine errors).
// ---------------------------------------------------------------------------

// ErrorBursts groups one rule's recorded error events into deterministic
// bursts: at least threshold errors where each error lands within window
// of the burst start. Simulation mirrors netWindow streaming semantics
// (fire once, re-arm when the count drops), so batch and streaming agree.
// Bursts return oldest-first; event ids inside each burst are sorted.
func ErrorBursts(errs []ErrorEvent, ruleID string, threshold int, window time.Duration) [][]ErrorEvent {
	var mine []ErrorEvent
	for _, e := range errs {
		if e.RuleID == ruleID {
			mine = append(mine, e)
		}
	}
	sort.Slice(mine, func(i, j int) bool {
		if mine[i].At.Equal(mine[j].At) {
			return mine[i].EventID < mine[j].EventID
		}
		return mine[i].At.Before(mine[j].At)
	})
	var bursts [][]ErrorEvent
	w := &netWindow{}
	fired := false
	for _, e := range mine {
		for len(w.entries) > 0 && e.At.Sub(w.entries[0].at) > window {
			w.entries = w.entries[1:]
		}
		w.entries = append(w.entries, netWindowEntry{at: e.At, id: e.EventID, severity: e.Severity})
		if len(w.entries) < threshold {
			fired = false
			continue
		}
		if fired {
			continue
		}
		fired = true
		burst := make([]ErrorEvent, 0, len(w.entries))
		byID := map[string]ErrorEvent{}
		for _, m := range mine {
			byID[m.EventID] = m
		}
		for _, en := range w.entries {
			if orig, ok := byID[en.id]; ok {
				burst = append(burst, orig)
			}
		}
		sort.Slice(burst, func(i, j int) bool { return burst[i].EventID < burst[j].EventID })
		bursts = append(bursts, burst)
	}
	if bursts == nil {
		bursts = [][]ErrorEvent{}
	}
	return bursts
}

// RuleErrorBurstRule builds engine-health detections from recorded rule
// errors. It implements Rule so metadata and registries treat it like any
// rule, but per-event Evaluate is intentionally a no-op: error bursts are
// aggregates, and firing per event would misattribute them. Use
// Detections() for the explicit batch computation. Do NOT register this
// in the hot path expecting per-event matches.
type RuleErrorBurstRule struct {
	eng       *Engine
	threshold int
	window    time.Duration
}

// NewRuleErrorBurstRule validates its inputs; nil engine and non-positive
// threshold/window are construction errors.
func NewRuleErrorBurstRule(eng *Engine, threshold int, window time.Duration) (*RuleErrorBurstRule, error) {
	if eng == nil {
		return nil, fmt.Errorf("detect: rule-error-burst engine is nil")
	}
	if err := checkBurstParams(threshold, window, "rule-error-burst"); err != nil {
		return nil, err
	}
	return &RuleErrorBurstRule{eng: eng, threshold: threshold, window: window}, nil
}

func (RuleErrorBurstRule) ID() string      { return "detection-rule-error-burst" }
func (RuleErrorBurstRule) Version() string { return "1" }
func (RuleErrorBurstRule) Name() string    { return "Detection rule error burst" }
func (RuleErrorBurstRule) Description() string {
	return "Aggregates repeated evaluation errors of one rule inside a window. " +
		"Engine-health signal; never a statement about any monitored target."
}

func (RuleErrorBurstRule) Evaluate(*v1.TelemetryEvent) (Outcome, error) {
	return Outcome{}, nil
}

// Detections computes one contract-valid Detection per failing rule with
// a threshold-meeting burst, using the existing builder (deterministic
// ids, severity inherited as the burst peak, confidence 0.0).
func (r *RuleErrorBurstRule) Detections(now func() time.Time) ([]*v1.Detection, error) {
	if now == nil || now().IsZero() {
		return nil, fmt.Errorf("detect: rule-error-burst needs a valid clock")
	}
	byRule := map[string][]ErrorEvent{}
	for _, h := range r.eng.Health() {
		if h.Errors == 0 {
			continue
		}
		byRule[h.RuleID] = r.eng.RuleErrors(h.RuleID)
	}
	ruleIDs := make([]string, 0, len(byRule))
	for id := range byRule {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	var out []*v1.Detection
	for _, id := range ruleIDs {
		for _, burst := range ErrorBursts(byRule[id], id, r.threshold, r.window) {
			ids := make([]string, 0, len(burst))
			peak := v1.Severity_SEVERITY_INFO
			for _, e := range burst {
				ids = append(ids, e.EventID)
				if e.Severity > peak {
					peak = e.Severity
				}
			}
			det, err := BuildDetection(r, Outcome{
				Matched:  true,
				Severity: peak,
				Title:    "Repeated rule evaluation errors observed",
				Detail: fmt.Sprintf("rule %q errored %d times within %v (threshold %d); engine health only",
					id, len(burst), r.window, r.threshold),
				EventIDs: ids,
				Attrs: map[string]string{
					"failing_rule": id,
					"threshold":    fmt.Sprint(r.threshold),
					"window":       r.window.String(),
					"count":        fmt.Sprint(len(burst)),
				},
			}, now())
			if err != nil {
				return nil, err
			}
			out = append(out, det)
		}
	}
	return out, nil
}
