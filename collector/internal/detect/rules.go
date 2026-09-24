// Initial rules (3). Each evaluates entirely from TelemetryEvent fields,
// carries a stable id + version, and documents its own limits. Severity is
// always inherited from the source rating — Blueveil never escalates above
// what the telemetry claimed. Confidence stays 0.0 (unmeasured, documented)
// rather than a fabricated probability.
package detect

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

// errNilEvent keeps nil handling uniform across rules.
var errNilEvent = errors.New("detect: rule received nil event")

// ---------------------------------------------------------------------------
// Rule 1: high-severity blocked request (stateless).
// ---------------------------------------------------------------------------

// BlockHighSeverityRule fires when a source reports refusing a request it
// rated HIGH or CRITICAL. Meaning: refused traffic worth analyst review.
// NOT proof of attack — the source saw it and refused it.
type BlockHighSeverityRule struct{}

func (BlockHighSeverityRule) ID() string      { return "waf-block-high-severity" }
func (BlockHighSeverityRule) Version() string { return "1" }
func (BlockHighSeverityRule) Name() string    { return "High-severity blocked request" }
func (BlockHighSeverityRule) Description() string {
	return "Matches event_type waf.request_blocked with source severity HIGH or CRITICAL. " +
		"Indicates refused traffic the source itself rated serious; not proof of attack."
}

func (BlockHighSeverityRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	sev := event.GetSeverity()
	if event.GetEventType() != "waf.request_blocked" ||
		(sev != v1.Severity_SEVERITY_HIGH && sev != v1.Severity_SEVERITY_CRITICAL) {
		return Outcome{}, nil
	}
	return Outcome{
		Matched:  true,
		Severity: sev,
		Title:    "High-severity blocked request observed",
		Detail: fmt.Sprintf("source %q reported event_type %q with severity %s for asset %q (event %s)",
			event.GetSource(), event.GetEventType(), sev, event.GetAssetId(), event.GetId()),
		EventIDs: []string{event.GetId()},
		Attrs:    map[string]string{"match": "event_type=waf.request_blocked,severity>=HIGH"},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule 2: blocked-request burst (stateful, local window per asset).
// ---------------------------------------------------------------------------

type burstEntry struct {
	at       time.Time
	id       string
	severity v1.Severity
}

type assetWindow struct {
	entries []burstEntry
	fired   bool
}

// BlockBurstRule fires once when at least threshold blocked requests for one
// asset occur within window (windowed on event occurred_at, deterministic in
// input order). It stays silent while the window remains at/above threshold
// and re-arms when the count drops below. Aggregation signal, not attack
// proof. State is local and explicit; restart clears it (documented limit).
type BlockBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time // reserved for processing-time guards; windows use event time
	mu        sync.Mutex
	windows   map[string]*assetWindow
}

// NewBlockBurstRule validates its parameters: non-positive threshold/window
// or nil clock is a construction error, never a silent default.
func NewBlockBurstRule(threshold int, window time.Duration, clock func() time.Time) (*BlockBurstRule, error) {
	if threshold <= 0 {
		return nil, fmt.Errorf("detect: burst threshold must be > 0, got %d", threshold)
	}
	if window <= 0 {
		return nil, fmt.Errorf("detect: burst window must be > 0, got %v", window)
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: burst clock is nil")
	}
	return &BlockBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*assetWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *BlockBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *BlockBurstRule) ID() string      { return "waf-block-burst" }
func (r *BlockBurstRule) Version() string { return "1" }
func (r *BlockBurstRule) Name() string    { return "Blocked-request burst" }
func (r *BlockBurstRule) Description() string {
	return "Matches when one asset accumulates threshold blocked requests inside window. " +
		"Counts refused traffic; says nothing about attacker intent or success."
}

func (r *BlockBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != "waf.request_blocked" {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "burst"); err != nil {
		return Outcome{}, err
	}
	at := event.GetOccurredAt().AsTime()
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: burst needs event occurred_at")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.windows[event.GetAssetId()]
	if !ok {
		w = &assetWindow{}
		r.windows[event.GetAssetId()] = w
	}
	cutoff := at.Add(-r.window)
	kept := w.entries[:0]
	for _, e := range w.entries {
		if !e.at.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	w.entries = kept
	w.entries = append(w.entries, burstEntry{at: at, id: event.GetId(), severity: event.GetSeverity()})
	if len(w.entries) < r.threshold {
		w.fired = false
		return Outcome{}, nil
	}
	if w.fired {
		return Outcome{}, nil
	}
	w.fired = true

	ids := make([]string, 0, len(w.entries))
	peak := v1.Severity_SEVERITY_INFO
	for _, e := range w.entries {
		ids = append(ids, e.id)
		if e.severity > peak {
			peak = e.severity
		}
	}
	sort.Strings(ids)
	return Outcome{
		Matched:  true,
		Severity: peak,
		Title:    "Blocked-request burst observed",
		Detail: fmt.Sprintf("%d blocked requests for asset %q within %v (threshold %d)",
			len(w.entries), event.GetAssetId(), r.window, r.threshold),
		EventIDs: ids,
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(w.entries)),
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule 3: source-declared critical (stateless).
// ---------------------------------------------------------------------------

// SourceCriticalRule fires on any telemetry the source itself rated
// CRITICAL, regardless of type. It inherits the source rating; Blueveil
// adds no judgment of its own.
type SourceCriticalRule struct{}

func (SourceCriticalRule) ID() string      { return "source-declared-critical" }
func (SourceCriticalRule) Version() string { return "1" }
func (SourceCriticalRule) Name() string    { return "Source-declared critical event" }
func (SourceCriticalRule) Description() string {
	return "Matches any event with source severity CRITICAL. " +
		"Repeats the source's own highest rating; not an independent assessment."
}

func (SourceCriticalRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetSeverity() != v1.Severity_SEVERITY_CRITICAL {
		return Outcome{}, nil
	}
	return Outcome{
		Matched:  true,
		Severity: v1.Severity_SEVERITY_CRITICAL,
		Title:    "Source-declared critical event observed",
		Detail: fmt.Sprintf("source %q rated event %q (type %q, asset %q) CRITICAL",
			event.GetSource(), event.GetId(), event.GetEventType(), event.GetAssetId()),
		EventIDs: []string{event.GetId()},
		Attrs:    map[string]string{"match": "severity=CRITICAL"},
	}, nil
}
