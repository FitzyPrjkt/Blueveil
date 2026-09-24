// Package detect is the rule-based detection layer: canonical telemetry in,
// contract-valid Detection and Alert objects out. Observation and decision
// data only — a match never authorizes, blocks, isolates, or executes
// anything. Response belongs to a later phase.
package detect

import (
	v1 "blueveil/collector/internal/contract/v1"
)

// Outcome is one rule's answer about one event.
type Outcome struct {
	Matched bool
	// Severity is the rule-declared severity for this match, always inherited
	// from (never above) the contributing telemetry's own rating.
	Severity v1.Severity
	// Confidence is 0.0 for boolean rules: no probabilistic estimate exists,
	// and none is fabricated. Detections carry attributes
	// blueveil.confidence_basis documenting this. Future probabilistic rules
	// will populate a derived value with their derivation documented.
	Confidence float64
	// Title is a short human label for the match.
	Title string
	// Detail explains WHY this matched, citing observed values only.
	Detail string
	// EventIDs are the contributing telemetry ids (builder sorts a copy).
	EventIDs []string
	// Attrs carries rule-specific facts (thresholds, counts). Rules must not
	// use blueveil.* keys: that namespace belongs to the pipeline builders.
	Attrs map[string]string
}

// Rule answers match/no-match for one telemetry event. Implementations must
// be deterministic: same event and same rule state yield the same outcome.
// Rules never emit actions; a match is data, not authorization.
type Rule interface {
	// ID is the stable rule identifier, e.g. "waf-block-high-severity".
	ID() string
	// Version pins the rule semantics; behavior changes bump it.
	Version() string
	// Name is the human rule name recorded on every Detection.
	Name() string
	// Description documents what the condition means AND its limits
	// (in particular: a match is not proof of attack).
	Description() string
	// Evaluate returns the outcome or an error. Errors are loud: the engine
	// aborts the event on rule error rather than reporting a false no-match.
	Evaluate(event *v1.TelemetryEvent) (Outcome, error)
}
