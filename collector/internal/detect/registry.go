// Rule registry: register, get, list, evaluate. Deterministic order
// (registration order). No dynamic loading, no marketplace, no remote rules.
package detect

import (
	"errors"
	"fmt"
	"sync"

	v1 "blueveil/collector/internal/contract/v1"
)

// ErrRuleRegistry marks registration failures (duplicates, invalid rules).
var ErrRuleRegistry = errors.New("detect: rule registry failure")

// Registry holds rules by stable id. Rules are enabled by default;
// Disable takes a rule out of evaluation without unregistering it.
// All methods are safe for concurrent use (registration races evaluation
// without this guard).
type Registry struct {
	mu       sync.RWMutex
	order    []Rule
	byID     map[string]Rule
	disabled map[string]bool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]Rule{}, disabled: map[string]bool{}}
}

// Register adds a rule; nil rules, empty ids and duplicate ids are rejected.
func (r *Registry) Register(rule Rule) error {
	if rule == nil {
		return fmt.Errorf("%w: rule is nil", ErrRuleRegistry)
	}
	if rule.ID() == "" {
		return fmt.Errorf("%w: rule id is empty", ErrRuleRegistry)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID = map[string]Rule{}
	}
	if r.disabled == nil {
		r.disabled = map[string]bool{}
	}
	if _, exists := r.byID[rule.ID()]; exists {
		return fmt.Errorf("%w: duplicate rule id %q", ErrRuleRegistry, rule.ID())
	}
	r.byID[rule.ID()] = rule
	r.order = append(r.order, rule)
	return nil
}

// Get returns the rule for id.
func (r *Registry) Get(id string) (Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.byID[id]
	return rule, ok
}

// List returns rules in registration order.
func (r *Registry) List() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rule, len(r.order))
	copy(out, r.order)
	return out
}

// Disable takes a registered rule out of evaluation. Unknown ids are
// rejected; disabling is explicit and reversible via Enable.
func (r *Registry) Disable(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return fmt.Errorf("%w: unknown rule id %q", ErrRuleRegistry, id)
	}
	r.disabled[id] = true
	return nil
}

// Enable returns a rule to evaluation. Unknown ids are rejected.
func (r *Registry) Enable(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return fmt.Errorf("%w: unknown rule id %q", ErrRuleRegistry, id)
	}
	delete(r.disabled, id)
	return nil
}

// IsEnabled reports whether a registered rule evaluates. Unregistered ids
// report false (never silently enabled).
func (r *Registry) IsEnabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.byID[id]; !ok {
		return false
	}
	return !r.disabled[id]
}

// Match pairs a rule with its outcome for one event.
type Match struct {
	Rule    Rule
	Outcome Outcome
}

// EvaluateAll runs every enabled rule in order. The first rule error
// aborts the whole evaluation: an error must never degrade into a silent
// no-match (that would be a false negative by construction). Disabled
// rules are skipped without evaluation.
func (r *Registry) EvaluateAll(event *v1.TelemetryEvent) ([]Match, error) {
	var matches []Match
	for _, rule := range r.order {
		if r.disabled[rule.ID()] {
			continue
		}
		outcome, err := rule.Evaluate(event)
		if err != nil {
			return nil, fmt.Errorf("detect: rule %q evaluation: %w", rule.ID(), err)
		}
		if outcome.Matched {
			matches = append(matches, Match{Rule: rule, Outcome: outcome})
		}
	}
	return matches, nil
}
