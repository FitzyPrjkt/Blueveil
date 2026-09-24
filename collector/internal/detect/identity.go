// Identity, authentication & data-security detections (Step 13E). Four
// deterministic rules over identity.activity / auth.activity /
// data.activity, registered with the existing engine — no second engine,
// no risk scores, no compromise claims. A match describes the observed
// condition precisely; it is never labeled breach, attack, or takeover.
package detect

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/identobs"
)

// ---------------------------------------------------------------------------
// Rule J1: identity privilege change (stateless).
// ---------------------------------------------------------------------------

// IdentityPrivilegeChangeRule fires on source-declared role/permission
// changes. Meaning: the source reported a privilege transition. NOT proof
// of escalation, compromise, or administrator status — a username alone
// never matches.
type IdentityPrivilegeChangeRule struct{}

func (IdentityPrivilegeChangeRule) ID() string      { return "identity-privilege-change" }
func (IdentityPrivilegeChangeRule) Version() string { return "1" }
func (IdentityPrivilegeChangeRule) Name() string    { return "Identity privilege change" }
func (IdentityPrivilegeChangeRule) Description() string {
	return "Matches identity.activity with action role_change or permission_change. " +
		"Repeats the source's declared change; not proof of escalation or compromise."
}

func (IdentityPrivilegeChangeRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != identobs.EventTypeIdentityActivity {
		return Outcome{}, nil
	}
	obs, err := identobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: privilege-change: %w", err)
	}
	if obs.Identity.Action != "role_change" && obs.Identity.Action != "permission_change" {
		return Outcome{}, nil
	}
	target := obs.Identity.Target
	if target == "" {
		target = obs.Identity.Role
	}
	return Outcome{
		Matched:  true,
		Severity: event.GetSeverity(),
		Title:    "Identity privilege change observed",
		Detail: fmt.Sprintf("source %q reported %s for principal %q targeting %q (event %s)",
			event.GetSource(), obs.Identity.Action, obs.Identity.Principal, target, event.GetId()),
		EventIDs: []string{event.GetId()},
		Attrs: map[string]string{
			"match":     "action=" + obs.Identity.Action,
			"principal": obs.Identity.Principal,
			"target":    target,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule J2: authentication failure burst (stateful, per principal+source).
// ---------------------------------------------------------------------------

// IdentAuthFailureBurstRule fires once when one principal accumulates
// threshold explicit auth.outcome=failure events inside window (event
// time). Only auth.activity with outcome failure counts — an HTTP 401 is
// a different event type and never feeds this window.
type IdentAuthFailureBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

// NewIdentAuthFailureBurstRule validates parameters; invalid is a
// construction error, never a silent default.
func NewIdentAuthFailureBurstRule(threshold int, window time.Duration, clock func() time.Time) (*IdentAuthFailureBurstRule, error) {
	if err := checkBurstParams(threshold, window, "ident-auth-failure-burst"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: ident-auth-failure-burst clock is nil")
	}
	return &IdentAuthFailureBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *IdentAuthFailureBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *IdentAuthFailureBurstRule) ID() string      { return "ident-auth-failure-burst" }
func (r *IdentAuthFailureBurstRule) Version() string { return "1" }
func (r *IdentAuthFailureBurstRule) Name() string    { return "Authentication failure burst" }
func (r *IdentAuthFailureBurstRule) Description() string {
	return "Matches when one principal accumulates threshold explicit auth failures inside window. " +
		"Repeated failures observed; not a brute-force confirmation."
}

func (r *IdentAuthFailureBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != identobs.EventTypeAuthActivity {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "ident-auth-failure-burst"); err != nil {
		return Outcome{}, err
	}
	obs, err := identobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: ident-auth-failure-burst: %w", err)
	}
	if obs.Auth.Outcome != "failure" {
		return Outcome{}, nil
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: ident-auth-failure-burst needs occurred_at")
	}
	key := obs.Auth.Principal + "\x1f" + event.GetSource()
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.windows[key]
	if !ok {
		w = &netWindow{}
		r.windows[key] = w
	}
	if !w.observe(at, event.GetId(), event.GetSeverity(), r.window, r.threshold) {
		return Outcome{}, nil
	}
	return Outcome{
		Matched:  true,
		Severity: w.peak(),
		Title:    "Repeated authentication failures observed",
		Detail: fmt.Sprintf("%d auth failures for principal %q within %v (threshold %d)",
			len(w.entries), obs.Auth.Principal, r.window, r.threshold),
		EventIDs: w.ids(),
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(w.entries)),
			"principal": obs.Auth.Principal,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule J3: authentication denied burst (stateful, per principal+source).
// ---------------------------------------------------------------------------

// IdentAuthDeniedBurstRule fires once when one principal accumulates
// threshold explicit auth.outcome=denied events inside window. Failure and
// denial are separate windows: failures never feed denial and vice versa.
type IdentAuthDeniedBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

// NewIdentAuthDeniedBurstRule validates parameters; invalid is a
// construction error, never a silent default.
func NewIdentAuthDeniedBurstRule(threshold int, window time.Duration, clock func() time.Time) (*IdentAuthDeniedBurstRule, error) {
	if err := checkBurstParams(threshold, window, "ident-auth-denied-burst"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: ident-auth-denied-burst clock is nil")
	}
	return &IdentAuthDeniedBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *IdentAuthDeniedBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *IdentAuthDeniedBurstRule) ID() string      { return "ident-auth-denied-burst" }
func (r *IdentAuthDeniedBurstRule) Version() string { return "1" }
func (r *IdentAuthDeniedBurstRule) Name() string    { return "Authentication denied burst" }
func (r *IdentAuthDeniedBurstRule) Description() string {
	return "Matches when one principal accumulates threshold explicit auth denials inside window. " +
		"Denial observed; not an unauthorized-attacker confirmation."
}

func (r *IdentAuthDeniedBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != identobs.EventTypeAuthActivity {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "ident-auth-denied-burst"); err != nil {
		return Outcome{}, err
	}
	obs, err := identobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: ident-auth-denied-burst: %w", err)
	}
	if obs.Auth.Outcome != "denied" {
		return Outcome{}, nil
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: ident-auth-denied-burst needs occurred_at")
	}
	key := obs.Auth.Principal + "\x1f" + event.GetSource()
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.windows[key]
	if !ok {
		w = &netWindow{}
		r.windows[key] = w
	}
	if !w.observe(at, event.GetId(), event.GetSeverity(), r.window, r.threshold) {
		return Outcome{}, nil
	}
	ids := w.ids()
	sort.Strings(ids)
	return Outcome{
		Matched:  true,
		Severity: w.peak(),
		Title:    "Repeated authentication denials observed",
		Detail: fmt.Sprintf("%d auth denials for principal %q within %v (threshold %d)",
			len(w.entries), obs.Auth.Principal, r.window, r.threshold),
		EventIDs: ids,
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(w.entries)),
			"principal": obs.Auth.Principal,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule J4: sensitive-data policy violation (stateless, explicit policy).
// ---------------------------------------------------------------------------

// SensitiveDataPolicy matches data observations against explicit operator
// policy. Empty classification/action lists mean "any". There are no
// built-in sensitive filenames: a read is not a breach and an export is
// not exfiltration unless the policy explicitly matches.
type SensitiveDataPolicy struct {
	Classifications []string
	Actions         []string
	Principals      []string
	Resources       []string
	Severity        v1.Severity
	Label           string
}

// SensitiveDataPolicyRule fires when a data observation matches an
// explicit policy entry. A policy violation remains a policy violation.
type SensitiveDataPolicyRule struct {
	classifications map[string]bool
	actions         map[string]bool
	principals      map[string]bool
	resources       map[string]bool
	severity        v1.Severity
	label           string
}

// NewSensitiveDataPolicyRule validates the whole policy up front: unknown
// data action, unspecified severity, or unlabeled policy is a construction
// error.
func NewSensitiveDataPolicyRule(p SensitiveDataPolicy) (*SensitiveDataPolicyRule, error) {
	if strings.TrimSpace(p.Label) == "" {
		return nil, fmt.Errorf("detect: data policy label required")
	}
	if p.Severity == v1.Severity_SEVERITY_UNSPECIFIED {
		return nil, fmt.Errorf("detect: data policy explicit severity required")
	}
	if _, known := v1.Severity_name[int32(p.Severity)]; !known {
		return nil, fmt.Errorf("detect: data policy unknown severity %v", p.Severity)
	}
	actions := map[string]bool{}
	for _, a := range p.Actions {
		low := strings.ToLower(strings.TrimSpace(a))
		switch low {
		case "read", "write", "delete", "export", "access", "permission_change":
		default:
			return nil, fmt.Errorf("detect: data policy unknown action %q", a)
		}
		actions[low] = true
	}
	lower := func(field string, in []string) (map[string]bool, error) {
		out := map[string]bool{}
		for _, s := range in {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				return nil, fmt.Errorf("detect: data policy empty %s entry (refusing over-broad match)", field)
			}
			out[s] = true
		}
		return out, nil
	}
	classifications, err := lower("classification", p.Classifications)
	if err != nil {
		return nil, err
	}
	principals, err := lower("principal", p.Principals)
	if err != nil {
		return nil, err
	}
	resources, err := lower("resource", p.Resources)
	if err != nil {
		return nil, err
	}
	return &SensitiveDataPolicyRule{
		classifications: classifications,
		actions:         actions,
		principals:      principals,
		resources:       resources,
		severity:        p.Severity,
		label:           strings.TrimSpace(p.Label),
	}, nil
}

func (SensitiveDataPolicyRule) ID() string      { return "sensitive-data-policy-violation" }
func (SensitiveDataPolicyRule) Version() string { return "1" }
func (SensitiveDataPolicyRule) Name() string    { return "Sensitive-data policy violation" }
func (SensitiveDataPolicyRule) Description() string {
	return "Matches data.activity observations against explicit operator policy. " +
		"A policy violation only; not a data breach."
}

func (r *SensitiveDataPolicyRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != identobs.EventTypeDataActivity {
		return Outcome{}, nil
	}
	obs, err := identobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: data-policy: %w", err)
	}
	if len(r.classifications) > 0 && !r.classifications[obs.Data.Classification] {
		return Outcome{}, nil
	}
	if len(r.actions) > 0 && !r.actions[obs.Data.Action] {
		return Outcome{}, nil
	}
	if len(r.principals) > 0 && !r.principals[strings.ToLower(obs.Data.Principal)] {
		return Outcome{}, nil
	}
	if len(r.resources) > 0 && !r.resources[strings.ToLower(obs.Data.Resource)] {
		return Outcome{}, nil
	}
	match := fmt.Sprintf("classification=%s,action=%s", obs.Data.Classification, obs.Data.Action)
	return Outcome{
		Matched:  true,
		Severity: r.severity,
		Title:    "Sensitive-data access policy violation",
		Detail: fmt.Sprintf("source %q observed %s on %q by %q matching policy %q (event %s)",
			event.GetSource(), obs.Data.Action, obs.Data.Resource, obs.Data.Principal,
			r.label, event.GetId()),
		EventIDs: []string{event.GetId()},
		Attrs: map[string]string{
			"policy": r.label,
			"match":  match,
		},
	}, nil
}
