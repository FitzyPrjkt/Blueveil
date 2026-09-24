// Application-layer defensive detections (13C). Reuses existing engine;
// no second engine, no vulnerability claims.
package detect

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/httpobs"
)

// ---------------------------------------------------------------------------
// HTTP 5xx burst (stateful, per asset+route).
// ---------------------------------------------------------------------------

type HTTPErrorBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

func NewHTTPErrorBurstRule(threshold int, window time.Duration, clock func() time.Time) (*HTTPErrorBurstRule, error) {
	if err := checkBurstParams(threshold, window, "http-error-burst"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: http-error-burst clock is nil")
	}
	return &HTTPErrorBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *HTTPErrorBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *HTTPErrorBurstRule) ID() string      { return "http-error-burst" }
func (r *HTTPErrorBurstRule) Version() string { return "1" }
func (r *HTTPErrorBurstRule) Name() string    { return "HTTP error burst" }
func (r *HTTPErrorBurstRule) Description() string {
	return "Matches when one asset/route accumulates threshold HTTP 5xx responses inside window. " +
		"Indicates instability; not a vulnerability."
}

func (r *HTTPErrorBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != httpobs.EventTypeHTTPRequest {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "http-error-burst"); err != nil {
		return Outcome{}, err
	}
	obs, err := httpobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: http-error-burst: %w", err)
	}
	if !obs.HasStatus || obs.StatusCode < 500 || obs.StatusCode > 599 {
		return Outcome{}, nil
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: http-error-burst needs occurred_at")
	}
	key := event.GetAssetId() + "\x1f" + obs.Host + "\x1f" + obs.Route
	route := obs.Route
	if route == "" {
		route = obs.Path
		key = event.GetAssetId() + "\x1f" + obs.Host + "\x1f" + obs.Path
	}
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
		Title:    "HTTP error burst observed",
		Detail:   fmt.Sprintf("%d HTTP 5xx for %s %s within %v (threshold %d)", len(w.entries), obs.Host, route, r.window, r.threshold),
		EventIDs: w.ids(),
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(w.entries)),
			"host":      obs.Host,
			"route":     obs.Route,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Auth failure burst (stateful, per asset).
// ---------------------------------------------------------------------------

type AuthFailureBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

func NewAuthFailureBurstRule(threshold int, window time.Duration, clock func() time.Time) (*AuthFailureBurstRule, error) {
	if err := checkBurstParams(threshold, window, "auth-failure-burst"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: auth-failure-burst clock is nil")
	}
	return &AuthFailureBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *AuthFailureBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *AuthFailureBurstRule) ID() string      { return "auth-failure-burst" }
func (r *AuthFailureBurstRule) Version() string { return "1" }
func (r *AuthFailureBurstRule) Name() string    { return "Authentication failure burst" }
func (r *AuthFailureBurstRule) Description() string {
	return "Matches when explicitly-declared authentication failures repeat past threshold inside window. " +
		"Counts source-declared auth_outcome=failure only."
}

func (r *AuthFailureBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != httpobs.EventTypeHTTPRequest {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "auth-failure-burst"); err != nil {
		return Outcome{}, err
	}
	obs, err := httpobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: auth-failure-burst: %w", err)
	}
	if obs.AuthOutcome != "failure" {
		return Outcome{}, nil
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: auth-failure-burst needs occurred_at")
	}
	key := event.GetAssetId()
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
		Title:    "Authentication failure burst observed",
		Detail:   fmt.Sprintf("%d auth failures for asset %q within %v (threshold %d)", len(w.entries), event.GetAssetId(), r.window, r.threshold),
		EventIDs: ids,
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(w.entries)),
		},
	}, nil
}

// ---------------------------------------------------------------------------
// App policy violation (stateless, explicit).
// ---------------------------------------------------------------------------

type AppPolicy struct {
	DisallowedMethods      []string
	DisallowedRoutes       []string
	DisallowedContentTypes []string
	// Severity rates every violation of this policy. It is required and
	// explicit: the rule invents no judgment of its own.
	Severity v1.Severity
}

type AppPolicyViolationRule struct {
	methods  map[string]bool
	routes   map[string]bool
	cts      map[string]bool
	severity v1.Severity
}

var validHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

func NewAppPolicyViolationRule(p AppPolicy) (*AppPolicyViolationRule, error) {
	if len(p.DisallowedMethods) == 0 && len(p.DisallowedRoutes) == 0 && len(p.DisallowedContentTypes) == 0 {
		return nil, fmt.Errorf("detect: app policy must have at least one disallowed entry")
	}
	if p.Severity == v1.Severity_SEVERITY_UNSPECIFIED {
		return nil, fmt.Errorf("detect: app policy explicit severity required")
	}
	if _, known := v1.Severity_name[int32(p.Severity)]; !known {
		return nil, fmt.Errorf("detect: app policy unknown severity %v", p.Severity)
	}
	methods := map[string]bool{}
	for _, m := range p.DisallowedMethods {
		up := strings.ToUpper(strings.TrimSpace(m))
		if up == "" {
			return nil, fmt.Errorf("detect: empty disallowed method")
		}
		if !validHTTPMethods[up] {
			return nil, fmt.Errorf("detect: invalid disallowed method %q", m)
		}
		methods[up] = true
	}
	routes := map[string]bool{}
	for _, r := range p.DisallowedRoutes {
		trim := strings.TrimSpace(r)
		if trim == "" {
			return nil, fmt.Errorf("detect: empty disallowed route")
		}
		routes[trim] = true
	}
	cts := map[string]bool{}
	for _, c := range p.DisallowedContentTypes {
		low := strings.ToLower(strings.TrimSpace(c))
		if low == "" {
			return nil, fmt.Errorf("detect: empty disallowed content type")
		}
		cts[low] = true
	}
	return &AppPolicyViolationRule{methods: methods, routes: routes, cts: cts, severity: p.Severity}, nil
}

func (r *AppPolicyViolationRule) ID() string      { return "app-policy-violation" }
func (r *AppPolicyViolationRule) Version() string { return "1" }
func (r *AppPolicyViolationRule) Name() string    { return "Application policy violation" }
func (r *AppPolicyViolationRule) Description() string {
	return "Matches http.request observations against explicit disallowed methods/routes/content types. " +
		"Repeats operator policy; not a vulnerability."
}

func (r *AppPolicyViolationRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != httpobs.EventTypeHTTPRequest {
		return Outcome{}, nil
	}
	obs, err := httpobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: app-policy: %w", err)
	}
	hit := ""
	if r.methods[obs.Method] {
		hit = "method=" + obs.Method
	} else if r.routes[obs.Path] || r.routes[obs.Route] {
		hit = "route=" + obs.Path
		if obs.Route != "" {
			hit = "route=" + obs.Route
		}
	} else if r.cts[obs.ContentType] {
		hit = "content_type=" + obs.ContentType
	}
	if hit == "" {
		return Outcome{}, nil
	}
	return Outcome{
		Matched:  true,
		Severity: r.severity,
		Title:    "Application policy violation observed",
		Detail:   fmt.Sprintf("policy violation %s for %s %s (event %s)", hit, obs.Method, obs.Path, event.GetId()),
		EventIDs: []string{event.GetId()},
		Attrs:    map[string]string{"policy": hit},
	}, nil
}
