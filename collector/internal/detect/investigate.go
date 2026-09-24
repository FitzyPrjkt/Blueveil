// Investigative derived signals (Step 13G). Three rules with precise,
// non-attributive wording:
//
// H1 fires when one principal shows explicit activity in at least
// threshold distinct telemetry domains inside a window. Meaning:
// "cross-domain principal activity observed" — never account compromise.
//
// H2 fires when an explicitly linked net → application → endpoint/server
// stage sequence shares one asset/correlation identifier in order inside
// a window. Linkage comes from identifiers on the events, never from
// timestamps. Meaning: "multi-stage asset timeline observed".
//
// H3 files one detection per evidence item that fails SHA-256 Verify.
// Per-event Evaluate is an explicit no-op (mirroring the T3 precedent):
// integrity is a batch property over stored evidence. Meaning:
// "evidence integrity verification failed".
package detect

import (
	"fmt"
	"sort"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/investigate"
)

// ---------------------------------------------------------------------------
// Rule H1: cross-domain principal activity (stateful, per principal).
// ---------------------------------------------------------------------------

// domainOf maps event types to investigation domains. Unknown types yield
// "" and never count toward any principal's domain set.
func domainOf(eventType string) string {
	switch eventType {
	case "auth.activity":
		return "authentication"
	case "identity.activity":
		return "identity"
	case "data.activity":
		return "data"
	case "net.connection":
		return "network"
	case "http.request", "waf.request_blocked", "waf.request_allowed":
		return "application"
	case "endpoint.activity":
		return "endpoint"
	case "server.activity":
		return "server"
	case "container.activity":
		return "container"
	case "cloud.activity":
		return "cloud"
	default:
		return ""
	}
}

type domainSight struct {
	at       time.Time
	id       string
	severity v1.Severity
}

// CrossDomainPrincipalRule fires once when one principal accumulates
// activity in threshold distinct domains within window (event time). It
// stays silent while the set remains at/above threshold and re-arms when
// the set drops below — the same fire-once/re-arm contract as netWindow.
type CrossDomainPrincipalRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	seen      map[string]map[string]domainSight
	fired     map[string]bool
}

// NewCrossDomainPrincipalRule validates parameters: threshold < 2 can
// never mean "cross-domain"; non-positive window and nil clock are
// construction errors.
func NewCrossDomainPrincipalRule(threshold int, window time.Duration, clock func() time.Time) (*CrossDomainPrincipalRule, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("detect: cross-domain threshold must be >= 2, got %d", threshold)
	}
	if window <= 0 {
		return nil, fmt.Errorf("detect: cross-domain window must be > 0, got %v", window)
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: cross-domain clock is nil")
	}
	return &CrossDomainPrincipalRule{
		threshold: threshold, window: window, clock: clock,
		seen: map[string]map[string]domainSight{}, fired: map[string]bool{},
	}, nil
}

func (*CrossDomainPrincipalRule) ID() string      { return "repeated-cross-domain-principal-activity" }
func (*CrossDomainPrincipalRule) Version() string { return "1" }
func (*CrossDomainPrincipalRule) Name() string {
	return "Cross-domain principal activity"
}
func (*CrossDomainPrincipalRule) Description() string {
	return "Matches when one principal shows activity in multiple telemetry domains inside a window. " +
		"Observed breadth of activity; not account compromise."
}

// ThresholdWindow exposes live configuration for metadata.
func (r *CrossDomainPrincipalRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}

func (r *CrossDomainPrincipalRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if err := checkNetClock(r.clock, "cross-domain"); err != nil {
		return Outcome{}, err
	}
	domain := domainOf(event.GetEventType())
	principal := investigate.PrincipalOf(event.GetAttributes())
	if domain == "" || principal == "" {
		return Outcome{}, nil
	}
	at := event.GetOccurredAt().AsTime()
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: cross-domain needs occurred_at")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.seen[principal]
	if !ok {
		set = map[string]domainSight{}
		r.seen[principal] = set
	}
	set[domain] = domainSight{at: at, id: event.GetId(), severity: event.GetSeverity()}
	cutoff := at.Add(-r.window)
	for d, s := range set {
		if s.at.Before(cutoff) {
			delete(set, d)
		}
	}
	if len(set) < r.threshold {
		r.fired[principal] = false
		return Outcome{}, nil
	}
	if r.fired[principal] {
		return Outcome{}, nil
	}
	r.fired[principal] = true
	ids := make([]string, 0, len(set))
	peak := v1.Severity_SEVERITY_INFO
	for _, s := range set {
		ids = append(ids, s.id)
		if s.severity > peak {
			peak = s.severity
		}
	}
	sort.Strings(ids)
	doms := make([]string, 0, len(set))
	for d := range set {
		doms = append(doms, d)
	}
	sort.Strings(doms)
	return Outcome{
		Matched:  true,
		Severity: peak,
		Title:    "Cross-domain principal activity observed",
		Detail: fmt.Sprintf("principal %q active in %d domains %v within %v (threshold %d)",
			principal, len(set), doms, r.window, r.threshold),
		EventIDs: ids,
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(set)),
			"principal": principal,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule H2: multi-stage asset timeline (stateful, per linkage key).
// ---------------------------------------------------------------------------

// stageOf maps event types to timeline stages in fixed order.
func stageOf(eventType string) int {
	switch eventType {
	case "net.connection":
		return 1
	case "http.request":
		return 2
	case "endpoint.activity", "server.activity":
		return 3
	default:
		return 0
	}
}

type chainState struct {
	stage int
	ids   []string
	start time.Time
	last  time.Time
	peak  v1.Severity
	fired bool
}

// MultiStageAssetTimelineRule fires once when net → application →
// endpoint/server stages complete in order for one linkage key
// (asset id, else blueveil.correlation_id) inside window. Out-of-order or
// unlinked events never advance a chain. After firing, the chain resets
// so a fresh sequence re-arms deterministically.
type MultiStageAssetTimelineRule struct {
	window time.Duration
	clock  func() time.Time
	mu     sync.Mutex
	chains map[string]*chainState
}

// NewMultiStageAssetTimelineRule validates parameters; the stage order is
// fixed by design, not configuration.
func NewMultiStageAssetTimelineRule(window time.Duration, clock func() time.Time) (*MultiStageAssetTimelineRule, error) {
	if window <= 0 {
		return nil, fmt.Errorf("detect: multi-stage window must be > 0, got %v", window)
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: multi-stage clock is nil")
	}
	return &MultiStageAssetTimelineRule{window: window, clock: clock, chains: map[string]*chainState{}}, nil
}

func (*MultiStageAssetTimelineRule) ID() string      { return "multi-stage-asset-timeline" }
func (*MultiStageAssetTimelineRule) Version() string { return "1" }
func (*MultiStageAssetTimelineRule) Name() string    { return "Multi-stage asset timeline" }
func (*MultiStageAssetTimelineRule) Description() string {
	return "Matches an explicitly linked net → application → endpoint/server stage sequence for one asset. " +
		"Observed linked sequence; ordering is not proof of causality."
}

func linkageOf(e *v1.TelemetryEvent) string {
	// Asset scope is the grouping this rule documents ("sequence for one
	// asset"): stage order + window constrain it, and the key is carried
	// verbatim in Attrs so the grouping is auditable, never causal proof.
	// A correlation id is the fallback when asset scope is absent (asset
	// is contract-required, so this branch is normally unreachable).
	if a := e.GetAssetId(); a != "" {
		return "asset:" + a
	}
	if c := e.GetAttributes()["blueveil.correlation_id"]; c != "" {
		return "corr:" + c
	}
	return ""
}

func (r *MultiStageAssetTimelineRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if err := checkNetClock(r.clock, "multi-stage"); err != nil {
		return Outcome{}, err
	}
	stage := stageOf(event.GetEventType())
	key := linkageOf(event)
	if stage == 0 || key == "" {
		return Outcome{}, nil
	}
	at := event.GetOccurredAt().AsTime()
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: multi-stage needs occurred_at")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.chains[key]
	if !ok {
		ch = &chainState{}
		r.chains[key] = ch
	}
	if ch.stage > 0 && at.Sub(ch.start) > r.window {
		*ch = chainState{}
	}
	switch {
	case stage == 1 && ch.stage == 0:
		*ch = chainState{stage: 1, ids: []string{event.GetId()}, start: at, last: at, peak: event.GetSeverity()}
		return Outcome{}, nil
	case stage == ch.stage+1 && !at.Before(ch.last):
		ch.stage = stage
		ch.ids = append(ch.ids, event.GetId())
		ch.last = at
		if event.GetSeverity() > ch.peak {
			ch.peak = event.GetSeverity()
		}
		if stage == 3 {
			ids := append([]string(nil), ch.ids...)
			sort.Strings(ids)
			peak := ch.peak
			*r.chains[key] = chainState{}
			return Outcome{
				Matched:  true,
				Severity: peak,
				Title:    "Multi-stage asset timeline observed",
				Detail: fmt.Sprintf("net → application → endpoint/server stages linked by %q within %v",
					key, r.window),
				EventIDs: ids,
				Attrs: map[string]string{
					"window":  r.window.String(),
					"linkage": key,
					"count":   "3",
				},
			}, nil
		}
		return Outcome{}, nil
	default:
		return Outcome{}, nil
	}
}

// ---------------------------------------------------------------------------
// Rule H3: forensic integrity failure (batch over stored evidence).
// ---------------------------------------------------------------------------

// IntegrityFailure is one verified-bad evidence item with the linkage the
// resulting detection must carry. TelemetryIDs must be non-empty: every
// detection links real observations.
type IntegrityFailure struct {
	Evidence       *v1.Evidence
	ExpectedDigest string
	TelemetryIDs   []string
}

// ForensicIntegrityFailureRule files one detection per evidence item that
// fails SHA-256 Verify. Per-event Evaluate is an explicit no-op
// (mirroring the T3 precedent): integrity is a batch property over
// stored evidence, and firing per event would misattribute it.
type ForensicIntegrityFailureRule struct{}

// NewForensicIntegrityFailureRule takes no tuning: the policy is
// explicit — every verified integrity failure is filed.
func NewForensicIntegrityFailureRule() (*ForensicIntegrityFailureRule, error) {
	return &ForensicIntegrityFailureRule{}, nil
}

func (ForensicIntegrityFailureRule) ID() string      { return "forensic-integrity-failure" }
func (ForensicIntegrityFailureRule) Version() string { return "1" }
func (ForensicIntegrityFailureRule) Name() string    { return "Forensic integrity failure" }
func (ForensicIntegrityFailureRule) Description() string {
	return "Files stored evidence that fails SHA-256 verification. " +
		"Evidence-integrity signal only; says nothing about any monitored target."
}

func (ForensicIntegrityFailureRule) Evaluate(*v1.TelemetryEvent) (Outcome, error) {
	return Outcome{}, nil
}

// Detections builds one contract-valid Detection per failure using the
// existing builder (deterministic ids, explicit HIGH policy severity,
// confidence 0.0). Severity HIGH is the explicit integrity-failure
// policy, not an inference about any system.
func (r ForensicIntegrityFailureRule) Detections(failures []IntegrityFailure, now func() time.Time) ([]*v1.Detection, error) {
	if now == nil || now().IsZero() {
		return nil, fmt.Errorf("detect: integrity-failure needs a valid clock")
	}
	var out []*v1.Detection
	for _, f := range failures {
		if f.Evidence == nil {
			return nil, fmt.Errorf("detect: integrity-failure nil evidence")
		}
		if len(f.TelemetryIDs) == 0 {
			return nil, fmt.Errorf("detect: integrity-failure %s needs telemetry linkage", f.Evidence.GetId())
		}
		det, err := BuildDetection(r, Outcome{
			Matched:  true,
			Severity: v1.Severity_SEVERITY_HIGH,
			Title:    "Evidence integrity verification failed",
			Detail: fmt.Sprintf("stored evidence %s (incident %s) failed SHA-256 verification; expected %s",
				f.Evidence.GetId(), f.Evidence.GetIncidentId(), f.ExpectedDigest),
			EventIDs: f.TelemetryIDs,
			Attrs: map[string]string{
				"evidence_id":     f.Evidence.GetId(),
				"incident_id":     f.Evidence.GetIncidentId(),
				"expected_digest": f.ExpectedDigest,
			},
		}, now())
		if err != nil {
			return nil, err
		}
		out = append(out, det)
	}
	return out, nil
}
