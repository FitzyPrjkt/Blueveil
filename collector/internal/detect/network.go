// Network defense rules (Step 13B). Three deterministic rules over
// event_type "net.connection", registered with the existing engine — no
// second detection engine, no new severity machinery.
//
// Severity policy: the disallow rule repeats the operator's explicit
// per-entry rating (the entry IS the policy judgment; Blueveil invents
// nothing from ports or traffic shape). Burst and denied-repeat inherit
// the window peak from source ratings, exactly like waf-block-burst.
// Confidence stays 0.0 (unmeasured). A telemetry observation is not
// automatically an alert: ordinary traffic matches nothing.
package detect

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/netobs"
)

// ---------------------------------------------------------------------------
// Rule N1: disallowed destination (stateless, explicit policy).
// ---------------------------------------------------------------------------

// DisallowedTarget is one explicit policy entry: traffic to DstIP
// (and DstPort/Protocol when set) violates operator policy. There are no
// built-in malicious ports or hosts — every entry is configured, rated,
// and labeled by the operator.
type DisallowedTarget struct {
	DstIP    string
	DstPort  uint16
	HasPort  bool
	Protocol string
	Severity v1.Severity
	Label    string
}

// NetDisallowedDestinationRule fires when an observed connection matches
// an explicit policy entry. Verdict is recorded, not gating: even denied
// attempts against a disallowed destination violate the policy.
type NetDisallowedDestinationRule struct {
	entries []normalizedTarget
}

type normalizedTarget struct {
	addr     netip.Addr
	port     uint16
	hasPort  bool
	protocol string
	severity v1.Severity
	label    string
	rawIP    string
}

// NewNetDisallowedDestinationRule validates the whole policy up front:
// empty policy, unparsable IP, out-of-range port, unknown protocol,
// unspecified severity, or unlabeled entry is a construction error.
func NewNetDisallowedDestinationRule(entries []DisallowedTarget) (*NetDisallowedDestinationRule, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("detect: disallow policy must hold at least one entry")
	}
	norm := make([]normalizedTarget, 0, len(entries))
	for i, e := range entries {
		addr, err := netip.ParseAddr(strings.TrimSpace(e.DstIP))
		if err != nil || !addr.IsValid() {
			return nil, fmt.Errorf("detect: entry %d: invalid dst ip %q", i, e.DstIP)
		}
		if e.HasPort && e.DstPort == 0 {
			return nil, fmt.Errorf("detect: entry %d: port out of range", i)
		}
		proto := strings.ToUpper(strings.TrimSpace(e.Protocol))
		if proto != "" {
			switch proto {
			case "TCP", "UDP", "ICMP", "ICMPV6", "SCTP":
			default:
				return nil, fmt.Errorf("detect: entry %d: unknown protocol %q", i, e.Protocol)
			}
		}
		if e.Severity == v1.Severity_SEVERITY_UNSPECIFIED {
			return nil, fmt.Errorf("detect: entry %d: explicit severity required", i)
		}
		if _, known := v1.Severity_name[int32(e.Severity)]; !known {
			return nil, fmt.Errorf("detect: entry %d: unknown severity %v", i, e.Severity)
		}
		if strings.TrimSpace(e.Label) == "" {
			return nil, fmt.Errorf("detect: entry %d: policy label required", i)
		}
		norm = append(norm, normalizedTarget{
			addr: addr, port: e.DstPort, hasPort: e.HasPort,
			protocol: proto, severity: e.Severity,
			label: strings.TrimSpace(e.Label), rawIP: addr.String(),
		})
	}
	return &NetDisallowedDestinationRule{entries: norm}, nil
}

func (NetDisallowedDestinationRule) ID() string      { return "net-disallowed-destination" }
func (NetDisallowedDestinationRule) Version() string { return "1" }
func (NetDisallowedDestinationRule) Name() string    { return "Disallowed network destination" }
func (NetDisallowedDestinationRule) Description() string {
	return "Matches net.connection observations against explicit operator policy entries. " +
		"Repeats the entry's configured severity; not proof of compromise or intent."
}

func (r *NetDisallowedDestinationRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != netobs.EventTypeConnection {
		return Outcome{}, nil
	}
	obs, err := netobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: disallow: %w", err)
	}
	for _, e := range r.entries {
		if obs.DstIP != e.addr {
			continue
		}
		if e.hasPort && (!obs.HasDstPort || obs.DstPort != e.port) {
			continue
		}
		if e.protocol != "" && obs.Protocol != e.protocol {
			continue
		}
		match := fmt.Sprintf("dst=%s", e.rawIP)
		if e.hasPort {
			match += fmt.Sprintf(",port=%d", e.port)
		}
		if e.protocol != "" {
			match += fmt.Sprintf(",protocol=%s", e.protocol)
		}
		return Outcome{
			Matched:  true,
			Severity: e.severity,
			Title:    "Disallowed network destination observed",
			Detail: fmt.Sprintf("source %q observed %s → %s:%s (%s, verdict %q) matching policy %q for asset %q (event %s)",
				event.GetSource(), obs.SrcIP, e.rawIP, portOrAny(obs), obs.Protocol, obs.Verdict,
				e.label, event.GetAssetId(), event.GetId()),
			EventIDs: []string{event.GetId()},
			Attrs: map[string]string{
				"policy":  e.label,
				"match":   match,
				"verdict": obs.Verdict,
			},
		}, nil
	}
	return Outcome{}, nil
}

func portOrAny(obs netobs.Observation) string {
	if obs.HasDstPort {
		return fmt.Sprint(obs.DstPort)
	}
	return "any"
}

// ---------------------------------------------------------------------------
// Shared event-time window machinery (same semantics as BlockBurstRule).
// ---------------------------------------------------------------------------

type netWindowEntry struct {
	at       time.Time
	id       string
	severity v1.Severity
}

type netWindow struct {
	entries []netWindowEntry
	fired   bool
}

// observe appends one event and reports whether the window just reached
// threshold (fires once, re-arms when the count drops below).
func (w *netWindow) observe(at time.Time, id string, sev v1.Severity, window time.Duration, threshold int) (reached bool) {
	cutoff := at.Add(-window)
	kept := w.entries[:0]
	for _, e := range w.entries {
		if !e.at.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	w.entries = kept
	w.entries = append(w.entries, netWindowEntry{at: at, id: id, severity: sev})
	if len(w.entries) < threshold {
		w.fired = false
		return false
	}
	if w.fired {
		return false
	}
	w.fired = true
	return true
}

func (w *netWindow) peak() v1.Severity {
	peak := v1.Severity_SEVERITY_INFO
	for _, e := range w.entries {
		if e.severity > peak {
			peak = e.severity
		}
	}
	return peak
}

func (w *netWindow) ids() []string {
	ids := make([]string, 0, len(w.entries))
	for _, e := range w.entries {
		ids = append(ids, e.id)
	}
	sort.Strings(ids)
	return ids
}

func checkNetClock(clock func() time.Time, what string) error {
	if clock == nil {
		return fmt.Errorf("detect: %s clock is nil", what)
	}
	if clock().IsZero() {
		return fmt.Errorf("detect: %s clock returned zero time", what)
	}
	return nil
}

func checkBurstParams(threshold int, window time.Duration, what string) error {
	if threshold <= 0 {
		return fmt.Errorf("detect: %s threshold must be > 0, got %d", what, threshold)
	}
	if window <= 0 {
		return fmt.Errorf("detect: %s window must be > 0, got %v", what, window)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Rule N2: connection burst (stateful, per source endpoint).
// ---------------------------------------------------------------------------

// NetConnectionBurstRule fires once when one source endpoint accumulates
// threshold connections inside window (event time). Aggregation signal,
// not attack proof. Restart clears state (same documented limit as the
// WAF burst rule).
type NetConnectionBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

// NewNetConnectionBurstRule validates parameters; invalid is a
// construction error, never a silent default.
func NewNetConnectionBurstRule(threshold int, window time.Duration, clock func() time.Time) (*NetConnectionBurstRule, error) {
	if err := checkBurstParams(threshold, window, "burst"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: burst clock is nil")
	}
	return &NetConnectionBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *NetConnectionBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *NetConnectionBurstRule) ID() string      { return "net-connection-burst" }
func (r *NetConnectionBurstRule) Version() string { return "1" }
func (r *NetConnectionBurstRule) Name() string    { return "Connection burst" }
func (r *NetConnectionBurstRule) Description() string {
	return "Matches when one source endpoint accumulates threshold connections inside window. " +
		"Counts observed traffic volume; says nothing about attacker intent or success."
}

func (r *NetConnectionBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != netobs.EventTypeConnection {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "burst"); err != nil {
		return Outcome{}, err
	}
	obs, err := netobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: burst: %w", err)
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: burst needs event occurred_at")
	}
	key := obs.SrcIP.String()
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
		Title:    "Connection burst observed",
		Detail: fmt.Sprintf("%d connections from %s within %v (threshold %d)",
			len(w.entries), key, r.window, r.threshold),
		EventIDs: w.ids(),
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(w.entries)),
			"src":       key,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Rule N3: repeated denied activity (stateful, explicit denial only).
// ---------------------------------------------------------------------------

// NetDeniedActivityRule fires once when threshold explicitly-denied
// connections share one (source, destination, port) key inside window.
// Only source-declared verdict=denied counts; absence of success is never
// treated as denial.
type NetDeniedActivityRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

// NewNetDeniedActivityRule validates parameters; invalid is a
// construction error, never a silent default.
func NewNetDeniedActivityRule(threshold int, window time.Duration, clock func() time.Time) (*NetDeniedActivityRule, error) {
	if err := checkBurstParams(threshold, window, "denied"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: denied clock is nil")
	}
	return &NetDeniedActivityRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *NetDeniedActivityRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *NetDeniedActivityRule) ID() string      { return "net-denied-repeated" }
func (r *NetDeniedActivityRule) Version() string { return "1" }
func (r *NetDeniedActivityRule) Name() string    { return "Repeated denied network activity" }
func (r *NetDeniedActivityRule) Description() string {
	return "Matches when explicitly-denied connections to one destination repeat past threshold inside window. " +
		"Counts source-declared denials only; never infers denial from missing success."
}

func (r *NetDeniedActivityRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != netobs.EventTypeConnection {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "denied"); err != nil {
		return Outcome{}, err
	}
	obs, err := netobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: denied: %w", err)
	}
	if obs.Verdict != "denied" {
		return Outcome{}, nil
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: denied needs event occurred_at")
	}
	port := "any"
	if obs.HasDstPort {
		port = fmt.Sprint(obs.DstPort)
	}
	key := obs.SrcIP.String() + "\x1f" + obs.DstIP.String() + "\x1f" + port
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
		Title:    "Repeated denied network activity observed",
		Detail: fmt.Sprintf("%d denied connections from %s to %s port %s within %v (threshold %d)",
			len(w.entries), obs.SrcIP, obs.DstIP, port, r.window, r.threshold),
		EventIDs: w.ids(),
		Attrs: map[string]string{
			"threshold": fmt.Sprint(r.threshold),
			"window":    r.window.String(),
			"count":     fmt.Sprint(len(w.entries)),
			"src":       obs.SrcIP.String(),
			"dst":       obs.DstIP.String(),
			"port":      port,
		},
	}, nil
}
