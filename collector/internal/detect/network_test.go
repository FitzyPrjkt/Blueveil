// RED: network defense rules — policy violation, burst, denied-repeat.
package detect

import (
	"strings"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var netBase = time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)

func netTelemetry(id, src, dst string, minute int, sev v1.Severity, extra map[string]string) *v1.TelemetryEvent {
	attrs := map[string]string{"net.src_ip": src, "net.dst_ip": dst}
	for k, v := range extra {
		attrs[k] = v
	}
	return &v1.TelemetryEvent{
		Id:         id,
		OccurredAt: timestamppb.New(netBase.Add(time.Duration(minute) * time.Minute)),
		Source:     "lab-sensor",
		AssetId:    "seed-net-01",
		EventType:  "net.connection",
		Severity:   sev,
		Attributes: attrs,
	}
}

func mustDisallow(t *testing.T, entries []DisallowedTarget) *NetDisallowedDestinationRule {
	t.Helper()
	r, err := NewNetDisallowedDestinationRule(entries)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	return r
}

func TestDisallowInvalidConfig(t *testing.T) {
	good := DisallowedTarget{DstIP: "203.0.113.7", DstPort: 4444, HasPort: true,
		Protocol: "TCP", Severity: v1.Severity_SEVERITY_HIGH, Label: "lab-policy"}
	bad := []DisallowedTarget{
		{}, // empty entry tested via empty slice below
		{DstIP: "bogus", Severity: v1.Severity_SEVERITY_HIGH, Label: "x"},
		{DstIP: "203.0.113.7", DstPort: 0, HasPort: true, Severity: v1.Severity_SEVERITY_HIGH, Label: "x"},
		{DstIP: "203.0.113.7", Protocol: "GRE", Severity: v1.Severity_SEVERITY_HIGH, Label: "x"},
		{DstIP: "203.0.113.7", Severity: v1.Severity_SEVERITY_UNSPECIFIED, Label: "x"},
		{DstIP: "203.0.113.7", Severity: v1.Severity_SEVERITY_HIGH},
	}
	_ = good
	if _, err := NewNetDisallowedDestinationRule(nil); err == nil {
		t.Errorf("empty policy must be rejected")
	}
	for i, e := range bad[1:] {
		if _, err := NewNetDisallowedDestinationRule([]DisallowedTarget{e}); err == nil {
			t.Errorf("entry %d must be rejected", i)
		}
	}
}

func TestDisallowMatchAndBoundary(t *testing.T) {
	r := mustDisallow(t, []DisallowedTarget{
		{DstIP: "203.0.113.7", DstPort: 4444, HasPort: true,
			Protocol: "TCP", Severity: v1.Severity_SEVERITY_HIGH, Label: "lab-doc-range"},
		{DstIP: "198.51.100.9", Severity: v1.Severity_SEVERITY_MEDIUM, Label: "lab-any-port"},
	})
	hit, err := r.Evaluate(netTelemetry("n1", "10.0.0.9", "203.0.113.7", 0, v1.Severity_SEVERITY_INFO,
		map[string]string{"net.dst_port": "4444", "net.protocol": "tcp"}))
	if err != nil || !hit.Matched {
		t.Fatalf("must match: %+v %v", hit, err)
	}
	if hit.Severity != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("policy severity applies, got %v", hit.Severity)
	}
	if !strings.Contains(hit.Attrs["policy"], "lab-doc-range") {
		t.Fatalf("policy provenance missing: %+v", hit.Attrs)
	}
	// Boundaries: wrong port, wrong proto, unlisted host, any-port entry.
	for name, e := range map[string]*v1.TelemetryEvent{
		"wrong port": netTelemetry("n2", "10.0.0.9", "203.0.113.7", 0, v1.Severity_SEVERITY_INFO,
			map[string]string{"net.dst_port": "80", "net.protocol": "TCP"}),
		"wrong proto": netTelemetry("n3", "10.0.0.9", "203.0.113.7", 0, v1.Severity_SEVERITY_INFO,
			map[string]string{"net.dst_port": "4444", "net.protocol": "UDP"}),
		"unlisted": netTelemetry("n4", "10.0.0.9", "192.0.2.1", 0, v1.Severity_SEVERITY_INFO,
			map[string]string{"net.dst_port": "4444", "net.protocol": "TCP"}),
	} {
		out, err := r.Evaluate(e)
		if err != nil || out.Matched {
			t.Errorf("%s: must not match: %+v %v", name, out, err)
		}
	}
	any, err := r.Evaluate(netTelemetry("n5", "10.0.0.9", "198.51.100.9", 0, v1.Severity_SEVERITY_LOW,
		map[string]string{"net.dst_port": "9999"}))
	if err != nil || !any.Matched || any.Severity != v1.Severity_SEVERITY_MEDIUM {
		t.Errorf("portless entry must match any port: %+v %v", any, err)
	}
	// Non-network events are ignored, never errors.
	waf := netTelemetry("w1", "10.0.0.9", "10.0.0.1", 0, v1.Severity_SEVERITY_HIGH, nil)
	waf.EventType = "waf.request_blocked"
	if out, err := r.Evaluate(waf); err != nil || out.Matched {
		t.Errorf("waf event must be ignored: %+v %v", out, err)
	}
	// Malformed network data fails explicitly (fail-closed).
	mal := netTelemetry("m1", "bogus", "10.0.0.1", 0, v1.Severity_SEVERITY_INFO, nil)
	if _, err := r.Evaluate(mal); err == nil {
		t.Errorf("malformed observation must error")
	}
	if _, err := r.Evaluate(nil); err == nil {
		t.Errorf("nil must error")
	}
}

func TestNetBurstThresholdWindowRearm(t *testing.T) {
	clock := func() time.Time { return netBase }
	r, err := NewNetConnectionBurstRule(3, 5*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mk := func(id string, minute int) *v1.TelemetryEvent {
		return netTelemetry(id, "10.0.0.9", "10.0.0.1", minute, v1.Severity_SEVERITY_LOW,
			map[string]string{"net.dst_port": "80", "net.protocol": "TCP"})
	}
	var fires []Outcome
	for i, m := range []int{0, 1, 2, 3, 10, 11, 12} {
		out, err := r.Evaluate(mk("b"+string(rune('0'+i)), m))
		if err != nil {
			t.Fatalf("minute %d: %v", m, err)
		}
		if out.Matched {
			fires = append(fires, out)
		}
	}
	if len(fires) != 2 {
		t.Fatalf("want fire at window-full + once after re-arm, got %d", len(fires))
	}
	if fires[0].Attrs["count"] != "3" || fires[0].Attrs["threshold"] != "3" {
		t.Fatalf("threshold provenance: %+v", fires[0].Attrs)
	}
	if fires[0].Severity != v1.Severity_SEVERITY_LOW {
		t.Fatalf("severity inherits source peak, got %v", fires[0].Severity)
	}
	// Per-source isolation: another source starts its own window.
	other := netTelemetry("c1", "10.0.0.99", "10.0.0.1", 12, v1.Severity_SEVERITY_LOW, nil)
	if out, _ := r.Evaluate(other); out.Matched {
		t.Fatalf("new source must not inherit the window")
	}
	if _, err := NewNetConnectionBurstRule(0, 5*time.Minute, clock); err == nil {
		t.Errorf("zero threshold must be rejected")
	}
	if _, err := NewNetConnectionBurstRule(3, 0, clock); err == nil {
		t.Errorf("zero window must be rejected")
	}
	if _, err := NewNetConnectionBurstRule(3, 5*time.Minute, nil); err == nil {
		t.Errorf("nil clock must be rejected")
	}
}

func TestNetDeniedRepeated(t *testing.T) {
	clock := func() time.Time { return netBase }
	r, err := NewNetDeniedActivityRule(3, 5*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mk := func(id string, minute int, verdict string) *v1.TelemetryEvent {
		return netTelemetry(id, "10.0.0.10", "10.0.0.1", minute, v1.Severity_SEVERITY_MEDIUM,
			map[string]string{"net.dst_port": "22", "net.protocol": "TCP", "net.verdict": verdict})
	}
	// Allowed traffic never counts — not even toward the threshold.
	seq := []struct {
		id, verdict string
		minute      int
		wantFire    bool
	}{
		{"d0", "allowed", 0, false},
		{"d1", "allowed", 1, false},
		{"d2", "denied", 2, false},
		{"d3", "denied", 3, false},
		{"d4", "allowed", 4, false},
		{"d5", "denied", 5, true},
	}
	fires := 0
	for _, s := range seq {
		out, err := r.Evaluate(mk(s.id, s.minute, s.verdict))
		if err != nil {
			t.Fatalf("%s: %v", s.id, err)
		}
		if out.Matched != s.wantFire {
			t.Errorf("%s: matched=%v want %v", s.id, out.Matched, s.wantFire)
		}
		if out.Matched {
			fires++
			if out.Attrs["count"] != "3" {
				t.Errorf("count provenance: %+v", out.Attrs)
			}
		}
	}
	if fires != 1 {
		t.Fatalf("want exactly one fire, got %d", fires)
	}
	// Missing verdict is not denial.
	nov := netTelemetry("d9", "10.0.0.10", "10.0.0.1", 6, v1.Severity_SEVERITY_MEDIUM, nil)
	if out, _ := r.Evaluate(nov); out.Matched {
		t.Fatalf("verdict-less event must not match")
	}
	if _, err := NewNetDeniedActivityRule(-1, 5*time.Minute, clock); err == nil {
		t.Errorf("negative threshold must be rejected")
	}
}

func TestNetRulesEngineIntegration(t *testing.T) {
	eng, err := NewEngine(func() time.Time { return netBase })
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	for _, r := range []Rule{BlockHighSeverityRule{}, SourceCriticalRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatal(err)
		}
	}
	burst, _ := NewNetConnectionBurstRule(99, time.Hour, func() time.Time { return netBase })
	for _, r := range []Rule{
		mustDisallow(t, []DisallowedTarget{{DstIP: "203.0.113.7", Severity: v1.Severity_SEVERITY_HIGH, Label: "lab"}}),
		burst,
	} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatal(err)
		}
	}
	// Ordinary traffic: observation, not an alert.
	normal := netTelemetry("ok1", "127.0.0.1", "127.0.0.1", 0, v1.Severity_SEVERITY_INFO,
		map[string]string{"net.dst_port": "8080", "net.protocol": "TCP", "net.verdict": "allowed"})
	res, err := eng.Process(normal)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Detections) != 0 || len(res.Alerts) != 0 {
		t.Fatalf("normal traffic must not alert: %+v", res)
	}
	// Violation: one deterministic detection + alert; reprocess suppresses.
	bad := netTelemetry("bad1", "10.0.0.9", "203.0.113.7", 1, v1.Severity_SEVERITY_MEDIUM,
		map[string]string{"net.dst_port": "443", "net.protocol": "TCP"})
	res, err = eng.Process(bad)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Detections) != 1 || len(res.Alerts) != 1 {
		t.Fatalf("want 1 detection + 1 alert, got %+v", res)
	}
	if res.Detections[0].GetRuleId() != "net-disallowed-destination" {
		t.Fatalf("rule: %s", res.Detections[0].GetRuleId())
	}
	res2, err := eng.Process(bad)
	if err != nil || len(res2.Detections) != 0 || res2.Suppressed != 1 {
		t.Fatalf("reprocess must suppress: %+v %v", res2, err)
	}
}
