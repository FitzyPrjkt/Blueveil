// RED: network observation normalization — deterministic, idempotent,
// explicit failures. No production code exists yet.
package netobs

import (
	"reflect"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func netEvent(attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id:         "evt-net-001",
		OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 4, 0, 0, time.UTC)),
		Source:     "lab-sensor",
		AssetId:    "seed-net-01",
		EventType:  EventTypeConnection,
		Severity:   v1.Severity_SEVERITY_INFO,
		Attributes: attrs,
	}
}

func TestParseFullIPv4(t *testing.T) {
	o, err := Parse(netEvent(map[string]string{
		"net.src_ip": "127.0.0.1", "net.dst_ip": "127.0.0.1",
		"net.src_port": "43110", "net.dst_port": "8080",
		"net.protocol": "tcp", "net.direction": "Outbound", "net.verdict": "ALLOWED",
	}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.SrcIP.String() != "127.0.0.1" || o.DstIP.String() != "127.0.0.1" {
		t.Fatalf("ips: %v %v", o.SrcIP, o.DstIP)
	}
	if !o.HasSrcPort || o.SrcPort != 43110 || !o.HasDstPort || o.DstPort != 8080 {
		t.Fatalf("ports: %+v", o)
	}
	if o.Protocol != "TCP" || o.Direction != "outbound" || o.Verdict != "allowed" {
		t.Fatalf("enums: %+v", o)
	}
	if o.EventID != "evt-net-001" || o.Source != "lab-sensor" {
		t.Fatalf("provenance: %+v", o)
	}
}

func TestParseIPv6Canonical(t *testing.T) {
	o, err := Parse(netEvent(map[string]string{
		"net.src_ip": "2001:0db8:0000:0000:0000:0000:0000:0001",
		"net.dst_ip": "::1",
	}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.SrcIP.String() != "2001:db8::1" || o.DstIP.String() != "::1" {
		t.Fatalf("not compressed: %v %v", o.SrcIP, o.DstIP)
	}
}

func TestParseMinimal(t *testing.T) {
	o, err := Parse(netEvent(map[string]string{
		"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
	}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.HasSrcPort || o.HasDstPort || o.Protocol != "" || o.Direction != "" || o.Verdict != "" {
		t.Fatalf("optional must stay empty: %+v", o)
	}
}

func TestParseRejects(t *testing.T) {
	base := map[string]string{"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1"}
	cases := map[string]struct {
		mutate func(map[string]string)
		event  func(*v1.TelemetryEvent)
	}{
		"wrong type":      {event: func(e *v1.TelemetryEvent) { e.EventType = "waf.request_blocked" }},
		"missing src":     {mutate: func(m map[string]string) { delete(m, "net.src_ip") }},
		"missing dst":     {mutate: func(m map[string]string) { delete(m, "net.dst_ip") }},
		"bad src":         {mutate: func(m map[string]string) { m["net.src_ip"] = "not-an-ip" }},
		"bad dst":         {mutate: func(m map[string]string) { m["net.dst_ip"] = "999.1.1.1" }},
		"port zero":       {mutate: func(m map[string]string) { m["net.dst_port"] = "0" }},
		"port overflow":   {mutate: func(m map[string]string) { m["net.dst_port"] = "99999" }},
		"port alpha":      {mutate: func(m map[string]string) { m["net.src_port"] = "http" }},
		"unknown proto":   {mutate: func(m map[string]string) { m["net.protocol"] = "GRE" }},
		"unknown dir":     {mutate: func(m map[string]string) { m["net.direction"] = "sideways" }},
		"unknown verdict": {mutate: func(m map[string]string) { m["net.verdict"] = "maybe" }},
		"nil event":       {event: func(e *v1.TelemetryEvent) { *e = v1.TelemetryEvent{} }},
	}
	for name, c := range cases {
		attrs := map[string]string{}
		for k, v := range base {
			attrs[k] = v
		}
		if c.mutate != nil {
			c.mutate(attrs)
		}
		e := netEvent(attrs)
		if c.event != nil {
			c.event(e)
		}
		if _, err := Parse(e); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestIdentityDeterministicAndIdempotent(t *testing.T) {
	mk := func() *v1.TelemetryEvent {
		return netEvent(map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
			"net.dst_port": "80", "net.protocol": "TCP",
		})
	}
	a, err := Parse(mk())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b, err := Parse(mk())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("not idempotent:\n%+v\n%+v", a, b)
	}
	if a.ID() == "" || a.ID() != b.ID() {
		t.Fatalf("identity unstable: %q %q", a.ID(), b.ID())
	}
	other, err := Parse(netEvent(map[string]string{
		"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.2",
		"net.dst_port": "80", "net.protocol": "TCP",
	}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if other.ID() == a.ID() {
		t.Fatalf("identity collision across destinations")
	}
}
