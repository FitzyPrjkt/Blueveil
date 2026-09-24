// Package netobs normalizes network observations carried by the existing
// TelemetryEvent contract (13B.2/13B.3). No contract change: the event_type
// is the free-form string "net.connection" and every network fact lives in
// attributes under the net.* namespace:
//
//	net.src_ip    required, IPv4 or IPv6 (canonicalized, compressed)
//	net.dst_ip    required, IPv4 or IPv6
//	net.src_port  optional, 1-65535
//	net.dst_port  optional, 1-65535
//	net.protocol  optional, TCP|UDP|ICMP|ICMPV6|SCTP (case-insensitive)
//	net.direction optional, inbound|outbound|internal|lateral (case-insensitive)
//	net.verdict   optional, allowed|denied (case-insensitive, source-declared)
//
// Missing optional fields stay empty (unknown) — Blueveil never fabricates
// network information. Present-but-malformed values are explicit errors, so
// malformed data can never normalize into valid-looking telemetry. Parse is
// pure and deterministic: same event bytes always yield the same Observation.
package netobs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

// EventTypeConnection is the only event_type this package understands.
const EventTypeConnection = "net.connection"

// Known protocol names (normalized to upper case).
var knownProtocols = map[string]bool{
	"TCP": true, "UDP": true, "ICMP": true, "ICMPV6": true, "SCTP": true,
}

// Known directions (normalized to lower case).
var knownDirections = map[string]bool{
	"inbound": true, "outbound": true, "internal": true, "lateral": true,
}

// Known verdicts (normalized to lower case). Only a source-declared
// "denied" counts as denied traffic; absence never implies denial.
var knownVerdicts = map[string]bool{"allowed": true, "denied": true}

// Observation is one normalized network connection/flow record.
type Observation struct {
	EventID    string
	Source     string
	AssetID    string
	OccurredAt time.Time
	Severity   v1.Severity
	SrcIP      netip.Addr
	DstIP      netip.Addr
	SrcPort    uint16
	HasSrcPort bool
	DstPort    uint16
	HasDstPort bool
	Protocol   string
	Direction  string
	Verdict    string
}

// Parse validates and normalizes one TelemetryEvent into an Observation.
func Parse(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	if event == nil {
		return o, fmt.Errorf("netobs: nil event")
	}
	if event.GetEventType() != EventTypeConnection {
		return o, fmt.Errorf("netobs: event_type %q is not %q", event.GetEventType(), EventTypeConnection)
	}
	attrs := event.GetAttributes()
	src, err := parseIP(attrs["net.src_ip"], "net.src_ip")
	if err != nil {
		return o, err
	}
	dst, err := parseIP(attrs["net.dst_ip"], "net.dst_ip")
	if err != nil {
		return o, err
	}
	srcPort, hasSrc, err := parsePort(attrs["net.src_port"], "net.src_port")
	if err != nil {
		return o, err
	}
	dstPort, hasDst, err := parsePort(attrs["net.dst_port"], "net.dst_port")
	if err != nil {
		return o, err
	}
	proto := strings.ToUpper(strings.TrimSpace(attrs["net.protocol"]))
	if proto != "" && !knownProtocols[proto] {
		return o, fmt.Errorf("netobs: unknown net.protocol %q", attrs["net.protocol"])
	}
	dir := strings.ToLower(strings.TrimSpace(attrs["net.direction"]))
	if dir != "" && !knownDirections[dir] {
		return o, fmt.Errorf("netobs: unknown net.direction %q", attrs["net.direction"])
	}
	verdict := strings.ToLower(strings.TrimSpace(attrs["net.verdict"]))
	if verdict != "" && !knownVerdicts[verdict] {
		return o, fmt.Errorf("netobs: unknown net.verdict %q", attrs["net.verdict"])
	}
	o = Observation{
		EventID:    event.GetId(),
		Source:     event.GetSource(),
		AssetID:    event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(),
		Severity:   event.GetSeverity(),
		SrcIP:      src,
		DstIP:      dst,
		SrcPort:    srcPort,
		HasSrcPort: hasSrc,
		DstPort:    dstPort,
		HasDstPort: hasDst,
		Protocol:   proto,
		Direction:  dir,
		Verdict:    verdict,
	}
	return o, nil
}

func parseIP(raw, what string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("netobs: invalid %s %q", what, raw)
	}
	return addr, nil
}

func parsePort(raw, what string) (uint16, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, false, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 || n > 65535 {
		return 0, false, fmt.Errorf("netobs: invalid %s %q: want 1-65535", what, raw)
	}
	return uint16(n), true, nil
}

// ID returns the deterministic identity of this observation:
// netobs-<16 hex of SHA-256 over canonical endpoint fields>. Same
// observation bytes always yield the same id; any field change moves it.
func (o Observation) ID() string {
	var b strings.Builder
	b.WriteString(o.SrcIP.String())
	b.WriteString("\x1f")
	b.WriteString(o.DstIP.String())
	b.WriteString("\x1f")
	fmt.Fprintf(&b, "%d\x1f%t\x1f%d\x1f%t\x1f%s\x1f%s\x1f%s",
		o.SrcPort, o.HasSrcPort, o.DstPort, o.HasDstPort,
		o.Protocol, o.Direction, o.Verdict)
	sum := sha256.Sum256([]byte(b.String()))
	return "netobs-" + hex.EncodeToString(sum[:])[:16]
}
