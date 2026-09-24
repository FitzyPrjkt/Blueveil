// RED: deterministic SIEM correlation — explicit linkage only.
package monitor

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func siemEvt(id, typ string, minute int, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(time.Duration(minute) * time.Minute)),
		Source: "seed-lab-monitoring", AssetId: "seed-mon-01", EventType: typ,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func TestCorrelateAuthToIdentity(t *testing.T) {
	win := 10 * time.Minute
	evts := []*v1.TelemetryEvent{
		siemEvt("f1", "auth.activity", 0, map[string]string{"auth.principal": "erin", "auth.outcome": "failure"}),
		siemEvt("f2", "auth.activity", 1, map[string]string{"auth.principal": "erin", "auth.outcome": "failure"}),
		siemEvt("c1", "identity.activity", 2, map[string]string{"identity.principal": "erin", "identity.action": "role_change"}),
		siemEvt("c2", "identity.activity", 3, map[string]string{"identity.principal": "mallory", "identity.action": "role_change"}),
		siemEvt("f3", "auth.activity", 50, map[string]string{"auth.principal": "erin", "auth.outcome": "failure"}),
	}
	corrs, err := CorrelateAuthToIdentity(evts, win)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(corrs) != 1 {
		t.Fatalf("want exactly 1 correlation (erin f+c), got %+v", corrs)
	}
	c := corrs[0]
	if c.Type != CorrelationAuthToIdentity || c.Status != StatusCorrelated {
		t.Fatalf("type/status: %+v", c)
	}
	if c.Principal != "erin" {
		t.Fatalf("principal: %+v", c)
	}
	if len(c.EventIDs) != 3 {
		t.Fatalf("want both failures + change, got %+v", c.EventIDs)
	}
	if c.ID == "" {
		t.Fatalf("deterministic id required")
	}
	// Deterministic: same input, same id.
	again, _ := CorrelateAuthToIdentity(evts, win)
	if again[0].ID != c.ID {
		t.Fatalf("correlation id unstable")
	}
	// Timestamp-only lookalike without shared principal must not correlate.
	lone := []*v1.TelemetryEvent{
		siemEvt("f9", "auth.activity", 0, map[string]string{"auth.principal": "erin", "auth.outcome": "failure"}),
		siemEvt("c9", "identity.activity", 1, map[string]string{"identity.principal": "mallory", "identity.action": "role_change"}),
	}
	got, err := CorrelateAuthToIdentity(lone, win)
	if err != nil || len(got) != 0 {
		t.Fatalf("different principals must not correlate: %+v %v", got, err)
	}
	// Outside window must not correlate.
	far := []*v1.TelemetryEvent{
		siemEvt("f8", "auth.activity", 0, map[string]string{"auth.principal": "erin", "auth.outcome": "failure"}),
		siemEvt("c8", "identity.activity", 60, map[string]string{"identity.principal": "erin", "identity.action": "role_change"}),
	}
	got, err = CorrelateAuthToIdentity(far, win)
	if err != nil || len(got) != 0 {
		t.Fatalf("outside window must not correlate: %+v %v", got, err)
	}
	if _, err := CorrelateAuthToIdentity(evts, -1); err == nil {
		t.Errorf("negative window must be rejected")
	}
}

func TestCorrelateNetworkToApp(t *testing.T) {
	win := 10 * time.Minute
	mkNet := func(id string, minute int, asset string) *v1.TelemetryEvent {
		e := siemEvt(id, "net.connection", minute, map[string]string{"net.src_ip": "10.0.0.1", "net.dst_ip": "10.0.0.2"})
		e.AssetId = asset
		return e
	}
	mkHTTP := func(id string, minute int, asset string) *v1.TelemetryEvent {
		e := siemEvt(id, "http.request", minute, map[string]string{"http.method": "GET", "http.host": "x", "http.path": "/"})
		e.AssetId = asset
		return e
	}
	evts := []*v1.TelemetryEvent{
		mkNet("n1", 0, "seed-mon-01"), mkHTTP("h1", 1, "seed-mon-01"),
		mkNet("n2", 2, "other-asset"), mkHTTP("h2", 3, "seed-mon-01"),
	}
	corrs, err := CorrelateNetworkToApp(evts, win)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(corrs) != 1 || corrs[0].AssetID != "seed-mon-01" {
		t.Fatalf("want exactly the linked pair, got %+v", corrs)
	}
	if corrs[0].Type != CorrelationNetworkToApp {
		t.Fatalf("type: %+v", corrs[0])
	}
}

func TestCorrelateEndpointToServer(t *testing.T) {
	win := 10 * time.Minute
	evts := []*v1.TelemetryEvent{
		siemEvt("p1", "endpoint.activity", 0, map[string]string{"endpoint.host": "web01", "endpoint.process": "x", "endpoint.action": "process_start"}),
		siemEvt("s1", "server.activity", 1, map[string]string{"server.hostname": "web01", "server.service": "nginx"}),
		siemEvt("s2", "server.activity", 2, map[string]string{"server.hostname": "db01", "server.service": "pg"}),
	}
	corrs, err := CorrelateEndpointToServer(evts, win)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(corrs) != 1 || corrs[0].AssetID != "web01" {
		t.Fatalf("want exactly the same-host pair, got %+v", corrs)
	}
	if corrs[0].Type != CorrelationEndpointToServer {
		t.Fatalf("type: %+v", corrs[0])
	}
}
