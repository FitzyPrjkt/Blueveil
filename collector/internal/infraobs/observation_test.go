// RED: infra observation normalization
package infraobs

import (
	"reflect"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func mkEvent(typ string, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: "evt-infra-001", OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: "seed-lab-infra", AssetId: "seed-infra-01", EventType: typ,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func TestEndpointFull(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeEndpointActivity, map[string]string{
		"endpoint.host": "web01", "endpoint.process": "explorer.exe", "endpoint.pid": "1234",
		"endpoint.action": "privilege_transition", "endpoint.integrity_level": "high", "endpoint.user": "SYSTEM",
		"endpoint.command": "run --token secret123", "endpoint.result": "success",
	}))
	if err != nil {
		t.Fatalf("endpoint full: %v", err)
	}
	if o.Endpoint.Host != "web01" || o.Endpoint.Action != "privilege_transition" {
		t.Fatalf("endpoint fields: %+v", o.Endpoint)
	}
	if _, ok := o.RawAttrs["endpoint.command"]; ok {
		// command should be redacted of secret
		if o.Endpoint.Command == "run --token secret123" {
			t.Fatalf("secret not redacted: %q", o.Endpoint.Command)
		}
	}
}

func TestServerMinimal(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeServerActivity, map[string]string{
		"server.hostname": "srv-01", "server.service": "nginx", "server.service_action": "restart",
	}))
	if err != nil {
		t.Fatalf("server minimal: %v", err)
	}
	if o.Server.Hostname != "srv-01" || o.Server.Service != "nginx" {
		t.Fatalf("server: %+v", o.Server)
	}
}

func TestContainerPolicy(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeContainerActivity, map[string]string{
		"container.container_id": "abc123", "container.image": "nginx:1.25", "container.action": "start",
		"container.privileged": "true", "container.host_network": "true",
	}))
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	if !o.Container.Privileged || !o.Container.HostNetwork {
		t.Fatalf("container flags: %+v", o.Container)
	}
}

func TestCloudDenied(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeCloudActivity, map[string]string{
		"cloud.provider": "aws", "cloud.action": "s3:GetObject", "cloud.result": "denied",
		"cloud.principal": "user-01", "cloud.resource": "bucket-01", "cloud.request_id": "req-123",
	}))
	if err != nil {
		t.Fatalf("cloud: %v", err)
	}
	if o.Cloud.Result != "denied" || o.Cloud.Provider != "aws" {
		t.Fatalf("cloud: %+v", o.Cloud)
	}
}

func TestInfraRedaction(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeCloudActivity, map[string]string{
		"cloud.provider": "aws", "cloud.action": "sts:AssumeRole", "cloud.result": "success",
		"cloud.access_key": "AKIASECRET",
	}))
	if err != nil {
		t.Fatalf("redact cloud: %v", err)
	}
	if _, ok := o.RawAttrs["cloud.access_key"]; ok {
		t.Fatalf("cloud secret not redacted")
	}
	o2, err := Parse(mkEvent(EventTypeEndpointActivity, map[string]string{
		"endpoint.host": "web01", "endpoint.process": "cmd.exe", "endpoint.action": "process_start",
		"endpoint.command": "run --password hunter2",
	}))
	if err != nil {
		t.Fatalf("endpoint redact: %v", err)
	}
	if _, ok := o2.RawAttrs["endpoint.command"]; !ok {
		// command should be present but redacted
		t.Fatalf("command missing after redact")
	}
	if o2.Endpoint.Command == "run --password hunter2" {
		t.Fatalf("password not redacted")
	}
}

func TestInfraRejects(t *testing.T) {
	cases := map[string]*v1.TelemetryEvent{
		"wrong type":         mkEvent("unknown", map[string]string{"endpoint.host": "web01"}),
		"missing host":       mkEvent(EventTypeEndpointActivity, map[string]string{"endpoint.process": "proc"}),
		"bad pid":            mkEvent(EventTypeEndpointActivity, map[string]string{"endpoint.host": "web01", "endpoint.process": "proc", "endpoint.pid": "abc"}),
		"bad container":      mkEvent(EventTypeContainerActivity, map[string]string{"container.action": "start"}),
		"bad cloud provider": mkEvent(EventTypeCloudActivity, map[string]string{"cloud.provider": "unknown", "cloud.action": "x"}),
	}
	for name, e := range cases {
		if _, err := Parse(e); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestInfraIdentity(t *testing.T) {
	mk := func() *v1.TelemetryEvent {
		return mkEvent(EventTypeEndpointActivity, map[string]string{"endpoint.host": "web01", "endpoint.process": "proc", "endpoint.action": "process_start"})
	}
	a, _ := Parse(mk())
	b, _ := Parse(mk())
	if !reflect.DeepEqual(a, b) || a.ID() != b.ID() || a.ID() == "" {
		t.Fatalf("idempotent: %+v %+v", a, b)
	}
	other, _ := Parse(mkEvent(EventTypeEndpointActivity, map[string]string{"endpoint.host": "web02", "endpoint.process": "proc", "endpoint.action": "process_start"}))
	if other.ID() == a.ID() {
		t.Fatalf("different host must differ")
	}
}
