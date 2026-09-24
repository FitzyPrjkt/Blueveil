package detect

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/infraobs"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func infraBase() time.Time { return time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC) }

func endpointEvt(id, host, action, level string) *v1.TelemetryEvent {
	attrs := map[string]string{"endpoint.host": host, "endpoint.process": "proc", "endpoint.action": action}
	if level != "" {
		attrs["endpoint.integrity_level"] = level
	}
	return &v1.TelemetryEvent{Id: id, OccurredAt: timestamppb.New(infraBase()), Source: "test", AssetId: "a1", EventType: infraobs.EventTypeEndpointActivity, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs}
}

func serverEvt(id, host, service, result string, minute int) *v1.TelemetryEvent {
	attrs := map[string]string{"server.hostname": host, "server.service": service, "server.result": result, "server.service_action": result}
	return &v1.TelemetryEvent{Id: id, OccurredAt: timestamppb.New(infraBase().Add(time.Duration(minute) * time.Minute)), Source: "test", AssetId: "a1", EventType: infraobs.EventTypeServerActivity, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs}
}

func containerEvt(id, cid, image string, privileged bool) *v1.TelemetryEvent {
	attrs := map[string]string{"container.container_id": cid, "container.image": image, "container.action": "start"}
	if privileged {
		attrs["container.privileged"] = "true"
	}
	return &v1.TelemetryEvent{Id: id, OccurredAt: timestamppb.New(infraBase()), Source: "test", AssetId: "a1", EventType: infraobs.EventTypeContainerActivity, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs}
}

func cloudEvt(id, provider, action, result, principal string, minute int) *v1.TelemetryEvent {
	attrs := map[string]string{"cloud.provider": provider, "cloud.action": action, "cloud.result": result, "cloud.principal": principal, "cloud.resource": "res-01"}
	return &v1.TelemetryEvent{Id: id, OccurredAt: timestamppb.New(infraBase().Add(time.Duration(minute) * time.Minute)), Source: "test", AssetId: "a1", EventType: infraobs.EventTypeCloudActivity, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs}
}

func TestEndpointPrivilege(t *testing.T) {
	r := EndpointPrivilegeChangeRule{}
	hit, _ := r.Evaluate(endpointEvt("e1", "web01", "privilege_transition", "high"))
	if !hit.Matched {
		t.Fatalf("must match")
	}
	miss, _ := r.Evaluate(endpointEvt("e2", "web01", "process_start", "high"))
	if miss.Matched {
		t.Fatalf("process_start must not match")
	}
	miss2, _ := r.Evaluate(endpointEvt("e3", "web01", "privilege_transition", ""))
	if miss2.Matched {
		t.Fatalf("missing level must not match")
	}
}

func TestServerBurst(t *testing.T) {
	clock := func() time.Time { return infraBase() }
	r, _ := NewServerServiceFailureBurstRule(3, 5*time.Minute, clock)
	for i := 0; i < 3; i++ {
		out, _ := r.Evaluate(serverEvt("s"+string(rune('0'+i)), "srv-01", "nginx", "failure", i))
		if i < 2 && out.Matched {
			t.Fatalf("should not fire before threshold at %d", i)
		}
		if i == 2 && !out.Matched {
			t.Fatalf("should fire at threshold")
		}
	}
	// success must not count
	if out, _ := r.Evaluate(serverEvt("sX", "srv-01", "nginx", "success", 3)); out.Matched {
		t.Fatalf("success must not count")
	}
}

func TestContainerPolicy(t *testing.T) {
	r, err := NewContainerRiskyRuntimePolicyRule(ContainerPolicy{Privileged: true, Severity: v1.Severity_SEVERITY_HIGH})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if _, err := NewContainerRiskyRuntimePolicyRule(ContainerPolicy{Privileged: true}); err == nil {
		t.Fatalf("policy without explicit severity must be rejected")
	}
	hit, _ := r.Evaluate(containerEvt("c1", "cnt-001", "nginx:1.25", true))
	if !hit.Matched {
		t.Fatalf("privileged must match")
	}
	if hit.Severity != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("outcome must repeat policy severity, got %v", hit.Severity)
	}
	miss, _ := r.Evaluate(containerEvt("c2", "cnt-002", "nginx:1.25", false))
	if miss.Matched {
		t.Fatalf("non-privileged must not match")
	}
	if _, err := NewContainerRiskyRuntimePolicyRule(ContainerPolicy{}); err == nil {
		t.Fatalf("empty policy must error")
	}
}

func TestCloudDeniedBurst(t *testing.T) {
	clock := func() time.Time { return infraBase() }
	r, _ := NewCloudDeniedActionBurstRule(3, 5*time.Minute, clock)
	for i := 0; i < 3; i++ {
		out, _ := r.Evaluate(cloudEvt("cl"+string(rune('0'+i)), "aws", "s3:GetObject", "denied", "user-01", i))
		if i < 2 && out.Matched {
			t.Fatalf("should not fire before threshold")
		}
		if i == 2 && !out.Matched {
			t.Fatalf("should fire")
		}
	}
	if out, _ := r.Evaluate(cloudEvt("clX", "aws", "s3:GetObject", "success", "user-01", 3)); out.Matched {
		t.Fatalf("success must not count")
	}
}
