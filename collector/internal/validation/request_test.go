package validation

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

var valClock = func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }

func valEvent(id, asset string, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, Source: "lab", AssetId: asset, EventType: "waf.request_blocked",
		Severity: v1.Severity_SEVERITY_HIGH, OccurredAt: timestamppb.New(valClock()),
		Attributes: attrs,
	}
}

func valDet(id string, events ...string) *v1.Detection {
	return &v1.Detection{
		Id: id, RuleId: "rule-1", RuleName: "Rule One", TelemetryEventIds: events,
		DetectedAt: timestamppb.New(valClock()), Severity: v1.Severity_SEVERITY_HIGH, Title: "T",
	}
}

func valAlert(id, detID string) *v1.Alert {
	return &v1.Alert{
		Id: id, DetectionIds: []string{detID}, Status: v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity: v1.Severity_SEVERITY_HIGH, CreatedAt: timestamppb.New(valClock()),
		UpdatedAt: timestamppb.New(valClock()), Title: "Alert: T",
	}
}

func valIncident(id, alertID string) *v1.Incident {
	return &v1.Incident{
		Id: id, AlertIds: []string{alertID}, Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		Severity: v1.Severity_SEVERITY_HIGH, CreatedAt: timestamppb.New(valClock()),
		UpdatedAt: timestamppb.New(valClock()), Title: "Incident", Summary: "1 alert(s)",
	}
}

func TestBuildRequestMapsHonestly(t *testing.T) {
	events := []*v1.TelemetryEvent{
		valEvent("e1", "asset-web-01", map[string]string{"rule_id": "WAF-XSS-01"}),
		valEvent("e2", "asset-web-01", map[string]string{}),
	}
	req, err := BuildRequest(
		valIncident("inc-1", "a1"), valAlert("a1", "d1"), valDet("d1", "e1", "e2"),
		events, valClock(),
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := contract.ValidateValidationRequest(req); err != nil {
		t.Fatalf("request must validate: %v", err)
	}
	if req.GetControlId() != "WAF-XSS-01" {
		t.Fatalf("control must come from telemetry attributes, got %q", req.GetControlId())
	}
	if req.GetTarget() != "asset-web-01" {
		t.Fatalf("target must be the observed asset, got %q", req.GetTarget())
	}
	if req.GetContext()["incident_id"] != "inc-1" || req.GetContext()["alert_id"] != "a1" ||
		req.GetContext()["detection_id"] != "d1" {
		t.Fatalf("linkage must ride in context: %v", req.GetContext())
	}
	// Deterministic id for the same inputs.
	again, _ := BuildRequest(
		valIncident("inc-1", "a1"), valAlert("a1", "d1"), valDet("d1", "e1", "e2"),
		events, valClock(),
	)
	if req.GetId() != again.GetId() {
		t.Fatal("request ids must be deterministic")
	}
}

func TestBuildRequestRefusesInvention(t *testing.T) {
	good := func() (*v1.Incident, *v1.Alert, *v1.Detection, []*v1.TelemetryEvent) {
		return valIncident("inc-1", "a1"), valAlert("a1", "d1"), valDet("d1", "e1"),
			[]*v1.TelemetryEvent{valEvent("e1", "asset-1", map[string]string{"rule_id": "C1"})}
	}
	// No control identity anywhere → explicit error, never an invented control.
	inc, alert, det, _ := good()
	noCtl := []*v1.TelemetryEvent{valEvent("e1", "asset-1", map[string]string{})}
	if _, err := BuildRequest(inc, alert, det, noCtl, valClock()); err == nil {
		t.Fatal("missing control identity must fail, not invent one")
	}
	// Unattached alert, unlinked detection, missing event, nils, zero clock.
	inc2, alert2, det2, events2 := good()
	cases := map[string]func() error{
		"unattached alert": func() error {
			_, err := BuildRequest(valIncident("inc-9", "a9"), alert2, det2, events2, valClock())
			return err
		},
		"unlinked detection": func() error {
			_, err := BuildRequest(inc2, alert2, valDet("other", "e1"), events2, valClock())
			return err
		},
		"missing event": func() error {
			_, err := BuildRequest(inc2, alert2, det2, nil, valClock())
			return err
		},
		"zero clock": func() error {
			_, err := BuildRequest(inc2, alert2, det2, events2, time.Time{})
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Fatalf("%s must fail", name)
		}
	}
	if _, err := BuildRequest(nil, alert2, det2, events2, valClock()); err == nil {
		t.Fatal("nil incident must fail")
	}
}
