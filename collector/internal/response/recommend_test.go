package response

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

var respClock = func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }

func respEvent(id, asset string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, Source: "lab", AssetId: asset, EventType: "waf.request_blocked",
		Severity: v1.Severity_SEVERITY_HIGH, OccurredAt: timestamppb.New(respClock()),
	}
}

func respDet(id string, sev v1.Severity, events ...string) *v1.Detection {
	return &v1.Detection{
		Id: id, RuleId: "rule-1", RuleName: "Rule One", TelemetryEventIds: events,
		DetectedAt: timestamppb.New(respClock()), Severity: sev, Title: "T",
	}
}

func respAlert(id, detID string, sev v1.Severity) *v1.Alert {
	return &v1.Alert{
		Id: id, DetectionIds: []string{detID}, Status: v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity: sev, CreatedAt: timestamppb.New(respClock()), UpdatedAt: timestamppb.New(respClock()),
		Title: "Alert: T",
	}
}

func respIncident(id, alertID string, sev v1.Severity) *v1.Incident {
	return &v1.Incident{
		Id: id, AlertIds: []string{alertID}, Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		Severity: sev, CreatedAt: timestamppb.New(respClock()), UpdatedAt: timestamppb.New(respClock()),
		Title: "Incident: Alert: T", Summary: "1 alert(s)",
	}
}

func TestRecommendBuildsReadOnlyProposal(t *testing.T) {
	r, err := NewRecommender(respClock)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	rec, err := r.Recommend(
		respIncident("inc-1", "a1", v1.Severity_SEVERITY_HIGH),
		respAlert("a1", "d1", v1.Severity_SEVERITY_HIGH),
		respDet("d1", v1.Severity_SEVERITY_HIGH, "e1"),
		[]*v1.TelemetryEvent{respEvent("e1", "asset-1")},
	)
	if err != nil {
		t.Fatalf("recommend: %v", err)
	}
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		t.Fatalf("recommendation must validate: %v", err)
	}
	if rec.GetOperation() != v1.OperationType_OPERATION_TYPE_RECOMMEND {
		t.Fatalf("HIGH incident proposes review, got %v", rec.GetOperation())
	}
	if rec.GetRisk() != v1.RiskLevel_RISK_LEVEL_HIGH || !rec.GetApprovalRequired() {
		t.Fatalf("risk/flag drift: %v %v", rec.GetRisk(), rec.GetApprovalRequired())
	}
	if rec.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_PROPOSED {
		t.Fatalf("new proposals are PROPOSED: %v", rec.GetStatus())
	}
	if rec.GetTarget() != "asset-1" || rec.GetIncidentId() != "inc-1" {
		t.Fatalf("target/linkage drift: %+v", rec)
	}
	// Deterministic id for the pair.
	r2, _ := NewRecommender(respClock)
	rec2, _ := r2.Recommend(
		respIncident("inc-1", "a1", v1.Severity_SEVERITY_HIGH),
		respAlert("a1", "d1", v1.Severity_SEVERITY_HIGH),
		respDet("d1", v1.Severity_SEVERITY_HIGH, "e1"),
		[]*v1.TelemetryEvent{respEvent("e1", "asset-1")},
	)
	if rec.GetId() != rec2.GetId() {
		t.Fatal("recommendation ids must be deterministic")
	}
}

func TestRecommendNeverProposesDestruction(t *testing.T) {
	r, _ := NewRecommender(respClock)
	for _, sev := range []v1.Severity{
		v1.Severity_SEVERITY_INFO, v1.Severity_SEVERITY_LOW,
		v1.Severity_SEVERITY_MEDIUM, v1.Severity_SEVERITY_HIGH,
		v1.Severity_SEVERITY_CRITICAL,
	} {
		rec, err := r.Recommend(
			respIncident("inc-1", "a1", sev),
			respAlert("a1", "d1", sev),
			respDet("d1", sev, "e1"),
			[]*v1.TelemetryEvent{respEvent("e1", "asset-1")},
		)
		if err != nil {
			t.Fatalf("severity %v: %v", sev, err)
		}
		switch rec.GetOperation() {
		case v1.OperationType_OPERATION_TYPE_OBSERVE,
			v1.OperationType_OPERATION_TYPE_ANALYZE,
			v1.OperationType_OPERATION_TYPE_RECOMMEND:
		default:
			t.Fatalf("severity %v proposed destructive %v", sev, rec.GetOperation())
		}
	}
}

func TestRecommendRejectsBadInput(t *testing.T) {
	r, _ := NewRecommender(respClock)
	inc := respIncident("inc-1", "a1", v1.Severity_SEVERITY_HIGH)
	alert := respAlert("a1", "d1", v1.Severity_SEVERITY_HIGH)
	det := respDet("d1", v1.Severity_SEVERITY_HIGH, "e1")
	events := []*v1.TelemetryEvent{respEvent("e1", "asset-1")}
	if _, err := r.Recommend(nil, alert, det, events); err == nil {
		t.Fatal("nil incident must fail")
	}
	if _, err := r.Recommend(inc, respAlert("other", "d1", v1.Severity_SEVERITY_HIGH), det, events); err == nil {
		t.Fatal("unattached alert must fail")
	}
	if _, err := r.Recommend(inc, alert, det, nil); err == nil {
		t.Fatal("missing target must fail")
	}
	broken, _ := NewRecommender(func() time.Time { return time.Time{} })
	if _, err := broken.Recommend(inc, alert, det, events); err == nil {
		t.Fatal("zero clock must fail")
	}
	if _, err := NewRecommender(nil); err == nil {
		t.Fatal("nil clock must fail")
	}
}
