package incident

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/correlate"
)

var testClock = func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }

func testEvent(id, corr string) *v1.TelemetryEvent {
	attrs := map[string]string{}
	if corr != "" {
		attrs[correlate.AttributeKey] = corr
	}
	return &v1.TelemetryEvent{
		Id: id, Source: "lab", AssetId: "asset-1", EventType: "waf.request_blocked",
		Severity: v1.Severity_SEVERITY_HIGH, OccurredAt: timestamppb.New(testClock()),
		Attributes: attrs,
	}
}

func testDetection(id string, eventIDs ...string) *v1.Detection {
	return &v1.Detection{
		Id: id, RuleId: "rule-1", RuleName: "Rule One", TelemetryEventIds: eventIDs,
		DetectedAt: timestamppb.New(testClock()), Severity: v1.Severity_SEVERITY_HIGH,
		Title: "T",
	}
}

func testAlert(id, detID string, sev v1.Severity) *v1.Alert {
	return &v1.Alert{
		Id: id, DetectionIds: []string{detID}, Status: v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity: sev, CreatedAt: timestamppb.New(testClock()), UpdatedAt: timestamppb.New(testClock()),
		Title: "Alert: T",
	}
}

func TestIngestCreatesIncident(t *testing.T) {
	mgr, err := NewManager(testClock)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	events := []*v1.TelemetryEvent{testEvent("e1", "corr-A")}
	det := testDetection("d1", "e1")
	alert := testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH)
	inc, created, err := mgr.Ingest(alert, det, events)
	if err != nil || !created {
		t.Fatalf("ingest: %+v %v %v", inc, created, err)
	}
	if err := contract.ValidateIncident(inc); err != nil {
		t.Fatalf("incident must validate: %v", err)
	}
	if inc.GetStatus() != v1.IncidentStatus_INCIDENT_STATUS_OPEN {
		t.Fatalf("new incident must be OPEN: %v", inc.GetStatus())
	}
	if len(inc.GetAlertIds()) != 1 || inc.GetAlertIds()[0] != "a1" {
		t.Fatalf("alert identity must be preserved: %v", inc.GetAlertIds())
	}
	if inc.GetSeverity() != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("severity must be preserved: %v", inc.GetSeverity())
	}
	// Deterministic id: same input in a fresh manager yields the same id.
	mgr2, _ := NewManager(testClock)
	inc2, _, _ := mgr2.Ingest(alert, det, events)
	if inc.GetId() != inc2.GetId() {
		t.Fatal("incident ids must be deterministic")
	}
}

func TestCorrelationMergesSharedGroup(t *testing.T) {
	mgr, _ := NewManager(testClock)
	e1 := testEvent("e1", "corr-A")
	e2 := testEvent("e2", "corr-A")
	inc1, c1, _ := mgr.Ingest(testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH), testDetection("d1", "e1"), []*v1.TelemetryEvent{e1})
	inc2, c2, err := mgr.Ingest(testAlert("a2", "d2", v1.Severity_SEVERITY_MEDIUM), testDetection("d2", "e2"), []*v1.TelemetryEvent{e2})
	if err != nil || !c1 || c2 {
		t.Fatalf("second same-group alert must merge: %v %v %v", inc2, c2, err)
	}
	if inc1.GetId() != inc2.GetId() {
		t.Fatal("same correlation group must share one incident")
	}
	if len(inc2.GetAlertIds()) != 2 {
		t.Fatalf("both alerts must be attached: %v", inc2.GetAlertIds())
	}
	if inc2.GetSeverity() != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("severity must be the max: %v", inc2.GetSeverity())
	}
}

func TestBaselineIsOneAlertOneIncident(t *testing.T) {
	mgr, _ := NewManager(testClock)
	// Events without an explicit correlation id: no aggressive merging.
	inc1, _, _ := mgr.Ingest(testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH), testDetection("d1", "e1"), []*v1.TelemetryEvent{testEvent("e1", "")})
	inc2, created, _ := mgr.Ingest(testAlert("a2", "d2", v1.Severity_SEVERITY_HIGH), testDetection("d2", "e1"), []*v1.TelemetryEvent{testEvent("e1", "")})
	if !created || inc1.GetId() == inc2.GetId() {
		t.Fatal("uncorrelated alerts must stay separate incidents")
	}
}

func TestReingestIsIdempotent(t *testing.T) {
	mgr, _ := NewManager(testClock)
	events := []*v1.TelemetryEvent{testEvent("e1", "corr-A")}
	alert := testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH)
	det := testDetection("d1", "e1")
	first, _, _ := mgr.Ingest(alert, det, events)
	second, created, err := mgr.Ingest(alert, det, events)
	if err != nil || created {
		t.Fatalf("re-ingest must be a no-op: %v %v", created, err)
	}
	if first.GetUpdatedAt().GetSeconds() != second.GetUpdatedAt().GetSeconds() ||
		len(second.GetAlertIds()) != 1 {
		t.Fatal("re-ingest must leave the incident untouched")
	}
}

func TestIngestRejectsBadInput(t *testing.T) {
	mgr, _ := NewManager(testClock)
	events := []*v1.TelemetryEvent{testEvent("e1", "corr-A")}
	det := testDetection("d1", "e1")
	alert := testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH)
	for name, fn := range map[string]func() error{
		"nil alert": func() error {
			_, _, err := mgr.Ingest(nil, det, events)
			return err
		},
		"unlinked detection": func() error {
			_, _, err := mgr.Ingest(alert, testDetection("other", "e1"), events)
			return err
		},
		"missing event": func() error {
			_, _, err := mgr.Ingest(alert, det, []*v1.TelemetryEvent{})
			return err
		},
		"invalid alert": func() error {
			bad := testAlert("bad", "d1", v1.Severity_SEVERITY_HIGH)
			bad.Status = v1.AlertStatus_ALERT_STATUS_UNSPECIFIED
			_, _, err := mgr.Ingest(bad, det, events)
			return err
		},
	} {
		if err := fn(); !errors.Is(err, ErrIncidentBuild) {
			t.Fatalf("%s: want ErrIncidentBuild, got %v", name, err)
		}
	}
	if _, err := NewManager(nil); err == nil {
		t.Fatal("nil clock must fail")
	}
	zeroMgr, _ := NewManager(func() time.Time { return time.Time{} })
	if _, _, err := zeroMgr.Ingest(alert, det, events); !errors.Is(err, ErrIncidentBuild) {
		t.Fatalf("zero clock: want ErrIncidentBuild, got %v", err)
	}
}

func TestLifecycleTransitions(t *testing.T) {
	mgr, _ := NewManager(testClock)
	inc, _, _ := mgr.Ingest(
		testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH),
		testDetection("d1", "e1"),
		[]*v1.TelemetryEvent{testEvent("e1", "")},
	)
	chain := []v1.IncidentStatus{
		v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING,
		v1.IncidentStatus_INCIDENT_STATUS_CONTAINED,
		v1.IncidentStatus_INCIDENT_STATUS_RESOLVED,
		v1.IncidentStatus_INCIDENT_STATUS_CLOSED,
	}
	for _, to := range chain {
		next, err := mgr.Transition(inc.GetId(), to)
		if err != nil {
			t.Fatalf("transition to %v: %v", to, err)
		}
		if next.GetStatus() != to {
			t.Fatalf("status drift: %v", next.GetStatus())
		}
		inc = next
	}
}

func TestInvalidTransitionsFail(t *testing.T) {
	mgr, _ := NewManager(testClock)
	inc, _, _ := mgr.Ingest(
		testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH),
		testDetection("d1", "e1"),
		[]*v1.TelemetryEvent{testEvent("e1", "")},
	)
	for name, to := range map[string]v1.IncidentStatus{
		"skip":     v1.IncidentStatus_INCIDENT_STATUS_RESOLVED,
		"repeat":   v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		"backward": v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		"zero":     v1.IncidentStatus_INCIDENT_STATUS_UNSPECIFIED,
	} {
		if _, err := mgr.Transition(inc.GetId(), to); !errors.Is(err, ErrIncidentTransition) {
			t.Fatalf("%s: want ErrIncidentTransition, got %v", name, err)
		}
	}
	if _, err := mgr.Transition("inc-ghost", v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("unknown id: want ErrIncidentNotFound, got %v", err)
	}
	// Terminal state stays terminal.
	id := inc.GetId()
	for _, to := range []v1.IncidentStatus{
		v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING,
		v1.IncidentStatus_INCIDENT_STATUS_CONTAINED,
		v1.IncidentStatus_INCIDENT_STATUS_RESOLVED,
		v1.IncidentStatus_INCIDENT_STATUS_CLOSED,
	} {
		var err error
		inc, err = mgr.Transition(id, to)
		if err != nil {
			t.Fatalf("walk to %v: %v", to, err)
		}
	}
	if _, err := mgr.Transition(id, v1.IncidentStatus_INCIDENT_STATUS_CLOSED); !errors.Is(err, ErrIncidentTransition) {
		t.Fatalf("terminal: want ErrIncidentTransition, got %v", err)
	}
}

func TestGetAndList(t *testing.T) {
	mgr, _ := NewManager(testClock)
	if _, ok := mgr.Get("inc-ghost"); ok {
		t.Fatal("unknown get must miss")
	}
	mgr.Ingest(testAlert("a1", "d1", v1.Severity_SEVERITY_HIGH), testDetection("d1", "e1"), []*v1.TelemetryEvent{testEvent("e1", "")})
	mgr.Ingest(testAlert("a2", "d2", v1.Severity_SEVERITY_HIGH), testDetection("d2", "e2"), []*v1.TelemetryEvent{testEvent("e2", "")})
	list := mgr.List()
	if len(list) != 2 || list[0].GetId() > list[1].GetId() {
		t.Fatalf("list must be stable id order: %v", list)
	}
	got, ok := mgr.Get(list[0].GetId())
	if !ok || got.GetId() != list[0].GetId() {
		t.Fatal("get must return the incident")
	}
}
