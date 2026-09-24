// RED: deterministic cross-domain timeline with provenance and stable
// tie-breaking. Temporal order is presentation, never causality.
package investigate

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func tlEvt(id, typ, source, asset string, minute int, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(time.Duration(minute) * time.Minute)),
		Source: source, AssetId: asset, EventType: typ, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func TestTimelineOrdersAcrossDomains(t *testing.T) {
	evts := []*v1.TelemetryEvent{
		tlEvt("t3", "http.request", "s", "a", 2, map[string]string{"auth.principal": "x"}),
		tlEvt("t1", "auth.activity", "s", "a", 0, map[string]string{"auth.principal": "erin"}),
		tlEvt("t2", "net.connection", "s", "a", 1, map[string]string{}),
	}
	entries, err := BuildTimeline(TimelineInput{Events: evts})
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(entries) != 3 || entries[0].ID != "t1" || entries[1].ID != "t2" || entries[2].ID != "t3" {
		t.Fatalf("occurred_at order violated: %+v", entries)
	}
	if entries[0].Kind != "telemetry" || entries[0].Source != "s" || entries[0].AssetID != "a" {
		t.Fatalf("provenance missing: %+v", entries[0])
	}
	if entries[0].Principal != "erin" {
		t.Fatalf("principal where safe: %+v", entries[0])
	}
}

func TestTimelineTieBreakStable(t *testing.T) {
	evts := []*v1.TelemetryEvent{
		tlEvt("b", "net.connection", "s", "a", 0, map[string]string{}),
		tlEvt("a", "auth.activity", "s", "a", 0, map[string]string{}),
	}
	one, err := BuildTimeline(TimelineInput{Events: evts})
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildTimeline(TimelineInput{Events: []*v1.TelemetryEvent{evts[1], evts[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 2 || one[0].ID != "a" || two[0].ID != "a" {
		t.Fatalf("tie-break must be stable id order regardless of input order: %+v %+v", one, two)
	}
}

func TestTimelineIncludesDetectionsAndEvidence(t *testing.T) {
	evts := []*v1.TelemetryEvent{
		tlEvt("t1", "auth.activity", "s", "a", 0, map[string]string{}),
	}
	dets := []*v1.Detection{{
		Id: "det-1", RuleId: "r", RuleName: "rn", TelemetryEventIds: []string{"t1"},
		DetectedAt: timestamppb.New(time.Date(2026, 9, 12, 9, 5, 0, 0, time.UTC)),
		Severity:   v1.Severity_SEVERITY_INFO, Confidence: 0, Title: "T", Description: "D",
	}}
	alerts := []*v1.Alert{{
		Id: "alert-1", DetectionIds: []string{"det-1"}, Status: v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity:  v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(time.Date(2026, 9, 12, 9, 6, 0, 0, time.UTC)),
		UpdatedAt: timestamppb.New(time.Date(2026, 9, 12, 9, 6, 0, 0, time.UTC)),
		Title:     "A",
	}}
	entries, err := BuildTimeline(TimelineInput{Events: evts, Detections: dets, Alerts: alerts})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want telemetry+detection+alert, got %+v", entries)
	}
	if entries[1].Kind != "detection" || entries[1].RuleID != "r" {
		t.Fatalf("detection provenance: %+v", entries[1])
	}
	if entries[2].Kind != "alert" {
		t.Fatalf("alert entry: %+v", entries[2])
	}
}

func TestTimelineCorruptFailsClosed(t *testing.T) {
	evts := []*v1.TelemetryEvent{
		tlEvt("t1", "auth.activity", "s", "a", 0, map[string]string{}),
	}
	evts[0].OccurredAt = nil
	if _, err := BuildTimeline(TimelineInput{Events: evts}); err == nil {
		t.Errorf("corrupt event must fail closed")
	}
}
