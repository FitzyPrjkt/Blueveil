package evidence

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

var evClock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func evEvent(id string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, Source: "lab", AssetId: "asset-1", EventType: "waf.request_blocked",
		Severity: v1.Severity_SEVERITY_HIGH, OccurredAt: timestamppb.New(evClock),
	}
}

func evDetection() *v1.Detection {
	return &v1.Detection{
		Id: "d1", RuleId: "rule-1", RuleName: "Rule One", TelemetryEventIds: []string{"e1", "e2"},
		DetectedAt: timestamppb.New(evClock), Severity: v1.Severity_SEVERITY_HIGH, Title: "T",
	}
}

func evAlert() *v1.Alert {
	return &v1.Alert{
		Id: "a1", DetectionIds: []string{"d1"}, Status: v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity: v1.Severity_SEVERITY_HIGH, CreatedAt: timestamppb.New(evClock),
		UpdatedAt: timestamppb.New(evClock), Title: "Alert: T",
	}
}

func TestBuildCapturesProvenance(t *testing.T) {
	events := []*v1.TelemetryEvent{evEvent("e1"), evEvent("e2")}
	out, err := BuildForAlert("inc-1", evAlert(), evDetection(), events, evClock)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(out) != 4 { // 2 events + detection + alert
		t.Fatalf("want 4 evidence items, got %d", len(out))
	}
	byRef := map[string]*v1.Evidence{}
	for _, e := range out {
		if err := contract.ValidateEvidence(e); err != nil {
			t.Fatalf("evidence must validate: %v", err)
		}
		if e.GetIncidentId() != "inc-1" {
			t.Fatalf("incident linkage broken: %+v", e)
		}
		if !Verify(e) {
			t.Fatalf("fresh evidence must verify: %s", e.GetId())
		}
		byRef[e.GetId()] = e
	}
	if len(byRef) != 4 {
		t.Fatal("evidence ids must be unique and deterministic")
	}
	// Deterministic: same inputs, same ids.
	again, _ := BuildForAlert("inc-1", evAlert(), evDetection(), events, evClock)
	for i := range out {
		if out[i].GetId() != again[i].GetId() || out[i].GetSha256() != again[i].GetSha256() {
			t.Fatal("evidence build must be deterministic")
		}
	}
	// Kind mapping: events are excerpts, decisions are notes.
	kinds := map[v1.EvidenceType]int{}
	for _, e := range out {
		kinds[e.GetType()]++
	}
	if kinds[v1.EvidenceType_EVIDENCE_TYPE_LOG_EXCERPT] != 2 ||
		kinds[v1.EvidenceType_EVIDENCE_TYPE_NOTE] != 2 {
		t.Fatalf("kind mapping drift: %v", kinds)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	out, err := BuildForAlert("inc-1", evAlert(), evDetection(), []*v1.TelemetryEvent{evEvent("e1"), evEvent("e2")}, evClock)
	if err != nil {
		t.Fatal(err)
	}
	mutated := proto.Clone(out[0]).(*v1.Evidence)
	mutated.Content += " (edited by an attacker)"
	if Verify(mutated) {
		t.Fatal("tampered content must fail verification")
	}
	if Verify(nil) {
		t.Fatal("nil must not verify")
	}
	stripped := proto.Clone(out[0]).(*v1.Evidence)
	stripped.Sha256 = ""
	if Verify(stripped) {
		t.Fatal("missing digest must not verify")
	}
}

func TestBuildRejectsGaps(t *testing.T) {
	events := []*v1.TelemetryEvent{evEvent("e1"), evEvent("e2")}
	cases := map[string]func() error{
		"empty incident": func() error {
			_, err := BuildForAlert("", evAlert(), evDetection(), events, evClock)
			return err
		},
		"nil alert": func() error {
			_, err := BuildForAlert("inc-1", nil, evDetection(), events, evClock)
			return err
		},
		"unlinked detection": func() error {
			det := evDetection()
			det.Id = "other"
			_, err := BuildForAlert("inc-1", evAlert(), det, events, evClock)
			return err
		},
		"missing event": func() error {
			_, err := BuildForAlert("inc-1", evAlert(), evDetection(), events[:1], evClock)
			return err
		},
		"zero clock": func() error {
			_, err := BuildForAlert("inc-1", evAlert(), evDetection(), events, time.Time{})
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil || !strings.Contains(err.Error(), "evidence: construction failure") {
			t.Fatalf("%s must fail construction, got %v", name, err)
		}
	}
}

func TestStoreDedupesAndOrders(t *testing.T) {
	store := NewStore()
	out, err := BuildForAlert("inc-1", evAlert(), evDetection(), []*v1.TelemetryEvent{evEvent("e1"), evEvent("e2")}, evClock)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range out {
		if !store.Add(e) {
			t.Fatalf("first add must succeed: %s", e.GetId())
		}
	}
	if store.Add(out[0]) {
		t.Fatal("duplicate add must report false")
	}
	if store.Count() != 4 {
		t.Fatalf("count: %d", store.Count())
	}
	list := store.List()
	for i := 1; i < len(list); i++ {
		if list[i-1].GetId() >= list[i].GetId() {
			t.Fatal("list must be stable id order")
		}
	}
	if _, ok := store.Get(list[0].GetId()); !ok {
		t.Fatal("get must hit")
	}
	if _, ok := store.Get("ev-ghost"); ok {
		t.Fatal("get must miss")
	}
}
