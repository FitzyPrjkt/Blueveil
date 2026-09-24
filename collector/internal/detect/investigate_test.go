// RED: H1 cross-domain principal, H2 multi-stage asset timeline, H3
// forensic integrity failure. Precise wording only — no compromise
// claims, no attribution.
package detect

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func invEvt(id, typ string, minute int, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(time.Duration(minute) * time.Minute)),
		Source: "seed-lab-investigation", AssetId: "seed-inv-01", EventType: typ,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func TestCrossDomainPrincipalFires(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	r, err := NewCrossDomainPrincipalRule(2, 30*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mk := func(id, typ string, minute int, attrs map[string]string) *v1.TelemetryEvent {
		return invEvt(id, typ, minute, attrs)
	}
	var fires []Outcome
	for _, e := range []*v1.TelemetryEvent{
		mk("c1", "auth.activity", 0, map[string]string{"auth.principal": "erin", "auth.outcome": "failure"}),
		mk("c2", "identity.activity", 1, map[string]string{"identity.principal": "erin", "identity.action": "role_change"}),
		mk("c3", "data.activity", 2, map[string]string{"data.principal": "erin", "data.action": "read", "data.resource": "r"}),
	} {
		out, err := r.Evaluate(e)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if out.Matched {
			fires = append(fires, out)
		}
	}
	if len(fires) != 1 {
		t.Fatalf("want exactly one fire at second domain, got %d", len(fires))
	}
	if len(fires[0].EventIDs) != 2 {
		t.Fatalf("want both contributing events, got %v", fires[0].EventIDs)
	}
	if fires[0].Attrs["principal"] != "erin" {
		t.Fatalf("principal provenance: %+v", fires[0].Attrs)
	}
	// Single-domain principal never fires.
	r2, _ := NewCrossDomainPrincipalRule(2, 30*time.Minute, clock)
	for _, e := range []*v1.TelemetryEvent{
		mk("s1", "auth.activity", 0, map[string]string{"auth.principal": "solo", "auth.outcome": "failure"}),
		mk("s2", "auth.activity", 1, map[string]string{"auth.principal": "solo", "auth.outcome": "failure"}),
	} {
		if out, _ := r2.Evaluate(e); out.Matched {
			t.Fatalf("single domain must not fire")
		}
	}
	// Different principals never join.
	r3, _ := NewCrossDomainPrincipalRule(2, 30*time.Minute, clock)
	r3.Evaluate(mk("d1", "auth.activity", 0, map[string]string{"auth.principal": "a", "auth.outcome": "failure"}))
	if out, _ := r3.Evaluate(mk("d2", "identity.activity", 1, map[string]string{"identity.principal": "b", "identity.action": "login"})); out.Matched {
		t.Fatalf("different principals must not join")
	}
	// Window expiry re-arms.
	r4, _ := NewCrossDomainPrincipalRule(2, 5*time.Minute, clock)
	r4.Evaluate(mk("w1", "auth.activity", 0, map[string]string{"auth.principal": "x", "auth.outcome": "failure"}))
	r4.Evaluate(mk("w2", "identity.activity", 1, map[string]string{"identity.principal": "x", "identity.action": "login"}))
	r4.Evaluate(mk("w3", "data.activity", 20, map[string]string{"data.principal": "x", "data.action": "read", "data.resource": "r"}))
	if out, _ := r4.Evaluate(mk("w4", "auth.activity", 21, map[string]string{"auth.principal": "x", "auth.outcome": "failure"})); !out.Matched {
		t.Fatalf("re-arm after window expiry must fire on fresh cross-domain pair")
	}
	for _, args := range []struct {
		threshold int
		window    time.Duration
	}{{0, 5 * time.Minute}, {2, 0}, {1, 5 * time.Minute}} {
		if _, err := NewCrossDomainPrincipalRule(args.threshold, args.window, clock); err == nil {
			t.Errorf("invalid params %+v must be rejected", args)
		}
	}
	if _, err := NewCrossDomainPrincipalRule(2, 5*time.Minute, nil); err == nil {
		t.Errorf("nil clock must be rejected")
	}
}

func TestMultiStageAssetTimeline(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	r, err := NewMultiStageAssetTimelineRule(10*time.Minute, clock)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	mk := func(id, typ string, minute int, asset string) *v1.TelemetryEvent {
		e := invEvt(id, typ, minute, map[string]string{})
		e.AssetId = asset
		return e
	}
	var fires []Outcome
	for _, e := range []*v1.TelemetryEvent{
		mk("n1", "net.connection", 0, "seed-inv-01"),
		mk("h1", "http.request", 1, "seed-inv-01"),
		mk("p1", "endpoint.activity", 2, "seed-inv-01"),
	} {
		out, err := r.Evaluate(e)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if out.Matched {
			fires = append(fires, out)
		}
	}
	if len(fires) != 1 || len(fires[0].EventIDs) != 3 {
		t.Fatalf("want one 3-stage fire, got %+v", fires)
	}
	// Unlinked assets never complete.
	r2, _ := NewMultiStageAssetTimelineRule(10*time.Minute, clock)
	r2.Evaluate(mk("n9", "net.connection", 0, "asset-a"))
	r2.Evaluate(mk("h9", "http.request", 1, "asset-b"))
	if out, _ := r2.Evaluate(mk("p9", "endpoint.activity", 2, "asset-c")); out.Matched {
		t.Fatalf("unlinked assets must not complete a timeline")
	}
	// Out-of-order stages never complete.
	r3, _ := NewMultiStageAssetTimelineRule(10*time.Minute, clock)
	r3.Evaluate(mk("p8", "endpoint.activity", 0, "asset-z"))
	r3.Evaluate(mk("h8", "http.request", 1, "asset-z"))
	if out, _ := r3.Evaluate(mk("n8", "net.connection", 2, "asset-z")); out.Matched {
		t.Fatalf("reversed stages must not complete")
	}
	if _, err := NewMultiStageAssetTimelineRule(0, clock); err == nil {
		t.Errorf("zero window must be rejected")
	}
}

func TestIntegrityFailureDetections(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	r, err := NewForensicIntegrityFailureRule()
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if r.ID() != "forensic-integrity-failure" || r.Version() != "1" {
		t.Fatalf("rule identity: %s %s", r.ID(), r.Version())
	}
	// Per-event evaluation is an explicit no-op; batch computes.
	if out, err := r.Evaluate(invEvt("x", "auth.activity", 0, map[string]string{})); err != nil || out.Matched {
		t.Fatalf("per-event must be silent no-op: %+v %v", out, err)
	}
	good, err := evidence.NewItem("inc-1", "note", "ref-1", v1.EvidenceType_EVIDENCE_TYPE_NOTE, "lab", "content-one", now())
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Verify(good) {
		t.Fatalf("good item must verify")
	}
	bad := proto.Clone(good).(*v1.Evidence)
	bad.Content = "content-one-mutated"
	if evidence.Verify(bad) {
		t.Fatalf("mutated copy must fail verify")
	}
	dets, err := r.Detections([]IntegrityFailure{
		{Evidence: bad, ExpectedDigest: good.GetSha256(), TelemetryIDs: []string{"t1", "t2"}},
	}, now)
	if err != nil {
		t.Fatalf("detections: %v", err)
	}
	if len(dets) != 1 {
		t.Fatalf("want one detection per failure, got %d", len(dets))
	}
	d := dets[0]
	if d.GetRuleId() != "forensic-integrity-failure" {
		t.Fatalf("rule id: %s", d.GetRuleId())
	}
	if len(d.GetTelemetryEventIds()) != 2 {
		t.Fatalf("linkage: %v", d.GetTelemetryEventIds())
	}
	if d.GetAttributes()["evidence_id"] != good.GetId() {
		t.Fatalf("evidence provenance: %+v", d.GetAttributes())
	}
	if d.GetSeverity() != v1.Severity_SEVERITY_HIGH {
		t.Fatalf("integrity failure is HIGH by explicit policy, got %v", d.GetSeverity())
	}
	// Clean evidence yields nothing; empty telemetry linkage rejected.
	empty, err := r.Detections(nil, now)
	if err != nil || len(empty) != 0 {
		t.Fatalf("no failures must yield no detections: %+v %v", empty, err)
	}
	if _, err := r.Detections([]IntegrityFailure{{Evidence: bad, TelemetryIDs: nil}}, now); err == nil {
		t.Errorf("linkage-less failure must be rejected")
	}
	// Deterministic ids.
	again, _ := r.Detections([]IntegrityFailure{
		{Evidence: bad, ExpectedDigest: good.GetSha256(), TelemetryIDs: []string{"t2", "t1"}},
	}, now)
	if again[0].GetId() != d.GetId() {
		t.Fatalf("detection id unstable across input order")
	}
}
