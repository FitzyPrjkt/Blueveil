// Response-stage integration: pipeline outputs (incident + alert +
// detection + events) driven through the gated response path — full chain
// plus the deny and missing-approval negatives. The pipeline itself stops
// at evidence; response is explicit API calls, never automatic execution.
package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/incident"
	"blueveil/collector/internal/response"
	"blueveil/collector/internal/source"
)

func responseHarness(t *testing.T) (*incident.Manager, *detect.Store, *InMemorySink) {
	t.Helper()
	ctx := context.Background()
	src := source.NewChannelSource(8)
	mem := &InMemorySink{}
	pipe, detStore, mgr, _ := wireIncidentStage(t, src, mem, mem)
	go func() {
		_ = src.Inject(ctx, incRaw("e1", "asset-web-01", "waf.request_blocked", "SEVERITY_HIGH", 0))
		_ = src.Stop()
	}()
	if _, err := pipe.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(mgr.List()) != 1 {
		t.Fatalf("harness must yield one incident, got %d", len(mgr.List()))
	}
	return mgr, detStore, mem
}

// resolveTriple re-materializes the (alert, detection, events) behind an
// incident's first alert from the in-memory stores. In production this
// lookup crosses the persistence boundary; here the stores stand in.
func resolveTriple(t *testing.T, dets *detect.Store, mem *InMemorySink, inc *v1.Incident) (*v1.Alert, *v1.Detection, []*v1.TelemetryEvent) {
	t.Helper()
	alertByID := map[string]*v1.Alert{}
	for _, a := range dets.Alerts() {
		alertByID[a.GetId()] = a
	}
	detByID := map[string]*v1.Detection{}
	for _, d := range dets.Detections() {
		detByID[d.GetId()] = d
	}
	eventByID := map[string]*v1.TelemetryEvent{}
	for _, e := range mem.Events() {
		eventByID[e.GetId()] = e
	}
	alert, ok := alertByID[inc.GetAlertIds()[0]]
	if !ok {
		t.Fatalf("alert %q not stored", inc.GetAlertIds()[0])
	}
	det, ok := detByID[alert.GetDetectionIds()[0]]
	if !ok {
		t.Fatalf("detection %q not stored", alert.GetDetectionIds()[0])
	}
	var events []*v1.TelemetryEvent
	for _, id := range det.GetTelemetryEventIds() {
		e, ok := eventByID[id]
		if !ok {
			t.Fatalf("event %q not stored", id)
		}
		events = append(events, e)
	}
	return alert, det, events
}

func responseEngine(t *testing.T, policy response.Policy, exec *response.SimulatedExecutor, verifier response.Verifier, audit *response.InMemoryAuditLog) *response.Engine {
	t.Helper()
	eng, err := response.NewEngine(policy, exec, verifier, audit, incidentClock)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return eng
}

func TestIncidentToVerifiedResponse(t *testing.T) {
	mgr, dets, mem := responseHarness(t)
	inc := mgr.List()[0]
	alert, det, events := resolveTriple(t, dets, mem, inc)

	exec := &response.SimulatedExecutor{}
	audit := &response.InMemoryAuditLog{}
	verifier := response.StaticVerifier{
		Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED,
		Detail:  "test source confirms",
	}
	eng := responseEngine(t, response.DefaultPolicy{}, exec, verifier, audit)

	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatalf("recommend: %v", err)
	}
	if rec.GetOperation() != v1.OperationType_OPERATION_TYPE_RECOMMEND {
		t.Fatalf("HIGH incident proposes review, got %v", rec.GetOperation())
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:pipeline-test"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:pipeline-lead", "proportional", time.Hour); err != nil {
		t.Fatalf("approve: %v", err)
	}
	executed, err := eng.Execute(rec.GetId())
	if err != nil || !executed.GetSuccess() {
		t.Fatalf("execute: %+v %v", executed, err)
	}
	// The executor saw exactly the authorized read-only operation on the
	// incident's target — nothing else, nothing destructive.
	calls := exec.Calls()
	if len(calls) != 1 || calls[0].Target != rec.GetTarget() ||
		calls[0].Operation != v1.OperationType_OPERATION_TYPE_RECOMMEND {
		t.Fatalf("executor call drift: %+v", calls)
	}
	ver, err := eng.Verify(rec.GetId())
	if err != nil || ver.GetOutcome() != v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED {
		t.Fatalf("verify: %+v %v", ver, err)
	}
	final, _ := eng.Get(rec.GetId())
	if final.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_VERIFIED {
		t.Fatalf("terminal: %v", final.GetStatus())
	}
	if err := contract.ValidateResponseRecommendation(final); err != nil {
		t.Fatalf("final record must validate: %v", err)
	}
	// Full audit trail in order.
	want := []response.AuditDecision{
		response.AuditRecommended, response.AuditApprovalRequired,
		response.AuditApproved, response.AuditExecuted, response.AuditVerified,
	}
	entries := audit.Entries()
	if len(entries) != len(want) {
		t.Fatalf("want %d audit entries, got %d", len(want), len(entries))
	}
	for i, w := range want {
		if entries[i].Decision != w || entries[i].ResponseID != rec.GetId() {
			t.Fatalf("audit[%d]: %+v", i, entries[i])
		}
	}
}

func TestResponseDenyAndMissingApprovalNegatives(t *testing.T) {
	mgr, dets, mem := responseHarness(t)
	inc := mgr.List()[0]
	alert, det, events := resolveTriple(t, dets, mem, inc)

	// DENY: decided, recorded, never executed.
	denyExec := &response.SimulatedExecutor{}
	denyEng := responseEngine(t, response.StaticDenyAll(), denyExec, response.UnknownVerifier{}, &response.InMemoryAuditLog{})
	rec, err := denyEng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denyEng.Decide(rec.GetId(), "analyst:pipeline-test"); !errors.Is(err, response.ErrPolicyDenied) {
		t.Fatalf("want ErrPolicyDenied, got %v", err)
	}
	if _, err := denyEng.Execute(rec.GetId()); err == nil {
		t.Fatal("denied must never execute")
	}
	if len(denyExec.Calls()) != 0 {
		t.Fatal("executor untouched after deny")
	}

	// Missing approval: parked HIGH request cannot jump to execution.
	exec := &response.SimulatedExecutor{}
	eng := responseEngine(t, response.DefaultPolicy{}, exec, response.UnknownVerifier{}, &response.InMemoryAuditLog{})
	rec2, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec2.GetId(), "analyst:pipeline-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(rec2.GetId()); err == nil {
		t.Fatal("execution without the required approval must fail")
	}
	if len(exec.Calls()) != 0 {
		t.Fatal("executor untouched without approval")
	}
}
