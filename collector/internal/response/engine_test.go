package response

import (
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

func highTriple() (*v1.Incident, *v1.Alert, *v1.Detection, []*v1.TelemetryEvent) {
	return respIncident("inc-1", "a1", v1.Severity_SEVERITY_HIGH),
		respAlert("a1", "d1", v1.Severity_SEVERITY_HIGH),
		respDet("d1", v1.Severity_SEVERITY_HIGH, "e1"),
		[]*v1.TelemetryEvent{respEvent("e1", "asset-1")}
}

func lowTriple() (*v1.Incident, *v1.Alert, *v1.Detection, []*v1.TelemetryEvent) {
	return respIncident("inc-9", "a9", v1.Severity_SEVERITY_LOW),
		respAlert("a9", "d9", v1.Severity_SEVERITY_LOW),
		respDet("d9", v1.Severity_SEVERITY_LOW, "e9"),
		[]*v1.TelemetryEvent{respEvent("e9", "asset-9")}
}

func fullEngine(t *testing.T, policy Policy, exec *SimulatedExecutor, verifier Verifier, audit *InMemoryAuditLog, clock func() time.Time) *Engine {
	t.Helper()
	eng, err := NewEngine(policy, exec, verifier, audit, clock)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

func TestFullApprovalChain(t *testing.T) {
	exec := &SimulatedExecutor{}
	audit := &InMemoryAuditLog{}
	verifier := StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "test source confirms containment"}
	eng := fullEngine(t, DefaultPolicy{}, exec, verifier, audit, respClock)

	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil || rec.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_PROPOSED {
		t.Fatalf("recommend: %+v %v", rec, err)
	}
	recID := rec.GetId()

	if _, err := eng.Decide(recID, "analyst:test"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	got, _ := eng.Get(recID)
	if got.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL {
		t.Fatalf("HIGH risk must park at PENDING_APPROVAL: %v", got.GetStatus())
	}

	// Execute before approval: refused while PENDING_APPROVAL, executor untouched.
	if _, err := eng.Execute(recID); !errors.Is(err, ErrResponseState) {
		t.Fatalf("want ErrResponseState pre-approval, got %v", err)
	}
	if len(exec.Calls()) != 0 {
		t.Fatal("executor must not run before approval")
	}

	appr, err := eng.Approve(recID, "test-actor:lead", "proportional to HIGH incident", time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if appr.GetApprover() != "test-actor:lead" {
		t.Fatalf("approver identity must be preserved: %+v", appr)
	}

	executed, err := eng.Execute(recID)
	if err != nil || !executed.GetSuccess() {
		t.Fatalf("execute: %+v %v", executed, err)
	}
	if executed.GetApprovalId() != appr.GetId() {
		t.Fatalf("execution must cite its approval: %+v", executed)
	}

	ver, err := eng.Verify(recID)
	if err != nil || ver.GetOutcome() != v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED {
		t.Fatalf("verify: %+v %v", ver, err)
	}
	final, _ := eng.Get(recID)
	if final.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_VERIFIED {
		t.Fatalf("terminal status: %v", final.GetStatus())
	}
	if err := contract.ValidateResponseRecommendation(final); err != nil {
		t.Fatalf("final record must validate: %v", err)
	}

	want := []AuditDecision{AuditRecommended, AuditApprovalRequired, AuditApproved, AuditExecuted, AuditVerified}
	entries := audit.Entries()
	if len(entries) != len(want) {
		t.Fatalf("want %d audit entries, got %d", len(want), len(entries))
	}
	for i, w := range want {
		if entries[i].Decision != w || entries[i].ResponseID != recID {
			t.Fatalf("audit[%d] drift: %+v", i, entries[i])
		}
	}
}

func TestAllowDirectChainEndsUnknown(t *testing.T) {
	exec := &SimulatedExecutor{}
	audit := &InMemoryAuditLog{}
	eng := fullEngine(t, DefaultPolicy{}, exec, UnknownVerifier{}, audit, respClock)

	inc, alert, det, events := lowTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); err != nil {
		t.Fatal(err)
	}
	got, _ := eng.Get(rec.GetId())
	if got.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_APPROVED {
		t.Fatalf("LOW read-only allows directly: %v", got.GetStatus())
	}
	if _, ok := eng.Approval(rec.GetId()); ok {
		t.Fatal("policy-allowed path creates no approval artifact")
	}
	if _, err := eng.Execute(rec.GetId()); err != nil {
		t.Fatalf("automatic gate must pass: %v", err)
	}
	ver, err := eng.Verify(rec.GetId())
	if err != nil || ver.GetOutcome() != v1.VerificationOutcome_VERIFICATION_OUTCOME_UNKNOWN {
		t.Fatalf("no source → UNKNOWN: %+v %v", ver, err)
	}
	final, _ := eng.Get(rec.GetId())
	if final.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_VERIFICATION_UNKNOWN {
		t.Fatalf("terminal: %v", final.GetStatus())
	}
}

func TestDenyChainNeverReachesExecutor(t *testing.T) {
	exec := &SimulatedExecutor{}
	audit := &InMemoryAuditLog{}
	eng := fullEngine(t, StaticDenyAll(), exec, UnknownVerifier{}, audit, respClock)

	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("want ErrPolicyDenied, got %v", err)
	}
	got, _ := eng.Get(rec.GetId())
	if got.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_DENIED {
		t.Fatalf("denied status must persist: %v", got.GetStatus())
	}
	if _, err := eng.Execute(rec.GetId()); err == nil {
		t.Fatal("denied requests must never execute")
	}
	if len(exec.Calls()) != 0 {
		t.Fatal("executor must stay untouched after deny")
	}
	entries := audit.Entries()
	if len(entries) != 2 || entries[1].Decision != AuditDenied {
		t.Fatalf("deny must be audited: %+v", entries)
	}
}

func TestFailedExecutionVerifiesFailed(t *testing.T) {
	exec := &SimulatedExecutor{Fail: map[v1.OperationType]bool{
		v1.OperationType_OPERATION_TYPE_RECOMMEND: true,
	}}
	audit := &InMemoryAuditLog{}
	eng := fullEngine(t, StaticAllowAll(), exec,
		StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "would-be"},
		audit, respClock)

	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	// StaticAllowAll removes the policy objection, but the HIGH-risk gate
	// still parks the request: approve explicitly, then execute.
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:lead", "test", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(rec.GetId()); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("want ErrExecutionFailed, got %v", err)
	}
	ver, err := eng.Verify(rec.GetId())
	if err != nil || ver.GetOutcome() != v1.VerificationOutcome_VERIFICATION_OUTCOME_FAILED {
		t.Fatalf("failed execution verifies FAILED, never inherited VERIFIED: %+v %v", ver, err)
	}
}

func TestExpiredApprovalRejects(t *testing.T) {
	now := respClock()
	clock := func() time.Time { return now }
	exec := &SimulatedExecutor{}
	eng := fullEngine(t, DefaultPolicy{}, exec, UnknownVerifier{}, &InMemoryAuditLog{}, clock)

	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:lead", "ok", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour) // approval expired
	if _, err := eng.Execute(rec.GetId()); !errors.Is(err, ErrApprovalInvalid) {
		t.Fatalf("want ErrApprovalInvalid on expiry, got %v", err)
	}
}

func TestOutOfOrderAndUnknownCallsFail(t *testing.T) {
	exec := &SimulatedExecutor{}
	eng := fullEngine(t, StaticAllowAll(), exec, UnknownVerifier{}, &InMemoryAuditLog{}, respClock)

	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	// Execute before decide.
	if _, err := eng.Execute(rec.GetId()); err == nil {
		t.Fatal("execute before decide must fail")
	}
	// Approve without a pending state.
	if _, err := eng.Approve(rec.GetId(), "x", "y", 0); err == nil {
		t.Fatal("approve outside PENDING_APPROVAL must fail")
	}
	// Verify before execute.
	if _, err := eng.Verify(rec.GetId()); err == nil {
		t.Fatal("verify before execute must fail")
	}
	// Unknown ids everywhere.
	if _, err := eng.Decide("rec-ghost", "a"); err == nil {
		t.Fatal("unknown decide must fail")
	}
	if _, err := eng.Execute("rec-ghost"); err == nil {
		t.Fatal("unknown execute must fail")
	}
	// Happy path then double-execute and post-terminal calls. HIGH parks
	// at PENDING_APPROVAL even under StaticAllowAll (gate rule), so approve.
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:lead", "test", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(rec.GetId()); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(rec.GetId()); err == nil {
		t.Fatal("double execute must fail")
	}
	if _, err := eng.Verify(rec.GetId()); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); err == nil {
		t.Fatal("terminal requests reject further calls")
	}
	if _, err := NewEngine(nil, exec, UnknownVerifier{}, &InMemoryAuditLog{}, respClock); err == nil {
		t.Fatal("nil policy must fail construction")
	}
}
