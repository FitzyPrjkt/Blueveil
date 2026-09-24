package response

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

// Security invariants: these matter more than polish. Each is a named,
// independently-failing assertion over the engine's observable behavior.
func invariantEngine(t *testing.T) (*Engine, *SimulatedExecutor, string) {
	t.Helper()
	exec := &SimulatedExecutor{}
	eng, err := NewEngine(DefaultPolicy{}, exec, UnknownVerifier{}, &InMemoryAuditLog{}, respClock)
	if err != nil {
		t.Fatal(err)
	}
	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	return eng, exec, rec.GetId()
}

func TestInvariantDetectionsAlertsIncidentsNeverAuthorize(t *testing.T) {
	eng, _, recID := invariantEngine(t)
	// Only recommendation ids open the gated path. Detection, alert and
	// incident ids are different namespaces and must all miss.
	for _, foreign := range []string{"d1", "a1", "inc-1", "e1", ""} {
		if _, err := eng.Decide(foreign, "analyst:test"); err == nil {
			t.Fatalf("foreign id %q must never decide", foreign)
		}
		if _, err := eng.Execute(foreign); err == nil {
			t.Fatalf("foreign id %q must never execute", foreign)
		}
	}
	// Sanity: the real recommendation id does open the path.
	if _, err := eng.Decide(recID, "analyst:test"); err != nil {
		t.Fatalf("genuine recommendation must decide: %v", err)
	}
}

func TestInvariantRecommendationNeverEqualsExecution(t *testing.T) {
	eng, exec, recID := invariantEngine(t)
	// A fresh PROPOSED recommendation is not executable, period.
	if _, err := eng.Execute(recID); err == nil {
		t.Fatal("PROPOSED must never execute")
	}
	if len(exec.Calls()) != 0 {
		t.Fatal("nothing may reach the executor pre-authorization")
	}
	got, _ := eng.Get(recID)
	if got.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_PROPOSED {
		t.Fatal("un-decided recommendation stays PROPOSED")
	}
}

func TestInvariantPolicyDenyNeverReachesExecutor(t *testing.T) {
	exec := &SimulatedExecutor{}
	eng, err := NewEngine(StaticDenyAll(), exec, UnknownVerifier{}, &InMemoryAuditLog{}, respClock)
	if err != nil {
		t.Fatal(err)
	}
	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = eng.Decide(rec.GetId(), "analyst:test")
	_, _ = eng.Execute(rec.GetId())
	_, _ = eng.Verify(rec.GetId())
	if len(exec.Calls()) != 0 {
		t.Fatalf("DENY leaked %d calls to the executor", len(exec.Calls()))
	}
}

func TestInvariantApprovalForOneRequestCannotAuthorizeAnother(t *testing.T) {
	now := respClock()
	recA := &v1.ResponseRecommendation{
		Id: "rec-A", IncidentId: "inc-A", Operation: v1.OperationType_OPERATION_TYPE_BLOCK,
		Target: "target-A", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Reason: "r",
		Status:        v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL,
		RecommendedAt: timestamppb.New(now), RecommendedBy: RecommenderName,
	}
	recB := &v1.ResponseRecommendation{
		Id: "rec-B", IncidentId: "inc-B", Operation: v1.OperationType_OPERATION_TYPE_DELETE,
		Target: "target-B", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Reason: "r",
		Status:        v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL,
		RecommendedAt: timestamppb.New(now), RecommendedBy: RecommenderName,
	}
	appr, err := Grant(recA, "test-actor:lead", "only A", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if Covers(appr, recB, now) {
		t.Fatal("approval for BLOCK target-A must not authorize DELETE target-B")
	}
	sameID := proto.Clone(recA).(*v1.ResponseRecommendation)
	sameID.Target = "target-A2"
	if Covers(appr, sameID, now) {
		t.Fatal("approval must not cover a retargeted request")
	}
}

func TestInvariantExecutionFailureNeverBecomesSuccess(t *testing.T) {
	exec := &SimulatedExecutor{Fail: map[v1.OperationType]bool{
		v1.OperationType_OPERATION_TYPE_RECOMMEND: true,
	}}
	eng, err := NewEngine(StaticAllowAll(), exec,
		StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "lying source"},
		&InMemoryAuditLog{}, respClock)
	if err != nil {
		t.Fatal(err)
	}
	inc, alert, det, events := highTriple()
	rec, _ := eng.Recommend(inc, alert, det, events)
	_, _ = eng.Decide(rec.GetId(), "analyst:test")
	_, _ = eng.Execute(rec.GetId())
	ver, _ := eng.Verify(rec.GetId())
	if ver.GetOutcome() == v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED {
		t.Fatal("failed execution must never verify VERIFIED, even with a lying verifier")
	}
	final, _ := eng.Get(rec.GetId())
	if final.GetStatus() == v1.ResponseStatus_RESPONSE_STATUS_VERIFIED ||
		final.GetStatus() == v1.ResponseStatus_RESPONSE_STATUS_EXECUTED {
		t.Fatalf("terminal status must record failure: %v", final.GetStatus())
	}
}

func TestInvariantUnknownVerificationNeverBecomesVerified(t *testing.T) {
	eng, _, recID := invariantEngine(t)
	// HIGH path parks for approval; drive it fully with the honest verifier.
	if _, err := eng.Decide(recID, "analyst:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(recID, "test-actor:lead", "ok", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(recID); err != nil {
		t.Fatal(err)
	}
	ver, err := eng.Verify(recID)
	if err != nil || ver.GetOutcome() != v1.VerificationOutcome_VERIFICATION_OUTCOME_UNKNOWN {
		t.Fatalf("honest default is UNKNOWN: %+v %v", ver, err)
	}
	final, _ := eng.Get(recID)
	if final.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_VERIFICATION_UNKNOWN {
		t.Fatalf("status must say UNKNOWN: %v", final.GetStatus())
	}
}

func TestInvariantApprovalReplayRejected(t *testing.T) {
	eng, _, recID := invariantEngine(t)
	if _, err := eng.Decide(recID, "analyst:test"); err != nil {
		t.Fatal(err)
	}
	appr, err := eng.Approve(recID, "test-actor:lead", "ok", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(recID); err != nil {
		t.Fatal(err)
	}
	// The approval is consumed: executing again fails (already-executed),
	// and the artifact still covers only its own request.
	if _, err := eng.Execute(recID); err == nil {
		t.Fatal("second execution with a consumed approval must fail")
	}
	rec, _ := eng.Get(recID)
	if !Covers(appr, rec, respClock()) {
		t.Fatal("consumed approval still describes its own request (no silent invalidation)")
	}
	other := proto.Clone(rec).(*v1.ResponseRecommendation)
	other.Id = "rec-other"
	if Covers(appr, other, respClock()) {
		t.Fatal("consumed approval must not stretch to another request")
	}
}

func TestInvariantApprovalMismatchRejected(t *testing.T) {
	eng, _, recID := invariantEngine(t)
	if _, err := eng.Decide(recID, "analyst:test"); err != nil {
		t.Fatal(err)
	}
	// Grant directly (bypassing the engine) for a DIFFERENT request: the
	// engine holds its own approval, so this only proves Covers — the
	// engine path is covered by the expiry test in engine_test.go.
	now := respClock()
	appr, err := Grant(&v1.ResponseRecommendation{
		Id: "rec-ghost", IncidentId: "inc-g", Operation: v1.OperationType_OPERATION_TYPE_BLOCK,
		Target: "target-g", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Reason: "r",
		Status:        v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL,
		RecommendedAt: timestamppb.New(now), RecommendedBy: RecommenderName,
	}, "test-actor:lead", "ghost approval", now, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := eng.Get(recID)
	if Covers(appr, rec, now) {
		t.Fatal("foreign approval must not cover this request")
	}
}
