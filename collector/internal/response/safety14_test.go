// Step 14E: safety/authorization boundary invariants at the engine
// level. Approval replay, expiry, operation/risk gating, and the
// detection≠authorization split are proven here, not just at the Covers
// helper level.
package response

import (
	"errors"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

func decideHigh(t *testing.T, eng *Engine) string {
	t.Helper()
	inc, alert, det, events := highTriple()
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); err != nil {
		t.Fatal(err)
	}
	got, _ := eng.Get(rec.GetId())
	if got.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL {
		t.Fatalf("HIGH must park at PENDING_APPROVAL: %v", got.GetStatus())
	}
	return rec.GetId()
}

func TestApprovalReplayRejected(t *testing.T) {
	exec := &SimulatedExecutor{}
	audit := &InMemoryAuditLog{}
	verifier := StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "t"}
	eng := fullEngine(t, DefaultPolicy{}, exec, verifier, audit, respClock)
	recID := decideHigh(t, eng)
	if _, err := eng.Approve(recID, "test-actor:lead", "first approval", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Replayed approval (same or different actor) is rejected: the
	// recommendation is no longer PENDING_APPROVAL.
	if _, err := eng.Approve(recID, "test-actor:lead", "replay", time.Hour); !errors.Is(err, ErrResponseState) {
		t.Fatalf("replayed approval must fail with ErrResponseState, got %v", err)
	}
	if _, err := eng.Approve(recID, "test-actor:other", "replay", time.Hour); !errors.Is(err, ErrResponseState) {
		t.Fatalf("second-actor replay must fail with ErrResponseState, got %v", err)
	}
}

func TestExpiredApprovalRefusesExecute(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	exec := &SimulatedExecutor{}
	audit := &InMemoryAuditLog{}
	verifier := StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "t"}
	eng := fullEngine(t, DefaultPolicy{}, exec, verifier, audit, clock)
	recID := decideHigh(t, eng)
	if _, err := eng.Approve(recID, "test-actor:lead", "short-lived", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := eng.Execute(recID); !errors.Is(err, ErrApprovalInvalid) {
		t.Fatalf("expired approval must fail with ErrApprovalInvalid, got %v", err)
	}
	if len(exec.Calls()) != 0 {
		t.Fatal("executor must not run on expired approval")
	}
}

func TestDestructiveOperationNeedsApprovalAtLowRisk(t *testing.T) {
	// Operation ≠ risk: BLOCK at LOW risk still parks for approval.
	if RequiredGate(v1.OperationType_OPERATION_TYPE_BLOCK, v1.RiskLevel_RISK_LEVEL_LOW, false) != GateApproved {
		t.Fatalf("destructive operation must require approval regardless of risk")
	}
	if RequiredGate(v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_LOW, false) != GateAutomatic {
		t.Fatalf("read-only low-risk operation must pass automatically")
	}
	if RequiredGate(v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_HIGH, false) != GateApproved {
		t.Fatalf("HIGH risk must require approval regardless of operation")
	}
	if RequiredGate(v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_CRITICAL, false) != GateApproved {
		t.Fatalf("CRITICAL risk must require explicit approval regardless of operation")
	}
}

func TestExecuteOnlyOnce(t *testing.T) {
	exec := &SimulatedExecutor{}
	audit := &InMemoryAuditLog{}
	verifier := StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "t"}
	eng := fullEngine(t, DefaultPolicy{}, exec, verifier, audit, respClock)
	recID := decideHigh(t, eng)
	if _, err := eng.Approve(recID, "test-actor:lead", "ok", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(recID); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(recID); !errors.Is(err, ErrResponseState) {
		t.Fatalf("second execute must fail with ErrResponseState, got %v", err)
	}
	if len(exec.Calls()) != 1 {
		t.Fatalf("executor must run exactly once, ran %d", len(exec.Calls()))
	}
}
