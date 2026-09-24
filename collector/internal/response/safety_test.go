package response

import (
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

// Conformance: these cases mirror the Rust core safety tests 1:1
// (core/src/safety.rs). Any divergence is a bug in one of the two.
func TestSafetyFullWalkWithApproval(t *testing.T) {
	state := StateObserve
	gates := []Gate{
		GateAutomatic, // OBSERVE -> ANALYZE
		GateAutomatic, // ANALYZE -> RECOMMEND
		GateAutomatic, // RECOMMEND -> CONFIRM
		GateApproved,  // CONFIRM -> EXECUTE
		GateAutomatic, // EXECUTE -> VERIFY
		GateAutomatic, // VERIFY -> AUDIT
	}
	var err error
	for _, g := range gates {
		state, err = state.Advance(g)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
	}
	if state != StateAudit {
		t.Fatalf("walk must end at AUDIT, got %v", state)
	}
	if _, err := state.Advance(GateApproved); err == nil {
		t.Fatal("AUDIT is terminal")
	}
}

func TestSafetyExecuteWithoutApprovalDenied(t *testing.T) {
	state := StateObserve
	var err error
	for i := 0; i < 3; i++ {
		state, err = state.Advance(GateAutomatic)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
	}
	if state != StateConfirm {
		t.Fatalf("want CONFIRM, got %v", state)
	}
	if _, err := state.Advance(GateAutomatic); err == nil {
		t.Fatal("CONFIRM→EXECUTE without approval must deny")
	}
}

func TestSafetyRequiredGateMatchesCore(t *testing.T) {
	for _, op := range []v1.OperationType{
		v1.OperationType_OPERATION_TYPE_BLOCK,
		v1.OperationType_OPERATION_TYPE_ISOLATE,
		v1.OperationType_OPERATION_TYPE_DELETE,
		v1.OperationType_OPERATION_TYPE_EXECUTE,
	} {
		if RequiredGate(op, v1.RiskLevel_RISK_LEVEL_LOW, false) != GateApproved {
			t.Fatalf("destructive %v must need approval", op)
		}
	}
	if RequiredGate(v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_CRITICAL, false) != GateApproved {
		t.Fatal("critical risk must need approval")
	}
	if RequiredGate(v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_LOW, false) != GateAutomatic {
		t.Fatal("low read-only must be automatic")
	}
	// Policy-demanded approval overrides a permissive bare gate.
	if RequiredGate(v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_LOW, true) != GateApproved {
		t.Fatal("policy-required approval must hold the gate")
	}
}
