// Safety lifecycle: a 1:1 port of the Rust core safety model
// (core/src/safety.rs) into Go. Same states, same order, same gate rules —
// deliberately NOT a second engine with different semantics. Any divergence
// between this file and safety.rs is a bug in one of them; the conformance
// tests in safety_test.go mirror the Rust safety tests case for case.
//
//	OBSERVE → ANALYZE → RECOMMEND → CONFIRM → EXECUTE → VERIFY → AUDIT
//
// Entering EXECUTE requires an approval gate; AUDIT is terminal; there is no
// jump API, so illegal transitions are unrepresentable outside advance().
package response

import (
	"fmt"

	v1 "blueveil/collector/internal/contract/v1"
)

// SafetyState is one lifecycle phase, in legal order.
type SafetyState int

const (
	StateObserve SafetyState = iota
	StateAnalyze
	StateRecommend
	StateConfirm
	StateExecute
	StateVerify
	StateAudit
)

// String names the state for audit records.
func (s SafetyState) String() string {
	switch s {
	case StateObserve:
		return "OBSERVE"
	case StateAnalyze:
		return "ANALYZE"
	case StateRecommend:
		return "RECOMMEND"
	case StateConfirm:
		return "CONFIRM"
	case StateExecute:
		return "EXECUTE"
	case StateVerify:
		return "VERIFY"
	case StateAudit:
		return "AUDIT"
	}
	return "UNKNOWN"
}

// Gate is what a transition demands.
type Gate int

const (
	// GateAutomatic needs no human.
	GateAutomatic Gate = iota
	// GateApproved needs a presented, bound, unexpired, unused approval
	// (or a policy decision that itself required approval).
	GateApproved
)

func nextState(s SafetyState) (SafetyState, bool) {
	switch s {
	case StateObserve:
		return StateAnalyze, true
	case StateAnalyze:
		return StateRecommend, true
	case StateRecommend:
		return StateConfirm, true
	case StateConfirm:
		return StateExecute, true
	case StateExecute:
		return StateVerify, true
	case StateVerify:
		return StateAudit, true
	}
	return s, false
}

// Advance moves exactly one step. Entering EXECUTE requires GateApproved;
// AUDIT is terminal. Mirrors SafetyState::advance.
func (s SafetyState) Advance(gate Gate) (SafetyState, error) {
	if s == StateAudit {
		return s, fmt.Errorf("%w: AUDIT is terminal", ErrSafetyViolation)
	}
	if s == StateConfirm && gate != GateApproved {
		return s, fmt.Errorf("%w: entering EXECUTE requires an approval gate", ErrSafetyViolation)
	}
	next, ok := nextState(s)
	if !ok {
		return s, fmt.Errorf("%w: no successor state", ErrSafetyViolation)
	}
	return next, nil
}

// RequiredGate mirrors SafetyEngine::required_gate exactly: it answers
// whether a HUMAN must approve (GateApproved) or policy allow suffices
// (GateAutomatic). Note the composition rule used by the Engine: entering
// EXECUTE via Advance always presents GateApproved once authorization is
// established — what varies is what established it (policy vs a bound human
// approval), never the gate value at that step.
func RequiredGate(op v1.OperationType, risk v1.RiskLevel, policyApprovalRequired bool) Gate {
	if policyApprovalRequired {
		return GateApproved
	}
	switch op {
	case v1.OperationType_OPERATION_TYPE_BLOCK,
		v1.OperationType_OPERATION_TYPE_ISOLATE,
		v1.OperationType_OPERATION_TYPE_DELETE,
		v1.OperationType_OPERATION_TYPE_EXECUTE:
		return GateApproved
	}
	switch risk {
	case v1.RiskLevel_RISK_LEVEL_HIGH, v1.RiskLevel_RISK_LEVEL_CRITICAL:
		return GateApproved
	}
	return GateAutomatic
}
