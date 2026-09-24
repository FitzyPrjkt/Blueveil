// Policy evaluation: Allow, Deny, or RequireApproval — mirroring the Rust
// core PolicyDecision. Fail-closed: anything unrecognized DENIES.
package response

import (
	"errors"
	"fmt"

	v1 "blueveil/collector/internal/contract/v1"
)

// ActionRequest is what policy decides about: an operation at a risk level,
// requested by an actor. Operation and risk are independent dimensions:
// HIGH never implies BLOCK.
type ActionRequest struct {
	Actor     string
	Operation v1.OperationType
	Target    string
	Risk      v1.RiskLevel
}

// Decision is the only three answers a policy may give.
type Decision int

const (
	// DecisionAllow needs no human approval.
	DecisionAllow Decision = iota
	// DecisionDeny refuses. Terminal.
	DecisionDeny
	// DecisionRequireApproval parks the request until a bound approval exists.
	DecisionRequireApproval
)

// Policy answers authorization questions and nothing else.
type Policy interface {
	Decide(req ActionRequest) (Decision, error)
}

// destructiveOps always need human approval regardless of risk, mirroring
// Rust SafetyEngine::required_gate exactly.
func isDestructive(op v1.OperationType) bool {
	switch op {
	case v1.OperationType_OPERATION_TYPE_BLOCK,
		v1.OperationType_OPERATION_TYPE_ISOLATE,
		v1.OperationType_OPERATION_TYPE_DELETE,
		v1.OperationType_OPERATION_TYPE_EXECUTE:
		return true
	}
	return false
}

func knownOperation(op v1.OperationType) bool {
	_, ok := v1.OperationType_name[int32(op)]
	return ok && op != v1.OperationType_OPERATION_TYPE_UNSPECIFIED
}

func knownRisk(risk v1.RiskLevel) bool {
	_, ok := v1.RiskLevel_name[int32(risk)]
	return ok && risk != v1.RiskLevel_RISK_LEVEL_UNSPECIFIED
}

// DefaultPolicy is the fail-closed production policy: destructive operations
// and HIGH/CRITICAL risk require approval; unknown operations, unknown
// risks, and empty actors DENY; everything else allows.
type DefaultPolicy struct{}

// Decide implements Policy.
func (DefaultPolicy) Decide(req ActionRequest) (Decision, error) {
	if req.Actor == "" {
		return DecisionDeny, errors.New("response: policy actor is empty")
	}
	if !knownOperation(req.Operation) {
		return DecisionDeny, fmt.Errorf("response: policy unknown operation %v", int32(req.Operation))
	}
	if !knownRisk(req.Risk) {
		return DecisionDeny, fmt.Errorf("response: policy unknown risk %v", int32(req.Risk))
	}
	if isDestructive(req.Operation) {
		return DecisionRequireApproval, nil
	}
	switch req.Risk {
	case v1.RiskLevel_RISK_LEVEL_HIGH, v1.RiskLevel_RISK_LEVEL_CRITICAL:
		return DecisionRequireApproval, nil
	}
	return DecisionAllow, nil
}

// StaticPolicy is a fixed-answer policy: a test double and explicit-default
// building block, mirroring Rust StaticPolicy. allowAll exists only to make
// tests state what they assume.
type StaticPolicy struct {
	decision Decision
}

// StaticAllowAll answers Allow to every well-formed request.
func StaticAllowAll() StaticPolicy { return StaticPolicy{decision: DecisionAllow} }

// StaticDenyAll answers Deny to every request.
func StaticDenyAll() StaticPolicy { return StaticPolicy{decision: DecisionDeny} }

// StaticRequireApproval answers RequireApproval to every well-formed request.
func StaticRequireApproval() StaticPolicy { return StaticPolicy{decision: DecisionRequireApproval} }

// Decide implements Policy.
func (p StaticPolicy) Decide(req ActionRequest) (Decision, error) {
	if req.Actor == "" {
		return DecisionDeny, errors.New("response: policy actor is empty")
	}
	if !knownOperation(req.Operation) || !knownRisk(req.Risk) {
		return DecisionDeny, fmt.Errorf("response: policy unknown operation/risk %v/%v",
			int32(req.Operation), int32(req.Risk))
	}
	return p.decision, nil
}
