// Package response is the safety-governed response layer: incident data in,
// authorized and verified outcomes out — through recommendation, policy,
// approval, execution gate, verification, and audit.
//
// Iron boundaries, enforced by construction and tests:
//
//   - Detection ≠ authorization. Alert ≠ authorization. Incident ≠ authorization.
//   - Recommendation ≠ execution. Only the Engine's gated path executes.
//   - Policy DENY never reaches the executor.
//   - An approval authorizes exactly one recommendation (id + operation +
//     target + risk must match; expired and replayed approvals reject).
//   - Execution failure never becomes success; unknown verification never
//     becomes verified.
//
// Execution uses a controlled in-memory simulated executor only. Nothing
// here touches real systems: no shell, no firewall, no processes, no
// network, no cloud. Fail-closed everywhere: unknown operations, unknown
// risks, and missing approvals DENY.
package response

import "errors"

var (
	// ErrResponseBuild: inputs could not become a contract-valid recommendation.
	ErrResponseBuild = errors.New("response: construction failure")
	// ErrPolicyDenied: policy refused the request. Terminal for the request.
	ErrPolicyDenied = errors.New("response: policy denied")
	// ErrApprovalRequired: policy requires human approval; none usable present.
	ErrApprovalRequired = errors.New("response: approval required")
	// ErrApprovalInvalid: approval missing, mismatched, expired, or replayed.
	ErrApprovalInvalid = errors.New("response: invalid approval")
	// ErrSafetyViolation: an illegal lifecycle transition was attempted.
	ErrSafetyViolation = errors.New("response: safety violation")
	// ErrExecutionFailed: the executor reported failure.
	ErrExecutionFailed = errors.New("response: execution failed")
	// ErrResponseState: the request is in the wrong lifecycle state for the call.
	ErrResponseState = errors.New("response: wrong lifecycle state")
)
