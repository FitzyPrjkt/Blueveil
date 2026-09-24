// Verification: execution success is not response success. A separate step
// asks whether the response intent holds, with three honest answers:
// VERIFIED, FAILED, or UNKNOWN. When no verification source exists the only
// correct answer is UNKNOWN — never VERIFIED.
package response

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// Verifier judges one finished execution.
type Verifier interface {
	Verify(rec *v1.ResponseRecommendation, exec *v1.ResponseExecution) (v1.VerificationOutcome, string)
}

// UnknownVerifier is the honest default: with no verification source
// attached, every execution verifies UNKNOWN.
type UnknownVerifier struct{}

// Verify implements Verifier.
func (UnknownVerifier) Verify(_ *v1.ResponseRecommendation, _ *v1.ResponseExecution) (v1.VerificationOutcome, string) {
	return v1.VerificationOutcome_VERIFICATION_OUTCOME_UNKNOWN,
		"no verification source attached: UNKNOWN, never verified"
}

// StaticVerifier is a test double returning a configured outcome with an
// explicit reason. It exists so VERIFIED/FAILED paths are testable without
// fabricating a real verification source.
type StaticVerifier struct {
	Outcome v1.VerificationOutcome
	Detail  string
}

// Verify implements Verifier.
func (s StaticVerifier) Verify(_ *v1.ResponseRecommendation, _ *v1.ResponseExecution) (v1.VerificationOutcome, string) {
	if s.Detail == "" {
		return s.Outcome, "static test verdict"
	}
	return s.Outcome, s.Detail
}

// verificationID is deterministic per execution.
func verificationID(execID string) string {
	sum := sha256.Sum256([]byte("blueveil-verification-v1\x1f" + execID))
	return "verif-" + hex.EncodeToString(sum[:])[:16]
}

// BuildVerification validates a verdict into a contract-valid record.
func BuildVerification(exec *v1.ResponseExecution, outcome v1.VerificationOutcome, detail string, now time.Time) (*v1.ResponseVerification, error) {
	if exec == nil {
		return nil, fmt.Errorf("verification needs an execution")
	}
	if err := contract.ValidateResponseExecution(exec); err != nil {
		return nil, fmt.Errorf("verification needs a valid execution: %w", err)
	}
	if _, known := v1.VerificationOutcome_name[int32(outcome)]; !known ||
		outcome == v1.VerificationOutcome_VERIFICATION_OUTCOME_UNSPECIFIED {
		return nil, fmt.Errorf("verification outcome must be explicit")
	}
	if detail == "" {
		return nil, fmt.Errorf("verification detail is required")
	}
	if now.IsZero() {
		return nil, fmt.Errorf("verification timestamp is zero")
	}
	ver := &v1.ResponseVerification{
		Id:          verificationID(exec.GetId()),
		ExecutionId: exec.GetId(),
		Outcome:     outcome,
		VerifiedAt:  timestamppb.New(now),
		Detail:      detail,
	}
	if ver.GetVerifiedAt() == nil {
		return nil, fmt.Errorf("verification timestamp out of range")
	}
	if err := contract.ValidateResponseVerification(ver); err != nil {
		return nil, err
	}
	return ver, nil
}
