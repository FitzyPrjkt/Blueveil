package response

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

func testExec(success bool) *v1.ResponseExecution {
	return &v1.ResponseExecution{
		Id: "exec-1", RecommendationId: "rec-1",
		Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND, Target: "asset-1",
		StartedAt: timestamppb.New(respClock()), FinishedAt: timestamppb.New(respClock()),
		Success: success, Detail: "simulated",
	}
}

func TestUnknownVerifierIsHonest(t *testing.T) {
	outcome, detail := UnknownVerifier{}.Verify(nil, testExec(true))
	if outcome != v1.VerificationOutcome_VERIFICATION_OUTCOME_UNKNOWN || detail == "" {
		t.Fatalf("default must be UNKNOWN with reason: %v %q", outcome, detail)
	}
}

func TestStaticVerifierReturnsConfiguredOutcome(t *testing.T) {
	v := StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "test source confirms"}
	outcome, detail := v.Verify(nil, testExec(true))
	if outcome != v.Outcome || detail != v.Detail {
		t.Fatal("static verdict must pass through")
	}
}

func TestBuildVerificationValidates(t *testing.T) {
	ver, err := BuildVerification(testExec(true),
		v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, "confirmed by test source", respClock())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := contract.ValidateResponseVerification(ver); err != nil {
		t.Fatalf("record must validate: %v", err)
	}
	if ver.GetExecutionId() != "exec-1" {
		t.Fatalf("execution linkage broken: %+v", ver)
	}
	// Deterministic id per execution.
	again, _ := BuildVerification(testExec(true),
		v1.VerificationOutcome_VERIFICATION_OUTCOME_FAILED, "other", respClock())
	if ver.GetId() != again.GetId() {
		t.Fatal("verification ids must be deterministic per execution")
	}
	if _, err := BuildVerification(nil,
		v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, "x", respClock()); err == nil {
		t.Fatal("nil execution must fail")
	}
	if _, err := BuildVerification(testExec(true),
		v1.VerificationOutcome_VERIFICATION_OUTCOME_UNSPECIFIED, "x", respClock()); err == nil {
		t.Fatal("unspecified outcome must fail")
	}
	if _, err := BuildVerification(testExec(true),
		v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, "", respClock()); err == nil {
		t.Fatal("empty detail must fail")
	}
}
