// Boundary validation for the Step-8 response contracts.
// Mirrors the Rust check_response_* functions and the four
// response_*.schema.json schemas.
package contract

import (
	"fmt"

	v1 "blueveil/collector/internal/contract/v1"
)

func checkOperationValue(v int32, what string) error {
	name, known := v1.OperationType_name[v]
	if !known {
		return fmt.Errorf("contract: %s: unknown value %d", what, v)
	}
	if v1.OperationType(v) == v1.OperationType_OPERATION_TYPE_UNSPECIFIED {
		return fmt.Errorf("contract: %s must be explicit, never %s", what, name)
	}
	return nil
}

func checkRiskValue(v int32, what string) error {
	name, known := v1.RiskLevel_name[v]
	if !known {
		return fmt.Errorf("contract: %s: unknown value %d", what, v)
	}
	if v1.RiskLevel(v) == v1.RiskLevel_RISK_LEVEL_UNSPECIFIED {
		return fmt.Errorf("contract: %s must be explicit, never %s", what, name)
	}
	return nil
}

func checkResponseStatus(v int32, what string) error {
	name, known := v1.ResponseStatus_name[v]
	if !known {
		return fmt.Errorf("contract: %s: unknown value %d", what, v)
	}
	if v1.ResponseStatus(v) == v1.ResponseStatus_RESPONSE_STATUS_UNSPECIFIED {
		return fmt.Errorf("contract: %s must be explicit, never %s", what, name)
	}
	return nil
}

// ValidateResponseRecommendation enforces the recommendation boundary:
// identity, incident linkage, explicit operation/risk/status, reason,
// timestamp, proposer identity. A proposal authorizes nothing by itself.
func ValidateResponseRecommendation(r *v1.ResponseRecommendation) error {
	if r == nil {
		return fmt.Errorf("contract: ResponseRecommendation is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", r.GetId()},
		{"incident_id", r.GetIncidentId()},
		{"target", r.GetTarget()},
		{"reason", r.GetReason()},
		{"recommended_by", r.GetRecommendedBy()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: ResponseRecommendation.%s: empty", f.name)
		}
	}
	if err := checkOperationValue(int32(r.GetOperation()), "ResponseRecommendation.operation"); err != nil {
		return err
	}
	if err := checkRiskValue(int32(r.GetRisk()), "ResponseRecommendation.risk"); err != nil {
		return err
	}
	if err := checkResponseStatus(int32(r.GetStatus()), "ResponseRecommendation.status"); err != nil {
		return err
	}
	if err := requireTimestamp(r.GetRecommendedAt(), "ResponseRecommendation.recommended_at"); err != nil {
		return err
	}
	return nil
}

// ValidateResponseApproval enforces the approval boundary, including the
// binding fields that make an approval usable for exactly one recommendation.
func ValidateResponseApproval(a *v1.ResponseApproval) error {
	if a == nil {
		return fmt.Errorf("contract: ResponseApproval is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", a.GetId()},
		{"recommendation_id", a.GetRecommendationId()},
		{"target", a.GetTarget()},
		{"approver", a.GetApprover()},
		{"reason", a.GetReason()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: ResponseApproval.%s: empty", f.name)
		}
	}
	if err := checkOperationValue(int32(a.GetOperation()), "ResponseApproval.operation"); err != nil {
		return err
	}
	if err := checkRiskValue(int32(a.GetRisk()), "ResponseApproval.risk"); err != nil {
		return err
	}
	if err := requireTimestamp(a.GetApprovedAt(), "ResponseApproval.approved_at"); err != nil {
		return err
	}
	return nil
}

// ValidateResponseExecution enforces the execution-report boundary. success
// reports what the executor did — never "secured".
func ValidateResponseExecution(e *v1.ResponseExecution) error {
	if e == nil {
		return fmt.Errorf("contract: ResponseExecution is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", e.GetId()},
		{"recommendation_id", e.GetRecommendationId()},
		{"target", e.GetTarget()},
		{"detail", e.GetDetail()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: ResponseExecution.%s: empty", f.name)
		}
	}
	if err := checkOperationValue(int32(e.GetOperation()), "ResponseExecution.operation"); err != nil {
		return err
	}
	if err := requireTimestamp(e.GetStartedAt(), "ResponseExecution.started_at"); err != nil {
		return err
	}
	if err := requireTimestamp(e.GetFinishedAt(), "ResponseExecution.finished_at"); err != nil {
		return err
	}
	return nil
}

// ValidateResponseVerification enforces the verification boundary. UNKNOWN
// is a valid, non-passing outcome.
func ValidateResponseVerification(v *v1.ResponseVerification) error {
	if v == nil {
		return fmt.Errorf("contract: ResponseVerification is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", v.GetId()},
		{"execution_id", v.GetExecutionId()},
		{"detail", v.GetDetail()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: ResponseVerification.%s: empty", f.name)
		}
	}
	name, known := v1.VerificationOutcome_name[int32(v.GetOutcome())]
	if !known {
		return fmt.Errorf("contract: ResponseVerification.outcome: unknown value %d", int32(v.GetOutcome()))
	}
	if v.GetOutcome() == v1.VerificationOutcome_VERIFICATION_OUTCOME_UNSPECIFIED {
		return fmt.Errorf("contract: ResponseVerification.outcome must be explicit, never %s", name)
	}
	if err := requireTimestamp(v.GetVerifiedAt(), "ResponseVerification.verified_at"); err != nil {
		return err
	}
	return nil
}
