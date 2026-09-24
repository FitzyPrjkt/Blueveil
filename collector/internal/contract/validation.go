// Boundary validation for ValidationRequest and ValidationResult.
// Mirrors check_validation_request / check_validation_result (Rust core)
// and validation_request/result.schema.json. Providers speak this contract;
// Blueveil validates every provider output before it enters any state.
package contract

import (
	"fmt"

	v1 "blueveil/collector/internal/contract/v1"
)

// ValidateValidationRequest enforces the request boundary.
func ValidateValidationRequest(r *v1.ValidationRequest) error {
	if r == nil {
		return fmt.Errorf("contract: ValidationRequest is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", r.GetId()},
		{"control_id", r.GetControlId()},
		{"target", r.GetTarget()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: ValidationRequest.%s: empty", f.name)
		}
	}
	if err := requireTimestamp(r.GetRequestedAt(), "ValidationRequest.requested_at"); err != nil {
		return err
	}
	return nil
}

// ValidateValidationResult enforces the result boundary. There is
// deliberately no SECURE verdict: NOT_TESTED means no validation was
// performed, UNKNOWN means it ran without a determinate outcome, and
// ALLOWED_AND_NOT_DETECTED means a gap was observed. Three different facts.
func ValidateValidationResult(r *v1.ValidationResult) error {
	if r == nil {
		return fmt.Errorf("contract: ValidationResult is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", r.GetId()},
		{"request_id", r.GetRequestId()},
		{"control_id", r.GetControlId()},
		{"provider", r.GetProvider()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: ValidationResult.%s: empty", f.name)
		}
	}
	if r.GetContractVersion() != ContractVersion {
		return fmt.Errorf("contract: ValidationResult.contract_version %q unsupported, collector speaks %q",
			r.GetContractVersion(), ContractVersion)
	}
	name, known := v1.ValidationVerdict_name[int32(r.GetVerdict())]
	if !known {
		return fmt.Errorf("contract: ValidationResult.verdict: unknown value %d", int32(r.GetVerdict()))
	}
	if r.GetVerdict() == v1.ValidationVerdict_VALIDATION_VERDICT_UNSPECIFIED {
		return fmt.Errorf("contract: ValidationResult.verdict must be explicit, never %s", name)
	}
	if err := requireTimestamp(r.GetValidatedAt(), "ValidationResult.validated_at"); err != nil {
		return err
	}
	for _, id := range r.GetEvidenceIds() {
		if id == "" {
			return fmt.Errorf("contract: ValidationResult.evidence_ids[]: empty id")
		}
	}
	return nil
}
