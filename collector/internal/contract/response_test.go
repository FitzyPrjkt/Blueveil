// Response validators checked against the Step-8 fixtures. Invalid cases:
// recommendation (missing operation), approval (bad expires_at timestamp),
// execution (missing detail), verification (bad verified_at timestamp).
package contract

import (
	"strings"
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestResponseFixturesValidate(t *testing.T) {
	cases := []struct {
		schema string
		file   string
		check  func() error
		wantOK bool
	}{
		{"recommendation", "response/valid_recommendation.json", func() error {
			var m v1.ResponseRecommendation
			if err := UnmarshalStrict(fixture(t, "response/valid_recommendation.json"), &m); err != nil {
				return err
			}
			return ValidateResponseRecommendation(&m)
		}, true},
		{"recommendation", "response/invalid_recommendation.json", func() error {
			var m v1.ResponseRecommendation
			if err := UnmarshalStrict(fixture(t, "response/invalid_recommendation.json"), &m); err != nil {
				return err
			}
			return ValidateResponseRecommendation(&m)
		}, false},
		{"approval", "response/valid_approval.json", func() error {
			var m v1.ResponseApproval
			if err := UnmarshalStrict(fixture(t, "response/valid_approval.json"), &m); err != nil {
				return err
			}
			return ValidateResponseApproval(&m)
		}, true},
		{"approval", "response/invalid_approval.json", func() error {
			var m v1.ResponseApproval
			if err := UnmarshalStrict(fixture(t, "response/invalid_approval.json"), &m); err != nil {
				return err
			}
			return ValidateResponseApproval(&m)
		}, false},
		{"execution", "response/valid_execution.json", func() error {
			var m v1.ResponseExecution
			if err := UnmarshalStrict(fixture(t, "response/valid_execution.json"), &m); err != nil {
				return err
			}
			return ValidateResponseExecution(&m)
		}, true},
		{"execution", "response/invalid_execution.json", func() error {
			var m v1.ResponseExecution
			if err := UnmarshalStrict(fixture(t, "response/invalid_execution.json"), &m); err != nil {
				return err
			}
			return ValidateResponseExecution(&m)
		}, false},
		{"verification", "response/valid_verification.json", func() error {
			var m v1.ResponseVerification
			if err := UnmarshalStrict(fixture(t, "response/valid_verification.json"), &m); err != nil {
				return err
			}
			return ValidateResponseVerification(&m)
		}, true},
		{"verification", "response/invalid_verification.json", func() error {
			var m v1.ResponseVerification
			if err := UnmarshalStrict(fixture(t, "response/invalid_verification.json"), &m); err != nil {
				return err
			}
			return ValidateResponseVerification(&m)
		}, false},
	}
	for _, c := range cases {
		err := c.check()
		if c.wantOK && err != nil {
			t.Errorf("%s/%s must validate: %v", c.schema, c.file, err)
		}
		if !c.wantOK && err == nil {
			t.Errorf("%s/%s must be rejected", c.schema, c.file)
		}
	}
}

func TestResponseContractHasNoBlanketPass(t *testing.T) {
	// The contract must never gain an ambiguous SUCCESS/SECURE/PASS value:
	// outcomes stay explicit. Mirrors the anti-SECURE verdict test.
	for enumName, values := range map[string]map[int32]string{
		"ResponseStatus":      v1.ResponseStatus_name,
		"VerificationOutcome": v1.VerificationOutcome_name,
	} {
		for _, name := range values {
			if strings.Contains(name, "SUCCESS") || strings.Contains(name, "SECURE") ||
				strings.Contains(name, "PASS") {
				t.Fatalf("%s must not contain blanket-pass value %q", enumName, name)
			}
		}
	}
}
