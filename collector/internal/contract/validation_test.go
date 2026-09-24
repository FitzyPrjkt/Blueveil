// Validation validators checked against the Step-2 fixtures, including the
// explicit NOT_TESTED case (valid, non-passing) from Step 2.
package contract

import (
	v1 "blueveil/collector/internal/contract/v1"
	"testing"
)

func TestValidationFixturesValidate(t *testing.T) {
	var req v1.ValidationRequest
	if err := UnmarshalStrict(fixture(t, "validation/valid_request.json"), &req); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateValidationRequest(&req); err != nil {
		t.Fatalf("valid request must validate: %v", err)
	}
	var badReq v1.ValidationRequest
	if err := UnmarshalStrict(fixture(t, "validation/invalid_request.json"), &badReq); err != nil {
		t.Fatalf("missing-field fixture parses by proto3 rules: %v", err)
	}
	if err := ValidateValidationRequest(&badReq); err == nil {
		t.Fatal("boundary must reject the control-less request")
	}

	for _, file := range []string{"validation/valid_result.json", "validation/valid_result_not_tested.json"} {
		var res v1.ValidationResult
		if err := UnmarshalStrict(fixture(t, file), &res); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		if err := ValidateValidationResult(&res); err != nil {
			t.Fatalf("%s must validate: %v", file, err)
		}
	}
	var badRes v1.ValidationResult
	if err := UnmarshalStrict(fixture(t, "validation/invalid_result.json"), &badRes); err != nil {
		t.Fatalf("missing-verdict fixture parses by proto3 rules: %v", err)
	}
	if err := ValidateValidationResult(&badRes); err == nil {
		t.Fatal("boundary must reject the verdict-less result")
	}
}
