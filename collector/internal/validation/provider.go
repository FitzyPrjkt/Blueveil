// Provider abstraction: request in, validated result out. The only seam
// through which validation implementations (native test doubles, the
// Redveil adapter, future scanners) plug into Blueveil.
package validation

import (
	"context"
	"errors"
	"fmt"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// ProviderInfo is the stable self-description every provider registers.
type ProviderInfo struct {
	ID              string
	Name            string
	Version         string
	ContractVersion string
}

// Provider validates one contract-valid request. Contract violations in the
// request are rejected before any provider runs. A nil error with a result
// means the provider executed; the verdict says what it found (including
// NOT_TESTED, which reports non-performance, never safety).
type Provider interface {
	Info() ProviderInfo
	Validate(ctx context.Context, req *v1.ValidationRequest) (*v1.ValidationResult, error)
}

// CheckRequest validates inbound requests at the boundary.
func CheckRequest(req *v1.ValidationRequest) error {
	if err := contract.ValidateValidationRequest(req); err != nil {
		return fmt.Errorf("validation: %w", err)
	}
	return nil
}

// CheckResult validates provider output before it enters Blueveil state.
// Invalid output is an explicit error, never silently accepted.
func CheckResult(res *v1.ValidationResult) error {
	if err := contract.ValidateValidationResult(res); err != nil {
		return fmt.Errorf("%w: %w", ErrProviderOutput, err)
	}
	return nil
}

// CheckIdentity enforces request/result linkage: the result must answer the
// request it claims (request id + control id preserved).
func CheckIdentity(req *v1.ValidationRequest, res *v1.ValidationResult) error {
	if res.GetRequestId() != req.GetId() {
		return fmt.Errorf("%w: result answers %q, request is %q",
			ErrProviderOutput, res.GetRequestId(), req.GetId())
	}
	if res.GetControlId() != req.GetControlId() {
		return fmt.Errorf("%w: result control %q, request control %q",
			ErrProviderOutput, res.GetControlId(), req.GetControlId())
	}
	return nil
}

var errNilProvider = errors.New("validation: provider is nil")

// CheckProvider rejects nil providers at registration.
func CheckProvider(p Provider) error {
	if p == nil {
		return errNilProvider
	}
	info := p.Info()
	if info.ID == "" {
		return fmt.Errorf("%w: provider id is empty", ErrRegistry)
	}
	return nil
}
