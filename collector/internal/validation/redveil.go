// Redveil adapter: the OPTIONAL external validation provider.
//
// Boundary rules, enforced by construction and tests:
//
//   - No Redveil import, no vendored source, no copied models, no copied
//     safety engine. This file (and package) depends only on the Blueveil
//     contract and the standard library — grep-audited.
//   - No Redveil dependency appears in go.mod/go.sum/Cargo files.
//   - Availability is explicit: Available() reports whether a Redveil
//     runtime was configured AND reachable. Unconfigured or unreachable ⟹
//     Validate answers contract-valid NOT_TESTED (genuinely not performed,
//     never a pass), it does NOT error and does NOT fabricate success.
//   - Provider crashes/errors stay errors (ErrProvider): nothing converts
//     an execution failure into a verdict.
//   - No process is spawned in this step: if a future revision adds a
//     controlled local-CLI invocation, it must live behind Validate with
//     allowlisted targets, no shell, and no user-controlled command strings.
//     Until such a seam exists with a real runtime to talk to, the adapter
//     reports unavailable — implementing an unavailable provider instead of
//     an unsafe or faked one, per the architecture decision.
//
// Environment fact (Step 9 discovery): a `redveil` CLI exists on PATH, but
// there is no Go-importable Redveil API, no validation service protocol,
// and no running instance to talk to. A CLI scrape would couple the adapter
// to Redveil's internal report schema — exactly the coupling forbidden
// above — so the adapter stays unavailable with that reason recorded.
package validation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// RedveilProviderID identifies the adapter everywhere.
const RedveilProviderID = "blueveil/provider/redveil"

// RedveilAdapter is the optional Redveil boundary. Construct it with
// NewUnavailableAdapter and a reason; a future revision may add a
// runtime-backed constructor behind this same interface.
type RedveilAdapter struct {
	version string
	clock   func() time.Time
	reason  string
}

// NewUnavailableAdapter returns an adapter that honestly reports no Redveil
// runtime. reason must say why (e.g. "no redveil runtime configured").
func NewUnavailableAdapter(version string, clock func() time.Time, reason string) (*RedveilAdapter, error) {
	if clock == nil {
		return nil, fmt.Errorf("validation: redveil adapter clock is nil")
	}
	if reason == "" {
		return nil, fmt.Errorf("validation: unavailability reason is required")
	}
	return &RedveilAdapter{version: version, clock: clock, reason: reason}, nil
}

// Info implements Provider.
func (a *RedveilAdapter) Info() ProviderInfo {
	return ProviderInfo{
		ID: RedveilProviderID, Name: "redveil", Version: a.version,
		ContractVersion: contract.ContractVersion,
	}
}

// Available reports whether a Redveil runtime backs this adapter.
// Step 9: always false; the reason says why.
func (a *RedveilAdapter) Available() bool { return false }

// UnavailableReason explains why no runtime backs this adapter.
func (a *RedveilAdapter) UnavailableReason() string { return a.reason }

// Validate implements Provider: without a runtime there is nothing to run,
// so every valid request answers NOT_TESTED with the reason attached.
// Invalid requests are still errors, not results.
func (a *RedveilAdapter) Validate(_ context.Context, req *v1.ValidationRequest) (*v1.ValidationResult, error) {
	if err := CheckRequest(req); err != nil {
		return nil, err
	}
	now := a.clock()
	if now.IsZero() {
		return nil, fmt.Errorf("%w: adapter clock returned zero time", ErrProvider)
	}
	sum := sha256.Sum256([]byte("blueveil-validation-result-v1\x1f" + req.GetId() + "\x1f" + RedveilProviderID))
	res := &v1.ValidationResult{
		Id:              "vres-" + hex.EncodeToString(sum[:])[:16],
		RequestId:       req.GetId(),
		ControlId:       req.GetControlId(),
		Provider:        RedveilProviderID,
		ProviderVersion: a.version,
		ContractVersion: contract.ContractVersion,
		Verdict:         v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED,
		ValidatedAt:     timestamppb.New(now),
		Note:            "redveil runtime unavailable (" + a.reason + "): NOT_TESTED, not a pass",
	}
	if res.GetValidatedAt() == nil {
		return nil, fmt.Errorf("%w: timestamp out of range", ErrProvider)
	}
	if err := CheckResult(res); err != nil {
		return nil, err
	}
	return res, nil
}
