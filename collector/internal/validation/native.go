// Native test provider: deterministic, in-memory, scripted verdicts.
// Clearly a test provider — never production security validation, never a
// realistic vulnerability result. Verdicts are scripted per control id with
// an explicit default; request identity is always preserved.
package validation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// NativeProviderID identifies the scripted test provider everywhere
// (registry, results, evidence, audit).
const NativeProviderID = "blueveil/provider/native-test"

// ScriptedProvider answers valid requests with scripted verdicts.
type ScriptedProvider struct {
	mu       sync.Mutex
	version  string
	clock    func() time.Time
	def      v1.ValidationVerdict
	scenario map[string]v1.ValidationVerdict
}

// NewScriptedProvider returns a provider answering defaultVerdict unless a
// per-control scenario says otherwise. A nil clock or an unspecified
// default verdict is rejected fail-fast (not later at CheckResult).
func NewScriptedProvider(version string, clock func() time.Time, defaultVerdict v1.ValidationVerdict) (*ScriptedProvider, error) {
	if clock == nil {
		return nil, fmt.Errorf("validation: native provider clock is nil")
	}
	if err := checkExplicitVerdict(defaultVerdict); err != nil {
		return nil, err
	}
	return &ScriptedProvider{
		version: version, clock: clock, def: defaultVerdict,
		scenario: map[string]v1.ValidationVerdict{},
	}, nil
}

// SetVerdict scripts one control id to answer verdict. Unspecified or
// unknown verdicts are rejected fail-fast.
func (p *ScriptedProvider) SetVerdict(controlID string, verdict v1.ValidationVerdict) error {
	if err := checkExplicitVerdict(verdict); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scenario[controlID] = verdict
	return nil
}

func checkExplicitVerdict(v v1.ValidationVerdict) error {
	if v == v1.ValidationVerdict_VALIDATION_VERDICT_UNSPECIFIED {
		return fmt.Errorf("validation: scripted verdict must be explicit (UNSPECIFIED is not an outcome)")
	}
	if _, known := v1.ValidationVerdict_name[int32(v)]; !known {
		return fmt.Errorf("validation: scripted verdict %d out of bounded vocabulary", int32(v))
	}
	return nil
}

// Info implements Provider.
func (p *ScriptedProvider) Info() ProviderInfo {
	return ProviderInfo{
		ID: NativeProviderID, Name: "native-test", Version: p.version,
		ContractVersion: contract.ContractVersion,
	}
}

// Validate implements Provider: valid request in, contract-valid scripted
// result out. Invalid requests are errors, not results.
func (p *ScriptedProvider) Validate(_ context.Context, req *v1.ValidationRequest) (*v1.ValidationResult, error) {
	if err := CheckRequest(req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	verdict, ok := p.scenario[req.GetControlId()]
	if !ok {
		verdict = p.def
	}
	p.mu.Unlock()
	now := p.clock()
	if now.IsZero() {
		return nil, fmt.Errorf("%w: provider clock returned zero time", ErrProvider)
	}
	sum := sha256.Sum256([]byte("blueveil-validation-result-v1\x1f" + req.GetId() + "\x1f" + NativeProviderID + "\x1f" + verdict.String()))
	res := &v1.ValidationResult{
		Id:              "vres-" + hex.EncodeToString(sum[:])[:16],
		RequestId:       req.GetId(),
		ControlId:       req.GetControlId(),
		Provider:        NativeProviderID,
		ProviderVersion: p.version,
		ContractVersion: contract.ContractVersion,
		Verdict:         verdict,
		ValidatedAt:     timestamppb.New(now),
		Note:            "synthetic test verdict, not production security validation",
	}
	if res.GetValidatedAt() == nil {
		return nil, fmt.Errorf("%w: timestamp out of range", ErrProvider)
	}
	if err := CheckResult(res); err != nil {
		return nil, err
	}
	return res, nil
}

// ErrorProvider is a test double that always fails: it proves provider
// errors propagate as errors and are never converted into verdicts.
type ErrorProvider struct {
	Err error
}

// Info implements Provider.
func (p *ErrorProvider) Info() ProviderInfo {
	return ProviderInfo{
		ID: "blueveil/provider/error-test", Name: "error-test", Version: "0",
		ContractVersion: contract.ContractVersion,
	}
}

// Validate implements Provider.
func (p *ErrorProvider) Validate(_ context.Context, req *v1.ValidationRequest) (*v1.ValidationResult, error) {
	if err := CheckRequest(req); err != nil {
		return nil, err
	}
	if p.Err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProvider, p.Err)
	}
	return nil, fmt.Errorf("%w: programmed failure", ErrProvider)
}
