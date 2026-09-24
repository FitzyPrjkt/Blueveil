// Campaign case execution (13H.5): every case runs through the SAME
// gated path as any response — Recommend → Decide → Approve → Execute →
// Verify → Audit — via ValidationExecutor. There is deliberately no other
// way to execute a provider: bypass is structurally impossible. HIGH and
// CRITICAL operations keep existing approval requirements through the
// engine; provider crashes stay errors and never become verdicts.
package validation

import (
	"context"
	"errors"
	"fmt"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/response"
)

// CaseParams binds one declarative case run.
type CaseParams struct {
	Provider  Provider
	Incident  *v1.Incident
	Alert     *v1.Alert
	Detection *v1.Detection
	Events    []*v1.TelemetryEvent
	Actor     string
	Reason    string
	Audit     *response.InMemoryAuditLog
	Evidence  *evidence.Store
	Clock     func() time.Time
}

// CaseOutcome is the structured result of one case run. ProviderErr is
// non-nil only when the provider itself failed (crash/error/contract
// violation) — a verdict, including NOT_TESTED, always arrives with nil
// ProviderErr. Success mirrors execution success, not security posture.
type CaseOutcome struct {
	Request     *v1.ValidationRequest
	Result      *v1.ValidationResult
	Success     bool
	ProviderErr error
}

// RunCase executes one case through the safety gate and returns the
// structured outcome. Infrastructure misuse (nil inputs) is an error;
// provider failure is a ProviderErr outcome, never a verdict.
func RunCase(ctx context.Context, p CaseParams) (CaseOutcome, error) {
	var out CaseOutcome
	if p.Provider == nil {
		return out, fmt.Errorf("validation: run needs a provider")
	}
	if p.Incident == nil || p.Alert == nil || p.Detection == nil {
		return out, fmt.Errorf("validation: run needs incident, alert and detection")
	}
	if p.Actor == "" {
		return out, fmt.Errorf("validation: run needs an actor")
	}
	if p.Audit == nil {
		return out, fmt.Errorf("validation: run needs an audit log")
	}
	if p.Evidence == nil {
		return out, fmt.Errorf("validation: run needs an evidence store")
	}
	if p.Clock == nil {
		return out, fmt.Errorf("validation: run needs a clock")
	}
	vex, err := NewValidationExecutor(p.Provider, p.Incident, p.Alert, p.Detection, p.Events, p.Evidence, p.Clock)
	if err != nil {
		return out, err
	}
	eng, err := response.NewEngine(response.DefaultPolicy{}, vex,
		response.StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "campaign harness confirms execution"},
		p.Audit, p.Clock)
	if err != nil {
		return out, err
	}
	r, err := eng.Recommend(p.Incident, p.Alert, p.Detection, p.Events)
	if err != nil {
		return out, err
	}
	dec, err := eng.Decide(r.GetId(), "campaign/policy")
	if err != nil {
		return out, err
	}
	// Approval only where the gate requires it (HIGH/CRITICAL risk):
	// low-risk recommendations decide straight to APPROVED and must
	// not be force-approved.
	if dec.GetStatus() == v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL {
		if _, err := eng.Approve(r.GetId(), p.Actor, p.Reason, time.Hour); err != nil {
			return out, err
		}
	}
	exec, err := eng.Execute(r.GetId())
	if err != nil {
		if !errors.Is(err, response.ErrExecutionFailed) {
			out.ProviderErr = err
			return out, err
		}
		// Execution reported failure (e.g. NOT_TESTED): the run
		// infrastructure worked and the executor already performed its
		// single provider invocation, so report that evidenced result
		// instead of re-invoking (a second call could diverge).
		req, res := vex.LastRequest(), vex.LastResult()
		if req == nil || res == nil {
			return out, fmt.Errorf("validation: execution failed without a recorded result: %v", err)
		}
		return CaseOutcome{Request: req, Result: res, Success: false}, nil
	}
	if _, err := eng.Verify(r.GetId()); err != nil {
		return out, err
	}
	req, res := vex.LastRequest(), vex.LastResult()
	if req == nil || res == nil {
		return out, fmt.Errorf("validation: execution succeeded without a recorded result")
	}
	return CaseOutcome{Request: req, Result: res, Success: exec.GetSuccess()}, nil
}

// Summary aggregates campaign outcomes by counting only. There are no
// rates, scores, coverage, or trend fields — anything not directly
// countable is omitted rather than derived.
type Summary struct {
	Total          int
	ByVerdict      map[v1.ValidationVerdict]int
	ProviderErrors int
	NotTested      int
	RateLimited    int
	Unknown        int
}

// Summarize counts outcomes honestly. A NOT_TESTED-only input yields
// zeros everywhere except NotTested/Total — never a success story.
func Summarize(outcomes []CaseOutcome) Summary {
	s := Summary{ByVerdict: map[v1.ValidationVerdict]int{}}
	for _, o := range outcomes {
		s.Total++
		if o.ProviderErr != nil || o.Result == nil {
			s.ProviderErrors++
			continue
		}
		v := o.Result.GetVerdict()
		s.ByVerdict[v]++
		switch v {
		case v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED:
			s.NotTested++
		case v1.ValidationVerdict_VALIDATION_VERDICT_RATE_LIMITED:
			s.RateLimited++
		case v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN:
			s.Unknown++
		}
	}
	return s
}
