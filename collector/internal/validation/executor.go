// ValidationExecutor adapts a ValidationProvider to the response Executor
// interface, so validation flows through the SAME gated path as any
// response: Recommend → Decide → Approve → Execute → Verify → Audit.
// Validation never bypasses policy, approval, gate, or audit — bypass is
// structurally impossible because the provider is only reachable here.
//
// Execute semantics, explicit:
//   - request binding: the engine's target must equal the bound target,
//     otherwise the executor refuses (defense in depth, not its primary gate).
//   - provider error → returned as error (never converted to a verdict).
//   - contract-invalid provider output → explicit error, nothing stored.
//   - verdict NOT_TESTED → execution Success=false ("not performed", with
//     the provider's reason preserved in evidence and audit).
//   - any other verdict → Success=true ("provider executed and answered";
//     the VERDICT says what it found, recorded in evidence and audit).
//   - one evidence NOTE per execution, linked to the incident, carrying the
//     canonical result (request id, result id, provider, verdict, timestamp).
package validation

import (
	"context"
	"fmt"
	"sort"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/response"
)

// ValidationExecutor binds one validation run: provider + inputs + stores.
type ValidationExecutor struct {
	provider Provider
	incident *v1.Incident
	alert    *v1.Alert
	det      *v1.Detection
	events   []*v1.TelemetryEvent
	target   string
	evidence *evidence.Store
	clock    func() time.Time
	// lastReq/lastRes record the single provider invocation performed by
	// Execute, so callers never re-invoke the provider (a second call with
	// a later clock could diverge from the evidenced result).
	lastReq *v1.ValidationRequest
	lastRes *v1.ValidationResult
}

// LastRequest returns the request of the single provider invocation, or
// nil when Execute has not completed one.
func (x *ValidationExecutor) LastRequest() *v1.ValidationRequest { return x.lastReq }

// LastResult returns the result of the single provider invocation, or nil
// when Execute has not completed one.
func (x *ValidationExecutor) LastResult() *v1.ValidationResult { return x.lastRes }

// NewValidationExecutor binds the run. Inputs are contract-validated now
// (fail fast); the target is derived from the contributing events.
func NewValidationExecutor(provider Provider, incident *v1.Incident, alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent, store *evidence.Store, clock func() time.Time) (*ValidationExecutor, error) {
	if provider == nil {
		return nil, fmt.Errorf("validation: executor needs a provider")
	}
	if store == nil {
		return nil, fmt.Errorf("validation: executor needs an evidence store")
	}
	if clock == nil {
		return nil, fmt.Errorf("validation: executor clock is nil")
	}
	if incident == nil || alert == nil || det == nil {
		return nil, fmt.Errorf("validation: incident, alert and detection are required")
	}
	targets := map[string]bool{}
	for _, e := range events {
		if e == nil {
			return nil, fmt.Errorf("validation: nil contributing event")
		}
		if err := contract.ValidateTelemetryEvent(e); err != nil {
			return nil, fmt.Errorf("validation: %w", err)
		}
		targets[e.GetAssetId()] = true
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("validation: no target asset")
	}
	return &ValidationExecutor{
		provider: provider, incident: incident, alert: alert, det: det,
		events: events, target: joinSorted(targets), evidence: store, clock: clock,
	}, nil
}

// Execute implements response.Executor: build the request from bound Blueveil
// data, run the provider, validate and store the outcome.
func (x *ValidationExecutor) Execute(ctx context.Context, req response.ExecRequest) (response.ExecResult, error) {
	if req.Target != x.target || req.Target == "" {
		return response.ExecResult{}, fmt.Errorf("validation: executor bound to target %q, request targets %q",
			x.target, req.Target)
	}
	now := x.clock()
	if now.IsZero() {
		return response.ExecResult{}, fmt.Errorf("validation: clock returned zero time")
	}
	vreq, err := BuildRequest(x.incident, x.alert, x.det, x.events, now)
	if err != nil {
		return response.ExecResult{}, err
	}
	res, err := x.provider.Validate(ctx, vreq)
	if err != nil {
		return response.ExecResult{}, fmt.Errorf("%w: %w", ErrProvider, err)
	}
	if err := CheckResult(res); err != nil {
		return response.ExecResult{}, err
	}
	if err := CheckIdentity(vreq, res); err != nil {
		return response.ExecResult{}, err
	}
	x.lastReq = vreq
	x.lastRes = res
	content, err := contract.MarshalCanonical(res)
	if err != nil {
		return response.ExecResult{}, fmt.Errorf("validation: serialize result: %w", err)
	}
	item, err := evidence.NewItem(
		x.incident.GetId(), "validation", res.GetId(),
		v1.EvidenceType_EVIDENCE_TYPE_NOTE, res.GetProvider(),
		string(content), now,
	)
	if err != nil {
		return response.ExecResult{}, fmt.Errorf("validation: evidence: %w", err)
	}
	x.evidence.Add(item)
	verdict := res.GetVerdict()
	detail := fmt.Sprintf("provider %s answered %s for control %s (request %s, result %s)",
		res.GetProvider(), verdict, res.GetControlId(), vreq.GetId(), res.GetId())
	if verdict == v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED {
		return response.ExecResult{Success: false, Detail: detail + ": validation not performed"}, nil
	}
	return response.ExecResult{Success: true, Detail: detail}, nil
}

func joinSorted(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	joined := ""
	for i, s := range out {
		if i > 0 {
			joined += ","
		}
		joined += s
	}
	return joined
}
