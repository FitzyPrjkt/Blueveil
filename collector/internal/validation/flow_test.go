// Gated validation flow: the §9 path through the REAL response engine —
// Recommend → Decide → Approve → Execute(validation provider) → Verify →
// Audit. Validation never bypasses policy, approval, gate, or audit because
// the provider is reachable only inside the executor step.
package validation

import (
	"context"
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/response"
)

func flowEngine(t *testing.T, policy response.Policy, vex response.Executor, verifier response.Verifier, audit *response.InMemoryAuditLog) *response.Engine {
	t.Helper()
	eng, err := response.NewEngine(policy, vex, verifier, audit, valClock)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return eng
}

func TestGatedValidationFlow(t *testing.T) {
	native, _ := NewScriptedProvider("1", valClock, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	store := evidence.NewStore()
	inc, alert, det, events := boundTriple()
	vex, err := NewValidationExecutor(native, inc, alert, det, events, store, valClock)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	audit := &response.InMemoryAuditLog{}
	eng := flowEngine(t, response.DefaultPolicy{}, vex,
		response.StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "control observed effective in lab"},
		audit)

	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatalf("recommend: %v", err)
	}
	// HIGH incident → policy parks for approval.
	if _, err := eng.Decide(rec.GetId(), "analyst:flow-test"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	// No jumping the gate.
	if _, err := eng.Execute(rec.GetId()); err == nil {
		t.Fatal("execute without approval must fail")
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:flow-lead", "proportional", time.Hour); err != nil {
		t.Fatalf("approve: %v", err)
	}
	executed, err := eng.Execute(rec.GetId())
	if err != nil || !executed.GetSuccess() {
		t.Fatalf("execute: %+v %v", executed, err)
	}
	if executed.GetOperation() != rec.GetOperation() || executed.GetTarget() != "asset-1" {
		t.Fatalf("execution must mirror the authorized request: %+v", executed)
	}
	ver, err := eng.Verify(rec.GetId())
	if err != nil || ver.GetOutcome() != v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED {
		t.Fatalf("verify: %+v %v", ver, err)
	}
	final, _ := eng.Get(rec.GetId())
	if final.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_VERIFIED {
		t.Fatalf("terminal: %v", final.GetStatus())
	}

	// Evidence: the validation NOTE is stored, verified, and linked.
	if store.Count() != 1 {
		t.Fatalf("one validation → one evidence item, got %d", store.Count())
	}
	ev := store.List()[0]
	if err := contract.ValidateEvidence(ev); err != nil || !evidence.Verify(ev) {
		t.Fatalf("validation evidence must validate and verify: %v", err)
	}
	if ev.GetIncidentId() != "inc-1" || ev.GetSource() != NativeProviderID {
		t.Fatalf("provenance drift: %+v", ev)
	}

	// Audit: requested → parked → approved → executed → verified, with the
	// provider and verdict visible in the execution entry.
	want := []response.AuditDecision{
		response.AuditRecommended, response.AuditApprovalRequired,
		response.AuditApproved, response.AuditExecuted, response.AuditVerified,
	}
	entries := audit.Entries()
	if len(entries) != len(want) {
		t.Fatalf("want %d entries, got %d", len(want), len(entries))
	}
	for i, w := range want {
		if entries[i].Decision != w {
			t.Fatalf("audit[%d]: %+v", i, entries[i])
		}
	}
	if got := entries[3].Result; got == "" {
		t.Fatal("execution audit must carry the result id")
	}
}

func TestValidationDenyLeavesProviderUntouched(t *testing.T) {
	native, _ := NewScriptedProvider("1", valClock, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	counting := &countingProvider{inner: native}
	store := evidence.NewStore()
	inc, alert, det, events := boundTriple()
	vex, err := NewValidationExecutor(counting, inc, alert, det, events, store, valClock)
	if err != nil {
		t.Fatal(err)
	}
	audit := &response.InMemoryAuditLog{}
	eng := flowEngine(t, response.StaticDenyAll(), vex, response.UnknownVerifier{}, audit)

	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:flow-test"); !errors.Is(err, response.ErrPolicyDenied) {
		t.Fatalf("want ErrPolicyDenied, got %v", err)
	}
	if _, err := eng.Execute(rec.GetId()); err == nil {
		t.Fatal("denied validation must never execute")
	}
	if counting.calls != 0 {
		t.Fatalf("DENY leaked %d provider calls", counting.calls)
	}
	if store.Count() != 0 {
		t.Fatal("denied validation stores no evidence")
	}
	entries := audit.Entries()
	if len(entries) != 2 || entries[1].Decision != response.AuditDenied {
		t.Fatalf("deny must be audited: %+v", entries)
	}
}

func TestValidationProviderFailureAudited(t *testing.T) {
	failing := &ErrorProvider{}
	store := evidence.NewStore()
	inc, alert, det, events := boundTriple()
	vex, err := NewValidationExecutor(failing, inc, alert, det, events, store, valClock)
	if err != nil {
		t.Fatal(err)
	}
	audit := &response.InMemoryAuditLog{}
	eng := flowEngine(t, response.StaticAllowAll(), vex, response.UnknownVerifier{}, audit)

	// LOW gate would allow directly; use the HIGH triple (parks) then approve
	// so the failure lands inside execution, where providers run.
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:flow-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:lead", "ok", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Execute(rec.GetId()); err == nil {
		t.Fatal("provider failure must surface, not succeed")
	}
	entries := audit.Entries()
	last := entries[len(entries)-1]
	if last.Decision != response.AuditExecutorError {
		t.Fatalf("provider failure must be audited as executor-error: %+v", entries)
	}
	if store.Count() != 0 {
		t.Fatal("failed validation stores no evidence")
	}
}

// countingProvider observes how often the engine reaches the provider.
type countingProvider struct {
	inner Provider
	calls int
}

func (p *countingProvider) Info() ProviderInfo { return p.inner.Info() }

func (p *countingProvider) Validate(ctx context.Context, req *v1.ValidationRequest) (*v1.ValidationResult, error) {
	p.calls++
	return p.inner.Validate(ctx, req)
}
