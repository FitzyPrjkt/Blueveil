// Engine walks one recommendation through the gated lifecycle:
// recommend → decide (policy) → approve (if required) → execute → verify,
// auditing every decision. State advances only through SafetyState.Advance,
// so illegal jumps are errors, not silent skips. Done requests reject
// further calls; approvals bind to one request and expire on schedule.
package response

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

type session struct {
	safety           SafetyState
	approval         *v1.ResponseApproval
	approvalRequired bool
	executed         bool
	verified         bool
	done             bool
	execution        *v1.ResponseExecution
}

// Engine is the gated response path. All collaborators are interfaces;
// clock is injected (deterministic tests, no wall time).
type Engine struct {
	mu          sync.Mutex
	policy      Policy
	executor    Executor
	verifier    Verifier
	audit       AuditLog
	clock       func() time.Time
	recommender *Recommender
	recs        map[string]*v1.ResponseRecommendation
	sessions    map[string]*session
}

// NewEngine wires the path; nil collaborators or clock are rejected.
func NewEngine(policy Policy, executor Executor, verifier Verifier, audit AuditLog, clock func() time.Time) (*Engine, error) {
	if policy == nil || executor == nil || verifier == nil || audit == nil {
		return nil, fmt.Errorf("response: engine needs policy, executor, verifier and audit")
	}
	rec, err := NewRecommender(clock)
	if err != nil {
		return nil, err
	}
	return &Engine{
		policy: policy, executor: executor, verifier: verifier, audit: audit,
		clock: clock, recommender: rec,
		recs:     map[string]*v1.ResponseRecommendation{},
		sessions: map[string]*session{},
	}, nil
}

func (e *Engine) now() (time.Time, error) {
	if e.clock == nil {
		return time.Time{}, fmt.Errorf("response: engine clock is nil")
	}
	now := e.clock()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("response: clock returned zero time")
	}
	return now, nil
}

func (e *Engine) record(actor string, op v1.OperationType, risk v1.RiskLevel, decision AuditDecision, reason, result, recID string, phase SafetyState) {
	now, err := e.now()
	if err != nil {
		// No audit entry without a real timestamp: an epoch-zero stamp
		// would invent time in exactly the trail meant to prove it.
		// Callers already fail fast on clock errors before recording.
		panic(fmt.Sprintf("response: audit record without clock: %v", err))
	}
	stamp := timestamppb.New(now)
	e.audit.Append(AuditEntry{
		DecidedAt: stamp, Actor: actor, Operation: op, Risk: risk,
		Decision: decision, Reason: reason, Result: result,
		ResponseID: recID, Phase: phase.String(),
	})
}

// Recommend builds the PROPOSED recommendation for (incident, alert),
// walking OBSERVE→ANALYZE→RECOMMEND. Recommending an attached pair twice
// returns the stored record (idempotent, no duplicate audit).
func (e *Engine) Recommend(incident *v1.Incident, alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent) (*v1.ResponseRecommendation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.now(); err != nil {
		return nil, err
	}
	rec, err := e.recommender.Recommend(incident, alert, det, events)
	if err != nil {
		return nil, err
	}
	if existing, ok := e.recs[rec.GetId()]; ok {
		return proto.Clone(existing).(*v1.ResponseRecommendation), nil
	}
	safety := StateObserve
	for i := 0; i < 2; i++ { // OBSERVE → ANALYZE → RECOMMEND
		safety, err = safety.Advance(GateAutomatic)
		if err != nil {
			return nil, fmt.Errorf("%w: recommend walk: %v", ErrSafetyViolation, err)
		}
	}
	if safety != StateRecommend {
		return nil, fmt.Errorf("%w: recommend walk ended at %v", ErrSafetyViolation, safety)
	}
	e.recs[rec.GetId()] = rec
	e.sessions[rec.GetId()] = &session{safety: safety}
	e.record(rec.GetRecommendedBy(), rec.GetOperation(), rec.GetRisk(),
		AuditRecommended, rec.GetReason(), rec.GetId(), rec.GetId(), StateRecommend)
	return proto.Clone(rec).(*v1.ResponseRecommendation), nil
}

// Decide runs policy over a PROPOSED recommendation. DENY is terminal;
// REQUIRE stays parked at PENDING_APPROVAL; ALLOW authorizes without human.
func (e *Engine) Decide(recID, actor string) (*v1.ResponseRecommendation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.now(); err != nil {
		return nil, err
	}
	rec, sess, err := e.live(recID)
	if err != nil {
		return nil, err
	}
	if rec.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_PROPOSED || sess.safety != StateRecommend {
		return nil, fmt.Errorf("%w: decide needs a PROPOSED recommendation", ErrResponseState)
	}
	decision, err := e.policy.Decide(ActionRequest{
		Actor: actor, Operation: rec.GetOperation(), Target: rec.GetTarget(), Risk: rec.GetRisk(),
	})
	if err != nil {
		return nil, fmt.Errorf("response: policy error: %w", err)
	}
	safety, err := sess.safety.Advance(GateAutomatic)
	if err != nil {
		return nil, err // already ErrSafetyViolation from Advance
	}
	sess.safety = safety // CONFIRM
	switch decision {
	case DecisionAllow:
		// Policy non-objection is not gate passage: HIGH/CRITICAL risk (or
		// destructive operations) still need a human under the gate rule,
		// so such requests park at PENDING_APPROVAL despite the allow.
		if RequiredGate(rec.GetOperation(), rec.GetRisk(), false) == GateApproved {
			rec.Status = v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL
			sess.approvalRequired = true
			e.record(actor, rec.GetOperation(), rec.GetRisk(), AuditApprovalRequired,
				"gate requires approval for this operation/risk despite policy allow", rec.GetId(), rec.GetId(), StateConfirm)
			break
		}
		rec.Status = v1.ResponseStatus_RESPONSE_STATUS_APPROVED
		sess.approvalRequired = false
		e.record(actor, rec.GetOperation(), rec.GetRisk(), AuditAllowed,
			"policy allowed without human approval", rec.GetId(), rec.GetId(), StateConfirm)
	case DecisionDeny:
		rec.Status = v1.ResponseStatus_RESPONSE_STATUS_DENIED
		sess.done = true
		e.record(actor, rec.GetOperation(), rec.GetRisk(), AuditDenied,
			"policy denied", rec.GetId(), rec.GetId(), StateConfirm)
		if verr := contract.ValidateResponseRecommendation(rec); verr != nil {
			return nil, verr
		}
		return proto.Clone(rec).(*v1.ResponseRecommendation), ErrPolicyDenied
	case DecisionRequireApproval:
		rec.Status = v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL
		sess.approvalRequired = true
		e.record(actor, rec.GetOperation(), rec.GetRisk(), AuditApprovalRequired,
			"policy requires human approval", rec.GetId(), rec.GetId(), StateConfirm)
	}
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return nil, err
	}
	return proto.Clone(rec).(*v1.ResponseRecommendation), nil
}

// Approve records a human approval for a PENDING_APPROVAL recommendation.
func (e *Engine) Approve(recID, approver, reason string, ttl time.Duration) (*v1.ResponseApproval, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now, err := e.now()
	if err != nil {
		return nil, err
	}
	rec, sess, err := e.live(recID)
	if err != nil {
		return nil, err
	}
	if rec.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL || sess.safety != StateConfirm {
		return nil, fmt.Errorf("%w: approve needs a PENDING_APPROVAL recommendation", ErrResponseState)
	}
	appr, err := Grant(rec, approver, reason, now, ttl)
	if err != nil {
		return nil, err
	}
	sess.approval = appr
	rec.Status = v1.ResponseStatus_RESPONSE_STATUS_APPROVED
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return nil, err
	}
	e.record(approver, rec.GetOperation(), rec.GetRisk(), AuditApproved,
		reason, appr.GetId(), rec.GetId(), StateConfirm)
	return appr, nil
}

// Execute runs an APPROVED recommendation through the execution gate exactly
// once. Approval-gated requests need a bound, unexpired approval; the gate
// rule mirrors the safety model (destructive or HIGH/CRITICAL always need
// approval). Failure returns ErrExecutionFailed with the recorded outcome.
func (e *Engine) Execute(recID string) (*v1.ResponseExecution, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now, err := e.now()
	if err != nil {
		return nil, err
	}
	rec, sess, err := e.live(recID)
	if err != nil {
		return nil, err
	}
	if rec.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_APPROVED || sess.safety != StateConfirm {
		return nil, fmt.Errorf("%w: execute needs an APPROVED recommendation", ErrResponseState)
	}
	if sess.executed {
		return nil, fmt.Errorf("%w: recommendation already executed", ErrResponseState)
	}
	gate := RequiredGate(rec.GetOperation(), rec.GetRisk(), sess.approvalRequired)
	approvalID := ""
	if gate == GateApproved {
		if sess.approval == nil {
			return nil, fmt.Errorf("%w: no approval presented", ErrApprovalRequired)
		}
		if !Covers(sess.approval, rec, now) {
			return nil, fmt.Errorf("%w: approval does not cover this request (mismatch or expired)", ErrApprovalInvalid)
		}
		approvalID = sess.approval.GetId()
	}
	// Authorization is established at this point — by policy allow (automatic
	// passage) or by a bound human approval. Entering EXECUTE therefore
	// always presents GateApproved; WHAT authorized it is what varied above.
	// This matches the core model: advance() never accepts Automatic here.
	safety, err := sess.safety.Advance(GateApproved)
	if err != nil {
		return nil, err // already wrapped as ErrSafetyViolation by Advance
	}
	sess.safety = safety // EXECUTE
	rec.Status = v1.ResponseStatus_RESPONSE_STATUS_EXECUTING
	res, err := e.executor.Execute(context.Background(), ExecRequest{
		Operation: rec.GetOperation(), Target: rec.GetTarget(), Risk: rec.GetRisk(),
		RecommendationID: rec.GetId(), ApprovalID: approvalID,
	})
	if err != nil {
		// Executor errors are auditable failures, distinct from a reported
		// EXECUTION_FAILED: no outcome exists to record on the recommendation.
		e.record("executor", rec.GetOperation(), rec.GetRisk(), AuditExecutorError,
			"executor errored without a Report", err.Error(), rec.GetId(), StateExecute)
		return nil, fmt.Errorf("response: executor error: %w", err)
	}
	finished, err := e.now()
	if err != nil {
		return nil, err
	}
	exec, err := BuildExecution(ExecRequest{
		Operation: rec.GetOperation(), Target: rec.GetTarget(), Risk: rec.GetRisk(),
		RecommendationID: rec.GetId(), ApprovalID: approvalID,
	}, res, now, finished)
	if err != nil {
		return nil, err
	}
	sess.execution = exec
	sess.executed = true
	safety, err = sess.safety.Advance(GateAutomatic)
	if err != nil {
		return nil, err // already ErrSafetyViolation from Advance
	}
	sess.safety = safety // VERIFY
	if res.Success {
		rec.Status = v1.ResponseStatus_RESPONSE_STATUS_EXECUTED
		e.record("executor", rec.GetOperation(), rec.GetRisk(), AuditExecuted,
			res.Detail, exec.GetId(), rec.GetId(), StateVerify)
		if err := contract.ValidateResponseRecommendation(rec); err != nil {
			return nil, err
		}
		return exec, nil
	}
	rec.Status = v1.ResponseStatus_RESPONSE_STATUS_EXECUTION_FAILED
	e.record("executor", rec.GetOperation(), rec.GetRisk(), AuditExecutionFailed,
		res.Detail, exec.GetId(), rec.GetId(), StateVerify)
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return nil, err
	}
	return exec, ErrExecutionFailed
}

// Verify judges the finished execution. Failed executions verify FAILED
// (the intent demonstrably does not hold); anything else goes to the
// configured verifier (default honest answer: UNKNOWN).
func (e *Engine) Verify(recID string) (*v1.ResponseVerification, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now, err := e.now()
	if err != nil {
		return nil, err
	}
	rec, sess, err := e.live(recID)
	if err != nil {
		return nil, err
	}
	if !sess.executed || sess.verified || sess.safety != StateVerify {
		return nil, fmt.Errorf("%w: verify needs a finished, unverified execution", ErrResponseState)
	}
	var outcome v1.VerificationOutcome
	var detail string
	if sess.execution.GetSuccess() {
		outcome, detail = e.verifier.Verify(rec, sess.execution)
	} else {
		outcome = v1.VerificationOutcome_VERIFICATION_OUTCOME_FAILED
		detail = "execution failed: response intent demonstrably does not hold"
	}
	ver, err := BuildVerification(sess.execution, outcome, detail, now)
	if err != nil {
		return nil, err
	}
	safety, err := sess.safety.Advance(GateAutomatic)
	if err != nil {
		return nil, err // already ErrSafetyViolation from Advance
	}
	sess.safety = safety // AUDIT
	sess.verified = true
	sess.done = true
	switch outcome {
	case v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED:
		rec.Status = v1.ResponseStatus_RESPONSE_STATUS_VERIFIED
		e.record("verifier", rec.GetOperation(), rec.GetRisk(), AuditVerified,
			detail, ver.GetId(), rec.GetId(), StateAudit)
	case v1.VerificationOutcome_VERIFICATION_OUTCOME_FAILED:
		rec.Status = v1.ResponseStatus_RESPONSE_STATUS_VERIFICATION_FAILED
		e.record("verifier", rec.GetOperation(), rec.GetRisk(), AuditVerificationFailed,
			detail, ver.GetId(), rec.GetId(), StateAudit)
	default:
		rec.Status = v1.ResponseStatus_RESPONSE_STATUS_VERIFICATION_UNKNOWN
		e.record("verifier", rec.GetOperation(), rec.GetRisk(), AuditVerificationUnknown,
			detail, ver.GetId(), rec.GetId(), StateAudit)
	}
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return nil, err
	}
	return ver, nil
}

// live returns the mutable record and session, rejecting unknown or done ids.
func (e *Engine) live(recID string) (*v1.ResponseRecommendation, *session, error) {
	rec, ok := e.recs[recID]
	if !ok {
		return nil, nil, fmt.Errorf("response: unknown recommendation %q", recID)
	}
	sess := e.sessions[recID]
	if sess.done {
		return nil, nil, fmt.Errorf("%w: recommendation %q is terminal", ErrResponseState, recID)
	}
	return rec, sess, nil
}

// Get returns a copy of the recommendation, or false when unknown.
func (e *Engine) Get(recID string) (*v1.ResponseRecommendation, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.recs[recID]
	if !ok {
		return nil, false
	}
	return proto.Clone(rec).(*v1.ResponseRecommendation), true
}

// Approval returns a copy of the recorded approval for recID, if any.
// Copies keep callers from retargeting a stored approval (which would
// defeat Covers checks).
func (e *Engine) Approval(recID string) (*v1.ResponseApproval, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	sess, ok := e.sessions[recID]
	if !ok || sess.approval == nil {
		return nil, false
	}
	return proto.Clone(sess.approval).(*v1.ResponseApproval), true
}
