// Executor boundary: the ONLY way a response operation runs. Production
// code here contains exactly one implementation — a controlled in-memory
// simulation that records requests and returns deterministic outcomes. It
// performs no real-world side effect by construction: no shell, no
// subprocess, no firewall, no processes, no network, no cloud, no OS calls.
// A real executor would be a separate, reviewed crate behind this same
// interface; none exists in this tree.
package response

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

// ExecRequest is one authorized execution. It must trace to a recommendation
// (and, when human approval was required, to a bound approval).
type ExecRequest struct {
	Operation        v1.OperationType
	Target           string
	Risk             v1.RiskLevel
	RecommendationID string
	ApprovalID       string // empty when policy authorized without human approval
}

// ExecResult is what the executor did. Success means "did what was asked" —
// never "secured". Detail always states the simulated nature.
type ExecResult struct {
	Success bool
	Detail  string
}

// Executor runs one authorized request.
type Executor interface {
	Execute(ctx context.Context, req ExecRequest) (ExecResult, error)
}

// executionID is deterministic per (recommendation, operation, target).
func executionID(req ExecRequest) string {
	sum := sha256.Sum256([]byte("blueveil-execution-v1\x1f" + req.RecommendationID + "\x1f" + fmt.Sprint(int32(req.Operation)) + "\x1f" + req.Target))
	return "exec-" + hex.EncodeToString(sum[:])[:16]
}

// BuildExecution validates an executor outcome into a contract-valid record.
// started/finished come from the engine clock; zero times are rejected.
func BuildExecution(req ExecRequest, res ExecResult, started, finished time.Time) (*v1.ResponseExecution, error) {
	if req.RecommendationID == "" || req.Target == "" {
		return nil, fmt.Errorf("%w: recommendation id and target are required", ErrExecutionFailed)
	}
	if started.IsZero() || finished.IsZero() {
		return nil, fmt.Errorf("%w: execution timestamps must be set", ErrExecutionFailed)
	}
	exec := &v1.ResponseExecution{
		Id:               executionID(req),
		RecommendationId: req.RecommendationID,
		ApprovalId:       req.ApprovalID,
		Operation:        req.Operation,
		Target:           req.Target,
		StartedAt:        timestamppb.New(started),
		FinishedAt:       timestamppb.New(finished),
		Success:          res.Success,
		Detail:           res.Detail,
	}
	if exec.GetStartedAt() == nil || exec.GetFinishedAt() == nil {
		return nil, fmt.Errorf("%w: timestamp out of range", ErrExecutionFailed)
	}
	if err := contract.ValidateResponseExecution(exec); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExecutionFailed, err)
	}
	return exec, nil
}

// SimulatedExecutor records every request and returns programmed outcomes:
// Fail[op] forces failure for an operation, everything else succeeds as a
// simulation. Either way the detail states no real-world effect occurred.
type SimulatedExecutor struct {
	mu       sync.Mutex
	Fail     map[v1.OperationType]bool
	Executed []ExecRequest
}

// Execute implements Executor.
func (s *SimulatedExecutor) Execute(_ context.Context, req ExecRequest) (ExecResult, error) {
	if req.RecommendationID == "" || req.Target == "" {
		return ExecResult{}, fmt.Errorf("simulated executor: recommendation id and target are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Executed = append(s.Executed, req)
	if s.Fail[req.Operation] {
		return ExecResult{
			Success: false,
			Detail:  fmt.Sprintf("simulated: %v on %q failed as programmed; no real-world effect occurred", req.Operation, req.Target),
		}, nil
	}
	return ExecResult{
		Success: true,
		Detail:  fmt.Sprintf("simulated: %v on %q recorded; no real-world effect occurred", req.Operation, req.Target),
	}, nil
}

// Calls returns a copy of recorded requests.
func (s *SimulatedExecutor) Calls() []ExecRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ExecRequest(nil), s.Executed...)
}
