package response

import (
	"context"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

func execReq() ExecRequest {
	return ExecRequest{
		Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND, Target: "asset-1",
		Risk: v1.RiskLevel_RISK_LEVEL_HIGH, RecommendationID: "rec-1", ApprovalID: "appr-1",
	}
}

func TestSimulatedExecutorRecordsWithoutSideEffects(t *testing.T) {
	sim := &SimulatedExecutor{Fail: map[v1.OperationType]bool{}}
	res, err := sim.Execute(context.Background(), execReq())
	if err != nil || !res.Success {
		t.Fatalf("default simulated execution succeeds: %+v %v", res, err)
	}
	calls := sim.Calls()
	if len(calls) != 1 || calls[0].Target != "asset-1" || calls[0].Operation != v1.OperationType_OPERATION_TYPE_RECOMMEND {
		t.Fatalf("request must be recorded exactly: %+v", calls)
	}
	if _, err := sim.Execute(context.Background(), ExecRequest{}); err == nil {
		t.Fatal("empty request must fail")
	}
}

func TestSimulatedExecutorExplicitFailure(t *testing.T) {
	sim := &SimulatedExecutor{Fail: map[v1.OperationType]bool{
		v1.OperationType_OPERATION_TYPE_BLOCK: true,
	}}
	res, err := sim.Execute(context.Background(), ExecRequest{
		Operation: v1.OperationType_OPERATION_TYPE_BLOCK, Target: "asset-9",
		RecommendationID: "rec-9",
	})
	if err != nil || res.Success {
		t.Fatalf("programmed failure must report failure: %+v %v", res, err)
	}
	if len(sim.Calls()) != 1 {
		t.Fatal("failed attempts are still recorded")
	}
}

func TestBuildExecutionValidates(t *testing.T) {
	start := respClock()
	exec, err := BuildExecution(execReq(), ExecResult{Success: true, Detail: "simulated"}, start, start.Add(time.Second))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !exec.GetSuccess() || exec.GetApprovalId() != "appr-1" {
		t.Fatalf("record drift: %+v", exec)
	}
	// Deterministic id for the request.
	again, _ := BuildExecution(execReq(), ExecResult{Success: false, Detail: "x"}, start, start.Add(time.Second))
	if exec.GetId() != again.GetId() {
		t.Fatal("execution ids must be deterministic per request")
	}
	if _, err := BuildExecution(ExecRequest{}, ExecResult{}, start, start); err == nil {
		t.Fatal("empty request must fail")
	}
	if _, err := BuildExecution(execReq(), ExecResult{Detail: "x"}, time.Time{}, start); err == nil {
		t.Fatal("zero timestamps must fail")
	}
}
