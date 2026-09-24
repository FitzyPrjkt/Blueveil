package validation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/response"
)

func testStamp9() *timestamppb.Timestamp { return timestamppb.New(valClock()) }

func boundTriple() (*v1.Incident, *v1.Alert, *v1.Detection, []*v1.TelemetryEvent) {
	return valIncident("inc-1", "a1"), valAlert("a1", "d1"),
		valDet("d1", "e1"),
		[]*v1.TelemetryEvent{valEvent("e1", "asset-1", map[string]string{"rule_id": "CTRL-A"})}
}

func TestValidationExecutorSuccessMapping(t *testing.T) {
	ctx := context.Background()
	native, _ := NewScriptedProvider("1", valClock, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	store := evidence.NewStore()
	inc, alert, det, events := boundTriple()
	x, err := NewValidationExecutor(native, inc, alert, det, events, store, valClock)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	res, err := x.Execute(ctx, response.ExecRequest{
		Operation: v1.OperationType_OPERATION_TYPE_ANALYZE, Target: "asset-1",
		Risk: v1.RiskLevel_RISK_LEVEL_HIGH, RecommendationID: "rec-1",
	})
	if err != nil || !res.Success {
		t.Fatalf("DETECTED verdict executes successfully: %+v %v", res, err)
	}
	items := store.List()
	if len(items) != 1 {
		t.Fatalf("one execution → one evidence item, got %d", len(items))
	}
	ev := items[0]
	if err := contract.ValidateEvidence(ev); err != nil {
		t.Fatalf("validation evidence must validate: %v", err)
	}
	if ev.GetIncidentId() != "inc-1" || ev.GetSource() != NativeProviderID {
		t.Fatalf("provenance drift: %+v", ev)
	}
	if !evidence.Verify(ev) {
		t.Fatal("validation evidence must verify")
	}
	// Content carries request id, result id, provider, verdict, timestamp.
	for _, want := range []string{"CTRL-A", NativeProviderID, "VALIDATION_VERDICT_DETECTED"} {
		if !strings.Contains(ev.GetContent(), want) {
			t.Fatalf("evidence content must carry %q: %s", want, ev.GetContent())
		}
	}
}

func TestValidationExecutorNotTestedIsNotSuccess(t *testing.T) {
	ctx := context.Background()
	native, _ := NewScriptedProvider("1", valClock, v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED)
	store := evidence.NewStore()
	inc, alert, det, events := boundTriple()
	x, _ := NewValidationExecutor(native, inc, alert, det, events, store, valClock)
	res, err := x.Execute(ctx, response.ExecRequest{
		Target: "asset-1", RecommendationID: "rec-1",
	})
	if err != nil {
		t.Fatalf("NOT_TESTED is a result, not an error: %v", err)
	}
	if res.Success {
		t.Fatal("NOT_TESTED must not report success")
	}
	if store.Count() != 1 {
		t.Fatal("non-performance is still recorded as evidence")
	}
}

func TestValidationExecutorRefusals(t *testing.T) {
	ctx := context.Background()
	native, _ := NewScriptedProvider("1", valClock, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	inc, alert, det, events := boundTriple()

	// Target binding: a request for another target refuses.
	x, _ := NewValidationExecutor(native, inc, alert, det, events, evidence.NewStore(), valClock)
	if _, err := x.Execute(ctx, response.ExecRequest{Target: "asset-2", RecommendationID: "r"}); err == nil {
		t.Fatal("off-target request must refuse")
	}

	// Provider errors propagate as errors, never as verdicts.
	failing, _ := NewValidationExecutor(&ErrorProvider{}, inc, alert, det, events, evidence.NewStore(), valClock)
	if _, err := failing.Execute(ctx, response.ExecRequest{Target: "asset-1", RecommendationID: "r"}); !errors.Is(err, ErrProvider) {
		t.Fatalf("want ErrProvider, got %v", err)
	}

	// Contract-invalid provider output is rejected, nothing stored.
	store := evidence.NewStore()
	lying := &lyingProvider{}
	lx, _ := NewValidationExecutor(lying, inc, alert, det, events, store, valClock)
	if _, err := lx.Execute(ctx, response.ExecRequest{Target: "asset-1", RecommendationID: "r"}); !errors.Is(err, ErrProviderOutput) {
		t.Fatalf("want ErrProviderOutput, got %v", err)
	}
	if store.Count() != 0 {
		t.Fatal("invalid output must store nothing")
	}

	// Constructor refusals.
	if _, err := NewValidationExecutor(nil, inc, alert, det, events, evidence.NewStore(), valClock); err == nil {
		t.Fatal("nil provider must fail")
	}
	if _, err := NewValidationExecutor(native, inc, alert, det, events, nil, valClock); err == nil {
		t.Fatal("nil store must fail")
	}
}

// lyingProvider returns a well-typed but contract-invalid result:
// right shape, wrong request id — identity mismatch must reject.
type lyingProvider struct{}

func (lyingProvider) Info() ProviderInfo {
	return ProviderInfo{ID: "blueveil/provider/lying-test", Name: "lying", Version: "0", ContractVersion: contract.ContractVersion}
}

func (lyingProvider) Validate(_ context.Context, req *v1.ValidationRequest) (*v1.ValidationResult, error) {
	return &v1.ValidationResult{
		Id: "vres-lie", RequestId: "vreq-someone-else", ControlId: req.GetControlId(),
		Provider: "blueveil/provider/lying-test", ProviderVersion: "0",
		ContractVersion: contract.ContractVersion,
		Verdict:         v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		ValidatedAt:     testStamp9(),
	}, nil
}
