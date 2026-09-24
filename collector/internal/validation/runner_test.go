// RED: campaign case execution through the safety gate + honest
// aggregation. Provider errors stay distinct from security verdicts.
package validation

import (
	"context"
	"errors"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/response"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func runFixture(t *testing.T) (*v1.Incident, *v1.Alert, *v1.Detection, []*v1.TelemetryEvent) {
	t.Helper()
	now := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	evt := &v1.TelemetryEvent{
		Id: "evt-run-001", OccurredAt: timestamppb.New(now),
		Source: "seed-lab-validation", AssetId: "seed-val-01",
		EventType: "http.request", Severity: v1.Severity_SEVERITY_HIGH,
		Attributes: map[string]string{"http.method": "GET", "control_id": "waf-xss-body-rule"},
	}
	det := &v1.Detection{
		Id: "det-run-001", RuleId: "http-error-burst", RuleName: "HTTP error burst",
		TelemetryEventIds: []string{"evt-run-001"},
		DetectedAt:        timestamppb.New(now.Add(time.Minute)),
		Severity:          v1.Severity_SEVERITY_HIGH, Confidence: 0,
		Title: "burst", Description: "lab",
	}
	alert := &v1.Alert{
		Id: "alert-run-001", DetectionIds: []string{"det-run-001"},
		Status: v1.AlertStatus_ALERT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_HIGH,
		CreatedAt: timestamppb.New(now.Add(2 * time.Minute)),
		UpdatedAt: timestamppb.New(now.Add(2 * time.Minute)),
		Title:     "Alert: burst",
	}
	inc := &v1.Incident{
		Id: "inc-run-001", AlertIds: []string{"alert-run-001"},
		Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_HIGH,
		CreatedAt: timestamppb.New(now.Add(3 * time.Minute)),
		UpdatedAt: timestamppb.New(now.Add(3 * time.Minute)),
		Title:     "I", Summary: "lab",
	}
	return inc, alert, det, []*v1.TelemetryEvent{evt}
}

type errProvider struct{}

func (errProvider) Info() ProviderInfo {
	return ProviderInfo{ID: "test/err", Name: "err", Version: "seed", ContractVersion: "blueveil.contracts.v1"}
}
func (errProvider) Validate(_ context.Context, _ *v1.ValidationRequest) (*v1.ValidationResult, error) {
	return nil, errors.New("boom: provider crashed")
}

// RunCase must invoke the provider exactly once (evidence and outcome
// share that single result; a second call could diverge). countingProvider
// lives in flow_test.go.
func TestRunCaseInvokesProviderOnce(t *testing.T) {
	inc, alert, det, events := runFixture(t)
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	inner, err := NewScriptedProvider("seed", clock, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	if err != nil {
		t.Fatal(err)
	}
	p := &countingProvider{inner: inner}
	out, err := RunCase(context.Background(), CaseParams{
		Provider: p, Incident: inc, Alert: alert, Detection: det, Events: events,
		Actor: "test-actor:seed-lead", Reason: "proportional",
		Audit: &response.InMemoryAuditLog{}, Evidence: evidence.NewStore(), Clock: clock,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("provider must be invoked exactly once, got %d", p.calls)
	}
	if out.Result == nil || out.Request == nil {
		t.Fatalf("outcome must carry the single invocation's request+result")
	}
}

func TestRunCaseSuccess(t *testing.T) {
	inc, alert, det, events := runFixture(t)
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	p, err := NewScriptedProvider("seed", clock, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RunCase(context.Background(), CaseParams{
		Provider: p, Incident: inc, Alert: alert, Detection: det, Events: events,
		Actor: "test-actor:seed-lead", Reason: "proportional",
		Audit: &response.InMemoryAuditLog{}, Evidence: evidence.NewStore(), Clock: clock,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !out.Success || out.ProviderErr != nil {
		t.Fatalf("want success, got %+v", out)
	}
	if out.Result.GetVerdict() != v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED {
		t.Fatalf("verdict: %v", out.Result.GetVerdict())
	}
	if out.Request.GetId() == "" || out.Result.GetRequestId() != out.Request.GetId() {
		t.Fatalf("request/result linkage: %+v", out)
	}
}

func TestRunCaseNotTestedFailsExecution(t *testing.T) {
	inc, alert, det, events := runFixture(t)
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	p, err := NewUnavailableAdapter("seed", clock, "no redveil runtime configured")
	if err != nil {
		t.Fatal(err)
	}
	out, err := RunCase(context.Background(), CaseParams{
		Provider: p, Incident: inc, Alert: alert, Detection: det, Events: events,
		Actor: "test-actor:seed-lead", Reason: "proportional",
		Audit: &response.InMemoryAuditLog{}, Evidence: evidence.NewStore(), Clock: clock,
	})
	if err != nil {
		t.Fatalf("run infrastructure must not error: %v", err)
	}
	if out.Success {
		t.Fatalf("NOT_TESTED must not succeed")
	}
	if out.Result.GetVerdict() != v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED {
		t.Fatalf("verdict: %v", out.Result.GetVerdict())
	}
}

func TestRunCaseProviderErrorDistinct(t *testing.T) {
	inc, alert, det, events := runFixture(t)
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	out, err := RunCase(context.Background(), CaseParams{
		Provider: errProvider{}, Incident: inc, Alert: alert, Detection: det, Events: events,
		Actor: "test-actor:seed-lead", Reason: "proportional",
		Audit: &response.InMemoryAuditLog{}, Evidence: evidence.NewStore(), Clock: clock,
	})
	if err == nil || out.ProviderErr == nil {
		t.Fatalf("provider crash must surface as error, not verdict: %+v %v", out, err)
	}
	if out.Result != nil {
		t.Fatalf("crashed provider must leave no result")
	}
}

func TestRunCaseValidation(t *testing.T) {
	inc, alert, det, events := runFixture(t)
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	p, _ := NewScriptedProvider("seed", clock, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	base := CaseParams{
		Provider: p, Incident: inc, Alert: alert, Detection: det, Events: events,
		Actor: "test-actor:seed-lead", Reason: "proportional",
		Audit: &response.InMemoryAuditLog{}, Evidence: evidence.NewStore(), Clock: clock,
	}
	for name, mut := range map[string]func(*CaseParams){
		"nil provider": func(p *CaseParams) { p.Provider = nil },
		"nil incident": func(p *CaseParams) { p.Incident = nil },
		"empty actor":  func(p *CaseParams) { p.Actor = "" },
		"nil audit":    func(p *CaseParams) { p.Audit = nil },
		"nil clock":    func(p *CaseParams) { p.Clock = nil },
	} {
		cp := base
		mut(&cp)
		if _, err := RunCase(context.Background(), cp); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSummarizeHonestCounts(t *testing.T) {
	mk := func(v v1.ValidationVerdict, perr error) CaseOutcome {
		var res *v1.ValidationResult
		if perr == nil {
			res = &v1.ValidationResult{Verdict: v}
		}
		return CaseOutcome{Result: res, ProviderErr: perr, Success: perr == nil}
	}
	s := Summarize([]CaseOutcome{
		mk(v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED, nil),
		mk(v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED, nil),
		mk(v1.ValidationVerdict_VALIDATION_VERDICT_RATE_LIMITED, nil),
		mk(v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN, nil),
		mk(0, errors.New("boom")),
	})
	if s.Total != 5 {
		t.Fatalf("total counts outcomes: %+v", s)
	}
	if s.ByVerdict[v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED] != 1 {
		t.Fatalf("by verdict: %+v", s.ByVerdict)
	}
	if s.NotTested != 1 || s.RateLimited != 1 || s.ProviderErrors != 1 {
		t.Fatalf("buckets: %+v", s)
	}
	if s.Unknown != 1 {
		t.Fatalf("unknown bucket: %+v", s)
	}
	empty := Summarize(nil)
	if empty.Total != 0 || len(empty.ByVerdict) != 0 {
		t.Fatalf("empty summarizes to zero: %+v", empty)
	}
	// A NOT_TESTED-only campaign must not look successful: no rate field exists.
}
