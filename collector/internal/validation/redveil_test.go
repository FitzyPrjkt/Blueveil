package validation

import (
	"context"
	"strings"
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestRedveilAdapterHonestUnavailability(t *testing.T) {
	ctx := context.Background()
	a, err := NewUnavailableAdapter("0-step9", valClock, "no redveil runtime configured")
	if err != nil {
		t.Fatal(err)
	}
	if a.Info().ID != RedveilProviderID {
		t.Fatalf("stable identity required: %+v", a.Info())
	}
	if a.Available() {
		t.Fatal("adapter must report unavailable")
	}
	if a.UnavailableReason() == "" {
		t.Fatal("reason must be recorded")
	}

	req := &v1.ValidationRequest{
		Id: "vreq-1", ControlId: "CTRL", Target: "asset-1",
		RequestedAt: testStamp9(),
	}
	res, err := a.Validate(ctx, req)
	if err != nil {
		t.Fatalf("unavailability answers NOT_TESTED, it does not error: %v", err)
	}
	if res.GetVerdict() != v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED {
		t.Fatalf("verdict must be NOT_TESTED, got %v", res.GetVerdict())
	}
	if res.GetRequestId() != req.GetId() || res.GetProvider() != RedveilProviderID {
		t.Fatalf("identity drift: %+v", res)
	}
	if !strings.Contains(res.GetNote(), "NOT_TESTED") || !strings.Contains(res.GetNote(), "not a pass") {
		t.Fatalf("note must state non-performance honestly: %q", res.GetNote())
	}
	if err := CheckResult(res); err != nil {
		t.Fatalf("NOT_TESTED answer must still validate: %v", err)
	}

	// No fake success exists on this path: the adapter can only produce
	// NOT_TESTED or errors. Invalid requests still error.
	if _, err := a.Validate(ctx, &v1.ValidationRequest{}); err == nil {
		t.Fatal("invalid request must error, not NOT_TESTED")
	}
	if _, err := NewUnavailableAdapter("x", nil, "r"); err == nil {
		t.Fatal("nil clock must fail")
	}
	if _, err := NewUnavailableAdapter("x", valClock, ""); err == nil {
		t.Fatal("empty reason must fail (unavailability must be explained)")
	}
}
