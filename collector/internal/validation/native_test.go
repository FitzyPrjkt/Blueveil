package validation

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestRegistryLifecycle(t *testing.T) {
	reg := NewRegistry()
	native, err := NewScriptedProvider("test", valClock, v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(native); err != nil {
		t.Fatalf("register: %v", err)
	}
	red, err := NewUnavailableAdapter("test", valClock, "no runtime")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(red); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(native); err == nil {
		t.Fatal("duplicate provider id must be rejected")
	}
	if err := reg.Register(nil); err == nil {
		t.Fatal("nil provider must be rejected")
	}
	got, ok := reg.Get(NativeProviderID)
	if !ok || got.Info().ID != NativeProviderID {
		t.Fatal("get must return the provider")
	}
	if _, ok := reg.Get("blueveil/provider/ghost"); ok {
		t.Fatal("unknown id must miss")
	}
	list := reg.List()
	if len(list) != 2 || list[0].ID >= list[1].ID {
		t.Fatalf("listing must be deterministic id order: %+v", list)
	}
}

func TestNativeProviderScenarios(t *testing.T) {
	ctx := context.Background()
	native, err := NewScriptedProvider("1-test", valClock, v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN)
	if err != nil {
		t.Fatal(err)
	}
	setVerdict := func(control string, v v1.ValidationVerdict) {
		t.Helper()
		if err := native.SetVerdict(control, v); err != nil {
			t.Fatal(err)
		}
	}
	setVerdict("CTRL-A", v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	setVerdict("CTRL-B", v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED)
	setVerdict("CTRL-C", v1.ValidationVerdict_VALIDATION_VERDICT_RATE_LIMITED)
	setVerdict("CTRL-D", v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED)
	if err := native.SetVerdict("CTRL-X", v1.ValidationVerdict_VALIDATION_VERDICT_UNSPECIFIED); err == nil {
		t.Errorf("UNSPECIFIED scripted verdict must be rejected fail-fast")
	}

	mkReq := func(control string) *v1.ValidationRequest {
		return &v1.ValidationRequest{
			Id: "vreq-" + control, ControlId: control, Target: "asset-1",
			RequestedAt: timestamppb.New(valClock()),
		}
	}
	for control, want := range map[string]v1.ValidationVerdict{
		"CTRL-A": v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		"CTRL-B": v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED,
		"CTRL-C": v1.ValidationVerdict_VALIDATION_VERDICT_RATE_LIMITED,
		"CTRL-D": v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED,
		"CTRL-X": v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN, // default
	} {
		res, err := native.Validate(ctx, mkReq(control))
		if err != nil {
			t.Fatalf("%s: %v", control, err)
		}
		if res.GetVerdict() != want {
			t.Fatalf("%s: got %v want %v", control, res.GetVerdict(), want)
		}
		// Request identity preserved; provider identity stamped.
		if res.GetRequestId() != "vreq-"+control || res.GetControlId() != control {
			t.Fatalf("identity drift: %+v", res)
		}
		if res.GetProvider() != NativeProviderID {
			t.Fatalf("provider drift: %+v", res)
		}
		if err := CheckResult(res); err != nil {
			t.Fatalf("scripted result must validate: %v", err)
		}
		// Deterministic: same request twice, same result id.
		again, _ := native.Validate(ctx, mkReq(control))
		if res.GetId() != again.GetId() {
			t.Fatalf("%s: result ids must be deterministic", control)
		}
	}

	// Invalid request → error, not a result.
	if _, err := native.Validate(ctx, &v1.ValidationRequest{}); err == nil {
		t.Fatal("invalid request must error")
	}
	if _, err := NewScriptedProvider("x", nil, v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN); err == nil {
		t.Fatal("nil clock must fail")
	}
}

func TestErrorProviderStaysError(t *testing.T) {
	p := &ErrorProvider{Err: context.DeadlineExceeded}
	req := &v1.ValidationRequest{
		Id: "vreq-1", ControlId: "C", Target: "t", RequestedAt: timestamppb.New(valClock()),
	}
	if _, err := p.Validate(context.Background(), req); err == nil {
		t.Fatal("programmed failure must error")
	}
}
