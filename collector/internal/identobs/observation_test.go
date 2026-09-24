// RED: identity/auth/data observation normalization — deterministic,
// idempotent, explicit failures, secret redaction.
package identobs

import (
	"reflect"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func mkEvent(typ string, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: "evt-ident-001", OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: "seed-lab-identity", AssetId: "seed-ident-01", EventType: typ,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func TestIdentityFull(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeIdentityActivity, map[string]string{
		"identity.principal": "alice", "identity.principal_type": "user",
		"identity.action": "role_change", "identity.target": "admin-role", "identity.target_type": "role",
		"identity.result": "success", "identity.provider": "lab-idp", "identity.request_id": "req-1",
	}))
	if err != nil {
		t.Fatalf("identity full: %v", err)
	}
	if o.Identity.Principal != "alice" || o.Identity.Action != "role_change" || o.Identity.Target != "admin-role" {
		t.Fatalf("identity fields: %+v", o.Identity)
	}
}

func TestIdentityMinimal(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeIdentityActivity, map[string]string{
		"identity.principal": "bob", "identity.action": "login",
	}))
	if err != nil {
		t.Fatalf("identity minimal: %v", err)
	}
	if o.Identity.Principal != "bob" || o.Identity.Action != "login" {
		t.Fatalf("identity minimal fields: %+v", o.Identity)
	}
	if o.Identity.Result != "" || o.Identity.Provider != "" {
		t.Fatalf("optional must stay unknown: %+v", o.Identity)
	}
}

func TestAuthFull(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeAuthActivity, map[string]string{
		"auth.principal": "alice", "auth.authentication_method": "password",
		"auth.outcome": "failure", "auth.provider": "lab-idp", "auth.target": "webapp",
		"auth.failure_reason": "bad-credentials", "auth.request_id": "req-2",
	}))
	if err != nil {
		t.Fatalf("auth full: %v", err)
	}
	if o.Auth.Principal != "alice" || o.Auth.Outcome != "failure" || o.Auth.FailureReason != "bad-credentials" {
		t.Fatalf("auth fields: %+v", o.Auth)
	}
}

func TestAuthMinimal(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeAuthActivity, map[string]string{
		"auth.principal": "carol", "auth.outcome": "success",
	}))
	if err != nil {
		t.Fatalf("auth minimal: %v", err)
	}
	if o.Auth.Principal != "carol" || o.Auth.Outcome != "success" {
		t.Fatalf("auth minimal fields: %+v", o.Auth)
	}
}

func TestDataFull(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeDataActivity, map[string]string{
		"data.data_store": "lab-db", "data.resource": "customers", "data.action": "export",
		"data.principal": "alice", "data.result": "success", "data.classification": "restricted",
		"data.bytes": "1024", "data.destination": "lab-export",
	}))
	if err != nil {
		t.Fatalf("data full: %v", err)
	}
	if o.Data.Store != "lab-db" || o.Data.Action != "export" || o.Data.Classification != "restricted" || !o.Data.HasBytes || o.Data.Bytes != 1024 {
		t.Fatalf("data fields: %+v", o.Data)
	}
}

func TestDataMinimal(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeDataActivity, map[string]string{
		"data.resource": "report-01", "data.action": "read",
	}))
	if err != nil {
		t.Fatalf("data minimal: %v", err)
	}
	if o.Data.Resource != "report-01" || o.Data.Action != "read" {
		t.Fatalf("data minimal fields: %+v", o.Data)
	}
}

func TestIdentRedaction(t *testing.T) {
	o, err := Parse(mkEvent(EventTypeAuthActivity, map[string]string{
		"auth.principal": "alice", "auth.outcome": "failure",
		"auth.password": "hunter2", "auth.access_token": "tok123",
	}))
	if err != nil {
		t.Fatalf("auth redact: %v", err)
	}
	if _, ok := o.RawAttrs["auth.password"]; ok {
		t.Fatalf("password not redacted")
	}
	if _, ok := o.RawAttrs["auth.access_token"]; ok {
		t.Fatalf("token not redacted")
	}
	o2, err := Parse(mkEvent(EventTypeDataActivity, map[string]string{
		"data.resource": "r1", "data.action": "read", "data.api_key": "key-secret",
	}))
	if err != nil {
		t.Fatalf("data redact: %v", err)
	}
	if _, ok := o2.RawAttrs["data.api_key"]; ok {
		t.Fatalf("api_key not redacted")
	}
}

func TestIdentRejects(t *testing.T) {
	cases := map[string]*v1.TelemetryEvent{
		"unknown type":      mkEvent("nope.nope", map[string]string{"identity.principal": "a"}),
		"missing principal": mkEvent(EventTypeIdentityActivity, map[string]string{"identity.action": "login"}),
		"missing action":    mkEvent(EventTypeIdentityActivity, map[string]string{"identity.principal": "a"}),
		"bad action":        mkEvent(EventTypeIdentityActivity, map[string]string{"identity.principal": "a", "identity.action": "hack"}),
		"missing outcome":   mkEvent(EventTypeAuthActivity, map[string]string{"auth.principal": "a"}),
		"bad outcome":       mkEvent(EventTypeAuthActivity, map[string]string{"auth.principal": "a", "auth.outcome": "pwned"}),
		"missing resource":  mkEvent(EventTypeDataActivity, map[string]string{"data.action": "read"}),
		"bad data action":   mkEvent(EventTypeDataActivity, map[string]string{"data.resource": "r", "data.action": "exfiltrate"}),
		"bad bytes":         mkEvent(EventTypeDataActivity, map[string]string{"data.resource": "r", "data.action": "read", "data.bytes": "-5"}),
	}
	for name, e := range cases {
		if _, err := Parse(e); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestIdentIdentity(t *testing.T) {
	mk := func() *v1.TelemetryEvent {
		return mkEvent(EventTypeAuthActivity, map[string]string{"auth.principal": "alice", "auth.outcome": "failure"})
	}
	a, _ := Parse(mk())
	b, _ := Parse(mk())
	if !reflect.DeepEqual(a, b) || a.ID() != b.ID() || a.ID() == "" {
		t.Fatalf("not idempotent: %+v %+v", a, b)
	}
	other, _ := Parse(mkEvent(EventTypeAuthActivity, map[string]string{"auth.principal": "bob", "auth.outcome": "failure"}))
	if other.ID() == a.ID() {
		t.Fatalf("different principal must differ")
	}
}
