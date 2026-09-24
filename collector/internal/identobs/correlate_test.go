// RED: identity/auth/data asset correlation — exact resolution,
// allowlist-gated auto-create, no false merge, idempotent relationships.
package identobs

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testBackend(t *testing.T) (store.Backend, *asset.Manager) {
	t.Helper()
	be := store.NewMemoryBackend()
	mgr, err := asset.NewManager(be.Assets, be.Relationships, time.Now)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	return be, mgr
}

func newCorr(t *testing.T, mgr *asset.Manager, be store.Backend, cfg IdentCorrelateConfig) *IdentCorrelator {
	t.Helper()
	c, err := NewIdentCorrelator(mgr, be.Relationships, cfg)
	if err != nil {
		t.Fatalf("correlator: %v", err)
	}
	return c
}

func identEvt(typ, id string, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: "seed-lab-identity", AssetId: "seed-ident-01", EventType: typ,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func TestCorrelateLoginAuthenticatesTo(t *testing.T) {
	be, mgr := testBackend(t)
	// Pre-existing service asset.
	if _, _, err := mgr.Ingest(context.Background(), asset.Observation{
		Source: "test", Type: v1.AssetType_ASSET_TYPE_SERVICE, Raw: "webapp:443",
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("ingest service: %v", err)
	}
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice"}})
	corr, err := c.Correlate(context.Background(), identEvt(EventTypeIdentityActivity, "e1", map[string]string{
		"identity.principal": "alice", "identity.action": "login", "identity.target": "webapp:443",
	}))
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if corr.PrincipalAsset == nil || !corr.PrincipalCreated {
		t.Fatalf("allowlisted principal must be created: %+v", corr)
	}
	if !corr.RelRecorded || corr.RelKind != asset.RelationAuthenticatesTo {
		t.Fatalf("AUTHENTICATES_TO must be recorded: %+v", corr)
	}
}

func TestCorrelateRoleChangeAssumes(t *testing.T) {
	be, mgr := testBackend(t)
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice"}})
	corr, err := c.Correlate(context.Background(), identEvt(EventTypeIdentityActivity, "e2", map[string]string{
		"identity.principal": "alice", "identity.action": "role_change", "identity.target": "admin-role",
	}))
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if corr.RelKind != asset.RelationAssumes || !corr.RelRecorded {
		t.Fatalf("ASSUMES must be recorded: %+v", corr)
	}
}

func TestCorrelateGroupChangeMemberOf(t *testing.T) {
	be, mgr := testBackend(t)
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"bob"}})
	corr, err := c.Correlate(context.Background(), identEvt(EventTypeIdentityActivity, "e3", map[string]string{
		"identity.principal": "bob", "identity.action": "group_change", "identity.target": "ops-team",
	}))
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if corr.RelKind != asset.RelationMemberOf || !corr.RelRecorded {
		t.Fatalf("MEMBER_OF must be recorded: %+v", corr)
	}
}

func TestCorrelateDataAccesses(t *testing.T) {
	be, mgr := testBackend(t)
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice"}})
	corr, err := c.Correlate(context.Background(), identEvt(EventTypeDataActivity, "e4", map[string]string{
		"data.resource": "customers", "data.action": "export", "data.principal": "alice",
	}))
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if corr.RelKind != asset.RelationAccesses || !corr.RelRecorded {
		t.Fatalf("ACCESSES must be recorded: %+v", corr)
	}
}

func TestCorrelateExternalUnresolved(t *testing.T) {
	be, mgr := testBackend(t)
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice"}})
	corr, err := c.Correlate(context.Background(), identEvt(EventTypeAuthActivity, "e5", map[string]string{
		"auth.principal": "mallory", "auth.outcome": "failure",
	}))
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if corr.PrincipalAsset != nil || corr.RelRecorded {
		t.Fatalf("external principal must stay unresolved: %+v", corr)
	}
}

func TestCorrelateNoFalseMerge(t *testing.T) {
	be, mgr := testBackend(t)
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice", "alice-admin"}})
	for _, p := range []string{"alice", "alice-admin"} {
		if _, err := c.Correlate(context.Background(), identEvt(EventTypeAuthActivity, "e-"+p, map[string]string{
			"auth.principal": p, "auth.outcome": "success",
		})); err != nil {
			t.Fatalf("correlate %s: %v", p, err)
		}
	}
	otherID := func(raw string) string {
		canonical, _ := asset.Canonicalize(v1.AssetType_ASSET_TYPE_OTHER, raw)
		return asset.IDFor(v1.AssetType_ASSET_TYPE_OTHER, canonical)
	}
	a1, _ := mgr.Resolve(context.Background(), otherID("alice"))
	a2, _ := mgr.Resolve(context.Background(), otherID("alice-admin"))
	if a1 == nil || a2 == nil || a1.GetId() == a2.GetId() {
		t.Fatalf("similar names must not merge: %v %v", a1, a2)
	}
}

func TestCorrelateIdempotent(t *testing.T) {
	be, mgr := testBackend(t)
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice"}})
	e := identEvt(EventTypeIdentityActivity, "e6", map[string]string{
		"identity.principal": "alice", "identity.action": "login", "identity.target": "webapp:443",
	})
	first, err := c.Correlate(context.Background(), e)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := c.Correlate(context.Background(), e)
	if err != nil {
		t.Fatalf("second must not error (duplicate rel): %v", err)
	}
	if second.PrincipalCreated {
		t.Fatalf("second must resolve, not create")
	}
	if first.PrincipalAsset.GetId() != second.PrincipalAsset.GetId() {
		t.Fatalf("identity drift")
	}
}

func TestCorrelateInvalidConfig(t *testing.T) {
	be, mgr := testBackend(t)
	for _, cfg := range []IdentCorrelateConfig{
		{AllowAutoCreate: true},
		{AllowedPrincipals: []string{"alice"}},
		{AllowAutoCreate: true, AllowedPrincipals: []string{""}},
	} {
		if _, err := NewIdentCorrelator(mgr, be.Relationships, cfg); err == nil {
			t.Errorf("%+v: expected config error", cfg)
		}
	}
	if _, err := NewIdentCorrelator(nil, be.Relationships, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"a"}}); err == nil {
		t.Errorf("nil manager must error")
	}
	if _, err := NewIdentCorrelator(mgr, nil, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"a"}}); err == nil {
		t.Errorf("nil rel store must error")
	}
}

func TestCorrelateMalformed(t *testing.T) {
	be, mgr := testBackend(t)
	c := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice"}})
	if _, err := c.Correlate(context.Background(), identEvt(EventTypeAuthActivity, "e7", map[string]string{
		"auth.principal": "alice",
	})); err == nil {
		t.Fatalf("missing outcome must fail explicitly")
	}
}
