// RED: supply-chain repositories on the memory backend.
package store

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/supplychain"
)

func testComponent() supplychain.Component {
	return supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
		Version: "1.3.0", Provenance: supplychain.ProvenanceLockfile,
		Source: "s", ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		Status: supplychain.StatusObserved,
	}
}

func TestSupplyRepositories(t *testing.T) {
	ctx := context.Background()
	be := NewMemoryBackend()
	c := testComponent()
	if err := be.Components.Create(ctx, c); err != nil {
		t.Fatalf("component create: %v", err)
	}
	if err := be.Components.Create(ctx, c); err == nil {
		t.Fatalf("duplicate component must fail")
	}
	got, err := be.Components.Get(ctx, c.ID())
	if err != nil || got.Name != "left-pad" {
		t.Fatalf("component get: %+v %v", got, err)
	}
	list, err := be.Components.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("component list: %+v %v", list, err)
	}
	if _, err := be.Components.Get(ctx, "no-such"); err == nil {
		t.Fatalf("missing must error")
	}
	bad := c
	bad.Name = ""
	if err := be.Components.Create(ctx, bad); err == nil {
		t.Fatalf("invalid must be rejected")
	}

	dep := supplychain.Dependency{
		ParentID: "app-1", ParentKind: "APPLICATION", ChildID: c.ID(),
		Kind: supplychain.DependencyDependsOn, Source: "s",
		ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
	}
	if err := be.Dependencies.Append(ctx, dep); err != nil {
		t.Fatalf("dependency append: %v", err)
	}
	if err := be.Dependencies.Append(ctx, dep); err == nil {
		t.Fatalf("duplicate dependency must fail")
	}
	kids, err := be.Dependencies.Children(ctx, "app-1")
	if err != nil || len(kids) != 1 {
		t.Fatalf("dependency children: %+v %v", kids, err)
	}

	sbom := supplychain.SBOM{
		Format: supplychain.SBOMCycloneDX, FormatVersion: "1.6",
		ComponentIDs: []string{c.ID()},
		GeneratedAt:  time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		Source:       "s",
	}
	if err := be.SBOMs.Create(ctx, sbom); err != nil {
		t.Fatalf("sbom create: %v", err)
	}
	if _, err := be.SBOMs.Get(ctx, sbom.ID()); err != nil {
		t.Fatalf("sbom get: %v", err)
	}

	pol := supplychain.SupplyPolicy{ID: "pol-1", Name: "n", Source: "s"}
	if err := be.Policies.Create(ctx, pol); err != nil {
		t.Fatalf("policy create: %v", err)
	}
	if _, err := be.Policies.Get(ctx, "pol-1"); err != nil {
		t.Fatalf("policy get: %v", err)
	}

	v := supplychain.Vendor{
		Name: "acme", Service: "dns", Status: supplychain.VendorActive,
		Source: "s", ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
	}
	if err := be.Vendors.Create(ctx, v); err != nil {
		t.Fatalf("vendor create: %v", err)
	}
	if _, err := be.Vendors.Get(ctx, v.ID()); err != nil {
		t.Fatalf("vendor get: %v", err)
	}
	va := supplychain.VendorAssessment{
		VendorID: v.ID(), Status: supplychain.VendorReviewed,
		Assessor: "a", ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
	}
	if err := be.VendorAssessments.Create(ctx, va); err != nil {
		t.Fatalf("vendor assessment create: %v", err)
	}
	vas, err := be.VendorAssessments.List(ctx)
	if err != nil || len(vas) != 1 {
		t.Fatalf("vendor assessment list: %+v %v", vas, err)
	}

	link := supplychain.SupplyLink{
		ControlID: "AC-1", SubjectKind: supplychain.LinkComponent,
		SubjectID: c.ID(), Basis: "component observed in lab",
	}
	if err := be.SupplyLinks.Create(ctx, link); err != nil {
		t.Fatalf("link create: %v", err)
	}
	links, err := be.SupplyLinks.List(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("link list: %+v %v", links, err)
	}
	if err := be.SupplyLinks.Create(ctx, link); err == nil {
		t.Fatalf("duplicate link must fail")
	}
}
