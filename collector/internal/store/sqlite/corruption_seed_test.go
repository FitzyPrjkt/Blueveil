// Valid seeds for the corruption matrix: one create per payload family,
// returning the persisted id for poisoning.
package sqlite

import (
	"context"
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/validation"
)

func ctxBG() context.Context { return context.Background() }

func setupPoisonAssessment(t *testing.T, be store.Backend) string {
	t.Helper()
	a := grc.Assessment{
		ControlID: "AC-1", Target: "t", Status: grc.StatusNotAssessed,
		Assessor: "s", ObservedAt: corruptNow,
	}
	if err := be.Assessments.Create(ctxBG(), a); err != nil {
		t.Fatal(err)
	}
	return a.ID()
}

func setupPoisonResilience(t *testing.T, be store.Backend) string {
	t.Helper()
	rec, err := grc.AssessResilience(grc.ResilienceInput{
		Target: "t", Assessor: "s", ObservedAt: corruptNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Resilience.Create(ctxBG(), rec); err != nil {
		t.Fatal(err)
	}
	return rec.ID
}

func setupPoisonCampaign(t *testing.T, be store.Backend) string {
	t.Helper()
	c := validation.Campaign{
		Name: "n", Target: "t", Provider: validation.NativeProviderID,
		Source: "s", Status: validation.StatusDraft,
	}
	if err := be.Campaigns.Create(ctxBG(), c); err != nil {
		t.Fatal(err)
	}
	return c.ID()
}

func setupPoisonExercise(t *testing.T, be store.Backend) string {
	t.Helper()
	ex, err := validation.BuildExercise(validation.ExerciseInput{
		CampaignID: "camp-poison", Name: "n", Source: "s",
		Entries: []validation.ExerciseEntryInput{{
			CaseID: "case-1", RequestID: "vreq-1", ResultID: "vres-1",
			Verdict:      v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
			TelemetryIDs: []string{"evt-1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Exercises.Create(ctxBG(), ex); err != nil {
		t.Fatal(err)
	}
	return ex.ID
}

func poisonComponent(t *testing.T, be store.Backend, name string) supplychain.Component {
	t.Helper()
	c := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: name,
		Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
		Source: "s", ObservedAt: corruptNow, Status: supplychain.StatusObserved,
	}
	if err := be.Components.Create(ctxBG(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

func setupPoisonComponent(t *testing.T, be store.Backend) string {
	t.Helper()
	return poisonComponent(t, be, "left-pad").ID()
}

func setupPoisonSBOM(t *testing.T, be store.Backend) string {
	t.Helper()
	c := poisonComponent(t, be, "left-pad")
	s := supplychain.SBOM{
		Format: supplychain.SBOMCycloneDX, FormatVersion: "1.5",
		ComponentIDs: []string{c.ID()}, GeneratedAt: corruptNow, Source: "s",
	}
	if err := be.SBOMs.Create(ctxBG(), s); err != nil {
		t.Fatal(err)
	}
	return s.ID()
}

func setupPoisonPolicy(t *testing.T, be store.Backend) string {
	t.Helper()
	p := supplychain.SupplyPolicy{ID: "pol-poison", Name: "n", Source: "s"}
	if err := be.Policies.Create(ctxBG(), p); err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func setupPoisonVendor(t *testing.T, be store.Backend) string {
	t.Helper()
	v := supplychain.Vendor{
		Name: "n", Service: "svc", Status: supplychain.VendorActive,
		Source: "s", ObservedAt: corruptNow,
	}
	if err := be.Vendors.Create(ctxBG(), v); err != nil {
		t.Fatal(err)
	}
	return v.ID()
}

func setupPoisonVendorAssessment(t *testing.T, be store.Backend) string {
	t.Helper()
	vid := setupPoisonVendor(t, be)
	a := supplychain.VendorAssessment{
		VendorID: vid, Status: supplychain.VendorReviewed,
		Assessor: "s", ObservedAt: corruptNow,
	}
	if err := be.VendorAssessments.Create(ctxBG(), a); err != nil {
		t.Fatal(err)
	}
	return a.ID()
}

func setupPoisonSupplyLink(t *testing.T, be store.Backend) string {
	t.Helper()
	cid := setupPoisonComponent(t, be)
	l := supplychain.SupplyLink{
		ControlID: "AC-1", SubjectKind: supplychain.LinkComponent,
		SubjectID: cid, Basis: "b",
	}
	if err := be.SupplyLinks.Create(ctxBG(), l); err != nil {
		t.Fatal(err)
	}
	return l.ID()
}

func setupPoisonDependency(t *testing.T, be store.Backend) string {
	t.Helper()
	mk := func(name string) supplychain.Component {
		return supplychain.Component{
			Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: name,
			Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
			Source: "s", ObservedAt: corruptNow, Status: supplychain.StatusObserved,
		}
	}
	a, b := mk("comp-poison-a"), mk("comp-poison-b")
	for _, c := range []supplychain.Component{a, b} {
		if err := be.Components.Create(ctxBG(), c); err != nil {
			t.Fatal(err)
		}
	}
	d := supplychain.Dependency{
		ParentID: a.ID(), ParentKind: "component", ChildID: b.ID(),
		Kind: supplychain.DependencyDependsOn, Source: "s", ObservedAt: corruptNow,
	}
	if err := be.Dependencies.Append(ctxBG(), d); err != nil {
		t.Fatal(err)
	}
	return a.ID()
}
