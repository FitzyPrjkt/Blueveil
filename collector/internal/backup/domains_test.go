// Full-domain restore verification (19C): every persisted domain is
// seeded, backed up, restored into isolation, and re-verified — counts,
// representative records, evidence digests, audit intactness, and
// deterministic ID stability.
package backup

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/asset"
	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/validation"
)

var domainClock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

// seedAllDomains persists one record per domain and returns the expected
// table counts plus anchor ids for post-restore comparison.
func seedAllDomains(t *testing.T, ctx context.Context, be store.Backend) (map[string]int64, map[string]string) {
	t.Helper()
	anchors := map[string]string{}
	evt := mustTelemetry("evt-dom-1")
	if err := be.Telemetry.Append(ctx, evt); err != nil {
		t.Fatal(err)
	}
	det := &v1.Detection{
		Id: "det-dom-1", RuleId: "r", RuleName: "r", TelemetryEventIds: []string{"evt-dom-1"},
		DetectedAt: timestamppb.New(domainClock), Severity: v1.Severity_SEVERITY_INFO, Title: "t",
	}
	if err := be.Detection.Append(ctx, det); err != nil {
		t.Fatal(err)
	}
	alert := &v1.Alert{
		Id: "alert-dom-1", DetectionIds: []string{"det-dom-1"},
		Status: v1.AlertStatus_ALERT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(domainClock), UpdatedAt: timestamppb.New(domainClock), Title: "t",
	}
	if err := be.Alert.Append(ctx, alert); err != nil {
		t.Fatal(err)
	}
	inc := &v1.Incident{
		Id: "inc-dom-1", AlertIds: []string{"alert-dom-1"},
		Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(domainClock), UpdatedAt: timestamppb.New(domainClock), Title: "t",
	}
	if err := be.Incident.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}
	item, err := evidence.NewItem("inc-dom-1", "telemetry", "evt-dom-1",
		v1.EvidenceType_EVIDENCE_TYPE_LOG_EXCERPT, "lab", "line", domainClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Evidence.Append(ctx, item); err != nil {
		t.Fatal(err)
	}
	anchors["evidence"] = item.GetId() + "\x1f" + item.GetSha256() + "\x1f" + item.GetContent()
	req := &v1.ValidationRequest{
		Id: "vreq-dom-1", ControlId: "AC-1", Target: "ast-1",
		RequestedAt: timestamppb.New(domainClock),
	}
	if err := be.Validation.AppendRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	res := &v1.ValidationResult{
		Id: "vres-dom-1", RequestId: "vreq-dom-1", ControlId: "AC-1",
		Provider: "p", ProviderVersion: "1", ContractVersion: contract.ContractVersion,
		Verdict:     v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		ValidatedAt: timestamppb.New(domainClock), EvidenceIds: []string{item.GetId()},
	}
	if err := be.Validation.AppendResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	camp := validation.Campaign{
		Name: "n", Target: "t", Provider: validation.NativeProviderID,
		Source: "s", Status: validation.StatusDraft,
	}
	if err := be.Campaigns.Create(ctx, camp); err != nil {
		t.Fatal(err)
	}
	anchors["campaign"] = camp.ID()
	ex, err := validation.BuildExercise(validation.ExerciseInput{
		CampaignID: camp.ID(), Name: "e", Source: "s",
		Entries: []validation.ExerciseEntryInput{{
			CaseID: "c", RequestID: "vreq-dom-1", ResultID: "vres-dom-1",
			Verdict:      v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
			TelemetryIDs: []string{"evt-dom-1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Exercises.Create(ctx, ex); err != nil {
		t.Fatal(err)
	}
	a := grc.Assessment{
		ControlID: "AC-1", Target: "t", Status: grc.StatusCompliant,
		Assessor: "s", ObservedAt: domainClock, Basis: "observed",
		EvidenceIDs: []string{item.GetId()},
	}
	if err := be.Assessments.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	rec, err := grc.AssessResilience(grc.ResilienceInput{
		Target: "t", Assessor: "s", ObservedAt: domainClock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Resilience.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	comp := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
		Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
		Source: "s", ObservedAt: domainClock, Status: supplychain.StatusObserved,
	}
	if err := be.Components.Create(ctx, comp); err != nil {
		t.Fatal(err)
	}
	anchors["component"] = comp.ID()
	vend := supplychain.Vendor{
		Name: "n", Service: "svc", Status: supplychain.VendorActive,
		Source: "s", ObservedAt: domainClock,
	}
	if err := be.Vendors.Create(ctx, vend); err != nil {
		t.Fatal(err)
	}
	if err := be.SupplyLinks.Create(ctx, supplychain.SupplyLink{
		ControlID: "AC-1", SubjectKind: supplychain.LinkComponent,
		SubjectID: comp.ID(), Basis: "b",
	}); err != nil {
		t.Fatal(err)
	}
	anchors["asset"] = "ast-dom-1"
	if err := be.Assets.Create(ctx, &v1.Asset{
		Id: "ast-dom-1", Type: v1.AssetType_ASSET_TYPE_HOST, Name: "web01",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Relationships.Append(ctx, asset.Relationship{
		ParentID: "ast-dom-1", ChildID: "ast-dom-1-x", Kind: asset.RelationContains,
		Source: "s", ObservedAt: domainClock,
	}); err != nil {
		// Child need not exist for the count check; relationship repos
		// may enforce FK (sqlite/pg do). Create the child first.
		if err := be.Assets.Create(ctx, &v1.Asset{
			Id: "ast-dom-1-x", Type: v1.AssetType_ASSET_TYPE_HOST, Name: "web02",
		}); err != nil {
			t.Fatal(err)
		}
		if err := be.Relationships.Append(ctx, asset.Relationship{
			ParentID: "ast-dom-1", ChildID: "ast-dom-1-x", Kind: asset.RelationContains,
			Source: "s", ObservedAt: domainClock,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]int64{
		"telemetry_events": 1, "detections": 1, "alerts": 1, "incidents": 1,
		"evidence": 1, "validation_requests": 1, "validation_results": 1,
	}, anchors
}

// verifyAllDomains re-checks every domain on a backend: representative
// reads, evidence digest recomputation (no mutation), and deterministic
// id stability against anchors.
func verifyAllDomains(t *testing.T, ctx context.Context, be store.Backend, anchors map[string]string) {
	t.Helper()
	evt, err := be.Telemetry.Get(ctx, "evt-dom-1")
	if err != nil || evt.GetSource() != "lab" {
		t.Fatalf("telemetry: %+v %v", evt, err)
	}
	items, err := be.Evidence.List(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("evidence list: %+v %v", items, err)
	}
	got := items[0]
	want := anchors["evidence"]
	parts := split3(want)
	if got.GetId() != parts[0] || got.GetSha256() != parts[1] || got.GetContent() != parts[2] {
		t.Fatalf("evidence drift: %+v vs %q", got, want)
	}
	if !evidence.Verify(got) {
		t.Fatalf("restored evidence must verify (no automatic mutation)")
	}
	gotCamp, err := be.Campaigns.Get(ctx, anchors["campaign"])
	if err != nil || gotCamp.ID() != anchors["campaign"] {
		t.Fatalf("campaign id unstable: %+v %v", gotCamp, err)
	}
	gotComp, err := be.Components.Get(ctx, anchors["component"])
	if err != nil || gotComp.ID() != anchors["component"] {
		t.Fatalf("component id unstable: %+v %v", gotComp, err)
	}
	gotAsset, err := be.Assets.Get(ctx, anchors["asset"])
	if err != nil || gotAsset.GetName() != "web01" {
		t.Fatalf("asset: %+v %v", gotAsset, err)
	}
	kids, err := be.Relationships.Children(ctx, anchors["asset"])
	if err != nil || len(kids) != 1 || kids[0].ChildID != "ast-dom-1-x" {
		t.Fatalf("relationships: %+v %v", kids, err)
	}
	res, err := be.Validation.GetResult(ctx, "vres-dom-1")
	if err != nil || res.GetVerdict() != v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED {
		t.Fatalf("validation result: %+v %v", res, err)
	}
	ass, err := be.Assessments.List(ctx)
	if err != nil || len(ass) != 1 || ass[0].ControlID != "AC-1" {
		t.Fatalf("assessments: %+v %v", ass, err)
	}
	links, err := be.SupplyLinks.List(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("supply links: %+v %v", links, err)
	}
	exs, err := be.Exercises.List(ctx)
	if err != nil || len(exs) != 1 {
		t.Fatalf("exercises: %+v %v", exs, err)
	}
	recs, err := be.Resilience.List(ctx)
	if err != nil || len(recs) != 1 {
		t.Fatalf("resilience: %+v %v", recs, err)
	}
}

func split3(s string) [3]string {
	var out [3]string
	for i := 0; i < 2; i++ {
		j := indexByte(s, 0x1f)
		if j < 0 {
			return out
		}
		out[i] = s[:j]
		s = s[j+1:]
	}
	out[2] = s
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
