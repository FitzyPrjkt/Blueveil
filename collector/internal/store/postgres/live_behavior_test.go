// Live behavior parity tests: every repository family round-trips,
// duplicates collide, ordering is deterministic, corruption fails
// closed, and relationships reference real identities.
package postgres

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/validation"
)

func liveTelemetry(id string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(pgClock),
		Source: "lab", AssetId: "ast-1", EventType: "net.connection",
		Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
			"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
		},
	}
}

func TestLiveTelemetryRoundTrip(t *testing.T) {
	ctx := context.Background()
	dbh, _ := openTestDB(t, ctx)
	be := dbh.Backend()
	if err := be.Telemetry.Append(ctx, liveTelemetry("evt-1")); err != nil {
		t.Fatal(err)
	}
	if err := be.Telemetry.Append(ctx, liveTelemetry("evt-1")); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}
	got, err := be.Telemetry.Get(ctx, "evt-1")
	if err != nil || got.GetSource() != "lab" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := be.Telemetry.Get(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := be.Telemetry.Append(ctx, liveTelemetry("evt-0")); err != nil {
		t.Fatal(err)
	}
	list, err := be.Telemetry.List(ctx)
	if err != nil || len(list) != 2 || list[0].GetId() != "evt-0" || list[1].GetId() != "evt-1" {
		t.Fatalf("want id-ordered [evt-0 evt-1], got %+v %v", list, err)
	}
}

func TestLiveDetectionAlertIncidentEvidenceChain(t *testing.T) {
	ctx := context.Background()
	dbh, _ := openTestDB(t, ctx)
	be := dbh.Backend()
	if err := be.Telemetry.Append(ctx, liveTelemetry("evt-1")); err != nil {
		t.Fatal(err)
	}
	det := &v1.Detection{
		Id: "det-1", RuleId: "r", RuleName: "r", TelemetryEventIds: []string{"evt-1"},
		DetectedAt: timestamppb.New(pgClock), Severity: v1.Severity_SEVERITY_INFO, Title: "t",
	}
	if err := be.Detection.Append(ctx, det); err != nil {
		t.Fatal(err)
	}
	alert := &v1.Alert{
		Id: "alert-1", DetectionIds: []string{"det-1"},
		Status: v1.AlertStatus_ALERT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(pgClock), UpdatedAt: timestamppb.New(pgClock), Title: "t",
	}
	if err := be.Alert.Append(ctx, alert); err != nil {
		t.Fatal(err)
	}
	inc := &v1.Incident{
		Id: "inc-1", AlertIds: []string{"alert-1"},
		Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(pgClock), UpdatedAt: timestamppb.New(pgClock), Title: "t",
	}
	if err := be.Incident.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}
	item, err := evidence.NewItem("inc-1", "telemetry", "evt-1",
		v1.EvidenceType_EVIDENCE_TYPE_LOG_EXCERPT, "lab", "line", pgClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Evidence.Append(ctx, item); err != nil {
		t.Fatal(err)
	}
	got, err := be.Evidence.Get(ctx, item.GetId())
	if err != nil || got.GetContent() != "line" {
		t.Fatalf("evidence get: %+v %v", got, err)
	}
	byInc, err := be.Evidence.ListByIncident(ctx, "inc-1")
	if err != nil || len(byInc) != 1 {
		t.Fatalf("list by incident: %+v %v", byInc, err)
	}
}

func TestLiveValidationCampaignExercise(t *testing.T) {
	ctx := context.Background()
	dbh, _ := openTestDB(t, ctx)
	be := dbh.Backend()
	req := &v1.ValidationRequest{
		Id: "vreq-1", ControlId: "AC-1", Target: "ast-1",
		RequestedAt: timestamppb.New(pgClock),
	}
	if err := be.Validation.AppendRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	res := &v1.ValidationResult{
		Id: "vres-1", RequestId: "vreq-1", ControlId: "AC-1",
		Provider: "p", ProviderVersion: "1", ContractVersion: contract.ContractVersion,
		Verdict:     v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		ValidatedAt: timestamppb.New(pgClock), EvidenceIds: []string{"ev-1"},
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
	ex, err := validation.BuildExercise(validation.ExerciseInput{
		CampaignID: camp.ID(), Name: "e", Source: "s",
		Entries: []validation.ExerciseEntryInput{{
			CaseID: "c", RequestID: "vreq-1", ResultID: "vres-1",
			Verdict:      v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
			TelemetryIDs: []string{"evt-1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Exercises.Create(ctx, ex); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Exercises.Get(ctx, ex.ID); err != nil {
		t.Fatalf("exercise get: %v", err)
	}
}

func TestLiveGRCAndSupply(t *testing.T) {
	ctx := context.Background()
	dbh, _ := openTestDB(t, ctx)
	be := dbh.Backend()
	a := grc.Assessment{
		ControlID: "AC-1", Target: "t", Status: grc.StatusCompliant,
		Assessor: "s", ObservedAt: pgClock, Basis: "observed",
		EvidenceIDs: []string{"ev-1"},
	}
	if err := be.Assessments.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	rec, err := grc.AssessResilience(grc.ResilienceInput{
		Target: "t", Assessor: "s", ObservedAt: pgClock,
		BackupObserved: true, BackupAt: pgClock,
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
		Source: "s", ObservedAt: pgClock, Status: supplychain.StatusObserved,
	}
	if err := be.Components.Create(ctx, comp); err != nil {
		t.Fatal(err)
	}
	vend := supplychain.Vendor{
		Name: "n", Service: "svc", Status: supplychain.VendorActive,
		Source: "s", ObservedAt: pgClock,
	}
	if err := be.Vendors.Create(ctx, vend); err != nil {
		t.Fatal(err)
	}
	if err := be.Dependencies.Append(ctx, supplychain.Dependency{
		ParentID: comp.ID(), ParentKind: "component", ChildID: comp.ID() + "-x",
		Kind: supplychain.DependencyDependsOn, Source: "s", ObservedAt: pgClock,
	}); err != nil {
		t.Fatal(err)
	}
	kids, err := be.Dependencies.Children(ctx, comp.ID())
	if err != nil || len(kids) != 1 {
		t.Fatalf("dependency children: %+v %v", kids, err)
	}
	if err := be.SupplyLinks.Create(ctx, supplychain.SupplyLink{
		ControlID: "AC-1", SubjectKind: supplychain.LinkComponent,
		SubjectID: comp.ID(), Basis: "b",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLiveCorruptionFailsClosed(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t, ctx)
	be := db.Backend()
	if err := be.Telemetry.Append(ctx, liveTelemetry("evt-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, `UPDATE telemetry_events SET severity = 999 WHERE id = 'evt-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Telemetry.Get(ctx, "evt-1"); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("want ErrCorrupted, got %v", err)
	}
	if _, err := be.Telemetry.List(ctx); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("list want ErrCorrupted, got %v", err)
	}
	comp := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
		Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
		Source: "s", ObservedAt: pgClock, Status: supplychain.StatusObserved,
	}
	if err := be.Components.Create(ctx, comp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, `UPDATE supply_components SET payload = '{not-json' WHERE id = $1`, comp.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Components.Get(ctx, comp.ID()); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("want ErrCorrupted, got %v", err)
	}
}

func TestLivePersistRunTxAtomic(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t, ctx)
	be := db.Backend()
	out := PipelineOutputs{
		Telemetry: []*v1.TelemetryEvent{liveTelemetry("evt-1")},
		Detections: []*v1.Detection{{
			Id: "det-1", RuleId: "r", RuleName: "r", TelemetryEventIds: []string{"evt-1"},
			DetectedAt: timestamppb.New(pgClock), Severity: v1.Severity_SEVERITY_INFO, Title: "t",
		}},
	}
	if err := PersistRunTx(ctx, db, out); err != nil {
		t.Fatalf("persist: %v", err)
	}
	// Second run collides on evt-1: the whole batch rolls back, so det-2
	// (new) must NOT be persisted either.
	out2 := PipelineOutputs{
		Telemetry: []*v1.TelemetryEvent{liveTelemetry("evt-1")},
		Detections: []*v1.Detection{{
			Id: "det-2", RuleId: "r", RuleName: "r", TelemetryEventIds: []string{"evt-1"},
			DetectedAt: timestamppb.New(pgClock), Severity: v1.Severity_SEVERITY_INFO, Title: "t",
		}},
	}
	if err := PersistRunTx(ctx, db, out2); err == nil {
		t.Fatalf("colliding batch must fail")
	}
	if _, err := be.Detection.Get(ctx, "det-2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back detection must be absent, got %v", err)
	}
	list, err := be.Telemetry.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("telemetry must hold exactly the first run: %+v %v", list, err)
	}
}

func TestLivePersistenceAttackCorpus(t *testing.T) {
	ctx := context.Background()
	dbh, _ := openTestDB(t, ctx)
	be := dbh.Backend()
	itoa := func(i int) string { return strconv.Itoa(i) }
	evils := []string{
		`' OR '1'='1`, `'; DROP TABLE telemetry_events; --`, `"quoted"`,
		`back\slash`, `-- comment`, `/* block */`, `%_[]`, "null\x00byte",
		"Ünïcodé-☃", "trailing-space ", "\nnewline\ttab",
	}
	// PostgreSQL TEXT is valid UTF-8 without NUL bytes: a NUL-bearing
	// value fails the write loudly (fail-closed), unlike SQLite which
	// stores it verbatim. Both are safe; the difference is pinned here
	// so no future change can silently reinterpret it.
	stored := 0
	for i, evil := range evils {
		evt := liveTelemetry("evt-pevil-" + itoa(i))
		evt.Source = evil
		err := be.Telemetry.Append(ctx, evt)
		if strings.Contains(evil, "\x00") {
			if err == nil {
				t.Fatalf("NUL byte value must fail on PostgreSQL, got success")
			}
			continue
		}
		if err != nil {
			t.Fatalf("append %q: %v", evil, err)
		}
		stored++
	}
	for i, evil := range evils {
		if strings.Contains(evil, "\x00") {
			continue
		}
		got, err := be.Telemetry.Get(ctx, "evt-pevil-"+itoa(i))
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.GetSource() != evil {
			t.Fatalf("source drift: %q vs %q", got.GetSource(), evil)
		}
	}
	list, err := be.Telemetry.List(ctx)
	if err != nil || len(list) != stored {
		t.Fatalf("list must hold exactly the stored corpus: %d %v", len(list), err)
	}
	// Tables still exist afterwards (no DROP smuggled through).
	if _, err := be.Telemetry.List(ctx); err != nil {
		t.Fatalf("table must survive: %v", err)
	}
}

func TestLiveHealth(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t, ctx)
	if err := db.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
}

func TestLiveConcurrentAppends(t *testing.T) {
	ctx := context.Background()
	dbh, _ := openTestDB(t, ctx)
	be := dbh.Backend()
	done := make(chan error, 8)
	for w := 0; w < 4; w++ {
		go func(w int) {
			for i := 0; i < 5; i++ {
				id := string(rune('a'+w)) + string(rune('0'+i)) + "-conc"
				if err := be.Telemetry.Append(ctx, liveTelemetry("evt-"+id)); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(w)
	}
	for w := 0; w < 4; w++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	list, err := be.Telemetry.List(ctx)
	if err != nil || len(list) != 20 {
		t.Fatalf("want 20 events, got %d %v", len(list), err)
	}
}
