package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/store/storetest"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/validation"

	_ "modernc.org/sqlite"
)

func openMemory(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), Config{})
	if err != nil {
		t.Fatalf("open memory: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func openFile(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blueveil-test.db")
	db, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

// Local builders mirror the storetest fixtures (kept in sync by the shared
// conformance suite both backends must pass).
func storetestTelemetry(w, i int) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: fmt.Sprintf("evt-%d-%d", w, i), Source: "lab", AssetId: "asset-1",
		EventType: "waf.request_blocked", Severity: v1.Severity_SEVERITY_HIGH,
		OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)),
	}
}

func storetestIncident() *v1.Incident {
	now := timestamppb.New(time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC))
	return &v1.Incident{
		Id: "inc-1", AlertIds: []string{"a1"}, Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		Severity: v1.Severity_SEVERITY_HIGH, CreatedAt: now, UpdatedAt: now,
		Title: "Incident", Summary: "1 alert(s)",
	}
}

func storetestEvidence(incID string) *v1.Evidence {
	return &v1.Evidence{
		Id: "ev-1", IncidentId: incID, Type: v1.EvidenceType_EVIDENCE_TYPE_NOTE,
		CollectedAt: timestamppb.New(time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)),
		Source:      "lab", MediaType: "application/json",
		Sha256:  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Content: "test",
	}
}

func storetestAudit() store.AuditEntry {
	return store.AuditEntry{
		ID: "audit-0001", DecidedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		Actor: "test-actor:x", Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Decision: "recommended",
		Reason: "r", Result: "rec-1", ResponseID: "rec-1", Phase: "RECOMMEND",
	}
}

func TestSQLiteBackendConformance(t *testing.T) {
	storetest.Run(t, openMemory(t).Backend())
}

func TestSQLiteFileBackendConformance(t *testing.T) {
	db, _ := openFile(t)
	storetest.Run(t, db.Backend())
}

func TestSchemaVersionGate(t *testing.T) {
	ctx := context.Background()
	db, path := openFile(t)
	v, err := SchemaVersion(ctx, db.db)
	if err != nil || v != CurrentSchemaVersion {
		t.Fatalf("fresh database must report version %d, got %d %v", CurrentSchemaVersion, v, err)
	}
	db.Close()

	// Reopen: same version, no re-migration, data intact.
	db2, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	v, err = SchemaVersion(ctx, db2.db)
	if err != nil || v != CurrentSchemaVersion {
		t.Fatalf("reopened version: %d %v", v, err)
	}

	// Foreign version: explicit incompatibility, never silent adoption.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE schema_version SET version = 99`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if _, err := Open(ctx, Config{Path: path}); err == nil {
		t.Fatal("version 99 must be rejected")
	} else if got := err.Error(); !contains(got, "unsupported") {
		t.Fatalf("rejection must say unsupported, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func storetestAsset() *v1.Asset {
	ts := timestamppb.New(time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC))
	return &v1.Asset{
		Id: "ast-mig-1", Type: v1.AssetType_ASSET_TYPE_DOMAIN, Name: "example.com",
		Environment: "lab", Status: v1.AssetStatus_ASSET_STATUS_ACTIVE,
		FirstSeen: ts, LastSeen: ts,
		Identifiers: []*v1.AssetIdentifier{{Type: "domain", Value: "example.com"}},
	}
}

// TestMigrationV1ToV2 builds a genuine v1-layout database by hand (as Step-10
// code would have left it: version row 1, no asset tables), then opens it
// with current code: additive upgrade, pre-existing rows preserved, version
// lands on CurrentSchemaVersion.
func TestMigrationV1ToV2(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v1.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE schema_version (version INTEGER PRIMARY KEY)`,
		`INSERT INTO schema_version (version) VALUES (1)`,
		`CREATE TABLE incidents (
			id TEXT PRIMARY KEY, alert_ids TEXT NOT NULL, status INTEGER NOT NULL,
			severity INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
			title TEXT NOT NULL, summary TEXT
		)`,
		`INSERT INTO incidents (id, alert_ids, status, severity, created_at, updated_at, title, summary)
		 VALUES ('inc-legacy', '["a1"]', 1, 4, '2026-09-12T09:00:00Z', '2026-09-12T09:00:00Z', 'Legacy', 'old')`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("v1 fixture: %v", err)
		}
	}
	raw.Close()

	db, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("v1→v2 upgrade must succeed: %v", err)
	}
	defer db.Close()
	v, err := SchemaVersion(ctx, db.db)
	if err != nil || v != CurrentSchemaVersion {
		t.Fatalf("upgraded version: %d %v", v, err)
	}
	// Legacy row survived the upgrade byte-identical.
	be := db.Backend()
	got, err := be.Incident.Get(ctx, "inc-legacy")
	if err != nil || got.GetTitle() != "Legacy" || got.GetSummary() != "old" {
		t.Fatalf("legacy row drift: %+v %v", got, err)
	}
	// New tables usable immediately.
	a := storetestAsset()
	if err := be.Assets.Create(ctx, a); err != nil {
		t.Fatalf("post-upgrade asset create: %v", err)
	}
}

func TestRestartPersistence(t *testing.T) {
	ctx := context.Background()
	db, path := openFile(t)
	be := db.Backend()
	inc := storetestIncident()
	if err := be.Incident.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}
	ev := storetestEvidence(inc.GetId())
	if err := be.Evidence.Append(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := be.Audit.Append(ctx, storetestAudit()); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Restart: read back exactly what was written.
	db2, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	be2 := db2.Backend()
	gotInc, err := be2.Incident.Get(ctx, inc.GetId())
	if err != nil || !proto.Equal(gotInc, inc) {
		t.Fatalf("incident restart drift: %+v %v", gotInc, err)
	}
	gotEv, err := be2.Evidence.Get(ctx, ev.GetId())
	if err != nil || !evidence.Verify(gotEv) {
		t.Fatalf("evidence restart drift: %+v %v", gotEv, err)
	}
	list, err := be2.Audit.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != "audit-0001" {
		t.Fatalf("audit restart drift: %+v %v", list, err)
	}
}

func TestTransactionRollback(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	inc := storetestIncident()
	first := storetestEvidence(inc.GetId())
	dup := storetestEvidence(inc.GetId())
	dup.Id = first.GetId() // same id twice: second insert must fail the unit
	if err := CreateIncidentWithEvidence(ctx, db, inc, []*v1.Evidence{first, dup}); err == nil {
		t.Fatal("duplicate evidence must fail the transaction")
	} else if !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}
	// Rollback: neither the incident nor the evidence survived.
	if _, err := be.Incident.Get(ctx, inc.GetId()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back incident must be absent, got %v", err)
	}
	if _, err := be.Evidence.Get(ctx, first.GetId()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back evidence must be absent, got %v", err)
	}
	// Clean unit commits.
	second := storetestEvidence(inc.GetId())
	second.Id = "ev-rollback-2"
	if err := CreateIncidentWithEvidence(ctx, db, inc, []*v1.Evidence{first, second}); err != nil {
		t.Fatalf("clean unit must commit: %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	db, _ := openFile(t)
	be := db.Backend()

	// Distinct ids: all writers succeed, count is exact.
	const writers = 8
	const perWriter = 25
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				e := storetestTelemetry(w, i)
				if err := be.Telemetry.Append(ctx, e); err != nil {
					errs[w] = err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	for w, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", w, err)
		}
	}
	list, err := be.Telemetry.List(ctx)
	if err != nil || len(list) != writers*perWriter {
		t.Fatalf("want %d rows, got %d %v", writers*perWriter, len(list), err)
	}

	// Same id raced: exactly one wins, the rest get explicit duplicates.
	var wg2 sync.WaitGroup
	results := make([]error, writers)
	for w := 0; w < writers; w++ {
		wg2.Add(1)
		go func(w int) {
			defer wg2.Done()
			results[w] = be.Telemetry.Append(ctx, storetestTelemetry(999, 999))
		}(w)
	}
	wg2.Wait()
	ok, dup := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, store.ErrDuplicate):
			dup++
		default:
			t.Fatalf("unexpected race error: %v", err)
		}
	}
	if ok != 1 || dup != writers-1 {
		t.Fatalf("exactly one winner: ok=%d dup=%d", ok, dup)
	}

	// Same incident saved concurrently: no error, final row is one
	// complete write (never a mix, never an error).
	inc := storetestIncident()
	if err := be.Incident.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}
	var wg3 sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg3.Add(1)
		go func(w int) {
			defer wg3.Done()
			updated := storetestIncident()
			updated.Summary = fmt.Sprintf("writer-%d", w)
			if err := be.Incident.Save(ctx, updated); err != nil {
				t.Errorf("concurrent save: %v", err)
			}
		}(w)
	}
	wg3.Wait()
	got, err := be.Incident.Get(ctx, inc.GetId())
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for w := 0; w < writers; w++ {
		if got.GetSummary() == fmt.Sprintf("writer-%d", w) {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("final state must equal one complete write, got %q", got.GetSummary())
	}
}

// TestCorruptedGovernanceSurfaces proves hand-poisoned GRC payloads fail
// closed on read instead of surfacing as silently dropped rows.
func TestCorruptedGovernanceSurfaces(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	ass := grc.Assessment{
		ControlID: "AC-1", Target: "t", Status: grc.StatusNotAssessed,
		Assessor: "s", ObservedAt: now,
	}
	if err := be.Assessments.Create(ctx, ass); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.ExecContext(ctx, `UPDATE grc_assessments SET payload = ? WHERE id = ?`,
		"{not-json", ass.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Assessments.Get(ctx, ass.ID()); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("tampered assessment must surface ErrCorrupted, got %v", err)
	}
	if _, err := be.Assessments.List(ctx); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("tampered assessment list must surface ErrCorrupted, got %v", err)
	}
}

func TestCorruptedEvidenceSurfaces(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	inc := storetestIncident()
	if err := be.Incident.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}
	ev := storetestEvidence(inc.GetId())
	if err := be.Evidence.Append(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// Corrupt the bytes behind the repository's back (no update API exists
	// to do this legitimately).
	if _, err := db.db.ExecContext(ctx, `UPDATE evidence SET content = ? WHERE id = ?`,
		"tampered", ev.GetId()); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Evidence.Get(ctx, ev.GetId()); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("tampered evidence must surface ErrCorrupted, got %v", err)
	}
	// Untouched rows still read fine.
	ev2 := storetestEvidence(inc.GetId())
	ev2.Id = "ev-clean-2"
	if err := be.Evidence.Append(ctx, ev2); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Evidence.Get(ctx, ev2.GetId()); err != nil {
		t.Fatalf("clean row must read: %v", err)
	}
}

func TestForeignKeyEnforcement(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	// Evidence for a nonexistent incident: the FK refuses, explicitly.
	if err := be.Evidence.Append(ctx, storetestEvidence("inc-ghost")); err == nil {
		t.Fatal("orphan evidence must be refused")
	}
}

func TestClosedHandleFailsExplicitly(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	db.Close()
	if err := be.Telemetry.Append(ctx, storetestTelemetry(1, 1)); err == nil {
		t.Fatal("writes after Close must fail")
	}
	if _, err := be.Telemetry.Get(ctx, "x"); err == nil {
		t.Fatal("reads after Close must fail")
	}
	if err := db.Ping(ctx); err == nil {
		t.Fatal("ping after Close must fail")
	}
}

func TestCancelledContextFailsCleanly(t *testing.T) {
	db := openMemory(t)
	be := db.Backend()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := be.Telemetry.Append(ctx, storetestTelemetry(1, 1)); err == nil {
		t.Fatal("cancelled writes must fail")
	}
	// The handle itself stays usable afterwards.
	if err := be.Telemetry.Append(context.Background(), storetestTelemetry(1, 1)); err != nil {
		t.Fatalf("backend must survive cancellation: %v", err)
	}
}

// TestMigrationV2ToV3 builds a genuine v2-layout database by hand (version
// row 2 plus one validation result, no campaign tables), then opens it
// with current code: additive upgrade, pre-existing rows preserved,
// version lands on CurrentSchemaVersion, campaign/exercise/GRC tables
// usable immediately.
func TestMigrationV2ToV3(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v2.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE schema_version (version INTEGER PRIMARY KEY)`,
		`INSERT INTO schema_version (version) VALUES (2)`,
		`CREATE TABLE validation_results (
			id TEXT PRIMARY KEY, request_id TEXT NOT NULL, control_id TEXT NOT NULL,
			provider TEXT NOT NULL, provider_version TEXT, contract_version TEXT NOT NULL,
			verdict INTEGER NOT NULL, validated_at TEXT NOT NULL, evidence_ids TEXT NOT NULL, note TEXT
		)`,
		`INSERT INTO validation_results (id, request_id, control_id, provider, contract_version, verdict, validated_at, evidence_ids)
		 VALUES ('vres-legacy', 'vreq-legacy', 'ctl', 'p', 'blueveil.contracts.v1', 2, '2026-09-12T10:00:00Z', '[]')`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("v2 fixture: %v", err)
		}
	}
	raw.Close()

	db, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("v2→v%d upgrade must succeed: %v", CurrentSchemaVersion, err)
	}
	defer db.Close()
	v, err := SchemaVersion(ctx, db.db)
	if err != nil || v != CurrentSchemaVersion {
		t.Fatalf("upgraded version: %d %v", v, err)
	}
	be := db.Backend()
	got, err := be.Validation.GetResult(ctx, "vres-legacy")
	if err != nil || got.GetControlId() != "ctl" {
		t.Fatalf("legacy row drift: %+v %v", got, err)
	}
	camp := validation.Campaign{
		Name: "post-upgrade", Target: "t", Provider: validation.NativeProviderID,
		Source: "s", Status: validation.StatusDraft,
	}
	if err := be.Campaigns.Create(ctx, camp); err != nil {
		t.Fatalf("post-upgrade campaign create: %v", err)
	}
	ex, err := validation.BuildExercise(validation.ExerciseInput{
		CampaignID: camp.ID(), Name: "e", Source: "s",
		Entries: []validation.ExerciseEntryInput{{
			CaseID: "c", RequestID: "r", ResultID: "vres-legacy",
			Verdict: 2, TelemetryIDs: []string{"evt-1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Exercises.Create(ctx, ex); err != nil {
		t.Fatalf("post-upgrade exercise create: %v", err)
	}
	// v4 GRC tables usable immediately after the same upgrade.
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	ass := grc.Assessment{
		ControlID: "AC-1", Target: "t", Status: grc.StatusNotAssessed,
		Assessor: "s", ObservedAt: now,
	}
	if err := be.Assessments.Create(ctx, ass); err != nil {
		t.Fatalf("post-upgrade assessment create: %v", err)
	}
	rec, err := grc.AssessResilience(grc.ResilienceInput{
		Target: "t", Assessor: "s", ObservedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Resilience.Create(ctx, rec); err != nil {
		t.Fatalf("post-upgrade resilience create: %v", err)
	}
}

// TestMigrationV4ToV5 builds a genuine v4-layout database by hand (version
// row 4 plus one assessment, no supply tables), then opens it with current
// code: additive upgrade, pre-existing rows preserved, version lands on
// CurrentSchemaVersion, supply tables usable immediately.
func TestMigrationV4ToV5(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v4.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE schema_version (version INTEGER PRIMARY KEY)`,
		`INSERT INTO schema_version (version) VALUES (4)`,
		`CREATE TABLE grc_assessments (id TEXT PRIMARY KEY, payload TEXT NOT NULL)`,
		`INSERT INTO grc_assessments (id, payload) VALUES ('gass-legacy', '{"ControlID":"AC-1","Target":"t","Status":"NOT_ASSESSED","Assessor":"s","ObservedAt":"2026-09-12T10:00:00Z"}')`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("v4 fixture: %v", err)
		}
	}
	raw.Close()

	db, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("v4→v%d upgrade must succeed: %v", CurrentSchemaVersion, err)
	}
	defer db.Close()
	v, err := SchemaVersion(ctx, db.db)
	if err != nil || v != CurrentSchemaVersion {
		t.Fatalf("upgraded version: %d %v", v, err)
	}
	be := db.Backend()
	got, err := be.Assessments.Get(ctx, "gass-legacy")
	if err != nil || got.ControlID != "AC-1" {
		t.Fatalf("legacy row drift: %+v %v", got, err)
	}
	comp := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
		Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
		Source: "s", ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		Status: supplychain.StatusObserved,
	}
	if err := be.Components.Create(ctx, comp); err != nil {
		t.Fatalf("post-upgrade component create: %v", err)
	}
}

// TestCorruptedSupplySurfaces proves hand-poisoned supply payloads fail
// closed on read instead of surfacing as silently dropped rows.
func TestCorruptedSupplySurfaces(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	comp := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
		Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
		Source: "s", ObservedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		Status: supplychain.StatusObserved,
	}
	if err := be.Components.Create(ctx, comp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.ExecContext(ctx, `UPDATE supply_components SET payload = ? WHERE id = ?`,
		"{not-json", comp.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Components.Get(ctx, comp.ID()); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("tampered component must surface ErrCorrupted, got %v", err)
	}
	if _, err := be.Components.List(ctx); !errors.Is(err, store.ErrCorrupted) {
		t.Fatalf("tampered component list must surface ErrCorrupted, got %v", err)
	}
}

func TestDoubleCloseSafe(t *testing.T) {
	db := openMemory(t)
	if err := db.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// Second close must not panic; error or nil are both explicit.
	_ = db.Close()
}
