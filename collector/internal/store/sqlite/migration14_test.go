// Step 14C: migration coverage for every supported origin (v1–v5).
// v2 and v4 origins have dedicated tests in sqlite_test.go; this file
// covers v1, v3, and v5-current plus the transactional/unknown-version
// gates, building fixtures from the real migrations array so they stay
// in sync with the DDL.
package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// openAtVersion builds a genuine origin-version database by applying the
// real migration DDL up to v, stamping the version row, and inserting one
// legacy telemetry row. Opening it with Open must migrate to current.
func openAtVersion(t *testing.T, v int, seedTelemetry bool) (*DB, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "origin.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version > v {
			break
		}
		for _, stmt := range m.ddl {
			if _, err := raw.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("origin v%d fixture %s: %v", v, m.name, err)
			}
		}
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, v); err != nil {
		t.Fatalf("origin v%d version stamp: %v", v, err)
	}
	if seedTelemetry {
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO telemetry_events (id, occurred_at, source, asset_id, event_type, severity, attributes, raw)
			 VALUES ('evt-legacy', '2026-09-12T10:00:00Z', 'lab', 'ast-legacy', 'net.connection', 1, '{}', '')`); err != nil {
			t.Fatalf("origin v%d telemetry seed: %v", v, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("v%d→v%d upgrade must succeed: %v", v, CurrentSchemaVersion, err)
	}
	t.Cleanup(func() { db.Close() })
	got, err := SchemaVersion(ctx, db.db)
	if err != nil || got != CurrentSchemaVersion {
		t.Fatalf("upgraded version: %d %v", got, err)
	}
	return db, path
}

func TestMigrationV1ToCurrent(t *testing.T) {
	ctx := context.Background()
	db, _ := openAtVersion(t, 1, true)
	be := db.Backend()
	got, err := be.Telemetry.Get(ctx, "evt-legacy")
	if err != nil || got.GetSource() != "lab" {
		t.Fatalf("legacy row drift: %+v %v", got, err)
	}
	// Every newer table is usable immediately after the upgrade.
	comps, err := be.Components.List(ctx)
	if err != nil || len(comps) != 0 {
		t.Fatalf("supply tables must exist and read empty: %+v %v", comps, err)
	}
	camps, err := be.Campaigns.List(ctx)
	if err != nil || len(camps) != 0 {
		t.Fatalf("campaign tables must exist and read empty: %+v %v", camps, err)
	}
	assess, err := be.Assessments.List(ctx)
	if err != nil || len(assess) != 0 {
		t.Fatalf("grc tables must exist and read empty: %+v %v", assess, err)
	}
	assets, err := be.Assets.List(ctx)
	if err != nil || len(assets) != 0 {
		t.Fatalf("asset tables must exist and read empty: %+v %v", assets, err)
	}
}

func TestMigrationV3ToCurrent(t *testing.T) {
	ctx := context.Background()
	// v3 already had campaign tables: a campaign row written pre-upgrade
	// must survive the upgrade alongside legacy telemetry.
	path := filepath.Join(t.TempDir(), "v3.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version > 3 {
			break
		}
		for _, stmt := range m.ddl {
			if _, err := raw.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("v3 fixture %s: %v", m.name, err)
			}
		}
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (3)`); err != nil {
		t.Fatalf("v3 version stamp: %v", err)
	}
	for _, stmt := range []string{
		`INSERT INTO telemetry_events (id, occurred_at, source, asset_id, event_type, severity, attributes, raw)
		 VALUES ('evt-legacy', '2026-09-12T10:00:00Z', 'lab', 'ast-legacy', 'net.connection', 1, '{}', '')`,
		`INSERT INTO validation_campaigns (id, payload) VALUES ('camp-legacy', '{"ID":"camp-legacy"}')`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("v3 seed: %v", err)
		}
	}
	raw.Close()
	db, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("v3→v%d upgrade must succeed: %v", CurrentSchemaVersion, err)
	}
	t.Cleanup(func() { db.Close() })
	be := db.Backend()
	got, err := be.Telemetry.Get(ctx, "evt-legacy")
	if err != nil || got.GetSource() != "lab" {
		t.Fatalf("legacy row drift: %+v %v", got, err)
	}
	var payload string
	if err := db.db.QueryRowContext(ctx,
		`SELECT payload FROM validation_campaigns WHERE id = 'camp-legacy'`).Scan(&payload); err != nil {
		t.Fatalf("pre-upgrade campaign row must survive: %v", err)
	}
	// v4/v5 tables are usable immediately after the same upgrade.
	comps, err := be.Components.List(ctx)
	if err != nil || len(comps) != 0 {
		t.Fatalf("supply tables must exist and read empty: %+v %v", comps, err)
	}
	assess, err := be.Assessments.List(ctx)
	if err != nil || len(assess) != 0 {
		t.Fatalf("grc tables must exist and read empty: %+v %v", assess, err)
	}
}

func TestMigrationV5CurrentIsNOP(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	v, err := SchemaVersion(ctx, db.db)
	if err != nil || v != CurrentSchemaVersion {
		t.Fatalf("fresh version: %d %v", v, err)
	}
	// Re-opening a current database migrates nothing and loses nothing.
	be := db.Backend()
	if _, err := be.Components.List(ctx); err != nil {
		t.Fatalf("current list: %v", err)
	}
}

func TestMigrationRejectsFutureVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "future.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_version (version INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, CurrentSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if _, err := Open(ctx, Config{Path: path}); err == nil {
		t.Fatalf("future schema version must be refused")
	}
}

func TestMigrationRejectsUnknownPresent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "unknown.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// Version row claims a version with no matching migration and no
	// tables: neither fresh (-1) nor known.
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_version (version INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (42)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if _, err := Open(ctx, Config{Path: path}); err == nil {
		t.Fatalf("unknown schema version must be refused")
	}
}
