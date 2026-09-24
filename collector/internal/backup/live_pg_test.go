// Live PostgreSQL backup/restore/disaster tests (19B–19D, 19F).
// Gated on BLUEVEIL_TEST_POSTGRES (admin conn string); each test uses
// isolated databases and never touches the operator's active dataset.
package backup

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"blueveil/collector/internal/config"
	"blueveil/collector/internal/store/postgres"
)

func pgAdmin(t *testing.T, ctx context.Context) (*pgx.Conn, string) {
	t.Helper()
	cs := strings.TrimSpace(os.Getenv("BLUEVEIL_TEST_POSTGRES"))
	if cs == "" {
		t.Skip("BLUEVEIL_TEST_POSTGRES unset: live PG backup tests skipped (nothing faked)")
	}
	c, err := pgx.Connect(ctx, cs)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { c.Close(ctx) })
	return c, cs
}

func pgTestConfig(dbname string) config.Config {
	c := config.LabDefaults()
	c.Database.Backend = config.BackendPostgres
	c.Database.Postgres = config.PostgresConfig{
		Host: "/tmp/pgtest", Port: 55433, User: "blueveil_test",
		DBName: dbname, SSLMode: "disable",
	}
	return c
}

func mkPGDB(t *testing.T, ctx context.Context, admin *pgx.Conn, name string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+quotePG(name)+` WITH (FORCE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+quotePG(name)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+quotePG(name)+` WITH (FORCE)`)
	})
}

func quotePG(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func seedPG(t *testing.T, ctx context.Context, cfg config.Config) {
	t.Helper()
	pg := cfg.Database.Postgres
	db, err := openPGForSeed(ctx, pg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustAppendTelemetry(t, ctx, db.Backend(), "evt-pg-1")
}

func TestPGBackupRestoreCycle(t *testing.T) {
	ctx := context.Background()
	admin, _ := pgAdmin(t, ctx)
	mkPGDB(t, ctx, admin, "blueveil_bk_src")
	src := pgTestConfig("blueveil_bk_src")
	seedPG(t, ctx, src)
	// Rich multi-domain seed for full verification after restore.
	srcDB := mustOpenPG(t, ctx, src)
	_, anchors := seedAllDomains(t, ctx, srcDB.Backend())
	srcDB.Close()

	parent := t.TempDir()
	dir, m, err := Backup(ctx, src, parent)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if m.Backend != "postgres" || m.SchemaVersion != 5 || m.Tables["telemetry_events"] != 2 {
		t.Fatalf("manifest: %+v", m)
	}

	// Restore into an isolated target: every domain re-verified.
	mkPGDB(t, ctx, admin, "blueveil_bk_dst")
	dst := pgTestConfig("blueveil_bk_dst")
	counts, err := Restore(ctx, dst, dir, RestoreTarget{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if counts["telemetry_events"] != 2 {
		t.Fatalf("restored counts: %+v", counts)
	}
	dstDB := mustOpenPG(t, ctx, dst)
	defer dstDB.Close()
	verifyAllDomains(t, ctx, dstDB.Backend(), anchors)
}

func TestPGInterruptedBackupLeavesNothing(t *testing.T) {
	ctx := context.Background()
	_, _ = pgAdmin(t, ctx)
	// Unreachable database: pg_dump fails, explicit error, no partial dir.
	bad := pgTestConfig("blueveil_no_such_db_xyz")
	bad.Database.Postgres.Port = 1
	parent := t.TempDir()
	if _, _, err := Backup(ctx, bad, parent); err == nil {
		t.Fatalf("unreachable DB backup must fail")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed backup must leave nothing, left %d entries", len(entries))
	}
}

func TestPGCorruptDumpRestoreFails(t *testing.T) {
	ctx := context.Background()
	admin, _ := pgAdmin(t, ctx)
	mkPGDB(t, ctx, admin, "blueveil_bk_csrc")
	src := pgTestConfig("blueveil_bk_csrc")
	seedPG(t, ctx, src)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, src, parent)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the dump (truncate mid-statement): manifest catches it.
	dump := dir + "/dump.sql"
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dump, raw[:len(raw)/2], 0600); err != nil {
		t.Fatal(err)
	}
	mkPGDB(t, ctx, admin, "blueveil_bk_cdst")
	dst := pgTestConfig("blueveil_bk_cdst")
	if _, err := Restore(ctx, dst, dir, RestoreTarget{}); err == nil {
		t.Fatalf("corrupt dump restore must fail (manifest hash gate)")
	}
}

func TestPGRestoreRefusesConflictingTarget(t *testing.T) {
	ctx := context.Background()
	admin, _ := pgAdmin(t, ctx)
	mkPGDB(t, ctx, admin, "blueveil_bk_qsrc")
	src := pgTestConfig("blueveil_bk_qsrc")
	seedPG(t, ctx, src)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, src, parent)
	if err != nil {
		t.Fatal(err)
	}
	// Target holds different state: refuse without force.
	mkPGDB(t, ctx, admin, "blueveil_bk_qdst")
	dst := pgTestConfig("blueveil_bk_qdst")
	seedPG(t, ctx, dst)
	if _, err := Restore(ctx, dst, dir, RestoreTarget{}); err == nil {
		t.Fatalf("conflicting target must be refused without force")
	}
}

func openPGForSeed(ctx context.Context, pg config.PostgresConfig) (*postgres.DB, error) {
	return postgres.Open(ctx, postgres.Config{
		Host: pg.Host, Port: pg.Port, User: pg.User, Password: pg.Password,
		DBName: pg.DBName, SSLMode: pg.SSLMode, MaxConns: 2,
	})
}

func mustOpenPG(t *testing.T, ctx context.Context, cfg config.Config) *postgres.DB {
	t.Helper()
	pg := cfg.Database.Postgres
	db, err := postgres.Open(ctx, postgres.Config{
		Host: pg.Host, Port: pg.Port, User: pg.User, Password: pg.Password,
		DBName: pg.DBName, SSLMode: pg.SSLMode, MaxConns: 2,
	})
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	return db
}
