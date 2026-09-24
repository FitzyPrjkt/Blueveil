// Live backup/restore cycles (19B/19C) plus failure regression (19I).
// SQLite cycles run everywhere (file databases in t.TempDir); PostgreSQL
// cycles need BLUEVEIL_TEST_POSTGRES and skip honestly otherwise.
package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/config"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/store/sqlite"
)

func sqliteTestConfig(t *testing.T) config.Config {
	t.Helper()
	c := config.LabDefaults()
	c.Database.SQLitePath = filepath.Join(t.TempDir(), "src.db")
	return c
}

func seedSQLite(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	be := db.Backend()
	mustAppendTelemetry(t, ctx, be, "evt-b1")
}

func TestSQLiteBackupRestoreCycle(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	// Rich multi-domain seed for full verification after restore.
	db0, err := sqlite.Open(ctx, sqlite.Config{Path: cfg.Database.SQLitePath})
	if err != nil {
		t.Fatal(err)
	}
	_, anchors := seedAllDomains(t, ctx, db0.Backend())
	db0.Close()

	parent := t.TempDir()
	dir, m, err := Backup(ctx, cfg, parent)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if m.Backend != "sqlite" || m.SchemaVersion != sqlite.CurrentSchemaVersion {
		t.Fatalf("manifest: %+v", m)
	}
	if m.Tables["telemetry_events"] != 2 {
		t.Fatalf("manifest counts: %+v", m.Tables)
	}
	if _, err := os.Stat(filepath.Join(dir, "blueveil.db")); err != nil {
		t.Fatalf("payload missing: %v", err)
	}

	// Restore into an isolated target: counts reproduce exactly.
	target := filepath.Join(t.TempDir(), "restored.db")
	rcfg := cfg
	rcfg.Database.SQLitePath = target
	counts, err := Restore(ctx, rcfg, dir, RestoreTarget{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if counts["telemetry_events"] != 2 {
		t.Fatalf("restored counts: %+v", counts)
	}
	// Restored database opens and serves through the real backend:
	// every domain re-verified, digests recomputed, ids stable.
	db, err := sqlite.Open(ctx, sqlite.Config{Path: target})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	verifyAllDomains(t, ctx, db.Backend(), anchors)
}

func TestSQLiteBackupWhileWriting(t *testing.T) {
	// VACUUM INTO must stay consistent under concurrent writers: the
	// snapshot reflects a transactionally consistent point, never a tear.
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	db, err := sqlite.Open(ctx, sqlite.Config{Path: cfg.Database.SQLitePath})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	be := db.Backend()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				_ = be.Telemetry.Append(ctx, mustTelemetry("evt-w-"+itoa(i)))
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, cfg, parent)
	close(stop)
	<-done
	if err != nil {
		t.Fatalf("backup under write load: %v", err)
	}
	if _, err := ReadManifest(dir); err != nil {
		t.Fatalf("backup under load must verify: %v", err)
	}
}

func TestRestoreRefusesConflictingTarget(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, cfg, parent)
	if err != nil {
		t.Fatal(err)
	}
	// Target exists with different state: refuse without force.
	other := filepath.Join(t.TempDir(), "other.db")
	seedSQLite(t, ctx, other)
	rcfg := cfg
	rcfg.Database.SQLitePath = other
	if _, err := Restore(ctx, rcfg, dir, RestoreTarget{}); err == nil {
		t.Fatalf("conflicting target must be refused without force")
	}
	// Explicit force replaces and verifies.
	counts, err := Restore(ctx, rcfg, dir, RestoreTarget{Force: true})
	if err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	if counts["telemetry_events"] != 1 {
		t.Fatalf("forced restore counts: %+v", counts)
	}
}

func TestRestoreRefusesBackendMismatch(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, cfg, parent)
	if err != nil {
		t.Fatal(err)
	}
	// Same backup presented as postgres: refused before any database is
	// touched (no live server needed for the refusal).
	pgcfg := sqliteTestConfig(t)
	pgcfg.Database.Backend = config.BackendPostgres
	if _, err := Restore(ctx, pgcfg, dir, RestoreTarget{}); err == nil {
		t.Fatalf("cross-backend restore must be refused")
	}
}

func TestRestoreIgnoresExtraArchiveFiles(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, cfg, parent)
	if err != nil {
		t.Fatal(err)
	}
	// Unexpected archive contents must not affect the restore.
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("junk"), 0644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "r.db")
	rcfg := cfg
	rcfg.Database.SQLitePath = target
	if _, err := Restore(ctx, rcfg, dir, RestoreTarget{}); err != nil {
		t.Fatalf("extra archive files must be ignored: %v", err)
	}
}

func TestConcurrentBackupsSerialize(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	const n = 4
	type result struct {
		dir string
		err error
	}
	done := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			dir, _, err := Backup(ctx, cfg, parent)
			done <- result{dir, err}
		}()
	}
	won := map[string]bool{}
	failed := 0
	for i := 0; i < n; i++ {
		r := <-done
		if r.err != nil {
			failed++
			continue
		}
		if won[r.dir] {
			t.Fatalf("two backups must never share a directory: %s", r.dir)
		}
		won[r.dir] = true
	}
	// Exactly one winner (same-second names collide) or several with
	// distinct names; every completed backup verifies; nothing corrupt.
	if len(won) == 0 {
		t.Fatalf("at least one backup must succeed")
	}
	for dir := range won {
		if _, err := ReadManifest(dir); err != nil {
			t.Fatalf("completed backup must verify: %v", err)
		}
	}
	t.Logf("concurrent backups: %d won, %d refused", len(won), failed)
}

func TestBackupCancelledContext(t *testing.T) {
	cfg := sqliteTestConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	parent := t.TempDir()
	if _, _, err := Backup(ctx, cfg, parent); err == nil {
		t.Fatalf("cancelled backup must fail explicitly")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "backup-") {
			t.Fatalf("cancelled backup left %s behind", e.Name())
		}
	}
}

func TestBackupLeavesSourceUntouched(t *testing.T) {
	// Invariant: backup is read-only against the source. Hash the live
	// database file before and after: identical bytes.
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	before, err := os.ReadFile(cfg.Database.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if _, _, err := Backup(ctx, cfg, parent); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg.Database.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("backup mutated the source database")
	}
}

func TestRestoreLeavesBackupPristine(t *testing.T) {
	// Invariant: restore never writes into the backup directory. The
	// manifest re-verifies byte-identical after a restore ran from it.
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, cfg, parent)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "r.db")
	rcfg := cfg
	rcfg.Database.SQLitePath = target
	if _, err := Restore(ctx, rcfg, dir, RestoreTarget{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(dir); err != nil {
		t.Fatalf("backup must verify after being restored from: %v", err)
	}
}

func TestRestoreRejectsDBNameForSQLite(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, cfg, parent)
	if err != nil {
		t.Fatal(err)
	}
	// --restore-dbname is postgres-only: silently retargeting a sqlite
	// restore would scatter databases across the filesystem.
	if _, err := Restore(ctx, cfg, dir, RestoreTarget{Database: "elsewhere"}); err == nil {
		t.Fatalf("sqlite restore with dbname override must fail explicitly")
	}
}

func TestRestoreRejectsTamperedBackup(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	dir, _, err := Backup(ctx, cfg, parent)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the payload in place (simulating a damaged archive).
	f, err := os.OpenFile(filepath.Join(dir, "blueveil.db"), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteAt([]byte("FORGED!"), 100)
	f.Close()
	rcfg := cfg
	rcfg.Database.SQLitePath = filepath.Join(t.TempDir(), "r.db")
	if _, err := Restore(ctx, rcfg, dir, RestoreTarget{}); err == nil {
		t.Fatalf("tampered backup must fail manifest verification")
	}
}

func TestBackupRejectsMissingSource(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t) // never seeded: no file at all
	if _, _, err := Backup(ctx, cfg, t.TempDir()); err == nil {
		t.Fatalf("missing source must fail explicitly")
	}
	var bad config.Config
	if _, _, err := Backup(ctx, bad, t.TempDir()); err == nil {
		t.Fatalf("invalid config must fail before side effects")
	}
}

func TestPruneEndToEnd(t *testing.T) {
	ctx := context.Background()
	cfg := sqliteTestConfig(t)
	seedSQLite(t, ctx, cfg.Database.SQLitePath)
	parent := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, _, err := Backup(ctx, cfg, parent); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond) // distinct timestamp names
	}
	removed, err := Prune(parent, 2)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("want 1 removal, got %d", removed)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 backups left, got %d", len(entries))
	}
	for _, e := range entries {
		if _, err := ReadManifest(filepath.Join(parent, e.Name())); err != nil {
			t.Fatalf("survivors must verify: %v", e.Name())
		}
	}
}

func mustTelemetry(id string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: "lab", AssetId: "ast-1", EventType: "net.connection",
		Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
			"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
		},
	}
}

func mustAppendTelemetry(t *testing.T, ctx context.Context, be store.Backend, id string) {
	t.Helper()
	if err := be.Telemetry.Append(ctx, mustTelemetry(id)); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [32]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
