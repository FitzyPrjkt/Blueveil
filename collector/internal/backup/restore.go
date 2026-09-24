// Restore paths: validated manifests into isolated targets, with
// count-verified results. Restores never write into the backup
// directory, never overwrite a conflicting target without explicit
// force, and never auto-repair: verification failures leave the target
// in place for investigation and report explicitly.
package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"blueveil/collector/internal/config"
	"blueveil/collector/internal/store/postgres"
	"blueveil/collector/internal/store/sqlite"
)

// RestoreTarget overrides where a restore lands. For PostgreSQL it is
// the (fresh, isolated) database name; for SQLite it is the destination
// file path. Empty means the config's own target.
type RestoreTarget struct {
	Database string
	Force    bool
}

// Restore validates backupDir and restores it into cfg's backend. It
// returns the verified table counts.
func Restore(ctx context.Context, cfg config.Config, backupDir string, target RestoreTarget) (map[string]int64, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("restore: invalid configuration: %v", err)
	}
	m, err := ReadManifest(backupDir)
	if err != nil {
		return nil, err
	}
	if m.Backend != string(cfg.Database.Backend) {
		return nil, fmt.Errorf("restore: backup backend %q does not match configured %q (cross-backend restores refused)",
			m.Backend, cfg.Database.Backend)
	}
	switch cfg.Database.Backend {
	case config.BackendSQLite:
		return restoreSQLite(ctx, cfg, backupDir, m, target)
	case config.BackendPostgres:
		return restorePostgres(ctx, cfg, backupDir, m, target)
	default:
		return nil, fmt.Errorf("restore: unknown backend %q", cfg.Database.Backend)
	}
}

func verifyCounts(have, want map[string]int64) error {
	for table, n := range want {
		if have[table] != n {
			return fmt.Errorf("restore: table %s has %d rows, backup recorded %d: incomplete restore",
				table, have[table], n)
		}
	}
	for table := range have {
		if _, ok := want[table]; !ok {
			return fmt.Errorf("restore: unexpected table %s: refusing foreign state", table)
		}
	}
	return nil
}

func restoreSQLite(ctx context.Context, cfg config.Config, backupDir string, m Manifest, target RestoreTarget) (map[string]int64, error) {
	if target.Database != "" {
		return nil, fmt.Errorf("restore: --restore-dbname is postgres-only; sqlite restores to the configured sqlite_path (replace it with --force)")
	}
	dest := cfg.Database.SQLitePath
	payload := filepath.Join(backupDir, "blueveil.db")
	if _, err := os.Stat(payload); err != nil {
		return nil, fmt.Errorf("restore: sqlite payload missing: %v", err)
	}
	if _, err := os.Stat(dest); err == nil && !target.Force {
		return nil, fmt.Errorf("restore: target %s exists (refusing to overwrite without force)", dest)
	} else if err == nil {
		if err := os.Remove(dest); err != nil {
			return nil, fmt.Errorf("restore: remove existing target: %v", err)
		}
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			_ = os.Remove(dest + suffix)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return nil, fmt.Errorf("restore: create target dir: %v", err)
	}
	// Copy (never move): the backup directory stays pristine.
	if err := copyFile(payload, dest); err != nil {
		return nil, fmt.Errorf("restore: copy: %v", err)
	}
	// Open migrates older schemas forward; future schemas refuse.
	db, err := sqlite.Open(ctx, sqlite.Config{Path: dest})
	if err != nil {
		return nil, fmt.Errorf("restore: open restored database (left in place for investigation): %v", err)
	}
	defer db.Close()
	be := db.Backend()
	_ = be
	counts, err := sqliteCountsRO(ctx, dest)
	if err != nil {
		return nil, fmt.Errorf("restore: count restored database (left in place for investigation): %v", err)
	}
	if err := verifyCounts(counts, m.Tables); err != nil {
		return nil, fmt.Errorf("%v (target left in place for investigation)", err)
	}
	return counts, nil
}

func sqliteCountsRO(ctx context.Context, dest string) (map[string]int64, error) {
	_ = ctx
	db, err := openSQLiteRO(dest)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return sqliteCounts(db)
}

func copyFile(src, dest string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, raw, 0600)
}

func restorePostgres(ctx context.Context, cfg config.Config, backupDir string, m Manifest, target RestoreTarget) (map[string]int64, error) {
	pg := cfg.Database.Postgres
	dbname := pg.DBName
	if target.Database != "" {
		dbname = target.Database
	}
	dump := filepath.Join(backupDir, "dump.sql")
	if _, err := os.Stat(dump); err != nil {
		return nil, fmt.Errorf("restore: postgres payload missing: %v", err)
	}
	adminCS := pgConnString(pg, "postgres")
	admin, err := pgx.Connect(ctx, adminCS)
	if err != nil {
		return nil, fmt.Errorf("restore: admin connect: %v", err)
	}
	defer admin.Close(ctx)
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, dbname).Scan(&exists); err != nil {
		return nil, fmt.Errorf("restore: check target: %v", err)
	}
	if exists {
		counts, err := pgTableCounts(ctx, pgConnString(pg, dbname))
		if err != nil {
			// Unreadable target (not a Blueveil database at all).
			if !target.Force {
				return nil, fmt.Errorf("restore: target database %q exists and is not readable as a Blueveil database (refusing without force)", dbname)
			}
		} else if len(counts) > 0 && !target.Force {
			return nil, fmt.Errorf("restore: target database %q already holds %d tables (refusing to overwrite without force)", dbname, len(counts))
		}
		if target.Force {
			if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdentPG(dbname)+` WITH (FORCE)`); err != nil {
				return nil, fmt.Errorf("restore: drop conflicting target: %v", err)
			}
			exists = false
		}
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+quoteIdentPG(dbname)); err != nil {
			return nil, fmt.Errorf("restore: create target database: %v", err)
		}
	}
	psql, err := findPGTool("psql")
	if err != nil {
		return nil, err
	}
	// Native restore: psql stops at the first error (no partial success
	// masquerading as a restore).
	cmd := exec.CommandContext(ctx, psql,
		"-h", pg.Host, "-p", fmt.Sprintf("%d", pg.Port), "-U", pg.User,
		"-d", dbname,
		"-v", "ON_ERROR_STOP=1", "-q", "-f", dump)
	cmd.Env = append(pgEnv(pg), "PGOPTIONS=-c statement_timeout=60000")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("restore: psql (target left in place for investigation): %v: %s", err, firstLine(out))
	}
	// Open migrates older schemas forward and refuses future ones; then
	// counts must reproduce the manifest exactly.
	targetCS := pgConnString(pg, dbname)
	v, err := pgSchemaVersion(ctx, targetCS)
	if err != nil {
		return nil, fmt.Errorf("restore: version check (target left in place for investigation): %v", err)
	}
	if v > postgres.CurrentSchemaVersion {
		return nil, fmt.Errorf("restore: restored schema v%d is newer than this binary (v%d): refusing to serve (target left in place for investigation)", v, postgres.CurrentSchemaVersion)
	}
	counts, err := pgTableCounts(ctx, targetCS)
	if err != nil {
		return nil, fmt.Errorf("restore: count restored database (left in place for investigation): %v", err)
	}
	if err := verifyCounts(counts, m.Tables); err != nil {
		return nil, fmt.Errorf("%v (target left in place for investigation)", err)
	}
	return counts, nil
}
