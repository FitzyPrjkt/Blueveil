// Live backup/restore engine: whole-database snapshots with manifests,
// secret scanning, and count-verified restores. Backups never mutate
// the source (schema must already be current — migrate by starting the
// server first); restores never touch the backup directory and refuse
// non-empty targets without explicit force.
package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"
	_ "modernc.org/sqlite"

	"blueveil/collector/internal/config"
	"blueveil/collector/internal/store/postgres"
	"blueveil/collector/internal/store/sqlite"
)

// findPGTool locates a PostgreSQL client binary via PATH, then the
// well-known Debian server bindir. Missing tooling is an explicit error,
// never a silent skip.
func findPGTool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/lib/postgresql/17/bin", "/usr/lib/postgresql/16/bin", "/usr/lib/postgresql/15/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("backup: %s not found (install PostgreSQL client tools)", name)
}

// pgEnv renders password/timeout environment for libpq children.
// Password travels by environment, never argv.
func pgEnv(cfg config.PostgresConfig) []string {
	env := os.Environ()
	if cfg.Password != "" {
		env = append(env, "PGPASSWORD="+cfg.Password)
	}
	env = append(env, "PGCONNECT_TIMEOUT=10", "PGSSLMODE="+orDefault(cfg.SSLMode, "require"))
	return env
}

// pgConnString renders a libpq string for drivers and CLIs.
func pgConnString(pg config.PostgresConfig, dbname string) string {
	parts := []string{"host=" + postgres.QuoteConnValue(pg.Host), fmt.Sprintf("port=%d", pg.Port),
		"user=" + postgres.QuoteConnValue(pg.User), "dbname=" + postgres.QuoteConnValue(dbname)}
	if pg.Password != "" {
		parts = append(parts, "password="+postgres.QuoteConnValue(pg.Password))
	}
	sslmode := pg.SSLMode
	if sslmode == "" {
		sslmode = "require"
	}
	return strings.Join(append(parts, "sslmode="+sslmode), " ")
}

// tableCounts reads user-table row counts without migrating anything.
func pgTableCounts(ctx context.Context, cs string) (map[string]int64, error) {
	c, err := pgx.Connect(ctx, cs)
	if err != nil {
		return nil, fmt.Errorf("backup: connect: %v", err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT LIKE 'pg_%'`)
	if err != nil {
		return nil, fmt.Errorf("backup: list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, fmt.Errorf("backup: scan tables: %v", err)
		}
		tables = append(tables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backup: tables: %v", err)
	}
	out := map[string]int64{}
	for _, t := range tables {
		var n int64
		if err := c.QueryRow(ctx, `SELECT count(*) FROM `+quoteIdentPG(t)).Scan(&n); err != nil {
			return nil, fmt.Errorf("backup: count %s: %v", t, err)
		}
		out[t] = n
	}
	return out, nil
}

func quoteIdentPG(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// pgSchemaVersion reads schema_version without migrating.
func pgSchemaVersion(ctx context.Context, cs string) (int, error) {
	c, err := pgx.Connect(ctx, cs)
	if err != nil {
		return -1, fmt.Errorf("backup: connect: %v", err)
	}
	defer c.Close(ctx)
	var v int
	if err := c.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&v); err != nil {
		return -1, fmt.Errorf("backup: schema version unreadable (not a Blueveil database?): %v", err)
	}
	return v, nil
}

// sqliteCounts reads user-table row counts over a plain handle (no
// migration, no mutation of the source).
func sqliteCounts(db *sql.DB) (map[string]int64, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, fmt.Errorf("backup: list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, fmt.Errorf("backup: scan tables: %v", err)
		}
		tables = append(tables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backup: tables: %v", err)
	}
	out := map[string]int64{}
	for _, t := range tables {
		var n int64
		if err := db.QueryRow(`SELECT count(*) FROM "` + strings.ReplaceAll(t, `"`, `""`) + `"`).Scan(&n); err != nil {
			return nil, fmt.Errorf("backup: count %s: %v", t, err)
		}
		out[t] = n
	}
	return out, nil
}

// sqliteVersion reads schema_version over a plain handle.
func sqliteVersion(db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil {
		return -1, fmt.Errorf("backup: schema version unreadable (not a Blueveil database?): %v", err)
	}
	return v, nil
}

func openSQLiteRO(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("backup: open sqlite: %v", err)
	}
	return db, nil
}

func openSQLiteRW(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("backup: open sqlite: %v", err)
	}
	return db, nil
}

// removePartial deletes a failed backup directory. Partial backups must
// never look valid: since backup.json is written last and verified on
// read, removal is belt-and-braces with an explicit error already
// returned to the operator.
func removePartial(dir string) {
	_ = os.RemoveAll(dir)
}

// Backup creates a timestamped backup directory under outParent for the
// database cfg points at. The source schema must already be current;
// anything else fails explicitly (start the server once to migrate,
// then back up). Returns the backup directory and manifest.
func Backup(ctx context.Context, cfg config.Config, outParent string) (string, Manifest, error) {
	var empty Manifest
	if err := cfg.Validate(); err != nil {
		return "", empty, fmt.Errorf("backup: invalid configuration: %v", err)
	}
	if err := os.MkdirAll(outParent, 0755); err != nil {
		return "", empty, fmt.Errorf("backup: create parent: %v", err)
	}
	// Mutual exclusion across processes: concurrent backups serialize
	// explicitly instead of interleaving payloads. O_EXCL creation is
	// the atomic check; stale locks from crashed runs are refused, not
	// stolen (operator removes the file after investigating).
	lockPath := filepath.Join(outParent, "backup.lock")
	lock, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if lockErr != nil {
		if os.IsExist(lockErr) {
			return "", empty, fmt.Errorf("backup: another backup holds %s (remove after investigating a crashed run)", lockPath)
		}
		return "", empty, fmt.Errorf("backup: lock %s: %v", lockPath, lockErr)
	}
	_ = lock.Close()
	defer os.Remove(lockPath)
	dir := filepath.Join(outParent, BackupDirName(string(cfg.Database.Backend)))
	// A second backup within the same second must never merge into (or
	// silently replace) the first: refuse non-empty directories so every
	// backup directory holds exactly one backup.
	if st, statErr := os.Stat(dir); statErr == nil && st.IsDir() {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			return "", empty, fmt.Errorf("backup: read dir: %v", readErr)
		}
		if len(entries) > 0 {
			return "", empty, fmt.Errorf("backup: %s exists and is not empty (concurrent backup?): refusing to merge", dir)
		}
	} else if err := os.MkdirAll(dir, 0755); err != nil {
		return "", empty, fmt.Errorf("backup: create dir: %v", err)
	}
	failed := true
	defer func() {
		if failed {
			removePartial(dir)
		}
	}()
	var m Manifest
	var err error
	switch cfg.Database.Backend {
	case config.BackendSQLite:
		m, err = backupSQLite(ctx, cfg, dir)
	case config.BackendPostgres:
		m, err = backupPostgres(ctx, cfg, dir)
	default:
		return "", empty, fmt.Errorf("backup: unknown backend %q", cfg.Database.Backend)
	}
	if err != nil {
		return "", empty, err
	}
	// Secret scan over every payload file before the backup is accepted.
	for _, f := range m.Files {
		raw, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			return "", empty, fmt.Errorf("backup: scan %s: %v", f.Name, err)
		}
		if err := ScanBackupBytes(raw); err != nil {
			return "", empty, err
		}
	}
	failed = false
	return dir, m, nil
}

func backupSQLite(ctx context.Context, cfg config.Config, dir string) (Manifest, error) {
	var empty Manifest
	src := cfg.Database.SQLitePath
	ro, err := openSQLiteRO(src)
	if err != nil {
		return empty, err
	}
	defer ro.Close()
	v, err := sqliteVersion(ro)
	if err != nil {
		return empty, err
	}
	if v != sqlite.CurrentSchemaVersion {
		return empty, fmt.Errorf("backup: sqlite schema v%d is not current (v%d): start the server once to migrate, then back up", v, sqlite.CurrentSchemaVersion)
	}
	counts, err := sqliteCounts(ro)
	if err != nil {
		return empty, err
	}
	// VACUUM INTO takes a consistent snapshot without stopping writers
	// and without copying WAL state by hand.
	dest := filepath.Join(dir, "blueveil.db")
	rw, err := openSQLiteRW(src)
	if err != nil {
		return empty, err
	}
	defer rw.Close()
	if _, err := rw.ExecContext(ctx, `VACUUM INTO '`+strings.ReplaceAll(dest, `'`, `''`)+`'`); err != nil {
		return empty, fmt.Errorf("backup: sqlite snapshot: %v", err)
	}
	return WriteManifest(dir, Manifest{
		Backend: "sqlite", Database: filepath.Base(src),
		SchemaVersion: v, Tables: counts,
	})
}

func backupPostgres(ctx context.Context, cfg config.Config, dir string) (Manifest, error) {
	var empty Manifest
	pg := cfg.Database.Postgres
	cs := pgConnString(pg, pg.DBName)
	v, err := pgSchemaVersion(ctx, cs)
	if err != nil {
		return empty, err
	}
	if v != postgres.CurrentSchemaVersion {
		return empty, fmt.Errorf("backup: postgres schema v%d is not current (v%d): start the server once to migrate, then back up", v, postgres.CurrentSchemaVersion)
	}
	counts, err := pgTableCounts(ctx, cs)
	if err != nil {
		return empty, err
	}
	dump, err := findPGTool("pg_dump")
	if err != nil {
		return empty, err
	}
	dest := filepath.Join(dir, "dump.sql")
	// One --dbname conninfo string (positional key=value words are not
	// accepted by pg_dump); password travels by environment only.
	conninfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s",
		pg.Host, pg.Port, pg.User, pg.DBName, orDefault(pg.SSLMode, "require"))
	cmd := exec.CommandContext(ctx, dump,
		"--no-owner", "--no-privileges", "--file="+dest, "--dbname="+conninfo)
	cmd.Env = pgEnv(pg)
	if out, err := cmd.CombinedOutput(); err != nil {
		return empty, fmt.Errorf("backup: pg_dump: %v: %s", err, firstLine(out))
	}
	return WriteManifest(dir, Manifest{
		Backend: "postgres", Database: pg.DBName,
		SchemaVersion: v, Tables: counts,
	})
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
