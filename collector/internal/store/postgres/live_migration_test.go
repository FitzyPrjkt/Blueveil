// Step 15C: PostgreSQL migration hardening. Fresh, v1→current,
// future/unknown rejection, and rollback: a deliberately failing
// migration step must leave no partially migrated schema behind.
package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func adminConn(t *testing.T, ctx context.Context) (*pgx.Conn, string) {
	t.Helper()
	cs := strings.TrimSpace(envMust(t, "BLUEVEIL_TEST_POSTGRES"))
	c, err := pgx.Connect(ctx, cs)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { c.Close(ctx) })
	return c, cs
}

func envMust(t *testing.T, key string) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	t.Skipf("%s unset: live PostgreSQL tests skipped (nothing faked)", key)
	return ""
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// withDBName swaps the dbname in a libpq conn string.
func withDBName(cs, name string) string {
	parts := strings.Fields(cs)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if !strings.HasPrefix(p, "dbname=") {
			out = append(out, p)
		}
	}
	return strings.Join(append(out, "dbname="+name), " ")
}

// openTestDB creates an isolated database and returns an Opened handle
// plus the conn string reaching it (for alternate pool settings).
func openTestDB(t *testing.T, ctx context.Context) (*DB, string) {
	t.Helper()
	c, cs := adminConn(t, ctx)
	name := fmt.Sprintf("blueveil_t_%d", time.Now().UnixNano())
	if _, err := c.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		d, err := pgx.Connect(ctx, cs)
		if err != nil {
			return
		}
		defer d.Close(ctx)
		_, _ = d.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	})
	db, err := OpenConnString(ctx, withDBName(cs, name), 4, 5*time.Second)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, withDBName(cs, name)
}

func freshDB(t *testing.T, ctx context.Context, c *pgx.Conn, cs string) *DB {
	t.Helper()
	name := fmt.Sprintf("blueveil_m_%d", time.Now().UnixNano())
	if _, err := c.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		d, err := pgx.Connect(ctx, cs)
		if err != nil {
			return
		}
		defer d.Close(ctx)
		_, _ = d.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	})
	db, err := OpenConnString(ctx, withDBName(cs, name), 2, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLiveMigrationFresh(t *testing.T) {
	ctx := context.Background()
	c, cs := adminConn(t, ctx)
	db := freshDB(t, ctx, c, cs)
	v, err := SchemaVersion(ctx, db.pool)
	if err != nil || v != CurrentSchemaVersion {
		t.Fatalf("fresh version: %d %v", v, err)
	}
	// Indexes exist explicitly.
	var n int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_indexes WHERE tablename IN ('telemetry_events','assets','supply_dependencies','evidence')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatalf("expected explicit indexes, found none")
	}
	// Foreign keys enforced.
	if _, err := db.pool.Exec(ctx,
		`INSERT INTO evidence (id, incident_id, type, collected_at, source, media_type, content)
		 VALUES ('ev-x','no-such-incident',1,'2026-09-12T10:00:00Z','s','text/plain','c')`); err == nil {
		t.Fatalf("evidence FK must reject unknown incident")
	}
}

func TestLiveMigrationV1ToCurrent(t *testing.T) {
	ctx := context.Background()
	c, cs := adminConn(t, ctx)
	name := fmt.Sprintf("blueveil_m1_%d", time.Now().UnixNano())
	if _, err := c.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		d, err := pgx.Connect(ctx, cs)
		if err != nil {
			return
		}
		defer d.Close(ctx)
		_, _ = d.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	})
	v1, err := pgx.Connect(ctx, withDBName(cs, name))
	if err != nil {
		t.Fatal(err)
	}
	defer v1.Close(ctx)
	// Apply only the v1 DDL + version stamp + one legacy row: a genuine
	// v1-layout database.
	for _, stmt := range migrations[0].ddl {
		if _, err := v1.Exec(ctx, stmt); err != nil {
			t.Fatalf("v1 ddl: %v", err)
		}
	}
	if _, err := v1.Exec(ctx, `INSERT INTO schema_version (version) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := v1.Exec(ctx,
		`INSERT INTO telemetry_events (id, occurred_at, source, asset_id, event_type, severity, attributes, raw)
		 VALUES ('evt-legacy','2026-09-12T10:00:00Z','lab','ast-1','net.connection',1,'{}','')`); err != nil {
		t.Fatal(err)
	}
	v1.Close(ctx)
	db, err := OpenConnString(ctx, withDBName(cs, name), 2, 5*time.Second)
	if err != nil {
		t.Fatalf("v1→current must succeed: %v", err)
	}
	defer db.Close()
	var src string
	if err := db.pool.QueryRow(ctx, `SELECT source FROM telemetry_events WHERE id='evt-legacy'`).Scan(&src); err != nil || src != "lab" {
		t.Fatalf("legacy row must survive: %q %v", src, err)
	}
	var cnt int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM assets`).Scan(&cnt); err != nil || cnt != 0 {
		t.Fatalf("v2 tables must exist and read empty: %v", err)
	}
}

func TestLiveQueryTimeoutEnforced(t *testing.T) {
	ctx := context.Background()
	c, cs := adminConn(t, ctx)
	name := fmt.Sprintf("blueveil_qto_%d", time.Now().UnixNano())
	if _, err := c.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		d, err := pgx.Connect(ctx, cs)
		if err != nil {
			return
		}
		defer d.Close(ctx)
		_, _ = d.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	})
	db, err := Open(ctx, Config{
		Host: "/tmp/pgtest", Port: 55433, User: "blueveil_test",
		DBName: name, SSLMode: "disable", QueryTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open with query timeout: %v", err)
	}
	defer db.Close()
	// Slow query must die at the timeout, never hang the caller.
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := db.pool.Exec(ctx2, `SELECT pg_sleep(5)`); err == nil {
		t.Fatalf("pg_sleep(5) must fail under a 50ms statement timeout")
	}
	// Pool stays usable afterwards.
	if err := db.Health(ctx); err != nil {
		t.Fatalf("pool must stay usable after timeout: %v", err)
	}
}

func TestLivePoolSerializesAtMaxConns1(t *testing.T) {
	ctx := context.Background()
	_, cs := openTestDB(t, ctx)
	one, err := OpenConnString(ctx, cs, 1, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	// One connection serving 8 concurrent queries: all succeed, none
	// fails, the pool serializes instead of erroring.
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			var n int
			done <- one.pool.QueryRow(ctx, `SELECT 1`).Scan(&n)
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatalf("pooled query at max_conns=1: %v", err)
		}
	}
}

func TestLiveHealthAfterCloseFails(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t, ctx)
	db.Close()
	if err := db.Health(ctx); err == nil {
		t.Fatalf("health on a closed pool must fail (reconnect means reopening, never silent)")
	}
}

func TestLiveMigrationRejectsFutureAndUnknown(t *testing.T) {
	ctx := context.Background()
	c, cs := adminConn(t, ctx)
	mk := func(t *testing.T, version int) string {
		t.Helper()
		name := fmt.Sprintf("blueveil_mr_%d", time.Now().UnixNano())
		if _, err := c.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
			t.Fatalf("create db: %v", err)
		}
		t.Cleanup(func() {
			d, err := pgx.Connect(ctx, cs)
			if err != nil {
				return
			}
			defer d.Close(ctx)
			_, _ = d.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
		})
		d, err := pgx.Connect(ctx, withDBName(cs, name))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close(ctx)
		if _, err := d.Exec(ctx, `CREATE TABLE schema_version (version INTEGER PRIMARY KEY)`); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(ctx, `INSERT INTO schema_version (version) VALUES ($1)`, version); err != nil {
			t.Fatal(err)
		}
		return name
	}
	if _, err := OpenConnString(ctx, withDBName(cs, mk(t, CurrentSchemaVersion+1)), 2, 5*time.Second); err == nil {
		t.Fatalf("future schema version must be refused")
	}
	if _, err := OpenConnString(ctx, withDBName(cs, mk(t, 42)), 2, 5*time.Second); err == nil {
		t.Fatalf("unknown schema version must be refused")
	}
}

func TestLiveMigrationRollbackLeavesNothing(t *testing.T) {
	ctx := context.Background()
	c, cs := adminConn(t, ctx)
	name := fmt.Sprintf("blueveil_rb_%d", time.Now().UnixNano())
	if _, err := c.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		d, err := pgx.Connect(ctx, cs)
		if err != nil {
			return
		}
		defer d.Close(ctx)
		_, _ = d.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	})
	d, err := pgx.Connect(ctx, withDBName(cs, name))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(ctx)
	// v1 layout + version stamp.
	for _, stmt := range migrations[0].ddl {
		if _, err := d.Exec(ctx, stmt); err != nil {
			t.Fatalf("v1 ddl: %v", err)
		}
	}
	if _, err := d.Exec(ctx, `INSERT INTO schema_version (version) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	// Simulate a mid-migration failure: begin, apply one v2 statement,
	// then fail and roll back — the schema must be byte-identical after.
	tx, err := d.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, migrations[1].ddl[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE assets (id TEXT PRIMARY KEY)`); err == nil {
		t.Fatalf("expected the duplicate-table statement to fail")
	}
	tx.Rollback(ctx)
	var assets int
	if err := d.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_name='assets'`).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != 0 {
		t.Fatalf("rolled-back migration must leave no assets table")
	}
	var v int
	if err := d.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("version row must still read v1: %d %v", v, err)
	}
	// And the real migrate() still upgrades this database cleanly after.
	d.Close(ctx)
	db, err := OpenConnString(ctx, withDBName(cs, name), 2, 5*time.Second)
	if err != nil {
		t.Fatalf("post-rollback upgrade must succeed: %v", err)
	}
	defer db.Close()
}

func TestLiveDoubleCloseSafe(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t, ctx)
	db.Close()
	// Second close must not panic.
	db.Close()
}
