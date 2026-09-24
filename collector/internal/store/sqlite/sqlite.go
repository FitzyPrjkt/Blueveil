// Package sqlite is the local/lab persistence backend: the nine store
// interfaces implemented over SQLite via database/sql and a pure-Go driver
// (modernc.org/sqlite: no cgo, no ORM, no migration framework).
//
// Boundary discipline: database representation (tables, SQL, placeholders)
// lives ONLY in this package. Domain code sees the store interfaces; rows
// map to canonical protobuf types and back, and every object is
// contract-validated before write and after read. Timestamps persist as
// RFC 3339 UTC text; enums as proto numbers; maps and id lists as JSON.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// CurrentSchemaVersion is the only schema this code speaks. Fresh databases
// initialize at it; older known versions migrate forward additively;
// anything else refuses to open. v2 adds asset inventory, v3 validation
// campaigns, v4 GRC governance, v5 supply chain.
const CurrentSchemaVersion = 5

// Config carries the backend settings. Path selects the database file;
// empty Path means process-local :memory: (never the working tree, never
// /tmp by default — callers pass explicit paths for files).
type Config struct {
	Path string
}

// dsn resolves the driver data source name. Pragmas ride in the DSN so
// EVERY pooled connection gets them (ExecContext pragmas would only touch
// whichever connection the pool hands out first).
func (c Config) dsn() string {
	if path := strings.TrimSpace(c.Path); path != "" {
		return "file:" + path +
			"?_pragma=foreign_keys(1)" +
			"&_pragma=busy_timeout(5000)" +
			"&_pragma=journal_mode(WAL)"
	}
	return ":memory:?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

// DB is an open SQLite backend. Close it when done; in-memory databases
// vanish on close by design (documented, tested restart uses files).
type DB struct {
	db     *sql.DB
	memory bool
}

// Open initializes (or verifies) the schema and returns the backend.
// Pragmas: foreign keys enforced, WAL for file databases (concurrent
// readers during writes), busy timeout instead of instant lock errors.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	memory := strings.TrimSpace(cfg.Path) == ""
	db, err := sql.Open("sqlite", cfg.dsn())
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if memory {
		// One connection: every :memory: connection is a separate database.
		db.SetMaxOpenConns(1)
	} else {
		// Verify WAL actually engaged (concurrent readers during writes);
		// fail fast instead of silently running a lesser journal mode.
		var mode string
		if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite: read journal_mode: %w", err)
		}
		if !strings.EqualFold(mode, "wal") {
			db.Close()
			return nil, fmt.Errorf("sqlite: journal_mode is %q, need WAL", mode)
		}
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db: db, memory: memory}, nil
}

// Close releases the backend. Pending operations fail explicitly; the
// handle must not be used afterwards (database/sql returns ErrDBClosed).
func (d *DB) Close() error {
	return d.db.Close()
}

// Ping verifies the handle is alive.
func (d *DB) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

// SchemaVersion reports the live schema version for readiness checks.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	return SchemaVersion(ctx, d.db)
}
