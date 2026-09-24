// Package postgres is the production PostgreSQL backend implementing the
// same store.Backend abstraction as SQLite and memory. No ORM, no
// migration framework, no PostgreSQL types in domain models: repositories
// speak protobuf/domain types only, placeholders are $n, and every read
// re-validates (corruption surfaces as store.ErrCorrupted, never as
// empty/default objects).
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"blueveil/collector/internal/store"
)

// CurrentSchemaVersion mirrors the SQLite lineage: v1 initial, v2 assets,
// v3 validation campaigns, v4 GRC governance, v5 supply chain.
const CurrentSchemaVersion = 5

// Config carries connection settings. Password travels from env or the
// config file only — never a flag, never a log line. QueryTimeout bounds
// every query (statement_timeout per connection); zero means no timeout.
type Config struct {
	Host           string
	Port           int
	User           string
	Password       string
	DBName         string
	SSLMode        string
	MaxConns       int
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// DefaultConfig returns explicit local defaults (no credentials).
func DefaultConfig() Config {
	return Config{Host: "127.0.0.1", Port: 5432, SSLMode: "require"}
}

// Validate rejects incomplete configurations explicitly, without echoing
// secret values.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("postgres: host is empty")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("postgres: port out of range")
	}
	if strings.TrimSpace(c.User) == "" {
		return fmt.Errorf("postgres: user is empty")
	}
	if strings.TrimSpace(c.DBName) == "" {
		return fmt.Errorf("postgres: dbname is empty")
	}
	switch c.SSLMode {
	case "", "disable", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("postgres: sslmode unknown")
	}
	if c.MaxConns < 0 {
		return fmt.Errorf("postgres: max_conns must not be negative")
	}
	return nil
}

// pgconn is the query surface repositories need. *pgxpool.Pool and
// pgx.Tx both satisfy it, so a transaction can back a whole Backend for
// atomic multi-entity writes.
type dbconn interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

// DB is a versioned PostgreSQL backend over a connection pool.
type DB struct {
	pool *pgxpool.Pool
}

// QuoteConnValue renders one libpq keyword value: bare when it needs
// no quoting, single-quoted with backslash escapes otherwise. Without
// this, a password containing spaces, quotes, or backslashes silently
// re-parses into different keywords (wrong database, wrong user — or a
// connection failure far from the real cause).
func QuoteConnValue(v string) string {
	safe := len(v) > 0
	for i := 0; i < len(v) && safe; i++ {
		c := v[i]
		safe = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '-' || c == '/' || c == '@' || c == ':'
	}
	if safe {
		return v
	}
	var b strings.Builder
	b.WriteByte('\'')
	for i := 0; i < len(v); i++ {
		if v[i] == '\'' || v[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	b.WriteByte('\'')
	return b.String()
}

// connString renders the libpq-style connection string. The password is
// embedded for the driver only; callers must never log it.
func (c Config) connString() string {
	parts := []string{
		"host=" + QuoteConnValue(c.Host),
		fmt.Sprintf("port=%d", c.Port),
		"user=" + QuoteConnValue(c.User),
		"dbname=" + QuoteConnValue(c.DBName),
	}
	if c.Password != "" {
		parts = append(parts, "password="+QuoteConnValue(c.Password))
	}
	if c.SSLMode != "" {
		parts = append(parts, "sslmode="+c.SSLMode)
	}
	return strings.Join(parts, " ")
}

// OpenConnString connects from a libpq-style connection string (tests,
// operators). The string carries credentials: callers must never log it.
func OpenConnString(ctx context.Context, connStr string, maxConns int, connectTimeout time.Duration) (*DB, error) {
	pcfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}
	if maxConns > 0 {
		pcfg.MaxConns = int32(maxConns)
	}
	if connectTimeout > 0 {
		pcfg.ConnConfig.ConnectTimeout = connectTimeout
	}
	return openPool(ctx, pcfg, 0)
}

// Open connects, verifies health, and migrates the schema to current.
// Anything unsupported fails before the backend is returned.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	pcfg, err := pgxpool.ParseConfig(cfg.connString())
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}
	if cfg.MaxConns > 0 {
		pcfg.MaxConns = int32(cfg.MaxConns)
	}
	if cfg.ConnectTimeout > 0 {
		pcfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}
	return openPool(ctx, pcfg, cfg.QueryTimeout)
}

// openPool builds the pool, enforces the per-connection statement
// timeout, pings, and migrates. One path for every opener so timeout
// and migration behavior cannot diverge.
func openPool(ctx context.Context, pcfg *pgxpool.Config, queryTimeout time.Duration) (*DB, error) {
	if queryTimeout > 0 {
		qt := queryTimeout
		pcfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, fmt.Sprintf("SET statement_timeout = '%dms'", qt.Milliseconds()))
			return err
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	db := &DB{pool: pool}
	if err := db.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

// Close drains the pool.
func (d *DB) Close() {
	d.pool.Close()
}

// Ping verifies the server is reachable.
func (d *DB) Ping(ctx context.Context) error {
	if err := d.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: health ping: %w", err)
	}
	return nil
}

// Health verifies reachability and that the live schema is exactly the
// supported version: connection loss, pending migrations, and future
// schemas all fail explicitly.
func (d *DB) Health(ctx context.Context) error {
	if err := d.Ping(ctx); err != nil {
		return err
	}
	v, err := SchemaVersion(ctx, d.pool)
	if err != nil {
		return err
	}
	if v != CurrentSchemaVersion {
		return fmt.Errorf("postgres: schema version %d unsupported (code speaks %d)", v, CurrentSchemaVersion)
	}
	return nil
}

func isDuplicate(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func mapWriteError(err error, kind, id string) error {
	if err == nil {
		return nil
	}
	if isDuplicate(err) {
		return fmt.Errorf("%w: %s %q", store.ErrDuplicate, kind, id)
	}
	return fmt.Errorf("postgres: write %s %q: %w", kind, id, err)
}

func mapReadError(err error, kind, id string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s %q", store.ErrNotFound, kind, id)
	}
	if err != nil {
		return fmt.Errorf("postgres: read %s %q: %w", kind, id, err)
	}
	return nil
}

func mapWriteErrorTx(err error, kind, id string) error {
	if isDuplicate(err) {
		return fmt.Errorf("%w: %s %q", store.ErrDuplicate, kind, id)
	}
	return fmt.Errorf("postgres: tx write %s %q: %w", kind, id, err)
}
