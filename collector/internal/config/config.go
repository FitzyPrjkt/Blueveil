// Package config is the single production configuration boundary for
// the Blueveil collector. All environment parsing, file loading,
// defaults, and validation live here — nowhere else in the codebase may
// read process environment for configuration.
//
// Environments: "lab" keeps the convenient historical defaults
// (loopback bind, SQLite, no auth/TLS); "production" fails closed on
// anything unsafe or missing. Secrets (passwords, key hashes) never
// appear in errors, logs, or the Redacted view.
package config

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"blueveil/collector/internal/auth"
)

// Environment selects lab convenience vs production fail-closed behavior.
type Environment string

const (
	EnvLab        Environment = "lab"
	EnvProduction Environment = "production"
)

// DatabaseBackend selects the repository implementation.
type DatabaseBackend string

const (
	BackendSQLite   DatabaseBackend = "sqlite"
	BackendPostgres DatabaseBackend = "postgres"
)

// Roles bound to API keys. The vocabulary is owned by the auth package
// (single source); config validation rejects unknown roles before
// startup through it.
const (
	RoleRead     = auth.RoleRead
	RoleRespond  = auth.RoleRespond
	RoleValidate = auth.RoleValidate
	RoleAdmin    = auth.RoleAdmin
)

// PostgresConfig carries PostgreSQL connection settings. Password comes
// from env (BLUEVEIL_PG_PASSWORD) or the config file — never a flag.
type PostgresConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Password       string `json:"password"`
	DBName         string `json:"dbname"`
	SSLMode        string `json:"sslmode"`
	MaxConns       int    `json:"max_conns"`
	ConnectTimeout string `json:"connect_timeout"`
	// QueryTimeout bounds every query (statement_timeout per
	// connection); empty means no timeout. Purpose/default/failure
	// documented in the operator runbook.
	QueryTimeout string `json:"query_timeout"`
}

// DatabaseConfig selects and configures the backend.
type DatabaseConfig struct {
	Backend    DatabaseBackend `json:"backend"`
	SQLitePath string          `json:"sqlite_path"`
	Postgres   PostgresConfig  `json:"postgres"`
}

// TLSConfig configures transport security. Certificates are loaded from
// files at startup and validated before serving; nothing is generated.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	MinVersion string `json:"min_version"`
	// ExplicitInsecureHTTP permits plaintext HTTP in production. It must
	// be set deliberately (e.g. TLS terminated upstream) and is logged.
	ExplicitInsecureHTTP bool `json:"explicit_insecure_http"`
}

// APIKey binds one credential id to a role. Hash is a password-hash of
// the secret (bcrypt); the secret itself is never stored.
type APIKey struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Hash      string `json:"hash"`
	ExpiresAt string `json:"expires_at"`
}

// AuthConfig configures API authentication.
type AuthConfig struct {
	Enabled     bool     `json:"enabled"`
	Keys        []APIKey `json:"keys"`
	PublicPaths []string `json:"public_paths"`
}

// LoggingConfig configures structured operational logging.
type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// LimitsConfig bounds operational resource use. Every limit documents
// its purpose in the operator runbook: body bytes cap request payloads
// (413/close on excess), header timeout bounds slowloris-style reads,
// shutdown timeout bounds drain on SIGINT/SIGTERM.
type LimitsConfig struct {
	RequestBodyBytes  int64  `json:"request_body_bytes"`
	ReadHeaderTimeout string `json:"read_header_timeout"`
	ShutdownTimeout   string `json:"shutdown_timeout"`
}

// IOCSetConfig points at the offline threat-intel set.
type IOCSetConfig struct {
	Path    string `json:"path"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Config is the whole typed server configuration.
type Config struct {
	Env        Environment    `json:"env"`
	ListenAddr string         `json:"listen_addr"`
	Database   DatabaseConfig `json:"database"`
	TLS        TLSConfig      `json:"tls"`
	Auth       AuthConfig     `json:"auth"`
	Logging    LoggingConfig  `json:"logging"`
	Limits     LimitsConfig   `json:"limits"`
	UIDir      string         `json:"ui_dir"`
	IOCSet     IOCSetConfig   `json:"ioc_set"`
}

// LabDefaults returns the historical convenient behavior: loopback bind,
// SQLite, no auth, no TLS, text logs.
func LabDefaults() Config {
	return Config{
		Env:        EnvLab,
		ListenAddr: "127.0.0.1:8008",
		Database:   DatabaseConfig{Backend: BackendSQLite},
		TLS:        TLSConfig{MinVersion: "1.3"},
		Auth:       AuthConfig{PublicPaths: []string{"/api/v1/healthz"}},
		Logging:    LoggingConfig{Level: "info", Format: "text"},
		Limits: LimitsConfig{
			RequestBodyBytes:  1 << 20,
			ReadHeaderTimeout: "5s",
			ShutdownTimeout:   "10s",
		},
		UIDir: "collector/ui/dist",
	}
}

// applyDefaults fills fields introduced after a config file was written
// so upgrades never break on missing keys: an older valid file stays
// valid with safe defaults. New REQUIRED settings must never be
// defaulted here (fail closed instead).
func (c *Config) applyDefaults() {
	d := LabDefaults()
	if c.Env == "" {
		c.Env = d.Env
	}
	if c.ListenAddr == "" {
		c.ListenAddr = d.ListenAddr
	}
	if c.Logging.Level == "" {
		c.Logging.Level = d.Logging.Level
	}
	if c.Logging.Format == "" {
		c.Logging.Format = d.Logging.Format
	}
	if c.Limits.RequestBodyBytes == 0 {
		c.Limits.RequestBodyBytes = d.Limits.RequestBodyBytes
	}
	if c.Limits.ReadHeaderTimeout == "" {
		c.Limits.ReadHeaderTimeout = d.Limits.ReadHeaderTimeout
	}
	if c.Limits.ShutdownTimeout == "" {
		c.Limits.ShutdownTimeout = d.Limits.ShutdownTimeout
	}
	if c.TLS.MinVersion == "" {
		c.TLS.MinVersion = d.TLS.MinVersion
	}
	if c.UIDir == "" {
		c.UIDir = d.UIDir
	}
}

// Redacted returns a copy safe to log: secrets cleared, structure kept.
func (c Config) Redacted() Config {
	out := c
	out.Database.Postgres.Password = ""
	for i := range out.Auth.Keys {
		out.Auth.Keys[i].Hash = ""
	}
	return out
}

func validRole(r string) bool { return auth.ValidRole(r) }

// Validate enforces the whole model. Errors name fields and rules only —
// never secret values.
func (c *Config) Validate() error {
	switch c.Env {
	case EnvLab, EnvProduction:
	default:
		return fmt.Errorf("config: env must be %q or %q", EnvLab, EnvProduction)
	}
	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("config: listen_addr is empty")
	}
	host, _, err := splitHostPort(c.ListenAddr)
	if err != nil {
		return fmt.Errorf("config: listen_addr invalid: %v", err)
	}
	// Lab mode must never silently become internet-exposed through a
	// convenient default: only loopback binds validate. Production binds
	// are the operator's explicit choice (still gated by required auth
	// and TLS-or-opt-out below).
	if c.Env == EnvLab && !isLoopback(host) {
		return fmt.Errorf("config: lab listen_addr must be loopback (127.0.0.1, localhost, ::1)")
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: logging.level must be debug|info|warn|error")
	}
	switch c.Logging.Format {
	case "text", "json":
	default:
		return fmt.Errorf("config: logging.format must be text|json")
	}
	if c.Limits.RequestBodyBytes <= 0 {
		return fmt.Errorf("config: limits.request_body_bytes must be positive")
	}
	if _, err := parseDur(c.Limits.ReadHeaderTimeout); err != nil {
		return fmt.Errorf("config: limits.read_header_timeout invalid: %v", err)
	}
	if d, err := parseDur(c.Limits.ShutdownTimeout); err != nil || d <= 0 {
		return fmt.Errorf("config: limits.shutdown_timeout must be a positive duration")
	}
	if err := c.validateDatabase(); err != nil {
		return err
	}
	if err := c.validateTLS(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if c.IOCSet.Path == "" && (c.IOCSet.ID != "" || c.IOCSet.Version != "") {
		return fmt.Errorf("config: ioc_set id/version require ioc_set path")
	}
	if c.IOCSet.Path != "" && (c.IOCSet.ID == "" || c.IOCSet.Version == "") {
		return fmt.Errorf("config: ioc_set path requires ioc_set id and version")
	}
	return nil
}

func (c *Config) validateDatabase() error {
	switch c.Database.Backend {
	case BackendSQLite:
		if strings.TrimSpace(c.Database.SQLitePath) == "" {
			return fmt.Errorf("config: database.sqlite_path is required")
		}
		if c.Env == EnvProduction && c.Database.SQLitePath == ":memory:" {
			return fmt.Errorf("config: sqlite :memory: is not a production database")
		}
	case BackendPostgres:
		pg := c.Database.Postgres
		if strings.TrimSpace(pg.Host) == "" {
			return fmt.Errorf("config: database.postgres.host is required")
		}
		if pg.Port <= 0 || pg.Port > 65535 {
			return fmt.Errorf("config: database.postgres.port out of range")
		}
		if strings.TrimSpace(pg.User) == "" {
			return fmt.Errorf("config: database.postgres.user is required")
		}
		if strings.TrimSpace(pg.DBName) == "" {
			return fmt.Errorf("config: database.postgres.dbname is required")
		}
		// TCP without a password is fail-closed; unix-socket peer auth
		// (host starting with "/") legitimately carries none.
		if pg.Password == "" && !strings.HasPrefix(pg.Host, "/") && pg.Host != "localhost" {
			return fmt.Errorf("config: database.postgres.password is required for TCP connections")
		}
		switch pg.SSLMode {
		case "", "disable", "require", "verify-ca", "verify-full":
		default:
			return fmt.Errorf("config: database.postgres.sslmode unknown")
		}
		if c.Env == EnvProduction && (pg.SSLMode == "" || pg.SSLMode == "disable") && !strings.HasPrefix(pg.Host, "/") {
			return fmt.Errorf("config: production postgres over TCP requires sslmode require or stronger")
		}
		if pg.MaxConns < 0 {
			return fmt.Errorf("config: database.postgres.max_conns must not be negative")
		}
		if pg.ConnectTimeout != "" {
			if _, err := parseDur(pg.ConnectTimeout); err != nil {
				return fmt.Errorf("config: database.postgres.connect_timeout invalid: %v", err)
			}
		}
	default:
		return fmt.Errorf("config: database.backend must be %q or %q", BackendSQLite, BackendPostgres)
	}
	// Duration formats validate regardless of backend: a typo'd timeout
	// must fail loudly, never be silently ignored on the other backend.
	if pg := c.Database.Postgres; pg.QueryTimeout != "" {
		if d, err := parseDur(pg.QueryTimeout); err != nil || d <= 0 {
			return fmt.Errorf("config: database.postgres.query_timeout must be a positive duration")
		}
	}
	return nil
}

func (c *Config) validateTLS() error {
	switch c.TLS.MinVersion {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("config: tls.min_version must be 1.2 or 1.3")
	}
	if !c.TLS.Enabled {
		if c.Env == EnvProduction && !c.TLS.ExplicitInsecureHTTP {
			return fmt.Errorf("config: production requires tls.enabled or explicit tls.explicit_insecure_http")
		}
		if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
			return fmt.Errorf("config: tls cert/key files require tls.enabled")
		}
		return nil
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return fmt.Errorf("config: tls.enabled requires tls.cert_file and tls.key_file")
	}
	// Load now: missing/unparseable/mismatched material fails startup,
	// not the first handshake.
	if _, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile); err != nil {
		return fmt.Errorf("config: tls cert/key failed to load: %v", err)
	}
	return nil
}

func (c *Config) validateAuth() error {
	if !c.Auth.Enabled {
		if c.Env == EnvProduction {
			return fmt.Errorf("config: production requires auth.enabled")
		}
		return nil
	}
	if len(c.Auth.Keys) == 0 {
		return fmt.Errorf("config: auth.enabled requires at least one auth key (no default production credential)")
	}
	seen := map[string]bool{}
	now := time.Now()
	for i, k := range c.Auth.Keys {
		if strings.TrimSpace(k.ID) == "" {
			return fmt.Errorf("config: auth.keys[%d].id is empty", i)
		}
		if seen[k.ID] {
			return fmt.Errorf("config: auth.keys id %q is duplicated", k.ID)
		}
		seen[k.ID] = true
		if !validRole(k.Role) {
			return fmt.Errorf("config: auth.keys id %q has unknown role", k.ID)
		}
		if !looksLikeHash(k.Hash) {
			return fmt.Errorf("config: auth.keys id %q hash is malformed (want a password hash)", k.ID)
		}
		if k.ExpiresAt != "" {
			exp, err := time.Parse(time.RFC3339, k.ExpiresAt)
			if err != nil {
				return fmt.Errorf("config: auth.keys id %q expires_at invalid (RFC3339 required)", k.ID)
			}
			if !exp.After(now) {
				return fmt.Errorf("config: auth.keys id %q is already expired", k.ID)
			}
		}
	}
	return nil
}

// looksLikeHash accepts common password-hash encodings without importing
// a hashing library into the config boundary (verification lives in the
// auth package). It only gates shape, never value.
func looksLikeHash(h string) bool {
	return strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") ||
		strings.HasPrefix(h, "$2y$") || strings.HasPrefix(h, "$argon2")
}

func splitHostPort(addr string) (string, string, error) {
	host, port, err := splitHostPortStd(addr)
	if err != nil {
		return "", "", err
	}
	if port == "" {
		return "", "", fmt.Errorf("missing port")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", fmt.Errorf("bad port: %v", err)
	}
	return host, port, nil
}
