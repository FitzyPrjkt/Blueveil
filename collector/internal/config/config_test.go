// Step 15A RED: production configuration model. Explicit lab vs
// production behavior; production fails closed on unsafe/missing config;
// secrets never appear in errors or logs.
package config

import (
	"os"
	"strings"
	"testing"
)

func TestLabDefaultsValidate(t *testing.T) {
	c := LabDefaults()
	c.Database.SQLitePath = t.TempDir() + "/lab.db"
	if err := c.Validate(); err != nil {
		t.Fatalf("lab defaults must validate: %v", err)
	}
	if c.Env != EnvLab {
		t.Fatalf("default env must be lab, got %q", c.Env)
	}
}

func TestLabRefusesNonLoopbackBind(t *testing.T) {
	c := LabDefaults()
	c.Database.SQLitePath = t.TempDir() + "/lab.db"
	for _, addr := range []string{"0.0.0.0:8008", ":8008", "192.168.1.10:8008"} {
		c.ListenAddr = addr
		if err := c.Validate(); err == nil {
			t.Errorf("lab bind %q must fail (never silently internet-exposed)", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8008", "localhost:8008", "[::1]:8008"} {
		c.ListenAddr = addr
		if err := c.Validate(); err != nil {
			t.Errorf("lab loopback bind %q must validate: %v", addr, err)
		}
	}
	// Production may bind wider (operator's explicit choice, still gated
	// by required auth + TLS-or-opt-out).
	c.Env = EnvProduction
	c.ListenAddr = "0.0.0.0:9000"
	c.Auth.Enabled = true
	c.Auth.Keys = []APIKey{{ID: "k1", Role: RoleAdmin, Hash: testHash(t, "s")}}
	c.TLS.Enabled = true
	c.TLS.CertFile = "testdata/cert.pem"
	c.TLS.KeyFile = "testdata/key.pem"
	if err := c.Validate(); err != nil {
		t.Errorf("production wide bind with auth+TLS must validate: %v", err)
	}
}

func TestProductionRequiresDatabase(t *testing.T) {
	c := LabDefaults()
	c.Env = EnvProduction
	c.Database.SQLitePath = t.TempDir() + "/prod.db"
	c.Auth.Enabled = true
	c.Auth.Keys = []APIKey{{ID: "k1", Role: RoleAdmin, Hash: testHash(t, "secret-1")}}
	if err := c.Validate(); err == nil {
		t.Fatalf("production without TLS or explicit insecure opt-out must fail")
	}
	c.TLS.Enabled = true
	c.TLS.CertFile = "testdata/cert.pem"
	c.TLS.KeyFile = "testdata/key.pem"
	if err := c.Validate(); err != nil {
		t.Fatalf("complete production config must validate: %v", err)
	}
}

func TestProductionRequiresAuth(t *testing.T) {
	c := LabDefaults()
	c.Env = EnvProduction
	c.Database.SQLitePath = t.TempDir() + "/prod.db"
	c.TLS.Enabled = true
	c.TLS.CertFile = "testdata/cert.pem"
	c.TLS.KeyFile = "testdata/key.pem"
	if err := c.Validate(); err == nil {
		t.Fatalf("production without auth must fail")
	}
	c.Auth.Enabled = true
	if err := c.Validate(); err == nil {
		t.Fatalf("production auth without keys must fail")
	}
}

func TestProductionRejectsBadKeys(t *testing.T) {
	mk := func() Config {
		c := LabDefaults()
		c.Env = EnvProduction
		c.Database.SQLitePath = t.TempDir() + "/prod.db"
		c.TLS.Enabled = true
		c.TLS.CertFile = "testdata/cert.pem"
		c.TLS.KeyFile = "testdata/key.pem"
		c.Auth.Enabled = true
		return c
	}
	c := mk()
	c.Auth.Keys = []APIKey{{ID: "", Role: RoleRead, Hash: testHash(t, "s")}}
	if err := c.Validate(); err == nil {
		t.Fatalf("empty key id must fail")
	}
	c = mk()
	c.Auth.Keys = []APIKey{{ID: "k1", Role: "SUPERUSER", Hash: testHash(t, "s")}}
	if err := c.Validate(); err == nil {
		t.Fatalf("unknown role must fail")
	}
	c = mk()
	c.Auth.Keys = []APIKey{{ID: "k1", Role: RoleRead, Hash: "not-a-hash"}}
	if err := c.Validate(); err == nil {
		t.Fatalf("malformed hash must fail")
	}
	c = mk()
	c.Auth.Keys = []APIKey{
		{ID: "k1", Role: RoleRead, Hash: testHash(t, "s")},
		{ID: "k1", Role: RoleAdmin, Hash: testHash(t, "s2")},
	}
	if err := c.Validate(); err == nil {
		t.Fatalf("duplicate key ids must fail")
	}
}

func TestValidationErrorsNeverCarrySecrets(t *testing.T) {
	c := LabDefaults()
	c.Env = EnvProduction
	c.Database.Backend = BackendPostgres
	c.Database.Postgres.Password = "super-secret-pg-password"
	c.Auth.Enabled = true
	c.Auth.Keys = []APIKey{{ID: "k1", Role: RoleRead, Hash: testHash(t, "api-secret-value")}}
	err := c.Validate()
	if err == nil {
		t.Fatalf("expected validation errors for incomplete prod config")
	}
	for _, secret := range []string{"super-secret-pg-password", "api-secret-value"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error leaks secret: %v", err)
		}
	}
	s := c.Redacted().Database.Postgres.Password
	if s != "" {
		t.Fatalf("redacted config must not carry password, got %q", s)
	}
}

func TestPostgresRequiresFields(t *testing.T) {
	c := LabDefaults()
	c.Env = EnvProduction
	c.Database.Backend = BackendPostgres
	c.Auth.Enabled = true
	c.Auth.Keys = []APIKey{{ID: "k1", Role: RoleAdmin, Hash: testHash(t, "s")}}
	c.TLS.Enabled = true
	c.TLS.CertFile = "testdata/cert.pem"
	c.TLS.KeyFile = "testdata/key.pem"
	if err := c.Validate(); err == nil {
		t.Fatalf("postgres without host/db/user must fail")
	}
	c.Database.Postgres = PostgresConfig{Host: "db.internal", Port: 5432, User: "blueveil", DBName: "blueveil", SSLMode: "require"}
	if err := c.Validate(); err == nil {
		t.Fatalf("postgres without password over TCP must fail in production")
	}
	c.Database.Postgres.Password = "pw"
	if err := c.Validate(); err != nil {
		t.Fatalf("complete postgres config must validate: %v", err)
	}
}

func TestOldConfigFileUpgradesCleanly(t *testing.T) {
	// A v15-era file (no shutdown_timeout, query_timeout, min_version)
	// must load with safe defaults and validate: upgrades never break
	// on missing keys.
	dir := t.TempDir()
	path := dir + "/old.json"
	old := `{"env":"lab","listen_addr":"127.0.0.1:8008",
		"database":{"backend":"sqlite","sqlite_path":"` + dir + `/old.db"},
		"tls":{"enabled":false},"auth":{"enabled":false},
		"logging":{"level":"info","format":"text"},
		"limits":{"request_body_bytes":1048576,"read_header_timeout":"5s"},
		"ui_dir":"x"}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("old file must load: %v", err)
	}
	if c.Limits.ShutdownTimeout != "10s" || c.TLS.MinVersion != "1.3" {
		t.Fatalf("new fields must default safely: %+v", c.Limits)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("old file must validate after defaults: %v", err)
	}
}

func TestSafeDriftAccepted(t *testing.T) {
	base := LabDefaults()
	base.Database.SQLitePath = t.TempDir() + "/lab.db"
	drift := func(mut func(*Config)) Config {
		c := base
		mut(&c)
		return c
	}
	for name, mut := range map[string]func(*Config){
		"log level":     func(c *Config) { c.Logging.Level = "debug" },
		"log format":    func(c *Config) { c.Logging.Format = "json" },
		"body limit":    func(c *Config) { c.Limits.RequestBodyBytes = 2 << 20 },
		"header time":   func(c *Config) { c.Limits.ReadHeaderTimeout = "10s" },
		"shutdown time": func(c *Config) { c.Limits.ShutdownTimeout = "30s" },
		"loopback move": func(c *Config) { c.ListenAddr = "127.0.0.1:9008" },
		"ui dir":        func(c *Config) { c.UIDir = "/srv/blueveil/ui" },
		"pg pool":       func(c *Config) { c.Database.Postgres.MaxConns = 4 },
		"pg query time": func(c *Config) { c.Database.Postgres.QueryTimeout = "5s" },
	} {
		c := drift(mut)
		if err := c.Validate(); err != nil {
			t.Errorf("safe drift %q must validate: %v", name, err)
		}
	}
}

func TestDangerousDriftRejected(t *testing.T) {
	base := LabDefaults()
	base.Database.SQLitePath = t.TempDir() + "/lab.db"
	drift := func(mut func(*Config)) Config {
		c := base
		mut(&c)
		return c
	}
	for name, mut := range map[string]func(*Config){
		"bad backend":    func(c *Config) { c.Database.Backend = "cassandra" },
		"empty db path":  func(c *Config) { c.Database.SQLitePath = "" },
		"bad log level":  func(c *Config) { c.Logging.Level = "verbose" },
		"zero body":      func(c *Config) { c.Limits.RequestBodyBytes = 0 },
		"zero shutdown":  func(c *Config) { c.Limits.ShutdownTimeout = "0s" },
		"wide lab bind":  func(c *Config) { c.ListenAddr = "0.0.0.0:8008" },
		"bad tls min":    func(c *Config) { c.TLS.MinVersion = "1.0" },
		"tls files off":  func(c *Config) { c.TLS.CertFile = "/x.pem" },
		"bad pg timeout": func(c *Config) { c.Database.Postgres.QueryTimeout = "soon" },
	} {
		c := drift(mut)
		if err := c.Validate(); err == nil {
			t.Errorf("dangerous drift %q must fail validation", name)
		}
	}
	// Secrets never reinterpreted, never echoed: redacted view + errors.
	c := base
	c.Database.Postgres.Password = "drift-secret-pw"
	if got := c.Redacted().Database.Postgres.Password; got != "" {
		t.Fatalf("redacted password: %q", got)
	}
}

func TestEnvParsingIsCentralized(t *testing.T) {
	t.Setenv("BLUEVEIL_ENV", "production")
	t.Setenv("BLUEVEIL_ADDR", "0.0.0.0:9000")
	t.Setenv("BLUEVEIL_DB_BACKEND", "postgres")
	t.Setenv("BLUEVEIL_PG_HOST", "db.internal")
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Env != EnvProduction || c.ListenAddr != "0.0.0.0:9000" {
		t.Fatalf("env overrides not applied: %+v", c)
	}
	if c.Database.Backend != BackendPostgres || c.Database.Postgres.Host != "db.internal" {
		t.Fatalf("db env overrides not applied: %+v", c.Database)
	}
}
