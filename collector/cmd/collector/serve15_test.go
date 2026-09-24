// Steps 15F/15H: TLS configuration, config assembly, and production
// startup failure behavior. Failures name fields and reasons — never
// secret values.
package main

import (
	"crypto/tls"
	"os"
	"strings"
	"testing"

	"blueveil/collector/internal/config"
)

func TestTLSConfigFor(t *testing.T) {
	cfg, err := tlsConfigFor(config.TLSConfig{Enabled: false})
	if err != nil || cfg != nil {
		t.Fatalf("disabled TLS: %+v %v", cfg, err)
	}
	cfg, err = tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: "testdata/cert.pem", KeyFile: "testdata/key.pem",
		MinVersion: "1.3",
	})
	if err != nil || cfg == nil {
		t.Fatalf("valid pair: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("default minimum must be TLS 1.3, got %x", cfg.MinVersion)
	}
	cfg, err = tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: "testdata/cert.pem", KeyFile: "testdata/key.pem",
		MinVersion: "1.2",
	})
	if err != nil || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("1.2 minimum: %+v %v", cfg, err)
	}
	if _, err := tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: "testdata/cert.pem", KeyFile: "testdata/key.pem",
		MinVersion: "1.0",
	}); err == nil {
		t.Fatalf("TLS 1.0 must be rejected")
	}
	if _, err := tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: "testdata/nope.pem", KeyFile: "testdata/key.pem",
	}); err == nil {
		t.Fatalf("missing certificate must fail")
	}
	if _, err := tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: "testdata/cert.pem", KeyFile: "testdata/nope.pem",
	}); err == nil {
		t.Fatalf("missing key must fail")
	}
}

func TestServeConfigLabAssembles(t *testing.T) {
	t.Setenv("BLUEVEIL_ENV", "")
	t.Setenv("BLUEVEIL_CONFIG_FILE", "")
	cfg, err := serveConfig("", serveFlags{dbPath: t.TempDir() + "/lab.db"})
	if err != nil {
		t.Fatalf("lab serve config: %v", err)
	}
	if cfg.Env != config.EnvLab || cfg.Database.Backend != config.BackendSQLite {
		t.Fatalf("lab defaults: %+v", cfg)
	}
}

func TestServeConfigProductionFailsClosed(t *testing.T) {
	t.Setenv("BLUEVEIL_CONFIG_FILE", "")
	t.Setenv("BLUEVEIL_ENV", "production")
	_, err := serveConfig("", serveFlags{dbPath: t.TempDir() + "/p.db"})
	if err == nil {
		t.Fatalf("bare production flags must fail (no auth, no TLS)")
	}
}

func TestServeConfigPrecedenceFlagOverEnvOverFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/base.json"
	base := `{"env":"lab","listen_addr":"127.0.0.1:8008",
		"database":{"backend":"sqlite","sqlite_path":"` + dir + `/a.db"},
		"tls":{"enabled":false},"auth":{"enabled":false},
		"logging":{"level":"info","format":"text"},
		"limits":{"request_body_bytes":1048576,"read_header_timeout":"5s","shutdown_timeout":"10s"},
		"ui_dir":"x"}`
	if err := os.WriteFile(cfgPath, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLUEVEIL_ADDR", "127.0.0.1:9001")
	// Flag beats env.
	cfg, err := serveConfig(cfgPath, serveFlags{addr: "127.0.0.1:9002", dbPath: dir + "/b.db"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:9002" {
		t.Fatalf("flag must win, got %q", cfg.ListenAddr)
	}
	// Env beats file.
	cfg, err = serveConfig(cfgPath, serveFlags{dbPath: dir + "/b.db"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:9001" {
		t.Fatalf("env must beat file, got %q", cfg.ListenAddr)
	}
}

func TestServeConfigBadEnvRejected(t *testing.T) {
	t.Setenv("BLUEVEIL_CONFIG_FILE", "")
	_, err := serveConfig("", serveFlags{envName: "staging"})
	if err == nil {
		t.Fatalf("unknown env must fail")
	}
	_, err = serveConfig("", serveFlags{dbPath: t.TempDir() + "/x.db", dbBackend: "cassandra"})
	if err == nil {
		t.Fatalf("unknown backend must fail")
	}
}

func TestOpenBackendFailuresNameBackendNotSecrets(t *testing.T) {
	cfg := config.LabDefaults()
	cfg.Database.SQLitePath = "/nonexistent-dir-xyz/db.sqlite"
	_, _, _, err := openBackend(t.Context(), cfg)
	if err == nil {
		t.Fatalf("missing sqlite dir must fail")
	}
	cfg.Database.Backend = config.BackendPostgres
	cfg.Database.Postgres = config.PostgresConfig{
		Host: "127.0.0.1", Port: 1, User: "u", Password: "pg-secret-value",
		DBName: "d", SSLMode: "require",
	}
	_, _, _, err = openBackend(t.Context(), cfg)
	if err == nil {
		t.Fatalf("unreachable postgres must fail")
	}
	for _, secret := range []string{"pg-secret-value"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("backend error leaks secret: %v", err)
		}
	}
	if !strings.Contains(err.Error(), "postgres") {
		t.Fatalf("backend error must name the backend: %v", err)
	}
}
