// Environment and file loading: the ONLY place process environment is
// read for configuration. Precedence: explicit file < environment <
// caller overrides (flags). Secret-bearing values (passwords, key
// hashes) are transported, never logged or echoed in errors.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func splitHostPortStd(addr string) (string, string, error) {
	return net.SplitHostPort(addr)
}

// isLoopback reports loopback hosts. Empty means all interfaces (never
// loopback).
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseDur(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// LoadFile reads a JSON config file (0600 recommended for key material).
func LoadFile(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("config: read file: %v", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("config: parse file: %v", err)
	}
	c.applyDefaults()
	return c, nil
}

// Load returns lab defaults overridden by BLUEVEIL_CONFIG_FILE (if set)
// and then by BLUEVEIL_* environment variables. It does not validate;
// callers Validate before startup.
func Load() (Config, error) {
	c := LabDefaults()
	if path := strings.TrimSpace(os.Getenv("BLUEVEIL_CONFIG_FILE")); path != "" {
		filed, err := LoadFile(path)
		if err != nil {
			return c, err
		}
		c = filed
	}
	ApplyEnv(&c)
	return c, nil
}

func setIfEnv(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

func setIntIfEnv(dst *int, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			*dst = n
		}
	}
}

func setInt64IfEnv(dst *int64, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			*dst = n
		}
	}
}

func setBoolIfEnv(dst *bool, key string) {
	if v, ok := os.LookupEnv(key); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes":
			*dst = true
		case "0", "false", "no":
			*dst = false
		}
	}
}

// ApplyEnv maps the documented BLUEVEIL_* surface onto Config. Malformed
// values fail at Validate (actionable errors), never silently here —
// except enums, which are ignored when unknown so a typo cannot silently
// downgrade (e.g. production → lab). Exported so the serve entrypoint can
// layer env over an explicit config file (file < env < flags).
func ApplyEnv(c *Config) {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("BLUEVEIL_ENV"))); v != "" {
		switch Environment(v) {
		case EnvLab:
			c.Env = EnvLab
		case EnvProduction:
			c.Env = EnvProduction
		}
	}
	setIfEnv(&c.ListenAddr, "BLUEVEIL_ADDR")
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("BLUEVEIL_DB_BACKEND"))); v != "" {
		switch DatabaseBackend(v) {
		case BackendSQLite:
			c.Database.Backend = BackendSQLite
		case BackendPostgres:
			c.Database.Backend = BackendPostgres
		}
	}
	setIfEnv(&c.Database.SQLitePath, "BLUEVEIL_SQLITE_PATH")
	setIfEnv(&c.Database.Postgres.Host, "BLUEVEIL_PG_HOST")
	setIntIfEnv(&c.Database.Postgres.Port, "BLUEVEIL_PG_PORT")
	setIfEnv(&c.Database.Postgres.User, "BLUEVEIL_PG_USER")
	setIfEnv(&c.Database.Postgres.Password, "BLUEVEIL_PG_PASSWORD")
	setIfEnv(&c.Database.Postgres.DBName, "BLUEVEIL_PG_DBNAME")
	setIfEnv(&c.Database.Postgres.SSLMode, "BLUEVEIL_PG_SSLMODE")
	setIntIfEnv(&c.Database.Postgres.MaxConns, "BLUEVEIL_PG_MAX_CONNS")
	setIfEnv(&c.Database.Postgres.ConnectTimeout, "BLUEVEIL_PG_TIMEOUT")
	setIfEnv(&c.Database.Postgres.QueryTimeout, "BLUEVEIL_PG_QUERY_TIMEOUT")
	setBoolIfEnv(&c.TLS.Enabled, "BLUEVEIL_TLS_ENABLED")
	setIfEnv(&c.TLS.CertFile, "BLUEVEIL_TLS_CERT")
	setIfEnv(&c.TLS.KeyFile, "BLUEVEIL_TLS_KEY")
	setIfEnv(&c.TLS.MinVersion, "BLUEVEIL_TLS_MIN")
	setBoolIfEnv(&c.TLS.ExplicitInsecureHTTP, "BLUEVEIL_INSECURE_HTTP")
	setBoolIfEnv(&c.Auth.Enabled, "BLUEVEIL_AUTH_ENABLED")
	if v := strings.TrimSpace(os.Getenv("BLUEVEIL_API_KEYS")); v != "" {
		var keys []APIKey
		if err := json.Unmarshal([]byte(v), &keys); err == nil {
			c.Auth.Keys = keys
		}
	}
	if v := strings.TrimSpace(os.Getenv("BLUEVEIL_PUBLIC_PATHS")); v != "" {
		c.Auth.PublicPaths = strings.Split(v, ",")
		for i := range c.Auth.PublicPaths {
			c.Auth.PublicPaths[i] = strings.TrimSpace(c.Auth.PublicPaths[i])
		}
	}
	setIfEnv(&c.Logging.Level, "BLUEVEIL_LOG_LEVEL")
	setIfEnv(&c.Logging.Format, "BLUEVEIL_LOG_FORMAT")
	setInt64IfEnv(&c.Limits.RequestBodyBytes, "BLUEVEIL_MAX_BODY")
	setIfEnv(&c.Limits.ReadHeaderTimeout, "BLUEVEIL_READ_HEADER_TIMEOUT")
	setIfEnv(&c.UIDir, "BLUEVEIL_UI_DIR")
	setIfEnv(&c.IOCSet.Path, "BLUEVEIL_IOC_SET")
	setIfEnv(&c.IOCSet.ID, "BLUEVEIL_IOC_SET_ID")
	setIfEnv(&c.IOCSet.Version, "BLUEVEIL_IOC_SET_VERSION")
}
