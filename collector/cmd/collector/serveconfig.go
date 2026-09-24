// serveConfig assembles one validated Config from the JSON file (if
// given), environment, and CLI flags — in that precedence order, flags
// winning. Secrets travel by file or environment only, never by flag
// (command lines leak via ps).
package main

import (
	"fmt"
	"strings"

	"blueveil/collector/internal/config"
)

type serveFlags struct {
	addr                                string
	uiDir                               string
	iocSetPath, iocSetID, iocSetVersion string
	envName, dbBackend                  string
	tlsEnabled                          bool
	tlsCert, tlsKey                     string
	authEnabled                         bool
	logLevel, logFormat                 string
	dbPath                              string
}

func serveConfig(configFile string, f serveFlags) (config.Config, error) {
	var cfg config.Config
	var err error
	if strings.TrimSpace(configFile) != "" {
		cfg, err = config.LoadFile(configFile)
		if err != nil {
			return cfg, err
		}
		// Environment still overrides file content (file < env < flags).
		config.ApplyEnv(&cfg)
	} else {
		cfg, err = config.Load()
		if err != nil {
			return cfg, err
		}
	}
	// Flag overrides (operational surface only — never secrets).
	if f.addr != "" {
		cfg.ListenAddr = f.addr
	}
	if f.uiDir != "" {
		cfg.UIDir = f.uiDir
	}
	if f.iocSetPath != "" {
		cfg.IOCSet.Path = f.iocSetPath
	}
	if f.iocSetID != "" {
		cfg.IOCSet.ID = f.iocSetID
	}
	if f.iocSetVersion != "" {
		cfg.IOCSet.Version = f.iocSetVersion
	}
	if f.envName != "" {
		switch config.Environment(strings.ToLower(f.envName)) {
		case config.EnvLab:
			cfg.Env = config.EnvLab
		case config.EnvProduction:
			cfg.Env = config.EnvProduction
		default:
			return cfg, fmt.Errorf("serve: --env must be lab|production")
		}
	}
	if f.dbBackend != "" {
		switch config.DatabaseBackend(strings.ToLower(f.dbBackend)) {
		case config.BackendSQLite:
			cfg.Database.Backend = config.BackendSQLite
		case config.BackendPostgres:
			cfg.Database.Backend = config.BackendPostgres
		default:
			return cfg, fmt.Errorf("serve: --db-backend must be sqlite|postgres")
		}
	}
	if f.dbPath != "" {
		cfg.Database.SQLitePath = f.dbPath
	}
	if f.tlsEnabled {
		cfg.TLS.Enabled = true
	}
	if f.tlsCert != "" {
		cfg.TLS.CertFile = f.tlsCert
	}
	if f.tlsKey != "" {
		cfg.TLS.KeyFile = f.tlsKey
	}
	if f.authEnabled {
		cfg.Auth.Enabled = true
	}
	if f.logLevel != "" {
		cfg.Logging.Level = f.logLevel
	}
	if f.logFormat != "" {
		cfg.Logging.Format = f.logFormat
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
