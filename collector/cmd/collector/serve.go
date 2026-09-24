// Command serve exposes the workstation API and the built UI. The
// server is driven by one validated Config (see internal/config):
// backend selection (SQLite/PostgreSQL), TLS, authentication,
// authorization, structured logging, and metrics. Lab mode keeps the
// historical loopback-only behavior; production binds the configured
// address and fails closed on anything unsafe.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"blueveil/collector/internal/api"
	"blueveil/collector/internal/auth"
	"blueveil/collector/internal/config"
	"blueveil/collector/internal/obs"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/store/postgres"
	"blueveil/collector/internal/store/sqlite"
	"blueveil/collector/internal/threatintel"
)

// tlsConfigFor renders the Go TLS configuration. Certificates were
// already load-validated by config.Validate; this maps the minimum
// version (modern defaults, no custom cryptography).
func tlsConfigFor(tlsCfg config.TLSConfig) (*tls.Config, error) {
	if !tlsCfg.Enabled {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("serve: tls cert/key: %v", err)
	}
	min := uint16(tls.VersionTLS13)
	switch tlsCfg.MinVersion {
	case "", "1.3":
		min = tls.VersionTLS13
	case "1.2":
		min = tls.VersionTLS12
	default:
		return nil, fmt.Errorf("serve: tls min version must be 1.2 or 1.3")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   min,
	}, nil
}

func runServe(cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("serve: invalid configuration: %v", err)
	}
	if cfg.Env == config.EnvLab {
		host, _, err := net.SplitHostPort(cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("bad listen addr %q: %v", cfg.ListenAddr, err)
		}
		if host != "" && !isLoopback(host) {
			return fmt.Errorf("refusing non-loopback bind %q in lab mode (production for wider binds)", host)
		}
	}

	logger, err := obs.New(cfg.Logging.Level, cfg.Logging.Format, os.Stderr)
	if err != nil {
		return fmt.Errorf("serve: logging: %v", err)
	}
	metrics := obs.NewMetrics()
	log := logger.With("component", "serve")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	backend, health, closer, err := openBackend(ctx, cfg)
	if err != nil {
		return err
	}
	defer closer()
	log.Info("database ready", "backend", string(cfg.Database.Backend))

	apiSrv := api.NewServer(backend)
	if cfg.Auth.Enabled {
		keys := make([]auth.Key, 0, len(cfg.Auth.Keys))
		for _, k := range cfg.Auth.Keys {
			var exp time.Time
			if k.ExpiresAt != "" {
				exp, err = time.Parse(time.RFC3339, k.ExpiresAt)
				if err != nil {
					return fmt.Errorf("serve: auth key %q expires_at invalid: %v", k.ID, err)
				}
			}
			keys = append(keys, auth.Key{ID: k.ID, Role: k.Role, Hash: k.Hash, ExpiresAt: exp})
		}
		authenticator, err := auth.NewAPIKeyAuthenticator(keys, time.Now)
		if err != nil {
			return fmt.Errorf("serve: auth: %v", err)
		}
		apiSrv.UseAuth(authenticator, cfg.Auth.PublicPaths)
		log.Info("authentication enabled", "keys", len(keys))
	} else {
		log.Info("authentication disabled (lab mode)")
	}
	apiSrv.UseObservability(logger.With("component", "api"), metrics, health)
	if cfg.IOCSet.Path != "" {
		set, err := threatintel.LoadSet(cfg.IOCSet.Path, cfg.IOCSet.ID, cfg.IOCSet.Version)
		if err != nil {
			return fmt.Errorf("load IOC set: %v", err)
		}
		apiSrv.SetIOCSet(&set)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", apiSrv.Handler())
	index := filepath.Join(cfg.UIDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		return fmt.Errorf("UI not built: %s missing (run `npm run build` in collector/ui first)", index)
	}
	fileServer := http.FileServer(http.Dir(cfg.UIDir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback: hash tabs need no server routing, but direct hits
		// to unknown paths still land on the shell, never a blank page.
		path := filepath.Join(cfg.UIDir, filepath.Clean("/"+strings.TrimPrefix(r.URL.Path, "/")))
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			http.ServeFile(w, r, index)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
	limited := http.MaxBytesHandler(mux, cfg.Limits.RequestBodyBytes)
	readHeaderTimeout, err := time.ParseDuration(cfg.Limits.ReadHeaderTimeout)
	if err != nil {
		return fmt.Errorf("serve: read header timeout: %v", err)
	}
	srv := &http.Server{
		Addr: cfg.ListenAddr, Handler: limited,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	tlsCfg, err := tlsConfigFor(cfg.TLS)
	if err != nil {
		return err
	}
	redacted := cfg.Redacted()
	log.Info("serving Blueveil workstation",
		"addr", redacted.ListenAddr,
		"env", string(redacted.Env),
		"db_backend", string(redacted.Database.Backend),
		"tls", tlsCfg != nil,
		"auth", cfg.Auth.Enabled,
	)
	if cfg.Env == config.EnvProduction && tlsCfg == nil {
		log.Warn("serving plaintext HTTP in production (explicit insecure opt-out)")
	}
	shutdownTimeout, err := time.ParseDuration(cfg.Limits.ShutdownTimeout)
	if err != nil {
		return fmt.Errorf("serve: shutdown timeout: %v", err)
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	apiSrv.SetServing(true)
	return serveWithShutdown(srv, tlsCfg, log, shutdownTimeout,
		func() { apiSrv.SetServing(false) },
		func() { closer() },
		nil, signals)
}

// serveWithShutdown runs srv to READY, then on the first signal flips
// readiness (onSignal), stops accepting, drains in-flight work bounded
// by timeout, runs onShutdown exactly once (persistence close), and
// exits. Extra signals are drained and ignored: shutdown proceeds to
// its bound exactly once. listened receives the bound address (nil ok).
func serveWithShutdown(srv *http.Server, tlsCfg *tls.Config, log *obs.Logger, timeout time.Duration, onSignal, onShutdown func(), listened chan<- string, signals <-chan os.Signal) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("serve: listen: %v", err)
	}
	if listened != nil {
		listened <- ln.Addr().String()
	}
	serveErr := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			tlsLn := tls.NewListener(ln, tlsCfg)
			serveErr <- srv.Serve(tlsLn)
			return
		}
		serveErr <- srv.Serve(ln)
	}()
	log.Info("ready")
	sig := <-signals
	log.Info("shutdown signal received", "signal", sig.String())
	// Drain the signal buffer: repeats are acknowledged, never fatal,
	// never re-entrant.
	go func() {
		for range signals {
		}
	}()
	if onSignal != nil {
		onSignal()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	shutErr := srv.Shutdown(ctx)
	serveErrVal := <-serveErr
	if onShutdown != nil {
		onShutdown()
	}
	if shutErr != nil {
		return fmt.Errorf("serve: shutdown: %v", shutErr)
	}
	if serveErrVal != nil && serveErrVal != http.ErrServerClosed {
		return serveErrVal
	}
	log.Info("stopped")
	return nil
}

// pgConfigFrom maps the central config onto the postgres driver config.
func pgConfigFrom(cfg config.Config) postgres.Config {
	pg := cfg.Database.Postgres
	timeout := 10 * time.Second
	if pg.ConnectTimeout != "" {
		if d, err := time.ParseDuration(pg.ConnectTimeout); err == nil {
			timeout = d
		}
	}
	var queryTimeout time.Duration
	if pg.QueryTimeout != "" {
		if d, err := time.ParseDuration(pg.QueryTimeout); err == nil {
			queryTimeout = d
		}
	}
	maxConns := 8
	if pg.MaxConns > 0 {
		maxConns = pg.MaxConns
	}
	return postgres.Config{
		Host: pg.Host, Port: pg.Port, User: pg.User, Password: pg.Password,
		DBName: pg.DBName, SSLMode: pg.SSLMode,
		MaxConns: maxConns, ConnectTimeout: timeout, QueryTimeout: queryTimeout,
	}
}

// openBackend opens the configured database and returns the repository
// backend, a readiness health hook, and a closer. Failures name the
// backend and reason — never credentials.
func openBackend(ctx context.Context, cfg config.Config) (store.Backend, func(r *http.Request) error, func(), error) {
	switch cfg.Database.Backend {
	case config.BackendSQLite:
		db, err := sqlite.Open(ctx, sqlite.Config{Path: cfg.Database.SQLitePath})
		if err != nil {
			return store.Backend{}, nil, nil, fmt.Errorf("serve: sqlite open: %v", err)
		}
		health := func(r *http.Request) error {
			if err := db.Ping(r.Context()); err != nil {
				return err
			}
			v, err := db.SchemaVersion(r.Context())
			if err != nil {
				return err
			}
			if v != sqlite.CurrentSchemaVersion {
				return fmt.Errorf("sqlite schema version %d unsupported", v)
			}
			return nil
		}
		return db.Backend(), health, func() { _ = db.Close() }, nil
	case config.BackendPostgres:
		db, err := postgres.Open(ctx, pgConfigFrom(cfg))
		if err != nil {
			return store.Backend{}, nil, nil, fmt.Errorf("serve: postgres open: %v", err)
		}
		health := func(r *http.Request) error { return db.Health(r.Context()) }
		return db.Backend(), health, func() { db.Close() }, nil
	default:
		return store.Backend{}, nil, nil, fmt.Errorf("serve: unknown database backend %q", cfg.Database.Backend)
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
