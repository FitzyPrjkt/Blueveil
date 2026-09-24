// Capacity benchmarks 21B–21F, 21H. Run with e.g.
// go test ./internal/perf/ -bench 'APIReads/SQLite' -benchtime 500x -run '^$'
// PG benchmarks additionally need BLUEVEIL_TEST_POSTGRES. Benchmarks log
// observed summaries; they assert nothing about speed.
package perf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"database/sql"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"blueveil/collector/internal/api"
	"blueveil/collector/internal/auth"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/normalize"
	"blueveil/collector/internal/pipeline"
	"blueveil/collector/internal/source"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/store/postgres"
	"blueveil/collector/internal/store/sqlite"
)

// pgOpenBench creates an isolated database on the test server and opens
// it. Caller closes (cleanup drops the database).
func pgOpenBench(b *testing.B, cs string) (*postgres.DB, error) {
	b.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, cs)
	if err != nil {
		return nil, err
	}
	defer admin.Close(ctx)
	name := fmt.Sprintf("blueveil_bench_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+strings.ReplaceAll(name, `"`, `""`)+`"`); err != nil {
		return nil, err
	}
	b.Cleanup(func() {
		c, err := pgx.Connect(ctx, cs)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, `DROP DATABASE IF EXISTS "`+strings.ReplaceAll(name, `"`, `""`)+`" WITH (FORCE)`)
	})
	host, port, user, dbname := splitConn(cs)
	_ = dbname
	return postgres.Open(ctx, postgres.Config{
		Host: host, Port: port, User: user, DBName: name, SSLMode: "disable", MaxConns: 8,
	})
}

func splitConn(cs string) (host string, port int, user, dbname string) {
	host, port, user, dbname = "127.0.0.1", 5432, "", ""
	for _, part := range strings.Fields(cs) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "host":
			host = kv[1]
		case "port":
			fmt.Sscanf(kv[1], "%d", &port)
		case "user":
			user = kv[1]
		case "dbname":
			dbname = kv[1]
		}
	}
	return host, port, user, dbname
}

type pgOutputs = postgres.PipelineOutputs

func pgPersistBench(b *testing.B, db *postgres.DB, batch postgres.PipelineOutputs) error {
	b.Helper()
	return postgres.PersistRunTx(context.Background(), db, batch)
}

func sqlOpenBench(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
}

var apiEndpoints = []string{
	"/api/v1/telemetry", "/api/v1/detections", "/api/v1/alerts",
	"/api/v1/incidents", "/api/v1/evidence", "/api/v1/assets",
	"/api/v1/network/observations", "/api/v1/monitoring/events",
	"/api/v1/hunting/events", "/api/v1/grc/assessments",
	"/api/v1/supply-chain/components", "/api/v1/validation-results",
	"/api/v1/continuous-security/checks",
}

// seedAPIStore persists count telemetry rows plus the fixed lab rows the
// endpoints join against (detections for detected flags, one asset).
func seedAPIStore(t TB, be store.Backend, count int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < count; i++ {
		raw := rawBenchEvent(i)
		evt := mustProtoEvent(t, raw)
		if err := be.Telemetry.Append(ctx, evt); err != nil {
			t.Fatal(err)
		}
	}
}

func benchSQLiteSeeded(t TB, count int) store.Backend {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "bench.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	be := db.Backend()
	seedAPIStore(t, be, count)
	return be
}

func benchAPILevels(b *testing.B, name string, be store.Backend, authSecret string) {
	for _, c := range []int{1, 5, 10, 25, 50, 100} {
		c := c
		b.Run(fmt.Sprintf("C%d", c), func(b *testing.B) {
			srv := api.NewServer(be)
			if authSecret != "" {
				h, err := bcrypt.GenerateFromPassword([]byte(authSecret), bcrypt.MinCost)
				if err != nil {
					b.Fatal(err)
				}
				a, err := auth.NewAPIKeyAuthenticator([]auth.Key{
					{ID: "bench", Role: auth.RoleRead, Hash: string(h)},
				}, time.Now)
				if err != nil {
					b.Fatal(err)
				}
				srv.UseAuth(a, nil)
			}
			h := srv.Handler()
			const perLevel = 300
			start := time.Now()
			lats, errs := runAPIWorkload(h, apiEndpoints, perLevel, c, authSecret)
			el := time.Since(start)
			s := Summarize(name, lats, c, el, errs)
			b.Logf("concurrency=%d ops=%d elapsed=%v err=%d min=%v p50=%v p95=%v(ok=%v) p99=%v(ok=%v) max=%v rps=%.1f",
				c, s.Ops, el, errs, s.Min, s.P50, s.P95, s.P95ok, s.P99, s.P99ok, s.Max,
				float64(s.Ops)/el.Seconds())
		})
	}
}

func BenchmarkAPIReadsSQLite(b *testing.B) {
	be := benchSQLiteSeeded(b, 1000)
	benchAPILevels(b, "api-reads-sqlite-1k", be, "")
}

// BenchmarkAPIReadsPerEndpoint isolates per-route cost at concurrency 1
// so the mixed workload above can be attributed honestly.
func BenchmarkAPIReadsPerEndpoint(b *testing.B) {
	be := benchSQLiteSeeded(b, 1000)
	srv := api.NewServer(be)
	h := srv.Handler()
	for _, ep := range apiEndpoints {
		ep := ep
		b.Run(fmt.Sprintf("EP%s", shortEP(ep)), func(b *testing.B) {
			start := time.Now()
			lats, errs := runAPIWorkload(h, []string{ep}, 100, 1, "")
			el := time.Since(start)
			s := Summarize("per-endpoint", lats, 1, el, errs)
			b.Logf("endpoint=%s ops=%d err=%d min=%v p50=%v max=%v rps=%.1f",
				ep, s.Ops, errs, s.Min, s.P50, s.Max, float64(s.Ops)/el.Seconds())
		})
	}
}

func shortEP(ep string) string {
	parts := splitPath(ep)
	return parts[len(parts)-1]
}

func splitPath(ep string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(ep); i++ {
		if ep[i] == '/' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(ep[i])
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func BenchmarkAPIReadsMemory(b *testing.B) {
	be := store.NewMemoryBackend()
	seedAPIStore(b, be, 1000)
	benchAPILevels(b, "api-reads-memory-1k", be, "")
}

func BenchmarkAPIReadsGated(b *testing.B) {
	// Production-equivalent path (bcrypt verification per request).
	be := store.NewMemoryBackend()
	seedAPIStore(b, be, 200)
	srv := api.NewServer(be)
	h, _ := bcrypt.GenerateFromPassword([]byte("bench-secret"), bcrypt.MinCost)
	a, err := auth.NewAPIKeyAuthenticator([]auth.Key{
		{ID: "bench", Role: auth.RoleRead, Hash: string(h)},
	}, time.Now)
	if err != nil {
		b.Fatal(err)
	}
	srv.UseAuth(a, nil)
	start := time.Now()
	lats, errs := runAPIWorkload(srv.Handler(), apiEndpoints, 200, 5, "bench-secret")
	el := time.Since(start)
	s := Summarize("api-reads-gated", lats, 5, el, errs)
	b.Logf("ops=%d elapsed=%v err=%d min=%v p50=%v max=%v rps=%.1f",
		s.Ops, el, errs, s.Min, s.P50, s.Max, float64(s.Ops)/el.Seconds())
}

// BenchmarkIngestPaced injects total events at ratePerSec via the real
// pipeline and reports accepted/rejected plus achieved rate. The
// pipeline applies backpressure (blocking inject), so achieved rate is
// the honest capacity signal — never assumed equal to target.
func BenchmarkIngestPaced(b *testing.B) {
	for _, rate := range []int{10, 50, 100, 250, 500} {
		rate := rate
		b.Run(fmt.Sprintf("R%d", rate), func(b *testing.B) {
			const total = 2000
			pipe, src, _, _ := benchPipeline(b, 256)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reportCh := make(chan *pipeline.Report, 1)
			go func() {
				rep, err := pipe.Run(ctx)
				if err != nil {
					b.Errorf("run: %v", err)
				}
				reportCh <- rep
			}()
			ticker := time.NewTicker(time.Second / time.Duration(rate))
			defer ticker.Stop()
			sent := 0
			start := time.Now()
			for i := 0; i < total; i++ {
				<-ticker.C
				if err := src.Inject(ctx, rawBenchEvent(i)); err != nil {
					b.Fatalf("inject %d: %v", i, err)
				}
				sent++
			}
			_ = src.Stop()
			rep := <-reportCh
			el := time.Since(start)
			achieved := float64(sent) / el.Seconds()
			b.Logf("target=%d/s sent=%d accepted=%d rejected=%d elapsed=%v achieved=%.1f/s",
				rate, sent, rep.Accepted, len(rep.Rejected), el, achieved)
		})
	}
}

// mustProtoEvent converts one synthetic raw event via the real
// normalizer (the same mapping production ingestion uses).
func mustProtoEvent(t TB, raw source.RawEvent) *v1.TelemetryEvent {
	t.Helper()
	evt, err := normalize.New().Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return evt
}

// BenchmarkPersistSQLite times whole-run persistence batches.
func BenchmarkPersistSQLite(b *testing.B) {
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(b.TempDir(), "bench.db")})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	be := db.Backend()
	var batch sqlite.PipelineOutputs
	for i := 0; i < 100; i++ {
		batch.Telemetry = append(batch.Telemetry, mustProtoEvent(b, rawBenchEvent(i)))
	}
	b.ResetTimer()
	start := time.Now()
	if err := sqlite.PersistRunTx(context.Background(), db, batch); err != nil {
		b.Fatal(err)
	}
	_ = be
	el := time.Since(start)
	b.Logf("batch=100 elapsed=%v per_event=%v", el, el/100)
}

// BenchmarkAPIReadsPostgres runs the mixed workload against live PG.
// Gated on BLUEVEIL_TEST_POSTGRES; each run uses an isolated database.
func BenchmarkAPIReadsPostgres(b *testing.B) {
	cs := os.Getenv("BLUEVEIL_TEST_POSTGRES")
	if cs == "" {
		b.Skip("BLUEVEIL_TEST_POSTGRES unset")
	}
	db, err := pgOpenBench(b, cs)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	seedAPIStore(b, db.Backend(), 1000)
	benchAPILevels(b, "api-reads-pg-1k", db.Backend(), "")
}

// BenchmarkPersistPostgres times whole-run batches on live PG.
func BenchmarkPersistPostgres(b *testing.B) {
	cs := os.Getenv("BLUEVEIL_TEST_POSTGRES")
	if cs == "" {
		b.Skip("BLUEVEIL_TEST_POSTGRES unset")
	}
	db, err := pgOpenBench(b, cs)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	var batch pgOutputs
	for i := 0; i < 100; i++ {
		batch.Telemetry = append(batch.Telemetry, mustProtoEvent(b, rawBenchEvent(i)))
	}
	b.ResetTimer()
	start := time.Now()
	if err := pgPersistBench(b, db, batch); err != nil {
		b.Fatal(err)
	}
	el := time.Since(start)
	b.Logf("batch=100 elapsed=%v per_event=%v", el, el/100)
}

// BenchmarkBackupSQLite times VACUUM INTO snapshots at two dataset
// sizes (integrity-preserving path, no stop required).
func BenchmarkBackupSQLite(b *testing.B) {
	for _, n := range []int{100, 2000} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			dir := b.TempDir()
			db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(dir, "src.db")})
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			be := db.Backend()
			for i := 0; i < n; i++ {
				if err := be.Telemetry.Append(context.Background(), mustProtoEvent(b, rawBenchEvent(i))); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			start := time.Now()
			rw, err := sqlOpenBench(dir + "/src.db")
			if err != nil {
				b.Fatal(err)
			}
			defer rw.Close()
			if _, err := rw.Exec(`VACUUM INTO '` + dir + `/snap.db'`); err != nil {
				b.Fatal(err)
			}
			el := time.Since(start)
			var sz int64
			if fi, err := os.Stat(dir + "/snap.db"); err == nil {
				sz = fi.Size()
			}
			b.Logf("rows=%d elapsed=%v snapshot_bytes=%d", n, el, sz)
		})
	}
}

// BenchmarkAPIBurstErrors runs a fixed burst and reports only errors
// (capacity smoke for the error paths, not latency).
func BenchmarkAPIBurstErrors(b *testing.B) {
	be := store.NewMemoryBackend()
	srv := api.NewServer(be)
	start := time.Now()
	_, errs := runAPIWorkload(srv.Handler(), []string{"/api/v1/assets/no-such"}, 200, 10, "")
	el := time.Since(start)
	b.Logf("ops=200 err=%d elapsed=%v (all errors must be 404 envelopes)", errs, el)
}

// BenchmarkDetection measures per-event cost with stateful rules over
// 2000 mixed events, reporting matches and throughput.
func BenchmarkDetection(b *testing.B) {
	eng := benchEngine(b)
	norm := normalize.New()
	events := make([]*v1.TelemetryEvent, 2000)
	for i := range events {
		evt, err := norm.Normalize(rawBenchEvent(i))
		if err != nil {
			b.Fatal(err)
		}
		events[i] = evt
	}
	b.ResetTimer()
	start := time.Now()
	matched := 0
	for i := 0; i < b.N; i++ {
		res, err := eng.Process(events[i%len(events)])
		if err != nil {
			b.Fatal(err)
		}
		matched += len(res.Detections)
	}
	el := time.Since(start)
	b.Logf("events=%d matched=%d elapsed=%v per_event=%v eps=%.1f",
		b.N, matched, el, el/time.Duration(b.N), float64(b.N)/el.Seconds())
}
