// Deterministic synthetic workloads for capacity measurement (21B–
// 21F). All data is generated locally with fixed seeds/ids; nothing
// touches production datasets. Benchmarks log perf.Summary lines via
// b.Log — numbers are observed, never asserted (assertions live in the
// domain suites and in Test* below).
package perf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/incident"
	"blueveil/collector/internal/pipeline"
	"blueveil/collector/internal/source"
)

var benchClock = func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }

// rawBenchEvent builds a valid waf/net raw event with deterministic id.
func rawBenchEvent(i int) source.RawEvent {
	typ := "waf.request_blocked"
	attrs := map[string]string{}
	sev := "SEVERITY_HIGH"
	if i%2 == 1 {
		typ = "net.connection"
		sev = "SEVERITY_INFO"
		attrs = map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
			"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
		}
	}
	return source.RawEvent{
		ID: fmt.Sprintf("evt-bench-%06d", i), Source: "bench", AssetID: "bench-asset",
		EventType: typ, Severity: sev, Attributes: attrs,
		OccurredAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Millisecond),
	}
}

// TB is the *testing.B/*testing.T surface the harness needs.
type TB interface {
	Helper()
	Fatal(...any)
	Fatalf(string, ...any)
	TempDir() string
	Cleanup(func())
}

func benchEngine(t TB) *detect.Engine {
	t.Helper()
	eng, err := detect.NewEngine(benchClock)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []detect.Rule{detect.BlockHighSeverityRule{}, detect.SourceCriticalRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatal(err)
		}
	}
	burst, err := detect.NewBlockBurstRule(3, 5*time.Minute, benchClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RegisterRule(burst); err != nil {
		t.Fatal(err)
	}
	return eng
}

func benchPipeline(t TB, queue int) (*pipeline.Pipeline, *source.ChannelSource, *pipeline.InMemorySink, *detect.Store) {
	t.Helper()
	src := source.NewChannelSource(queue)
	mem := &pipeline.InMemorySink{}
	mgr, err := incident.NewManager(benchClock)
	if err != nil {
		t.Fatal(err)
	}
	en, err := enrich.New("bench", benchClock)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := pipeline.NewIncidentSink(benchEngine(t), mgr, evidence.NewStore(), &detect.Store{}, mem, mem)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := pipeline.NewPipeline(pipeline.Config{QueueSize: queue}, src, stage)
	if err != nil {
		t.Fatal(err)
	}
	pipe.WithEnricher(en).WithCorrelation(false)
	return pipe, src, mem, stage.Detections
}

// runAPIWorkload serves n requests across endpoints at concurrency c,
// returning per-request latencies and error count. requests carry the
// given Authorization secret ("" for open lab mode).
func runAPIWorkload(h http.Handler, endpoints []string, n, c int, auth string) ([]time.Duration, int) {
	lats := make([]time.Duration, n)
	var mu sync.Mutex
	errs := 0
	var wg sync.WaitGroup
	perWorker := (n + c - 1) / c
	idx := 0
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				mu.Lock()
				k := idx
				idx++
				mu.Unlock()
				if k >= n {
					return
				}
				req := httptest.NewRequest(http.MethodGet, endpoints[k%len(endpoints)], nil)
				if auth != "" {
					req.Header.Set("Authorization", "Bearer "+auth)
				}
				rec := httptest.NewRecorder()
				start := time.Now()
				h.ServeHTTP(rec, req)
				el := time.Since(start)
				mu.Lock()
				lats[k] = el
				if rec.Code != 200 {
					errs++
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return lats[:idx], errs
}
