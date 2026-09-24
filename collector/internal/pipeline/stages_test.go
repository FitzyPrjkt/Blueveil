package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/source"
)

func fixedEnricher(t *testing.T) enrich.Enricher {
	t.Helper()
	en, err := enrich.New("stage-test", func() time.Time {
		return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("enricher: %v", err)
	}
	return en
}

func stageRaw(id string) source.RawEvent {
	return source.RawEvent{
		ID: id, Source: "lab", AssetID: "a1", EventType: "t.a",
		Severity: "SEVERITY_LOW", OccurredAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC),
	}
}

func TestStagesMetricsAreCounted(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, &InMemorySink{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	pipe.WithEnricher(fixedEnricher(t)).WithCorrelation(true)
	go func() {
		_ = src.Inject(ctx, stageRaw("ok-1"))
		_ = src.Inject(ctx, source.RawEvent{ID: "bad-norm"}) // normalize fails
		_ = src.Stop()
	}()
	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	m := report.Metrics
	if m.Received != 2 || m.Accepted != 1 || m.Rejected != 1 || m.NormalizeErrs != 1 {
		t.Fatalf("metrics drift: %+v", m)
	}
	if m.EnrichErrs != 0 || m.SinkErrs != 0 {
		t.Fatalf("unexpected error counters: %+v", m)
	}
	if m.LatencyTotal <= 0 || m.AvgLatency() <= 0 {
		t.Fatalf("latency must be measured: %+v", m)
	}
}

func TestEnrichFailureIsARejection(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	// Enricher whose clock lies: every event fails enrichment, none invented.
	broken, err := enrich.New("broken", func() time.Time { return time.Time{} })
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, &InMemorySink{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	pipe.WithEnricher(broken)
	go func() {
		_ = src.Inject(ctx, stageRaw("ok-1"))
		_ = src.Stop()
	}()
	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Metrics.EnrichErrs != 1 || len(report.Rejected) != 1 || report.Accepted != 0 {
		t.Fatalf("enrich failure must reject exactly once: %+v", report.Metrics)
	}
	if !errors.Is(report.Rejected[0].Err, enrich.ErrEnrichment) {
		t.Fatalf("rejection must wrap ErrEnrichment: %v", report.Rejected[0].Err)
	}
}

func TestSlowSinkBoundedQueueLosesNothing(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	gate := make(chan struct{})
	slow := &gateSink{release: gate}
	pipe, err := NewPipeline(Config{QueueSize: 1}, src, slow)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for _, id := range []string{"q-1", "q-2", "q-3"} {
		if err := src.Inject(ctx, stageRaw(id)); err != nil {
			t.Fatalf("inject: %v", err)
		}
	}
	_ = src.Stop()
	done := make(chan *Report, 1)
	go func() {
		report, err := pipe.Run(ctx)
		if err != nil {
			t.Errorf("run: %v", err)
		}
		done <- report
	}()
	time.Sleep(100 * time.Millisecond) // let pressure build on the size-1 queue
	close(gate)                        // release the sink; everything must still arrive
	select {
	case report := <-done:
		if report.Accepted != 3 || len(report.Rejected) != 0 {
			t.Fatalf("bounded queue must lose nothing: %+v", report)
		}
		if got := slow.ids(); len(got) != 3 || got[0] != "q-1" || got[2] != "q-3" {
			t.Fatalf("order must survive backpressure: %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run hung under backpressure")
	}
}

type gateSink struct {
	release chan struct{}
	mu      sync.Mutex
	seen    []string
}

func (s *gateSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, e.GetId())
	return nil
}

func (s *gateSink) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func TestNoProcessingAfterShutdown(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	sink := &InMemorySink{}
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, sink)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	go func() {
		_ = src.Inject(ctx, stageRaw("only-1"))
		_ = src.Stop()
	}()
	if _, err := pipe.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	n := len(sink.Events())
	if err := src.Inject(ctx, stageRaw("late-1")); err == nil {
		t.Fatal("inject after pipeline Stop must fail (source stopped)")
	}
	time.Sleep(50 * time.Millisecond)
	if len(sink.Events()) != n {
		t.Fatal("events processed after shutdown completion")
	}
}
