// Step 21L: performance regression properties. These assert behavior
// that capacity work must never break — not speed (benchmarks measure
// speed; these pin the invariants speed-ups must preserve).
package perf

import (
	"context"
	"testing"
	"time"

	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/pipeline"
)

// TestPipelineNoSilentLoss: every injected event is accepted or
// explicitly rejected — Accepted + len(Rejected) == sent, always.
func TestPipelineNoSilentLoss(t *testing.T) {
	ctx := context.Background()
	const total = 1000
	pipe, src, _, _ := benchPipeline(t, 256)
	reportCh := make(chan *pipeline.Report, 1)
	go func() {
		rep, err := pipe.Run(ctx)
		if err != nil {
			t.Errorf("run: %v", err)
		}
		reportCh <- rep
	}()
	for i := 0; i < total; i++ {
		if err := src.Inject(ctx, rawBenchEvent(i)); err != nil {
			t.Fatalf("inject %d: %v", i, err)
		}
	}
	_ = src.Stop()
	var rep *pipeline.Report
	select {
	case rep = <-reportCh:
	case <-time.After(60 * time.Second):
		t.Fatal("pipeline did not finish")
	}
	if rep.Accepted+len(rep.Rejected) != total {
		t.Fatalf("silent loss: accepted=%d rejected=%d sent=%d",
			rep.Accepted, len(rep.Rejected), total)
	}
	if rep.Accepted != total {
		t.Fatalf("all valid events must accept: %+v", rep.Metrics)
	}
}

// TestDetectionDeterministicUnderLoad: repeated identical events yield
// identical detection ids (no concurrency-driven duplicates).
func TestDetectionDeterministicUnderLoad(t *testing.T) {
	_ = evidence.NewStore
	eng := benchEngine(t)
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		evt := mustProtoEvent(t, rawBenchEvent(i%50))
		res, err := eng.Process(evt)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range res.Detections {
			seen[d.GetId()]++
		}
	}
	// 50 distinct events seen 4 times each: suppression must hold, so
	// each detection id appears exactly once (emitted) regardless of
	// repeats.
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("detection %s emitted %d times (want exactly once)", id, n)
		}
	}
}
