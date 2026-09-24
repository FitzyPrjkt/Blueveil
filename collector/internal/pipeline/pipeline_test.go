package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/source"
)

func TestEndToEndAcceptedAndRejectedAreAccounted(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	sink := &InMemorySink{}
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, sink)
	if err != nil {
		t.Fatalf("new pipeline: %v", err)
	}

	now := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id, typ string) source.RawEvent {
		return source.RawEvent{
			ID: id, Source: "test", AssetID: "asset-1",
			EventType: typ, Severity: "SEVERITY_LOW", OccurredAt: now,
		}
	}
	go func() {
		_ = src.Inject(ctx, mk("evt-ok-1", "t.a"))
		_ = src.Inject(ctx, mk("evt-ok-2", "t.b"))
		_ = src.Inject(ctx, source.RawEvent{ID: "evt-bad", Source: "test"}) // no asset/type
		_ = src.Stop()
	}()

	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Accepted != 2 {
		t.Fatalf("accepted=%d, want 2", report.Accepted)
	}
	if len(report.Rejected) != 1 || report.Rejected[0].Raw.ID != "evt-bad" {
		t.Fatalf("rejected must hold exactly the bad event: %+v", report.Rejected)
	}
	if len(sink.Events()) != 2 {
		t.Fatalf("sink holds %d events, want 2", len(sink.Events()))
	}
	if sink.Events()[0].GetId() != "evt-ok-1" {
		t.Fatalf("sink order/content drift: %+v", sink.Events()[0])
	}
}

func TestSinkFailureAbortsRun(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	sink := &InMemorySink{}
	sink.SetError(errors.New("disk gone"))
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, sink)
	if err != nil {
		t.Fatalf("new pipeline: %v", err)
	}
	go func() {
		_ = src.Inject(ctx, source.RawEvent{
			ID: "evt-1", Source: "test", AssetID: "a", EventType: "t.e",
			Severity: "SEVERITY_LOW", OccurredAt: time.Now(),
		})
		_ = src.Stop()
	}()
	report, err := pipe.Run(ctx)
	if !errors.Is(err, ErrSink) {
		t.Fatalf("want ErrSink, got %v (report %+v)", err, report)
	}
	if report.Accepted != 0 {
		t.Fatalf("nothing must be counted accepted on sink failure: %+v", report)
	}
}

func TestCancelShutsDownWithoutHanging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	src := source.NewChannelSource(0) // rendezvous: nothing flows without a receiver
	sink := &InMemorySink{}
	pipe, err := NewPipeline(Config{QueueSize: 2}, src, sink)
	if err != nil {
		t.Fatalf("new pipeline: %v", err)
	}
	done := make(chan *Report, 1)
	go func() {
		report, err := pipe.Run(ctx)
		if err != nil {
			t.Errorf("cancelled run must return report+nil, got %v", err)
		}
		done <- report
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case report := <-done:
		if report.Accepted != 0 || len(report.Rejected) != 0 {
			t.Fatalf("empty run must report zeros: %+v", report)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not shut down after cancel (goroutine leak)")
	}
}

func TestBadConfigRejected(t *testing.T) {
	if _, err := NewPipeline(Config{QueueSize: 0}, source.NewChannelSource(1), &InMemorySink{}); err == nil {
		t.Fatal("QueueSize 0 must be rejected")
	}
	if _, err := NewPipeline(Config{QueueSize: 1}, nil, &InMemorySink{}); err == nil {
		t.Fatal("nil source must be rejected")
	}
}
