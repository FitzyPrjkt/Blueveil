package source

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInjectReceiveAndStop(t *testing.T) {
	ctx := context.Background()
	s := NewChannelSource(4)
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	want := RawEvent{ID: "evt-1", Source: "test", AssetID: "a", EventType: "t.e"}
	if err := s.Inject(ctx, want); err != nil {
		t.Fatalf("inject: %v", err)
	}
	select {
	case got := <-s.Events():
		if got.ID != want.ID {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, ok := <-s.Events(); ok {
		t.Fatal("channel must be closed after Stop")
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("second Stop must be idempotent: %v", err)
	}
}

func TestInjectAfterStopFails(t *testing.T) {
	ctx := context.Background()
	s := NewChannelSource(0)
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := s.Inject(ctx, RawEvent{}); !errors.Is(err, ErrSourceClosed) {
		t.Fatalf("want ErrSourceClosed, got %v", err)
	}
}
