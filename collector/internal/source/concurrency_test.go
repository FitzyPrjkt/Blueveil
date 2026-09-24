// Step 14D: cancellation and Stop-while-blocked on ChannelSource.
// A blocked Inject with a cancelled context returns ctx.Err without
// touching state; Stop racing blocked injects never panics and every
// caller gets an explicit result. Run with -race.
package source

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInjectCancelledContext(t *testing.T) {
	s := NewChannelSource(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Inject(ctx, RawEvent{ID: "x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	// Nothing was delivered: the channel still blocks a receiver.
	select {
	case <-s.Events():
		t.Fatalf("cancelled inject must not deliver")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestStopWhileInjectBlocked(t *testing.T) {
	s := NewChannelSource(0)
	const n = 8
	var closed, cancelled atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			switch err := s.Inject(ctx, RawEvent{ID: "y"}); {
			case err == nil:
				t.Errorf("unreceived inject must not succeed")
			case errors.Is(err, ErrSourceClosed):
				closed.Add(1)
			case errors.Is(err, context.DeadlineExceeded):
				cancelled.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	// Every caller got an explicit verdict; none panicked, none succeeded
	// spuriously. (Blocked senders may observe either close or timeout.)
	if closed.Load()+cancelled.Load() != n {
		t.Fatalf("want %d explicit results, got closed=%d cancelled=%d", n, closed.Load(), cancelled.Load())
	}
	if err := s.Inject(context.Background(), RawEvent{ID: "z"}); !errors.Is(err, ErrSourceClosed) {
		t.Fatalf("post-stop inject must be ErrSourceClosed, got %v", err)
	}
}
