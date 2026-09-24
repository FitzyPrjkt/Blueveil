package source

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const readerFixture = `{"id":"evt-r-01","source":"lab","asset_id":"a1","event_type":"t.a","severity":"SEVERITY_LOW","occurred_at":"2026-09-12T09:00:00Z"}

not-json{{{
{"id":"evt-r-02","source":"lab","asset_id":"a1","event_type":"t.b","occurred_at":"not-a-time"}
{"id":"evt-r-03","source":"lab","asset_id":"a1","event_type":"t.c"}
`

func drain(t *testing.T, s *ReaderSource) []RawEvent {
	t.Helper()
	var out []RawEvent
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e, ok := <-s.Events():
			if !ok {
				return out
			}
			out = append(out, e)
		case <-timeout:
			t.Fatal("timed out draining ReaderSource")
		}
	}
}

func TestReaderSourceValidAndMalformed(t *testing.T) {
	ctx := context.Background()
	s := NewReaderSource(strings.NewReader(readerFixture))
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	got := drain(t, s)
	if len(got) != 2 || got[0].ID != "evt-r-01" || got[1].ID != "evt-r-03" {
		t.Fatalf("valid lines must flow in order, got %+v", got)
	}
	if !got[0].OccurredAt.Equal(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("timestamp drift: %v", got[0].OccurredAt)
	}
	bad := s.BadLines()
	if len(bad) != 2 || bad[0].Line != 3 || bad[1].Line != 4 {
		t.Fatalf("malformed lines 3,4 must be recorded, got %+v", bad)
	}
}

func TestReaderSourceShutdown(t *testing.T) {
	ctx := context.Background()
	s := NewReaderSource(strings.NewReader(readerFixture))
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatalf("repeated Start must be a no-op: %v", err)
	}
	_ = drain(t, s)
	for i := 0; i < 3; i++ {
		if err := s.Stop(); err != nil {
			t.Fatalf("repeated Stop must be safe: %v", err)
		}
	}
}

func TestReaderSourceStopBeforeStart(t *testing.T) {
	s := NewReaderSource(strings.NewReader(""))
	if err := s.Stop(); err != nil {
		t.Fatalf("stop before start: %v", err)
	}
	if _, ok := <-s.Events(); ok {
		t.Fatal("channel must be closed")
	}
}

func TestReaderSourceCancelStopsScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Never-yielding but closable reader: shutdown must still terminate.
	s := NewReaderSource(&slowReader{})
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	cancel()
	done := make(chan struct{})
	go func() { _ = s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung after cancel (goroutine leak)")
	}
	if n := len(s.BadLines()); n != 0 {
		t.Fatalf("close-induced read error must not pollute BadLines, got %v", s.BadLines())
	}
}

type slowReader struct {
	mu     sync.Mutex
	closed bool
}

func (r *slowReader) Read(_ []byte) (int, error) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, errors.New("closed")
	}
	time.Sleep(20 * time.Millisecond)
	return 0, nil
}

func (r *slowReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}
