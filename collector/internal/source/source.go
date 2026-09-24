// Package source abstracts telemetry intake. One interface, one in-memory
// implementation for verification/testing. No OS/network collectors here.
package source

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RawEvent is unvalidated input from a telemetry source. It is NOT a
// contract type: the normalizer decides what crosses the boundary.
type RawEvent struct {
	ID         string // source-assigned stable id (required downstream)
	Source     string // collector/source name, e.g. "waf-sim"
	AssetID    string // the observed asset
	IdentityID string // optional
	EventType  string // source-namespaced, e.g. "waf.request_blocked"
	Severity   string // contract enum name, e.g. "SEVERITY_HIGH"; empty = unknown
	Attributes map[string]string
	Raw        string    // UTF-8 excerpt of the raw record
	OccurredAt time.Time // zero = unknown (the collector never invents time)
}

// Source produces raw events until stopped or its channel closes.
type Source interface {
	Start(ctx context.Context) error
	Events() <-chan RawEvent
	Stop() error
}

// ErrSourceClosed is returned when injecting into a stopped source.
var ErrSourceClosed = errors.New("source: channel source stopped")

// ChannelSource is an in-memory source for tests and self-test. It owns no
// goroutine: Inject blocks until the pipeline receives (or ctx ends), and
// Stop closes the channel exactly once. No leak by construction.
type ChannelSource struct {
	ch     chan RawEvent
	mu     sync.RWMutex
	closed bool
}

// NewChannelSource returns a source with the given channel buffer.
func NewChannelSource(buffer int) *ChannelSource {
	if buffer < 0 {
		buffer = 0
	}
	return &ChannelSource{ch: make(chan RawEvent, buffer)}
}

// Start is a no-op: there is no background work to begin.
func (s *ChannelSource) Start(_ context.Context) error { return nil }

// Events exposes the receive-only channel for the pipeline.
func (s *ChannelSource) Events() <-chan RawEvent { return s.ch }

// Inject delivers one raw event, blocking until received or ctx ends.
// The read lock is held across the send so Stop cannot close the channel
// mid-send (send-on-closed panics); Stop waits for in-flight injects.
func (s *ChannelSource) Inject(ctx context.Context, e RawEvent) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrSourceClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.ch <- e:
		return nil
	}
}

// Stop closes the event channel exactly once; further Inject calls fail.
func (s *ChannelSource) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	return nil
}
