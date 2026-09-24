// ReaderSource: a realistic local/lab source reading JSON-lines telemetry
// from any io.Reader (file, stdin, in-memory buffer in tests).
//
// Each non-empty line must be one JSON object shaped like RawEvent with
// snake_case keys: id, source, asset_id, identity_id, event_type, severity,
// attributes, raw, occurred_at (RFC 3339, empty = unknown).
//
// Malformed lines (bad JSON, bad timestamp) never enter the pipeline: they
// are recorded as BadLines, observable after the run. Semantically empty
// but well-formed lines flow to the normalizer, which rejects them there.
// Empty lines are skipped silently (line framing, not telemetry).
package source

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// SourceError is one malformed input line, with its 1-based line number.
type SourceError struct {
	Line  int
	Cause string
}

// BadLineReporter is implemented by sources that can report malformed input
// the pipeline never accepted. The pipeline appends these to its report.
type BadLineReporter interface {
	BadLines() []SourceError
}

// readerBuffer caps lines at 1 MiB: telemetry lines are small; anything
// larger is malformed input, not telemetry.
const readerBuffer = 1 << 20

// ReaderSource streams decoded RawEvents. It owns exactly one scanner
// goroutine between Start and Stop; repeated Start/Stop are safe.
type ReaderSource struct {
	r       io.Reader
	ch      chan RawEvent
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	started bool
	stopped bool
	bad     []SourceError
}

// NewReaderSource returns a source decoding JSON-lines from r.
func NewReaderSource(r io.Reader) *ReaderSource {
	return &ReaderSource{r: r, ch: make(chan RawEvent, 64), stopCh: make(chan struct{})}
}

// Start begins scanning. Safe to call repeatedly (later calls are no-ops).
// Starting after Stop is an error: a stopped source stays stopped.
func (s *ReaderSource) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return fmt.Errorf("source: ReaderSource stopped")
	}
	if s.started {
		return nil
	}
	s.started = true
	s.wg.Add(1)
	go s.scan(ctx)
	return nil
}

// Events exposes the decoded-event channel (valid after construction).
func (s *ReaderSource) Events() <-chan RawEvent { return s.ch }

// BadLines returns a copy of every malformed line recorded so far.
func (s *ReaderSource) BadLines() []SourceError {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SourceError, len(s.bad))
	copy(out, s.bad)
	return out
}

// Stop halts scanning, waits for the scanner, and closes the channel.
// Safe to call repeatedly and before Start. Stop takes ownership of the
// reader: if it implements io.Closer it is closed to unblock an in-flight
// Read. A never-yielding, non-closable reader is the one documented case
// where shutdown waits for the reader — use finite streams or Closers.
func (s *ReaderSource) Stop() error {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		close(s.stopCh)
	}
	started := s.started
	s.mu.Unlock()
	if c, ok := s.r.(io.Closer); ok {
		_ = c.Close()
	}
	if started {
		s.wg.Wait()
	} else {
		close(s.ch)
	}
	return nil
}

func (s *ReaderSource) record(line int, cause string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bad = append(s.bad, SourceError{Line: line, Cause: cause})
}

type rawJSON struct {
	ID         string            `json:"id"`
	Source     string            `json:"source"`
	AssetID    string            `json:"asset_id"`
	IdentityID string            `json:"identity_id"`
	EventType  string            `json:"event_type"`
	Severity   string            `json:"severity"`
	Attributes map[string]string `json:"attributes"`
	Raw        string            `json:"raw"`
	OccurredAt string            `json:"occurred_at"`
}

func (s *ReaderSource) scan(ctx context.Context) {
	defer close(s.ch)
	defer s.wg.Done()
	scanner := bufio.NewScanner(s.r)
	scanner.Buffer(make([]byte, 4096), readerBuffer)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}
		var in rawJSON
		if err := json.Unmarshal([]byte(text), &in); err != nil {
			s.record(lineNo, "json: "+err.Error())
			continue
		}
		raw, err := decodeLine(in)
		if err != nil {
			s.record(lineNo, err.Error())
			continue
		}
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case s.ch <- raw:
		}
	}
	if err := scanner.Err(); err != nil && !s.stopRequested(ctx) {
		s.record(lineNo+1, "read: "+err.Error())
	}
}

func (s *ReaderSource) stopRequested(ctx context.Context) bool {
	select {
	case <-s.stopCh:
		return true
	default:
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func decodeLine(in rawJSON) (RawEvent, error) {
	raw := RawEvent{
		ID:         in.ID,
		Source:     in.Source,
		AssetID:    in.AssetID,
		IdentityID: in.IdentityID,
		EventType:  in.EventType,
		Severity:   in.Severity,
		Attributes: in.Attributes,
		Raw:        in.Raw,
	}
	if in.OccurredAt != "" {
		ts, err := time.Parse(time.RFC3339, in.OccurredAt)
		if err != nil {
			return RawEvent{}, fmt.Errorf("occurred_at: %v", err)
		}
		raw.OccurredAt = ts
	}
	return raw, nil
}
