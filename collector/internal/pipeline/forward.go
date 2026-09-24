// LineSink forwards contract-valid telemetry as canonical protojson,
// one event per line, to any io.Writer (file, stdout, buffer). This is the
// v1 cross-language boundary: Go emits these bytes, any contract-speaking
// consumer (including the Rust core intake test) reads them. No RPC, no
// broker — a byte stream with a contract.
package pipeline

import (
	"context"
	"fmt"
	"io"
	"sync"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// LineSink is safe for sequential use from the Run loop (mutex-guarded
// for direct use).
type LineSink struct {
	mu    sync.Mutex
	w     io.Writer
	lines int64
	bytes int64
}

// NewLineSink returns a sink writing to w; nil writer is a construction error.
func NewLineSink(w io.Writer) (*LineSink, error) {
	if w == nil {
		return nil, fmt.Errorf("pipeline: LineSink writer is nil")
	}
	return &LineSink{w: w}, nil
}

// Emit serializes canonically and writes exactly one line.
func (s *LineSink) Emit(_ context.Context, e *v1.TelemetryEvent) error {
	data, err := contract.MarshalCanonical(e)
	if err != nil {
		return fmt.Errorf("pipeline: linesink marshal: %w", err)
	}
	data = append(data, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(data) > 0 {
		n, err := s.w.Write(data)
		if err != nil {
			return fmt.Errorf("pipeline: linesink write: %w", err)
		}
		if n <= 0 || n > len(data) {
			return fmt.Errorf("pipeline: linesink writer returned invalid count %d for %d bytes", n, len(data))
		}
		data = data[n:]
		s.bytes += int64(n)
	}
	s.lines++
	return nil
}

// Lines returns the number of events written.
func (s *LineSink) Lines() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lines
}

// Bytes returns the total bytes written, newlines included.
func (s *LineSink) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}
