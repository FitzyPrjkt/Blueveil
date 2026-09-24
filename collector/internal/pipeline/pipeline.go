// Package pipeline wires Source -> Normalizer -> Sink in one in-process
// pipeline: observe, normalize, emit. It decides nothing, detects nothing,
// responds to nothing.
//
// One reader goroutine feeds a bounded internal queue; the Run loop
// normalizes and emits. Rejected events are recorded in the report — never
// silently dropped. Cancellation drains the queue, then returns; the reader
// always exits, so shutdown leaves no goroutine behind.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/correlate"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/normalize"
	"blueveil/collector/internal/source"
)

// ErrSink aborts the run: the pipeline cannot deliver valid telemetry.
var ErrSink = errors.New("pipeline: sink failure")

// Config carries the only knob the skeleton needs: the internal queue size.
type Config struct {
	QueueSize int
}

// Validate rejects non-positive queue sizes; callers must set one explicitly.
func (c Config) Validate() error {
	if c.QueueSize <= 0 {
		return fmt.Errorf("pipeline: QueueSize must be > 0, got %d", c.QueueSize)
	}
	return nil
}

// Sink consumes contract-valid telemetry. Implementations must be safe for
// sequential use from the Run loop.
type Sink interface {
	Emit(ctx context.Context, e *v1.TelemetryEvent) error
}

// InMemorySink records emitted events for tests and self-test.
type InMemorySink struct {
	mu     sync.Mutex
	events []*v1.TelemetryEvent
	err    error
}

// Emit appends the event, or returns the injected error (test hook).
func (s *InMemorySink) Emit(_ context.Context, e *v1.TelemetryEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, e)
	return nil
}

// SetError makes subsequent Emit calls fail (test hook, e.g. errors.New).
func (s *InMemorySink) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Events returns a copy of everything emitted so far.
func (s *InMemorySink) Events() []*v1.TelemetryEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*v1.TelemetryEvent, len(s.events))
	copy(out, s.events)
	return out
}

// Rejection is one raw event the pipeline refused, with the reason attached.
type Rejection struct {
	Raw source.RawEvent
	Err error
}

// Metrics is the local observability of one Run: pipeline verification
// data, not production observability (no server, no exporter).
type Metrics struct {
	Received      int           // every event dequeued from the internal queue
	Accepted      int           // normalized (+enriched) and emitted
	Rejected      int           // refused at any stage, each recorded with cause
	NormalizeErrs int           // normalization-stage failures (incl. invalid source data)
	EnrichErrs    int           // enrichment-stage failures
	SinkErrs      int           // forwarding failures (abort the run)
	LatencyTotal  time.Duration // summed handle latency (normalize+enrich+emit)
	LatencyMax    time.Duration // slowest single handle
}

// AvgLatency is mean handle latency; zero when nothing was received.
func (m Metrics) AvgLatency() time.Duration {
	if m.Received == 0 {
		return 0
	}
	return m.LatencyTotal / time.Duration(m.Received)
}

// Report is the terminal accounting of a Run: every event the pipeline
// accepted is either Accepted (emitted) or Rejected (recorded with cause),
// plus malformed source lines that never entered the pipeline.
type Report struct {
	Accepted     int
	Rejected     []Rejection
	Metrics      Metrics
	SourceErrors []source.SourceError
}

// Pipeline is the wired collector. Construct with NewPipeline.
type Pipeline struct {
	cfg       Config
	src       source.Source
	norm      normalize.Normalizer
	sink      Sink
	enricher  *enrich.Enricher
	correlate bool
}

// NewPipeline validates the config and wires the stages.
func NewPipeline(cfg Config, src source.Source, sink Sink) (*Pipeline, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if src == nil || sink == nil {
		return nil, errors.New("pipeline: source and sink are required")
	}
	return &Pipeline{cfg: cfg, src: src, norm: normalize.New(), sink: sink}, nil
}

// WithEnricher enables the enrichment stage (nil by default = skipped,
// which keeps the raw normalize→emit path available for tests).
func (p *Pipeline) WithEnricher(e enrich.Enricher) *Pipeline {
	p.enricher = &e
	return p
}

// WithCorrelation enables correlation-id stamping (off by default).
func (p *Pipeline) WithCorrelation(on bool) *Pipeline {
	p.correlate = on
	return p
}

// Run consumes the source until it closes or ctx is cancelled, then returns
// the full accounting. Cancellation is normal shutdown: the queue is drained
// first, and the report (not the context error) is returned.
func (p *Pipeline) Run(ctx context.Context) (*Report, error) {
	if err := p.src.Start(ctx); err != nil {
		return nil, fmt.Errorf("pipeline: source start: %w", err)
	}
	defer func() { _ = p.src.Stop() }()

	queue := make(chan source.RawEvent, p.cfg.QueueSize)
	go func() {
		defer close(queue)
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-p.src.Events():
				if !ok {
					return
				}
				select {
				case <-ctx.Done():
					return
				case queue <- e:
				}
			}
		}
	}()

	report := &Report{}
	draining := false
	for {
		if draining {
			select {
			case e, ok := <-queue:
				if !ok {
					return p.finish(report), nil
				}
				if err := p.handle(ctx, e, report); err != nil {
					return p.finish(report), err
				}
			default:
				return p.finish(report), nil
			}
		}
		select {
		case <-ctx.Done():
			draining = true
		case e, ok := <-queue:
			if !ok {
				return p.finish(report), nil
			}
			if err := p.handle(ctx, e, report); err != nil {
				return p.finish(report), err
			}
		}
	}
}

// finish attaches malformed-source accounting before returning the report.
func (p *Pipeline) finish(report *Report) *Report {
	if lr, ok := p.src.(source.BadLineReporter); ok {
		report.SourceErrors = lr.BadLines()
	}
	return report
}

func (p *Pipeline) handle(ctx context.Context, raw source.RawEvent, report *Report) error {
	start := time.Now()
	accepted, err := p.process(ctx, raw, report)
	elapsed := time.Since(start)
	report.Metrics.Received++
	report.Metrics.LatencyTotal += elapsed
	if elapsed > report.Metrics.LatencyMax {
		report.Metrics.LatencyMax = elapsed
	}
	if err != nil {
		report.Metrics.SinkErrs++
		return err
	}
	if accepted {
		report.Metrics.Accepted++
	}
	return nil
}

func (p *Pipeline) process(ctx context.Context, raw source.RawEvent, report *Report) (bool, error) {
	event, err := p.norm.Normalize(raw)
	if err != nil {
		report.Metrics.Rejected++
		report.Metrics.NormalizeErrs++
		report.Rejected = append(report.Rejected, Rejection{Raw: raw, Err: err})
		return false, nil
	}
	if p.enricher != nil {
		if err := p.enricher.Enrich(event); err != nil {
			report.Metrics.Rejected++
			report.Metrics.EnrichErrs++
			report.Rejected = append(report.Rejected, Rejection{Raw: raw, Err: err})
			return false, nil
		}
	}
	if p.correlate {
		correlate.Apply(event)
	}
	if err := p.sink.Emit(ctx, event); err != nil {
		// Double %w (Go 1.20+): ErrSink marks delivery failure while the
		// sink's own wrapped chain (e.g. ErrDetection → rule cause) stays
		// matchable via errors.Is. No error information is stringified away.
		return false, fmt.Errorf("%w: %w", ErrSink, err)
	}
	report.Accepted++
	return true, nil
}
