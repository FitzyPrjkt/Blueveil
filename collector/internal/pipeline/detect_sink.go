// Detection stage for the telemetry pipeline: matching telemetry flows
// through a detection Engine, new detections/alerts land in a Store, and the
// original event continues downstream untouched.
//
// Fail-closed: a detection error aborts emission with ErrDetection. A rule
// failure must never look like clean telemetry passing through.
package pipeline

import (
	"context"
	"errors"
	"fmt"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
)

// ErrDetection aborts the run when the detection stage fails.
var ErrDetection = errors.New("pipeline: detection failure")

// DetectingSink decorates a downstream Sink with detection.
type DetectingSink struct {
	Engine     *detect.Engine
	Downstream Sink
	Store      *detect.Store
}

// NewDetectingSink wires the stage; nil components are rejected.
func NewDetectingSink(engine *detect.Engine, downstream Sink, store *detect.Store) (*DetectingSink, error) {
	if engine == nil || downstream == nil || store == nil {
		return nil, fmt.Errorf("pipeline: detecting sink needs engine, downstream and store")
	}
	return &DetectingSink{Engine: engine, Downstream: downstream, Store: store}, nil
}

// Emit detects, stores new output, then forwards the original event.
func (s *DetectingSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	res, err := s.Engine.Process(e)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDetection, err)
	}
	if len(res.Detections) != len(res.Alerts) {
		return fmt.Errorf("%w: detections/alerts length mismatch %d/%d",
			ErrDetection, len(res.Detections), len(res.Alerts))
	}
	for i := range res.Detections {
		s.Store.Add(res.Detections[i], res.Alerts[i])
	}
	return s.Downstream.Emit(ctx, e)
}
