// Incident stage for the telemetry pipeline: matching telemetry becomes
// detections and alerts (via the detection Engine), alerts become incidents
// (via the incident Manager, correlated by explicit correlation id with a
// 1-alert→1-incident baseline), and every alert yields provenance evidence.
//
// The original event still flows downstream untouched. Fail-closed like the
// detection stage: incident or evidence construction errors abort the run
// with explicit errors — never a silent "no incident".
package pipeline

import (
	"context"
	"errors"
	"fmt"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/incident"
)

var (
	// ErrIncident aborts the run when an alert cannot become an incident.
	ErrIncident = errors.New("pipeline: incident failure")
	// ErrEvidence aborts the run when evidence cannot be constructed.
	ErrEvidence = errors.New("pipeline: evidence failure")
)

// EventArchive resolves contributing telemetry by id. InMemorySink
// implements it; the stage never fabricates missing events.
type EventArchive interface {
	Events() []*v1.TelemetryEvent
}

// IncidentSink is the full Step-7 chain in one stage: detect → incident →
// evidence → forward. It supersedes DetectingSink where the incident layer
// is wanted; DetectingSink stays for detection-only wiring.
type IncidentSink struct {
	Engine     *detect.Engine
	Incidents  *incident.Manager
	Evidence   *evidence.Store
	Detections *detect.Store
	Archive    EventArchive
	Downstream Sink
}

// NewIncidentSink wires the stage; nil components are rejected.
func NewIncidentSink(engine *detect.Engine, manager *incident.Manager, evStore *evidence.Store, detStore *detect.Store, archive EventArchive, downstream Sink) (*IncidentSink, error) {
	if engine == nil || manager == nil || evStore == nil || detStore == nil || archive == nil || downstream == nil {
		return nil, fmt.Errorf("pipeline: incident sink needs engine, manager, stores, archive and downstream")
	}
	return &IncidentSink{
		Engine: engine, Incidents: manager, Evidence: evStore,
		Detections: detStore, Archive: archive, Downstream: downstream,
	}, nil
}

// Emit detects, folds alerts into incidents, captures evidence, then
// forwards the original event downstream. Forwarding is last: a failure
// in incident/evidence handling emits nothing downstream (fail-closed and
// atomic — mirroring DetectingSink's detect-then-forward order).
func (s *IncidentSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	res, err := s.Engine.Process(e)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDetection, err)
	}
	if len(res.Detections) != len(res.Alerts) {
		return fmt.Errorf("%w: detections/alerts length mismatch %d/%d",
			ErrDetection, len(res.Detections), len(res.Alerts))
	}
	for i := range res.Detections {
		s.Detections.Add(res.Detections[i], res.Alerts[i])
	}
	archive := map[string]*v1.TelemetryEvent{}
	for _, stored := range s.Archive.Events() {
		if _, dup := archive[stored.GetId()]; dup {
			return fmt.Errorf("%w: duplicate archived event id %q",
				ErrIncident, stored.GetId())
		}
		archive[stored.GetId()] = stored
	}
	// The event being emitted is itself archivable: contributing
	// detections routinely reference it. It joins the snapshot explicitly
	// (never via downstream side effects), so forwarding stays last.
	if _, dup := archive[e.GetId()]; dup {
		return fmt.Errorf("%w: duplicate event id %q",
			ErrIncident, e.GetId())
	}
	archive[e.GetId()] = e
	for i := range res.Detections {
		det, alert := res.Detections[i], res.Alerts[i]
		contributing := make([]*v1.TelemetryEvent, 0, len(det.GetTelemetryEventIds()))
		for _, id := range det.GetTelemetryEventIds() {
			ev, ok := archive[id]
			if !ok {
				return fmt.Errorf("%w: detection event %q not archived (refusing to fabricate)",
					ErrIncident, id)
			}
			contributing = append(contributing, ev)
		}
		inc, _, err := s.Incidents.Ingest(alert, det, contributing)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrIncident, err)
		}
		items, err := evidence.BuildForAlert(inc.GetId(), alert, det, contributing, inc.GetUpdatedAt().AsTime())
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEvidence, err)
		}
		for _, item := range items {
			s.Evidence.Add(item)
		}
	}
	if err := s.Downstream.Emit(ctx, e); err != nil {
		return fmt.Errorf("%w: %w", ErrSink, err)
	}
	return nil
}
