// Incident-stage integration: telemetry → detection → alert → incident →
// evidence through the real pipeline, plus negative and failure paths.
package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/incident"
	"blueveil/collector/internal/source"
)

var incidentClock = func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }

func incidentEngine(t *testing.T) *detect.Engine {
	t.Helper()
	eng, err := detect.NewEngine(incidentClock)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	for _, r := range []detect.Rule{detect.BlockHighSeverityRule{}, detect.SourceCriticalRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	burst, err := detect.NewBlockBurstRule(3, 5*time.Minute, incidentClock)
	if err != nil {
		t.Fatalf("burst: %v", err)
	}
	if err := eng.RegisterRule(burst); err != nil {
		t.Fatalf("register burst: %v", err)
	}
	return eng
}

func incRaw(id, asset, typ, sev string, minute int) source.RawEvent {
	return source.RawEvent{
		ID: id, Source: "lab", AssetID: asset, EventType: typ, Severity: sev,
		OccurredAt: time.Date(2026, 9, 12, 9, minute, 0, 0, time.UTC),
	}
}

func wireIncidentStage(t *testing.T, src source.Source, downstream Sink, archive *InMemorySink) (*Pipeline, *detect.Store, *incident.Manager, *evidence.Store) {
	t.Helper()
	mgr, err := incident.NewManager(incidentClock)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	en, err := enrich.New("incident-test", incidentClock)
	if err != nil {
		t.Fatalf("enricher: %v", err)
	}
	stage, err := NewIncidentSink(incidentEngine(t), mgr, evidence.NewStore(), &detect.Store{}, archive, downstream)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	pipe, err := NewPipeline(Config{QueueSize: 8}, src, stage)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	pipe.WithEnricher(en).WithCorrelation(true)
	return pipe, stage.Detections, mgr, stage.Evidence
}

func TestTelemetryToIncidentToEvidence(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(16)
	mem := &InMemorySink{}
	pipe, detStore, mgr, evStore := wireIncidentStage(t, src, mem, mem)
	go func() {
		_ = src.Inject(ctx, incRaw("e1", "asset-web-01", "waf.request_blocked", "SEVERITY_HIGH", 0))
		_ = src.Inject(ctx, incRaw("e2", "asset-web-01", "waf.request_blocked", "SEVERITY_LOW", 1))
		_ = src.Inject(ctx, incRaw("e3", "asset-web-01", "waf.request_blocked", "SEVERITY_LOW", 2))
		_ = src.Inject(ctx, incRaw("e4", "asset-web-02", "waf.request_blocked", "SEVERITY_HIGH", 3))
		_ = src.Inject(ctx, source.RawEvent{ID: "bad"})
		_ = src.Stop()
	}()
	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Accepted != 4 || len(report.Rejected) != 1 {
		t.Fatalf("telemetry accounting: %+v", report)
	}
	dets, alerts := detStore.Counts()
	if dets != 3 || alerts != 3 {
		t.Fatalf("want 3 detections + 3 alerts, got %d + %d", dets, alerts)
	}
	incidents := mgr.List()
	if len(incidents) != 2 {
		t.Fatalf("want 2 incidents (one per correlation group), got %d", len(incidents))
	}
	for _, inc := range incidents {
		if err := contract.ValidateIncident(inc); err != nil {
			t.Fatalf("stored incident must validate: %v", err)
		}
		if inc.GetStatus() != v1.IncidentStatus_INCIDENT_STATUS_OPEN {
			t.Fatalf("new incidents are OPEN: %v", inc.GetStatus())
		}
	}
	// Group assertions: asset-web-01 holds two alerts, asset-web-02 one.
	sizes := map[int]int{}
	for _, inc := range incidents {
		sizes[len(inc.GetAlertIds())]++
	}
	if sizes[2] != 1 || sizes[1] != 1 {
		t.Fatalf("alert grouping drift: %v", incidents)
	}
	if evStore.Count() != 10 {
		t.Fatalf("want 10 unique evidence items, got %d", evStore.Count())
	}
	for _, ev := range evStore.List() {
		if err := contract.ValidateEvidence(ev); err != nil {
			t.Fatalf("stored evidence must validate: %v", err)
		}
		if !evidence.Verify(ev) {
			t.Fatalf("stored evidence must verify: %s", ev.GetId())
		}
	}
	// Every evidence item belongs to a known incident.
	incIDs := map[string]bool{}
	for _, inc := range incidents {
		incIDs[inc.GetId()] = true
	}
	for _, ev := range evStore.List() {
		if !incIDs[ev.GetIncidentId()] {
			t.Fatalf("orphan evidence: %s", ev.GetId())
		}
	}
	// Lifecycle works on a pipeline-built incident.
	moved, err := mgr.Transition(incidents[0].GetId(), v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING)
	if err != nil || moved.GetStatus() != v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING {
		t.Fatalf("transition: %v %+v", err, moved)
	}
	if _, err := mgr.Transition(incidents[0].GetId(), v1.IncidentStatus_INCIDENT_STATUS_CLOSED); err == nil {
		t.Fatal("skipping lifecycle must fail")
	}
}

func TestIncidentNegativePathStaysEmpty(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	mem := &InMemorySink{}
	pipe, detStore, mgr, evStore := wireIncidentStage(t, src, mem, mem)
	go func() {
		_ = src.Inject(ctx, incRaw("q-1", "a", "waf.request_allowed", "SEVERITY_INFO", 0))
		_ = src.Stop()
	}()
	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Accepted != 1 {
		t.Fatalf("telemetry must flow: %+v", report)
	}
	if d, a := detStore.Counts(); d != 0 || a != 0 {
		t.Fatal("no detections expected")
	}
	if len(mgr.List()) != 0 || evStore.Count() != 0 {
		t.Fatal("no incidents or evidence expected")
	}
}

func TestIncidentStageFailsOnMissingArchive(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	// Archive is a DIFFERENT, empty sink: burst history cannot be
	// resolved, so the stage must abort rather than fabricate. (The event
	// being emitted joins the snapshot explicitly, so only genuinely
	// missing history aborts.)
	down := &InMemorySink{}
	emptyArchive := &InMemorySink{}
	pipe, _, _, _ := wireIncidentStage(t, src, down, emptyArchive)
	go func() {
		_ = src.Inject(ctx, incRaw("e1", "a1", "waf.request_blocked", "SEVERITY_HIGH", 0))
		_ = src.Inject(ctx, incRaw("e2", "a1", "waf.request_blocked", "SEVERITY_HIGH", 1))
		_ = src.Inject(ctx, incRaw("e3", "a1", "waf.request_blocked", "SEVERITY_HIGH", 2))
		_ = src.Stop()
	}()
	_, err := pipe.Run(ctx)
	if !errors.Is(err, ErrIncident) {
		t.Fatalf("want ErrIncident abort, got %v", err)
	}
}
