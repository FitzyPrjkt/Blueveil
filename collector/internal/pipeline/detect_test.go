// Detection-stage integration: telemetry → matching rule → detection →
// alert through the real pipeline, plus the negative path and fail-closed
// behavior on detection errors.
package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/source"
)

func detectEngine(t *testing.T) (*detect.Engine, *detect.Store) {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC) }
	eng, err := detect.NewEngine(clock)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	for _, r := range []detect.Rule{detect.BlockHighSeverityRule{}, detect.SourceCriticalRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatalf("register %s: %v", r.ID(), err)
		}
	}
	burst, err := detect.NewBlockBurstRule(3, 5*time.Minute, clock)
	if err != nil {
		t.Fatalf("burst: %v", err)
	}
	if err := eng.RegisterRule(burst); err != nil {
		t.Fatalf("register burst: %v", err)
	}
	return eng, &detect.Store{}
}

func detRaw(id, typ string, sev string, minute int) source.RawEvent {
	return source.RawEvent{
		ID: id, Source: "lab-waf", AssetID: "asset-web-01", EventType: typ,
		Severity: sev, OccurredAt: time.Date(2026, 9, 12, 9, minute, 0, 0, time.UTC),
	}
}

func TestTelemetryToDetectionToAlert(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(16)
	mem := &InMemorySink{}
	eng, store := detectEngine(t)
	stage, err := NewDetectingSink(eng, mem, store)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	pipe, err := NewPipeline(Config{QueueSize: 8}, src, stage)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	go func() {
		_ = src.Inject(ctx, detRaw("d-high", "waf.request_blocked", "SEVERITY_HIGH", 0)) // R1 fires
		_ = src.Inject(ctx, detRaw("d-low", "waf.request_allowed", "SEVERITY_INFO", 1))  // nothing
		_ = src.Inject(ctx, detRaw("b-1", "waf.request_blocked", "SEVERITY_LOW", 2))     // burst 1/3
		_ = src.Inject(ctx, detRaw("b-2", "waf.request_blocked", "SEVERITY_LOW", 3))     // burst 2/3
		_ = src.Inject(ctx, detRaw("b-3", "waf.request_blocked", "SEVERITY_MEDIUM", 4))  // burst 3/3 → R2 fires
		_ = src.Inject(ctx, source.RawEvent{ID: "bad"})                                  // rejected pre-detection
		_ = src.Stop()
	}()
	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Accepted != 5 || len(report.Rejected) != 1 {
		t.Fatalf("telemetry accounting: %+v", report)
	}
	dets, alerts := store.Counts()
	if dets != 2 || alerts != 2 {
		t.Fatalf("want 2 detections + 2 alerts, got %d + %d", dets, alerts)
	}
	byRule := map[string]int{}
	for _, d := range store.Detections() {
		if err := contract.ValidateDetection(d); err != nil {
			t.Fatalf("stored detection must validate: %v", err)
		}
		byRule[d.GetRuleId()]++
	}
	if byRule["waf-block-high-severity"] != 1 || byRule["waf-block-burst"] != 1 {
		t.Fatalf("rule attribution drift: %v", byRule)
	}
	for _, d := range store.Detections() {
		if len(d.GetTelemetryEventIds()) == 0 {
			t.Fatal("detection without events")
		}
	}
	for _, a := range store.Alerts() {
		if err := contract.ValidateAlert(a); err != nil {
			t.Fatalf("stored alert must validate: %v", err)
		}
	}
	// Alert linkage: every alert references exactly one stored detection.
	detIDs := map[string]bool{}
	for _, d := range store.Detections() {
		detIDs[d.GetId()] = true
	}
	for _, a := range store.Alerts() {
		if len(a.GetDetectionIds()) != 1 || !detIDs[a.GetDetectionIds()[0]] {
			t.Fatalf("alert linkage broken: %+v", a)
		}
	}
	// Burst detection references all three contributing events.
	for _, d := range store.Detections() {
		if d.GetRuleId() == "waf-block-burst" && len(d.GetTelemetryEventIds()) != 3 {
			t.Fatalf("burst must reference 3 events: %v", d.GetTelemetryEventIds())
		}
	}
}

func TestNoMatchYieldsNoDetectionNoAlert(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	eng, store := detectEngine(t)
	stage, err := NewDetectingSink(eng, &InMemorySink{}, store)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, stage)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	go func() {
		_ = src.Inject(ctx, detRaw("q-1", "waf.request_allowed", "SEVERITY_INFO", 0))
		_ = src.Inject(ctx, detRaw("q-2", "waf.request_blocked", "SEVERITY_LOW", 1))
		_ = src.Stop()
	}()
	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Accepted != 2 {
		t.Fatalf("telemetry must still flow: %+v", report)
	}
	if d, a := store.Counts(); d != 0 || a != 0 {
		t.Fatalf("negative path must stay empty: %d %d", d, a)
	}
}

func TestDetectionErrorAbortsRun(t *testing.T) {
	ctx := context.Background()
	src := source.NewChannelSource(8)
	eng, err := detect.NewEngine(time.Now)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	// A rule that always fails: the run must abort loudly, never pass the
	// event downstream as if it were clean.
	if err := eng.RegisterRule(failRule{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	down := &InMemorySink{}
	stage, err := NewDetectingSink(eng, down, &detect.Store{})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, stage)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	go func() {
		_ = src.Inject(ctx, detRaw("x-1", "waf.request_blocked", "SEVERITY_HIGH", 0))
		_ = src.Stop()
	}()
	_, err = pipe.Run(ctx)
	if !errors.Is(err, ErrDetection) || !errors.Is(err, ErrSink) {
		t.Fatalf("want ErrSink→ErrDetection→rule-cause chain, got %v", err)
	}
	if len(down.Events()) != 0 {
		t.Fatal("failed detection must not forward the event downstream")
	}
}

// failRule is a locally-defined always-failing rule proving fail-closed
// behavior (distinct from the same-named stub in detect's own tests).
type failRule struct{}

func (failRule) ID() string      { return "test-pipeline-fails" }
func (failRule) Version() string { return "1" }
func (failRule) Name() string    { return "test" }
func (failRule) Description() string {
	return "test double"
}
func (failRule) Evaluate(_ *v1.TelemetryEvent) (detect.Outcome, error) {
	return detect.Outcome{}, errors.New("boom")
}
