// Validation integration: IncidentSink outputs driven through the gated
// validation path (native provider), plus the honest-failure path when
// telemetry names no control. Pipeline stops at evidence; validation runs
// explicit API calls through the response engine — never automatic.
package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/incident"
	"blueveil/collector/internal/response"
	"blueveil/collector/internal/source"
	"blueveil/collector/internal/validation"
)

func valRaw(id, asset string, attrs map[string]string, minute int) source.RawEvent {
	return source.RawEvent{
		ID: id, Source: "lab", AssetID: asset, EventType: "waf.request_blocked",
		Severity: "SEVERITY_HIGH", Attributes: attrs,
		OccurredAt: time.Date(2026, 9, 12, 9, minute, 0, 0, time.UTC),
	}
}

func runValidationPipeline(t *testing.T, inputs []source.RawEvent) (*incident.Manager, *detect.Store, *evidence.Store, *InMemorySink) {
	t.Helper()
	ctx := context.Background()
	src := source.NewChannelSource(16)
	mem := &InMemorySink{}
	mgr, err := incident.NewManager(incidentClock)
	if err != nil {
		t.Fatal(err)
	}
	en, err := enrich.New("validation-test", incidentClock)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := detect.NewEngine(incidentClock)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []detect.Rule{detect.BlockHighSeverityRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := NewIncidentSink(eng, mgr, evidence.NewStore(), &detect.Store{}, mem, mem)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := NewPipeline(Config{QueueSize: 8}, src, stage)
	if err != nil {
		t.Fatal(err)
	}
	pipe.WithEnricher(en).WithCorrelation(true)
	go func() {
		for _, in := range inputs {
			_ = src.Inject(ctx, in)
		}
		_ = src.Stop()
	}()
	if _, err := pipe.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	return mgr, stage.Detections, stage.Evidence, mem
}

func firstTriple(t *testing.T, mgr *incident.Manager, dets *detect.Store, mem *InMemorySink) (*v1.Incident, *v1.Alert, *v1.Detection, []*v1.TelemetryEvent) {
	t.Helper()
	list := mgr.List()
	if len(list) == 0 {
		t.Fatal("no incidents to validate")
	}
	inc := list[0]
	alertByID := map[string]*v1.Alert{}
	for _, a := range dets.Alerts() {
		alertByID[a.GetId()] = a
	}
	detByID := map[string]*v1.Detection{}
	for _, d := range dets.Detections() {
		detByID[d.GetId()] = d
	}
	eventByID := map[string]*v1.TelemetryEvent{}
	for _, e := range mem.Events() {
		eventByID[e.GetId()] = e
	}
	alert := alertByID[inc.GetAlertIds()[0]]
	det := detByID[alert.GetDetectionIds()[0]]
	var events []*v1.TelemetryEvent
	for _, id := range det.GetTelemetryEventIds() {
		events = append(events, eventByID[id])
	}
	return inc, alert, det, events
}

func TestPipelineOutputsValidateThroughGate(t *testing.T) {
	attrs := map[string]string{"rule_id": "CTRL-LAB-01"}
	mgr, dets, evStore, mem := runValidationPipeline(t, []source.RawEvent{
		valRaw("e1", "asset-web-01", attrs, 0),
	})
	inc, alert, det, events := firstTriple(t, mgr, dets, mem)

	native, err := validation.NewScriptedProvider("1", incidentClock,
		v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	if err != nil {
		t.Fatal(err)
	}
	vex, err := validation.NewValidationExecutor(native, inc, alert, det, events, evStore, incidentClock)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	audit := &response.InMemoryAuditLog{}
	eng, err := response.NewEngine(response.DefaultPolicy{}, vex,
		response.StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "lab confirms"},
		audit, incidentClock)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatalf("recommend: %v", err)
	}
	if _, err := eng.Decide(rec.GetId(), "analyst:pipeline-validation"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:pipeline-lead", "proportional", time.Hour); err != nil {
		t.Fatalf("approve: %v", err)
	}
	executed, err := eng.Execute(rec.GetId())
	if err != nil || !executed.GetSuccess() {
		t.Fatalf("execute: %+v %v", executed, err)
	}
	if _, err := eng.Verify(rec.GetId()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	final, _ := eng.Get(rec.GetId())
	if final.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_VERIFIED {
		t.Fatalf("terminal: %v", final.GetStatus())
	}

	// The validation NOTE is stored, verified, and carries provider + verdict.
	found := false
	for _, ev := range evStore.List() {
		if ev.GetSource() != validation.NativeProviderID {
			continue
		}
		found = true
		if err := contract.ValidateEvidence(ev); err != nil || !evidence.Verify(ev) {
			t.Fatalf("validation evidence must validate and verify: %v", err)
		}
		for _, want := range []string{"CTRL-LAB-01", "VALIDATION_VERDICT_DETECTED", validation.NativeProviderID} {
			if !strings.Contains(ev.GetContent(), want) {
				t.Fatalf("evidence must carry %q: %s", want, ev.GetContent())
			}
		}
	}
	if !found {
		t.Fatal("validation evidence missing from store")
	}
	// Audit shows the gated validation run end to end.
	if len(audit.Entries()) != 5 {
		t.Fatalf("want 5 audit entries, got %d", len(audit.Entries()))
	}
}

func TestValidationWithoutNamedControlFailsHonestly(t *testing.T) {
	// Telemetry names no control: the request cannot be built, so execution
	// fails explicitly and the failure is audited — never a verdict.
	mgr, dets, evStore, mem := runValidationPipeline(t, []source.RawEvent{
		valRaw("e1", "asset-web-01", map[string]string{}, 0),
	})
	inc, alert, det, events := firstTriple(t, mgr, dets, mem)

	native, _ := validation.NewScriptedProvider("1", incidentClock,
		v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	vex, err := validation.NewValidationExecutor(native, inc, alert, det, events, evStore, incidentClock)
	if err != nil {
		t.Fatalf("bind needs no control: %v", err)
	}
	audit := &response.InMemoryAuditLog{}
	eng, err := response.NewEngine(response.StaticAllowAll(), vex,
		response.UnknownVerifier{}, audit, incidentClock)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		t.Fatal(err)
	}
	// LOW gate allows directly... HIGH parks; either way approve first when needed.
	if _, err := eng.Decide(rec.GetId(), "analyst:test"); err != nil {
		t.Fatal(err)
	}
	got, _ := eng.Get(rec.GetId())
	if got.GetStatus() == v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL {
		if _, err := eng.Approve(rec.GetId(), "test-actor:lead", "ok", 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := eng.Execute(rec.GetId()); err == nil {
		t.Fatal("execution without an honest request must fail")
	}
	entries := audit.Entries()
	if entries[len(entries)-1].Decision != response.AuditExecutorError {
		t.Fatalf("failure must be audited as executor-error: %+v", entries)
	}
}
