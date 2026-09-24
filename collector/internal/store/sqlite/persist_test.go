// Pipeline persistence: a real run persists, survives restart, and reads
// back with IDs and relationships intact — telemetry → detection → alert →
// incident → evidence via PersistRun, plus linked response/validation/audit
// records by id. Poisoned input persists nothing.
package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/incident"
	"blueveil/collector/internal/pipeline"
	"blueveil/collector/internal/source"
	"blueveil/collector/internal/store"
)

var persistClock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func persistRaw(id, sev string, minute int) source.RawEvent {
	return source.RawEvent{
		ID: id, Source: "lab", AssetID: "asset-web-01", EventType: "waf.request_blocked",
		Severity: sev, Attributes: map[string]string{"rule_id": "CTRL-LAB-01"},
		OccurredAt: time.Date(2026, 9, 12, 9, minute, 0, 0, time.UTC),
	}
}

func persistStamp() *timestamppb.Timestamp {
	return timestamppb.New(persistClock)
}

func storetestRecommendation(incID string) *v1.ResponseRecommendation {
	return &v1.ResponseRecommendation{
		Id: "rec-1", IncidentId: incID, Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-web-01", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Reason: "review",
		Status: v1.ResponseStatus_RESPONSE_STATUS_EXECUTED, RecommendedAt: persistStamp(),
		RecommendedBy: "blueveil-recommender/1", ApprovalRequired: true,
	}
}

func storetestApproval(id, recID string) *v1.ResponseApproval {
	return &v1.ResponseApproval{
		Id: id, RecommendationId: recID, Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-web-01", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Approver: "test-actor:x",
		ApprovedAt: persistStamp(), Reason: "ok",
	}
}

func storetestExecution(id, recID string) *v1.ResponseExecution {
	return &v1.ResponseExecution{
		Id: id, RecommendationId: recID, Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-web-01", StartedAt: persistStamp(), FinishedAt: persistStamp(),
		Success: true, Detail: "simulated",
	}
}

func storetestVerification(id, execID string) *v1.ResponseVerification {
	return &v1.ResponseVerification{
		Id: id, ExecutionId: execID, Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED,
		VerifiedAt: persistStamp(), Detail: "confirmed",
	}
}

func storetestValRequest(id string) *v1.ValidationRequest {
	return &v1.ValidationRequest{
		Id: id, ControlId: "CTRL-LAB-01", Target: "asset-web-01", RequestedAt: persistStamp(),
	}
}

func storetestValResult(id, reqID string) *v1.ValidationResult {
	return &v1.ValidationResult{
		Id: id, RequestId: reqID, ControlId: "CTRL-LAB-01", Provider: "p",
		ContractVersion: "blueveil.contracts.v1",
		Verdict:         v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		ValidatedAt:     persistStamp(),
	}
}

func runPersistPipeline(t *testing.T) (*pipeline.InMemorySink, *detect.Store, *incident.Manager, *evidence.Store) {
	t.Helper()
	ctx := context.Background()
	src := source.NewChannelSource(8)
	mem := &pipeline.InMemorySink{}
	mgr, err := incident.NewManager(func() time.Time { return persistClock })
	if err != nil {
		t.Fatal(err)
	}
	en, err := enrich.New("persist-test", func() time.Time { return persistClock })
	if err != nil {
		t.Fatal(err)
	}
	eng, err := detect.NewEngine(func() time.Time { return persistClock })
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RegisterRule(detect.BlockHighSeverityRule{}); err != nil {
		t.Fatal(err)
	}
	burst, err := detect.NewBlockBurstRule(3, 5*time.Minute, func() time.Time { return persistClock })
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RegisterRule(burst); err != nil {
		t.Fatal(err)
	}
	detStore := &detect.Store{}
	evStore := evidence.NewStore()
	stage, err := pipeline.NewIncidentSink(eng, mgr, evStore, detStore, mem, mem)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := pipeline.NewPipeline(pipeline.Config{QueueSize: 8}, src, stage)
	if err != nil {
		t.Fatal(err)
	}
	pipe.WithEnricher(en).WithCorrelation(true)
	go func() {
		_ = src.Inject(ctx, persistRaw("e1", "SEVERITY_HIGH", 0))
		_ = src.Inject(ctx, persistRaw("e2", "SEVERITY_LOW", 1))
		_ = src.Inject(ctx, persistRaw("e3", "SEVERITY_LOW", 2))
		_ = src.Stop()
	}()
	if _, err := pipe.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	return mem, detStore, mgr, evStore
}

func TestPipelinePersistRestartReadBack(t *testing.T) {
	ctx := context.Background()
	mem, detStore, mgr, evStore := runPersistPipeline(t)

	// Gather the durable subset.
	var out PipelineOutputs
	out.Telemetry = mem.Events()
	for _, d := range detStore.Detections() {
		out.Detections = append(out.Detections, d)
	}
	for _, a := range detStore.Alerts() {
		out.Alerts = append(out.Alerts, a)
	}
	out.Incidents = mgr.List()
	out.Evidence = evStore.List()
	if len(out.Telemetry) != 3 || len(out.Detections) != 2 || len(out.Alerts) != 2 ||
		len(out.Incidents) != 1 || len(out.Evidence) != 7 {
		t.Fatalf("pipeline output drift: %d %d %d %d %d",
			len(out.Telemetry), len(out.Detections), len(out.Alerts), len(out.Incidents), len(out.Evidence))
	}

	path := filepath.Join(t.TempDir(), "persist.db")
	db, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	be := db.Backend()
	if err := PersistRunTx(ctx, db, out); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Linked response/validation/audit records by id (engine-owned flows
	// persist through their own repository calls, same transaction-free
	// per-operation atomicity).
	inc := out.Incidents[0]
	rec := storetestRecommendation(inc.GetId())
	if err := be.Response.Create(ctx, rec); err != nil {
		t.Fatalf("persist recommendation: %v", err)
	}
	appr := storetestApproval("appr-1", rec.GetId())
	if err := be.ResponseRecords.AppendApproval(ctx, appr); err != nil {
		t.Fatal(err)
	}
	exec := storetestExecution("exec-1", rec.GetId())
	if err := be.ResponseRecords.AppendExecution(ctx, exec); err != nil {
		t.Fatal(err)
	}
	verif := storetestVerification("verif-1", exec.GetId())
	if err := be.ResponseRecords.AppendVerification(ctx, verif); err != nil {
		t.Fatal(err)
	}
	if err := be.Validation.AppendRequest(ctx, storetestValRequest("vreq-1")); err != nil {
		t.Fatal(err)
	}
	if err := be.Validation.AppendResult(ctx, storetestValResult("vres-1", "vreq-1")); err != nil {
		t.Fatal(err)
	}
	auditIn := store.AuditEntry{
		ID: "audit-0001", DecidedAt: persistClock, Actor: "test-actor:x",
		Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND, Risk: v1.RiskLevel_RISK_LEVEL_HIGH,
		Decision: "executed", Reason: "r", Result: "exec-1", ResponseID: rec.GetId(), Phase: "VERIFY",
	}
	if err := be.Audit.Append(ctx, auditIn); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Restart and read everything back.
	db2, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	be2 := db2.Backend()

	telemetry, err := be2.Telemetry.List(ctx)
	if err != nil || len(telemetry) != 3 {
		t.Fatalf("telemetry: %+v %v", telemetry, err)
	}
	for _, e := range out.Telemetry {
		got, err := be2.Telemetry.Get(ctx, e.GetId())
		if err != nil || !proto.Equal(got, e) {
			t.Fatalf("telemetry %q drift: %+v %v", e.GetId(), got, err)
		}
	}
	dets, err := be2.Detection.List(ctx)
	if err != nil || len(dets) != 2 {
		t.Fatalf("detections: %v %v", dets, err)
	}
	detIDs := map[string]bool{}
	for _, d := range dets {
		detIDs[d.GetId()] = true
	}
	alerts, err := be2.Alert.List(ctx)
	if err != nil || len(alerts) != 2 {
		t.Fatalf("alerts: %v %v", alerts, err)
	}
	for _, a := range alerts {
		for _, id := range a.GetDetectionIds() {
			if !detIDs[id] {
				t.Fatalf("alert %q references missing detection %q", a.GetId(), id)
			}
		}
	}
	incidents, err := be2.Incident.List(ctx)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incidents: %v %v", incidents, err)
	}
	if !proto.Equal(incidents[0], inc) {
		t.Fatalf("incident drift:\n%v\n%v", incidents[0], inc)
	}
	byInc, err := be2.Evidence.ListByIncident(ctx, inc.GetId())
	if err != nil || len(byInc) != 7 {
		t.Fatalf("evidence by incident: %d %v", len(byInc), err)
	}
	for _, e := range byInc {
		if !evidence.Verify(e) {
			t.Fatalf("evidence %q fails verify after restart", e.GetId())
		}
	}
	gotRec, err := be2.Response.Get(ctx, rec.GetId())
	if err != nil || !proto.Equal(gotRec, rec) {
		t.Fatalf("recommendation drift: %+v %v", gotRec, err)
	}
	if _, err := be2.ResponseRecords.GetApproval(ctx, appr.GetId()); err != nil {
		t.Fatalf("approval: %v", err)
	}
	if _, err := be2.ResponseRecords.GetExecution(ctx, exec.GetId()); err != nil {
		t.Fatalf("execution: %v", err)
	}
	if _, err := be2.ResponseRecords.GetVerification(ctx, verif.GetId()); err != nil {
		t.Fatalf("verification: %v", err)
	}
	if _, err := be2.Validation.GetResult(ctx, "vres-1"); err != nil {
		t.Fatalf("validation result: %v", err)
	}
	auditOut, err := be2.Audit.List(ctx)
	if err != nil || len(auditOut) != 1 || auditOut[0].ID != "audit-0001" {
		t.Fatalf("audit: %+v %v", auditOut, err)
	}
	// Every stored object still validates: durability never launders data.
	for _, e := range byInc {
		if err := contract.ValidateEvidence(e); err != nil {
			t.Fatalf("stored evidence invalid after restart: %v", err)
		}
	}
}

func TestPersistRunRejectsPoisonedInput(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	bad := &v1.TelemetryEvent{Id: "poison"} // contract-invalid
	err := PersistRun(ctx, be, PipelineOutputs{Telemetry: []*v1.TelemetryEvent{bad}})
	if err == nil {
		t.Fatal("poisoned archive must abort persistence")
	}
	list, err := be.Telemetry.List(ctx)
	if err != nil || len(list) != 0 {
		t.Fatalf("nothing may persist on validation failure: %+v %v", list, err)
	}
}
