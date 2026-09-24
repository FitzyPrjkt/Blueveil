package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

func seedBackend(t *testing.T) store.Backend {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	ts := timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC))
	if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
		Id: "evt-1", Source: "lab", AssetId: "asset-1", EventType: "waf.request_blocked",
		Severity: v1.Severity_SEVERITY_HIGH, OccurredAt: ts,
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Detection.Append(ctx, &v1.Detection{
		Id: "det-1", RuleId: "rule-1", RuleName: "Rule One",
		TelemetryEventIds: []string{"evt-1"}, DetectedAt: ts,
		Severity: v1.Severity_SEVERITY_HIGH, Title: "T",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Alert.Append(ctx, &v1.Alert{
		Id: "alert-1", DetectionIds: []string{"det-1"},
		Status: v1.AlertStatus_ALERT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_HIGH,
		CreatedAt: ts, UpdatedAt: ts, Title: "Alert: T",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Incident.Create(ctx, &v1.Incident{
		Id: "inc-1", AlertIds: []string{"alert-1"},
		Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_HIGH,
		CreatedAt: ts, UpdatedAt: ts, Title: "Incident", Summary: "1 alert(s)",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Evidence.Append(ctx, &v1.Evidence{
		Id: "ev-1", IncidentId: "inc-1", Type: v1.EvidenceType_EVIDENCE_TYPE_NOTE,
		CollectedAt: ts, Source: "lab", MediaType: "application/json",
		Sha256:  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Content: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Validation.AppendRequest(ctx, &v1.ValidationRequest{
		Id: "vreq-1", ControlId: "CTRL", Target: "asset-1", RequestedAt: ts,
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Validation.AppendResult(ctx, &v1.ValidationResult{
		Id: "vres-1", RequestId: "vreq-1", ControlId: "CTRL", Provider: "p",
		ContractVersion: "blueveil.contracts.v1",
		Verdict:         v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED,
		ValidatedAt:     ts,
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Response.Create(ctx, &v1.ResponseRecommendation{
		Id: "rec-1", IncidentId: "inc-1", Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-1", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Reason: "review",
		Status: v1.ResponseStatus_RESPONSE_STATUS_PROPOSED, RecommendedAt: ts,
		RecommendedBy: "blueveil-recommender/1", ApprovalRequired: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.ResponseRecords.AppendApproval(ctx, &v1.ResponseApproval{
		Id: "appr-1", RecommendationId: "rec-1", Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-1", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Approver: "test-actor:x",
		ApprovedAt: ts, Reason: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.ResponseRecords.AppendExecution(ctx, &v1.ResponseExecution{
		Id: "exec-1", RecommendationId: "rec-1", Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-1", StartedAt: ts, FinishedAt: ts, Success: true, Detail: "simulated",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.ResponseRecords.AppendVerification(ctx, &v1.ResponseVerification{
		Id: "verif-1", ExecutionId: "exec-1", Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED,
		VerifiedAt: ts, Detail: "confirmed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Audit.Append(ctx, store.AuditEntry{
		ID: "audit-0001", DecidedAt: ts.AsTime(), Actor: "test-actor:x",
		Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND, Risk: v1.RiskLevel_RISK_LEVEL_HIGH,
		Decision: "recommended", Reason: "r", Result: "rec-1", ResponseID: "rec-1", Phase: "RECOMMEND",
	}); err != nil {
		t.Fatal(err)
	}
	return be
}

func get(t *testing.T, srv *Server, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s: invalid JSON: %v", path, err)
	}
	return rec.Code, body
}

func TestHealth(t *testing.T) {
	srv := NewServer(store.NewMemoryBackend())
	code, body := get(t, srv, "/api/v1/healthz")
	if code != 200 || body["data"].(map[string]any)["status"] != "ok" {
		t.Fatalf("health: %d %+v", code, body)
	}
}

func TestListsServeCanonicalJSON(t *testing.T) {
	srv := NewServer(seedBackend(t))
	for path, wantID := range map[string]string{
		"/api/v1/telemetry":          "evt-1",
		"/api/v1/detections":         "det-1",
		"/api/v1/alerts":             "alert-1",
		"/api/v1/incidents":          "inc-1",
		"/api/v1/evidence":           "ev-1",
		"/api/v1/recommendations":    "rec-1",
		"/api/v1/approvals":          "appr-1",
		"/api/v1/executions":         "exec-1",
		"/api/v1/verifications":      "verif-1",
		"/api/v1/validation-results": "vres-1",
		"/api/v1/audit":              "audit-0001",
	} {
		code, body := get(t, srv, path)
		if code != 200 {
			t.Fatalf("GET %s: %d %+v", path, code, body)
		}
		data, ok := body["data"].([]any)
		if !ok || len(data) != 1 {
			t.Fatalf("GET %s: want 1 item, got %+v", path, body)
		}
		raw, _ := json.Marshal(data[0])
		if !strings.Contains(string(raw), wantID) {
			t.Fatalf("GET %s: missing %s in %s", path, wantID, raw)
		}
	}
}

func TestEnumNamesVerbatim(t *testing.T) {
	srv := NewServer(seedBackend(t))
	_, body := get(t, srv, "/api/v1/validation-results/vres-1")
	raw, _ := json.Marshal(body["data"])
	if !strings.Contains(string(raw), "VALIDATION_VERDICT_NOT_TESTED") {
		t.Fatalf("verdict must be verbatim enum name: %s", raw)
	}
	if strings.Contains(string(raw), "SECURE") {
		t.Fatalf("no SECURE may appear: %s", raw)
	}
}

func TestEvidenceIntegrityEnvelope(t *testing.T) {
	srv := NewServer(seedBackend(t))
	code, body := get(t, srv, "/api/v1/evidence/ev-1")
	if code != 200 || body["integrity"] != "verified" {
		t.Fatalf("evidence envelope: %d %+v", code, body)
	}
	code, body = get(t, srv, "/api/v1/evidence?incident=inc-1")
	if code != 200 {
		t.Fatalf("by-incident: %d %+v", code, body)
	}
	if body["integrity"] != "verified" || len(body["data"].([]any)) != 1 {
		t.Fatalf("by-incident envelope: %+v", body)
	}
	code, body = get(t, srv, "/api/v1/evidence?incident=ghost")
	if code != 404 || body["error"].(map[string]any)["code"] != "NOT_FOUND" {
		t.Fatalf("unknown incident must 404, not empty: %d %+v", code, body)
	}
}

func TestNotFoundAndMethodGuards(t *testing.T) {
	srv := NewServer(seedBackend(t))
	code, body := get(t, srv, "/api/v1/alerts/ghost")
	if code != 404 || body["error"].(map[string]any)["code"] != "NOT_FOUND" {
		t.Fatalf("missing must 404: %d %+v", code, body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Fatalf("POST must 405, got %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/alerts/alert-1", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Fatalf("DELETE must 405, got %d", rec.Code)
	}
}

func TestEmptyDatabaseListsEmpty(t *testing.T) {
	srv := NewServer(store.NewMemoryBackend())
	code, body := get(t, srv, "/api/v1/incidents")
	if code != 200 {
		t.Fatalf("empty must 200: %d %+v", code, body)
	}
	if data, ok := body["data"].([]any); !ok || len(data) != 0 {
		t.Fatalf("empty must be [], got %+v", body)
	}
}
