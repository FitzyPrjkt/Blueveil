// Package storetest pins the behavioral contract every store backend must
// satisfy: memory today, SQLite today, PostgreSQL tomorrow. Backends wire
// one function — open a backend, run the suite, close — and inherit the
// whole matrix: create/get/list, duplicates, missing reads, invalid input,
// lifecycle updates, append-only enforcement, corruption detection.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/store"
)

var clock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func stamp() *timestamppb.Timestamp { return timestamppb.New(clock) }

func telemetry(id string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, Source: "lab", AssetId: "asset-1", EventType: "waf.request_blocked",
		Severity: v1.Severity_SEVERITY_HIGH, OccurredAt: stamp(),
	}
}

func detection(id string, events ...string) *v1.Detection {
	return &v1.Detection{
		Id: id, RuleId: "rule-1", RuleName: "Rule One", TelemetryEventIds: events,
		DetectedAt: stamp(), Severity: v1.Severity_SEVERITY_HIGH, Title: "T",
	}
}

func alert(id, detID string) *v1.Alert {
	return &v1.Alert{
		Id: id, DetectionIds: []string{detID}, Status: v1.AlertStatus_ALERT_STATUS_OPEN,
		Severity: v1.Severity_SEVERITY_HIGH, CreatedAt: stamp(), UpdatedAt: stamp(),
		Title: "Alert: T",
	}
}

func incident(id, alertID string) *v1.Incident {
	return &v1.Incident{
		Id: id, AlertIds: []string{alertID}, Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN,
		Severity: v1.Severity_SEVERITY_HIGH, CreatedAt: stamp(), UpdatedAt: stamp(),
		Title: "Incident", Summary: "1 alert(s)",
	}
}

func evItem(id, incID string) *v1.Evidence {
	return &v1.Evidence{
		Id: id, IncidentId: incID, Type: v1.EvidenceType_EVIDENCE_TYPE_NOTE,
		CollectedAt: stamp(), Source: "lab", MediaType: "application/json",
		Sha256:  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Content: "test",
	}
}

func recommendation(id, incID string, status v1.ResponseStatus) *v1.ResponseRecommendation {
	return &v1.ResponseRecommendation{
		Id: id, IncidentId: incID, Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-1", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Reason: "review",
		Status: status, RecommendedAt: stamp(), RecommendedBy: "blueveil-recommender/1",
		ApprovalRequired: true,
	}
}

func approval(id, recID string) *v1.ResponseApproval {
	return &v1.ResponseApproval{
		Id: id, RecommendationId: recID, Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-1", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Approver: "test-actor:x",
		ApprovedAt: stamp(), Reason: "ok",
	}
}

func execution(id, recID string) *v1.ResponseExecution {
	return &v1.ResponseExecution{
		Id: id, RecommendationId: recID, Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-1", StartedAt: stamp(), FinishedAt: stamp(),
		Success: true, Detail: "simulated",
	}
}

func verification(id, execID string) *v1.ResponseVerification {
	return &v1.ResponseVerification{
		Id: id, ExecutionId: execID, Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_UNKNOWN,
		VerifiedAt: stamp(), Detail: "no source",
	}
}

func valRequest(id string) *v1.ValidationRequest {
	return &v1.ValidationRequest{
		Id: id, ControlId: "CTRL", Target: "asset-1", RequestedAt: stamp(),
	}
}

func valResult(id, reqID string) *v1.ValidationResult {
	return &v1.ValidationResult{
		Id: id, RequestId: reqID, ControlId: "CTRL", Provider: "p",
		ContractVersion: "blueveil.contracts.v1",
		Verdict:         v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		ValidatedAt:     stamp(),
	}
}

func auditEntry(id string) store.AuditEntry {
	return store.AuditEntry{
		ID: id, DecidedAt: clock, Actor: "test-actor:x",
		Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND, Risk: v1.RiskLevel_RISK_LEVEL_HIGH,
		Decision: "recommended", Reason: "r", Result: "rec-1",
		ResponseID: "rec-1", Phase: "RECOMMEND",
	}
}

// Run exercises a backend through the full behavioral matrix. Open is the
// backend under test; cleanup releases it (close/remove temp files).
func Run(t *testing.T, backend store.Backend) {
	t.Helper()
	ctx := context.Background()
	t.Run("telemetry", func(t *testing.T) {
		if err := backend.Telemetry.Append(ctx, telemetry("e1")); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := backend.Telemetry.Append(ctx, telemetry("e1")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate must fail explicitly, got %v", err)
		}
		if _, err := backend.Telemetry.Get(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing must be ErrNotFound, got %v", err)
		}
		if err := backend.Telemetry.Append(ctx, &v1.TelemetryEvent{}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("invalid must never persist, got %v", err)
		}
		got, err := backend.Telemetry.Get(ctx, "e1")
		if err != nil || !proto.Equal(got, telemetry("e1")) {
			t.Fatalf("round-trip drift: %+v %v", got, err)
		}
		if err := backend.Telemetry.Append(ctx, telemetry("e0")); err != nil {
			t.Fatal(err)
		}
		list, err := backend.Telemetry.List(ctx)
		if err != nil || len(list) != 2 || list[0].GetId() != "e0" || list[1].GetId() != "e1" {
			t.Fatalf("listing must be stable id order: %+v %v", list, err)
		}
	})
	t.Run("detection", func(t *testing.T) {
		if err := backend.Detection.Append(ctx, detection("d1", "e1")); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := backend.Detection.Append(ctx, detection("d1", "e1")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate: %v", err)
		}
		if err := backend.Detection.Append(ctx, &v1.Detection{}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("invalid: %v", err)
		}
		got, err := backend.Detection.Get(ctx, "d1")
		if err != nil || !proto.Equal(got, detection("d1", "e1")) {
			t.Fatalf("round-trip drift: %+v %v", got, err)
		}
	})
	t.Run("alert", func(t *testing.T) {
		if err := backend.Alert.Append(ctx, alert("a1", "d1")); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := backend.Alert.Append(ctx, alert("a1", "d1")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate: %v", err)
		}
		if _, err := backend.Alert.Get(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		got, err := backend.Alert.Get(ctx, "a1")
		if err != nil || !proto.Equal(got, alert("a1", "d1")) {
			t.Fatalf("round-trip drift: %+v %v", got, err)
		}
	})
	t.Run("incident-lifecycle", func(t *testing.T) {
		if err := backend.Incident.Create(ctx, incident("inc-1", "a1")); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := backend.Incident.Create(ctx, incident("inc-1", "a1")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate: %v", err)
		}
		updated := incident("inc-1", "a1")
		updated.Status = v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING
		if err := backend.Incident.Save(ctx, updated); err != nil {
			t.Fatalf("save: %v", err)
		}
		if err := backend.Incident.Save(ctx, incident("inc-ghost", "a1")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("save-missing: %v", err)
		}
		got, err := backend.Incident.Get(ctx, "inc-1")
		if err != nil || !proto.Equal(got, updated) {
			t.Fatalf("lifecycle state must persist: %+v %v", got, err)
		}
	})
	t.Run("evidence", func(t *testing.T) {
		// Parent incident first: linkage is enforced, not assumed.
		if err := backend.Incident.Create(ctx, incident("inc-ev", "a1")); err != nil {
			t.Fatalf("parent: %v", err)
		}
		if err := backend.Evidence.Append(ctx, evItem("ev-1", "inc-ev")); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := backend.Evidence.Append(ctx, evItem("ev-1", "inc-ev")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate: %v", err)
		}
		if _, err := backend.Evidence.Get(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		got, err := backend.Evidence.Get(ctx, "ev-1")
		if err != nil || !evidence.Verify(got) {
			t.Fatalf("stored evidence must verify: %+v %v", got, err)
		}
		byInc, err := backend.Evidence.ListByIncident(ctx, "inc-ev")
		if err != nil || len(byInc) != 1 {
			t.Fatalf("by-incident: %+v %v", byInc, err)
		}
		empty, err := backend.Evidence.ListByIncident(ctx, "inc-ghost")
		if err != nil || len(empty) != 0 {
			t.Fatalf("unknown incident lists empty: %+v %v", empty, err)
		}
	})
	t.Run("response-lifecycle", func(t *testing.T) {
		if err := backend.Response.Create(ctx, recommendation("rec-1", "inc-1", v1.ResponseStatus_RESPONSE_STATUS_PROPOSED)); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := backend.Response.Create(ctx, recommendation("rec-1", "inc-1", v1.ResponseStatus_RESPONSE_STATUS_PROPOSED)); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate: %v", err)
		}
		moved := recommendation("rec-1", "inc-1", v1.ResponseStatus_RESPONSE_STATUS_APPROVED)
		if err := backend.Response.Save(ctx, moved); err != nil {
			t.Fatalf("save: %v", err)
		}
		got, err := backend.Response.Get(ctx, "rec-1")
		if err != nil || !proto.Equal(got, moved) {
			t.Fatalf("status move must persist: %+v %v", got, err)
		}
	})
	t.Run("response-records", func(t *testing.T) {
		if err := backend.ResponseRecords.AppendApproval(ctx, approval("appr-1", "rec-1")); err != nil {
			t.Fatalf("approval: %v", err)
		}
		if err := backend.ResponseRecords.AppendExecution(ctx, execution("exec-1", "rec-1")); err != nil {
			t.Fatalf("execution: %v", err)
		}
		if err := backend.ResponseRecords.AppendVerification(ctx, verification("verif-1", "exec-1")); err != nil {
			t.Fatalf("verification: %v", err)
		}
		if err := backend.ResponseRecords.AppendApproval(ctx, approval("appr-1", "rec-1")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate record: %v", err)
		}
		if _, err := backend.ResponseRecords.GetExecution(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		a, err := backend.ResponseRecords.GetApproval(ctx, "appr-1")
		if err != nil || !proto.Equal(a, approval("appr-1", "rec-1")) {
			t.Fatalf("approval round-trip: %+v %v", a, err)
		}
	})
	t.Run("validation", func(t *testing.T) {
		if err := backend.Validation.AppendRequest(ctx, valRequest("vreq-1")); err != nil {
			t.Fatalf("request: %v", err)
		}
		if err := backend.Validation.AppendResult(ctx, valResult("vres-1", "vreq-1")); err != nil {
			t.Fatalf("result: %v", err)
		}
		if err := backend.Validation.AppendResult(ctx, valResult("vres-1", "vreq-1")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate: %v", err)
		}
		got, err := backend.Validation.GetResult(ctx, "vres-1")
		if err != nil || !proto.Equal(got, valResult("vres-1", "vreq-1")) {
			t.Fatalf("round-trip: %+v %v", got, err)
		}
		results, err := backend.Validation.ListResults(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("list: %+v %v", results, err)
		}
	})
	t.Run("audit-append-only", func(t *testing.T) {
		if err := backend.Audit.Append(ctx, auditEntry("audit-0001")); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := backend.Audit.Append(ctx, auditEntry("audit-0001")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate: %v", err)
		}
		if err := backend.Audit.Append(ctx, store.AuditEntry{}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("invalid: %v", err)
		}
		if err := backend.Audit.Append(ctx, auditEntry("audit-0002")); err != nil {
			t.Fatal(err)
		}
		list, err := backend.Audit.List(ctx)
		if err != nil || len(list) != 2 || list[0].ID != "audit-0001" || list[1].ID != "audit-0002" {
			t.Fatalf("chronological order must hold: %+v %v", list, err)
		}
		got, err := backend.Audit.Get(ctx, "audit-0002")
		if err != nil || got.Actor != "test-actor:x" || got.ResponseID != "rec-1" {
			t.Fatalf("linkage must persist: %+v %v", got, err)
		}
		// No update/delete surface exists on the interface: compile-enforced.
		// (There is literally no method to call here.)
	})
	t.Run("assets", func(t *testing.T) {
		a := testAsset("ast-x1", v1.AssetType_ASSET_TYPE_DOMAIN, "example.com")
		if err := backend.Assets.Create(ctx, a); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := backend.Assets.Create(ctx, a); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate id: %v", err)
		}
		// Same identity, different id: duplicate identity, not just id.
		clone := testAsset("ast-x2", v1.AssetType_ASSET_TYPE_DOMAIN, "example.com")
		if err := backend.Assets.Create(ctx, clone); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate identity: %v", err)
		}
		if err := backend.Assets.Create(ctx, &v1.Asset{}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("invalid: %v", err)
		}
		// Non-canonical names never become durable.
		raw := testAsset("ast-x3", v1.AssetType_ASSET_TYPE_DOMAIN, "Example.COM.")
		if err := backend.Assets.Create(ctx, raw); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("non-canonical name: %v", err)
		}
		if _, err := backend.Assets.Get(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		got, err := backend.Assets.Get(ctx, "ast-x1")
		if err != nil || !proto.Equal(got, a) {
			t.Fatalf("round-trip drift: %+v %v", got, err)
		}
		// Lifecycle update persists.
		moved := testAsset("ast-x1", v1.AssetType_ASSET_TYPE_DOMAIN, "example.com")
		moved.Status = v1.AssetStatus_ASSET_STATUS_ACTIVE
		if err := backend.Assets.Save(ctx, moved); err != nil {
			t.Fatalf("save: %v", err)
		}
		if err := backend.Assets.Save(ctx, testAsset("ghost", v1.AssetType_ASSET_TYPE_HOST, "h")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("save-missing: %v", err)
		}
		// Filtered listings.
		if err := backend.Assets.Create(ctx, testAsset("ast-x9", v1.AssetType_ASSET_TYPE_IP_ADDRESS, "127.0.0.1")); err != nil {
			t.Fatal(err)
		}
		byType, err := backend.Assets.ListByType(ctx, v1.AssetType_ASSET_TYPE_DOMAIN)
		if err != nil || len(byType) != 1 || byType[0].GetId() != "ast-x1" {
			t.Fatalf("by-type: %+v %v", byType, err)
		}
		byStatus, err := backend.Assets.ListByStatus(ctx, v1.AssetStatus_ASSET_STATUS_ACTIVE)
		if err != nil || len(byStatus) != 1 {
			t.Fatalf("by-status: %+v %v", byStatus, err)
		}
		list, err := backend.Assets.List(ctx)
		if err != nil || len(list) != 2 || list[0].GetId() != "ast-x1" || list[1].GetId() != "ast-x9" {
			t.Fatalf("stable id order: %+v %v", list, err)
		}
	})
	t.Run("relationships", func(t *testing.T) {
		mkrel := func(parent, child string) asset.Relationship {
			return asset.Relationship{
				ParentID: parent, ChildID: child, Kind: asset.RelationContains,
				Source: "test", ObservedAt: clock,
			}
		}
		if err := backend.Relationships.Append(ctx, mkrel("ast-x1", "ast-x9")); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := backend.Relationships.Append(ctx, mkrel("ast-x1", "ast-x9")); !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate link: %v", err)
		}
		bad := mkrel("ast-x1", "ast-x1")
		if err := backend.Relationships.Append(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("self-link: %v", err)
		}
		bad.Source = ""
		bad.ParentID = "ast-x1"
		bad.ChildID = "ast-x2"
		if err := backend.Relationships.Append(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("sourceless link: %v", err)
		}
		children, err := backend.Relationships.Children(ctx, "ast-x1")
		if err != nil || len(children) != 1 || children[0].ChildID != "ast-x9" {
			t.Fatalf("children: %+v %v", children, err)
		}
		parents, err := backend.Relationships.Parents(ctx, "ast-x9")
		if err != nil || len(parents) != 1 || parents[0].ParentID != "ast-x1" {
			t.Fatalf("parents: %+v %v", parents, err)
		}
		none, err := backend.Relationships.Children(ctx, "ghost")
		if err != nil || len(none) != 0 {
			t.Fatalf("unknown parent lists empty, not error: %+v %v", none, err)
		}
	})
}

func testAsset(id string, typ v1.AssetType, name string) *v1.Asset {
	return &v1.Asset{
		Id: id, Type: typ, Name: name, Environment: "lab",
		Status:    v1.AssetStatus_ASSET_STATUS_DISCOVERED,
		FirstSeen: stamp(), LastSeen: stamp(),
		Identifiers: []*v1.AssetIdentifier{{Type: "test", Value: name}},
	}
}
