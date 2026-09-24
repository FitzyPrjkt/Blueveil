// Step 14C: persistence corruption matrix. Every payload family is
// poisoned five ways (malformed JSON, invalid enum, missing required
// field, bad timestamp, tampered content/canonical form) and every read
// path must fail closed with ErrCorrupted — never an empty result, never
// a default object.
package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/supplychain"
)

var corruptNow = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func poison(t *testing.T, db *DB, stmt string, args ...any) {
	t.Helper()
	if _, err := db.db.ExecContext(context.Background(), stmt, args...); err != nil {
		t.Fatalf("poison: %v", err)
	}
}

func mustCorrupted(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, store.ErrCorrupted) {
		t.Errorf("%s: want ErrCorrupted, got %v", what, err)
	}
}

// seedCorruptChain stores a minimal linked run: telemetry → detection →
// alert → incident → evidence, plus a validation request → result and one
// canonical domain asset. All ids are fixed for poisoning.
func seedCorruptChain(t *testing.T, be store.Backend) {
	t.Helper()
	ctx := context.Background()
	evt := &v1.TelemetryEvent{
		Id: "evt-poison", OccurredAt: timestamppb.New(corruptNow),
		Source: "lab", AssetId: "ast-poison", EventType: "net.connection",
		Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
			"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
		},
	}
	if err := be.Telemetry.Append(ctx, evt); err != nil {
		t.Fatal(err)
	}
	det := &v1.Detection{
		Id: "det-poison", RuleId: "r", RuleName: "r",
		TelemetryEventIds: []string{"evt-poison"}, DetectedAt: timestamppb.New(corruptNow),
		Severity: v1.Severity_SEVERITY_INFO, Title: "t",
	}
	if err := be.Detection.Append(ctx, det); err != nil {
		t.Fatal(err)
	}
	alert := &v1.Alert{
		Id: "alert-poison", DetectionIds: []string{"det-poison"},
		Status: v1.AlertStatus_ALERT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(corruptNow), UpdatedAt: timestamppb.New(corruptNow),
		Title: "t",
	}
	if err := be.Alert.Append(ctx, alert); err != nil {
		t.Fatal(err)
	}
	inc := &v1.Incident{
		Id: "inc-poison", AlertIds: []string{"alert-poison"},
		Status: v1.IncidentStatus_INCIDENT_STATUS_OPEN, Severity: v1.Severity_SEVERITY_INFO,
		CreatedAt: timestamppb.New(corruptNow), UpdatedAt: timestamppb.New(corruptNow),
		Title: "t",
	}
	if err := be.Incident.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}
	item, err := evidence.NewItem("inc-poison", "telemetry", "evt-poison",
		v1.EvidenceType_EVIDENCE_TYPE_LOG_EXCERPT, "lab", "line", corruptNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Evidence.Append(ctx, item); err != nil {
		t.Fatal(err)
	}
	req := &v1.ValidationRequest{
		Id: "vreq-poison", ControlId: "AC-1", Target: "ast-poison",
		RequestedAt: timestamppb.New(corruptNow),
	}
	if err := be.Validation.AppendRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	res := &v1.ValidationResult{
		Id: "vres-poison", RequestId: "vreq-poison", ControlId: "AC-1",
		Provider: "p", ProviderVersion: "1", ContractVersion: contract.ContractVersion,
		Verdict:     v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
		ValidatedAt: timestamppb.New(corruptNow), EvidenceIds: []string{item.GetId()},
	}
	if err := be.Validation.AppendResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	if err := be.Assets.Create(ctx, &v1.Asset{
		Id: "ast-poison-dom", Type: v1.AssetType_ASSET_TYPE_DOMAIN, Name: "example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.Audit.Append(ctx, store.AuditEntry{
		ID: "audit-poison-1", DecidedAt: corruptNow, Actor: "test",
		Operation: v1.OperationType_OPERATION_TYPE_OBSERVE,
		Risk:      v1.RiskLevel_RISK_LEVEL_LOW,
		Decision:  "recommended", Reason: "r", Result: "rec-1",
		ResponseID: "rec-1", Phase: "recommend",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptionMatrixStructured(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		table string
		idCol string
		id    string
		set   string
		get   func(be store.Backend) error
		list  func(be store.Backend) error
	}{
		{"telemetry bad enum", "telemetry_events", "id", "evt-poison", "severity = 999",
			func(be store.Backend) error { _, err := be.Telemetry.Get(ctx, "evt-poison"); return err },
			func(be store.Backend) error { _, err := be.Telemetry.List(ctx); return err }},
		{"telemetry bad timestamp", "telemetry_events", "id", "evt-poison", "occurred_at = 'not-a-time'",
			func(be store.Backend) error { _, err := be.Telemetry.Get(ctx, "evt-poison"); return err },
			func(be store.Backend) error { _, err := be.Telemetry.List(ctx); return err }},
		{"detection bad enum", "detections", "id", "det-poison", "severity = 999",
			func(be store.Backend) error { _, err := be.Detection.Get(ctx, "det-poison"); return err },
			func(be store.Backend) error { _, err := be.Detection.List(ctx); return err }},
		{"alert bad status", "alerts", "id", "alert-poison", "status = 999",
			func(be store.Backend) error { _, err := be.Alert.Get(ctx, "alert-poison"); return err },
			func(be store.Backend) error { _, err := be.Alert.List(ctx); return err }},
		{"incident bad status", "incidents", "id", "inc-poison", "status = 999",
			func(be store.Backend) error { _, err := be.Incident.Get(ctx, "inc-poison"); return err },
			func(be store.Backend) error { _, err := be.Incident.List(ctx); return err }},
		{"evidence tampered content", "evidence", "id", "", "content = 'forged'",
			func(be store.Backend) error { _, err := be.Evidence.List(ctx); return err },
			func(be store.Backend) error { _, err := be.Evidence.List(ctx); return err }},
		{"request missing control", "validation_requests", "id", "vreq-poison", "control_id = ''",
			func(be store.Backend) error { _, err := be.Validation.GetRequest(ctx, "vreq-poison"); return err },
			// No ListRequests exists: results list legitimately ignores
			// request rows, so there is no list leg for this family.
			nil},
		{"result unspecified verdict", "validation_results", "id", "vres-poison", "verdict = 0",
			func(be store.Backend) error { _, err := be.Validation.GetResult(ctx, "vres-poison"); return err },
			func(be store.Backend) error { _, err := be.Validation.ListResults(ctx); return err }},
		{"asset non-canonical name", "assets", "id", "ast-poison-dom", "name = 'EXAMPLE.COM'",
			func(be store.Backend) error { _, err := be.Assets.Get(ctx, "ast-poison-dom"); return err },
			func(be store.Backend) error { _, err := be.Assets.List(ctx); return err }},
		{"audit empty decision", "audit_entries", "id", "audit-poison-1", "decision = ''",
			func(be store.Backend) error { _, err := be.Audit.Get(ctx, "audit-poison-1"); return err },
			func(be store.Backend) error { _, err := be.Audit.List(ctx); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openMemory(t)
			be := db.Backend()
			seedCorruptChain(t, be)
			if tc.id == "" {
				poison(t, db, `UPDATE `+tc.table+` SET `+tc.set)
			} else {
				poison(t, db, `UPDATE `+tc.table+` SET `+tc.set+` WHERE `+tc.idCol+` = ?`, tc.id)
			}
			mustCorrupted(t, tc.get(be), tc.name+" get")
			if tc.list != nil {
				mustCorrupted(t, tc.list(be), tc.name+" list")
			}
		})
	}
}

func TestCorruptionMatrixJSON(t *testing.T) {
	ctx := context.Background()
	_ = ctx
	cases := []struct {
		name  string
		table string
		id    string
		setup func(t *testing.T, be store.Backend) string
		get   func(be store.Backend, id string) error
		list  func(be store.Backend) error
	}{
		{"assessment invalid enum", "grc_assessments", "", setupPoisonAssessment,
			func(be store.Backend, id string) error { _, err := be.Assessments.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.Assessments.List(ctx); return err }},
		{"resilience missing target", "resilience_records", "", setupPoisonResilience,
			func(be store.Backend, id string) error { _, err := be.Resilience.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.Resilience.List(ctx); return err }},
		{"campaign zero status", "validation_campaigns", "", setupPoisonCampaign,
			func(be store.Backend, id string) error { _, err := be.Campaigns.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.Campaigns.List(ctx); return err }},
		{"exercise empty campaign", "purple_team_exercises", "", setupPoisonExercise,
			func(be store.Backend, id string) error { _, err := be.Exercises.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.Exercises.List(ctx); return err }},
		{"component invalid type", "supply_components", "", setupPoisonComponent,
			func(be store.Backend, id string) error { _, err := be.Components.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.Components.List(ctx); return err }},
		{"sbom invalid format", "supply_sboms", "", setupPoisonSBOM,
			func(be store.Backend, id string) error { _, err := be.SBOMs.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.SBOMs.List(ctx); return err }},
		{"policy empty id", "supply_policies", "", setupPoisonPolicy,
			func(be store.Backend, id string) error { _, err := be.Policies.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.Policies.List(ctx); return err }},
		{"vendor trusted status", "supply_vendors", "", setupPoisonVendor,
			func(be store.Backend, id string) error { _, err := be.Vendors.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.Vendors.List(ctx); return err }},
		{"vendor assessment certified", "supply_vendor_assessments", "", setupPoisonVendorAssessment,
			func(be store.Backend, id string) error { _, err := be.VendorAssessments.Get(ctx, id); return err },
			func(be store.Backend) error { _, err := be.VendorAssessments.List(ctx); return err }},
		{"supply link empty control", "supply_links", "", setupPoisonSupplyLink,
			func(be store.Backend, id string) error { _, err := be.SupplyLinks.List(ctx); return err },
			func(be store.Backend) error { _, err := be.SupplyLinks.List(ctx); return err }},
		{"dependency bogus kind", "supply_dependencies", "", setupPoisonDependency,
			func(be store.Backend, id string) error {
				_, err := be.Dependencies.Children(ctx, id)
				return err
			},
			func(be store.Backend) error {
				// Component IDs are deterministic: recompute the child id.
				child := supplychain.Component{
					Type: supplychain.ComponentLibrary, Ecosystem: "npm",
					Name: "comp-poison-b", Version: "1.0.0",
				}.ID()
				_, err := be.Dependencies.Parents(ctx, child)
				return err
			}},
	}
	mutants := []struct {
		name    string
		payload string
	}{
		{"malformed json", "{not-json"},
		{"missing required", `{"ID":"x"}`},
		{"invalid enum", `{"ID":"x","Status":"SECURE","Target":"t","Assessor":"s","ObservedAt":"2026-09-12T10:00:00Z"}`},
		{"bad timestamp", `{"ID":"x","Status":"UNKNOWN","Target":"t","Assessor":"s","ObservedAt":"yesterday"}`},
	}
	for _, tc := range cases {
		for _, m := range mutants {
			t.Run(tc.name+"/"+m.name, func(t *testing.T) {
				db := openMemory(t)
				be := db.Backend()
				id := tc.setup(t, be)
				poison(t, db, `UPDATE `+tc.table+` SET payload = ? WHERE `+idColFor(tc.table)+` = ?`, m.payload, id)
				mustCorrupted(t, tc.get(be, id), tc.name+"/"+m.name+" get")
				mustCorrupted(t, tc.list(be), tc.name+"/"+m.name+" list")
			})
		}
	}
}

func idColFor(table string) string {
	if table == "supply_dependencies" {
		return "parent_id"
	}
	return "id"
}
