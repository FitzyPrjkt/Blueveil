// RED: GRC/architecture/resilience read endpoints. Read-only,
// bounded, deterministic; unknown ids 404; POST rejected.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/store"
)

func seedGRC(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	mkAss := func(control, status string, basis string) {
		a := grc.Assessment{
			ControlID: control, Target: "seed-lab", Status: grc.AssessmentStatus(status),
			Assessor: "seed-lab-grc", ObservedAt: now, Basis: basis,
			EvidenceIDs: []string{"ev-1"},
		}
		if status == string(grc.StatusNotAssessed) {
			a.Basis = ""
			a.EvidenceIDs = nil
		}
		if err := be.Assessments.Create(ctx, a); err != nil {
			t.Fatalf("assessment %s: %v", control, err)
		}
	}
	mkAss("AC-1", string(grc.StatusCompliant), "validation observed")
	mkAss("NW-1", string(grc.StatusNonCompliant), "detection observed, no prevention")
	mkAss("RC-1", string(grc.StatusNotAssessed), "")
	rec, err := grc.AssessResilience(grc.ResilienceInput{
		Target: "seed-lab", Assessor: "seed-lab-grc", ObservedAt: now,
		BackupObserved: true, BackupAt: now, EvidenceIDs: []string{"ev-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Resilience.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := be.Assets.Create(ctx, &v1.Asset{
		Id: "ast-1", Type: v1.AssetType_ASSET_TYPE_HOST, Name: "web01",
		Environment: "lab",
	}); err != nil {
		t.Fatal(err)
	}
	return NewServer(be)
}

func TestGRCFrameworksAndControls(t *testing.T) {
	srv := seedGRC(t)
	code, body := apiGet(t, srv, "/api/v1/grc/frameworks")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 framework, got %d %+v", code, body)
	}
	fw := body["data"].([]any)[0].(map[string]any)
	if fw["kind"] != "INTERNAL_BASELINE" {
		t.Fatalf("framework kind: %+v", fw)
	}
	code, body = apiGet(t, srv, "/api/v1/grc/controls")
	if code != 200 || dataLen(t, body) < 6 {
		t.Fatalf("want baseline controls, got %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/grc/controls?domain=identity")
	if code != 200 {
		t.Fatalf("domain filter: %d %+v", code, body)
	}
	for _, r := range body["data"].([]any) {
		if r.(map[string]any)["domain"] != "identity" {
			t.Fatalf("domain leak: %v", r)
		}
	}
	code, body = apiGet(t, srv, "/api/v1/grc/controls/AC-1")
	if code != 200 {
		t.Fatalf("get control: %d %+v", code, body)
	}
	if body["data"].(map[string]any)["id"] != "AC-1" {
		t.Fatalf("control id: %+v", body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/grc/controls/NOPE"); code != 404 {
		t.Errorf("unknown control must 404, got %d", code)
	}
}

func TestGRCAssessments(t *testing.T) {
	srv := seedGRC(t)
	code, body := apiGet(t, srv, "/api/v1/grc/assessments")
	if code != 200 || dataLen(t, body) != 3 {
		t.Fatalf("want 3 assessments, got %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/grc/assessments?status=NON_COMPLIANT")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 non-compliant, got %d %+v", code, body)
	}
	// Statuses render verbatim; no SECURE anywhere.
	if code, _ := apiGet(t, srv, "/api/v1/grc/assessments?status=SECURE"); code != 400 {
		t.Errorf("SECURE must be rejected, got %d", code)
	}
	code, body = apiGet(t, srv, "/api/v1/grc/assessments?control=AC-1")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("control filter: %d %+v", code, body)
	}
	// evidence_ids must always be an array (never null) so UI parsers
	// accept evidence-less assessments.
	for _, r := range body["data"].([]any) {
		if _, ok := r.(map[string]any)["evidence_ids"].([]any); !ok {
			t.Fatalf("evidence_ids must be an array: %v", r)
		}
	}
	// Resolve one id for the get path.
	code, body = apiGet(t, srv, "/api/v1/grc/assessments?control=NW-1")
	id := body["data"].([]any)[0].(map[string]any)["id"].(string)
	code, body = apiGet(t, srv, "/api/v1/grc/assessments/"+id)
	if code != 200 {
		t.Fatalf("get assessment: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/grc/assessments/no-such"); code != 404 {
		t.Errorf("unknown assessment must 404, got %d", code)
	}
}

func TestArchitectureEndpoints(t *testing.T) {
	srv := seedGRC(t)
	code, body := apiGet(t, srv, "/api/v1/architecture/assets")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 node, got %d %+v", code, body)
	}
	node := body["data"].([]any)[0].(map[string]any)
	if node["asset_id"] != "ast-1" || node["boundary"] != "lab" {
		t.Fatalf("node provenance: %+v", node)
	}
	code, body = apiGet(t, srv, "/api/v1/architecture/relationships")
	if code != 200 || dataLen(t, body) != 0 {
		t.Fatalf("want 0 edges, got %d %+v", code, body)
	}
}

func TestResilienceEndpoints(t *testing.T) {
	srv := seedGRC(t)
	code, body := apiGet(t, srv, "/api/v1/resilience/posture")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 posture row, got %d %+v", code, body)
	}
	row := body["data"].([]any)[0].(map[string]any)
	if row["status"] != "DEGRADED" {
		t.Fatalf("partial evidence must be DEGRADED: %+v", row)
	}
	for k := range row {
		if k == "score" || k == "resilience_score" {
			t.Fatalf("no scores allowed: %+v", row)
		}
	}
	code, body = apiGet(t, srv, "/api/v1/resilience/recovery?status=DEGRADED")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("status filter: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/resilience/recovery?status=READY_NOW"); code != 400 {
		t.Errorf("unknown status must 400, got %d", code)
	}
}

func TestGRCMethodGuard(t *testing.T) {
	srv := seedGRC(t)
	for _, p := range []string{
		"/api/v1/grc/frameworks", "/api/v1/grc/controls", "/api/v1/grc/assessments",
		"/api/v1/architecture/assets", "/api/v1/architecture/relationships",
		"/api/v1/resilience/posture", "/api/v1/resilience/recovery",
	} {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(m, p, nil))
			if rec.Code != 405 {
				t.Errorf("%s %s: want 405, got %d", m, p, rec.Code)
			}
		}
	}
}
