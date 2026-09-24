// RED: campaign/history/purple-team read endpoints. Read-only,
// bounded, deterministic; POST rejected everywhere.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/validation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func seedValidationLab(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	camp := validation.Campaign{
		Name: "lab campaign", Description: "d", Target: "seed-lab",
		Provider: validation.NativeProviderID, Source: "seed-lab-validation",
		Status: validation.StatusCompleted, CreatedAt: now.Add(-time.Hour),
		StartedAt: now.Add(-30 * time.Minute), CompletedAt: now,
		CaseIDs: []string{"vcase-a"}, ResultIDs: []string{"vres-a", "vres-b"},
	}
	if err := be.Campaigns.Create(ctx, camp); err != nil {
		t.Fatal(err)
	}
	mkRes := func(id, req string, v v1.ValidationVerdict, prov string) {
		if err := be.Validation.AppendResult(ctx, &v1.ValidationResult{
			Id: id, RequestId: req, ControlId: "ctl-lab", Provider: prov,
			ProviderVersion: "seed", ContractVersion: "blueveil.contracts.v1",
			Verdict: v, ValidatedAt: timestamppb.New(now),
		}); err != nil {
			t.Fatalf("result %s: %v", id, err)
		}
	}
	mkRes("vres-a", "vreq-a", v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED, validation.NativeProviderID)
	mkRes("vres-b", "vreq-b", v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED, validation.RedveilProviderID)
	ex, err := validation.BuildExercise(validation.ExerciseInput{
		CampaignID: camp.ID(), Name: "lab exercise", Source: "seed-lab-validation",
		Entries: []validation.ExerciseEntryInput{{
			CaseID: "vcase-a", RequestID: "vreq-a", ResultID: "vres-a",
			Verdict:      v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED,
			TelemetryIDs: []string{"evt-1"}, DetectionIDs: []string{"det-1"},
			AlertIDs: []string{"alert-1"}, IncidentIDs: []string{"inc-1"},
			EvidenceIDs: []string{"ev-1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Exercises.Create(ctx, ex); err != nil {
		t.Fatal(err)
	}
	return NewServer(be)
}

func TestCampaignEndpoints(t *testing.T) {
	srv := seedValidationLab(t)
	code, body := apiGet(t, srv, "/api/v1/validation/campaigns")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 campaign, got %d %+v", code, body)
	}
	row := body["data"].([]any)[0].(map[string]any)
	if row["status"] != "COMPLETED" {
		t.Fatalf("status string: %+v", row)
	}
	for _, k := range []string{"id", "name", "target", "provider", "summary"} {
		if _, ok := row[k]; !ok {
			t.Fatalf("campaign row missing %s: %+v", k, row)
		}
	}
	sum := row["summary"].(map[string]any)
	if sum["total"] != 2.0 || sum["not_tested"] != 1.0 {
		t.Fatalf("campaign summary counts actuals: %+v", sum)
	}
	campID := row["id"].(string)
	code, body = apiGet(t, srv, "/api/v1/validation/campaigns/"+campID)
	if code != 200 {
		t.Fatalf("get: %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/validation/campaigns/"+campID+"/results")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("want 2 campaign results, got %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/validation/campaigns/no-such"); code != 404 {
		t.Errorf("unknown campaign must 404, got %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/validation/campaigns/no-such/results"); code != 404 {
		t.Errorf("unknown campaign results must 404, got %d", code)
	}
}

func TestValidationHistory(t *testing.T) {
	srv := seedValidationLab(t)
	cases := map[string]struct {
		path string
		want int
	}{
		"all":      {"/api/v1/validation/history", 2},
		"verdict":  {"/api/v1/validation/history?verdict=DETECTED", 1},
		"provider": {"/api/v1/validation/history?provider=" + validation.RedveilProviderID, 1},
		"limit":    {"/api/v1/validation/history?limit=1", 1},
	}
	for name, c := range cases {
		code, body := apiGet(t, srv, c.path)
		if code != 200 || dataLen(t, body) != c.want {
			t.Errorf("%s: want %d, got %d %+v", name, c.want, code, body)
		}
	}
	for name, path := range map[string]string{
		"bad verdict": "/api/v1/validation/history?verdict=SECURE",
		"bad limit":   "/api/v1/validation/history?limit=0",
		"bad from":    "/api/v1/validation/history?from=nope",
	} {
		if code, _ := apiGet(t, srv, path); code != 400 {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
}

func TestPurpleTeamEndpoints(t *testing.T) {
	srv := seedValidationLab(t)
	code, body := apiGet(t, srv, "/api/v1/purple-team/exercises")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 exercise, got %d %+v", code, body)
	}
	row := body["data"].([]any)[0].(map[string]any)
	if row["entries"].([]any)[0].(map[string]any)["status"] != "DETECTED" {
		t.Fatalf("entry status: %+v", row)
	}
	exID := row["id"].(string)
	code, body = apiGet(t, srv, "/api/v1/purple-team/exercises/"+exID)
	if code != 200 {
		t.Fatalf("get: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/purple-team/exercises/no-such"); code != 404 {
		t.Errorf("unknown exercise must 404, got %d", code)
	}
}

func TestValidationMethodGuard(t *testing.T) {
	srv := seedValidationLab(t)
	for _, p := range []string{
		"/api/v1/validation/campaigns", "/api/v1/validation/history",
		"/api/v1/purple-team/exercises",
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
