package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

func seedAssets(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	mgr, err := asset.NewManager(be.Assets, memRelStore{be.Relationships}, func() time.Time {
		return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, obs := range []asset.Observation{
		{Source: "test", Type: v1.AssetType_ASSET_TYPE_URL, Raw: "https://seed-lab.example/app", ObservedAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC), Environment: "lab"},
		{Source: "test", Type: v1.AssetType_ASSET_TYPE_HOST, Raw: "seed-web-01", ObservedAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC), Environment: "lab"},
	} {
		if _, _, err := mgr.Ingest(ctx, obs); err != nil {
			t.Fatalf("ingest %+v: %v", obs, err)
		}
	}
	// One ACTIVE asset for status filtering (walk DISCOVERED → ACTIVE).
	for _, a := range mustListAssets(t, be) {
		if a.GetType() == v1.AssetType_ASSET_TYPE_HOST {
			updated := a
			updated.Status = v1.AssetStatus_ASSET_STATUS_ACTIVE
			if err := be.Assets.Save(ctx, updated); err != nil {
				t.Fatal(err)
			}
		}
	}
	return NewServer(be)
}

func mustListAssets(t *testing.T, be store.Backend) []*v1.Asset {
	t.Helper()
	list, err := be.Assets.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// memRelStore adapts the memory relationship repo to the manager interface.
type memRelStore struct {
	repo store.AssetRelationshipRepository
}

func (m memRelStore) Append(ctx context.Context, rel asset.Relationship) error {
	return m.repo.Append(ctx, rel)
}

func apiGet(t *testing.T, srv *Server, path string) (int, map[string]any) {
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

func TestAssetListAndFilters(t *testing.T) {
	srv := seedAssets(t)
	code, body := apiGet(t, srv, "/api/v1/assets")
	if code != 200 {
		t.Fatalf("list: %d %+v", code, body)
	}
	// URL + domain + service (decomposed) + host = 4.
	if data := body["data"].([]any); len(data) != 4 {
		t.Fatalf("want 4 assets, got %d", len(data))
	}
	code, body = apiGet(t, srv, "/api/v1/assets?type=ASSET_TYPE_DOMAIN")
	if code != 200 || len(body["data"].([]any)) != 1 {
		t.Fatalf("type filter: %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/assets?status=ASSET_STATUS_ACTIVE")
	if code != 200 || len(body["data"].([]any)) != 1 {
		t.Fatalf("status filter: %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/assets?q=seed-lab")
	if code != 200 || len(body["data"].([]any)) < 2 {
		t.Fatalf("search: %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/assets?type=BOGUS")
	if code != 400 {
		t.Fatalf("bad type must 400: %d %+v", code, body)
	}
}

func TestAssetGetAndRelationships(t *testing.T) {
	srv := seedAssets(t)
	_, body := apiGet(t, srv, "/api/v1/assets")
	var urlID, domainID string
	for _, item := range body["data"].([]any) {
		m := item.(map[string]any)
		if m["type"] == "ASSET_TYPE_URL" {
			urlID = m["id"].(string)
		}
		if m["type"] == "ASSET_TYPE_DOMAIN" {
			domainID = m["id"].(string)
		}
	}
	code, single := apiGet(t, srv, "/api/v1/assets/"+urlID)
	if code != 200 {
		t.Fatalf("get: %d %+v", code, single)
	}
	code, rels := apiGet(t, srv, "/api/v1/assets/"+domainID+"/relationships")
	if code != 200 {
		t.Fatalf("relationships: %d %+v", code, rels)
	}
	data := rels["data"].(map[string]any)
	if len(data["children"].([]any)) != 1 {
		t.Fatalf("domain must contain the url: %+v", rels)
	}
	code, rels = apiGet(t, srv, "/api/v1/assets/"+urlID+"/relationships")
	if code != 200 || len(rels["data"].(map[string]any)["parents"].([]any)) != 1 {
		t.Fatalf("url parents: %d %+v", code, rels)
	}
	code, missing := apiGet(t, srv, "/api/v1/assets/ghost")
	if code != 404 {
		t.Fatalf("missing must 404: %d %+v", code, missing)
	}
}

func TestPostObservationAndLifecycle(t *testing.T) {
	srv := seedAssets(t)
	post := func(body string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/observations", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, created := post(`{"source":"test","type":"ASSET_TYPE_IP_ADDRESS","raw":"10.0.0.9","observed_at":"2026-09-12T11:00:00Z","environment":"lab"}`)
	if code != 201 || created["created"] != true {
		t.Fatalf("observation create: %d %+v", code, created)
	}
	id := created["data"].(map[string]any)["id"].(string)
	// Same observation again: touch, not duplicate.
	code, touched := post(`{"source":"test","type":"ASSET_TYPE_IP_ADDRESS","raw":"10.0.0.9","observed_at":"2026-09-12T12:00:00Z"}`)
	if code != 201 || touched["created"] != false {
		t.Fatalf("re-observation must touch: %d %+v", code, touched)
	}
	if touched["data"].(map[string]any)["id"] != id {
		t.Fatal("identity must be stable")
	}
	// Malformed bodies rejected explicitly.
	for _, bad := range []string{
		`{not json`,
		`{"source":"test","type":"BOGUS","raw":"x","observed_at":"2026-09-12T11:00:00Z"}`,
		`{"source":"test","type":"ASSET_TYPE_DOMAIN","raw":"bad domain!!","observed_at":"2026-09-12T11:00:00Z"}`,
		`{"source":"","type":"ASSET_TYPE_DOMAIN","raw":"example.com","observed_at":"2026-09-12T11:00:00Z"}`,
		`{"source":"test","type":"ASSET_TYPE_DOMAIN","raw":"example.com","observed_at":"not-a-time"}`,
	} {
		if code, _ := post(bad); code != 400 {
			t.Fatalf("malformed must 400: %q → %d", bad, code)
		}
	}
	// Lifecycle on a FRESH asset (still DISCOVERED): skipping straight to
	// RETIRED is illegal; walking DISCOVERED → ACTIVE works.
	// (Note: `id` is already ACTIVE — the re-observation touch confirmed it.)
	freshCode, fresh := post(`{"source":"test","type":"ASSET_TYPE_IP_ADDRESS","raw":"10.0.0.99","observed_at":"2026-09-12T11:00:00Z"}`)
	if freshCode != 201 {
		t.Fatalf("fresh observation: %d %+v", freshCode, fresh)
	}
	freshID := fresh["data"].(map[string]any)["id"].(string)
	patchFresh := func(status string) int {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/assets/"+freshID+"/lifecycle",
			strings.NewReader(`{"status":"`+status+`"}`))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := patchFresh("ASSET_STATUS_RETIRED"); code != 400 {
		t.Fatalf("skip must 400, got %d", code)
	}
	patch := func(status string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/assets/"+freshID+"/lifecycle",
			strings.NewReader(`{"status":"`+status+`"}`))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	if code, out := patch("ASSET_STATUS_ACTIVE"); code != 200 ||
		out["data"].(map[string]any)["status"] != "ASSET_STATUS_ACTIVE" {
		t.Fatalf("legal move: %d %+v", code, out)
	}
	if code, _ := patch("BOGUS"); code != 400 {
		t.Fatalf("bad status must 400, got %d", code)
	}
}
