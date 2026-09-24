// Step 14B: API boundary matrix. Every route group is probed for the
// same fail-closed contract: malformed input → 400, unknown resource →
// 404, wrong method → 405, corruption → INTEGRITY_FAILURE (never an
// empty list), error envelopes always {error:{code,message}} with a
// bounded code, list output deterministically ordered.
package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/store/sqlite"
	"blueveil/collector/internal/supplychain"
	"google.golang.org/protobuf/types/known/timestamppb"

	_ "modernc.org/sqlite"
)

func emptyBoundaryServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(store.NewMemoryBackend())
}

func apiGetCode(t *testing.T, srv *Server, path string) (int, map[string]any) {
	t.Helper()
	code, body := apiGet(t, srv, path)
	return code, body
}

// TestBoundaryUnknownIDs asserts every {id} GET route 404s on unknown ids.
func TestBoundaryUnknownIDs(t *testing.T) {
	srv := emptyBoundaryServer(t)
	paths := []string{
		"/api/v1/telemetry/no-such",
		"/api/v1/detections/no-such",
		"/api/v1/alerts/no-such",
		"/api/v1/incidents/no-such",
		"/api/v1/incidents/no-such/timeline",
		"/api/v1/evidence/no-such",
		"/api/v1/recommendations/no-such",
		"/api/v1/approvals/no-such",
		"/api/v1/executions/no-such",
		"/api/v1/verifications/no-such",
		"/api/v1/validation-requests/no-such",
		"/api/v1/validation-results/no-such",
		"/api/v1/validation/campaigns/no-such",
		"/api/v1/purple-team/exercises/no-such",
		"/api/v1/audit/no-such",
		"/api/v1/assets/no-such",
		"/api/v1/grc/controls/NOPE",
		"/api/v1/grc/assessments/no-such",
		"/api/v1/supply-chain/components/no-such",
		"/api/v1/supply-chain/sboms/no-such",
		"/api/v1/supply-chain/policies/no-such",
		"/api/v1/supply-chain/policies/no-such/evaluate?component=no-such",
		"/api/v1/third-party/vendors/no-such",
		"/api/v1/third-party/assessments/no-such",
	}
	for _, p := range paths {
		if code, _ := apiGetCode(t, srv, p); code != 404 {
			t.Errorf("GET %s: want 404, got %d", p, code)
		}
	}
}

// TestBoundaryInvalidEnums asserts bounded filters reject garbage with 400.
func TestBoundaryInvalidEnums(t *testing.T) {
	srv := emptyBoundaryServer(t)
	paths := []string{
		"/api/v1/assets?type=BOGUS",
		"/api/v1/assets?status=SECURE",
		"/api/v1/application/observations?method=FOO",
		"/api/v1/application/observations?status=abc",
		"/api/v1/application/observations?status=99",
		"/api/v1/endpoint/observations?detected=maybe",
		"/api/v1/server/observations?detected=maybe",
		"/api/v1/container/observations?detected=maybe",
		"/api/v1/cloud/observations?detected=maybe",
		"/api/v1/identity/observations?action=BOGUS",
		"/api/v1/authentication/observations?outcome=BOGUS",
		"/api/v1/monitoring/events?order=sideways",
		"/api/v1/hunting/events?order=sideways",
		"/api/v1/detection-rules?stateful=maybe",
		"/api/v1/grc/controls?domain=BOGUS",
		"/api/v1/grc/controls?implementation=SECURE",
		"/api/v1/architecture/assets?type=NOPE",
		"/api/v1/grc/assessments?status=SECURE",
		"/api/v1/resilience/recovery?status=READY_NOW",
		"/api/v1/validation/campaigns?status=BOGUS",
		"/api/v1/validation/history?verdict=BOGUS",
		"/api/v1/supply-chain/components?type=VULNERABLE",
		"/api/v1/supply-chain/components?status=SECURE",
		"/api/v1/supply-chain/dependencies?parent=x&kind=BOGUS",
		"/api/v1/supply-chain/links?kind=timestamp",
		"/api/v1/third-party/vendors?status=TRUSTED",
		"/api/v1/third-party/assessments?status=CERTIFIED",
		"/api/v1/continuous-security/checks?check=BOGUS",
		"/api/v1/continuous-security/checks?require_sbom=maybe",
		"/api/v1/continuous-security/checks?vendor_window=bogus",
		"/api/v1/continuous-security/checks?allowed_provenance=BOGUS",
		"/api/v1/continuous-security/history?kind=trend",
		"/api/v1/supply-chain/dependencies",
		"/api/v1/supply-chain/policies/pol-x/evaluate",
	}
	for _, p := range paths {
		if code, _ := apiGetCode(t, srv, p); code != 400 {
			t.Errorf("GET %s: want 400, got %d", p, code)
		}
	}
}

// TestBoundaryEmptyParams asserts empty query values behave as absent
// (200), never as errors or as filters matching nothing silently.
func TestBoundaryEmptyParams(t *testing.T) {
	srv := emptyBoundaryServer(t)
	paths := []string{
		"/api/v1/assets?type=&status=",
		"/api/v1/supply-chain/components?type=&status=&ecosystem=",
		"/api/v1/grc/controls?domain=&implementation=",
		"/api/v1/third-party/vendors?status=",
		"/api/v1/continuous-security/checks?check=",
		"/api/v1/monitoring/events?order=",
	}
	for _, p := range paths {
		if code, _ := apiGetCode(t, srv, p); code != 200 {
			t.Errorf("GET %s: want 200, got %d", p, code)
		}
	}
}

// TestBoundaryLimits asserts pagination bounds are uniform: 1..1000,
// everything else 400.
func TestBoundaryLimits(t *testing.T) {
	srv := emptyBoundaryServer(t)
	for _, p := range []string{
		"/api/v1/validation/history?limit=0",
		"/api/v1/validation/history?limit=-1",
		"/api/v1/validation/history?limit=1001",
		"/api/v1/validation/history?limit=abc",
		"/api/v1/monitoring/events?limit=0",
		"/api/v1/monitoring/events?limit=-5",
		"/api/v1/monitoring/events?limit=1001",
		"/api/v1/monitoring/events?limit=abc",
		"/api/v1/hunting/events?limit=0",
		"/api/v1/hunting/events?limit=-5",
		"/api/v1/hunting/events?limit=1001",
		"/api/v1/hunting/events?limit=abc",
	} {
		if code, _ := apiGetCode(t, srv, p); code != 400 {
			t.Errorf("GET %s: want 400, got %d", p, code)
		}
	}
	if code, _ := apiGetCode(t, srv, "/api/v1/validation/history?limit=1000"); code != 200 {
		t.Errorf("limit=1000: want 200, got %d", code)
	}
}

// TestBoundaryMethods asserts the read-only contract on every route:
// non-GET is 405 except the two documented asset-ingest paths.
func TestBoundaryMethods(t *testing.T) {
	srv := emptyBoundaryServer(t)
	getOnly := []string{
		"/api/v1/healthz",
		"/api/v1/telemetry", "/api/v1/detections", "/api/v1/alerts",
		"/api/v1/incidents", "/api/v1/evidence", "/api/v1/recommendations",
		"/api/v1/approvals", "/api/v1/executions", "/api/v1/verifications",
		"/api/v1/validation-results", "/api/v1/audit",
		"/api/v1/assets",
		"/api/v1/network/observations", "/api/v1/network/relationships",
		"/api/v1/application/observations", "/api/v1/application/relationships",
		"/api/v1/endpoint/observations", "/api/v1/server/observations",
		"/api/v1/container/observations", "/api/v1/cloud/observations",
		"/api/v1/infrastructure/relationships",
		"/api/v1/identity/observations", "/api/v1/identity/relationships",
		"/api/v1/authentication/observations", "/api/v1/data/observations",
		"/api/v1/monitoring/events", "/api/v1/monitoring/correlations",
		"/api/v1/detection-rules", "/api/v1/detection-rules/health",
		"/api/v1/threat-intelligence/iocs", "/api/v1/threat-intelligence/matches",
		"/api/v1/hunting/events", "/api/v1/hunting/timeline",
		"/api/v1/forensics/artifacts", "/api/v1/forensics/endpoint",
		"/api/v1/forensics/network", "/api/v1/forensics/cloud",
		"/api/v1/forensics/identity",
		"/api/v1/validation/campaigns", "/api/v1/validation/history",
		"/api/v1/purple-team/exercises",
		"/api/v1/grc/frameworks", "/api/v1/grc/controls", "/api/v1/grc/assessments",
		"/api/v1/architecture/assets", "/api/v1/architecture/relationships",
		"/api/v1/resilience/posture", "/api/v1/resilience/recovery",
		"/api/v1/supply-chain/components", "/api/v1/supply-chain/dependencies",
		"/api/v1/supply-chain/sboms", "/api/v1/supply-chain/policies",
		"/api/v1/supply-chain/links",
		"/api/v1/third-party/vendors", "/api/v1/third-party/assessments",
		"/api/v1/continuous-security/checks", "/api/v1/continuous-security/history",
	}
	methods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, p := range getOnly {
		for _, m := range methods {
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(m, p, nil))
			if rec.Code != 405 {
				t.Errorf("%s %s: want 405, got %d", m, p, rec.Code)
			}
		}
	}
	// Documented mutations: POST observations ingests, PATCH lifecycle
	// moves; every other method on those paths is still 405.
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(m, "/api/v1/assets/observations", nil))
		if rec.Code != 405 {
			t.Errorf("%s /api/v1/assets/observations: want 405, got %d", m, rec.Code)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(m, "/api/v1/assets/ast-1/lifecycle", nil))
		if rec.Code != 405 {
			t.Errorf("%s lifecycle: want 405, got %d", m, rec.Code)
		}
	}
}

// TestBoundaryErrorEnvelopes asserts every sampled error carries
// {error:{code,message}} with a bounded code.
func TestBoundaryErrorEnvelopes(t *testing.T) {
	srv := emptyBoundaryServer(t)
	allowed := map[string]bool{
		"BAD_REQUEST": true, "NOT_FOUND": true, "METHOD_NOT_ALLOWED": true,
		"INTERNAL": true, "INTEGRITY_FAILURE": true,
		"UNAUTHORIZED": true, "FORBIDDEN": true,
	}
	paths := []string{
		"/api/v1/assets?type=BOGUS",
		"/api/v1/assets/no-such",
		"/api/v1/telemetry/no-such",
		"/api/v1/grc/controls/NOPE",
		"/api/v1/supply-chain/dependencies",
		"/api/v1/continuous-security/checks?check=BOGUS",
		"/api/v1/validation/history?limit=0",
	}
	for _, p := range paths {
		code, body := apiGetCode(t, srv, p)
		if code < 400 {
			t.Errorf("GET %s: want error, got %d", p, code)
			continue
		}
		errObj, ok := body["error"].(map[string]any)
		if !ok {
			t.Errorf("GET %s: missing error envelope: %+v", p, body)
			continue
		}
		c, _ := errObj["code"].(string)
		m, _ := errObj["message"].(string)
		if !allowed[c] || m == "" {
			t.Errorf("GET %s: bad envelope code=%q message=%q", p, c, m)
		}
	}
}

// TestBoundaryDeterministicOrder asserts list output is id-ordered even
// when insertion order is reversed.
func TestBoundaryDeterministicOrder(t *testing.T) {
	be := store.NewMemoryBackend()
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	mkComp := func(name string) supplychain.Component {
		return supplychain.Component{
			Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: name,
			Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
			Source: "boundary-test", ObservedAt: now, Status: supplychain.StatusObserved,
		}
	}
	// Insert zzz first, aaa second: output must still be id-sorted.
	zzz, aaa := mkComp("zzz-lib"), mkComp("aaa-lib")
	if zzz.ID() < aaa.ID() {
		zzz, aaa = aaa, zzz
	}
	for _, c := range []supplychain.Component{zzz, aaa} {
		if err := be.Components.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []supplychain.Vendor{
		{Name: "Zulu", Service: "cdn", Status: supplychain.VendorActive, Source: "boundary-test", ObservedAt: now},
		{Name: "Alpha", Service: "cdn", Status: supplychain.VendorActive, Source: "boundary-test", ObservedAt: now},
	} {
		if err := be.Vendors.Create(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewServer(be)
	code, body := apiGetCode(t, srv, "/api/v1/supply-chain/components")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("components: %d %+v", code, body)
	}
	rows := body["data"].([]any)
	first, _ := rows[0].(map[string]any)["id"].(string)
	second, _ := rows[1].(map[string]any)["id"].(string)
	if first == "" || first > second {
		t.Errorf("components not id-ordered: %+v", body)
	}
	code, body = apiGetCode(t, srv, "/api/v1/third-party/vendors")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("vendors: %d %+v", code, body)
	}
	rows = body["data"].([]any)
	first, _ = rows[0].(map[string]any)["id"].(string)
	second, _ = rows[1].(map[string]any)["id"].(string)
	if first == "" || first > second {
		t.Errorf("vendors not id-ordered: %+v", body)
	}
}

// seedBoundaryTelemetry stores two contract-valid net observations.
func seedBoundaryTelemetry(t *testing.T, be store.Backend) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	for i, id := range []string{"evt-boundary-1", "evt-boundary-2"} {
		if err := be.Telemetry.Append(ctx, &v1.TelemetryEvent{
			Id: id, OccurredAt: timestamppb.New(base.Add(time.Duration(i) * time.Minute)),
			Source: "lab-sensor", AssetId: "seed-net-01",
			EventType: "net.connection", Severity: v1.Severity_SEVERITY_INFO,
			Attributes: map[string]string{
				"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
				"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestBoundaryCorruptFailsClosed poisons one stored telemetry row (through
// a second SQL handle, the way disk corruption would present) and asserts
// the list fails with INTEGRITY_FAILURE instead of an empty list.
func TestBoundaryCorruptFailsClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "boundary.db")
	db, err := sqlite.Open(ctx, sqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	be := db.Backend()
	seedBoundaryTelemetry(t, be)
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx,
		`UPDATE telemetry_events SET severity = 999 WHERE id = 'evt-boundary-1'`); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(be)
	code, body := apiGetCode(t, srv, "/api/v1/telemetry")
	if code != 500 {
		t.Fatalf("corrupt list: want 500, got %d", code)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok || errObj["code"] != "INTEGRITY_FAILURE" {
		t.Fatalf("corrupt list must be INTEGRITY_FAILURE, got %+v", body)
	}
	code, body = apiGetCode(t, srv, "/api/v1/network/observations")
	if code != 500 {
		t.Fatalf("corrupt observations: want 500, got %d", code)
	}
	if errObj, ok := body["error"].(map[string]any); !ok || errObj["code"] != "INTEGRITY_FAILURE" {
		t.Fatalf("corrupt observations must be INTEGRITY_FAILURE, got %+v", body)
	}
}

// TestBoundaryGetWithBody documents that GET ignores request bodies
// (no body-driven behavior change on a read-only API).
func TestBoundaryGetWithBody(t *testing.T) {
	srv := emptyBoundaryServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/healthz", strings.NewReader(`{"admin":true}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("GET with body: want 200, got %d", rec.Code)
	}
}
