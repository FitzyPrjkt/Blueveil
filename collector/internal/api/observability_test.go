// Step 15G: observability wiring tests. Access logs carry operation,
// status, duration, request id, and role — never credentials. Metrics
// count requests and error classes. Readyz reports honestly.
package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blueveil/collector/internal/obs"
	"blueveil/collector/internal/store"
)

func obsServer(t *testing.T) (*Server, *bytes.Buffer, *obs.Metrics) {
	t.Helper()
	srv := NewServer(store.NewMemoryBackend())
	var buf bytes.Buffer
	log, err := obs.New("info", "json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	m := obs.NewMetrics()
	srv.UseObservability(log, m, func(r *http.Request) error { return nil })
	return srv, &buf, m
}

func TestAccessLogHasOperationWithoutSecrets(t *testing.T) {
	srv, buf, _ := obsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets?type=BOGUS", nil)
	req.Header.Set("Authorization", "Bearer top-secret-value")
	req.Header.Set("Cookie", "session=abc")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	out := buf.String()
	// Path only (never the query string: filters can carry sensitive
	// values and add unbounded cardinality to log pipelines).
	if !strings.Contains(out, "GET /api/v1/assets\"") {
		t.Fatalf("log must carry operation path: %s", out)
	}
	if !strings.Contains(out, `"status":400`) {
		t.Fatalf("log must carry status: %s", out)
	}
	if !strings.Contains(out, "request_id") {
		t.Fatalf("log must carry request id: %s", out)
	}
	for _, secret := range []string{"top-secret-value", "Bearer", "session=abc", "authorization"} {
		if strings.Contains(out, secret) {
			t.Fatalf("access log leaks %q: %s", secret, out)
		}
	}
}

func TestAccessLogCarriesAuthenticatedRole(t *testing.T) {
	srv, secrets := gatedServer(t)
	var buf bytes.Buffer
	log, _ := obs.New("info", "json", &buf)
	m := obs.NewMetrics()
	srv.UseObservability(log, m, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer "+secrets["ADMIN"])
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if !strings.Contains(buf.String(), `"role":"ADMIN"`) {
		t.Fatalf("access log must carry the authenticated role: %s", buf.String())
	}
}

func TestMetricsCountRequestsAndErrors(t *testing.T) {
	srv, _, m := obsServer(t)
	for _, p := range []string{"/api/v1/healthz", "/api/v1/assets"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/assets?type=BOGUS", nil))
	snap := m.Snapshot()
	if snap["requests_total"] != 3 {
		t.Fatalf("want 3 requests, got %+v", snap)
	}
	if snap["request_errors_4xx"] != 1 {
		t.Fatalf("want 1 4xx, got %+v", snap)
	}
	if snap["request_errors_5xx"] != 0 {
		t.Fatalf("want 0 5xx, got %+v", snap)
	}
}

func TestReadyzReports(t *testing.T) {
	srv, _, _ := obsServer(t)
	code, body := apiGet(t, srv, "/api/v1/readyz")
	if code != 200 {
		t.Fatalf("readyz: %d %+v", code, body)
	}
	data := body["data"].(map[string]any)
	if data["status"] != "ready" {
		t.Fatalf("status: %+v", data)
	}
	if data["checks"].(map[string]any)["database"] != "ok" {
		t.Fatalf("checks: %+v", data)
	}
	if _, ok := data["metrics"].(map[string]any)["requests_total"]; !ok {
		t.Fatalf("metrics snapshot must be present: %+v", data)
	}
}

func TestReadyzFailsClosed(t *testing.T) {
	srv := NewServer(store.NewMemoryBackend())
	var buf bytes.Buffer
	log, _ := obs.New("info", "json", &buf)
	srv.UseObservability(log, obs.NewMetrics(), func(r *http.Request) error {
		return errors.New("db down")
	})
	code, body := apiGet(t, srv, "/api/v1/readyz")
	if code != 503 {
		t.Fatalf("unhealthy ready must 503, got %d", code)
	}
	if body["data"].(map[string]any)["status"] != "not-ready" {
		t.Fatalf("status: %+v", body)
	}
}

func TestReadyzReflectsServingFlag(t *testing.T) {
	srv, _, _ := obsServer(t)
	srv.SetServing(false)
	code, body := apiGet(t, srv, "/api/v1/readyz")
	if code != 503 {
		t.Fatalf("non-serving ready must 503, got %d", code)
	}
	if body["data"].(map[string]any)["status"] != "not-ready" {
		t.Fatalf("status: %+v", body)
	}
	srv.SetServing(true)
	if code, _ := apiGet(t, srv, "/api/v1/readyz"); code != 200 {
		t.Fatalf("serving ready must 200, got %d", code)
	}
}

func TestHealthAliveWhileNotReady(t *testing.T) {
	// Liveness and readiness are distinct: a draining server with a dead
	// database is still alive (healthz 200) but not ready (readyz 503).
	srv := NewServer(store.NewMemoryBackend())
	var buf bytes.Buffer
	log, _ := obs.New("info", "json", &buf)
	srv.UseObservability(log, obs.NewMetrics(), func(r *http.Request) error {
		return errors.New("db down")
	})
	srv.SetServing(false)
	if code, _ := apiGet(t, srv, "/api/v1/healthz"); code != 200 {
		t.Fatalf("healthz must stay 200 while not-ready, got %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/readyz"); code != 503 {
		t.Fatalf("readyz must 503 while not-ready, got %d", code)
	}
}

func TestOversizedBodyBounded(t *testing.T) {
	// The mux in serve wraps handlers in MaxBytesHandler, but the
	// handler itself must also stay bounded: a 2MB garbage body must
	// fail fast with 400, never hang or exhaust memory.
	srv := NewServer(store.NewMemoryBackend())
	big := make([]byte, 2<<20)
	for i := range big {
		big[i] = 'x'
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/observations", bytes.NewReader(big))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("oversized body: want 400, got %d", rec.Code)
	}
}

func TestErrorResponsesCarryRequestIDWithoutTraces(t *testing.T) {
	srv := NewServer(store.NewMemoryBackend())
	for path, wantCode := range map[string]int{
		"/api/v1/assets/nope":       404,
		"/api/v1/assets?type=BOGUS": 400,
		"/api/v1/no-such-area":      404,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Request-ID", "diag-1")
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != wantCode {
			t.Errorf("GET %s: want %d, got %d", path, wantCode, rec.Code)
			continue
		}
		if rec.Header().Get("X-Request-ID") != "diag-1" {
			t.Errorf("GET %s: error must carry the request id", path)
		}
		body := rec.Body.String()
		for _, leak := range []string{"goroutine", "panic:", ".go:", "stack", "traceback"} {
			if strings.Contains(strings.ToLower(body), leak) {
				t.Errorf("GET %s: error leaks internals %q: %s", path, leak, body)
			}
		}
	}
}

func TestReadyzStaysPublicUnderGate(t *testing.T) {
	srv, secrets := gatedServer(t)
	_ = secrets
	if code := gatedGet(t, srv, "/api/v1/readyz", ""); code != 200 {
		t.Errorf("readyz must stay public, got %d", code)
	}
}
