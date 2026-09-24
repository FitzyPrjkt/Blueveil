// Step 15D/15E RED: API authentication + authorization at the boundary.
// Unauthenticated production API access is denied; health stays public;
// roles gate capabilities; the safety engine is untouched (no HTTP
// surface for approvals/execution exists or is added here).
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"blueveil/collector/internal/auth"
	"blueveil/collector/internal/store"
)

func mustHash(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func gatedServer(t *testing.T) (*Server, map[string]string) {
	t.Helper()
	srv := NewServer(store.NewMemoryBackend())
	secrets := map[string]string{
		"READ":     "read-secret",
		"RESPOND":  "respond-secret",
		"VALIDATE": "validate-secret",
		"ADMIN":    "admin-secret",
	}
	var keys []auth.Key
	for role, secret := range secrets {
		keys = append(keys, auth.Key{ID: "k-" + role, Role: role, Hash: mustHash(t, secret)})
	}
	a, err := auth.NewAPIKeyAuthenticator(keys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	srv.UseAuth(a, nil)
	return srv, secrets
}

func gatedGet(t *testing.T, srv *Server, path, secret string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func TestGateDeniesUnauthenticated(t *testing.T) {
	srv, _ := gatedServer(t)
	for _, p := range []string{
		"/api/v1/assets", "/api/v1/telemetry", "/api/v1/incidents",
		"/api/v1/grc/controls", "/api/v1/supply-chain/components",
		"/api/v1/continuous-security/checks",
	} {
		if code := gatedGet(t, srv, p, ""); code != 401 {
			t.Errorf("GET %s without credential: want 401, got %d", p, code)
		}
		if code := gatedGet(t, srv, p, "wrong-secret"); code != 401 {
			t.Errorf("GET %s with bad credential: want 401, got %d", p, code)
		}
	}
}

func TestGateHealthStaysPublic(t *testing.T) {
	srv, _ := gatedServer(t)
	if code := gatedGet(t, srv, "/api/v1/healthz", ""); code != 200 {
		t.Errorf("healthz must stay public, got %d", code)
	}
}

func TestGateReadRoleReads(t *testing.T) {
	srv, secrets := gatedServer(t)
	if code := gatedGet(t, srv, "/api/v1/assets", secrets["READ"]); code != 200 {
		t.Errorf("READ key must read, got %d", code)
	}
	if code := gatedGet(t, srv, "/api/v1/supply-chain/components", secrets["RESPOND"]); code != 200 {
		t.Errorf("RESPOND key must read (hierarchy), got %d", code)
	}
}

func TestGateInsufficientRoleDenied(t *testing.T) {
	srv, secrets := gatedServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/observations", nil)
	req.Header.Set("Authorization", "Bearer "+secrets["READ"])
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("READ key POST observations: want 403, got %d", rec.Code)
	}
	if code := gatedGet(t, srv, "/api/v1/assets/ast-x/lifecycle", secrets["RESPOND"]); code != 403 && code != 405 {
		t.Errorf("RESPOND key on admin path: want 403/405, got %d", code)
	}
}

func TestGateErrorsAreBounded(t *testing.T) {
	srv, _ := gatedServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer sekrit")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "sekrit") {
		t.Fatalf("401 response leaks credential: %s", body)
	}
	if !strings.Contains(body, "UNAUTHORIZED") {
		t.Fatalf("401 must carry bounded code: %s", body)
	}
}

func TestGateRequestIDPresent(t *testing.T) {
	srv, _ := gatedServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatalf("responses must carry X-Request-ID")
	}
	// Client-provided IDs propagate (correlation across tiers).
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/healthz", nil)
	req2.Header.Set("X-Request-ID", "corr-123")
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Header().Get("X-Request-ID") != "corr-123" {
		t.Fatalf("client request id must propagate, got %q", rec2.Header().Get("X-Request-ID"))
	}
}
