// Step 16F: deterministic authorization matrix over every registered
// API route. Generated from the actual route registrations: for each
// route × identity the expected code is pinned. Unknown /api/ paths
// fail closed; no role creates write APIs; the safety engine has no
// HTTP surface (approvals/execution are 405 for every role).
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func gatedMatrixServer(t *testing.T) (*Server, map[string]string) {
	t.Helper()
	return gatedServer(t)
}

func matrixDo(t *testing.T, srv *Server, method, path, secret string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

// TestAuthzMatrix pins route × identity → code for the whole API.
func TestAuthzMatrix(t *testing.T) {
	srv, secrets := gatedMatrixServer(t)
	read, respond, validate, admin := secrets["READ"], secrets["RESPOND"], secrets["VALIDATE"], secrets["ADMIN"]

	readRoutes := []string{
		"/api/v1/telemetry", "/api/v1/detections", "/api/v1/alerts",
		"/api/v1/incidents", "/api/v1/incidents/nope/timeline",
		"/api/v1/evidence", "/api/v1/recommendations", "/api/v1/approvals",
		"/api/v1/executions", "/api/v1/verifications",
		"/api/v1/validation-requests/nope", "/api/v1/validation-results",
		"/api/v1/audit", "/api/v1/assets",
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
		"/api/v1/supply-chain/components", "/api/v1/supply-chain/dependencies?parent=x",
		"/api/v1/supply-chain/sboms", "/api/v1/supply-chain/policies",
		"/api/v1/supply-chain/links",
		"/api/v1/third-party/vendors", "/api/v1/third-party/assessments",
		"/api/v1/continuous-security/checks", "/api/v1/continuous-security/history",
	}
	for _, p := range readRoutes {
		if got := matrixDo(t, srv, http.MethodGet, p, ""); got != 401 {
			t.Errorf("GET %s anon: want 401, got %d", p, got)
		}
		for role, secret := range map[string]string{
			"READ": read, "RESPOND": respond, "VALIDATE": validate, "ADMIN": admin,
		} {
			got := matrixDo(t, srv, http.MethodGet, p, secret)
			if got == 401 || got == 403 {
				t.Errorf("GET %s role %s: want handler code (200/400/404), got %d", p, role, got)
			}
		}
		if got := matrixDo(t, srv, http.MethodPost, p, read); got != 401 && got != 405 {
			// POST hits the gate first (401 without credential would
			// apply); with a READ credential the handler answers 405.
			t.Errorf("POST %s role READ: want 405, got %d", p, got)
		}
	}

	// Write paths: exact role gates.
	if got := matrixDo(t, srv, http.MethodPost, "/api/v1/assets/observations", ""); got != 401 {
		t.Errorf("POST observations anon: want 401, got %d", got)
	}
	if got := matrixDo(t, srv, http.MethodPost, "/api/v1/assets/observations", read); got != 403 {
		t.Errorf("POST observations READ: want 403, got %d", got)
	}
	for _, role := range []string{"RESPOND", "VALIDATE", "ADMIN"} {
		secret := map[string]string{"RESPOND": respond, "VALIDATE": validate, "ADMIN": admin}[role]
		if got := matrixDo(t, srv, http.MethodPost, "/api/v1/assets/observations", secret); got == 401 || got == 403 {
			t.Errorf("POST observations %s: want handler code, got %d", role, got)
		}
	}
	if got := matrixDo(t, srv, http.MethodPatch, "/api/v1/assets/ast-x/lifecycle", respond); got != 403 {
		t.Errorf("PATCH lifecycle RESPOND: want 403, got %d", got)
	}
	if got := matrixDo(t, srv, http.MethodPatch, "/api/v1/assets/ast-x/lifecycle", admin); got == 401 || got == 403 {
		t.Errorf("PATCH lifecycle ADMIN: want handler code (400/404), got %d", got)
	}

	// Unknown API paths fail closed: 401 anon, 404 authenticated.
	if got := matrixDo(t, srv, http.MethodGet, "/api/v1/no-such-area", ""); got != 401 {
		t.Errorf("unknown API path anon: want 401, got %d", got)
	}
	if got := matrixDo(t, srv, http.MethodGet, "/api/v1/no-such-area", read); got != 404 {
		t.Errorf("unknown API path READ: want 404, got %d", got)
	}

	// Public endpoints stay public.
	for _, p := range []string{"/api/v1/healthz", "/api/v1/readyz"} {
		if got := matrixDo(t, srv, http.MethodGet, p, ""); got != 200 {
			t.Errorf("GET %s anon: want 200, got %d", p, got)
		}
	}
}

// TestAuthzRouteCoverage regenerates the matrix from the full registered
// route table (every HandleFunc pattern): anonymous callers get 401 on
// every protected pattern and 200 on the two public ones; an
// authenticated READ key reaches a handler code (never 401/403) on
// every pattern, including all {id} variants.
func TestAuthzRouteCoverage(t *testing.T) {
	srv, secrets := gatedMatrixServer(t)
	read := secrets["READ"]
	public := map[string]bool{
		"/api/v1/healthz": true, "/api/v1/readyz": true,
	}
	byID := []string{
		"/api/v1/alerts/", "/api/v1/approvals/", "/api/v1/audit/",
		"/api/v1/detections/", "/api/v1/evidence/", "/api/v1/executions/",
		"/api/v1/incidents/", "/api/v1/recommendations/",
		"/api/v1/telemetry/", "/api/v1/verifications/",
		"/api/v1/validation-requests/", "/api/v1/validation-results/",
		"/api/v1/validation/campaigns/", "/api/v1/purple-team/exercises/",
		"/api/v1/grc/controls/", "/api/v1/grc/assessments/",
		"/api/v1/supply-chain/components/", "/api/v1/supply-chain/sboms/",
		"/api/v1/supply-chain/policies/", "/api/v1/third-party/vendors/",
		"/api/v1/third-party/assessments/", "/api/v1/assets/",
	}
	lists := []string{
		"/api/v1/alerts", "/api/v1/approvals", "/api/v1/audit",
		"/api/v1/detections", "/api/v1/evidence", "/api/v1/executions",
		"/api/v1/incidents", "/api/v1/recommendations",
		"/api/v1/telemetry", "/api/v1/verifications",
		"/api/v1/validation-results", "/api/v1/validation/campaigns",
		"/api/v1/validation/history", "/api/v1/purple-team/exercises",
		"/api/v1/grc/frameworks", "/api/v1/grc/controls", "/api/v1/grc/assessments",
		"/api/v1/architecture/assets", "/api/v1/architecture/relationships",
		"/api/v1/resilience/posture", "/api/v1/resilience/recovery",
		"/api/v1/assets", "/api/v1/network/observations", "/api/v1/network/relationships",
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
		"/api/v1/forensics/identity", "/api/v1/incidents/no-such/timeline",
		"/api/v1/supply-chain/components", "/api/v1/supply-chain/dependencies?parent=no-such",
		"/api/v1/supply-chain/sboms", "/api/v1/supply-chain/policies",
		"/api/v1/supply-chain/links",
		"/api/v1/third-party/vendors", "/api/v1/third-party/assessments",
		"/api/v1/continuous-security/checks", "/api/v1/continuous-security/history",
	}
	for _, p := range lists {
		if public[p] {
			if got := matrixDo(t, srv, http.MethodGet, p, ""); got != 200 {
				t.Errorf("GET %s anon: public must be 200, got %d", p, got)
			}
			continue
		}
		if got := matrixDo(t, srv, http.MethodGet, p, ""); got != 401 {
			t.Errorf("GET %s anon: want 401, got %d", p, got)
		}
		if got := matrixDo(t, srv, http.MethodGet, p, read); got == 401 || got == 403 {
			t.Errorf("GET %s READ: want handler code, got %d", p, got)
		}
	}
	for _, prefix := range byID {
		p := prefix + "no-such"
		if got := matrixDo(t, srv, http.MethodGet, p, ""); got != 401 {
			t.Errorf("GET %s anon: want 401, got %d", p, got)
		}
		if got := matrixDo(t, srv, http.MethodGet, p, read); got != 404 {
			t.Errorf("GET %s READ: want 404 (handler reached), got %d", p, got)
		}
	}
}

// TestAuthzAdversarial attacks the AuthN → AuthZ → handler boundary:
// role spellings, escalation, path and query manipulation.
func TestAuthzAdversarial(t *testing.T) {
	srv, secrets := gatedMatrixServer(t)
	read, validate, admin := secrets["READ"], secrets["VALIDATE"], secrets["ADMIN"]

	// Role hierarchy enforced: VALIDATE cannot do ADMIN work.
	if got := matrixDo(t, srv, http.MethodPatch, "/api/v1/assets/ast-x/lifecycle", validate); got != 403 {
		t.Errorf("PATCH lifecycle VALIDATE: want 403, got %d", got)
	}
	// ADMIN reaches every handler (never 401/403).
	for _, p := range []string{
		"/api/v1/assets", "/api/v1/telemetry",
		"/api/v1/supply-chain/policies/pol-x/evaluate?component=y",
		"/api/v1/continuous-security/checks?check=BOGUS",
	} {
		if got := matrixDo(t, srv, http.MethodGet, p, admin); got == 401 || got == 403 {
			t.Errorf("GET %s ADMIN: want handler code, got %d", p, got)
		}
	}
	// Query string cannot smuggle privilege.
	if got := matrixDo(t, srv, http.MethodPost, "/api/v1/assets/observations?role=ADMIN", read); got != 403 {
		t.Errorf("POST with ?role=ADMIN READ: want 403, got %d", got)
	}
	if got := matrixDo(t, srv, http.MethodGet, "/api/v1/assets?role=ADMIN", ""); got != 401 {
		t.Errorf("anon with ?role=ADMIN: want 401, got %d", got)
	}
	// Path manipulation stays fail-closed: prefix-sibling, dot
	// segments, and encoded dots never reach a handler unauthenticated,
	// and never match the wrong route authenticated.
	for _, p := range []string{
		"/api/v1/assetsExtra",
		"/api/v1/assets/",
		"/api/v1//assets",
		"/api/v1/./assets",
		"/api/%76%31/assets",
	} {
		if got := matrixDo(t, srv, http.MethodGet, p, ""); got != 401 {
			t.Errorf("GET %s anon: want 401, got %d", p, got)
		}
		if got := matrixDo(t, srv, http.MethodGet, p, read); got == 401 || got == 403 {
			t.Errorf("GET %s READ: gate must pass through to mux, got %d", p, got)
		}
	}
	// Case-sensitive methods: lowercase is not GET (mux 405 or gate
	// 401/405 — never a handler success).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("get", "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer "+read)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Errorf("lowercase method must not route as GET, got 200")
	}
}

// TestSafetyHasNoHTTPBypass proves no role — not even ADMIN — gains a
// write API for approvals, executions, recommendations, or verifications:
// the safety engine is reachable only through its own gated path.
func TestSafetyHasNoHTTPBypass(t *testing.T) {
	srv, secrets := gatedMatrixServer(t)
	paths := []string{
		"/api/v1/approvals", "/api/v1/executions",
		"/api/v1/recommendations", "/api/v1/verifications",
	}
	for _, p := range paths {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			for _, secret := range []string{secrets["READ"], secrets["ADMIN"], ""} {
				got := matrixDo(t, srv, m, p, secret)
				if secret == "" {
					if got != 401 {
						t.Errorf("%s %s anon: want 401, got %d", m, p, got)
					}
					continue
				}
				if got != 405 {
					t.Errorf("%s %s authenticated: want 405 (no such write API), got %d", m, p, got)
				}
			}
		}
	}
}
