// RED: supply-chain / third-party / continuous-security read endpoints.
// Read-only, bounded, deterministic; unknown ids 404; POST rejected;
// no scores, no vulnerability verdicts, no trust states.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"blueveil/collector/internal/store"
	"blueveil/collector/internal/supplychain"
)

var supplyT0 = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func seedSupply(t *testing.T) *Server {
	t.Helper()
	be := store.NewMemoryBackend()
	ctx := context.Background()
	leftPad := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: "left-pad",
		Version: "1.0.0", License: "MIT", LicenseSource: "declared",
		Provenance: supplychain.ProvenanceLockfile,
		Source:     "seed-lab-supply-chain", ObservedAt: supplyT0,
		Status: supplychain.StatusObserved,
	}
	requests := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "pypi", Name: "requests",
		Version: "2.31.0", License: "Apache-2.0", LicenseSource: "declared",
		Provenance: supplychain.ProvenanceManifest,
		Source:     "seed-lab-supply-chain", ObservedAt: supplyT0,
		Status: supplychain.StatusVerified, StatusBasis: "lockfile digest recorded",
	}
	for _, c := range []supplychain.Component{leftPad, requests} {
		if err := be.Components.Create(ctx, c); err != nil {
			t.Fatalf("component: %v", err)
		}
	}
	if err := be.Dependencies.Append(ctx, supplychain.Dependency{
		ParentID: requests.ID(), ParentKind: "component",
		ChildID: leftPad.ID(), Kind: supplychain.DependencyDependsOn,
		Source: "seed-lab-supply-chain", ObservedAt: supplyT0,
	}); err != nil {
		t.Fatalf("dependency: %v", err)
	}
	if err := be.SBOMs.Create(ctx, supplychain.SBOM{
		Format: supplychain.SBOMCycloneDX, FormatVersion: "1.5",
		ComponentIDs: []string{leftPad.ID()},
		GeneratedAt:  supplyT0, Source: "seed-lab-supply-chain",
	}); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if err := be.Policies.Create(ctx, supplychain.SupplyPolicy{
		ID: "pol-npm-only", Name: "npm only", Source: "seed-lab-supply-chain",
		AllowedEcosystems: []string{"npm"},
	}); err != nil {
		t.Fatalf("policy: %v", err)
	}
	vend := supplychain.Vendor{
		Name: "Example CDN", Service: "edge cache", Category: "hosting",
		Environment: "lab", Status: supplychain.VendorActive,
		Source: "seed-lab-supply-chain", ObservedAt: supplyT0,
	}
	if err := be.Vendors.Create(ctx, vend); err != nil {
		t.Fatalf("vendor: %v", err)
	}
	if err := be.VendorAssessments.Create(ctx, supplychain.VendorAssessment{
		VendorID: vend.ID(), Status: supplychain.VendorReviewed,
		Assessor: "seed-lab-supply-chain", ObservedAt: supplyT0,
		EvidenceIDs: []string{"ev-1"},
	}); err != nil {
		t.Fatalf("vendor assessment: %v", err)
	}
	if err := be.SupplyLinks.Create(ctx, supplychain.SupplyLink{
		ControlID: "SC-1", SubjectKind: supplychain.LinkComponent,
		SubjectID: leftPad.ID(), Basis: "component observed in lab manifest",
	}); err != nil {
		t.Fatalf("supply link: %v", err)
	}
	return NewServer(be)
}

func TestSupplyComponents(t *testing.T) {
	srv := seedSupply(t)
	code, body := apiGet(t, srv, "/api/v1/supply-chain/components")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("want 2 components, got %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/supply-chain/components?type=LIBRARY&ecosystem=npm")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 npm library, got %d %+v", code, body)
	}
	row := body["data"].([]any)[0].(map[string]any)
	// License renders verbatim as declared; never enriched.
	if row["license"] != "MIT" || row["license_source"] != "declared" {
		t.Fatalf("license verbatim: %+v", row)
	}
	for k := range row {
		if k == "score" || k == "vulnerable" || k == "vulnerability" {
			t.Fatalf("no scores or vulnerability states: %+v", row)
		}
	}
	code, body = apiGet(t, srv, "/api/v1/supply-chain/components?status=OBSERVED")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("status filter: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/components?type=VULNERABLE"); code != 400 {
		t.Errorf("unbounded type must 400, got %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/components?status=SECURE"); code != 400 {
		t.Errorf("SECURE must be rejected, got %d", code)
	}
	id := row["id"].(string)
	code, body = apiGet(t, srv, "/api/v1/supply-chain/components/"+id)
	if code != 200 {
		t.Fatalf("get component: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/components/no-such"); code != 404 {
		t.Errorf("unknown component must 404, got %d", code)
	}
}

func TestSupplyDependencies(t *testing.T) {
	srv := seedSupply(t)
	code, body := apiGet(t, srv, "/api/v1/supply-chain/components?ecosystem=pypi")
	parent := body["data"].([]any)[0].(map[string]any)["id"].(string)
	code, body = apiGet(t, srv, "/api/v1/supply-chain/dependencies?parent="+parent)
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 child edge, got %d %+v", code, body)
	}
	child := body["data"].([]any)[0].(map[string]any)["child_id"].(string)
	code, body = apiGet(t, srv, "/api/v1/supply-chain/dependencies?child="+child)
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 parent edge, got %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/dependencies"); code != 400 {
		t.Errorf("unscoped dependency list must 400, got %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/dependencies?parent="+parent+"&kind=BOGUS"); code != 400 {
		t.Errorf("unbounded kind must 400, got %d", code)
	}
}

func TestSupplySBOMsAndPolicies(t *testing.T) {
	srv := seedSupply(t)
	code, body := apiGet(t, srv, "/api/v1/supply-chain/sboms")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 sbom, got %d %+v", code, body)
	}
	row := body["data"].([]any)[0].(map[string]any)
	if row["format"] != "CycloneDX" {
		t.Fatalf("sbom format: %+v", row)
	}
	if _, ok := row["component_ids"].([]any); !ok {
		t.Fatalf("component_ids must be an array: %+v", row)
	}
	id := row["id"].(string)
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/sboms/"+id); code != 200 {
		t.Errorf("get sbom: %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/sboms/no-such"); code != 404 {
		t.Errorf("unknown sbom must 404, got %d", code)
	}
	code, body = apiGet(t, srv, "/api/v1/supply-chain/policies")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 policy, got %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/supply-chain/components?ecosystem=pypi")
	comp := body["data"].([]any)[0].(map[string]any)["id"].(string)
	code, body = apiGet(t, srv, "/api/v1/supply-chain/policies/pol-npm-only/evaluate?component="+comp)
	if code != 200 {
		t.Fatalf("evaluate: %d %+v", code, body)
	}
	if body["data"].(map[string]any)["verdict"] != "VIOLATION" {
		t.Fatalf("pypi against npm-only must violate: %+v", body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/policies/no-such/evaluate?component="+comp); code != 404 {
		t.Errorf("unknown policy must 404, got %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/policies/pol-npm-only/evaluate"); code != 400 {
		t.Errorf("missing component must 400, got %d", code)
	}
}

func TestThirdParty(t *testing.T) {
	srv := seedSupply(t)
	code, body := apiGet(t, srv, "/api/v1/third-party/vendors")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 vendor, got %d %+v", code, body)
	}
	row := body["data"].([]any)[0].(map[string]any)
	for k := range row {
		if k == "trust" || k == "trustworthy" || k == "score" {
			t.Fatalf("no trust states or scores: %+v", row)
		}
	}
	code, body = apiGet(t, srv, "/api/v1/third-party/vendors?status=ACTIVE")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("status filter: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/third-party/vendors?status=TRUSTED"); code != 400 {
		t.Errorf("TRUSTED must be rejected, got %d", code)
	}
	id := row["id"].(string)
	if code, _ := apiGet(t, srv, "/api/v1/third-party/vendors/"+id); code != 200 {
		t.Errorf("get vendor: %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/third-party/vendors/no-such"); code != 404 {
		t.Errorf("unknown vendor must 404, got %d", code)
	}
	code, body = apiGet(t, srv, "/api/v1/third-party/assessments?vendor="+id)
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 assessment, got %d %+v", code, body)
	}
	ass := body["data"].([]any)[0].(map[string]any)
	if _, ok := ass["evidence_ids"].([]any); !ok {
		t.Fatalf("evidence_ids must be an array: %+v", ass)
	}
	code, body = apiGet(t, srv, "/api/v1/third-party/assessments?status=REVIEWED")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("status filter: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/third-party/assessments?status=CERTIFIED"); code != 400 {
		t.Errorf("CERTIFIED must be rejected, got %d", code)
	}
	aid := ass["id"].(string)
	if code, _ := apiGet(t, srv, "/api/v1/third-party/assessments/"+aid); code != 200 {
		t.Errorf("get assessment: %d", code)
	}
	if code, _ := apiGet(t, srv, "/api/v1/third-party/assessments/no-such"); code != 404 {
		t.Errorf("unknown assessment must 404, got %d", code)
	}
}

func TestSupplyLinks(t *testing.T) {
	srv := seedSupply(t)
	code, body := apiGet(t, srv, "/api/v1/supply-chain/links")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 link, got %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/supply-chain/links?control=SC-1&kind=component")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("control+kind filter: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/supply-chain/links?kind=timestamp"); code != 400 {
		t.Errorf("unbounded kind must 400, got %d", code)
	}
}

func TestContinuousSecurity(t *testing.T) {
	srv := seedSupply(t)
	// Default config requires nothing: every check NOT_APPLICABLE.
	code, body := apiGet(t, srv, "/api/v1/continuous-security/checks")
	if code != 200 {
		t.Fatalf("checks: %d %+v", code, body)
	}
	for _, r := range body["data"].([]any) {
		outcome := r.(map[string]any)["outcome"].(string)
		switch outcome {
		case "PASS", "FAIL", "NOT_APPLICABLE", "DISABLED":
		default:
			t.Fatalf("unbounded outcome %q", outcome)
		}
		if r.(map[string]any)["version"] != "1" {
			t.Fatalf("check version pinned: %+v", r)
		}
	}
	// SBOM required: covered component passes, uncovered fails.
	code, body = apiGet(t, srv, "/api/v1/continuous-security/checks?require_sbom=true&check=supply-missing-sbom")
	if code != 200 || dataLen(t, body) != 2 {
		t.Fatalf("want 2 C1 rows, got %d %+v", code, body)
	}
	seen := map[string]string{}
	for _, r := range body["data"].([]any) {
		m := r.(map[string]any)
		seen[m["subject_id"].(string)] = m["outcome"].(string)
	}
	if len(seen) != 2 {
		t.Fatalf("one row per subject: %+v", seen)
	}
	nPass, nFail := 0, 0
	for _, o := range seen {
		switch o {
		case "PASS":
			nPass++
		case "FAIL":
			nFail++
		default:
			t.Fatalf("C1 with require_sbom must be PASS or FAIL, got %q", o)
		}
	}
	if nPass != 1 || nFail != 1 {
		t.Fatalf("covered passes, uncovered fails: %+v", seen)
	}
	if code, _ := apiGet(t, srv, "/api/v1/continuous-security/checks?check=BOGUS"); code != 400 {
		t.Errorf("unbounded check must 400, got %d", code)
	}
	// Vendor window far in the past relative to seed instant: stale.
	code, body = apiGet(t, srv, "/api/v1/continuous-security/checks?vendor_window=1h&check=supply-stale-vendor-assessment")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("want 1 C4 row, got %d %+v", code, body)
	}
	if body["data"].([]any)[0].(map[string]any)["outcome"] != "FAIL" {
		t.Fatalf("ancient assessment past 1h window must fail: %+v", body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/continuous-security/checks?vendor_window=bogus"); code != 400 {
		t.Errorf("bad window must 400, got %d", code)
	}
	// History derives from stored state, oldest first.
	code, body = apiGet(t, srv, "/api/v1/continuous-security/history")
	if code != 200 || dataLen(t, body) != 4 {
		t.Fatalf("want 4 history rows (2 components + 1 assessment + 1 sbom), got %d %+v", code, body)
	}
	code, body = apiGet(t, srv, "/api/v1/continuous-security/history?kind=sbom")
	if code != 200 || dataLen(t, body) != 1 {
		t.Fatalf("kind filter: %d %+v", code, body)
	}
	if code, _ := apiGet(t, srv, "/api/v1/continuous-security/history?kind=trend"); code != 400 {
		t.Errorf("unbounded kind must 400, got %d", code)
	}
}

func TestSupplyMethodGuard(t *testing.T) {
	srv := seedSupply(t)
	for _, p := range []string{
		"/api/v1/supply-chain/components", "/api/v1/supply-chain/dependencies",
		"/api/v1/supply-chain/sboms", "/api/v1/supply-chain/policies",
		"/api/v1/supply-chain/links", "/api/v1/third-party/vendors",
		"/api/v1/third-party/assessments", "/api/v1/continuous-security/checks",
		"/api/v1/continuous-security/history",
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
