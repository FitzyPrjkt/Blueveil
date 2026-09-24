// Supply-chain / third-party / continuous-security read endpoints (13J):
// components, dependencies, SBOM metadata, policies (+ pure evaluation),
// vendors, vendor assessments, control links, on-demand continuous checks
// C1–C5, and derived posture history. All read-only over persisted
// metadata. Licenses render verbatim as declared; absence of information
// is NOT_ASSESSED/UNKNOWN; nothing here scores, certifies, remediates,
// installs, or contacts anything external.
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"blueveil/collector/internal/supplychain"
)

func registerSupplyChainRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/supply-chain/components", s.listComponents)
	s.mux.HandleFunc("/api/v1/supply-chain/components/", s.getComponent)
	s.mux.HandleFunc("/api/v1/supply-chain/dependencies", s.listDependencies)
	s.mux.HandleFunc("/api/v1/supply-chain/sboms", s.listSBOMs)
	s.mux.HandleFunc("/api/v1/supply-chain/sboms/", s.getSBOM)
	s.mux.HandleFunc("/api/v1/supply-chain/policies", s.listPolicies)
	s.mux.HandleFunc("/api/v1/supply-chain/policies/", s.getPolicyOrEvaluate)
	s.mux.HandleFunc("/api/v1/supply-chain/links", s.listSupplyLinks)
	s.mux.HandleFunc("/api/v1/third-party/vendors", s.listVendors)
	s.mux.HandleFunc("/api/v1/third-party/vendors/", s.getVendor)
	s.mux.HandleFunc("/api/v1/third-party/assessments", s.listVendorAssessments)
	s.mux.HandleFunc("/api/v1/third-party/assessments/", s.getVendorAssessment)
	s.mux.HandleFunc("/api/v1/continuous-security/checks", s.listContinuousChecks)
	s.mux.HandleFunc("/api/v1/continuous-security/history", s.listPostureHistory)
}

func componentJSON(c supplychain.Component) map[string]any {
	return map[string]any{
		"id": c.ID(), "type": string(c.Type), "ecosystem": c.Ecosystem,
		"namespace": c.Namespace, "name": c.Name, "version": c.Version,
		"requested_version": c.RequestedVersion, "resolved_version": c.ResolvedVersion,
		"digest": c.Digest, "source_revision": c.SourceRevision,
		"license": c.License, "license_source": c.LicenseSource,
		"provenance": string(c.Provenance), "source": c.Source,
		"observed_at": c.ObservedAt.UTC().Format(timeFormat),
		"status":      string(c.Status), "status_basis": c.StatusBasis,
	}
}

func validComponentType(v string) bool {
	switch supplychain.ComponentType(v) {
	case supplychain.ComponentPackage, supplychain.ComponentLibrary,
		supplychain.ComponentFramework, supplychain.ComponentContainerImage,
		supplychain.ComponentBinary, supplychain.ComponentSourceRepository,
		supplychain.ComponentBuildArtifact, supplychain.ComponentInfrastructureModule,
		supplychain.ComponentUnknown:
		return true
	}
	return false
}

func validComponentStatus(v string) bool {
	switch supplychain.ComponentStatus(v) {
	case supplychain.StatusObserved, supplychain.StatusVerified,
		supplychain.StatusOutdated, supplychain.StatusUnsupported,
		supplychain.StatusPolicyViolation, supplychain.StatusNotAssessed,
		supplychain.StatusUnknown:
		return true
	}
	return false
}

// listComponents serves GET persisted components with type/ecosystem/
// status filters.
func (s *Server) listComponents(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	typ := strings.ToUpper(strings.TrimSpace(q.Get("type")))
	if typ != "" && !validComponentType(typ) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown component type")
		return
	}
	ecosystem := strings.ToLower(strings.TrimSpace(q.Get("ecosystem")))
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" && !validComponentStatus(status) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown component status")
		return
	}
	list, err := s.backend.Components.List(r.Context())
	if err != nil {
		mapError(w, err, "components", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		if typ != "" && string(c.Type) != typ {
			continue
		}
		if ecosystem != "" && strings.ToLower(c.Ecosystem) != ecosystem {
			continue
		}
		if status != "" && string(c.Status) != status {
			continue
		}
		out = append(out, componentJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getComponent serves GET one component by id.
func (s *Server) getComponent(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/supply-chain/components/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	c, err := s.backend.Components.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "component", id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": componentJSON(c)})
}

func dependencyJSON(d supplychain.Dependency) map[string]any {
	return map[string]any{
		"parent_id": d.ParentID, "parent_kind": d.ParentKind,
		"child_id": d.ChildID, "kind": string(d.Kind),
		"source": d.Source, "observed_at": d.ObservedAt.UTC().Format(timeFormat),
	}
}

// listDependencies serves GET edges scoped by parent or child id, with an
// optional bounded kind filter. Unscoped listing is refused: edges are
// only meaningful from an endpoint.
func (s *Server) listDependencies(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	parent := strings.TrimSpace(q.Get("parent"))
	child := strings.TrimSpace(q.Get("child"))
	if parent == "" && child == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "parent or child id required")
		return
	}
	kind := strings.ToUpper(strings.TrimSpace(q.Get("kind")))
	if kind != "" {
		switch supplychain.DependencyKind(kind) {
		case supplychain.DependencyDependsOn, supplychain.DependencyContains,
			supplychain.DependencyBuiltFrom, supplychain.DependencyDerivedFrom:
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown dependency kind")
			return
		}
	}
	ctx := r.Context()
	var edges []supplychain.Dependency
	if parent != "" {
		kids, err := s.backend.Dependencies.Children(r.Context(), parent)
		if err != nil {
			mapError(w, err, "dependencies", parent)
			return
		}
		edges = append(edges, kids...)
	}
	if child != "" {
		pars, err := s.backend.Dependencies.Parents(r.Context(), child)
		if err != nil {
			mapError(w, err, "dependencies", child)
			return
		}
		edges = append(edges, pars...)
	}
	out := make([]map[string]any, 0, len(edges))
	for _, d := range edges {
		if kind != "" && string(d.Kind) != kind {
			continue
		}
		out = append(out, dependencyJSON(d))
	}
	if len(edges) == 0 {
		// Distinguish "known endpoint, no edges" from a typo'd id:
		// dependency endpoints are assets or components, and unknown
		// scopes 404 like every other scoped route.
		for _, id := range []string{parent, child} {
			if id == "" {
				continue
			}
			if _, err := s.backend.Assets.Get(ctx, id); err == nil {
				continue
			}
			if _, err := s.backend.Components.Get(ctx, id); err != nil {
				mapError(w, err, "dependency endpoint", id)
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func sbomJSON(sb supplychain.SBOM) map[string]any {
	ids := sb.ComponentIDs
	if ids == nil {
		ids = []string{}
	}
	return map[string]any{
		"id": sb.ID(), "format": string(sb.Format), "format_version": sb.FormatVersion,
		"component_ids": ids, "generated_at": sb.GeneratedAt.UTC().Format(timeFormat),
		"source": sb.Source, "digest": sb.Digest,
	}
}

// listSBOMs serves GET persisted SBOM metadata records.
func (s *Server) listSBOMs(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	list, err := s.backend.SBOMs.List(r.Context())
	if err != nil {
		mapError(w, err, "sboms", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, sb := range list {
		out = append(out, sbomJSON(sb))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getSBOM serves GET one SBOM metadata record by id.
func (s *Server) getSBOM(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/supply-chain/sboms/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	sb, err := s.backend.SBOMs.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "sbom", id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": sbomJSON(sb)})
}

func policyJSON(p supplychain.SupplyPolicy) map[string]any {
	return map[string]any{
		"id": p.ID, "name": p.Name, "source": p.Source,
		"allowed_ecosystems": strList(p.AllowedEcosystems),
		"allowed_licenses":   strList(p.AllowedLicenses),
		"allowed_provenance": provenanceList(p.AllowedProvenance),
		"require_digest":     p.RequireDigest,
		"min_versions":       p.MinVersions,
		"prohibited":         strList(p.Prohibited),
		"require_sbom":       p.RequireSBOM,
		"approved_repos":     strList(p.ApprovedRepos),
	}
}

func provenanceList(in []supplychain.Provenance) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, string(p))
	}
	return out
}

// listPolicies serves GET persisted declarative policies.
func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	list, err := s.backend.Policies.List(r.Context())
	if err != nil {
		mapError(w, err, "policies", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, p := range list {
		out = append(out, policyJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getPolicyOrEvaluate serves GET one policy by id, or a pure evaluation
// of that policy against a stored component at {id}/evaluate.
func (s *Server) getPolicyOrEvaluate(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/supply-chain/policies/")
	if rest == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	if id, isEval := strings.CutSuffix(rest, "/evaluate"); isEval {
		if id == "" || strings.Contains(id, "/") {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
			return
		}
		s.evaluatePolicy(w, r, id)
		return
	}
	if strings.Contains(rest, "/") {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	p, err := s.backend.Policies.Get(r.Context(), rest)
	if err != nil {
		mapError(w, err, "policy", rest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": policyJSON(p)})
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request, policyID string) {
	compID := strings.TrimSpace(r.URL.Query().Get("component"))
	if compID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "component id required")
		return
	}
	p, err := s.backend.Policies.Get(r.Context(), policyID)
	if err != nil {
		mapError(w, err, "policy", policyID)
		return
	}
	c, err := s.backend.Components.Get(r.Context(), compID)
	if err != nil {
		mapError(w, err, "component", compID)
		return
	}
	res := supplychain.EvaluatePolicy(c, p)
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"policy_id": res.PolicyID, "component_id": res.ComponentID,
		"verdict": string(res.Verdict), "reasons": strList(res.Reasons),
	}})
}

func supplyLinkJSON(l supplychain.SupplyLink) map[string]any {
	return map[string]any{
		"id": l.ID(), "control_id": l.ControlID,
		"subject_kind": string(l.SubjectKind), "subject_id": l.SubjectID,
		"basis": l.Basis,
	}
}

// listSupplyLinks serves GET control→subject citations with control/kind
// filters.
func (s *Server) listSupplyLinks(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	control := strings.TrimSpace(q.Get("control"))
	kind := strings.ToLower(strings.TrimSpace(q.Get("kind")))
	if kind != "" {
		switch supplychain.LinkSubjectKind(kind) {
		case supplychain.LinkComponent, supplychain.LinkVendor, supplychain.LinkSBOM:
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown link subject kind")
			return
		}
	}
	list, err := s.backend.SupplyLinks.List(r.Context())
	if err != nil {
		mapError(w, err, "supply links", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, l := range list {
		if control != "" && l.ControlID != control {
			continue
		}
		if kind != "" && string(l.SubjectKind) != kind {
			continue
		}
		out = append(out, supplyLinkJSON(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func vendorJSON(v supplychain.Vendor) map[string]any {
	return map[string]any{
		"id": v.ID(), "name": v.Name, "service": v.Service,
		"category": v.Category, "environment": v.Environment,
		"status": string(v.Status), "source": v.Source,
		"observed_at": v.ObservedAt.UTC().Format(timeFormat),
	}
}

func validVendorStatus(v string) bool {
	switch supplychain.VendorStatus(v) {
	case supplychain.VendorActive, supplychain.VendorInactive,
		supplychain.VendorUnknown, supplychain.VendorNotAssessed:
		return true
	}
	return false
}

// listVendors serves GET declared vendors with a status filter.
func (s *Server) listVendors(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && !validVendorStatus(status) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown vendor status")
		return
	}
	list, err := s.backend.Vendors.List(r.Context())
	if err != nil {
		mapError(w, err, "vendors", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, v := range list {
		if status != "" && string(v.Status) != status {
			continue
		}
		out = append(out, vendorJSON(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getVendor serves GET one vendor by id.
func (s *Server) getVendor(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/third-party/vendors/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	v, err := s.backend.Vendors.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "vendor", id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": vendorJSON(v)})
}

func vendorAssessmentJSON(a supplychain.VendorAssessment) map[string]any {
	return map[string]any{
		"id": a.ID(), "vendor_id": a.VendorID, "status": string(a.Status),
		"assessor": a.Assessor, "observed_at": a.ObservedAt.UTC().Format(timeFormat),
		"evidence_ids": strList(a.EvidenceIDs), "note": a.Note,
	}
}

func validVendorAssessmentStatus(v string) bool {
	switch supplychain.VendorAssessmentStatus(v) {
	case supplychain.VendorReviewed, supplychain.VendorRequirementDeclared,
		supplychain.VendorNotAssessedStatus, supplychain.VendorUnknownStatus:
		return true
	}
	return false
}

// listVendorAssessments serves GET assessments with status/vendor filters.
func (s *Server) listVendorAssessments(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" && !validVendorAssessmentStatus(status) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown vendor assessment status")
		return
	}
	vendor := strings.TrimSpace(q.Get("vendor"))
	list, err := s.backend.VendorAssessments.List(r.Context())
	if err != nil {
		mapError(w, err, "vendor assessments", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		if status != "" && string(a.Status) != status {
			continue
		}
		if vendor != "" && a.VendorID != vendor {
			continue
		}
		out = append(out, vendorAssessmentJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getVendorAssessment serves GET one vendor assessment by id.
func (s *Server) getVendorAssessment(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/third-party/assessments/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	a, err := s.backend.VendorAssessments.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "vendor assessment", id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": vendorAssessmentJSON(a)})
}

func checkJSON(res supplychain.CheckResult) map[string]any {
	return map[string]any{
		"rule_id": string(res.RuleID), "version": res.Version,
		"subject_id": res.SubjectID, "outcome": string(res.Outcome),
		"basis": res.Basis,
	}
}

// listContinuousChecks evaluates C1–C5 on demand over stored state with an
// explicit query-supplied configuration. Zero configuration disables
// every dimension (NOT_APPLICABLE) rather than implying verdicts.
// Regression (C5) has no recorded previous state, so it always reports
// NOT_APPLICABLE — regression is never inferred from nothing.
func (s *Server) listContinuousChecks(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	only := supplychain.CheckID(strings.ToLower(strings.TrimSpace(q.Get("check"))))
	if only != "" {
		switch only {
		case supplychain.CheckIDMissingSBOM, supplychain.CheckIDUnverifiedProvenance,
			supplychain.CheckIDPolicyViolation, supplychain.CheckIDStaleVendor,
			supplychain.CheckIDRegression:
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown check id")
			return
		}
	}
	cfg := supplychain.CheckConfig{}
	var err error
	if v := strings.TrimSpace(q.Get("require_sbom")); v != "" {
		if cfg.RequireSBOM, err = strconv.ParseBool(v); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "bad require_sbom")
			return
		}
	}
	if v := strings.TrimSpace(q.Get("require_provenance")); v != "" {
		if cfg.RequireProvenance, err = strconv.ParseBool(v); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "bad require_provenance")
			return
		}
	}
	if v := strings.TrimSpace(q.Get("allowed_provenance")); v != "" {
		for _, p := range strings.Split(v, ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			switch supplychain.Provenance(p) {
			case supplychain.ProvenanceManifest, supplychain.ProvenanceLockfile,
				supplychain.ProvenanceBuildMetadata, supplychain.ProvenanceContainerMetadata,
				supplychain.ProvenanceSourceRepository, supplychain.ProvenanceDeploymentObservation,
				supplychain.ProvenanceOperatorDeclaration, supplychain.ProvenanceSBOMImport:
				cfg.AllowedProvenance = append(cfg.AllowedProvenance, supplychain.Provenance(p))
			default:
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown provenance "+p)
				return
			}
		}
	}
	for _, id := range q["policy"] {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		p, perr := s.backend.Policies.Get(r.Context(), id)
		if perr != nil {
			mapError(w, perr, "policy", id)
			return
		}
		cfg.Policies = append(cfg.Policies, p)
	}
	if v := strings.TrimSpace(q.Get("vendor_window")); v != "" {
		if cfg.VendorWindow, err = time.ParseDuration(v); err != nil || cfg.VendorWindow < 0 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "bad vendor_window")
			return
		}
	}
	ctx := r.Context()
	comps, err := s.backend.Components.List(ctx)
	if err != nil {
		mapError(w, err, "components", "")
		return
	}
	sboms, err := s.backend.SBOMs.List(ctx)
	if err != nil {
		mapError(w, err, "sboms", "")
		return
	}
	vendors, err := s.backend.Vendors.List(ctx)
	if err != nil {
		mapError(w, err, "vendors", "")
		return
	}
	assessments, err := s.backend.VendorAssessments.List(ctx)
	if err != nil {
		mapError(w, err, "vendor assessments", "")
		return
	}
	now := time.Now().UTC()
	want := func(id supplychain.CheckID) bool { return only == "" || only == id }
	out := make([]map[string]any, 0)
	for _, c := range comps {
		if want(supplychain.CheckIDMissingSBOM) {
			out = append(out, checkJSON(supplychain.CheckMissingSBOM(c, sboms, cfg)))
		}
		if want(supplychain.CheckIDUnverifiedProvenance) {
			out = append(out, checkJSON(supplychain.CheckUnverifiedProvenance(c, cfg)))
		}
		if want(supplychain.CheckIDPolicyViolation) {
			out = append(out, checkJSON(supplychain.CheckPolicyViolation(c, cfg)))
		}
		if want(supplychain.CheckIDRegression) {
			out = append(out, checkJSON(supplychain.CheckRegression(c.ID(), c, nil, cfg)))
		}
	}
	for _, v := range vendors {
		if want(supplychain.CheckIDStaleVendor) {
			out = append(out, checkJSON(supplychain.CheckStaleVendor(v.ID(), assessments, cfg, now)))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func historyJSON(e supplychain.HistoryEntry) map[string]any {
	return map[string]any{
		"id": e.ID, "occurred_at": e.OccurredAt.UTC().Format(timeFormat),
		"kind": e.Kind, "subject_id": e.SubjectID, "summary": e.Summary,
	}
}

// listPostureHistory serves GET time-ordered posture observations derived
// from stored state, with a bounded kind filter.
func (s *Server) listPostureHistory(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	if kind != "" {
		switch kind {
		case "component", "vendor-assessment", "sbom":
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown history kind")
			return
		}
	}
	ctx := r.Context()
	comps, err := s.backend.Components.List(ctx)
	if err != nil {
		mapError(w, err, "components", "")
		return
	}
	assessments, err := s.backend.VendorAssessments.List(ctx)
	if err != nil {
		mapError(w, err, "vendor assessments", "")
		return
	}
	sboms, err := s.backend.SBOMs.List(ctx)
	if err != nil {
		mapError(w, err, "sboms", "")
		return
	}
	out := make([]map[string]any, 0)
	for _, e := range supplychain.PostureHistory(comps, assessments, sboms) {
		if kind != "" && e.Kind != kind {
			continue
		}
		out = append(out, historyJSON(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}
