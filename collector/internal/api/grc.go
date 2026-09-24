// Governance read endpoints (13I): frameworks, controls, assessments,
// architecture context, and resilience posture. All read-only over the
// static baseline catalog plus persisted assessments/records. Unknown is
// reported as unknown; nothing here scores, certifies, or remediates.
package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/grc"
)

func registerGRCRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/grc/frameworks", s.listFrameworks)
	s.mux.HandleFunc("/api/v1/grc/controls", s.listControls)
	s.mux.HandleFunc("/api/v1/grc/controls/", s.getControl)
	s.mux.HandleFunc("/api/v1/grc/assessments", s.listAssessments)
	s.mux.HandleFunc("/api/v1/grc/assessments/", s.getAssessment)
	s.mux.HandleFunc("/api/v1/architecture/assets", s.listArchitectureAssets)
	s.mux.HandleFunc("/api/v1/architecture/relationships", s.listArchitectureRelationships)
	s.mux.HandleFunc("/api/v1/resilience/posture", s.listResiliencePosture)
	s.mux.HandleFunc("/api/v1/resilience/recovery", s.listResilienceRecovery)
}

func frameworkJSON(fw grc.Framework) map[string]any {
	return map[string]any{
		"id": fw.ID, "version": fw.Version,
		"kind": string(fw.Kind), "title": fw.Title,
	}
}

// listFrameworks serves GET the known framework catalog (static,
// deterministic).
func (s *Server) listFrameworks(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": []map[string]any{frameworkJSON(grc.BaselineFramework())}})
}

func controlJSON(c grc.Control) map[string]any {
	return map[string]any{
		"id": c.ID, "title": c.Title, "description": c.Description,
		"domain": string(c.Domain), "framework": c.Framework,
		"framework_version": c.FrameworkVersion,
		"implementation":    string(c.Implementation),
	}
}

// listControls serves GET the baseline catalog with framework/domain/
// implementation filters.
func (s *Server) listControls(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	fw := strings.TrimSpace(q.Get("framework"))
	domain := strings.ToLower(strings.TrimSpace(q.Get("domain")))
	if domain != "" {
		switch grc.Domain(domain) {
		case grc.DomainNetwork, grc.DomainApplication, grc.DomainEndpoint,
			grc.DomainServer, grc.DomainContainer, grc.DomainCloud,
			grc.DomainIdentity, grc.DomainAuth, grc.DomainData,
			grc.DomainWAF, grc.DomainGovernance, grc.DomainResilience:
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown control domain")
			return
		}
	}
	impl := strings.ToUpper(strings.TrimSpace(q.Get("implementation")))
	if impl != "" {
		switch impl {
		case "IMPLEMENTED", "PARTIAL", "NOT_IMPLEMENTED", "UNKNOWN":
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown implementation status")
			return
		}
	}
	out := make([]map[string]any, 0)
	for _, c := range grc.BaselineControls() {
		if fw != "" && c.Framework != fw {
			continue
		}
		if domain != "" && string(c.Domain) != domain {
			continue
		}
		if impl != "" && string(c.Implementation) != impl {
			continue
		}
		out = append(out, controlJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getControl serves GET one catalog control by id.
func (s *Server) getControl(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/grc/controls/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	for _, c := range grc.BaselineControls() {
		if c.ID == id {
			writeJSON(w, http.StatusOK, map[string]any{"data": controlJSON(c)})
			return
		}
	}
	writeError(w, http.StatusNotFound, "NOT_FOUND", "control "+id+" not found")
}

func assessmentJSON(a grc.Assessment) map[string]any {
	evIDs := a.EvidenceIDs
	if evIDs == nil {
		evIDs = []string{}
	}
	return map[string]any{
		"id": a.ID(), "control_id": a.ControlID, "target": a.Target,
		"status": string(a.Status), "assessor": a.Assessor,
		"observed_at":  a.ObservedAt.UTC().Format(timeFormat),
		"evidence_ids": evIDs, "basis": a.Basis, "notes": a.Notes,
		"risk": string(a.Risk), "risk_basis": a.RiskBasis,
	}
}

func validAssessmentStatus(s string) bool {
	switch grc.AssessmentStatus(s) {
	case grc.StatusCompliant, grc.StatusPartiallyCompliant, grc.StatusNonCompliant,
		grc.StatusNotAssessed, grc.StatusNotApplicable, grc.StatusUnknown:
		return true
	}
	return false
}

// listAssessments serves GET persisted assessments with status/control/
// target/risk filters, deterministic id order.
func (s *Server) listAssessments(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" && !validAssessmentStatus(status) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown assessment status")
		return
	}
	control := strings.TrimSpace(q.Get("control"))
	target := strings.TrimSpace(q.Get("target"))
	risk := strings.ToUpper(strings.TrimSpace(q.Get("risk")))
	if risk != "" {
		switch grc.RiskLevel(risk) {
		case grc.RiskLow, grc.RiskMedium, grc.RiskHigh, grc.RiskCritical, grc.RiskUnknown:
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown risk level")
			return
		}
	}
	list, err := s.backend.Assessments.List(r.Context())
	if err != nil {
		mapError(w, err, "assessments", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		if status != "" && string(a.Status) != status {
			continue
		}
		if control != "" && a.ControlID != control {
			continue
		}
		if target != "" && a.Target != target {
			continue
		}
		if risk != "" && string(a.Risk) != risk {
			continue
		}
		out = append(out, assessmentJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getAssessment serves GET one assessment by id.
func (s *Server) getAssessment(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/grc/assessments/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	a, err := s.backend.Assessments.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "assessment", id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": assessmentJSON(a)})
}

// listArchitectureAssets serves GET asset nodes with optional type filter.
func (s *Server) listArchitectureAssets(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	typ := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	if typ != "" {
		want := typ
		if !strings.HasPrefix(want, "ASSET_TYPE_") {
			want = "ASSET_TYPE_" + want
		}
		if _, ok := v1.AssetType_value[want]; !ok || want == "ASSET_TYPE_UNSPECIFIED" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown asset type")
			return
		}
	}
	assets, err := s.backend.Assets.List(r.Context())
	if err != nil {
		mapError(w, err, "assets", "")
		return
	}
	view := grc.ArchitectureView(assets, nil)
	out := make([]map[string]any, 0, len(view.Nodes))
	for _, n := range view.Nodes {
		if typ != "" {
			want := typ
			if !strings.HasPrefix(want, "ASSET_TYPE_") {
				want = "ASSET_TYPE_" + want
			}
			if n.Kind != want {
				continue
			}
		}
		out = append(out, map[string]any{
			"asset_id": n.AssetID, "kind": n.Kind, "name": n.Name, "boundary": n.Boundary,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// listArchitectureRelationships serves GET relationship edges, reusing
// stored asset relationships only, with optional kind filter.
func (s *Server) listArchitectureRelationships(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	kind := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("kind")))
	assets, err := s.backend.Assets.List(r.Context())
	if err != nil {
		mapError(w, err, "assets", "")
		return
	}
	byID := map[string]bool{}
	for _, a := range assets {
		byID[a.GetId()] = true
	}
	var rels []assetRelationship
	for id := range byID {
		kids, err := s.backend.Relationships.Children(r.Context(), id)
		if err != nil {
			mapError(w, err, "relationships", id)
			return
		}
		for _, k := range kids {
			rels = append(rels, assetRelationship{parent: k.ParentID, child: k.ChildID, kind: k.Kind})
		}
	}
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].parent != rels[j].parent {
			return rels[i].parent < rels[j].parent
		}
		if rels[i].child != rels[j].child {
			return rels[i].child < rels[j].child
		}
		return rels[i].kind < rels[j].kind
	})
	out := make([]map[string]any, 0, len(rels))
	for _, e := range rels {
		if kind != "" && e.kind != kind {
			continue
		}
		out = append(out, map[string]any{
			"parent_id": e.parent, "child_id": e.child, "kind": e.kind,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

type assetRelationship struct {
	parent, child, kind string
}

func strList(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func resilienceJSON(rec grc.ResilienceRecord) map[string]any {
	m := map[string]any{
		"id": rec.ID, "target": rec.Target, "assessor": rec.Assessor,
		"observed_at":           rec.ObservedAt.UTC().Format(timeFormat),
		"status":                string(rec.Status),
		"backup_observed":       rec.BackupObserved,
		"backup_at":             timeOrEmptyNano(rec.BackupAt),
		"restore_test_observed": rec.RestoreTestObserved,
		"restore_test_at":       timeOrEmptyNano(rec.RestoreTestAt),
		"procedure_declared":    rec.ProcedureDeclared,
		"dependencies":          strList(rec.Dependencies),
		"evidence_ids":          strList(rec.EvidenceIDs),
		"retention_configured":  rec.RetentionConfigured,
		"encryption_observed":   rec.EncryptionObserved,
	}
	if m["dependencies"] == nil {
		m["dependencies"] = []string{}
	}
	if m["evidence_ids"] == nil {
		m["evidence_ids"] = []string{}
	}
	return m
}

func timeOrEmptyNano(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeFormat)
}

// listResiliencePosture serves GET all posture records, deterministic.
func (s *Server) listResiliencePosture(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	list, err := s.backend.Resilience.List(r.Context())
	if err != nil {
		mapError(w, err, "resilience records", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, rec := range list {
		out = append(out, resilienceJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// listResilienceRecovery serves GET recovery-focused rows with status/
// target filters.
func (s *Server) listResilienceRecovery(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" {
		switch grc.ResilienceStatus(status) {
		case grc.ResilienceReady, grc.ResilienceDegraded, grc.ResilienceNotReady,
			grc.ResilienceNotAssessed, grc.ResilienceUnknown:
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown resilience status")
			return
		}
	}
	target := strings.TrimSpace(q.Get("target"))
	list, err := s.backend.Resilience.List(r.Context())
	if err != nil {
		mapError(w, err, "resilience records", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, rec := range list {
		if status != "" && string(rec.Status) != status {
			continue
		}
		if target != "" && rec.Target != target {
			continue
		}
		out = append(out, resilienceJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}
