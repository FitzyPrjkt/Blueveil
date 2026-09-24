// Package api is the minimal HTTP boundary for the Security Workstation
// UI. It serves canonical protojson (the same bytes the contract
// validators accept) straight from the store interfaces — no duplicate
// domain logic, no second persistence.
//
// Safety: read-only except two explicit asset-ingest paths. Every route
// is GET-only (anything else is 405) except POST /api/v1/assets/
// observations (ingest one observation) and PATCH /api/v1/assets/{id}/
// lifecycle (validated lifecycle move); both funnel through the same
// asset manager validation as the pipeline. There are no other mutation
// endpoints.
// The binary binds loopback by default; see cmd/collector serve.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/threatintel"
)

var marshaler = protojson.MarshalOptions{UseProtoNames: true}

// Server serves the store backend over HTTP. healthProvider and iocSet
// are optional attachments: health reflects a live engine (absent in
// serve processes by architecture) and iocSet reflects --ioc-set.
type Server struct {
	backend        store.Backend
	mux            *http.ServeMux
	healthProvider func() []detect.RuleHealth
	iocSet         *threatintel.Set
	gate           *Gate
	obs            *observability
	// serving flips false when shutdown begins: readyz reports
	// not-ready while the listener drains. Zero value is serving, so
	// tests and lab stacks without lifecycle wiring stay ready.
	unserving atomic.Bool
}

// SetServing marks the server serving (true) or draining (false) for
// readiness. It is lifecycle state only — it changes no routing.
func (s *Server) SetServing(v bool) {
	s.unserving.Store(!v)
}

// NewServer wires all read-only routes.
func NewServer(backend store.Backend) *Server {
	s := &Server{backend: backend, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/v1/healthz", s.handleHealth)
	s.mux.HandleFunc("/api/v1/readyz", s.handleReady)
	s.mux.HandleFunc("/api/v1/telemetry", s.listTelemetry)
	s.mux.HandleFunc("/api/v1/telemetry/", s.getTelemetry)
	s.mux.HandleFunc("/api/v1/detections", s.listDetections)
	s.mux.HandleFunc("/api/v1/detections/", s.getDetection)
	s.mux.HandleFunc("/api/v1/alerts", s.listAlerts)
	s.mux.HandleFunc("/api/v1/alerts/", s.getAlert)
	s.mux.HandleFunc("/api/v1/incidents", s.listIncidents)
	s.mux.HandleFunc("/api/v1/incidents/", s.getIncident)
	s.mux.HandleFunc("/api/v1/evidence", s.listEvidence)
	s.mux.HandleFunc("/api/v1/evidence/", s.getEvidence)
	s.mux.HandleFunc("/api/v1/recommendations", s.listRecommendations)
	s.mux.HandleFunc("/api/v1/recommendations/", s.getRecommendation)
	s.mux.HandleFunc("/api/v1/approvals", s.listApprovals)
	s.mux.HandleFunc("/api/v1/approvals/", s.getApproval)
	s.mux.HandleFunc("/api/v1/executions", s.listExecutions)
	s.mux.HandleFunc("/api/v1/executions/", s.getExecution)
	s.mux.HandleFunc("/api/v1/verifications", s.listVerifications)
	s.mux.HandleFunc("/api/v1/verifications/", s.getVerification)
	s.mux.HandleFunc("/api/v1/validation-requests/", s.getValidationRequest)
	s.mux.HandleFunc("/api/v1/validation-results", s.listValidationResults)
	s.mux.HandleFunc("/api/v1/validation-results/", s.getValidationResult)
	s.mux.HandleFunc("/api/v1/audit", s.listAudit)
	s.mux.HandleFunc("/api/v1/audit/", s.getAudit)
	registerAssetRoutes(s)
	registerNetworkRoutes(s)
	registerApplicationRoutes(s)
	registerInfraRoutes(s)
	registerIdentityRoutes(s)
	registerMonitoringRoutes(s)
	registerGRCRoutes(s)
	registerSupplyChainRoutes(s)
	registerValidationRoutes(s)
	registerInvestigateRoutes(s)
	return s
}

// Handler returns the composed middleware chain for http.Serve and
// httptest: request IDs outermost, then observability, then the auth
// gate, then the route mux. Auth runs inside observability so denied
// requests are still logged and counted (without credential material).
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	if s.gate != nil {
		h = s.gate.wrap(h)
	}
	if s.obs != nil {
		h = s.obs.wrap(h)
	}
	return withRequestID(h)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func mapError(w http.ResponseWriter, err error, kind, id string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", kind+" "+id+" not found")
	case errors.Is(err, store.ErrCorrupted):
		// Integrity failure is data, not absence: never an empty list.
		writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", kind+" "+id+" failed integrity check")
	default:
		writeError(w, http.StatusInternalServerError, "INTERNAL", "backend error")
	}
}

// mapListError maps backend list failures: corruption fails closed with
// INTEGRITY_FAILURE (never an empty list), anything else is INTERNAL.
func mapListError(w http.ResponseWriter, err error, kind string) {
	if errors.Is(err, store.ErrCorrupted) {
		writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", kind+" failed integrity check")
		return
	}
	writeError(w, http.StatusInternalServerError, "INTERNAL", "backend error")
}

func marshalProto(m proto.Message) (json.RawMessage, error) {
	data, err := marshaler.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// idFromPath extracts the trailing id from /api/v1/<entity>/<id>.
func idFromPath(path, prefix string) (string, bool) {
	id := strings.TrimPrefix(path, prefix)
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "read-only API: GET only")
		return false
	}
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"status": "ok"}})
}

// handleReady reports readiness: database reachability plus the live
// operational counters. No protected data, no secrets — safe public.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	checks := map[string]string{}
	ready := !s.unserving.Load()
	if !ready {
		checks["serving"] = "draining"
	}
	if s.obs != nil && s.obs.health != nil {
		if err := s.obs.health(r); err != nil {
			ready = false
			checks["database"] = "unreachable"
		} else {
			checks["database"] = "ok"
		}
	} else {
		checks["database"] = "unconfigured"
	}
	body := map[string]any{"data": map[string]any{
		"status": map[bool]string{true: "ready", false: "not-ready"}[ready],
		"checks": checks,
	}}
	if s.obs != nil && s.obs.metrics != nil {
		body["data"].(map[string]any)["metrics"] = s.obs.metrics.Snapshot()
	}
	if !ready {
		writeJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) writeProtoList(w http.ResponseWriter, items []proto.Message) {
	raw := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		data, err := marshalProto(item)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
			return
		}
		raw = append(raw, data)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": raw})
}

func (s *Server) writeProtoItem(w http.ResponseWriter, item proto.Message) {
	data, err := marshalProto(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

func toProtoList[T proto.Message](items []T) []proto.Message {
	msgs := make([]proto.Message, 0, len(items))
	for _, item := range items {
		msgs = append(msgs, item)
	}
	return msgs
}

func (s *Server) listTelemetry(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapListError(w, err, "telemetry")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getTelemetry(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/telemetry/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Telemetry.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "telemetry", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listDetections(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.Detection.List(r.Context())
	if err != nil {
		mapListError(w, err, "detections")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getDetection(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/detections/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Detection.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "detection", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.Alert.List(r.Context())
	if err != nil {
		mapListError(w, err, "alerts")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/alerts/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Alert.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "alert", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.Incident.List(r.Context())
	if err != nil {
		mapListError(w, err, "incidents")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/incidents/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Incident.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "incident", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	raw := []json.RawMessage{}
	if incidentID := r.URL.Query().Get("incident"); incidentID != "" {
		items, err := s.backend.Evidence.ListByIncident(r.Context(), incidentID)
		if err != nil {
			mapListError(w, err, "evidence")
			return
		}
		if len(items) == 0 {
			// Distinguish "no evidence" from "unknown incident".
			if _, err := s.backend.Incident.Get(r.Context(), incidentID); err != nil {
				mapError(w, err, "incident", incidentID)
				return
			}
		}
		for _, item := range items {
			data, err := marshalProto(item)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
				return
			}
			raw = append(raw, data)
		}
	} else {
		items, err := s.backend.Evidence.List(r.Context())
		if err != nil {
			mapListError(w, err, "evidence")
			return
		}
		for _, item := range items {
			data, err := marshalProto(item)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
				return
			}
			raw = append(raw, data)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": raw, "integrity": "verified"})
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/evidence/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Evidence.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "evidence", id)
		return
	}
	data, err := marshalProto(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "integrity": "verified"})
}

func (s *Server) listRecommendations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.Response.List(r.Context())
	if err != nil {
		mapListError(w, err, "responses")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getRecommendation(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/recommendations/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Response.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "recommendation", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.ResponseRecords.ListApprovals(r.Context())
	if err != nil {
		mapListError(w, err, "approvals")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getApproval(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/approvals/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.ResponseRecords.GetApproval(r.Context(), id)
	if err != nil {
		mapError(w, err, "approval", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listExecutions(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.ResponseRecords.ListExecutions(r.Context())
	if err != nil {
		mapListError(w, err, "executions")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getExecution(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/executions/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.ResponseRecords.GetExecution(r.Context(), id)
	if err != nil {
		mapError(w, err, "execution", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listVerifications(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.ResponseRecords.ListVerifications(r.Context())
	if err != nil {
		mapListError(w, err, "verifications")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getVerification(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/verifications/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.ResponseRecords.GetVerification(r.Context(), id)
	if err != nil {
		mapError(w, err, "verification", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) getValidationRequest(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/validation-requests/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Validation.GetRequest(r.Context(), id)
	if err != nil {
		mapError(w, err, "validation request", id)
		return
	}
	s.writeProtoItem(w, item)
}

func (s *Server) listValidationResults(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.Validation.ListResults(r.Context())
	if err != nil {
		mapListError(w, err, "validation results")
		return
	}
	s.writeProtoList(w, toProtoList(items))
}

func (s *Server) getValidationResult(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/validation-results/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Validation.GetResult(r.Context(), id)
	if err != nil {
		mapError(w, err, "validation result", id)
		return
	}
	s.writeProtoItem(w, item)
}

func auditToJSON(e store.AuditEntry) map[string]any {
	return map[string]any{
		"id":          e.ID,
		"decided_at":  e.DecidedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		"actor":       e.Actor,
		"operation":   e.Operation.String(),
		"risk":        e.Risk.String(),
		"decision":    e.Decision,
		"reason":      e.Reason,
		"result":      e.Result,
		"response_id": e.ResponseID,
		"phase":       e.Phase,
	}
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	items, err := s.backend.Audit.List(r.Context())
	if err != nil {
		mapListError(w, err, "audit")
		return
	}
	raw := make([]map[string]any, 0, len(items))
	for _, item := range items {
		raw = append(raw, auditToJSON(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": raw})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/audit/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	item, err := s.backend.Audit.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "audit", id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": auditToJSON(item)})
}
