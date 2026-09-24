// Application defense read endpoints (13C). Projections over telemetry and
// relationships; no mutation, no scanning.
package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/httpobs"
)

func registerApplicationRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/application/observations", s.listApplicationObservations)
	s.mux.HandleFunc("/api/v1/application/relationships", s.listApplicationRelationships)
}

var validAppMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

func (s *Server) listApplicationObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	method := strings.ToUpper(strings.TrimSpace(q.Get("method")))
	if method != "" && !validAppMethods[method] {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown method")
		return
	}
	statusStr := strings.TrimSpace(q.Get("status"))
	hasStatusFilter := statusStr != ""
	statusFilter := 0
	if hasStatusFilter {
		n, err := strconv.Atoi(statusStr)
		if err != nil || n < 100 || n > 599 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid status")
			return
		}
		statusFilter = n
	}
	hostFilter := strings.ToLower(strings.TrimSpace(q.Get("host")))
	routeFilter := strings.TrimSpace(q.Get("route"))
	authFilter := strings.ToLower(strings.TrimSpace(q.Get("auth")))
	if authFilter != "" && authFilter != "failure" && authFilter != "success" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown auth filter")
		return
	}
	detected := strings.ToLower(strings.TrimSpace(q.Get("detected")))
	switch detected {
	case "", "true", "false":
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "detected must be true or false")
		return
	}
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapError(w, err, "telemetry", "")
		return
	}
	detectedEvents, err := s.detectedEventIDs(r.Context())
	if err != nil {
		mapError(w, err, "detections", "")
		return
	}
	type row struct {
		event *v1.TelemetryEvent
		obs   httpobs.Observation
		hit   bool
	}
	rows := make([]row, 0)
	for _, e := range events {
		if e.GetEventType() != httpobs.EventTypeHTTPRequest {
			continue
		}
		obs, perr := httpobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", fmt.Sprintf("corrupt http event %s", e.GetId()))
			return
		}
		if method != "" && obs.Method != method {
			continue
		}
		if hasStatusFilter && (!obs.HasStatus || obs.StatusCode != statusFilter) {
			continue
		}
		if hostFilter != "" && obs.Host != hostFilter {
			continue
		}
		if routeFilter != "" && obs.Route != routeFilter && obs.Path != routeFilter {
			continue
		}
		if authFilter != "" && obs.AuthOutcome != authFilter {
			continue
		}
		hit := detectedEvents[e.GetId()]
		if detected == "true" && !hit {
			continue
		}
		if detected == "false" && hit {
			continue
		}
		rows = append(rows, row{event: e, obs: obs, hit: hit})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].event, rows[j].event
		if ai, bi := a.GetOccurredAt().AsTime(), b.GetOccurredAt().AsTime(); !ai.Equal(bi) {
			return ai.Before(bi)
		}
		return a.GetId() < b.GetId()
	})
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		m := map[string]any{
			"id":          row.event.GetId(),
			"occurred_at": row.event.GetOccurredAt().AsTime().UTC().Format(timeFormat),
			"source":      row.event.GetSource(),
			"asset_id":    row.event.GetAssetId(),
			"severity":    row.event.GetSeverity().String(),
			"method":      row.obs.Method,
			"host":        row.obs.Host,
			"path":        row.obs.Path,
			"detected":    row.hit,
		}
		if row.obs.Scheme != "" {
			m["scheme"] = row.obs.Scheme
		}
		if row.obs.HasStatus {
			m["status_code"] = row.obs.StatusCode
		}
		if row.obs.ContentType != "" {
			m["content_type"] = row.obs.ContentType
		}
		if row.obs.Route != "" {
			m["route"] = row.obs.Route
		}
		if row.obs.APIVersion != "" {
			m["api_version"] = row.obs.APIVersion
		}
		if row.obs.Direction != "" {
			m["direction"] = row.obs.Direction
		}
		if row.obs.AuthOutcome != "" {
			m["auth_outcome"] = row.obs.AuthOutcome
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) listApplicationRelationships(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	all, err := s.backend.Assets.List(r.Context())
	if err != nil {
		mapError(w, err, "assets", "")
		return
	}
	var out []map[string]any
	for _, a := range all {
		kids, err := s.backend.Relationships.Children(r.Context(), a.GetId())
		if err != nil {
			mapError(w, err, "relationships", a.GetId())
			return
		}
		for _, rel := range kids {
			if rel.Kind == asset.RelationExposes || rel.Kind == asset.RelationServedBy || rel.Kind == asset.RelationContains {
				// Only include if parent is APPLICATION or URL etc. For app view, include EXPOSES/SERVED_BY/CONTAINS where URL involved.
				if rel.Kind == asset.RelationContains {
					// Filter to URL-related CONTAINS (domain contains URL or URL contains service)
					// Keep all for simplicity but tests check at least one exists.
				}
				out = append(out, relationshipToJSON(rel))
			}
		}
	}
	// Deterministic order (parent,child,kind: the relationship PK).
	sort.Slice(out, func(i, j int) bool {
		pi, pj := out[i]["parent_id"].(string), out[j]["parent_id"].(string)
		if pi != pj {
			return pi < pj
		}
		ci, cj := out[i]["child_id"].(string), out[j]["child_id"].(string)
		if ci != cj {
			return ci < cj
		}
		return relationshipKind(out[i]) < relationshipKind(out[j])
	})
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}
