// Identity, authentication & data-security read endpoints (Step 13E).
// Read-only projections over telemetry + relationships. Responses carry
// redacted data only: any stored row still holding a sensitive attribute
// is skipped (defense in depth — the pipeline sink is the primary
// redaction point). Deterministic ordering throughout.
package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"blueveil/collector/internal/asset"
	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/identobs"
)

func registerIdentityRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/identity/observations", s.listIdentityObservations)
	s.mux.HandleFunc("/api/v1/authentication/observations", s.listAuthObservations)
	s.mux.HandleFunc("/api/v1/data/observations", s.listDataObservations)
	s.mux.HandleFunc("/api/v1/identity/relationships", s.listIdentityRelationships)
}

// hasSensitive reports stored attributes that must never leave the API
// (canonical fragments, shared with the pipeline sinks).
func hasSensitive(attrs map[string]string) bool {
	for k := range attrs {
		if contract.SensitiveField(k) {
			return true
		}
	}
	return false
}

func checkDetectedParam(q map[string][]string, key string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(firstQuery(q, key)))
	switch d {
	case "", "true", "false":
		return d, true
	default:
		return "", false
	}
}

func firstQuery(q map[string][]string, key string) string {
	if v, ok := q[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func validIdentityAction(a string) bool {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "login", "logout", "role_change", "group_change",
		"account_create", "account_disable", "account_enable", "permission_change":
		return true
	}
	return false
}

func validAuthOutcome(o string) bool {
	switch strings.ToLower(strings.TrimSpace(o)) {
	case "success", "failure", "denied", "challenged", "unknown":
		return true
	}
	return false
}

func validDataAction(a string) bool {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "read", "write", "delete", "export", "access", "permission_change":
		return true
	}
	return false
}

// listIdentityObservations serves GET with principal/action/result/
// detected filters. Order is deterministic (occurred_at, then id).
func (s *Server) listIdentityObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	principal := strings.TrimSpace(q.Get("principal"))
	action := strings.ToLower(strings.TrimSpace(q.Get("action")))
	if action != "" && !validIdentityAction(action) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown action")
		return
	}
	result := strings.ToLower(strings.TrimSpace(q.Get("result")))
	detected, ok := checkDetectedParam(r.URL.Query(), "detected")
	if !ok {
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
		obs   identobs.Observation
		hit   bool
	}
	rows := make([]row, 0, len(events))
	for _, e := range events {
		if e.GetEventType() != identobs.EventTypeIdentityActivity {
			continue
		}
		if hasSensitive(e.GetAttributes()) {
			continue
		}
		obs, perr := identobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", fmt.Sprintf("corrupt identity event %s", e.GetId()))
			return
		}
		if principal != "" && obs.Identity.Principal != principal {
			continue
		}
		if action != "" && obs.Identity.Action != action {
			continue
		}
		if result != "" && obs.Identity.Result != result {
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
			"principal":   row.obs.Identity.Principal,
			"action":      row.obs.Identity.Action,
			"detected":    row.hit,
		}
		if row.obs.Identity.Target != "" {
			m["target"] = row.obs.Identity.Target
		}
		if row.obs.Identity.Result != "" {
			m["result"] = row.obs.Identity.Result
		}
		if row.obs.Identity.Provider != "" {
			m["provider"] = row.obs.Identity.Provider
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// listAuthObservations serves GET with principal/method/outcome/provider/
// detected filters.
func (s *Server) listAuthObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	principal := strings.TrimSpace(q.Get("principal"))
	method := strings.TrimSpace(q.Get("method"))
	outcome := strings.ToLower(strings.TrimSpace(q.Get("outcome")))
	if outcome != "" && !validAuthOutcome(outcome) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown outcome")
		return
	}
	provider := strings.TrimSpace(q.Get("provider"))
	detected, ok := checkDetectedParam(r.URL.Query(), "detected")
	if !ok {
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
		obs   identobs.Observation
		hit   bool
	}
	rows := make([]row, 0, len(events))
	for _, e := range events {
		if e.GetEventType() != identobs.EventTypeAuthActivity {
			continue
		}
		if hasSensitive(e.GetAttributes()) {
			continue
		}
		obs, perr := identobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", fmt.Sprintf("corrupt auth event %s", e.GetId()))
			return
		}
		if principal != "" && obs.Auth.Principal != principal {
			continue
		}
		if method != "" && obs.Auth.AuthenticationMethod != method {
			continue
		}
		if outcome != "" && obs.Auth.Outcome != outcome {
			continue
		}
		if provider != "" && obs.Auth.Provider != provider {
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
			"principal":   row.obs.Auth.Principal,
			"outcome":     row.obs.Auth.Outcome,
			"detected":    row.hit,
		}
		if row.obs.Auth.AuthenticationMethod != "" {
			m["method"] = row.obs.Auth.AuthenticationMethod
		}
		if row.obs.Auth.Provider != "" {
			m["provider"] = row.obs.Auth.Provider
		}
		if row.obs.Auth.Target != "" {
			m["target"] = row.obs.Auth.Target
		}
		if row.obs.Auth.FailureReason != "" {
			m["failure_reason"] = row.obs.Auth.FailureReason
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// listDataObservations serves GET with store/resource/action/
// classification/result/detected filters.
func (s *Server) listDataObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	storeFilter := strings.TrimSpace(q.Get("store"))
	resource := strings.TrimSpace(q.Get("resource"))
	action := strings.ToLower(strings.TrimSpace(q.Get("action")))
	if action != "" && !validDataAction(action) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown action")
		return
	}
	classification := strings.ToLower(strings.TrimSpace(q.Get("classification")))
	result := strings.ToLower(strings.TrimSpace(q.Get("result")))
	detected, ok := checkDetectedParam(r.URL.Query(), "detected")
	if !ok {
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
		obs   identobs.Observation
		hit   bool
	}
	rows := make([]row, 0, len(events))
	for _, e := range events {
		if e.GetEventType() != identobs.EventTypeDataActivity {
			continue
		}
		if hasSensitive(e.GetAttributes()) {
			continue
		}
		obs, perr := identobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", fmt.Sprintf("corrupt data event %s", e.GetId()))
			return
		}
		if storeFilter != "" && obs.Data.Store != storeFilter {
			continue
		}
		if resource != "" && obs.Data.Resource != resource {
			continue
		}
		if action != "" && obs.Data.Action != action {
			continue
		}
		if classification != "" && obs.Data.Classification != classification {
			continue
		}
		if result != "" && obs.Data.Result != result {
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
			"resource":    row.obs.Data.Resource,
			"action":      row.obs.Data.Action,
			"detected":    row.hit,
		}
		if row.obs.Data.Store != "" {
			m["store"] = row.obs.Data.Store
		}
		if row.obs.Data.Principal != "" {
			m["principal"] = row.obs.Data.Principal
		}
		if row.obs.Data.Classification != "" {
			m["classification"] = row.obs.Data.Classification
		}
		if row.obs.Data.Result != "" {
			m["result"] = row.obs.Data.Result
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// listIdentityRelationships serves GET over ACCESSES/MEMBER_OF/ASSUMES/
// AUTHENTICATES_TO edges: identity linkage with provenance,
// deterministically ordered. ?principal= scopes to one identity asset.
func (s *Server) listIdentityRelationships(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	principal := strings.TrimSpace(r.URL.Query().Get("principal"))
	all, err := s.backend.Assets.List(r.Context())
	if err != nil {
		mapError(w, err, "assets", "")
		return
	}
	isIdentKind := func(kind string) bool {
		switch kind {
		case asset.RelationAccesses, asset.RelationMemberOf, asset.RelationAssumes, asset.RelationAuthenticatesTo:
			return true
		}
		return false
	}
	edges := map[string][]asset.Relationship{}
	for _, a := range all {
		kids, err := s.backend.Relationships.Children(r.Context(), a.GetId())
		if err != nil {
			mapError(w, err, "relationships", a.GetId())
			return
		}
		for _, rel := range kids {
			if isIdentKind(rel.Kind) {
				edges[a.GetId()] = append(edges[a.GetId()], rel)
			}
		}
	}
	parents := make([]string, 0, len(edges))
	for p := range edges {
		parents = append(parents, p)
	}
	sort.Strings(parents)
	byID := map[string]*v1.Asset{}
	for _, a := range all {
		byID[a.GetId()] = a
	}
	out := make([]map[string]any, 0)
	for _, p := range parents {
		if principal != "" {
			pa, ok := byID[p]
			if !ok || pa.GetName() != principal {
				continue
			}
		}
		kids := edges[p]
		sort.Slice(kids, func(i, j int) bool {
			if kids[i].ChildID != kids[j].ChildID {
				return kids[i].ChildID < kids[j].ChildID
			}
			return kids[i].Kind < kids[j].Kind
		})
		for _, rel := range kids {
			out = append(out, relationshipToJSON(rel))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}
