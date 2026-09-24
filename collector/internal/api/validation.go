// Validation campaign/history/purple-team read endpoints (13H).
// Read-only over persisted campaigns, exercises, requests, and results.
// Campaign summaries count actual stored results; history is bounded and
// deterministically ordered; corrupt rows fail closed.
package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/validation"
)

func registerValidationRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/validation/campaigns", s.listCampaigns)
	s.mux.HandleFunc("/api/v1/validation/campaigns/", s.campaignSub)
	s.mux.HandleFunc("/api/v1/validation/history", s.listValidationHistory)
	s.mux.HandleFunc("/api/v1/purple-team/exercises", s.listExercises)
	s.mux.HandleFunc("/api/v1/purple-team/exercises/", s.getExercise)
}

// campaignJSON renders one campaign with its honest result summary.
func (s *Server) campaignJSON(ctx context.Context, c validation.Campaign) (map[string]any, error) {
	results, err := s.resultsByID(ctx, c.ResultIDs)
	if err != nil {
		return nil, err
	}
	outs := make([]validation.CaseOutcome, 0, len(results))
	for _, res := range results {
		outs = append(outs, validation.CaseOutcome{Result: res, Success: true})
	}
	sum := validation.Summarize(outs)
	byVerdict := map[string]any{}
	for v, n := range sum.ByVerdict {
		byVerdict[v.String()] = n
	}
	return map[string]any{
		"id":           c.ID(),
		"name":         c.Name,
		"description":  c.Description,
		"target":       c.Target,
		"provider":     c.Provider,
		"source":       c.Source,
		"status":       c.Status.String(),
		"created_at":   timeOrEmpty(c.CreatedAt),
		"started_at":   timeOrEmpty(c.StartedAt),
		"completed_at": timeOrEmpty(c.CompletedAt),
		"case_ids":     strSlice(c.CaseIDs),
		"result_ids":   strSlice(c.ResultIDs),
		"summary": map[string]any{
			"total":           sum.Total,
			"by_verdict":      byVerdict,
			"provider_errors": sum.ProviderErrors,
			"not_tested":      sum.NotTested,
			"rate_limited":    sum.RateLimited,
			"unknown":         sum.Unknown,
		},
	}, nil
}

func strSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func timeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeFormat)
}

func (s *Server) resultsByID(ctx context.Context, ids []string) ([]*v1.ValidationResult, error) {
	out := make([]*v1.ValidationResult, 0, len(ids))
	for _, id := range ids {
		res, err := s.backend.Validation.GetResult(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// listCampaigns serves GET with optional status filter.
func (s *Server) listCampaigns(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	statusFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	if statusFilter != "" {
		switch statusFilter {
		case "DRAFT", "RUNNING", "COMPLETED", "FAILED":
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown campaign status")
			return
		}
	}
	camps, err := s.backend.Campaigns.List(r.Context())
	if err != nil {
		mapError(w, err, "campaigns", "")
		return
	}
	out := make([]map[string]any, 0, len(camps))
	for _, c := range camps {
		if statusFilter != "" && c.Status.String() != statusFilter {
			continue
		}
		row, err := s.campaignJSON(r.Context(), c)
		if err != nil {
			mapError(w, err, "validation result", "")
			return
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// campaignSub routes /{id} and /{id}/results.
func (s *Server) campaignSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/validation/campaigns/")
	if rest == "" || rest == r.URL.Path {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	id, sub, _ := strings.Cut(rest, "/")
	switch sub {
	case "":
		if !requireGET(w, r) {
			return
		}
		c, err := s.backend.Campaigns.Get(r.Context(), id)
		if err != nil {
			mapError(w, err, "campaign", id)
			return
		}
		row, err := s.campaignJSON(r.Context(), c)
		if err != nil {
			mapError(w, err, "validation result", "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": row})
	case "results":
		if !requireGET(w, r) {
			return
		}
		c, err := s.backend.Campaigns.Get(r.Context(), id)
		if err != nil {
			mapError(w, err, "campaign", id)
			return
		}
		results, err := s.resultsByID(r.Context(), c.ResultIDs)
		if err != nil {
			mapError(w, err, "validation result", "")
			return
		}
		s.writeProtoList(w, toProtoList(results))
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown campaign sub-resource")
	}
}

func historyVerdictParam(v string) (v1.ValidationVerdict, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, true
	}
	up := strings.ToUpper(v)
	if !strings.HasPrefix(up, "VALIDATION_VERDICT_") {
		up = "VALIDATION_VERDICT_" + up
	}
	n, ok := v1.ValidationVerdict_value[up]
	if !ok || v1.ValidationVerdict(n) == v1.ValidationVerdict_VALIDATION_VERDICT_UNSPECIFIED {
		return 0, false
	}
	return v1.ValidationVerdict(n), true
}

// listValidationHistory serves GET over stored results with
// campaign/case/target/provider/verdict/time/limit filters. Result rows
// carry their campaign linkage where a stored campaign references them.
func (s *Server) listValidationHistory(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	verdictFilter, ok := historyVerdictParam(q.Get("verdict"))
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown verdict")
		return
	}
	hasVerdict := strings.TrimSpace(q.Get("verdict")) != ""
	provider := strings.TrimSpace(q.Get("provider"))
	campaignFilter := strings.TrimSpace(q.Get("campaign"))
	target := strings.TrimSpace(q.Get("target"))
	from, err := parseTimeParam(q.Get("from"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid from timestamp (RFC3339 required)")
		return
	}
	to, err := parseTimeParam(q.Get("to"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid to timestamp (RFC3339 required)")
		return
	}
	if !from.IsZero() && !to.IsZero() && from.After(to) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "time range inverted")
		return
	}
	limit := 100
	if l := strings.TrimSpace(q.Get("limit")); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "limit must be 1..1000")
			return
		}
		limit = n
	}
	results, err := s.backend.Validation.ListResults(r.Context())
	if err != nil {
		mapError(w, err, "validation results", "")
		return
	}
	campaignOf := map[string]string{}
	if campaignFilter != "" || target != "" {
		camps, err := s.backend.Campaigns.List(r.Context())
		if err != nil {
			mapError(w, err, "campaigns", "")
			return
		}
		for _, c := range camps {
			if campaignFilter != "" && c.ID() != campaignFilter {
				continue
			}
			if target != "" && c.Target != target {
				continue
			}
			for _, rid := range c.ResultIDs {
				campaignOf[rid] = c.ID()
			}
		}
	}
	rows := make([]*v1.ValidationResult, 0, len(results))
	for _, res := range results {
		if hasVerdict && res.GetVerdict() != verdictFilter {
			continue
		}
		if provider != "" && res.GetProvider() != provider {
			continue
		}
		if campaignFilter != "" || target != "" {
			if _, ok := campaignOf[res.GetId()]; !ok {
				continue
			}
		}
		if !from.IsZero() && res.GetValidatedAt().AsTime().Before(from) {
			continue
		}
		if !to.IsZero() && res.GetValidatedAt().AsTime().After(to) {
			continue
		}
		rows = append(rows, res)
	}
	sort.Slice(rows, func(i, j int) bool {
		ai, bi := rows[i].GetValidatedAt().AsTime(), rows[j].GetValidatedAt().AsTime()
		if !ai.Equal(bi) {
			return ai.Before(bi)
		}
		return rows[i].GetId() < rows[j].GetId()
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	s.writeProtoList(w, toProtoList(rows))
}

func exerciseJSON(e validation.Exercise) map[string]any {
	entries := make([]map[string]any, 0, len(e.Entries))
	for _, en := range e.Entries {
		entries = append(entries, map[string]any{
			"case_id":       en.CaseID,
			"request_id":    en.RequestID,
			"result_id":     en.ResultID,
			"verdict":       en.Verdict.String(),
			"status":        string(en.Status),
			"telemetry_ids": en.TelemetryIDs,
			"detection_ids": en.DetectionIDs,
			"alert_ids":     en.AlertIDs,
			"incident_ids":  en.IncidentIDs,
			"evidence_ids":  en.EvidenceIDs,
		})
	}
	return map[string]any{
		"id":          e.ID,
		"campaign_id": e.CampaignID,
		"name":        e.Name,
		"source":      e.Source,
		"entries":     entries,
	}
}

// listExercises serves GET over stored purple-team exercises.
func (s *Server) listExercises(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	campaignFilter := strings.TrimSpace(r.URL.Query().Get("campaign"))
	list, err := s.backend.Exercises.List(r.Context())
	if err != nil {
		mapError(w, err, "exercises", "")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		if campaignFilter != "" && e.CampaignID != campaignFilter {
			continue
		}
		out = append(out, exerciseJSON(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// getExercise serves GET one exercise by id.
func (s *Server) getExercise(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := idFromPath(r.URL.Path, "/api/v1/purple-team/exercises/")
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing id")
		return
	}
	e, err := s.backend.Exercises.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "exercise", id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": exerciseJSON(e)})
}
