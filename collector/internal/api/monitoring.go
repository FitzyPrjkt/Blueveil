// Monitoring, detection-engineering, and threat-intel read endpoints
// (13F). All read-only over persisted telemetry plus static rule metadata
// and an optional IOC set / health provider. Anything unavailable is
// reported honestly as status "unavailable" — never fabricated.
package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/monitor"
	"blueveil/collector/internal/threatintel"
)

func registerMonitoringRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/monitoring/events", s.listMonitoringEvents)
	s.mux.HandleFunc("/api/v1/monitoring/correlations", s.listMonitoringCorrelations)
	s.mux.HandleFunc("/api/v1/detection-rules", s.listDetectionRules)
	s.mux.HandleFunc("/api/v1/detection-rules/health", s.detectionRulesHealth)
	s.mux.HandleFunc("/api/v1/threat-intelligence/iocs", s.listThreatIOCs)
	s.mux.HandleFunc("/api/v1/threat-intelligence/matches", s.listThreatMatches)
}

// SetHealthProvider attaches a live engine-health source. Absent, health
// reports honest unavailability (serve processes have no live engine).
func (s *Server) SetHealthProvider(fn func() []detect.RuleHealth) {
	s.healthProvider = fn
}

// SetIOCSet attaches the configured offline IOC set for TI endpoints.
func (s *Server) SetIOCSet(set *threatintel.Set) {
	s.iocSet = set
}

func parseTimeParam(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// listMonitoringEvents serves GET with event_type/source/severity/asset/
// correlation_id/detected/from/to/limit/order filters over persisted
// telemetry in deterministic order.
func (s *Server) listMonitoringEvents(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	var mq monitor.Query
	mq.EventType = strings.TrimSpace(q.Get("event_type"))
	mq.Source = strings.TrimSpace(q.Get("source"))
	mq.AssetID = strings.TrimSpace(q.Get("asset"))
	mq.CorrelationID = strings.TrimSpace(q.Get("correlation_id"))
	if sev := strings.TrimSpace(q.Get("severity")); sev != "" {
		v, ok := v1.Severity_value["SEVERITY_"+strings.ToUpper(sev)]
		if !ok || v1.Severity(v) == v1.Severity_SEVERITY_UNSPECIFIED {
			if _, ok2 := v1.Severity_value[strings.ToUpper(sev)]; !ok2 {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown severity")
				return
			}
			v = v1.Severity_value[strings.ToUpper(sev)]
			if v1.Severity(v) == v1.Severity_SEVERITY_UNSPECIFIED {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown severity")
				return
			}
		}
		mq.Severity, mq.HasSeverity = v1.Severity(v), true
	}
	if d := strings.ToLower(strings.TrimSpace(q.Get("detected"))); d != "" {
		switch d {
		case "true", "false":
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "detected must be true or false")
			return
		}
	}
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
	mq.From, mq.To = from, to
	if l := strings.TrimSpace(q.Get("limit")); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "limit must be 1..1000")
			return
		}
		mq.Limit = n
	}
	switch strings.ToLower(strings.TrimSpace(q.Get("order"))) {
	case "", "asc":
	case "desc":
		mq.OrderDesc = true
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "order must be asc or desc")
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
	mq.DetectedIDs = detectedEvents
	if d := strings.ToLower(strings.TrimSpace(q.Get("detected"))); d != "" {
		b := d == "true"
		mq.Detected = &b
	}
	rows, err := mq.Execute(events)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	s.writeProtoList(w, toProtoList(rows))
}

// correlationWindow is the documented default event-time window for
// monitoring correlation views.
const correlationWindow = 10 * time.Minute

// listMonitoringCorrelations serves GET computing C1/C2/C3 over stored
// telemetry. Filters: type, principal, asset, window_minutes.
func (s *Server) listMonitoringCorrelations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	typ := strings.TrimSpace(q.Get("type"))
	switch typ {
	case "", monitor.CorrelationAuthToIdentity, monitor.CorrelationNetworkToApp, monitor.CorrelationEndpointToServer:
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown correlation type")
		return
	}
	window := correlationWindow
	if wm := strings.TrimSpace(q.Get("window_minutes")); wm != "" {
		n, err := strconv.Atoi(wm)
		if err != nil || n < 1 || n > 1440 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "window_minutes must be 1..1440")
			return
		}
		window = time.Duration(n) * time.Minute
	}
	principal := strings.TrimSpace(q.Get("principal"))
	assetFilter := strings.TrimSpace(q.Get("asset"))
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapError(w, err, "telemetry", "")
		return
	}
	var corrs []monitor.Correlation
	run := func(t string, fn func([]*v1.TelemetryEvent, time.Duration) ([]monitor.Correlation, error)) bool {
		if typ != "" && typ != t {
			return true
		}
		got, err := fn(events, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return false
		}
		corrs = append(corrs, got...)
		return true
	}
	if !run(monitor.CorrelationAuthToIdentity, monitor.CorrelateAuthToIdentity) {
		return
	}
	if !run(monitor.CorrelationNetworkToApp, monitor.CorrelateNetworkToApp) {
		return
	}
	if !run(monitor.CorrelationEndpointToServer, monitor.CorrelateEndpointToServer) {
		return
	}
	out := make([]map[string]any, 0, len(corrs))
	for _, c := range corrs {
		if principal != "" && c.Principal != principal {
			continue
		}
		if assetFilter != "" && c.AssetID != assetFilter {
			continue
		}
		out = append(out, map[string]any{
			"id":          c.ID,
			"type":        c.Type,
			"event_ids":   c.EventIDs,
			"principal":   c.Principal,
			"asset_id":    c.AssetID,
			"observed_at": c.ObservedAt.UTC().Format(timeFormat),
			"status":      c.Status,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ai, bi := out[i]["observed_at"].(string), out[j]["observed_at"].(string)
		if ai != bi {
			return ai < bi
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// listDetectionRules serves GET over the static rule catalogue with
// domain/enabled/stateful/severity_basis filters.
func (s *Server) listDetectionRules(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	domain := strings.TrimSpace(q.Get("domain"))
	stateful := strings.ToLower(strings.TrimSpace(q.Get("stateful")))
	switch stateful {
	case "", "true", "false":
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "stateful must be true or false")
		return
	}
	enabled := strings.ToLower(strings.TrimSpace(q.Get("enabled")))
	switch enabled {
	case "", "true", "false":
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "enabled must be true or false")
		return
	}
	sevBasis := strings.TrimSpace(q.Get("severity_basis"))
	out := make([]map[string]any, 0)
	for _, m := range detect.Catalogue() {
		if domain != "" && m.Domain != domain {
			continue
		}
		if stateful != "" && ((stateful == "true") != m.Stateful) {
			continue
		}
		if enabled != "" && enabled != "true" {
			continue
		}
		if sevBasis != "" && m.SeverityBasis != sevBasis {
			continue
		}
		eventTypes := m.EventTypes
		if eventTypes == nil {
			eventTypes = []string{}
		}
		row := map[string]any{
			"id":               m.ID,
			"version":          m.Version,
			"title":            m.Title,
			"description":      m.Description,
			"domain":           m.Domain,
			"event_types":      eventTypes,
			"severity_basis":   m.SeverityBasis,
			"confidence_basis": m.ConfidenceBasis,
			"stateful":         m.Stateful,
			"enabled":          true,
		}
		if m.HasThreshold {
			row["threshold"] = m.Threshold
			row["window"] = m.Window.String()
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// detectionRulesHealth serves GET over live engine health when a provider
// is attached, or honest unavailability otherwise.
func (s *Server) detectionRulesHealth(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	if s.healthProvider == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "unavailable",
			"reason": "no live engine in this process; health is reported by the collecting process only",
			"data":   []map[string]any{},
		})
		return
	}
	rows := s.healthProvider()
	out := make([]map[string]any, 0, len(rows))
	for _, h := range rows {
		row := map[string]any{
			"rule_id":    h.RuleID,
			"version":    h.Version,
			"name":       h.Name,
			"enabled":    h.Enabled,
			"evaluated":  h.Evaluated,
			"detections": h.Detections,
			"errors":     h.Errors,
		}
		if h.HasThreshold {
			row["threshold"] = h.Threshold
			row["window"] = h.Window.String()
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "data": out})
}

// listThreatIOCs serves GET describing the configured offline IOC set, or
// honest unavailability when none is configured.
func (s *Server) listThreatIOCs(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	if s.iocSet == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "unavailable",
			"reason": "no IOC set configured (serve --ioc-set)",
			"data":   []map[string]any{},
		})
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	switch kind {
	case "", "domain", "ip", "sha256":
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown ioc kind")
		return
	}
	out := make([]map[string]any, 0, len(s.iocSet.Entries))
	for _, e := range s.iocSet.Entries {
		if kind != "" && e.Kind != kind {
			continue
		}
		out = append(out, map[string]any{
			"kind": e.Kind, "value": e.Value, "source": e.Source,
			"set_id": s.iocSet.ID, "set_version": s.iocSet.Version,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "set_id": s.iocSet.ID, "set_version": s.iocSet.Version, "data": out,
	})
}

// listThreatMatches serves GET computing exact IOC observations over
// stored telemetry. Filters: kind, set, field, asset, from/to.
func (s *Server) listThreatMatches(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	if s.iocSet == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "unavailable",
			"reason": "no IOC set configured (serve --ioc-set)",
			"data":   []map[string]any{},
		})
		return
	}
	q := r.URL.Query()
	kind := strings.ToLower(strings.TrimSpace(q.Get("kind")))
	switch kind {
	case "", "domain", "ip", "sha256":
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown ioc kind")
		return
	}
	setFilter := strings.TrimSpace(q.Get("set"))
	if setFilter != "" && setFilter != s.iocSet.ID {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "data": []map[string]any{}})
		return
	}
	field := strings.TrimSpace(q.Get("field"))
	assetFilter := strings.TrimSpace(q.Get("asset"))
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
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapError(w, err, "telemetry", "")
		return
	}
	out := make([]map[string]any, 0)
	for _, e := range events {
		if e.GetOccurredAt() == nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", "corrupt persisted event fails closed")
			return
		}
		at := e.GetOccurredAt().AsTime()
		if !from.IsZero() && at.Before(from) {
			continue
		}
		if !to.IsZero() && at.After(to) {
			continue
		}
		if assetFilter != "" && e.GetAssetId() != assetFilter {
			continue
		}
		for _, m := range threatintel.MatchEvent(e, *s.iocSet) {
			if kind != "" && m.Kind != kind {
				continue
			}
			if field != "" && m.MatchedField != field {
				continue
			}
			out = append(out, map[string]any{
				"id":            m.ID,
				"event_id":      m.EventID,
				"occurred_at":   at.UTC().Format(timeFormat),
				"asset_id":      e.GetAssetId(),
				"kind":          m.Kind,
				"indicator":     m.Indicator,
				"matched_field": m.MatchedField,
				"set_id":        m.SetID,
				"set_version":   m.SetVersion,
				"list_source":   m.ListSource,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ai, bi := out[i]["occurred_at"].(string), out[j]["occurred_at"].(string)
		if ai != bi {
			return ai < bi
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "data": out})
}
