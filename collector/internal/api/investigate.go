// Investigation read endpoints (13G): hunting, unified timeline,
// metadata-level forensics, and incident-scoped timelines. All read-only
// over persisted telemetry/detections/alerts/incidents/evidence plus
// computed correlations. No SQL, no filesystem, no mutation.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/investigate"
	"blueveil/collector/internal/monitor"
)

func registerInvestigateRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/hunting/events", s.listHuntingEvents)
	s.mux.HandleFunc("/api/v1/hunting/timeline", s.huntingTimeline)
	s.mux.HandleFunc("/api/v1/forensics/artifacts", s.listForensicArtifacts)
	s.mux.HandleFunc("/api/v1/forensics/endpoint", s.forensicEndpoint)
	s.mux.HandleFunc("/api/v1/forensics/network", s.forensicNetwork)
	s.mux.HandleFunc("/api/v1/forensics/cloud", s.forensicCloud)
	s.mux.HandleFunc("/api/v1/forensics/identity", s.forensicIdentity)
	s.mux.HandleFunc("/api/v1/incidents/{id}/timeline", s.incidentTimeline)
}

func huntingQueryFrom(r *http.Request) (investigate.HuntQuery, bool) {
	var hq investigate.HuntQuery
	q := r.URL.Query()
	hq.Source = strings.TrimSpace(q.Get("source"))
	hq.EventType = strings.TrimSpace(q.Get("event_type"))
	hq.AssetID = strings.TrimSpace(q.Get("asset"))
	hq.CorrelationID = strings.TrimSpace(q.Get("correlation_id"))
	hq.Principal = strings.TrimSpace(q.Get("principal"))
	hq.Keyword = strings.TrimSpace(q.Get("keyword"))
	if sev := strings.TrimSpace(q.Get("severity")); sev != "" {
		v, ok := v1.Severity_value["SEVERITY_"+strings.ToUpper(sev)]
		if !ok || v1.Severity(v) == v1.Severity_SEVERITY_UNSPECIFIED {
			if _, ok2 := v1.Severity_value[strings.ToUpper(sev)]; !ok2 {
				return hq, false
			}
			v = v1.Severity_value[strings.ToUpper(sev)]
			if v1.Severity(v) == v1.Severity_SEVERITY_UNSPECIFIED {
				return hq, false
			}
		}
		hq.Severity, hq.HasSeverity = v1.Severity(v), true
	}
	if d := strings.ToLower(strings.TrimSpace(q.Get("detected"))); d != "" {
		switch d {
		case "true", "false":
		default:
			return hq, false
		}
	}
	from, err := parseTimeParam(q.Get("from"))
	if err != nil {
		return hq, false
	}
	to, err := parseTimeParam(q.Get("to"))
	if err != nil {
		return hq, false
	}
	hq.From, hq.To = from, to
	if l := strings.TrimSpace(q.Get("limit")); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 1000 {
			return hq, false
		}
		hq.Limit = n
	}
	if o := strings.ToLower(strings.TrimSpace(q.Get("order"))); o != "" {
		if o != "asc" && o != "desc" {
			return hq, false
		}
		hq.OrderDesc = o == "desc"
	}
	return hq, true
}

func jsonUnmarshal(data json.RawMessage, v any) error {
	return json.Unmarshal(data, v)
}

// redactSecrets drops secret-bearing attribute keys from an already
// serialized hunting row. The pipeline sink is the primary redaction
// point; this is defense in depth so a leaked store can never exfiltrate
// credentials through the read API.
func redactSecrets(obj map[string]any) {
	attrs, ok := obj["attributes"].(map[string]any)
	if !ok {
		return
	}
	for k := range attrs {
		if contract.SensitiveField(k) {
			delete(attrs, k)
		}
	}
}

// listHuntingEvents serves GET hunting searches. Every row carries kind
// HUNT_RESULT: an observed result, never a confirmed attack.
func (s *Server) listHuntingEvents(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	hq, ok := huntingQueryFrom(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hunting query parameter")
		return
	}
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapError(w, err, "telemetry", "")
		return
	}
	if d := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("detected"))); d != "" {
		detectedEvents, err := s.detectedEventIDs(r.Context())
		if err != nil {
			mapError(w, err, "detections", "")
			return
		}
		hq.DetectedIDs = detectedEvents
		b := d == "true"
		hq.Detected = &b
	}
	rows, err := hq.Execute(events)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	raw := make([]map[string]any, 0, len(rows))
	for _, e := range rows {
		data, err := marshalProto(e)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
			return
		}
		var obj map[string]any
		if err := jsonUnmarshal(data, &obj); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
			return
		}
		obj["kind"] = investigate.HuntResultKind
		redactSecrets(obj)
		raw = append(raw, obj)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": raw})
}

func timelineEntryJSON(e investigate.TimelineEntry) map[string]any {
	return map[string]any{
		"id":             e.ID,
		"kind":           e.Kind,
		"occurred_at":    e.OccurredAt.UTC().Format(timeFormat),
		"source":         e.Source,
		"asset_id":       e.AssetID,
		"principal":      e.Principal,
		"rule_id":        e.RuleID,
		"correlation_id": e.CorrelationID,
		"evidence_id":    e.EvidenceID,
		"incident_id":    e.IncidentID,
		"summary":        e.Summary,
	}
}

func writeTimeline(w http.ResponseWriter, entries []investigate.TimelineEntry) {
	raw := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		raw = append(raw, timelineEntryJSON(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": raw})
}

func writeTimelineError(w http.ResponseWriter, err error) {
	writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
}

// loadTimelineInput gathers persisted objects; hunting filters scope the
// telemetry leg only (detections/alerts/incidents/evidence are archival
// joins, not search hits).
func (s *Server) loadTimelineInput(ctx context.Context, hq investigate.HuntQuery) (investigate.TimelineInput, error) {
	var in investigate.TimelineInput
	events, err := s.backend.Telemetry.List(ctx)
	if err != nil {
		return in, err
	}
	rows, err := hq.Execute(events)
	if err != nil {
		return in, err
	}
	in.Events = rows
	if in.Detections, err = s.backend.Detection.List(ctx); err != nil {
		return in, err
	}
	if in.Alerts, err = s.backend.Alert.List(ctx); err != nil {
		return in, err
	}
	if in.Incidents, err = s.backend.Incident.List(ctx); err != nil {
		return in, err
	}
	if in.Evidence, err = s.backend.Evidence.List(ctx); err != nil {
		return in, err
	}
	stored, err := s.backend.Telemetry.List(ctx)
	if err != nil {
		return in, err
	}
	for _, fn := range []func([]*v1.TelemetryEvent, time.Duration) ([]monitor.Correlation, error){
		monitor.CorrelateAuthToIdentity,
		monitor.CorrelateNetworkToApp,
		monitor.CorrelateEndpointToServer,
	} {
		corrs, err := fn(stored, correlationWindow)
		if err != nil {
			return in, err
		}
		in.Correlations = append(in.Correlations, corrs...)
	}
	return in, nil
}

// huntingTimeline serves GET over the full persisted timeline.
func (s *Server) huntingTimeline(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	hq, ok := huntingQueryFrom(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hunting query parameter")
		return
	}
	in, err := s.loadTimelineInput(r.Context(), hq)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	entries, err := investigate.BuildTimeline(in)
	if err != nil {
		writeTimelineError(w, err)
		return
	}
	writeTimeline(w, entries)
}

// incidentTimeline serves GET /api/v1/incidents/{id}/timeline scoped to
// one incident: the incident, its alerts/detections/evidence, and linked
// telemetry. Unknown ids 404; corrupt rows fail closed.
func (s *Server) incidentTimeline(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id := r.PathValue("id")
	inc, err := s.backend.Incident.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "incident", id)
		return
	}
	hq, ok := huntingQueryFrom(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid hunting query parameter")
		return
	}
	in, err := s.loadTimelineInput(r.Context(), hq)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	alertSet := map[string]bool{}
	for _, aid := range inc.GetAlertIds() {
		alertSet[aid] = true
	}
	detSet := map[string]bool{}
	for _, a := range in.Alerts {
		if alertSet[a.GetId()] {
			for _, did := range a.GetDetectionIds() {
				detSet[did] = true
			}
		}
	}
	telemetrySet := map[string]bool{}
	for _, d := range in.Detections {
		if detSet[d.GetId()] {
			for _, tid := range d.GetTelemetryEventIds() {
				telemetrySet[tid] = true
			}
		}
	}
	in.Events = filterEvents(in.Events, telemetrySet)
	in.Alerts = filterAlerts(in.Alerts, alertSet)
	in.Detections = filterDetections(in.Detections, detSet)
	in.Evidence = filterEvidence(in.Evidence, inc.GetId())
	in.Incidents = []*v1.Incident{inc}
	in.Correlations = filterCorrelations(in.Correlations, telemetrySet)
	entries, err := investigate.BuildTimeline(in)
	if err != nil {
		writeTimelineError(w, err)
		return
	}
	writeTimeline(w, entries)
}

func filterEvents(in []*v1.TelemetryEvent, keep map[string]bool) []*v1.TelemetryEvent {
	out := in[:0]
	for _, e := range in {
		if keep[e.GetId()] {
			out = append(out, e)
		}
	}
	return out
}

func filterAlerts(in []*v1.Alert, keep map[string]bool) []*v1.Alert {
	out := in[:0]
	for _, a := range in {
		if keep[a.GetId()] {
			out = append(out, a)
		}
	}
	return out
}

func filterDetections(in []*v1.Detection, keep map[string]bool) []*v1.Detection {
	out := in[:0]
	for _, d := range in {
		if keep[d.GetId()] {
			out = append(out, d)
		}
	}
	return out
}

func filterEvidence(in []*v1.Evidence, incidentID string) []*v1.Evidence {
	out := in[:0]
	for _, e := range in {
		if e.GetIncidentId() == incidentID {
			out = append(out, e)
		}
	}
	return out
}

func filterCorrelations(in []monitor.Correlation, telemetrySet map[string]bool) []monitor.Correlation {
	var out []monitor.Correlation
	for _, c := range in {
		for _, id := range c.EventIDs {
			if telemetrySet[id] {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func artifactJSON(a investigate.Artifact) map[string]any {
	return map[string]any{
		"type":        string(a.Type),
		"event_id":    a.EventID,
		"asset_id":    a.AssetID,
		"source":      a.Source,
		"observed_at": a.ObservedAt.UTC().Format(timeFormat),
		"metadata":    a.Metadata,
		"digest":      a.Digest,
	}
}

// listForensicArtifacts serves GET over classified artifacts for all
// persisted telemetry with an optional type filter.
func (s *Server) listForensicArtifacts(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	typ := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	if typ != "" && !validArtifactType(typ) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown artifact type")
		return
	}
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapError(w, err, "telemetry", "")
		return
	}
	rows, err := artifactsFor(events, typ)
	if err != nil {
		writeTimelineError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, artifactJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func validArtifactType(t string) bool {
	switch investigate.ArtifactType(t) {
	case investigate.ArtifactProcess, investigate.ArtifactFileActivity,
		investigate.ArtifactService, investigate.ArtifactNetwork,
		investigate.ArtifactAuthentication, investigate.ArtifactIdentity,
		investigate.ArtifactContainer, investigate.ArtifactCloud,
		investigate.ArtifactUnknown:
		return true
	}
	return false
}

func artifactsFor(events []*v1.TelemetryEvent, typ string) ([]investigate.Artifact, error) {
	rows := make([]investigate.Artifact, 0, len(events))
	for _, e := range events {
		a, err := investigate.ArtifactFor(e)
		if err != nil {
			return nil, err
		}
		if typ != "" && string(a.Type) != typ {
			continue
		}
		rows = append(rows, a)
	}
	return rows, nil
}

func (s *Server) forensicEndpoint(w http.ResponseWriter, r *http.Request) {
	s.forensicByTypes(w, r, map[string]bool{
		string(investigate.ArtifactProcess):      true,
		string(investigate.ArtifactFileActivity): true,
	})
}

func (s *Server) forensicNetwork(w http.ResponseWriter, r *http.Request) {
	s.forensicByTypes(w, r, map[string]bool{string(investigate.ArtifactNetwork): true})
}

func (s *Server) forensicCloud(w http.ResponseWriter, r *http.Request) {
	s.forensicByTypes(w, r, map[string]bool{string(investigate.ArtifactCloud): true})
}

func (s *Server) forensicIdentity(w http.ResponseWriter, r *http.Request) {
	s.forensicByTypes(w, r, map[string]bool{
		string(investigate.ArtifactAuthentication): true,
		string(investigate.ArtifactIdentity):       true,
	})
}

func (s *Server) forensicByTypes(w http.ResponseWriter, r *http.Request, want map[string]bool) {
	if !requireGET(w, r) {
		return
	}
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapError(w, err, "telemetry", "")
		return
	}
	rows, err := artifactsFor(events, "")
	if err != nil {
		writeTimelineError(w, err)
		return
	}
	out := make([]map[string]any, 0)
	for _, a := range rows {
		if want[string(a.Type)] {
			out = append(out, artifactJSON(a))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}
