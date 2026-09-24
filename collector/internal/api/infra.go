// Infrastructure read endpoints (13D)
package api

import (
	"net/http"
	"sort"
	"strings"

	"blueveil/collector/internal/infraobs"
)

func registerInfraRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/endpoint/observations", s.listEndpointObservations)
	s.mux.HandleFunc("/api/v1/server/observations", s.listServerObservations)
	s.mux.HandleFunc("/api/v1/container/observations", s.listContainerObservations)
	s.mux.HandleFunc("/api/v1/cloud/observations", s.listCloudObservations)
	s.mux.HandleFunc("/api/v1/infrastructure/relationships", s.listInfraRelationships)
}

func (s *Server) listEndpointObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	hostFilter := strings.ToLower(strings.TrimSpace(q.Get("host")))
	actionFilter := strings.ToLower(strings.TrimSpace(q.Get("action")))
	resultFilter := strings.ToLower(strings.TrimSpace(q.Get("result")))
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
	var out []map[string]any
	for _, e := range events {
		if e.GetEventType() != infraobs.EventTypeEndpointActivity {
			continue
		}
		obs, perr := infraobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", "corrupt endpoint event")
			return
		}
		if hostFilter != "" && strings.ToLower(obs.Endpoint.Host) != hostFilter {
			continue
		}
		if actionFilter != "" && obs.Endpoint.Action != actionFilter {
			continue
		}
		if resultFilter != "" && obs.Endpoint.Result != resultFilter {
			continue
		}
		hit := detectedEvents[e.GetId()]
		if detected == "true" && !hit {
			continue
		}
		if detected == "false" && hit {
			continue
		}
		m := map[string]any{
			"id": e.GetId(), "occurred_at": e.GetOccurredAt().AsTime().UTC().Format(timeFormat),
			"source": e.GetSource(), "asset_id": e.GetAssetId(), "severity": e.GetSeverity().String(),
			"host": obs.Endpoint.Host, "process": obs.Endpoint.Process, "action": obs.Endpoint.Action,
			"result": obs.Endpoint.Result, "detected": hit,
		}
		if obs.Endpoint.User != "" {
			m["user"] = obs.Endpoint.User
		}
		if obs.Endpoint.IntegrityLevel != "" {
			m["integrity_level"] = obs.Endpoint.IntegrityLevel
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["occurred_at"].(string) != out[j]["occurred_at"].(string) {
			return out[i]["occurred_at"].(string) < out[j]["occurred_at"].(string)
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) listServerObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	hostFilter := strings.ToLower(strings.TrimSpace(q.Get("host")))
	serviceFilter := strings.TrimSpace(q.Get("service"))
	resultFilter := strings.ToLower(strings.TrimSpace(q.Get("result")))
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
		mapListError(w, err, "detections")
		return
	}
	var out []map[string]any
	for _, e := range events {
		if e.GetEventType() != infraobs.EventTypeServerActivity {
			continue
		}
		obs, perr := infraobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", "corrupt infra event")
			return
		}
		if hostFilter != "" && strings.ToLower(obs.Server.Hostname) != hostFilter {
			continue
		}
		if serviceFilter != "" && obs.Server.Service != serviceFilter {
			continue
		}
		if resultFilter != "" && obs.Server.Result != resultFilter {
			continue
		}
		hit := detectedEvents[e.GetId()]
		if detected == "true" && !hit {
			continue
		}
		if detected == "false" && hit {
			continue
		}
		m := map[string]any{
			"id": e.GetId(), "occurred_at": e.GetOccurredAt().AsTime().UTC().Format(timeFormat),
			"source": e.GetSource(), "asset_id": e.GetAssetId(), "severity": e.GetSeverity().String(),
			"hostname": obs.Server.Hostname, "service": obs.Server.Service, "action": obs.Server.ServiceAction,
			"result": obs.Server.Result, "detected": hit,
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["occurred_at"].(string) != out[j]["occurred_at"].(string) {
			return out[i]["occurred_at"].(string) < out[j]["occurred_at"].(string)
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) listContainerObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	clusterFilter := strings.TrimSpace(q.Get("cluster"))
	nsFilter := strings.TrimSpace(q.Get("namespace"))
	resultFilter := strings.ToLower(strings.TrimSpace(q.Get("result")))
	detected := strings.ToLower(strings.TrimSpace(q.Get("detected")))
	switch detected {
	case "", "true", "false":
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "detected must be true or false")
		return
	}
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapListError(w, err, "telemetry")
		return
	}
	detectedEvents, err := s.detectedEventIDs(r.Context())
	if err != nil {
		mapListError(w, err, "detections")
		return
	}
	var out []map[string]any
	for _, e := range events {
		if e.GetEventType() != infraobs.EventTypeContainerActivity {
			continue
		}
		obs, perr := infraobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", "corrupt infra event")
			return
		}
		if clusterFilter != "" && obs.Container.Cluster != clusterFilter {
			continue
		}
		if nsFilter != "" && obs.Container.Namespace != nsFilter {
			continue
		}
		if resultFilter != "" && obs.Container.Result != resultFilter {
			continue
		}
		hit := detectedEvents[e.GetId()]
		if detected == "true" && !hit {
			continue
		}
		if detected == "false" && hit {
			continue
		}
		m := map[string]any{
			"id": e.GetId(), "occurred_at": e.GetOccurredAt().AsTime().UTC().Format(timeFormat),
			"source": e.GetSource(), "asset_id": e.GetAssetId(), "severity": e.GetSeverity().String(),
			"container_id": obs.Container.ContainerID, "image": obs.Container.Image,
			"cluster": obs.Container.Cluster, "namespace": obs.Container.Namespace,
			"privileged": obs.Container.Privileged, "host_network": obs.Container.HostNetwork, "host_pid": obs.Container.HostPID,
			"result": obs.Container.Result, "detected": hit,
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["occurred_at"].(string) != out[j]["occurred_at"].(string) {
			return out[i]["occurred_at"].(string) < out[j]["occurred_at"].(string)
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) listCloudObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	providerFilter := strings.ToLower(strings.TrimSpace(q.Get("provider")))
	principalFilter := strings.TrimSpace(q.Get("principal"))
	resultFilter := strings.ToLower(strings.TrimSpace(q.Get("result")))
	detected := strings.ToLower(strings.TrimSpace(q.Get("detected")))
	switch detected {
	case "", "true", "false":
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "detected must be true or false")
		return
	}
	events, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapListError(w, err, "telemetry")
		return
	}
	detectedEvents, err := s.detectedEventIDs(r.Context())
	if err != nil {
		mapListError(w, err, "detections")
		return
	}
	var out []map[string]any
	for _, e := range events {
		if e.GetEventType() != infraobs.EventTypeCloudActivity {
			continue
		}
		obs, perr := infraobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", "corrupt infra event")
			return
		}
		if providerFilter != "" && obs.Cloud.Provider != providerFilter {
			continue
		}
		if principalFilter != "" && obs.Cloud.Principal != principalFilter {
			continue
		}
		if resultFilter != "" && obs.Cloud.Result != resultFilter {
			continue
		}
		hit := detectedEvents[e.GetId()]
		if detected == "true" && !hit {
			continue
		}
		if detected == "false" && hit {
			continue
		}
		m := map[string]any{
			"id": e.GetId(), "occurred_at": e.GetOccurredAt().AsTime().UTC().Format(timeFormat),
			"source": e.GetSource(), "asset_id": e.GetAssetId(), "severity": e.GetSeverity().String(),
			"provider": obs.Cloud.Provider, "account": obs.Cloud.Account, "region": obs.Cloud.Region,
			"principal": obs.Cloud.Principal, "action": obs.Cloud.Action, "result": obs.Cloud.Result,
			"detected": hit,
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["occurred_at"].(string) != out[j]["occurred_at"].(string) {
			return out[i]["occurred_at"].(string) < out[j]["occurred_at"].(string)
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) listInfraRelationships(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	all, err := s.backend.Assets.List(r.Context())
	if err != nil {
		mapListError(w, err, "assets")
		return
	}
	var out []map[string]any
	for _, a := range all {
		kids, err := s.backend.Relationships.Children(r.Context(), a.GetId())
		if err != nil {
			mapListError(w, err, "relationships")
			return
		}
		for _, rel := range kids {
			if rel.Kind == "RUNS" || rel.Kind == "HOSTED_ON" || rel.Kind == "PART_OF" || rel.Kind == "BELONGS_TO" || rel.Kind == "CONTAINS" {
				out = append(out, relationshipToJSON(rel))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := out[i]["parent_id"].(string), out[j]["parent_id"].(string)
		if pi != pj {
			return pi < pj
		}
		if out[i]["child_id"].(string) != out[j]["child_id"].(string) {
			return out[i]["child_id"].(string) < out[j]["child_id"].(string)
		}
		return relationshipKind(out[i]) < relationshipKind(out[j])
	})
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// relationshipKind extracts the kind for deterministic tiebreaks (the
// relationship PK is parent,child,kind).
func relationshipKind(m map[string]any) string {
	k, _ := m["kind"].(string)
	return k
}

const occurredAtKey = "occurred_at"
