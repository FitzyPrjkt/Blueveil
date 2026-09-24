// Asset & attack-surface endpoints (Step 13A). Reads follow the existing
// envelope conventions; the two mutations are data-only and lifecycle
// guarded: observations normalize into inventory (never probe anything),
// lifecycle PATCH walks the domain transition table (invalid moves are
// explicit errors). No scanning, no scoring, no destructive capability.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

func (s *Server) assetManager() (*asset.Manager, error) {
	return asset.NewManager(s.backend.Assets, assetRelStore{s.backend.Relationships}, time.Now)
}

// assetRelStore adapts the store relationship repo to the manager's narrow
// interface (identical method set on asset.Relationship — implicit).
type assetRelStore struct {
	repo store.AssetRelationshipRepository
}

func (a assetRelStore) Append(ctx context.Context, rel asset.Relationship) error {
	return a.repo.Append(ctx, rel)
}

func registerAssetRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/assets", s.assetsRoot)
	s.mux.HandleFunc("/api/v1/assets/", s.assetSub)
	s.mux.HandleFunc("/api/v1/assets/observations", s.postObservation)
}

// assetsRoot serves GET list with type/status/search filters.
func (s *Server) assetsRoot(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	typeFilter, statusFilter, search := q.Get("type"), q.Get("status"), strings.ToLower(q.Get("q"))

	// Both filters validate independently and AND (never silently drop
	// one): a narrow query must return the intersection, not a wider arm.
	var wantType v1.AssetType
	var wantStatus v1.AssetStatus
	if typeFilter != "" {
		typ, ok := v1.AssetType_value[typeFilter]
		if !ok || v1.AssetType(typ) == v1.AssetType_ASSET_TYPE_UNSPECIFIED {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown asset type")
			return
		}
		wantType = v1.AssetType(typ)
	}
	if statusFilter != "" {
		st, ok := v1.AssetStatus_value[statusFilter]
		if !ok || v1.AssetStatus(st) == v1.AssetStatus_ASSET_STATUS_UNSPECIFIED {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown asset status")
			return
		}
		wantStatus = v1.AssetStatus(st)
	}
	items, err := s.backend.Assets.List(r.Context())
	if err != nil {
		mapListError(w, err, "assets")
		return
	}
	if typeFilter != "" || statusFilter != "" {
		kept := items[:0]
		for _, a := range items {
			if typeFilter != "" && a.GetType() != wantType {
				continue
			}
			if statusFilter != "" && a.GetStatus() != wantStatus {
				continue
			}
			kept = append(kept, a)
		}
		items = kept
	}
	if search != "" {
		kept := items[:0]
		for _, a := range items {
			if strings.Contains(strings.ToLower(a.GetId()), search) ||
				strings.Contains(strings.ToLower(a.GetName()), search) {
				kept = append(kept, a)
			}
		}
		items = kept
	}
	s.writeProtoList(w, toProtoList(items))
}

// assetSub routes /{id}, /{id}/relationships, /{id}/telemetry,
// /{id}/findings, /{id}/lifecycle (PATCH only).
func (s *Server) assetSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/assets/")
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
		item, err := s.backend.Assets.Get(r.Context(), id)
		if err != nil {
			mapError(w, err, "asset", id)
			return
		}
		s.writeProtoItem(w, item)
	case "lifecycle":
		if r.Method != http.MethodPatch {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "lifecycle moves via PATCH only")
			return
		}
		s.patchLifecycle(w, r, id)
	case "relationships":
		if !requireGET(w, r) {
			return
		}
		s.assetRelationships(w, r, id)
	case "telemetry":
		if !requireGET(w, r) {
			return
		}
		s.assetTelemetry(w, r, id)
	case "findings":
		if !requireGET(w, r) {
			return
		}
		s.assetFindings(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown asset sub-resource")
	}
}

func relationshipToJSON(r asset.Relationship) map[string]any {
	return map[string]any{
		"parent_id":   r.ParentID,
		"child_id":    r.ChildID,
		"kind":        r.Kind,
		"source":      r.Source,
		"observed_at": r.ObservedAt.UTC().Format(time.RFC3339Nano),
	}
}

func (s *Server) assetRelationships(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.backend.Assets.Get(r.Context(), id); err != nil {
		mapError(w, err, "asset", id)
		return
	}
	children, err := s.backend.Relationships.Children(r.Context(), id)
	if err != nil {
		mapListError(w, err, "relationships")
		return
	}
	parents, err := s.backend.Relationships.Parents(r.Context(), id)
	if err != nil {
		mapListError(w, err, "relationships")
		return
	}
	toJSON := func(rels []asset.Relationship) []map[string]any {
		out := make([]map[string]any, 0, len(rels))
		for _, rel := range rels {
			out = append(out, relationshipToJSON(rel))
		}
		return out
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"parents":  toJSON(parents),
			"children": toJSON(children),
		},
	})
}

// assetMatchKeys are the telemetry asset_id spellings that resolve to one
// asset: its id, canonical name, and identifier values.
func assetMatchKeys(a *v1.Asset) map[string]bool {
	keys := map[string]bool{a.GetId(): true, a.GetName(): true}
	for _, id := range a.GetIdentifiers() {
		keys[id.GetValue()] = true
	}
	return keys
}

func (s *Server) assetTelemetry(w http.ResponseWriter, r *http.Request, id string) {
	a, err := s.backend.Assets.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "asset", id)
		return
	}
	all, err := s.backend.Telemetry.List(r.Context())
	if err != nil {
		mapListError(w, err, "telemetry")
		return
	}
	keys := assetMatchKeys(a)
	var msgs []proto.Message
	for _, e := range all {
		if keys[e.GetAssetId()] {
			msgs = append(msgs, e)
		}
	}
	s.writeProtoList(w, msgs)
}

// assetFindings traverses telemetry → detection → alert → incident using
// stored linkage only (no inference): incidents/alerts/detections connected
// through telemetry that resolves to this asset.
func (s *Server) assetFindings(w http.ResponseWriter, r *http.Request, id string) {
	a, err := s.backend.Assets.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "asset", id)
		return
	}
	ctx := r.Context()
	telemetry, err := s.backend.Telemetry.List(ctx)
	if err != nil {
		mapListError(w, err, "telemetry")
		return
	}
	keys := assetMatchKeys(a)
	eventIDs := map[string]bool{}
	for _, e := range telemetry {
		if keys[e.GetAssetId()] {
			eventIDs[e.GetId()] = true
		}
	}
	detections, err := s.backend.Detection.List(ctx)
	if err != nil {
		mapListError(w, err, "detections")
		return
	}
	detIDs := map[string]bool{}
	var detOut []proto.Message
	for _, d := range detections {
		for _, eid := range d.GetTelemetryEventIds() {
			if eventIDs[eid] {
				detIDs[d.GetId()] = true
				detOut = append(detOut, d)
				break
			}
		}
	}
	alerts, err := s.backend.Alert.List(ctx)
	if err != nil {
		mapListError(w, err, "alerts")
		return
	}
	alertIDs := map[string]bool{}
	var alertOut []proto.Message
	for _, al := range alerts {
		for _, did := range al.GetDetectionIds() {
			if detIDs[did] {
				alertIDs[al.GetId()] = true
				alertOut = append(alertOut, al)
				break
			}
		}
	}
	incidents, err := s.backend.Incident.List(ctx)
	if err != nil {
		mapListError(w, err, "incidents")
		return
	}
	var incOut []proto.Message
	for _, in := range incidents {
		for _, aid := range in.GetAlertIds() {
			if alertIDs[aid] {
				incOut = append(incOut, in)
				break
			}
		}
	}
	marshal := func(msgs []proto.Message) []json.RawMessage {
		out := make([]json.RawMessage, 0, len(msgs))
		for _, m := range msgs {
			data, err := marshalProto(m)
			if err != nil {
				return nil
			}
			out = append(out, data)
		}
		return out
	}
	dets, alertsJSON, incs := marshal(detOut), marshal(alertOut), marshal(incOut)
	if dets == nil || alertsJSON == nil || incs == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"detections": dets,
			"alerts":     alertsJSON,
			"incidents":  incs,
		},
	})
}

// observationRequest is the POST /api/v1/assets/observations body: raw
// sightings only. No probing, no enrichment, no scoring.
type observationRequest struct {
	Source      string            `json:"source"`
	Type        string            `json:"type"`
	Raw         string            `json:"raw"`
	ObservedAt  string            `json:"observed_at"`
	Environment string            `json:"environment"`
	Attributes  map[string]string `json:"attributes"`
}

func (s *Server) postObservation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only here")
		return
	}
	var body observationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON body")
		return
	}
	typ, ok := v1.AssetType_value[body.Type]
	if !ok || v1.AssetType(typ) == v1.AssetType_ASSET_TYPE_UNSPECIFIED {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown asset type")
		return
	}
	observedAt, err := time.Parse(time.RFC3339, body.ObservedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "observed_at must be RFC 3339")
		return
	}
	mgr, err := s.assetManager()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "backend error")
		return
	}
	a, created, err := mgr.Ingest(r.Context(), asset.Observation{
		Source: body.Source, Type: v1.AssetType(typ), Raw: body.Raw,
		ObservedAt: observedAt, Environment: body.Environment, Attributes: body.Attributes,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	data, err := marshalProto(a)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "serialization error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "created": created})
}

// lifecycleRequest is the PATCH /{id}/lifecycle body: one explicit target
// status. The domain transition table decides; anything else is 400.
type lifecycleRequest struct {
	Status string `json:"status"`
}

func (s *Server) patchLifecycle(w http.ResponseWriter, r *http.Request, id string) {
	var body lifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON body")
		return
	}
	to, ok := v1.AssetStatus_value[body.Status]
	if !ok || v1.AssetStatus(to) == v1.AssetStatus_ASSET_STATUS_UNSPECIFIED {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown asset status")
		return
	}
	a, err := s.backend.Assets.Get(r.Context(), id)
	if err != nil {
		mapError(w, err, "asset", id)
		return
	}
	if err := asset.Transition(a, v1.AssetStatus(to), time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TRANSITION", err.Error())
		return
	}
	if err := s.backend.Assets.Save(r.Context(), a); err != nil {
		mapError(w, err, "asset", id)
		return
	}
	s.writeProtoItem(w, a)
}
