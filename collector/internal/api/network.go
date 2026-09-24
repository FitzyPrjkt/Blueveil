// Network defense read endpoints (Step 13B). Both handlers are read-only
// projections over the existing telemetry and relationship stores — no
// second store, no network mutation, no scanning. Network observations
// are TelemetryEvents with event_type "net.connection"; anything the
// normalizer would reject is surfaced as an explicit 500 rather than
// silently rendered as if it were well-formed.
package api

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/netobs"
)

func registerNetworkRoutes(s *Server) {
	s.mux.HandleFunc("/api/v1/network/observations", s.listNetworkObservations)
	s.mux.HandleFunc("/api/v1/network/relationships", s.listNetworkRelationships)
}

var netVerdictValues = map[string]bool{"allowed": true, "denied": true}

// listNetworkObservations serves GET with protocol/src/dst/verdict/
// detected filters. Order is deterministic (occurred_at, then id).
func (s *Server) listNetworkObservations(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	q := r.URL.Query()
	protocol := strings.ToUpper(strings.TrimSpace(q.Get("protocol")))
	if protocol != "" && !map[bool]bool{true: true}[isKnownProtocol(protocol)] {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown protocol")
		return
	}
	srcFilter, err := parseIPOrEmpty(q.Get("src"), "src")
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	dstFilter, err := parseIPOrEmpty(q.Get("dst"), "dst")
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	verdict := strings.ToLower(strings.TrimSpace(q.Get("verdict")))
	if verdict != "" && !netVerdictValues[verdict] {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown verdict")
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
		obs   netobs.Observation
		hit   bool
	}
	rows := make([]row, 0, len(events))
	for _, e := range events {
		if e.GetEventType() != netobs.EventTypeConnection {
			continue
		}
		obs, perr := netobs.Parse(e)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, "INTEGRITY_FAILURE", fmt.Sprintf("corrupt network event %s", e.GetId()))
			return
		}
		if protocol != "" && obs.Protocol != protocol {
			continue
		}
		if srcFilter.IsValid() && obs.SrcIP != srcFilter {
			continue
		}
		if dstFilter.IsValid() && obs.DstIP != dstFilter {
			continue
		}
		if verdict != "" && obs.Verdict != verdict {
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
		out = append(out, networkObservationJSON(row.event, row.obs, row.hit))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

const timeFormat = "2006-01-02T15:04:05.999999999Z07:00"

func networkObservationJSON(e *v1.TelemetryEvent, obs netobs.Observation, detected bool) map[string]any {
	row := map[string]any{
		"id":          e.GetId(),
		"occurred_at": e.GetOccurredAt().AsTime().UTC().Format(timeFormat),
		"source":      e.GetSource(),
		"asset_id":    e.GetAssetId(),
		"severity":    e.GetSeverity().String(),
		"src_ip":      obs.SrcIP.String(),
		"dst_ip":      obs.DstIP.String(),
		"detected":    detected,
	}
	if obs.HasSrcPort {
		row["src_port"] = int(obs.SrcPort)
	}
	if obs.HasDstPort {
		row["dst_port"] = int(obs.DstPort)
	}
	if obs.Protocol != "" {
		row["protocol"] = obs.Protocol
	}
	if obs.Direction != "" {
		row["direction"] = obs.Direction
	}
	if obs.Verdict != "" {
		row["verdict"] = obs.Verdict
	}
	return row
}

// listNetworkRelationships serves GET over COMMUNICATES_WITH edges:
// every observed traffic link with provenance, deterministically ordered.
// CONTAINS (inventory ownership) is excluded — this view is network
// observation, not decomposition. ?asset= scopes to one endpoint.
func (s *Server) listNetworkRelationships(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	assetID := strings.TrimSpace(r.URL.Query().Get("asset"))
	if assetID != "" {
		if _, err := s.backend.Assets.Get(r.Context(), assetID); err != nil {
			mapError(w, err, "asset", assetID)
			return
		}
	}
	all, err := s.backend.Assets.List(r.Context())
	if err != nil {
		mapError(w, err, "assets", "")
		return
	}
	edges := map[string][]asset.Relationship{}
	for _, a := range all {
		kids, err := s.backend.Relationships.Children(r.Context(), a.GetId())
		if err != nil {
			mapError(w, err, "relationships", a.GetId())
			return
		}
		for _, rel := range kids {
			if rel.Kind == asset.RelationCommunicatesWith {
				edges[a.GetId()] = append(edges[a.GetId()], rel)
			}
		}
	}
	parents := make([]string, 0, len(edges))
	for p := range edges {
		parents = append(parents, p)
	}
	sort.Strings(parents)
	out := make([]map[string]any, 0)
	for _, p := range parents {
		kids := edges[p]
		sort.Slice(kids, func(i, j int) bool { return kids[i].ChildID < kids[j].ChildID })
		for _, rel := range kids {
			if assetID != "" && rel.ParentID != assetID && rel.ChildID != assetID {
				continue
			}
			out = append(out, relationshipToJSON(rel))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// detectedEventIDs maps telemetry event ids that contributed to any
// stored detection.
func (s *Server) detectedEventIDs(ctx context.Context) (map[string]bool, error) {
	dets, err := s.backend.Detection.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, d := range dets {
		for _, id := range d.GetTelemetryEventIds() {
			out[id] = true
		}
	}
	return out, nil
}

func parseIPOrEmpty(raw, what string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid %s address", what)
	}
	return addr, nil
}

func isKnownProtocol(p string) bool {
	switch p {
	case "TCP", "UDP", "ICMP", "ICMPV6", "SCTP":
		return true
	}
	return false
}
