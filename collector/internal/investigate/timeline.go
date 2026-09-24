// Investigation timeline: one deterministic ordering over telemetry,
// detections, alerts, incidents, evidence, and correlations. Ordered by
// occurred_at with stable id tie-breaking. Temporal adjacency is
// presentation order only — the timeline never claims causality.
package investigate

import (
	"fmt"
	"sort"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/monitor"
)

// Entry kinds in timeline output.
const (
	KindTelemetry   = "telemetry"
	KindDetection   = "detection"
	KindAlert       = "alert"
	KindIncident    = "incident"
	KindEvidence    = "evidence"
	KindCorrelation = "correlation"
)

// TimelineInput gathers the persisted objects to order. Correlations
// come from the monitor package (13F); everything else from stores.
type TimelineInput struct {
	Events       []*v1.TelemetryEvent
	Detections   []*v1.Detection
	Alerts       []*v1.Alert
	Incidents    []*v1.Incident
	Evidence     []*v1.Evidence
	Correlations []monitor.Correlation
}

// TimelineEntry is one ordered row with provenance. Principal is filled
// only where a parser field safely carries it (same fixed key list as
// hunting); secrets never appear here because sources are redacted
// upstream and content is never embedded.
type TimelineEntry struct {
	OccurredAt    time.Time
	Kind          string
	ID            string
	Source        string
	AssetID       string
	Principal     string
	RuleID        string
	CorrelationID string
	EvidenceID    string
	IncidentID    string
	Summary       string
}

func principalOf(attrs map[string]string) string {
	for _, k := range principalKeys {
		if v := attrs[k]; v != "" {
			return v
		}
	}
	return ""
}

// BuildTimeline orders all inputs by occurred_at, breaking ties by
// (kind, id) so any input order yields identical output. Nil timestamps
// fail closed with the offending id.
func BuildTimeline(in TimelineInput) ([]TimelineEntry, error) {
	var out []TimelineEntry
	for _, e := range in.Events {
		if e == nil || e.GetOccurredAt() == nil {
			return nil, fmt.Errorf("investigate: corrupt telemetry %s fails closed", idOf(e))
		}
		out = append(out, TimelineEntry{
			OccurredAt: e.GetOccurredAt().AsTime(), Kind: KindTelemetry, ID: e.GetId(),
			Source: e.GetSource(), AssetID: e.GetAssetId(), Principal: principalOf(e.GetAttributes()),
			CorrelationID: e.GetAttributes()["blueveil.correlation_id"],
			Summary:       e.GetEventType(),
		})
	}
	for _, d := range in.Detections {
		if d == nil || d.GetDetectedAt() == nil {
			return nil, fmt.Errorf("investigate: corrupt detection fails closed")
		}
		out = append(out, TimelineEntry{
			OccurredAt: d.GetDetectedAt().AsTime(), Kind: KindDetection, ID: d.GetId(),
			RuleID: d.GetRuleId(), Summary: d.GetTitle(),
		})
	}
	for _, a := range in.Alerts {
		if a == nil || a.GetCreatedAt() == nil {
			return nil, fmt.Errorf("investigate: corrupt alert fails closed")
		}
		out = append(out, TimelineEntry{
			OccurredAt: a.GetCreatedAt().AsTime(), Kind: KindAlert, ID: a.GetId(),
			Summary: a.GetTitle(),
		})
	}
	for _, i := range in.Incidents {
		if i == nil || i.GetCreatedAt() == nil {
			return nil, fmt.Errorf("investigate: corrupt incident fails closed")
		}
		out = append(out, TimelineEntry{
			OccurredAt: i.GetCreatedAt().AsTime(), Kind: KindIncident, ID: i.GetId(),
			Summary: i.GetTitle(),
		})
	}
	for _, e := range in.Evidence {
		if e == nil || e.GetCollectedAt() == nil {
			return nil, fmt.Errorf("investigate: corrupt evidence fails closed")
		}
		out = append(out, TimelineEntry{
			OccurredAt: e.GetCollectedAt().AsTime(), Kind: KindEvidence, ID: e.GetId(),
			Source: e.GetSource(), EvidenceID: e.GetId(), IncidentID: e.GetIncidentId(),
			Summary: string(e.GetType()),
		})
	}
	for _, c := range in.Correlations {
		if c.ObservedAt.IsZero() {
			return nil, fmt.Errorf("investigate: corrupt correlation %s fails closed", c.ID)
		}
		out = append(out, TimelineEntry{
			OccurredAt: c.ObservedAt, Kind: KindCorrelation, ID: c.ID,
			Principal: c.Principal, AssetID: c.AssetID, CorrelationID: c.ID,
			Summary: c.Type,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func idOf(e *v1.TelemetryEvent) string {
	if e == nil {
		return "<nil>"
	}
	return e.GetId()
}
