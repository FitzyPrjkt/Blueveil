// Package monitor is the defensive security-monitoring layer: deterministic
// queries over already-persisted telemetry plus explicit SIEM-style
// correlation. It introduces no second event store — callers pass the
// persisted events in, and every result has deterministic ordering
// (occurred_at, then event id). Corrupt rows fail closed with an explicit
// error naming the event; they never silently disappear.
package monitor

import (
	"fmt"
	"sort"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

// MaxLimit bounds monitoring result sets; larger requests are rejected,
// never silently truncated.
const MaxLimit = 1000

// DefaultLimit applies when Query.Limit is zero.
const DefaultLimit = 100

// Query filters monitoring searches. Zero values mean "no constraint"
// except Limit (zero means DefaultLimit) and Detected (nil means either).
type Query struct {
	From          time.Time
	To            time.Time
	Source        string
	EventType     string
	Severity      v1.Severity
	HasSeverity   bool
	AssetID       string
	CorrelationID string
	DetectedIDs   map[string]bool
	Detected      *bool
	Limit         int
	OrderDesc     bool
}

// Execute filters events deterministically. Every returned row passed all
// constraints; ordering is occurred_at then id (reversed for OrderDesc).
func (q Query) Execute(events []*v1.TelemetryEvent) ([]*v1.TelemetryEvent, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 0 || limit > MaxLimit {
		return nil, fmt.Errorf("monitor: limit %d out of [0,%d]", q.Limit, MaxLimit)
	}
	if !q.From.IsZero() && !q.To.IsZero() && q.From.After(q.To) {
		return nil, fmt.Errorf("monitor: time range inverted")
	}
	out := make([]*v1.TelemetryEvent, 0, len(events))
	for _, e := range events {
		if e == nil || e.GetOccurredAt() == nil {
			id := "<nil>"
			if e != nil {
				id = e.GetId()
			}
			return nil, fmt.Errorf("monitor: corrupt persisted event %s fails closed", id)
		}
		at := e.GetOccurredAt().AsTime()
		if !q.From.IsZero() && at.Before(q.From) {
			continue
		}
		if !q.To.IsZero() && at.After(q.To) {
			continue
		}
		if q.Source != "" && e.GetSource() != q.Source {
			continue
		}
		if q.EventType != "" && e.GetEventType() != q.EventType {
			continue
		}
		if q.HasSeverity && e.GetSeverity() != q.Severity {
			continue
		}
		if q.AssetID != "" && e.GetAssetId() != q.AssetID {
			continue
		}
		if q.CorrelationID != "" && e.GetAttributes()["blueveil.correlation_id"] != q.CorrelationID {
			continue
		}
		if q.Detected != nil {
			hit := q.DetectedIDs[e.GetId()]
			if *q.Detected != hit {
				continue
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, bi := out[i].GetOccurredAt().AsTime(), out[j].GetOccurredAt().AsTime()
		if !ai.Equal(bi) {
			if q.OrderDesc {
				return ai.After(bi)
			}
			return ai.Before(bi)
		}
		if q.OrderDesc {
			return out[i].GetId() > out[j].GetId()
		}
		return out[i].GetId() < out[j].GetId()
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
