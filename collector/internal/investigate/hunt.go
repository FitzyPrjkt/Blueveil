// Package investigate is the defensive investigation layer: read-only
// hunting queries, deterministic timelines, metadata-level forensic
// artifacts, and derived investigative signals. It composes existing
// monitoring, telemetry, detection, incident, and evidence stores — no
// parallel stores, engines, or safety systems. Nothing here acquires
// memory, disk, packets, or cloud state; everything analyzes
// already-persisted observations.
package investigate

import (
	"fmt"
	"strings"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/monitor"
)

// HuntResultKind tags every hunting row: an observed result, never a
// confirmed attack.
const HuntResultKind = "HUNT_RESULT"

// MaxLimit bounds hunting result sets; DefaultLimit applies when unset.
const (
	MaxLimit     = 1000
	DefaultLimit = 100
)

// principalKeys are the attribute keys that may carry a principal name.
// Fixed list over real parser fields — no guessing, no inference.
var principalKeys = []string{
	"auth.principal",
	"identity.principal",
	"data.principal",
	"endpoint.user",
	"cloud.principal",
	"container.user",
	"server.user",
}

// HuntQuery composes monitor.Query with principal and keyword dimensions.
type HuntQuery struct {
	monitor.Query
	Principal string
	Keyword   string
}

// Execute filters events deterministically (occurred_at, then id).
// Keyword is a bounded case-insensitive substring over id, source,
// asset, event type, and string attribute values only — no SQL, no DB
// internals. Corrupt rows fail closed.
func (q HuntQuery) Execute(events []*v1.TelemetryEvent) ([]*v1.TelemetryEvent, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 0 || limit > MaxLimit {
		return nil, fmt.Errorf("investigate: limit %d out of [0,%d]", q.Limit, MaxLimit)
	}
	base := q.Query
	base.Limit = 0 // apply our own bound after keyword filtering
	rows, err := base.Execute(events)
	if err != nil {
		return nil, err
	}
	kw := strings.ToLower(strings.TrimSpace(q.Keyword))
	out := make([]*v1.TelemetryEvent, 0, len(rows))
	for _, e := range rows {
		if q.Principal != "" && !hasPrincipal(e, q.Principal) {
			continue
		}
		if kw != "" && !matchesKeyword(e, kw) {
			continue
		}
		out = append(out, e)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func hasPrincipal(e *v1.TelemetryEvent, principal string) bool {
	return PrincipalOf(e.GetAttributes()) == principal && principal != ""
}

// PrincipalOf returns the first non-empty principal attribute using the
// fixed parser-field list, or "". Shared by hunting and H1 so both agree
// on what "same principal" means.
func PrincipalOf(attrs map[string]string) string {
	for _, k := range principalKeys {
		if v := attrs[k]; v != "" {
			return v
		}
	}
	return ""
}

func matchesKeyword(e *v1.TelemetryEvent, kw string) bool {
	if strings.Contains(strings.ToLower(e.GetId()), kw) ||
		strings.Contains(strings.ToLower(e.GetSource()), kw) ||
		strings.Contains(strings.ToLower(e.GetAssetId()), kw) ||
		strings.Contains(strings.ToLower(e.GetEventType()), kw) {
		return true
	}
	for _, v := range e.GetAttributes() {
		if strings.Contains(strings.ToLower(v), kw) {
			return true
		}
	}
	return false
}

// TimeRange validates a from/to pair shared by investigation endpoints.
func TimeRange(from, to time.Time) error {
	if !from.IsZero() && !to.IsZero() && from.After(to) {
		return fmt.Errorf("investigate: time range inverted")
	}
	return nil
}
