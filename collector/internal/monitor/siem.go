// SIEM-style deterministic correlation over persisted telemetry. Three
// explicit rules; every correlation needs an explicit shared identifier
// (principal, asset/correlation id, host) plus an event-time window.
// Timestamps alone never correlate. Output status is always CORRELATED —
// a correlation is observed co-occurrence, never proof of attack. No
// probabilities, no inference, no AI.
package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

const (
	// CorrelationAuthToIdentity links auth failures to a later identity
	// privilege change for the same principal.
	CorrelationAuthToIdentity = "auth-to-identity-change"
	// CorrelationNetworkToApp links network and application observations
	// sharing one asset or correlation id.
	CorrelationNetworkToApp = "network-to-application"
	// CorrelationEndpointToServer links endpoint and server observations
	// sharing one exact host string.
	CorrelationEndpointToServer = "endpoint-to-server"
)

// StatusCorrelated is the only correlation status: observed, not judged.
const StatusCorrelated = "CORRELATED"

// Correlation is one observed multi-event linkage with provenance.
type Correlation struct {
	ID         string
	Type       string
	EventIDs   []string
	Principal  string
	AssetID    string
	ObservedAt time.Time
	Status     string
}

func correlationID(typ string, eventIDs []string) string {
	sorted := append([]string(nil), eventIDs...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(typ + "\x1f" + joinIDs(sorted)))
	return "corr-" + hex.EncodeToString(sum[:])[:16]
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += "\x1f"
		}
		out += id
	}
	return out
}

func eventTime(e *v1.TelemetryEvent) (time.Time, error) {
	if e == nil || e.GetOccurredAt() == nil {
		return time.Time{}, fmt.Errorf("monitor: corrupt event fails closed")
	}
	return e.GetOccurredAt().AsTime(), nil
}

func checkWindow(window time.Duration) error {
	if window <= 0 {
		return fmt.Errorf("monitor: window must be > 0, got %v", window)
	}
	return nil
}

// CorrelateAuthToIdentity (SIEM-C1): for each identity privilege change
// (role_change/permission_change), collect same-principal auth failures at
// or before the change within window. One correlation per qualifying
// change; failures after the change never join it.
func CorrelateAuthToIdentity(events []*v1.TelemetryEvent, window time.Duration) ([]Correlation, error) {
	if err := checkWindow(window); err != nil {
		return nil, err
	}
	byPrincipal := map[string][]*v1.TelemetryEvent{}
	var changes []*v1.TelemetryEvent
	for _, e := range events {
		if e.GetEventType() == "auth.activity" && e.GetAttributes()["auth.outcome"] == "failure" {
			p := e.GetAttributes()["auth.principal"]
			if p == "" {
				continue
			}
			byPrincipal[p] = append(byPrincipal[p], e)
		}
		if e.GetEventType() == "identity.activity" {
			a := e.GetAttributes()["identity.action"]
			if a == "role_change" || a == "permission_change" {
				changes = append(changes, e)
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].GetId() < changes[j].GetId() })
	var out []Correlation
	for _, c := range changes {
		p := c.GetAttributes()["identity.principal"]
		if p == "" {
			continue
		}
		ct, err := eventTime(c)
		if err != nil {
			return nil, err
		}
		ids := []string{c.GetId()}
		latest := ct
		for _, f := range byPrincipal[p] {
			ft, err := eventTime(f)
			if err != nil {
				return nil, err
			}
			d := ct.Sub(ft)
			if d < 0 || d > window {
				continue
			}
			ids = append(ids, f.GetId())
		}
		if len(ids) < 2 {
			continue
		}
		out = append(out, Correlation{
			ID: correlationID(CorrelationAuthToIdentity, ids), Type: CorrelationAuthToIdentity,
			EventIDs: sortedCopy(ids), Principal: p, ObservedAt: latest, Status: StatusCorrelated,
		})
	}
	if out == nil {
		out = []Correlation{}
	}
	return out, nil
}

func sortedCopy(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

// clusterByTime groups sorted events into time-connected clusters where
// consecutive events differ by at most window.
func clusterByTime(sorted []*v1.TelemetryEvent, window time.Duration) ([][]*v1.TelemetryEvent, error) {
	var clusters [][]*v1.TelemetryEvent
	var cur []*v1.TelemetryEvent
	var prev time.Time
	for _, e := range sorted {
		at, err := eventTime(e)
		if err != nil {
			return nil, err
		}
		if cur == nil || at.Sub(prev) <= window {
			cur = append(cur, e)
		} else {
			clusters = append(clusters, cur)
			cur = []*v1.TelemetryEvent{e}
		}
		prev = at
	}
	if cur != nil {
		clusters = append(clusters, cur)
	}
	return clusters, nil
}

func byTimeAsc(events []*v1.TelemetryEvent) {
	sort.Slice(events, func(i, j int) bool {
		ai, bi := events[i].GetOccurredAt().AsTime(), events[j].GetOccurredAt().AsTime()
		if !ai.Equal(bi) {
			return ai.Before(bi)
		}
		return events[i].GetId() < events[j].GetId()
	})
}

// linkageKey returns the shared asset or correlation id, or "".
func linkageKey(e *v1.TelemetryEvent) string {
	if a := e.GetAssetId(); a != "" {
		return "asset:" + a
	}
	if c := e.GetAttributes()["blueveil.correlation_id"]; c != "" {
		return "corr:" + c
	}
	return ""
}

// CorrelateNetworkToApp (SIEM-C2): network + application observations
// sharing one asset/correlation id, clustered by window. Timestamp
// proximity without shared linkage never correlates.
func CorrelateNetworkToApp(events []*v1.TelemetryEvent, window time.Duration) ([]Correlation, error) {
	if err := checkWindow(window); err != nil {
		return nil, err
	}
	groups := map[string][]*v1.TelemetryEvent{}
	for _, e := range events {
		t := e.GetEventType()
		if t != "net.connection" && t != "http.request" {
			continue
		}
		if k := linkageKey(e); k != "" {
			groups[k] = append(groups[k], e)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Correlation
	for _, k := range keys {
		g := groups[k]
		byTimeAsc(g)
		clusters, err := clusterByTime(g, window)
		if err != nil {
			return nil, err
		}
		for _, cl := range clusters {
			var hasNet, hasHTTP bool
			var latest time.Time
			ids := make([]string, 0, len(cl))
			for _, e := range cl {
				if e.GetEventType() == "net.connection" {
					hasNet = true
				} else {
					hasHTTP = true
				}
				ids = append(ids, e.GetId())
				if at := e.GetOccurredAt().AsTime(); at.After(latest) {
					latest = at
				}
			}
			if !hasNet || !hasHTTP {
				continue
			}
			asset := ""
			if len(cl) > 0 {
				asset = cl[0].GetAssetId()
			}
			out = append(out, Correlation{
				ID: correlationID(CorrelationNetworkToApp, ids), Type: CorrelationNetworkToApp,
				EventIDs: sortedCopy(ids), AssetID: asset, ObservedAt: latest, Status: StatusCorrelated,
			})
		}
	}
	if out == nil {
		out = []Correlation{}
	}
	return out, nil
}

// CorrelateEndpointToServer (SIEM-C3): endpoint + server observations with
// exactly equal host strings, clustered by window.
func CorrelateEndpointToServer(events []*v1.TelemetryEvent, window time.Duration) ([]Correlation, error) {
	if err := checkWindow(window); err != nil {
		return nil, err
	}
	groups := map[string][]*v1.TelemetryEvent{}
	for _, e := range events {
		var host string
		switch e.GetEventType() {
		case "endpoint.activity":
			host = e.GetAttributes()["endpoint.host"]
		case "server.activity":
			host = e.GetAttributes()["server.hostname"]
		default:
			continue
		}
		if host == "" {
			continue
		}
		groups[host] = append(groups[host], e)
	}
	hosts := make([]string, 0, len(groups))
	for h := range groups {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	var out []Correlation
	for _, h := range hosts {
		g := groups[h]
		byTimeAsc(g)
		clusters, err := clusterByTime(g, window)
		if err != nil {
			return nil, err
		}
		for _, cl := range clusters {
			var hasEndpoint, hasServer bool
			var latest time.Time
			ids := make([]string, 0, len(cl))
			for _, e := range cl {
				if e.GetEventType() == "endpoint.activity" {
					hasEndpoint = true
				} else {
					hasServer = true
				}
				ids = append(ids, e.GetId())
				if at := e.GetOccurredAt().AsTime(); at.After(latest) {
					latest = at
				}
			}
			if !hasEndpoint || !hasServer {
				continue
			}
			out = append(out, Correlation{
				ID: correlationID(CorrelationEndpointToServer, ids), Type: CorrelationEndpointToServer,
				EventIDs: sortedCopy(ids), AssetID: h, ObservedAt: latest, Status: StatusCorrelated,
			})
		}
	}
	if out == nil {
		out = []Correlation{}
	}
	return out, nil
}
