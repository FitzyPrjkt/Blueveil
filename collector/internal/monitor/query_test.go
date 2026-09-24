// RED: deterministic monitoring query over persisted telemetry.
package monitor

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func mkEvt(id, source, typ, asset, sev string, minute int, corr string) *v1.TelemetryEvent {
	attrs := map[string]string{}
	if corr != "" {
		attrs["blueveil.correlation_id"] = corr
	}
	sevv := v1.Severity_SEVERITY_INFO
	if sev == "HIGH" {
		sevv = v1.Severity_SEVERITY_HIGH
	}
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(time.Duration(minute) * time.Minute)),
		Source: source, AssetId: asset, EventType: typ, Severity: sevv, Attributes: attrs,
	}
}

func fixtureEvents() []*v1.TelemetryEvent {
	return []*v1.TelemetryEvent{
		mkEvt("e1", "s1", "auth.activity", "a1", "INFO", 0, "c1"),
		mkEvt("e2", "s1", "auth.activity", "a1", "HIGH", 1, "c1"),
		mkEvt("e3", "s2", "net.connection", "a2", "INFO", 2, ""),
		mkEvt("e4", "s2", "http.request", "a2", "INFO", 3, "c2"),
	}
}

func TestQueryFilters(t *testing.T) {
	evts := fixtureEvents()
	cases := map[string]struct {
		q    Query
		want []string
	}{
		"empty matches all": {Query{}, []string{"e1", "e2", "e3", "e4"}},
		"source":            {Query{Source: "s1"}, []string{"e1", "e2"}},
		"event type":        {Query{EventType: "net.connection"}, []string{"e3"}},
		"severity":          {Query{Severity: v1.Severity_SEVERITY_HIGH, HasSeverity: true}, []string{"e2"}},
		"asset":             {Query{AssetID: "a2"}, []string{"e3", "e4"}},
		"correlation":       {Query{CorrelationID: "c1"}, []string{"e1", "e2"}},
		"time range":        {Query{From: ts(1), To: ts(2)}, []string{"e2", "e3"}},
		"limit":             {Query{Limit: 2}, []string{"e1", "e2"}},
		"desc":              {Query{OrderDesc: true}, []string{"e4", "e3", "e2", "e1"}},
		"combined":          {Query{Source: "s2", AssetID: "a2"}, []string{"e3", "e4"}},
		"detected ids":      {Query{DetectedIDs: map[string]bool{"e2": true, "e4": true}, Detected: boolPtr(true)}, []string{"e2", "e4"}},
		"undetected only":   {Query{DetectedIDs: map[string]bool{"e2": true}, Detected: boolPtr(false)}, []string{"e1", "e3", "e4"}},
	}
	for name, c := range cases {
		got, err := c.q.Execute(evts)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, ids(got))
			continue
		}
		for i := range got {
			if got[i].GetId() != c.want[i] {
				t.Errorf("%s: want %v, got %v", name, c.want, ids(got))
				break
			}
		}
	}
}

func TestQueryValidation(t *testing.T) {
	evts := fixtureEvents()
	for name, q := range map[string]Query{
		"bad limit":    {Limit: -1},
		"limit excess": {Limit: MaxLimit + 1},
		"bad range":    {From: ts(5), To: ts(1)},
	} {
		if _, err := q.Execute(evts); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestQueryCorruptFailsClosed(t *testing.T) {
	evts := fixtureEvents()
	evts[1].OccurredAt = nil // corrupt persisted row
	if _, err := (Query{}).Execute(evts); err == nil {
		t.Errorf("corrupt event must fail closed, not disappear")
	}
}

func ts(m int) time.Time {
	return time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(time.Duration(m) * time.Minute)
}

func boolPtr(b bool) *bool { return &b }

func ids(evts []*v1.TelemetryEvent) []string {
	out := make([]string, 0, len(evts))
	for _, e := range evts {
		out = append(out, e.GetId())
	}
	return out
}
