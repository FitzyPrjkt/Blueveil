// RED: deterministic hunting query composes monitor.Query; keyword is a
// bounded substring over safe fields only — no SQL, no DB internals.
package investigate

import (
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func mkEvt(id, typ, source, asset string, minute int, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(time.Duration(minute) * time.Minute)),
		Source: source, AssetId: asset, EventType: typ, Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
}

func huntFixture() []*v1.TelemetryEvent {
	return []*v1.TelemetryEvent{
		mkEvt("h1", "endpoint.activity", "seed-lab-investigation", "seed-inv-01", 0,
			map[string]string{"endpoint.host": "web01", "endpoint.process": "agent", "endpoint.action": "process_start"}),
		mkEvt("h2", "auth.activity", "seed-lab-investigation", "seed-inv-01", 1,
			map[string]string{"auth.principal": "erin", "auth.outcome": "failure"}),
		mkEvt("h3", "net.connection", "other-source", "seed-inv-02", 2,
			map[string]string{"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1"}),
	}
}

func TestHuntFilters(t *testing.T) {
	evts := huntFixture()
	cases := map[string]struct {
		q    HuntQuery
		want []string
	}{
		"empty matches all": {HuntQuery{}, []string{"h1", "h2", "h3"}},
		"source":            {HuntQuery{Source: "other-source"}, []string{"h3"}},
		"principal":         {HuntQuery{Principal: "erin"}, []string{"h2"}},
		"keyword id":        {HuntQuery{Keyword: "h3"}, []string{"h3"}},
		"keyword attr":      {HuntQuery{Keyword: "web01"}, []string{"h1"}},
		"keyword type":      {HuntQuery{Keyword: "net.connection"}, []string{"h3"}},
		"combined":          {HuntQuery{Source: "seed-lab-investigation", Principal: "erin"}, []string{"h2"}},
		"limit":             {HuntQuery{Limit: 2}, []string{"h1", "h2"}},
		"no match":          {HuntQuery{Keyword: "zzz-no-such"}, []string{}},
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

func TestHuntValidation(t *testing.T) {
	evts := huntFixture()
	for name, q := range map[string]HuntQuery{
		"limit over max": {Limit: 1001},
		"negative limit": {Limit: -1},
	} {
		if _, err := q.Execute(evts); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Default limit applies without error.
	if _, err := (HuntQuery{}).Execute(evts); err != nil {
		t.Errorf("default query: %v", err)
	}
}

func TestHuntCorruptFailsClosed(t *testing.T) {
	evts := huntFixture()
	evts[0].OccurredAt = nil
	if _, err := (HuntQuery{}).Execute(evts); err == nil {
		t.Errorf("corrupt event must fail closed")
	}
}

func TestHuntKindMarksResults(t *testing.T) {
	// Hunt results are data rows tagged HUNT_RESULT by the caller-facing
	// row shape, never CONFIRMED_ATTACK.
	if HuntResultKind != "HUNT_RESULT" {
		t.Errorf("hunt kind must be HUNT_RESULT, got %q", HuntResultKind)
	}
}

func ids(evts []*v1.TelemetryEvent) []string {
	out := make([]string, 0, len(evts))
	for _, e := range evts {
		out = append(out, e.GetId())
	}
	return out
}
