// RED: HTTP observation normalization — deterministic, idempotent, explicit failures.
package httpobs

import (
	"reflect"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func httpEvent(attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id:         "evt-http-001",
		OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source:     "lab-http",
		AssetId:    "seed-http-01",
		EventType:  EventTypeHTTPRequest,
		Severity:   v1.Severity_SEVERITY_INFO,
		Attributes: attrs,
	}
}

func TestParseFull(t *testing.T) {
	o, err := Parse(httpEvent(map[string]string{
		"http.method": "get", "http.scheme": "HTTPS", "http.host": "Example.COM",
		"http.path": "/api/v1/users", "http.query_present": "true", "http.status_code": "200",
		"http.content_type": "Application/JSON", "http.route": "/api/v1/users",
		"http.api_version": "v1", "http.request_id": "req-abc", "http.direction": "inbound",
		"http.bytes_in": "123", "http.bytes_out": "456",
	}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.Method != "GET" || o.Scheme != "https" || o.Host != "example.com" {
		t.Fatalf("normalize: %+v", o)
	}
	if o.Path != "/api/v1/users" || !o.QueryPresent || o.StatusCode != 200 || !o.HasStatus {
		t.Fatalf("path/query/status: %+v", o)
	}
	if o.ContentType != "application/json" || o.Route != "/api/v1/users" || o.APIVersion != "v1" {
		t.Fatalf("content/route: %+v", o)
	}
}

func TestParseMinimal(t *testing.T) {
	o, err := Parse(httpEvent(map[string]string{
		"http.method": "POST", "http.host": "seed-lab.example", "http.path": "/login",
	}))
	if err != nil {
		t.Fatalf("minimal: %v", err)
	}
	if o.Method != "POST" || o.Host != "seed-lab.example" || o.Path != "/login" {
		t.Fatalf("minimal fields: %+v", o)
	}
	if o.HasStatus || o.ContentType != "" || o.Route != "" {
		t.Fatalf("optional must stay empty: %+v", o)
	}
}

func TestRedactsSensitive(t *testing.T) {
	o, err := Parse(httpEvent(map[string]string{
		"http.method": "GET", "http.host": "example.com", "http.path": "/",
		"http.authorization": "Bearer secret", "http.cookie": "session=abc",
		"http.api_key": "key123", "http.raw_body": "password=123",
	}))
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if _, ok := o.RawAttrs["http.authorization"]; ok {
		t.Fatalf("sensitive not redacted")
	}
	if _, ok := o.RawAttrs["http.cookie"]; ok {
		t.Fatalf("sensitive not redacted")
	}
}

func TestParseRejects(t *testing.T) {
	base := map[string]string{"http.method": "GET", "http.host": "example.com", "http.path": "/"}
	cases := map[string]struct {
		mutate func(map[string]string)
		event  func(*v1.TelemetryEvent)
	}{
		"wrong type":     {event: func(e *v1.TelemetryEvent) { e.EventType = "waf.request_blocked" }},
		"missing method": {mutate: func(m map[string]string) { delete(m, "http.method") }},
		"missing host":   {mutate: func(m map[string]string) { delete(m, "http.host") }},
		"missing path":   {mutate: func(m map[string]string) { delete(m, "http.path") }},
		"bad method":     {mutate: func(m map[string]string) { m["http.method"] = "FOO" }},
		"bad scheme":     {mutate: func(m map[string]string) { m["http.scheme"] = "ftp" }},
		"bad status":     {mutate: func(m map[string]string) { m["http.status_code"] = "9999" }},
		"bad content":    {mutate: func(m map[string]string) { m["http.content_type"] = "not/a/type/invalid!!" }},
		"bad query":      {mutate: func(m map[string]string) { m["http.query_present"] = "maybe" }},
		"nil event":      {event: func(e *v1.TelemetryEvent) { *e = v1.TelemetryEvent{} }},
	}
	for name, c := range cases {
		attrs := map[string]string{}
		for k, v := range base {
			attrs[k] = v
		}
		if c.mutate != nil {
			c.mutate(attrs)
		}
		e := httpEvent(attrs)
		if c.event != nil {
			c.event(e)
		}
		if _, err := Parse(e); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestIdentityDeterministic(t *testing.T) {
	mk := func() *v1.TelemetryEvent {
		return httpEvent(map[string]string{
			"http.method": "GET", "http.host": "example.com", "http.path": "/api/users",
			"http.status_code": "200",
		})
	}
	a, _ := Parse(mk())
	b, _ := Parse(mk())
	if !reflect.DeepEqual(a, b) || a.ID() == "" || a.ID() != b.ID() {
		t.Fatalf("idempotent: %+v %+v", a, b)
	}
	other, _ := Parse(httpEvent(map[string]string{
		"http.method": "POST", "http.host": "example.com", "http.path": "/api/users",
	}))
	if other.ID() == a.ID() {
		t.Fatalf("different method must differ")
	}
}
