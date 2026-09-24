// Step 14F: sink-level redaction proof. Secret-bearing attributes must
// be gone from the event the downstream (persistence) receives — for
// every key in the sensitive inventory.
package httpobs

import (
	"context"
	"strings"
	"testing"

	"blueveil/collector/internal/contract"
	"google.golang.org/protobuf/proto"

	v1 "blueveil/collector/internal/contract/v1"
)

type captureDownstream struct {
	got []*v1.TelemetryEvent
}

func (c *captureDownstream) Emit(_ context.Context, e *v1.TelemetryEvent) error {
	cp := proto.Clone(e).(*v1.TelemetryEvent)
	c.got = append(c.got, cp)
	return nil
}

func TestSinkRedactsInventory(t *testing.T) {
	ctx := context.Background()
	corr, _ := httpSetup(t, HTTPCorrelateConfig{AllowAutoCreate: true, AllowedHosts: []string{"example.com"}})
	attrs := map[string]string{
		"http.method": "GET", "http.host": "example.com", "http.path": "/",
	}
	for _, k := range contract.SensitiveFragments {
		attrs["http.x-"+k] = "SECRET-MARKER"
	}
	attrs["http.raw_body"] = "SECRET-MARKER"
	e := httpEvent(attrs)
	down := &captureDownstream{}
	sink, err := NewCorrelatingSink(corr, down)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(ctx, e); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(down.got) != 1 {
		t.Fatalf("downstream must receive exactly one event, got %d", len(down.got))
	}
	for k, v := range down.got[0].Attributes {
		if contract.SensitiveField(k) || strings.Contains(strings.ToLower(k), "raw_body") {
			t.Errorf("sensitive key %q reached downstream", k)
		}
		if strings.Contains(v, "SECRET-MARKER") {
			t.Errorf("secret value survived under key %q", k)
		}
	}
	for _, keep := range []string{"http.method", "http.host", "http.path"} {
		if _, ok := down.got[0].Attributes[keep]; !ok {
			t.Errorf("harmless key %q must survive", keep)
		}
	}
}
