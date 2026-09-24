// Step 14F: sink-level redaction proof for endpoint events, including
// command-argument scrubbing.
package infraobs

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/asset"
	"blueveil/collector/internal/contract"
	"google.golang.org/protobuf/proto"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
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
	be := store.NewMemoryBackend()
	mgr, err := asset.NewManager(be.Assets, be.Relationships, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	corr, err := NewInfraCorrelator(mgr, be.Relationships,
		InfraCorrelateConfig{AllowAutoCreate: true, AllowedHosts: []string{"web01"}})
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{
		"endpoint.host": "web01", "endpoint.process": "worker",
		"endpoint.action":  "process_start",
		"endpoint.command": "run --token SECRET-MARKER --mode fast",
	}
	for _, k := range contract.SensitiveFragments {
		attrs["endpoint.x-"+k] = "SECRET-MARKER"
	}
	e := &v1.TelemetryEvent{
		Id: "evt-redact-1", OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: "lab", AssetId: "ast-1", EventType: EventTypeEndpointActivity,
		Severity: v1.Severity_SEVERITY_INFO, Attributes: attrs,
	}
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
		if contract.SensitiveField(k) {
			t.Errorf("sensitive key %q reached downstream", k)
		}
		if strings.Contains(v, "SECRET-MARKER") {
			t.Errorf("secret value survived under key %q: %q", k, v)
		}
	}
	if down.got[0].Attributes["endpoint.host"] != "web01" {
		t.Errorf("harmless host must survive: %+v", down.got[0].Attributes)
	}
}
