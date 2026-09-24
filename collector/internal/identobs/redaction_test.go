// Step 14F: sink-level redaction proof for identity/auth/data events.
package identobs

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
	be, mgr := testBackend(t)
	corr := newCorr(t, mgr, be, IdentCorrelateConfig{AllowAutoCreate: true, AllowedPrincipals: []string{"alice"}})
	attrs := map[string]string{
		"identity.principal": "alice", "identity.action": "login",
	}
	for _, k := range contract.SensitiveFragments {
		attrs["identity.x-"+k] = "SECRET-MARKER"
	}
	e := identEvt(EventTypeIdentityActivity, "evt-redact-1", attrs)
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
			t.Errorf("secret value survived under key %q", k)
		}
	}
	if down.got[0].Attributes["identity.principal"] != "alice" {
		t.Errorf("harmless principal must survive: %+v", down.got[0].Attributes)
	}
}
