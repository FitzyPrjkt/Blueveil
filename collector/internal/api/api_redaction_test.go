// Step 14F: API redaction surfaces. Hunting rows never carry
// secret-bearing attributes (defense in depth over the pipeline sinks),
// and identity observations with unredacted secrets never leave the API.
package api

import (
	"strings"
	"testing"

	"blueveil/collector/internal/contract"
)

func TestRedactSecretsInventory(t *testing.T) {
	obj := map[string]any{
		"attributes": map[string]any{
			"rule_id": "r", "principal": "alice",
		},
	}
	attrs := obj["attributes"].(map[string]any)
	for _, k := range contract.SensitiveFragments {
		attrs["x-"+k] = "SECRET-MARKER"
	}
	redactSecrets(obj)
	for k, v := range attrs {
		if contract.SensitiveField(k) {
			t.Errorf("sensitive key %q survived redactSecrets", k)
		}
		if s, ok := v.(string); ok && strings.Contains(s, "SECRET-MARKER") {
			t.Errorf("secret value survived under key %q", k)
		}
	}
	if attrs["rule_id"] != "r" || attrs["principal"] != "alice" {
		t.Errorf("harmless keys must survive: %+v", attrs)
	}
}

func TestHasSensitiveInventory(t *testing.T) {
	for _, k := range contract.SensitiveFragments {
		if !hasSensitive(map[string]string{"x-" + k: "v"}) {
			t.Errorf("hasSensitive must fire on %q", k)
		}
	}
	if hasSensitive(map[string]string{"principal": "alice", "action": "login"}) {
		t.Errorf("hasSensitive must not fire on harmless attributes")
	}
}
