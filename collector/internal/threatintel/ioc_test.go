// RED: offline IOC set loading (Python-normalized) + exact matching.
package threatintel

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func writeSet(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "iocs.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

const labSet = `[
  {"kind":"ip","value":"203.0.113.7","source":"lab-ioc-v1"},
  {"kind":"domain","value":"Malicious-Test.EXAMPLE.","source":"lab-ioc-v1"},
  {"kind":"sha256","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"lab-ioc-v1"}
]`

func TestLoadSetNormalizesViaPython(t *testing.T) {
	set, err := LoadSet(writeSet(t, labSet), "lab-ioc-set", "v1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.ID != "lab-ioc-set" || set.Version != "v1" || len(set.Entries) != 3 {
		t.Fatalf("set identity wrong: %+v", set)
	}
	// Python normalization applied: domain lowered + trailing dot stripped.
	if set.Entries[1].Value != "malicious-test.example" {
		t.Fatalf("domain not Python-normalized: %+v", set.Entries[1])
	}
	if set.Entries[0].Value != "203.0.113.7" {
		t.Fatalf("ip wrong: %+v", set.Entries[0])
	}
}

func TestLoadSetRejects(t *testing.T) {
	for name, content := range map[string]string{
		"not json":     `nope`,
		"not array":    `{"kind":"ip"}`,
		"unknown kind": `[{"kind":"md5","value":"x","source":"s"}]`,
		"bad ip":       `[{"kind":"ip","value":"999.1.1.1","source":"s"}]`,
		"empty id":     ``,
	} {
		var err error
		if content == "" {
			_, err = LoadSet(writeSet(t, content), "", "v1")
		} else {
			_, err = LoadSet(writeSet(t, content), "s", "v1")
		}
		if err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := LoadSet("/nonexistent/iocs.json", "s", "v1"); err == nil {
		t.Errorf("missing file must error")
	}
	if _, err := LoadSet(writeSet(t, labSet), "s", ""); err == nil {
		t.Errorf("empty version must error")
	}
}

func mkEvt(id, typ string, attrs map[string]string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: "s", AssetId: "a", EventType: typ, Severity: v1.Severity_SEVERITY_INFO,
		Attributes: attrs,
	}
}

func TestMatchExact(t *testing.T) {
	set, err := LoadSet(writeSet(t, labSet), "lab-ioc-set", "v1")
	if err != nil {
		t.Fatal(err)
	}
	hit := mkEvt("m1", "net.connection", map[string]string{"net.dst_ip": "203.0.113.7"})
	matches := MatchEvent(hit, set)
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %+v", matches)
	}
	m := matches[0]
	if m.Indicator != "203.0.113.7" || m.Kind != "ip" || m.SetID != "lab-ioc-set" || m.SetVersion != "v1" {
		t.Fatalf("match provenance wrong: %+v", m)
	}
	if m.EventID != "m1" || m.MatchedField == "" {
		t.Fatalf("match identity wrong: %+v", m)
	}
	if m.ID == "" {
		t.Fatalf("stable match id required")
	}
	// Normalization-equivalent spelling matches (upper-case domain attr).
	hit2 := mkEvt("m2", "http.request", map[string]string{"http.host": "MALICIOUS-TEST.EXAMPLE"})
	if len(MatchEvent(hit2, set)) != 1 {
		t.Fatalf("equivalent spelling must match")
	}
	// Near-miss must NOT match (no fuzzy matching).
	near := mkEvt("m3", "net.connection", map[string]string{"net.dst_ip": "203.0.113.70"})
	if len(MatchEvent(near, set)) != 0 {
		t.Fatalf("near-miss must not match: %+v", MatchEvent(near, set))
	}
	// Unrelated value: nothing.
	plain := mkEvt("m4", "auth.activity", map[string]string{"auth.principal": "alice"})
	if len(MatchEvent(plain, set)) != 0 {
		t.Fatalf("unrelated must not match")
	}
	// Deterministic: same input, same match id.
	again := MatchEvent(hit, set)
	if again[0].ID != m.ID {
		t.Fatalf("match id unstable")
	}
}
