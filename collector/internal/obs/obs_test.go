// Step 15G RED: operational observability. Structured logs with
// request/correlation IDs and zero secret material; honest counters
// only (no security scores, no invented metrics).
package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggerRedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	l, err := New("info", "json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	l.Info("auth attempt", "key_id", "k1", "authorization", "Bearer SECRET-VALUE",
		"password", "hunter2", "path", "/api/v1/assets")
	out := buf.String()
	for _, secret := range []string{"SECRET-VALUE", "hunter2", "Bearer"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log leaks secret %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "k1") || !strings.Contains(out, "/api/v1/assets") {
		t.Fatalf("operational fields must survive: %s", out)
	}
}

func TestLoggerLevelsAndFormats(t *testing.T) {
	if _, err := New("verbose", "json", &bytes.Buffer{}); err == nil {
		t.Fatalf("unknown level must fail")
	}
	if _, err := New("info", "yaml", &bytes.Buffer{}); err == nil {
		t.Fatalf("unknown format must fail")
	}
	var buf bytes.Buffer
	l, err := New("warn", "text", &buf)
	if err != nil {
		t.Fatal(err)
	}
	l.Info("dropped below level")
	l.Warn("kept")
	if strings.Contains(buf.String(), "dropped below level") {
		t.Fatalf("level filtering broken")
	}
	if !strings.Contains(buf.String(), "kept") {
		t.Fatalf("warn must emit")
	}
}

func TestMetricsCountHonestly(t *testing.T) {
	m := NewMetrics()
	m.Request()
	m.Request()
	m.RequestError(401)
	m.RequestError(500)
	m.PersistenceFailure()
	m.IngestAccepted()
	m.IngestRejected()
	m.DetectionError()
	m.ValidationProviderError()
	snap := m.Snapshot()
	want := map[string]uint64{
		"requests_total": 2, "request_errors_4xx": 1, "request_errors_5xx": 1,
		"persistence_failures": 1, "ingest_accepted": 1, "ingest_rejected": 1,
		"detection_errors": 1, "validation_provider_errors": 1,
	}
	for k, v := range want {
		if snap[k] != v {
			t.Errorf("metric %s: want %d, got %d", k, v, snap[k])
		}
	}
	// Snapshot is a copy: mutating it changes nothing.
	snap["requests_total"] = 999
	if m.Snapshot()["requests_total"] != 2 {
		t.Fatalf("snapshot must be a copy")
	}
}

func TestLoggerIsStructured(t *testing.T) {
	var buf bytes.Buffer
	l, err := New("info", "json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	l.Info("started", "component", "serve", "addr", "127.0.0.1:8008")
	out := buf.String()
	for _, frag := range []string{`"msg":"started"`, `"component":"serve"`, `"time":`} {
		if !strings.Contains(out, frag) {
			t.Fatalf("missing structured field %s: %s", frag, out)
		}
	}
	_ = slog.Default()
}
