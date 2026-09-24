// End-to-end telemetry test: realistic local source (JSON-lines) through
// the full pipeline into canonical protojson bytes, validated back against
// the contract. Telemetry only: nothing here detects, alerts, or responds.
package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/correlate"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/source"
)

const e2eInput = `{"id":"evt-e2e-01","source":"lab-waf","asset_id":"asset-web-01","event_type":"waf.request_blocked","severity":"SEVERITY_HIGH","attributes":{"_note":"synthetic e2e fixture, not a finding"},"occurred_at":"2026-09-12T09:00:00Z"}
{"id":"evt-e2e-02","source":"lab-waf","asset_id":"asset-web-01","event_type":"waf.request_blocked","severity":"SEVERITY_MEDIUM","occurred_at":"2026-09-12T09:01:00Z"}
{"id":"evt-e2e-03","source":"lab-waf","asset_id":"asset-web-01","event_type":"waf.request_allowed","severity":"SEVERITY_INFO","occurred_at":"2026-09-12T09:02:00Z"}
{"id":"broken-line
{"id":"","source":"lab-waf"}
`

func TestTelemetryPipelineEndToEnd(t *testing.T) {
	ctx := context.Background()
	src := source.NewReaderSource(strings.NewReader(e2eInput))
	en, err := enrich.New("e2e-collector", func() time.Time {
		return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("enricher: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "telemetry.jsonl")
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	lines, err := NewLineSink(f)
	if err != nil {
		t.Fatalf("linesink: %v", err)
	}
	pipe, err := NewPipeline(Config{QueueSize: 4}, src, lines)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	pipe.WithEnricher(en).WithCorrelation(true)

	report, err := pipe.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close output: %v", err)
	}

	// Accounting: 5 lines in, 1 malformed at source, 4 through the pipeline,
	// 3 accepted, 1 rejected (semantically empty).
	if len(report.SourceErrors) != 1 || report.SourceErrors[0].Line != 4 {
		t.Fatalf("source errors: %+v", report.SourceErrors)
	}
	if report.Accepted != 3 || len(report.Rejected) != 1 {
		t.Fatalf("report: %+v", report)
	}
	m := report.Metrics
	if m.Received != 4 || m.Accepted != 3 || m.Rejected != 1 || m.NormalizeErrs != 1 {
		t.Fatalf("metrics: %+v", m)
	}
	if lines.Lines() != 3 || lines.Bytes() <= 0 {
		t.Fatalf("linesink wrote %d lines %d bytes", lines.Lines(), lines.Bytes())
	}

	// Every emitted line parses back and validates against the contract.
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	texts := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(texts) != 3 {
		t.Fatalf("want 3 lines, got %d", len(texts))
	}
	byID := map[string]*v1.TelemetryEvent{}
	for _, text := range texts {
		var e v1.TelemetryEvent
		if err := contract.UnmarshalStrict([]byte(text), &e); err != nil {
			t.Fatalf("emitted line must parse: %v\n%s", err, text)
		}
		if err := contract.ValidateTelemetryEvent(&e); err != nil {
			t.Fatalf("emitted line must validate: %v", err)
		}
		byID[e.GetId()] = &e
	}

	// Enrichment: deterministic collector identity and timestamp on all.
	for id, e := range byID {
		if e.GetAttributes()["blueveil.collector"] != "e2e-collector" {
			t.Fatalf("%s missing collector enrichment: %v", id, e.GetAttributes())
		}
		if e.GetAttributes()["blueveil.collected_at"] != "2026-09-12T10:00:00Z" {
			t.Fatalf("%s missing collection timestamp: %v", id, e.GetAttributes())
		}
		// No fabricated security metadata anywhere.
		for k := range e.GetAttributes() {
			if strings.HasPrefix(k, "blueveil.threat") || strings.HasPrefix(k, "blueveil.ioc") ||
				k == "blueveil.verdict" || k == "blueveil.confidence" {
				t.Fatalf("%s carries fabricated security metadata %q", id, k)
			}
		}
	}

	// Correlation: the two blocked-request events share one id; the allowed
	// request carries a different one. Metadata association only.
	c1 := byID["evt-e2e-01"].GetAttributes()[correlate.AttributeKey]
	c2 := byID["evt-e2e-02"].GetAttributes()[correlate.AttributeKey]
	c3 := byID["evt-e2e-03"].GetAttributes()[correlate.AttributeKey]
	if c1 == "" || c1 != c2 {
		t.Fatalf("related events must share correlation id: %q %q", c1, c2)
	}
	if c1 == c3 {
		t.Fatalf("unrelated events must differ: %q", c3)
	}
	if want := correlate.IDFor("lab-waf", "asset-web-01", "waf.request_blocked"); c1 != want {
		t.Fatalf("correlation id must be the deterministic digest, got %q want %q", c1, want)
	}
}
