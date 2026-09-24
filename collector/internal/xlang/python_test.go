// Cross-language boundary test (Step 11D): the Python extension speaks,
// the Go contract boundary judges.
//
// Python --(canonical JSON)--> Go UnmarshalStrict + ValidateTelemetryEvent.
// Fixtures come from Step 2 (not hand-built): the valid telemetry fixture
// flows through `blueveil_ioc enrich` and must come back contract-valid
// with enrichment attached; malformed stdin must be rejected with a
// non-zero exit. Nothing here compares snapshots — the real validators run.
package xlang

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

func pythonRoot(t *testing.T) string {
	t.Helper()
	if override := os.Getenv("BLUEVEIL_PYTHON_EXT"); override != "" {
		return override
	}
	// Package dir collector/internal/xlang → Blueveil/extensions/python.
	root := filepath.Join("..", "..", "..", "extensions", "python")
	if _, err := os.Stat(filepath.Join(root, "blueveil_ioc", "__init__.py")); err != nil {
		t.Skipf("python extension not found at %s (set BLUEVEIL_PYTHON_EXT)", root)
	}
	return root
}

func python3(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH; cannot prove the cross-language boundary")
	}
	return path
}

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "fixtures", rel))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func writeIndicators(t *testing.T, dir string) string {
	t.Helper()
	// Deliberately un-normalized spellings: the extension must canonicalize
	// before matching (Example.COM. must hit example.com in raw).
	raw := `[{"kind":"domain","value":"Example.COM.","source":"xlang-test"},
	        {"kind":"ip","value":"127.0.0.1","source":"xlang-test"}]`
	path := filepath.Join(dir, "indicators.json")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPythonEnrichOutputIsContractValid(t *testing.T) {
	py := python3(t)
	root := pythonRoot(t)
	dir := t.TempDir()

	cmd := exec.Command(py, "-m", "blueveil_ioc", "enrich", "--indicators", writeIndicators(t, dir))
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(string(fixture(t, "telemetry/valid.json")))
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("python enrich failed: %v (%s)", err, ee.Stderr)
		}
		t.Fatalf("python enrich failed to run: %v", err)
	}

	// Determinism: byte-identical output on re-run.
	cmd2 := exec.Command(py, "-m", "blueveil_ioc", "enrich", "--indicators", filepath.Join(dir, "indicators.json"))
	cmd2.Dir = root
	cmd2.Stdin = strings.NewReader(string(fixture(t, "telemetry/valid.json")))
	out2, err := cmd2.Output()
	if err != nil || string(out) != string(out2) {
		t.Fatal("extension output must be deterministic")
	}

	var enriched v1.TelemetryEvent
	if err := contract.UnmarshalStrict(out, &enriched); err != nil {
		t.Fatalf("python output must parse under proto JSON mapping: %v", err)
	}
	if err := contract.ValidateTelemetryEvent(&enriched); err != nil {
		t.Fatalf("python output must validate: %v", err)
	}
	// Identity, enums, timestamps preserved from the fixture.
	// (2026-09-12T09:00:00Z as observed through the real parser, not assumed.)
	if enriched.GetId() != "evt-test-001" ||
		enriched.GetSeverity() != v1.Severity_SEVERITY_HIGH ||
		enriched.GetOccurredAt().GetSeconds() != 1789203600 {
		t.Fatalf("contract fields drifted: %+v", &enriched)
	}
	attrs := enriched.GetAttributes()
	if !strings.Contains(attrs["blueveil.python.ioc_match"], "127.0.0.1|attributes.client_ip") {
		t.Fatalf("attribute match missing: %v", attrs)
	}
	if attrs["rule_id"] != "CRS-941100" {
		t.Fatalf("source attributes must survive enrichment: %v", attrs)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	if _, hasCamel := raw["occurredAt"]; hasCamel {
		t.Fatal("canonical form must stay snake_case across the language boundary")
	}
}

func TestPythonCanonicalizesBeforeMatching(t *testing.T) {
	py := python3(t)
	root := pythonRoot(t)
	dir := t.TempDir()

	// Synthetic input (labeled): un-normalized spelling in raw must still
	// match after the extension canonicalizes both sides.
	input := `{"id":"evt-xlang-001","occurred_at":"2026-09-12T09:00:00Z",` +
		`"source":"xlang-test","asset_id":"asset-x","event_type":"dns.query",` +
		`"severity":"SEVERITY_INFO","raw":"GET http://Example.COM./x"}`
	cmd := exec.Command(py, "-m", "blueveil_ioc", "enrich", "--indicators", writeIndicators(t, dir))
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python enrich failed: %v", err)
	}
	var enriched v1.TelemetryEvent
	if err := contract.UnmarshalStrict(out, &enriched); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := contract.ValidateTelemetryEvent(&enriched); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := enriched.GetAttributes()["blueveil.python.ioc_match"]; !strings.Contains(got, "example.com|raw") {
		t.Fatalf("un-normalized spelling must match post-canonicalization: %q", got)
	}
}

func TestPythonRejectsMalformedInput(t *testing.T) {
	py := python3(t)
	root := pythonRoot(t)
	dir := t.TempDir()

	cmd := exec.Command(py, "-m", "blueveil_ioc", "enrich", "--indicators", writeIndicators(t, dir))
	cmd.Dir = root
	cmd.Stdin = strings.NewReader("{not json")
	if err := cmd.Run(); err == nil {
		t.Fatal("malformed stdin must be rejected with non-zero exit")
	}
}
