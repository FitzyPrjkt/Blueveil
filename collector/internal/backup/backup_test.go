// Step 19B RED: backup manifest, secret scan, naming, and prune.
// Pure logic first; live database cycles follow once these pass.
package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dump.sql"), []byte("SELECT 1;"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := WriteManifest(dir, Manifest{
		Backend: "postgres", Database: "blueveil", SchemaVersion: 5,
		Tables: map[string]int64{"telemetry_events": 72},
	})
	if err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if m.FormatVersion != 1 || m.Tool != "blueveil-backup" {
		t.Fatalf("manifest identity: %+v", m)
	}
	got, err := ReadManifest(dir)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if got.SchemaVersion != 5 || got.Tables["telemetry_events"] != 72 {
		t.Fatalf("manifest drift: %+v", got)
	}
	if len(got.Files) != 1 || got.Files[0].SHA256 == "" {
		t.Fatalf("manifest must hash its files: %+v", got.Files)
	}
}

func TestManifestDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dump.sql"), []byte("SELECT 1;"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteManifest(dir, Manifest{Backend: "sqlite", Database: "x", SchemaVersion: 5}); err != nil {
		t.Fatal(err)
	}
	// Tamper with the payload after the manifest was written.
	if err := os.WriteFile(filepath.Join(dir, "dump.sql"), []byte("SELECT 2; -- forged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(dir); err == nil {
		t.Fatalf("tampered payload must fail manifest verification")
	}
	// Missing manifest is explicit, not an empty backup.
	if _, err := ReadManifest(t.TempDir()); err == nil {
		t.Fatalf("missing manifest must fail")
	}
}

func TestSecretScanFindsMarkers(t *testing.T) {
	clean := "CREATE TABLE t (id TEXT);\nINSERT INTO t VALUES ('evidence-sha256-abc');\n"
	if err := ScanBackupBytes([]byte(clean)); err != nil {
		t.Fatalf("clean dump must pass: %v", err)
	}
	for name, blob := range map[string]string{
		"private key":  "-----BEGIN RSA PRIVATE KEY-----\nabc",
		"test marker":  "hunter2-should-be-redacted",
		"aws marker":   "AKIAIOSFODNN7SECRET",
		"conn string":  "password=super-secret-pw dbname=x",
		"api key dump": `"api_keys": [{"hash": "x", "secret": "s"}]`,
	} {
		if err := ScanBackupBytes([]byte(cleam(blob))); err == nil {
			t.Errorf("%s must be flagged", name)
		}
	}
}

func cleam(s string) string { return "CREATE TABLE t (id TEXT);\n" + s }

func TestBackupNaming(t *testing.T) {
	a := BackupDirName("postgres")
	b := BackupDirName("sqlite")
	if a == b {
		t.Fatalf("names must differ by backend: %q", a)
	}
	if !strings.HasPrefix(a, "backup-") || !strings.Contains(a, "postgres") {
		t.Fatalf("name shape: %q", a)
	}
	if _, err := ParseBackupTime(a); err != nil {
		t.Fatalf("name must carry a parseable UTC timestamp: %v", err)
	}
	if _, err := ParseBackupTime("not-a-backup"); err == nil {
		t.Fatalf("garbage names must not parse")
	}
}

func TestManifestRejectsUnknownFieldsAndFutureVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dump.sql"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := WriteManifest(dir, Manifest{Backend: "sqlite", Database: "x", SchemaVersion: 5})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	var wide map[string]any
	if err := json.Unmarshal(raw, &wide); err != nil {
		t.Fatal(err)
	}
	wide["destructive_restore"] = true
	wideRaw, _ := json.Marshal(wide)
	if err := os.WriteFile(filepath.Join(dir, "backup.json"), wideRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(dir); err == nil {
		t.Fatalf("unknown manifest fields must be refused")
	}
	wide["destructive_restore"] = nil
	delete(wide, "destructive_restore")
	wide["format_version"] = 99
	wideRaw, _ = json.Marshal(wide)
	if err := os.WriteFile(filepath.Join(dir, "backup.json"), wideRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(dir); err == nil {
		t.Fatalf("future manifest version must be refused")
	}
}

func TestLargeManifestFailsBounded(t *testing.T) {
	// A 10 MB garbage "manifest" must fail fast with a bounded error,
	// never hang the decoder or exhaust memory.
	dir := t.TempDir()
	big := make([]byte, 10<<20)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(dir, "backup.json"), big, 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := ReadManifest(dir); err == nil {
		t.Fatalf("garbage manifest must fail")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("manifest parse must be bounded")
	}
}

func TestManifestRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "backup.json"), []byte("{oops"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(dir); err == nil {
		t.Fatalf("malformed manifest must fail")
	}
}

func TestVerifyCountsMismatch(t *testing.T) {
	if err := verifyCounts(map[string]int64{"a": 1}, map[string]int64{"a": 1}); err != nil {
		t.Fatalf("equal counts must verify: %v", err)
	}
	if err := verifyCounts(map[string]int64{"a": 0}, map[string]int64{"a": 1}); err == nil {
		t.Fatalf("short restore must fail")
	}
	if err := verifyCounts(map[string]int64{"a": 1, "evil": 1}, map[string]int64{"a": 1}); err == nil {
		t.Fatalf("foreign tables must fail")
	}
}

func TestManifestRejectsEscapeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dump.sql"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := WriteManifest(dir, Manifest{Backend: "sqlite", Database: "x", SchemaVersion: 5})
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the manifest with a traversing filename.
	m.Files = []ManifestFile{{Name: "../../evil.sql", Bytes: 1, SHA256: m.Files[0].SHA256}}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "backup.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(dir); err == nil {
		t.Fatalf("traversing manifest filename must be refused")
	}
	// Symlinked payload.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "real.sql"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir2, "real.sql"), filepath.Join(dir2, "dump.sql")); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteManifest(dir2, Manifest{Backend: "sqlite", Database: "x", SchemaVersion: 5}); err == nil {
		t.Fatalf("symlinked payload must be refused at manifest time")
	}
}

func TestPruneKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	mk("backup-20260101T000000Z-sqlite")
	mk("backup-20260201T000000Z-sqlite")
	mk("backup-20260301T000000Z-sqlite")
	mk("notes.txt")
	removed, err := Prune(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("want 1 removal, got %d", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "backup-20260101T000000Z-sqlite")); !os.IsNotExist(err) {
		t.Fatalf("oldest must be pruned")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("non-backup entries must never be touched: %v", err)
	}
	if _, err := Prune(dir, 0); err == nil {
		t.Fatalf("keep=0 must fail (never delete the newest)")
	}
	if _, err := Prune(dir, 5); err != nil {
		t.Fatalf("keep-all must succeed: %v", err)
	}
}
