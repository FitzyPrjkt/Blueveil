// Step 19 CLI coverage: backup/restore/prune commands end to end
// against disposable SQLite state (no server, no network).
package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"blueveil/collector/internal/store/sqlite"
)

func TestBackupRestorePruneCommands(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "src.db")
	db, err := sqlite.Open(ctx, sqlite.Config{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := `{"env":"lab","listen_addr":"127.0.0.1:18099",
		"database":{"backend":"sqlite","sqlite_path":"` + dbPath + `"},
		"tls":{"enabled":false},"auth":{"enabled":false},
		"logging":{"level":"error","format":"text"},
		"limits":{"request_body_bytes":1048576,"read_header_timeout":"5s","shutdown_timeout":"10s"},
		"ui_dir":"x"}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}
	backups := filepath.Join(dir, "backups")
	if err := runBackup(cfgPath, serveFlags{}, backups); err != nil {
		t.Fatalf("backup: %v", err)
	}
	entries, err := os.ReadDir(backups)
	if err != nil || len(entries) != 1 {
		t.Fatalf("want 1 backup, got %+v %v", entries, err)
	}
	// Restore refusals first (target exists, no force).
	if err := runRestore(cfgPath, serveFlags{}, filepath.Join(backups, entries[0].Name()), "", false); err == nil {
		t.Fatalf("conflicting restore must fail without force")
	}
	// Forced restore over the same path verifies counts.
	if err := runRestore(cfgPath, serveFlags{}, filepath.Join(backups, entries[0].Name()), "", true); err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	// Prune refuses keep=0, accepts keep=1.
	if err := runPrune(backups, 0); err == nil {
		t.Fatalf("prune keep=0 must fail")
	}
	if err := runPrune(backups, 5); err != nil {
		t.Fatalf("prune: %v", err)
	}
}
