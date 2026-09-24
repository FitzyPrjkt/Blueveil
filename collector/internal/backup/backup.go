// Package backup implements the minimum real backup capability for
// private self-hosting: consistent whole-database snapshots with
// versioned manifests, secret scanning, and explicit pruning. It is
// operational infrastructure, not a security-action path: it never
// mutates, repairs, or reinterprets persisted records.
//
// Layout of one backup directory:
//
//	backup-<UTC-timestamp>-<backend>/
//	    backup.json   manifest (identity, schema, table counts, file hashes)
//	    dump.sql      PostgreSQL plain dump, or
//	    blueveil.db   SQLite VACUUM INTO snapshot
package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var secretKeyRe = regexp.MustCompile(`"secret"\s*:`)

// ManifestFormatVersion pins the manifest shape.
const ManifestFormatVersion = 1

// Manifest describes one backup. Tables maps table name to the row
// count observed at backup time; restores must reproduce it exactly.
type Manifest struct {
	FormatVersion int              `json:"format_version"`
	Tool          string           `json:"tool"`
	CreatedAt     string           `json:"created_at"`
	Backend       string           `json:"backend"`
	Database      string           `json:"database"`
	SchemaVersion int              `json:"schema_version"`
	Tables        map[string]int64 `json:"tables"`
	Files         []ManifestFile   `json:"files"`
}

// ManifestFile hashes one payload file.
type ManifestFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// WriteManifest hashes every payload file in dir (everything except
// backup.json itself), stamps identity, and writes backup.json. It
// fails when the directory holds no payload.
func WriteManifest(dir string, m Manifest) (Manifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: read dir: %v", err)
	}
	m.FormatVersion = ManifestFormatVersion
	m.Tool = "blueveil-backup"
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	if m.Tables == nil {
		m.Tables = map[string]int64{}
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "backup.json" {
			continue
		}
		if e.Name() != filepath.Base(e.Name()) {
			return Manifest{}, fmt.Errorf("backup: refusing irregular filename %q", e.Name())
		}
		if st, err := os.Lstat(filepath.Join(dir, e.Name())); err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return Manifest{}, fmt.Errorf("backup: refusing non-regular payload %q", e.Name())
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return Manifest{}, fmt.Errorf("backup: hash %s: %v", e.Name(), err)
		}
		sum := sha256.Sum256(raw)
		m.Files = append(m.Files, ManifestFile{
			Name: e.Name(), Bytes: int64(len(raw)), SHA256: hex.EncodeToString(sum[:]),
		})
	}
	if len(m.Files) == 0 {
		return Manifest{}, fmt.Errorf("backup: nothing to back up in %s", dir)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: encode manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup.json"), raw, 0600); err != nil {
		return Manifest{}, fmt.Errorf("backup: write manifest: %v", err)
	}
	return m, nil
}

// ReadManifest loads backup.json and verifies every listed file exists
// with matching size and hash. Any mismatch — tampered, truncated, or
// missing payload — is an explicit error, never an empty backup.
func ReadManifest(dir string) (Manifest, error) {
	var m Manifest
	raw, err := os.ReadFile(filepath.Join(dir, "backup.json"))
	if err != nil {
		return m, fmt.Errorf("backup: read manifest: %v", err)
	}
	// Strict decoding: unknown fields are refused rather than silently
	// ignored, so a manifest from a newer (or foreign) tool can never
	// pass as ours with semantics we don't understand.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("backup: parse manifest: %v", err)
	}
	if m.FormatVersion != ManifestFormatVersion {
		return m, fmt.Errorf("backup: manifest format %d unsupported (code speaks %d)", m.FormatVersion, ManifestFormatVersion)
	}
	if len(m.Files) == 0 {
		return m, fmt.Errorf("backup: manifest lists no files")
	}
	for _, f := range m.Files {
		// Filenames come from the archive itself (which may have
		// traveled): reject separators, parent refs, and symlinks so a
		// malicious manifest cannot pull reads (or, on restore paths,
		// writes) outside the backup directory.
		if f.Name != filepath.Base(f.Name) || strings.Contains(f.Name, "..") {
			return m, fmt.Errorf("backup: manifest filename %q escapes the backup directory", f.Name)
		}
		full := filepath.Join(dir, f.Name)
		if st, err := os.Lstat(full); err != nil {
			return m, fmt.Errorf("backup: payload %s: %v", f.Name, err)
		} else if st.Mode()&os.ModeSymlink != 0 {
			return m, fmt.Errorf("backup: payload %s is a symlink: refusing", f.Name)
		}
		payload, err := os.ReadFile(full)
		if err != nil {
			return m, fmt.Errorf("backup: payload %s: %v", f.Name, err)
		}
		if int64(len(payload)) != f.Bytes {
			return m, fmt.Errorf("backup: payload %s size drift (%d vs %d): incomplete backup", f.Name, len(payload), f.Bytes)
		}
		sum := sha256.Sum256(payload)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return m, fmt.Errorf("backup: payload %s hash mismatch: tampered or truncated backup", f.Name)
		}
	}
	return m, nil
}

// secretMarkers is a marker-based tripwire, not an exhaustive scanner:
// private-key blocks, connection-string passwords, our own synthetic
// test markers (which must never persist), and obvious key dumps. A hit
// fails the backup loudly; absence is necessary, not sufficient.
var secretMarkers = []string{
	"PRIVATE KEY",
	"hunter2",
	"AKIAIOSFODNN7SECRET",
	"should-be-redacted",
}

// ScanBackupBytes rejects payload bytes containing secret markers.
func ScanBackupBytes(raw []byte) error {
	for _, marker := range secretMarkers {
		if strings.Contains(string(raw), marker) {
			return fmt.Errorf("backup: secret marker %q in backup payload", marker)
		}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		low := strings.ToLower(line)
		if strings.Contains(low, "password=") && !strings.Contains(low, "password required") && !strings.Contains(low, "password is") {
			return fmt.Errorf("backup: connection-string password in backup payload")
		}
		// A JSON key literally named "secret" holding a value is a
		// credential dump, not prose (prose like "top secret" has no
		// key form and stays passing).
		if secretKeyRe.MatchString(line) {
			return fmt.Errorf("backup: secret-valued key in backup payload")
		}
	}
	return nil
}

// BackupDirName renders backup-<UTC-timestamp>-<backend>. Timestamps are
// UTC, second resolution, lexicographically sortable.
func BackupDirName(backend string) string {
	return fmt.Sprintf("backup-%s-%s", time.Now().UTC().Format("20060102T150405Z"), backend)
}

// ParseBackupTime extracts the UTC instant from a backup directory name.
// The timestamp is the fixed 16-char basic-format prefix after "backup-"
// (backend labels may themselves contain dashes, so splitting on dashes
// is wrong).
func ParseBackupTime(name string) (time.Time, error) {
	rest, ok := strings.CutPrefix(name, "backup-")
	if !ok || len(rest) < 17 || rest[16] != '-' {
		return time.Time{}, fmt.Errorf("backup: %q is not a backup directory", name)
	}
	ts, err := time.Parse("20060102T150405Z", rest[:16])
	if err != nil {
		return time.Time{}, fmt.Errorf("backup: %q carries no valid timestamp: %v", name, err)
	}
	return ts, nil
}

// Prune deletes backup directories in dir keeping the newest keep.
// Non-backup entries are never touched; keep < 1 fails (the newest
// backup is never deleted silently). Returns the removal count.
func Prune(dir string, keep int) (int, error) {
	if keep < 1 {
		return 0, fmt.Errorf("backup: keep must be >= 1 (refusing to delete the newest backup)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("backup: read dir: %v", err)
	}
	type cand struct {
		name string
		when time.Time
	}
	var cands []cand
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		when, err := ParseBackupTime(e.Name())
		if err != nil {
			continue
		}
		cands = append(cands, cand{e.Name(), when})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].when.Before(cands[j].when) })
	removed := 0
	for len(cands) > keep {
		victim := cands[0]
		cands = cands[1:]
		if err := os.RemoveAll(filepath.Join(dir, victim.name)); err != nil {
			return removed, fmt.Errorf("backup: prune %s: %v", victim.name, err)
		}
		removed++
	}
	return removed, nil
}
