// Package threatintel is the offline threat-intelligence layer: a local,
// explicitly configured IOC set matched exactly against persisted
// telemetry. Normalization is NOT reimplemented here — every indicator is
// canonicalized through the Step 11 Python extension
// (python3 -m blueveil_ioc normalize), the single normalization
// implementation. Matching is strict exact membership (case-insensitive);
// there is no fuzzy matching, no reputation, no verdict. A match means
// "configured IOC observed", never "malicious" or "compromised". No
// network, no feeds, no external calls of any kind.
package threatintel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	v1 "blueveil/collector/internal/contract/v1"
)

// Entry is one normalized indicator with list provenance.
type Entry struct {
	Kind   string
	Value  string
	Source string
}

// Set is one explicitly configured offline IOC set.
type Set struct {
	ID      string
	Version string
	Entries []Entry
}

// Match is one exact observation of a configured indicator.
type Match struct {
	ID           string
	SetID        string
	SetVersion   string
	Indicator    string
	Kind         string
	ListSource   string
	EventID      string
	MatchedField string
}

type rawIndicator struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// pythonRoot locates Blueveil/extensions/python: BLUEVEIL_PYTHON_EXT
// override first, else the source-tree relative path.
func pythonRoot() (string, error) {
	if override := os.Getenv("BLUEVEIL_PYTHON_EXT"); override != "" {
		return override, nil
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("threatintel: cannot locate caller")
	}
	// This file lives at collector/internal/threatintel → up to Blueveil/.
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "extensions", "python")
	if _, err := os.Stat(filepath.Join(root, "blueveil_ioc", "__init__.py")); err != nil {
		return "", fmt.Errorf("threatintel: python extension not found (set BLUEVEIL_PYTHON_EXT): %v", err)
	}
	return root, nil
}

func pythonBin() (string, error) {
	if override := os.Getenv("BLUEVEIL_PYTHON_BIN"); override != "" {
		return override, nil
	}
	path, err := exec.LookPath("python3")
	if err != nil {
		return "", fmt.Errorf("threatintel: python3 not on PATH: %v", err)
	}
	return path, nil
}

// normalizeOne canonicalizes a single indicator through the Python
// extension. Python failures are construction errors, never silent.
func normalizeOne(py, root, kind, value string) (string, error) {
	cmd := exec.Command(py, "-m", "blueveil_ioc", "normalize", "--kind", kind, "--value", value)
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("threatintel: normalize %s %q: %v: %s", kind, value, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// LoadSet reads a JSON array of {kind,value,source} indicators and
// normalizes every value through the Python extension. Empty ids,
// versions, files, or sets are rejected; any malformed entry aborts the
// whole load loudly.
func LoadSet(path, id, version string) (Set, error) {
	var set Set
	if strings.TrimSpace(id) == "" {
		return set, fmt.Errorf("threatintel: set id required")
	}
	if strings.TrimSpace(version) == "" {
		return set, fmt.Errorf("threatintel: set version required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return set, fmt.Errorf("threatintel: read %s: %v", path, err)
	}
	return LoadSetBytes(raw, path, id, version)
}

// LoadSetBytes normalizes an in-memory JSON indicator array. LoadSet
// delegates here after reading the file, so file and embedded inputs
// share one validation path.
func LoadSetBytes(raw []byte, origin, id, version string) (Set, error) {
	var set Set
	if strings.TrimSpace(id) == "" {
		return set, fmt.Errorf("threatintel: set id required")
	}
	if strings.TrimSpace(version) == "" {
		return set, fmt.Errorf("threatintel: set version required")
	}
	var items []rawIndicator
	if err := json.Unmarshal(raw, &items); err != nil {
		return set, fmt.Errorf("threatintel: parse %s: %v", origin, err)
	}
	if len(items) == 0 {
		return set, fmt.Errorf("threatintel: empty indicator set %s", origin)
	}
	py, err := pythonBin()
	if err != nil {
		return set, err
	}
	root, err := pythonRoot()
	if err != nil {
		return set, err
	}
	set = Set{ID: id, Version: version}
	for i, item := range items {
		if strings.TrimSpace(item.Source) == "" {
			return Set{}, fmt.Errorf("threatintel: indicator %d: empty source", i)
		}
		norm, err := normalizeOne(py, root, item.Kind, item.Value)
		if err != nil {
			return Set{}, fmt.Errorf("threatintel: indicator %d: %v", i, err)
		}
		set.Entries = append(set.Entries, Entry{Kind: item.Kind, Value: norm, Source: item.Source})
	}
	return set, nil
}

// matchID deterministically identifies one observation.
func matchID(setID, version, eventID, indicator, field string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{setID, version, eventID, indicator, field}, "\x1f")))
	return "iocm-" + hex.EncodeToString(sum[:])[:16]
}

// MatchEvent reports exact-membership observations of set indicators in
// one event. Scanned text: id, event_type, asset_id, source, and every
// attribute value — each compared case-insensitively for exact equality
// after trimming. Substrings and near-misses never match. Results sort by
// (indicator, field).
func MatchEvent(event *v1.TelemetryEvent, set Set) []Match {
	if event == nil || len(set.Entries) == 0 {
		return nil
	}
	fields := map[string]string{
		"id":         event.GetId(),
		"event_type": event.GetEventType(),
		"asset_id":   event.GetAssetId(),
		"source":     event.GetSource(),
		"raw":        event.GetRaw(),
	}
	keys := make([]string, 0, len(event.GetAttributes()))
	for k := range event.GetAttributes() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields["attributes."+k] = event.GetAttributes()[k]
	}
	var out []Match
	for _, e := range set.Entries {
		for field, text := range fields {
			if text == "" {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(text), e.Value) {
				continue
			}
			out = append(out, Match{
				ID:           matchID(set.ID, set.Version, event.GetId(), e.Value, field),
				SetID:        set.ID,
				SetVersion:   set.Version,
				Indicator:    e.Value,
				Kind:         e.Kind,
				ListSource:   e.Source,
				EventID:      event.GetId(),
				MatchedField: field,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Indicator != out[j].Indicator {
			return out[i].Indicator < out[j].Indicator
		}
		if out[i].MatchedField != out[j].MatchedField {
			return out[i].MatchedField < out[j].MatchedField
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ListSource < out[j].ListSource
	})
	return out
}
