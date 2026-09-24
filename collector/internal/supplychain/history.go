// Posture history (13J.15): time-ordered observations derived from
// stored state — component observations, vendor assessments, SBOM
// records. Nothing is computed beyond ordering; there are no trends,
// no percentages, no improvement metrics.
package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// HistoryEntry is one observed posture fact in time order.
type HistoryEntry struct {
	ID         string
	OccurredAt time.Time
	Kind       string
	SubjectID  string
	Summary    string
}

func historyID(kind, subject string, at time.Time) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-supply-history-v1", kind, subject,
		at.UTC().Format(time.RFC3339Nano),
	}, "\x1f")))
	return "shist-" + hex.EncodeToString(sum[:])[:16]
}

// PostureHistory derives deterministic history rows from stored state.
// SBOMs contribute their generation instants.
func PostureHistory(comps []Component, assessments []VendorAssessment, sboms []SBOM) []HistoryEntry {
	var out []HistoryEntry
	for _, c := range comps {
		if c.ObservedAt.IsZero() {
			continue
		}
		out = append(out, HistoryEntry{
			ID:         historyID("component", c.ID(), c.ObservedAt),
			OccurredAt: c.ObservedAt,
			Kind:       "component",
			SubjectID:  c.ID(),
			Summary:    string(c.Ecosystem) + "/" + c.Name + "@" + c.Version + " " + string(c.Status),
		})
	}
	for _, a := range assessments {
		if a.ObservedAt.IsZero() {
			continue
		}
		out = append(out, HistoryEntry{
			ID:         historyID("vendor-assessment", a.ID(), a.ObservedAt),
			OccurredAt: a.ObservedAt,
			Kind:       "vendor-assessment",
			SubjectID:  a.VendorID,
			Summary:    "vendor " + a.VendorID + " " + string(a.Status),
		})
	}
	for _, s := range sboms {
		if s.GeneratedAt.IsZero() {
			continue
		}
		out = append(out, HistoryEntry{
			ID:         historyID("sbom", s.ID(), s.GeneratedAt),
			OccurredAt: s.GeneratedAt,
			Kind:       "sbom",
			SubjectID:  s.ID(),
			Summary:    string(s.Format) + " sbom with " + itoa(len(s.ComponentIDs)) + " components",
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
