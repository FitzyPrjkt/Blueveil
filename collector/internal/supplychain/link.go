// Explicit supply-chain linkage (13J.16-17): a control cites a real
// subject (component, vendor, SBOM) with a written basis. Links reference
// actual IDs — timestamp-only correlation has no representation here.
package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// LinkSubjectKind bounds what a control mapping may cite.
type LinkSubjectKind string

const (
	LinkComponent LinkSubjectKind = "component"
	LinkVendor    LinkSubjectKind = "vendor"
	LinkSBOM      LinkSubjectKind = "sbom"
)

// SupplyLink is one explicit control→subject citation.
type SupplyLink struct {
	ControlID   string
	SubjectKind LinkSubjectKind
	SubjectID   string
	Basis       string
}

// ID deterministically identifies the link.
func (l SupplyLink) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-supply-link-v1",
		l.ControlID, string(l.SubjectKind), l.SubjectID,
	}, "\x1f")))
	return "slink-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces explicit links.
func (l SupplyLink) Validate() error {
	if strings.TrimSpace(l.ControlID) == "" {
		return fmt.Errorf("supplychain: link control required")
	}
	switch l.SubjectKind {
	case LinkComponent, LinkVendor, LinkSBOM:
	default:
		return fmt.Errorf("supplychain: link subject kind %q not in bounded vocabulary", l.SubjectKind)
	}
	if strings.TrimSpace(l.SubjectID) == "" {
		return fmt.Errorf("supplychain: link subject id required (no timestamp-only links)")
	}
	if strings.TrimSpace(l.Basis) == "" {
		return fmt.Errorf("supplychain: link basis required")
	}
	return nil
}
