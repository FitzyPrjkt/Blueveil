// Third-party vendor inventory and assessments (13J.11-12): explicit
// declarations only. Nothing here claims a vendor is secure, compliant,
// or trustworthy; nothing contacts vendors or external systems.
package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// VendorStatus bounds vendor lifecycle state.
type VendorStatus string

const (
	VendorActive      VendorStatus = "ACTIVE"
	VendorInactive    VendorStatus = "INACTIVE"
	VendorUnknown     VendorStatus = "UNKNOWN"
	VendorNotAssessed VendorStatus = "NOT_ASSESSED"
)

// Vendor is one declared third-party service/vendor. Ownership is never
// inferred from DNS or domains — name/service come from declaration.
type Vendor struct {
	Name        string
	Service     string
	Category    string
	Environment string
	Status      VendorStatus
	Source      string
	ObservedAt  time.Time
}

// ID deterministically identifies the vendor.
func (v Vendor) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-supply-vendor-v1", v.Name, v.Service,
	}, "\x1f")))
	return "vend-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces explicit vendors.
func (v Vendor) Validate() error {
	if strings.TrimSpace(v.Name) == "" {
		return fmt.Errorf("supplychain: vendor name required")
	}
	if strings.TrimSpace(v.Service) == "" {
		return fmt.Errorf("supplychain: vendor service required")
	}
	switch v.Status {
	case VendorActive, VendorInactive, VendorUnknown, VendorNotAssessed:
	default:
		return fmt.Errorf("supplychain: vendor status %q not in bounded vocabulary (no trust states)", v.Status)
	}
	if strings.TrimSpace(v.Source) == "" {
		return fmt.Errorf("supplychain: vendor source required")
	}
	if v.ObservedAt.IsZero() {
		return fmt.Errorf("supplychain: vendor observed timestamp required")
	}
	return nil
}

// VendorAssessmentStatus bounds third-party posture observations.
type VendorAssessmentStatus string

const (
	VendorReviewed            VendorAssessmentStatus = "REVIEWED"
	VendorRequirementDeclared VendorAssessmentStatus = "REQUIREMENT_DECLARED"
	VendorNotAssessedStatus   VendorAssessmentStatus = "NOT_ASSESSED"
	VendorUnknownStatus       VendorAssessmentStatus = "UNKNOWN"
)

// VendorAssessment is one explicit vendor posture observation with
// evidence linkage. It never certifies the vendor.
type VendorAssessment struct {
	VendorID    string
	Status      VendorAssessmentStatus
	Assessor    string
	ObservedAt  time.Time
	EvidenceIDs []string
	Note        string
}

// ID deterministically identifies the assessment.
func (a VendorAssessment) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-supply-vendor-assessment-v1",
		a.VendorID, string(a.Status),
		a.ObservedAt.UTC().Format(time.RFC3339Nano),
	}, "\x1f")))
	return "vass-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces explicit assessments.
func (a VendorAssessment) Validate() error {
	if strings.TrimSpace(a.VendorID) == "" {
		return fmt.Errorf("supplychain: vendor assessment vendor required")
	}
	switch a.Status {
	case VendorReviewed, VendorRequirementDeclared, VendorNotAssessedStatus, VendorUnknownStatus:
	default:
		return fmt.Errorf("supplychain: vendor assessment status %q not in bounded vocabulary (no certifications)", a.Status)
	}
	if strings.TrimSpace(a.Assessor) == "" {
		return fmt.Errorf("supplychain: vendor assessment assessor required")
	}
	if a.ObservedAt.IsZero() {
		return fmt.Errorf("supplychain: vendor assessment observed timestamp required")
	}
	return nil
}

// IsAssessmentStale reports whether an assessment instant is at or past
// the window edge relative to now. Pure and deterministic.
func IsAssessmentStale(assessedAt time.Time, window time.Duration, now time.Time) bool {
	return !assessedAt.After(now.Add(-window))
}
