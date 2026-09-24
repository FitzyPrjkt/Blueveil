// Package grc is the governance layer: requirements, controls,
// assessments, mappings, architecture context, and resilience posture.
// Every status is explicit and bounded. Absence of evidence is
// NOT_ASSESSED or UNKNOWN — never compliant, never a score. Nothing here
// remediates, contains, executes, or modifies anything.
package grc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"blueveil/collector/internal/contract"
)

// Domain bounds the governance vocabulary to existing Blueveil telemetry
// domains plus governance itself.
type Domain string

const (
	DomainNetwork      Domain = "network"
	DomainApplication  Domain = "application"
	DomainEndpoint     Domain = "endpoint"
	DomainServer       Domain = "server"
	DomainContainer    Domain = "container"
	DomainCloud        Domain = "cloud"
	DomainIdentity     Domain = "identity"
	DomainAuth         Domain = "auth"
	DomainData         Domain = "data"
	DomainWAF          Domain = "waf"
	DomainGovernance   Domain = "governance"
	DomainResilience   Domain = "resilience"
	DomainArchitecture Domain = "architecture"
)

func validDomain(d Domain) bool {
	switch d {
	case DomainNetwork, DomainApplication, DomainEndpoint, DomainServer,
		DomainContainer, DomainCloud, DomainIdentity, DomainAuth,
		DomainData, DomainWAF, DomainGovernance, DomainResilience,
		DomainArchitecture:
		return true
	}
	return false
}

// Requirement is one security requirement in a framework version.
type Requirement struct {
	Framework        string
	FrameworkVersion string
	ControlRef       string
	Title            string
	Description      string
	Domain           Domain
}

// ID deterministically identifies the requirement.
func (r Requirement) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-grc-requirement-v1",
		r.Framework, r.FrameworkVersion, r.ControlRef,
	}, "\x1f")))
	return "greq-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces explicit, bounded requirements.
func (r Requirement) Validate() error {
	if strings.TrimSpace(r.Framework) == "" {
		return fmt.Errorf("grc: requirement framework required")
	}
	if strings.TrimSpace(r.ControlRef) == "" {
		return fmt.Errorf("grc: requirement control reference required")
	}
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("grc: requirement title required")
	}
	if !validDomain(r.Domain) {
		return fmt.Errorf("grc: requirement domain %q not in bounded vocabulary", r.Domain)
	}
	return nil
}

// ImplementationStatus is whether a control is implemented. It says
// nothing about effectiveness — that is the assessment's job.
type ImplementationStatus string

const (
	ImplImplemented    ImplementationStatus = "IMPLEMENTED"
	ImplPartial        ImplementationStatus = "PARTIAL"
	ImplNotImplemented ImplementationStatus = "NOT_IMPLEMENTED"
	ImplUnknown        ImplementationStatus = "UNKNOWN"
)

// Control is one expected control in a framework version.
type Control struct {
	ID               string
	Title            string
	Description      string
	Domain           Domain
	Framework        string
	FrameworkVersion string
	Implementation   ImplementationStatus
}

// Validate enforces explicit, bounded controls.
func (c Control) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("grc: control id required")
	}
	if strings.TrimSpace(c.Title) == "" {
		return fmt.Errorf("grc: control title required")
	}
	if !validDomain(c.Domain) {
		return fmt.Errorf("grc: control domain %q not in bounded vocabulary", c.Domain)
	}
	if strings.TrimSpace(c.Framework) == "" {
		return fmt.Errorf("grc: control framework required")
	}
	switch c.Implementation {
	case ImplImplemented, ImplPartial, ImplNotImplemented, ImplUnknown, "":
	default:
		return fmt.Errorf("grc: control implementation %q not in bounded vocabulary", c.Implementation)
	}
	return nil
}

// AssessmentStatus is the bounded compliance vocabulary. There is no
// SECURE/SAFE/GUARANTEED: the strongest claim available is COMPLIANT,
// and only with an explicit basis.
type AssessmentStatus string

const (
	StatusCompliant          AssessmentStatus = "COMPLIANT"
	StatusPartiallyCompliant AssessmentStatus = "PARTIALLY_COMPLIANT"
	StatusNonCompliant       AssessmentStatus = "NON_COMPLIANT"
	StatusNotAssessed        AssessmentStatus = "NOT_ASSESSED"
	StatusNotApplicable      AssessmentStatus = "NOT_APPLICABLE"
	StatusUnknown            AssessmentStatus = "UNKNOWN"
)

// RiskLevel is the bounded risk vocabulary, separate from severity,
// verdicts, operations, and response risk. A non-UNKNOWN level must name
// its basis; nothing here computes scores.
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
	RiskUnknown  RiskLevel = "UNKNOWN"
)

// Assessment is one explicit control assessment. A decisive status
// (COMPLIANT/PARTIALLY/NON_COMPLIANT) requires a written basis;
// NOT_ASSESSED/NOT_APPLICABLE/UNKNOWN honestly record the absence of one.
// ValidationIDs cites real validation results; a result supports an
// assessment only through this explicit link — never automatically.
type Assessment struct {
	ControlID     string
	Target        string
	Status        AssessmentStatus
	Assessor      string
	ObservedAt    time.Time
	EvidenceIDs   []string
	ValidationIDs []string
	Basis         string
	Notes         string
	Risk          RiskLevel
	RiskBasis     string
}

// ID deterministically identifies the assessment.
func (a Assessment) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-grc-assessment-v1",
		a.ControlID, a.Target, string(a.Status), a.Assessor,
		a.ObservedAt.UTC().Format(time.RFC3339Nano),
	}, "\x1f")))
	return "gass-" + hex.EncodeToString(sum[:])[:16]
}

// RedactMetadata drops secret-bearing keys from free-form metadata
// before persistence. Callers must pass metadata through here; the
// repository trusts but verifies nothing about key names.
func RedactMetadata(meta map[string]string) map[string]string {
	out := make(map[string]string, len(meta))
	for k, v := range meta {
		drop := contract.SensitiveField(k)
		if !drop {
			out[k] = v
		}
	}
	return out
}

// Validate enforces explicit assessments and rejects fabricated ones.
func (a Assessment) Validate() error {
	if strings.TrimSpace(a.ControlID) == "" {
		return fmt.Errorf("grc: assessment control required")
	}
	if strings.TrimSpace(a.Target) == "" {
		return fmt.Errorf("grc: assessment target required")
	}
	switch a.Status {
	case StatusCompliant, StatusPartiallyCompliant, StatusNonCompliant,
		StatusNotAssessed, StatusNotApplicable, StatusUnknown:
	default:
		return fmt.Errorf("grc: assessment status %q not in bounded vocabulary (no SECURE/SAFE)", a.Status)
	}
	if strings.TrimSpace(a.Assessor) == "" {
		return fmt.Errorf("grc: assessment assessor/source required")
	}
	if a.ObservedAt.IsZero() {
		return fmt.Errorf("grc: assessment observed timestamp required")
	}
	switch a.Status {
	case StatusCompliant, StatusPartiallyCompliant, StatusNonCompliant:
		if strings.TrimSpace(a.Basis) == "" {
			return fmt.Errorf("grc: status %s requires an explicit basis", a.Status)
		}
	}
	switch a.Risk {
	case "", RiskLow, RiskMedium, RiskHigh, RiskCritical, RiskUnknown:
	default:
		return fmt.Errorf("grc: risk %q not in bounded vocabulary (no scores)", a.Risk)
	}
	if a.Risk != "" && a.Risk != RiskUnknown && strings.TrimSpace(a.RiskBasis) == "" {
		return fmt.Errorf("grc: risk %s requires an explicit basis", a.Risk)
	}
	return nil
}
