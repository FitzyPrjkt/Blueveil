// Campaign model (13H.3-4): a deterministic grouping of declarative
// validation cases around one target/scope and provider. Cases describe
// what defensive behavior is expected; they never carry commands,
// scripts, URLs-as-payloads, or exploit material — there is no execution
// mechanism here at all. Execution lives behind the response safety
// pipeline (runner.go); this file is data + validation only.
package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

// CampaignStatus is the bounded campaign lifecycle.
type CampaignStatus int

const (
	StatusDraft CampaignStatus = iota + 1
	StatusRunning
	StatusCompleted
	StatusFailed
)

func (s CampaignStatus) String() string {
	switch s {
	case StatusDraft:
		return "DRAFT"
	case StatusRunning:
		return "RUNNING"
	case StatusCompleted:
		return "COMPLETED"
	case StatusFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// CaseDomain bounds the telemetry domain a case exercises.
type CaseDomain string

const (
	DomainNetwork     CaseDomain = "network"
	DomainApplication CaseDomain = "application"
	DomainEndpoint    CaseDomain = "endpoint"
	DomainServer      CaseDomain = "server"
	DomainContainer   CaseDomain = "container"
	DomainCloud       CaseDomain = "cloud"
	DomainIdentity    CaseDomain = "identity"
	DomainAuth        CaseDomain = "auth"
	DomainData        CaseDomain = "data"
	DomainWAF         CaseDomain = "waf"
)

func validDomain(d CaseDomain) bool {
	switch d {
	case DomainNetwork, DomainApplication, DomainEndpoint, DomainServer,
		DomainContainer, DomainCloud, DomainIdentity, DomainAuth,
		DomainData, DomainWAF:
		return true
	}
	return false
}

// ExpectedBehavior bounds what defensive behavior a case expects.
type ExpectedBehavior string

const (
	ExpectPrevent          ExpectedBehavior = "PREVENT"
	ExpectDetect           ExpectedBehavior = "DETECT"
	ExpectPreventAndDetect ExpectedBehavior = "PREVENT_AND_DETECT"
	ExpectObserve          ExpectedBehavior = "OBSERVE"
)

func validExpected(e ExpectedBehavior) bool {
	switch e {
	case ExpectPrevent, ExpectDetect, ExpectPreventAndDetect, ExpectObserve:
		return true
	}
	return false
}

// ValidationCase is one declarative validation scenario.
type ValidationCase struct {
	Title     string
	Domain    CaseDomain
	Target    string
	Expected  ExpectedBehavior
	Operation v1.OperationType
	Risk      v1.RiskLevel
	Provider  string
	Source    string
}

// ID deterministically identifies the case from its material inputs.
func (c ValidationCase) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-validation-case-v1",
		c.Title, string(c.Domain), c.Target, string(c.Expected), c.Provider,
	}, "\x1f")))
	return "vcase-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces declarative, bounded cases.
func (c ValidationCase) Validate() error {
	if strings.TrimSpace(c.Title) == "" {
		return fmt.Errorf("validation: case title required")
	}
	if !validDomain(c.Domain) {
		return fmt.Errorf("validation: case domain %q not in bounded vocabulary", c.Domain)
	}
	if strings.TrimSpace(c.Target) == "" {
		return fmt.Errorf("validation: case target required")
	}
	if !validExpected(c.Expected) {
		return fmt.Errorf("validation: case expected %q not in bounded vocabulary", c.Expected)
	}
	if _, known := v1.OperationType_name[int32(c.Operation)]; !known ||
		c.Operation == v1.OperationType_OPERATION_TYPE_UNSPECIFIED {
		return fmt.Errorf("validation: case operation must be explicit")
	}
	if _, known := v1.RiskLevel_name[int32(c.Risk)]; !known ||
		c.Risk == v1.RiskLevel_RISK_LEVEL_UNSPECIFIED {
		return fmt.Errorf("validation: case risk must be explicit")
	}
	if strings.TrimSpace(c.Provider) == "" {
		return fmt.Errorf("validation: case provider required")
	}
	if strings.TrimSpace(c.Source) == "" {
		return fmt.Errorf("validation: case source required")
	}
	return nil
}

// Campaign groups cases with lifecycle and result references. ResultIDs
// reference ValidationResult.id values actually produced — never invented.
type Campaign struct {
	Name        string
	Description string
	Target      string
	Provider    string
	Source      string
	Status      CampaignStatus
	CreatedAt   time.Time
	StartedAt   time.Time
	CompletedAt time.Time
	CaseIDs     []string
	ResultIDs   []string
}

// ID deterministically identifies the campaign from its material inputs.
func (c Campaign) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-validation-campaign-v1",
		c.Name, c.Target, c.Provider,
	}, "\x1f")))
	return "vcamp-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces the campaign boundary, including timestamp order.
func (c Campaign) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("validation: campaign name required")
	}
	if strings.TrimSpace(c.Target) == "" {
		return fmt.Errorf("validation: campaign target required")
	}
	if strings.TrimSpace(c.Provider) == "" {
		return fmt.Errorf("validation: campaign provider required")
	}
	if strings.TrimSpace(c.Source) == "" {
		return fmt.Errorf("validation: campaign source required")
	}
	// Zero is rejected: an unset status must never persist only to render
	// as UNKNOWN elsewhere (unset and explicit states stay distinct).
	switch c.Status {
	case StatusDraft, StatusRunning, StatusCompleted, StatusFailed:
	default:
		return fmt.Errorf("validation: campaign status %d out of bounded vocabulary", int(c.Status))
	}
	if !c.CreatedAt.IsZero() && !c.StartedAt.IsZero() && c.StartedAt.Before(c.CreatedAt) {
		return fmt.Errorf("validation: campaign started before created")
	}
	if !c.StartedAt.IsZero() && !c.CompletedAt.IsZero() && c.CompletedAt.Before(c.StartedAt) {
		return fmt.Errorf("validation: campaign completed before started")
	}
	return nil
}
