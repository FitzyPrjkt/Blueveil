// Synthetic versioned control baseline (13I.5): a small deterministic
// catalog for the lab. Clearly internal — never an official certification
// or authoritative external mapping.
package grc

import "fmt"

// FrameworkKind distinguishes internal baselines from illustrative
// external mappings. The lab catalog is always internal.
type FrameworkKind string

const (
	FrameworkInternal     FrameworkKind = "INTERNAL_BASELINE"
	FrameworkIllustrative FrameworkKind = "ILLUSTRATIVE_MAPPING"
)

// Framework identifies one control catalog version.
type Framework struct {
	ID      string
	Version string
	Kind    FrameworkKind
	Title   string
}

// BaselineFramework returns the lab baseline identity.
func BaselineFramework() Framework {
	return Framework{
		ID: "BLUEVEIL-BASELINE", Version: "1.0.0-lab",
		Kind: FrameworkInternal, Title: "Blueveil lab control baseline",
	}
}

// BaselineControls returns the deterministic lab control set in stable
// order. Each control names observable evidence; none claims outcomes.
func BaselineControls() []Control {
	fw := BaselineFramework()
	mk := func(id, title, desc string, domain Domain, impl ImplementationStatus) Control {
		return Control{
			ID: id, Title: title, Description: desc, Domain: domain,
			Framework: fw.ID, FrameworkVersion: fw.Version, Implementation: impl,
		}
	}
	return []Control{
		mk("AC-1", "Authentication required for lab access",
			"Access to lab systems requires an authenticated principal.", DomainIdentity, ImplImplemented),
		mk("LG-1", "Security telemetry logging enabled",
			"Lab sources emit structured security telemetry.", DomainGovernance, ImplImplemented),
		mk("NW-1", "Egress connections observed",
			"Outbound lab connections are observed and recorded.", DomainNetwork, ImplPartial),
		mk("DT-1", "Suspicious lab activity detected",
			"Deterministic detection rules evaluate lab telemetry.", DomainData, ImplImplemented),
		mk("RC-1", "Recovery procedure declared",
			"A lab recovery procedure is documented.", DomainResilience, ImplNotImplemented),
		mk("BK-1", "Backup observations recorded",
			"Backup observations are recorded when a source emits them.", DomainResilience, ImplUnknown),
		mk("AP-1", "Application requests observed",
			"Lab application traffic is observed.", DomainApplication, ImplImplemented),
		mk("EP-1", "Endpoint process activity observed",
			"Lab endpoint process activity is observed.", DomainEndpoint, ImplImplemented),
	}
}

// SourceType bounds what an assessment may cite. Only real Blueveil
// object kinds — mappings cite ids that must actually exist.
type SourceType string

const (
	SourceAsset            SourceType = "asset"
	SourceTelemetry        SourceType = "telemetry"
	SourceDetection        SourceType = "detection"
	SourceAlert            SourceType = "alert"
	SourceIncident         SourceType = "incident"
	SourceEvidence         SourceType = "evidence"
	SourceValidationResult SourceType = "validation-result"
	SourceResponseAudit    SourceType = "response-audit"
)

// ControlMapping is one explicit control→object citation. There is no
// timestamp-only form: without a real source id there is no mapping.
type ControlMapping struct {
	ControlID  string
	SourceType SourceType
	SourceID   string
	Note       string
}

// Validate enforces explicit, bounded mappings.
func (m ControlMapping) Validate() error {
	if m.ControlID == "" {
		return fmt.Errorf("grc: mapping control required")
	}
	switch m.SourceType {
	case SourceAsset, SourceTelemetry, SourceDetection, SourceAlert,
		SourceIncident, SourceEvidence, SourceValidationResult,
		SourceResponseAudit:
	default:
		return fmt.Errorf("grc: mapping source %q not in bounded vocabulary", m.SourceType)
	}
	if m.SourceID == "" {
		return fmt.Errorf("grc: mapping source id required (no timestamp-only mappings)")
	}
	return nil
}
