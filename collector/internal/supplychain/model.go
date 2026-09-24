// Package supplychain is metadata-level defensive supply-chain
// visibility: components, dependencies, SBOM records, policies, vendors,
// and continuous checks over persisted state. Nothing here installs,
// upgrades, removes, executes, scans, or contacts anything: every fact is
// declared or observed locally, and every status needs an explicit basis.
// Absence of information is NOT_ASSESSED or UNKNOWN — never a verdict
// about vulnerability, and never a score.
package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ComponentType bounds what a component may be. The type comes from
// explicit metadata, never from guessing at a filename.
type ComponentType string

const (
	ComponentPackage              ComponentType = "PACKAGE"
	ComponentLibrary              ComponentType = "LIBRARY"
	ComponentFramework            ComponentType = "FRAMEWORK"
	ComponentContainerImage       ComponentType = "CONTAINER_IMAGE"
	ComponentBinary               ComponentType = "BINARY"
	ComponentSourceRepository     ComponentType = "SOURCE_REPOSITORY"
	ComponentBuildArtifact        ComponentType = "BUILD_ARTIFACT"
	ComponentInfrastructureModule ComponentType = "INFRASTRUCTURE_MODULE"
	ComponentUnknown              ComponentType = "UNKNOWN"
)

// Provenance bounds where a component fact was observed. MANIFEST-class
// provenance is not a deployment claim: seen in a manifest is not
// verified as deployed.
type Provenance string

const (
	ProvenanceManifest              Provenance = "MANIFEST"
	ProvenanceLockfile              Provenance = "LOCKFILE"
	ProvenanceBuildMetadata         Provenance = "BUILD_METADATA"
	ProvenanceContainerMetadata     Provenance = "CONTAINER_METADATA"
	ProvenanceSourceRepository      Provenance = "SOURCE_REPOSITORY"
	ProvenanceDeploymentObservation Provenance = "DEPLOYMENT_OBSERVATION"
	ProvenanceOperatorDeclaration   Provenance = "OPERATOR_DECLARATION"
	ProvenanceSBOMImport            Provenance = "SBOM_IMPORT"
)

// ComponentStatus bounds component posture. Decisive states need a
// StatusBasis; without one the component stays OBSERVED/NOT_ASSESSED/
// UNKNOWN. There is no vulnerable/compromised state here — Blueveil
// holds no vulnerability intelligence.
type ComponentStatus string

const (
	StatusObserved        ComponentStatus = "OBSERVED"
	StatusVerified        ComponentStatus = "VERIFIED"
	StatusOutdated        ComponentStatus = "OUTDATED"
	StatusUnsupported     ComponentStatus = "UNSUPPORTED"
	StatusPolicyViolation ComponentStatus = "POLICY_VIOLATION"
	StatusNotAssessed     ComponentStatus = "NOT_ASSESSED"
	StatusUnknown         ComponentStatus = "UNKNOWN"
)

// Component is one software component record. Versions and digests are
// recorded only when explicitly present — never invented, never enriched
// from registries.
type Component struct {
	Type             ComponentType
	Ecosystem        string
	Namespace        string
	Name             string
	Version          string
	RequestedVersion string
	ResolvedVersion  string
	Digest           string
	SourceRevision   string
	License          string
	LicenseSource    string
	Provenance       Provenance
	Source           string
	ObservedAt       time.Time
	Status           ComponentStatus
	StatusBasis      string
}

// ID deterministically identifies the component over explicit identity
// inputs (ecosystem lowercased; everything else verbatim).
func (c Component) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"blueveil-supply-component-v1",
		strings.ToLower(strings.TrimSpace(c.Ecosystem)),
		c.Namespace, c.Name, c.Version, c.Digest,
	}, "\x1f")))
	return "comp-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces explicit, bounded components.
func (c Component) Validate() error {
	switch c.Type {
	case ComponentPackage, ComponentLibrary, ComponentFramework,
		ComponentContainerImage, ComponentBinary, ComponentSourceRepository,
		ComponentBuildArtifact, ComponentInfrastructureModule, ComponentUnknown:
	default:
		return fmt.Errorf("supplychain: component type %q not in bounded vocabulary", c.Type)
	}
	if strings.TrimSpace(c.Ecosystem) == "" {
		return fmt.Errorf("supplychain: component ecosystem required")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("supplychain: component name required")
	}
	switch c.Provenance {
	case ProvenanceManifest, ProvenanceLockfile, ProvenanceBuildMetadata,
		ProvenanceContainerMetadata, ProvenanceSourceRepository,
		ProvenanceDeploymentObservation, ProvenanceOperatorDeclaration,
		ProvenanceSBOMImport:
	default:
		return fmt.Errorf("supplychain: provenance %q not in bounded vocabulary", c.Provenance)
	}
	if strings.TrimSpace(c.Source) == "" {
		return fmt.Errorf("supplychain: component source required")
	}
	if c.ObservedAt.IsZero() {
		return fmt.Errorf("supplychain: component observed timestamp required")
	}
	switch c.Status {
	case StatusObserved, StatusNotAssessed, StatusUnknown:
	case StatusVerified, StatusOutdated, StatusUnsupported, StatusPolicyViolation:
		if strings.TrimSpace(c.StatusBasis) == "" {
			return fmt.Errorf("supplychain: status %s requires an explicit basis", c.Status)
		}
	default:
		return fmt.Errorf("supplychain: status %q not in bounded vocabulary (no vulnerability states)", c.Status)
	}
	return nil
}
