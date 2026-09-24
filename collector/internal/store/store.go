// Package store defines the persistence boundary: repository interfaces
// speaking domain protobuf types only. No sql.Rows, no *sql.DB, no driver
// types, no transaction objects cross this boundary — backends hide those.
//
// Semantics are explicit per entity (see method docs): telemetry, detection,
// alert, validation results, and response records are append-only history;
// incidents and recommendations are lifecycle-mutable (Save replaces);
// audit is append-only with no update/delete surface at all (compile-level).
// Caller-assigned deterministic ids everywhere: the store never invents
// identity. Invalid objects are rejected before any write (ErrInvalid);
// missing reads are ErrNotFound; id collisions are ErrDuplicate.
package store

import (
	"context"
	"errors"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/validation"
)

var (
	// ErrNotFound: no such id stored.
	ErrNotFound = errors.New("store: not found")
	// ErrDuplicate: id already stored (create/append of an existing id).
	ErrDuplicate = errors.New("store: duplicate id")
	// ErrInvalid: object failed contract validation; never persisted.
	ErrInvalid = errors.New("store: invalid object")
	// ErrCorrupted: stored bytes fail integrity re-check on read.
	ErrCorrupted = errors.New("store: corrupted record")
)

// TelemetryRepository archives observed telemetry: append and read only.
type TelemetryRepository interface {
	Append(ctx context.Context, e *v1.TelemetryEvent) error
	Get(ctx context.Context, id string) (*v1.TelemetryEvent, error)
	List(ctx context.Context) ([]*v1.TelemetryEvent, error)
}

// DetectionRepository archives detections: append and read only.
type DetectionRepository interface {
	Append(ctx context.Context, d *v1.Detection) error
	Get(ctx context.Context, id string) (*v1.Detection, error)
	List(ctx context.Context) ([]*v1.Detection, error)
}

// AlertRepository archives alerts: append and read only.
type AlertRepository interface {
	Append(ctx context.Context, a *v1.Alert) error
	Get(ctx context.Context, id string) (*v1.Alert, error)
	List(ctx context.Context) ([]*v1.Alert, error)
}

// IncidentRepository owns incident lifecycle state: create once, Save
// replaces on lifecycle transitions (validated by the incident Manager
// above this boundary), read any time.
type IncidentRepository interface {
	Create(ctx context.Context, in *v1.Incident) error
	Save(ctx context.Context, in *v1.Incident) error
	Get(ctx context.Context, id string) (*v1.Incident, error)
	List(ctx context.Context) ([]*v1.Incident, error)
}

// EvidenceRepository archives evidence with incident linkage: append and
// read only. Backends re-verify digests on read.
type EvidenceRepository interface {
	Append(ctx context.Context, e *v1.Evidence) error
	Get(ctx context.Context, id string) (*v1.Evidence, error)
	List(ctx context.Context) ([]*v1.Evidence, error)
	ListByIncident(ctx context.Context, incidentID string) ([]*v1.Evidence, error)
}

// ResponseRepository owns recommendation lifecycle state (status moves
// PROPOSED → … → terminal, validated by the response Engine above).
type ResponseRepository interface {
	Create(ctx context.Context, r *v1.ResponseRecommendation) error
	Save(ctx context.Context, r *v1.ResponseRecommendation) error
	Get(ctx context.Context, id string) (*v1.ResponseRecommendation, error)
	List(ctx context.Context) ([]*v1.ResponseRecommendation, error)
}

// ResponseRecordRepository archives immutable response artifacts:
// approvals, executions, verifications. Append and read only.
type ResponseRecordRepository interface {
	AppendApproval(ctx context.Context, a *v1.ResponseApproval) error
	AppendExecution(ctx context.Context, e *v1.ResponseExecution) error
	AppendVerification(ctx context.Context, v *v1.ResponseVerification) error
	GetApproval(ctx context.Context, id string) (*v1.ResponseApproval, error)
	GetExecution(ctx context.Context, id string) (*v1.ResponseExecution, error)
	GetVerification(ctx context.Context, id string) (*v1.ResponseVerification, error)
	ListApprovals(ctx context.Context) ([]*v1.ResponseApproval, error)
	ListExecutions(ctx context.Context) ([]*v1.ResponseExecution, error)
	ListVerifications(ctx context.Context) ([]*v1.ResponseVerification, error)
}

// ValidationRepository archives validation requests and results: append
// and read only. Results always answer a stored request in our flows, but
// the interface does not hard-require insertion order (backends may).
type ValidationRepository interface {
	AppendRequest(ctx context.Context, r *v1.ValidationRequest) error
	AppendResult(ctx context.Context, r *v1.ValidationResult) error
	GetRequest(ctx context.Context, id string) (*v1.ValidationRequest, error)
	GetResult(ctx context.Context, id string) (*v1.ValidationResult, error)
	ListResults(ctx context.Context) ([]*v1.ValidationResult, error)
}

// CampaignRepository archives validation campaigns: create once, Save
// replaces on lifecycle moves (DRAFT→RUNNING→COMPLETED/FAILED).
// Caller-assigned deterministic ids; invalid objects rejected.
type CampaignRepository interface {
	Create(ctx context.Context, c validation.Campaign) error
	Save(ctx context.Context, c validation.Campaign) error
	Get(ctx context.Context, id string) (validation.Campaign, error)
	List(ctx context.Context) ([]validation.Campaign, error)
}

// AssessmentRepository archives control assessments: append-only.
// Assessments are point-in-time records with deterministic ids.
type AssessmentRepository interface {
	Create(ctx context.Context, a grc.Assessment) error
	Get(ctx context.Context, id string) (grc.Assessment, error)
	List(ctx context.Context) ([]grc.Assessment, error)
}

// ResilienceRepository archives resilience posture records: append-only,
// deterministic ids over target/assessor/time/status.
type ResilienceRepository interface {
	Create(ctx context.Context, r grc.ResilienceRecord) error
	Get(ctx context.Context, id string) (grc.ResilienceRecord, error)
	List(ctx context.Context) ([]grc.ResilienceRecord, error)
}

// ExerciseRepository archives purple-team exercises: append-only. Exercises
// are immutable once built (deterministic id over content).
type ExerciseRepository interface {
	Create(ctx context.Context, e validation.Exercise) error
	Get(ctx context.Context, id string) (validation.Exercise, error)
	List(ctx context.Context) ([]validation.Exercise, error)
}

// ComponentRepository archives supply-chain components: create once,
// duplicate ids rejected. Identity is deterministic; versions recorded,
// never invented.
type ComponentRepository interface {
	Create(ctx context.Context, c supplychain.Component) error
	Get(ctx context.Context, id string) (supplychain.Component, error)
	List(ctx context.Context) ([]supplychain.Component, error)
}

// DependencyRepository archives explicit dependency edges: append-only,
// duplicate (parent, child, kind) rejected.
type DependencyRepository interface {
	Append(ctx context.Context, d supplychain.Dependency) error
	Children(ctx context.Context, parentID string) ([]supplychain.Dependency, error)
	Parents(ctx context.Context, childID string) ([]supplychain.Dependency, error)
}

// SBOMRepository archives SBOM metadata records: create once.
type SBOMRepository interface {
	Create(ctx context.Context, s supplychain.SBOM) error
	Get(ctx context.Context, id string) (supplychain.SBOM, error)
	List(ctx context.Context) ([]supplychain.SBOM, error)
}

// PolicyRepository archives declarative supply-chain policies.
type PolicyRepository interface {
	Create(ctx context.Context, p supplychain.SupplyPolicy) error
	Get(ctx context.Context, id string) (supplychain.SupplyPolicy, error)
	List(ctx context.Context) ([]supplychain.SupplyPolicy, error)
}

// VendorRepository archives third-party vendors: create once.
type VendorRepository interface {
	Create(ctx context.Context, v supplychain.Vendor) error
	Get(ctx context.Context, id string) (supplychain.Vendor, error)
	List(ctx context.Context) ([]supplychain.Vendor, error)
}

// VendorAssessmentRepository archives vendor posture observations.
type VendorAssessmentRepository interface {
	Create(ctx context.Context, a supplychain.VendorAssessment) error
	Get(ctx context.Context, id string) (supplychain.VendorAssessment, error)
	List(ctx context.Context) ([]supplychain.VendorAssessment, error)
}

// SupplyLinkRepository archives explicit control→subject citations.
type SupplyLinkRepository interface {
	Create(ctx context.Context, l supplychain.SupplyLink) error
	List(ctx context.Context) ([]supplychain.SupplyLink, error)
}

// AuditRepository archives audit decisions: append and read only. There are
// deliberately no Update/Delete methods: immutability is compile-enforced.
type AuditRepository interface {
	Append(ctx context.Context, e AuditEntry) error
	Get(ctx context.Context, id string) (AuditEntry, error)
	List(ctx context.Context) ([]AuditEntry, error)
}

// AssetRepository owns asset lifecycle state: create once, Save replaces on
// lifecycle transitions and re-observation (validated by the asset Manager
// above this boundary), read any time. Identity (uniqueness) is enforced
// on (type, canonical): the database equivalent is a composite unique
// constraint; callers compute ids via asset.IDFor.
type AssetRepository interface {
	Create(ctx context.Context, a *v1.Asset) error
	Save(ctx context.Context, a *v1.Asset) error
	Get(ctx context.Context, id string) (*v1.Asset, error)
	List(ctx context.Context) ([]*v1.Asset, error)
	ListByType(ctx context.Context, typ v1.AssetType) ([]*v1.Asset, error)
	ListByStatus(ctx context.Context, status v1.AssetStatus) ([]*v1.Asset, error)
}

// AssetRelationshipRepository archives CONTAINS relationships between asset
// ids with provenance. Append and read only: relationships are evidence,
// never edited in place (superseded links retire via asset lifecycle, not
// by rewriting history). The record shape is asset.Relationship (the store
// package already depends on asset for canonical checks; no duplication).
type AssetRelationshipRepository interface {
	Append(ctx context.Context, r asset.Relationship) error
	Children(ctx context.Context, parentID string) ([]asset.Relationship, error)
	Parents(ctx context.Context, childID string) ([]asset.Relationship, error)
}
