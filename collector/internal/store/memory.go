// In-memory repository implementations: maps guarded by mutexes, sorted
// listings for determinism. Fast deterministic unit tests; the behavioral
// contract is pinned by the shared storetest suite both backends must pass.
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"google.golang.org/protobuf/proto"

	"blueveil/collector/internal/asset"
	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/validation"
)

func sortedIDs[T any](m map[string]T) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func cloneOf[T proto.Message](v T) T {
	return proto.Clone(v).(T)
}

// ---------------------------------------------------------------------------
// Append-only entity repositories (telemetry, detection, alert).
// ---------------------------------------------------------------------------

type memoryTelemetry struct {
	mu    sync.Mutex
	items map[string]*v1.TelemetryEvent
}

func (r *memoryTelemetry) Append(ctx context.Context, e *v1.TelemetryEvent) error {
	if err := contract.ValidateTelemetryEvent(e); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[e.GetId()]; exists {
		return fmt.Errorf("%w: telemetry %q", ErrDuplicate, e.GetId())
	}
	r.items[e.GetId()] = cloneOf(e)
	return nil
}

func (r *memoryTelemetry) Get(_ context.Context, id string) (*v1.TelemetryEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: telemetry %q", ErrNotFound, id)
	}
	return cloneOf(e), nil
}

func (r *memoryTelemetry) List(context.Context) ([]*v1.TelemetryEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.TelemetryEvent, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, cloneOf(r.items[id]))
	}
	return out, nil
}

type memoryDetection struct {
	mu    sync.Mutex
	items map[string]*v1.Detection
}

func (r *memoryDetection) Append(ctx context.Context, d *v1.Detection) error {
	if err := contract.ValidateDetection(d); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[d.GetId()]; exists {
		return fmt.Errorf("%w: detection %q", ErrDuplicate, d.GetId())
	}
	r.items[d.GetId()] = cloneOf(d)
	return nil
}

func (r *memoryDetection) Get(_ context.Context, id string) (*v1.Detection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: detection %q", ErrNotFound, id)
	}
	return cloneOf(d), nil
}

func (r *memoryDetection) List(context.Context) ([]*v1.Detection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.Detection, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, cloneOf(r.items[id]))
	}
	return out, nil
}

type memoryAlert struct {
	mu    sync.Mutex
	items map[string]*v1.Alert
}

func (r *memoryAlert) Append(ctx context.Context, a *v1.Alert) error {
	if err := contract.ValidateAlert(a); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[a.GetId()]; exists {
		return fmt.Errorf("%w: alert %q", ErrDuplicate, a.GetId())
	}
	r.items[a.GetId()] = cloneOf(a)
	return nil
}

func (r *memoryAlert) Get(_ context.Context, id string) (*v1.Alert, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: alert %q", ErrNotFound, id)
	}
	return cloneOf(a), nil
}

func (r *memoryAlert) List(context.Context) ([]*v1.Alert, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.Alert, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, cloneOf(r.items[id]))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Lifecycle-mutable repositories (incident, recommendation).
// ---------------------------------------------------------------------------

type memoryIncident struct {
	mu    sync.Mutex
	items map[string]*v1.Incident
}

func (r *memoryIncident) Create(ctx context.Context, in *v1.Incident) error {
	if err := contract.ValidateIncident(in); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[in.GetId()]; exists {
		return fmt.Errorf("%w: incident %q", ErrDuplicate, in.GetId())
	}
	r.items[in.GetId()] = cloneOf(in)
	return nil
}

func (r *memoryIncident) Save(ctx context.Context, in *v1.Incident) error {
	if err := contract.ValidateIncident(in); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[in.GetId()]; !exists {
		return fmt.Errorf("%w: incident %q", ErrNotFound, in.GetId())
	}
	r.items[in.GetId()] = cloneOf(in)
	return nil
}

func (r *memoryIncident) Get(_ context.Context, id string) (*v1.Incident, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	in, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: incident %q", ErrNotFound, id)
	}
	return cloneOf(in), nil
}

func (r *memoryIncident) List(context.Context) ([]*v1.Incident, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.Incident, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, cloneOf(r.items[id]))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Evidence (append-only, digest re-verified on read by callers via
// evidence.Verify; stored bytes are exactly what was appended).
// ---------------------------------------------------------------------------

type memoryEvidence struct {
	mu    sync.Mutex
	items map[string]*v1.Evidence
}

func (r *memoryEvidence) Append(ctx context.Context, e *v1.Evidence) error {
	if err := contract.ValidateEvidence(e); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[e.GetId()]; exists {
		return fmt.Errorf("%w: evidence %q", ErrDuplicate, e.GetId())
	}
	r.items[e.GetId()] = cloneOf(e)
	return nil
}

func (r *memoryEvidence) Get(_ context.Context, id string) (*v1.Evidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: evidence %q", ErrNotFound, id)
	}
	return cloneOf(e), nil
}

func (r *memoryEvidence) List(context.Context) ([]*v1.Evidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listLocked(), nil
}

func (r *memoryEvidence) ListByIncident(_ context.Context, incidentID string) ([]*v1.Evidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*v1.Evidence
	for _, id := range sortedIDs(r.items) {
		if r.items[id].GetIncidentId() == incidentID {
			out = append(out, cloneOf(r.items[id]))
		}
	}
	return out, nil
}

func (r *memoryEvidence) listLocked() []*v1.Evidence {
	out := make([]*v1.Evidence, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, cloneOf(r.items[id]))
	}
	return out
}

// ---------------------------------------------------------------------------
// Response lifecycle + immutable response records.
// ---------------------------------------------------------------------------

type memoryResponse struct {
	mu    sync.Mutex
	items map[string]*v1.ResponseRecommendation
}

func (r *memoryResponse) Create(ctx context.Context, rec *v1.ResponseRecommendation) error {
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[rec.GetId()]; exists {
		return fmt.Errorf("%w: recommendation %q", ErrDuplicate, rec.GetId())
	}
	r.items[rec.GetId()] = cloneOf(rec)
	return nil
}

func (r *memoryResponse) Save(ctx context.Context, rec *v1.ResponseRecommendation) error {
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[rec.GetId()]; !exists {
		return fmt.Errorf("%w: recommendation %q", ErrNotFound, rec.GetId())
	}
	r.items[rec.GetId()] = cloneOf(rec)
	return nil
}

func (r *memoryResponse) Get(_ context.Context, id string) (*v1.ResponseRecommendation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: recommendation %q", ErrNotFound, id)
	}
	return cloneOf(rec), nil
}

func (r *memoryResponse) List(context.Context) ([]*v1.ResponseRecommendation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.ResponseRecommendation, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, cloneOf(r.items[id]))
	}
	return out, nil
}

type memoryResponseRecords struct {
	mu            sync.Mutex
	approvals     map[string]*v1.ResponseApproval
	executions    map[string]*v1.ResponseExecution
	verifications map[string]*v1.ResponseVerification
}

func (r *memoryResponseRecords) AppendApproval(ctx context.Context, a *v1.ResponseApproval) error {
	if err := contract.ValidateResponseApproval(a); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.approvals[a.GetId()]; exists {
		return fmt.Errorf("%w: approval %q", ErrDuplicate, a.GetId())
	}
	r.approvals[a.GetId()] = cloneOf(a)
	return nil
}

func (r *memoryResponseRecords) AppendExecution(ctx context.Context, e *v1.ResponseExecution) error {
	if err := contract.ValidateResponseExecution(e); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.executions[e.GetId()]; exists {
		return fmt.Errorf("%w: execution %q", ErrDuplicate, e.GetId())
	}
	r.executions[e.GetId()] = cloneOf(e)
	return nil
}

func (r *memoryResponseRecords) AppendVerification(ctx context.Context, v *v1.ResponseVerification) error {
	if err := contract.ValidateResponseVerification(v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.verifications[v.GetId()]; exists {
		return fmt.Errorf("%w: verification %q", ErrDuplicate, v.GetId())
	}
	r.verifications[v.GetId()] = cloneOf(v)
	return nil
}

func (r *memoryResponseRecords) GetApproval(_ context.Context, id string) (*v1.ResponseApproval, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.approvals[id]
	if !ok {
		return nil, fmt.Errorf("%w: approval %q", ErrNotFound, id)
	}
	return cloneOf(a), nil
}

func (r *memoryResponseRecords) GetExecution(_ context.Context, id string) (*v1.ResponseExecution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.executions[id]
	if !ok {
		return nil, fmt.Errorf("%w: execution %q", ErrNotFound, id)
	}
	return cloneOf(e), nil
}

func (r *memoryResponseRecords) GetVerification(_ context.Context, id string) (*v1.ResponseVerification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.verifications[id]
	if !ok {
		return nil, fmt.Errorf("%w: verification %q", ErrNotFound, id)
	}
	return cloneOf(v), nil
}

func (r *memoryResponseRecords) ListApprovals(context.Context) ([]*v1.ResponseApproval, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.ResponseApproval, 0, len(r.approvals))
	for _, id := range sortedIDs(r.approvals) {
		out = append(out, cloneOf(r.approvals[id]))
	}
	return out, nil
}

func (r *memoryResponseRecords) ListExecutions(context.Context) ([]*v1.ResponseExecution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.ResponseExecution, 0, len(r.executions))
	for _, id := range sortedIDs(r.executions) {
		out = append(out, cloneOf(r.executions[id]))
	}
	return out, nil
}

func (r *memoryResponseRecords) ListVerifications(context.Context) ([]*v1.ResponseVerification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.ResponseVerification, 0, len(r.verifications))
	for _, id := range sortedIDs(r.verifications) {
		out = append(out, cloneOf(r.verifications[id]))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Validation requests + results (append-only).
// ---------------------------------------------------------------------------

type memoryValidation struct {
	mu       sync.Mutex
	requests map[string]*v1.ValidationRequest
	results  map[string]*v1.ValidationResult
}

func (r *memoryValidation) AppendRequest(ctx context.Context, req *v1.ValidationRequest) error {
	if err := contract.ValidateValidationRequest(req); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.requests[req.GetId()]; exists {
		return fmt.Errorf("%w: validation request %q", ErrDuplicate, req.GetId())
	}
	r.requests[req.GetId()] = cloneOf(req)
	return nil
}

func (r *memoryValidation) AppendResult(ctx context.Context, res *v1.ValidationResult) error {
	if err := contract.ValidateValidationResult(res); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.results[res.GetId()]; exists {
		return fmt.Errorf("%w: validation result %q", ErrDuplicate, res.GetId())
	}
	r.results[res.GetId()] = cloneOf(res)
	return nil
}

func (r *memoryValidation) GetRequest(_ context.Context, id string) (*v1.ValidationRequest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	req, ok := r.requests[id]
	if !ok {
		return nil, fmt.Errorf("%w: validation request %q", ErrNotFound, id)
	}
	return cloneOf(req), nil
}

func (r *memoryValidation) GetResult(_ context.Context, id string) (*v1.ValidationResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res, ok := r.results[id]
	if !ok {
		return nil, fmt.Errorf("%w: validation result %q", ErrNotFound, id)
	}
	return cloneOf(res), nil
}

// ---------------------------------------------------------------------------
// Validation campaigns (lifecycle-mutable) + purple-team exercises
// (append-only, content-addressed by deterministic id).
// ---------------------------------------------------------------------------

type memoryCampaign struct {
	mu    sync.Mutex
	items map[string]validation.Campaign
}

func (r *memoryCampaign) Create(_ context.Context, c validation.Campaign) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[c.ID()]; exists {
		return fmt.Errorf("%w: campaign %q", ErrDuplicate, c.ID())
	}
	r.items[c.ID()] = c
	return nil
}

func (r *memoryCampaign) Save(_ context.Context, c validation.Campaign) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[c.ID()]; !exists {
		return fmt.Errorf("%w: campaign %q", ErrNotFound, c.ID())
	}
	r.items[c.ID()] = c
	return nil
}

func (r *memoryCampaign) Get(_ context.Context, id string) (validation.Campaign, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.items[id]
	if !ok {
		return validation.Campaign{}, fmt.Errorf("%w: campaign %q", ErrNotFound, id)
	}
	return c, nil
}

func (r *memoryCampaign) List(context.Context) ([]validation.Campaign, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]validation.Campaign, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

type memoryExercise struct {
	mu    sync.Mutex
	items map[string]validation.Exercise
}

func (r *memoryExercise) Create(_ context.Context, e validation.Exercise) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[e.ID]; exists {
		return fmt.Errorf("%w: exercise %q", ErrDuplicate, e.ID)
	}
	r.items[e.ID] = e
	return nil
}

func (r *memoryExercise) Get(_ context.Context, id string) (validation.Exercise, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.items[id]
	if !ok {
		return validation.Exercise{}, fmt.Errorf("%w: exercise %q", ErrNotFound, id)
	}
	return e, nil
}

func (r *memoryExercise) List(context.Context) ([]validation.Exercise, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]validation.Exercise, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

func (r *memoryValidation) ListResults(context.Context) ([]*v1.ValidationResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*v1.ValidationResult, 0, len(r.results))
	for _, id := range sortedIDs(r.results) {
		out = append(out, cloneOf(r.results[id]))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Audit (append-only; no update/delete surface exists by design).
// ---------------------------------------------------------------------------

type memoryAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
	byID    map[string]AuditEntry
}

func (r *memoryAudit) Append(_ context.Context, e AuditEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[e.ID]; exists {
		return fmt.Errorf("%w: audit %q", ErrDuplicate, e.ID)
	}
	r.byID[e.ID] = e
	r.entries = append(r.entries, e)
	return nil
}

func (r *memoryAudit) Get(_ context.Context, id string) (AuditEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byID[id]
	if !ok {
		return AuditEntry{}, fmt.Errorf("%w: audit %q", ErrNotFound, id)
	}
	return e, nil
}

func (r *memoryAudit) List(context.Context) ([]AuditEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AuditEntry(nil), r.entries...), nil
}

// NewMemoryBackend returns all repositories backed by maps, for fast
// deterministic unit tests. Production/lab durability comes from SQLite.
func NewMemoryBackend() Backend {
	return Backend{
		Telemetry: &memoryTelemetry{items: map[string]*v1.TelemetryEvent{}},
		Detection: &memoryDetection{items: map[string]*v1.Detection{}},
		Alert:     &memoryAlert{items: map[string]*v1.Alert{}},
		Incident:  &memoryIncident{items: map[string]*v1.Incident{}},
		Evidence:  &memoryEvidence{items: map[string]*v1.Evidence{}},
		Response:  &memoryResponse{items: map[string]*v1.ResponseRecommendation{}},
		ResponseRecords: &memoryResponseRecords{
			approvals:     map[string]*v1.ResponseApproval{},
			executions:    map[string]*v1.ResponseExecution{},
			verifications: map[string]*v1.ResponseVerification{},
		},
		Validation: &memoryValidation{
			requests: map[string]*v1.ValidationRequest{},
			results:  map[string]*v1.ValidationResult{},
		},
		Campaigns:         &memoryCampaign{items: map[string]validation.Campaign{}},
		Exercises:         &memoryExercise{items: map[string]validation.Exercise{}},
		Assessments:       &memoryAssessment{items: map[string]grc.Assessment{}},
		Resilience:        &memoryResilience{items: map[string]grc.ResilienceRecord{}},
		Components:        &memoryComponent{items: map[string]supplychain.Component{}},
		Dependencies:      &memoryDependency{items: map[depKey]supplychain.Dependency{}},
		SBOMs:             &memorySBOM{items: map[string]supplychain.SBOM{}},
		Policies:          &memoryPolicy{items: map[string]supplychain.SupplyPolicy{}},
		Vendors:           &memoryVendor{items: map[string]supplychain.Vendor{}},
		VendorAssessments: &memoryVendorAssessment{items: map[string]supplychain.VendorAssessment{}},
		SupplyLinks:       &memorySupplyLink{items: map[string]supplychain.SupplyLink{}},
		Audit:             &memoryAudit{byID: map[string]AuditEntry{}},
		Assets:            &memoryAsset{items: map[string]*v1.Asset{}},
		Relationships:     &memoryRelationships{items: map[relKey]asset.Relationship{}},
	}
}

// Backend bundles every repository behind its interface. Both the in-memory
// and SQLite backends produce one; the shared storetest suite runs against
// either without knowing which.
type Backend struct {
	Telemetry         TelemetryRepository
	Detection         DetectionRepository
	Alert             AlertRepository
	Incident          IncidentRepository
	Evidence          EvidenceRepository
	Response          ResponseRepository
	ResponseRecords   ResponseRecordRepository
	Validation        ValidationRepository
	Campaigns         CampaignRepository
	Exercises         ExerciseRepository
	Assessments       AssessmentRepository
	Resilience        ResilienceRepository
	Components        ComponentRepository
	Dependencies      DependencyRepository
	SBOMs             SBOMRepository
	Policies          PolicyRepository
	Vendors           VendorRepository
	VendorAssessments VendorAssessmentRepository
	SupplyLinks       SupplyLinkRepository
	Audit             AuditRepository
	Assets            AssetRepository
	Relationships     AssetRelationshipRepository
}

// ---------------------------------------------------------------------------
// Assets (lifecycle-mutable) + relationships (append-only).
// ---------------------------------------------------------------------------

type memoryAsset struct {
	mu    sync.Mutex
	items map[string]*v1.Asset
}

func (r *memoryAsset) Create(ctx context.Context, a *v1.Asset) error {
	if err := contract.ValidateAsset(a); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := asset.CheckCanonical(a); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[a.GetId()]; exists {
		return fmt.Errorf("%w: asset %q", ErrDuplicate, a.GetId())
	}
	for _, existing := range r.items {
		if existing.GetType() == a.GetType() && existing.GetName() == a.GetName() {
			return fmt.Errorf("%w: asset identity (type %v, %q)",
				ErrDuplicate, a.GetType(), a.GetName())
		}
	}
	r.items[a.GetId()] = cloneOf(a)
	return nil
}

func (r *memoryAsset) Save(ctx context.Context, a *v1.Asset) error {
	if err := contract.ValidateAsset(a); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := asset.CheckCanonical(a); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[a.GetId()]; !exists {
		return fmt.Errorf("%w: asset %q", ErrNotFound, a.GetId())
	}
	// Save must not steal another asset's (type,name) identity (mirrors
	// the UNIQUE(type,name) the SQLite backend enforces).
	for id, existing := range r.items {
		if id != a.GetId() && existing.GetType() == a.GetType() && existing.GetName() == a.GetName() {
			return fmt.Errorf("%w: asset identity (type %v, %q)",
				ErrDuplicate, a.GetType(), a.GetName())
		}
	}
	r.items[a.GetId()] = cloneOf(a)
	return nil
}

func (r *memoryAsset) Get(_ context.Context, id string) (*v1.Asset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: asset %q", ErrNotFound, id)
	}
	return cloneOf(a), nil
}

func (r *memoryAsset) listWhere(typ *v1.AssetType, status *v1.AssetStatus) []*v1.Asset {
	var out []*v1.Asset
	for _, id := range sortedIDs(r.items) {
		a := r.items[id]
		if typ != nil && a.GetType() != *typ {
			continue
		}
		if status != nil && a.GetStatus() != *status {
			continue
		}
		out = append(out, cloneOf(a))
	}
	return out
}

func (r *memoryAsset) List(context.Context) ([]*v1.Asset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listWhere(nil, nil), nil
}

func (r *memoryAsset) ListByType(_ context.Context, typ v1.AssetType) ([]*v1.Asset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listWhere(&typ, nil), nil
}

func (r *memoryAsset) ListByStatus(_ context.Context, status v1.AssetStatus) ([]*v1.Asset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listWhere(nil, &status), nil
}

type relKey struct {
	parent, child, kind string
}

type memoryRelationships struct {
	mu    sync.Mutex
	items map[relKey]asset.Relationship
}

func (r *memoryRelationships) Append(_ context.Context, rel asset.Relationship) error {
	if err := rel.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := relKey{rel.ParentID, rel.ChildID, rel.Kind}
	if _, exists := r.items[k]; exists {
		return fmt.Errorf("%w: relationship %v", ErrDuplicate, k)
	}
	r.items[k] = rel
	return nil
}

func (r *memoryRelationships) Children(_ context.Context, parentID string) ([]asset.Relationship, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []asset.Relationship
	for _, k := range sortedRelKeys(r.items) {
		if k.parent == parentID {
			out = append(out, r.items[k])
		}
	}
	return out, nil
}

func (r *memoryRelationships) Parents(_ context.Context, childID string) ([]asset.Relationship, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []asset.Relationship
	for _, k := range sortedRelKeys(r.items) {
		if k.child == childID {
			out = append(out, r.items[k])
		}
	}
	return out, nil
}

func sortedRelKeys(m map[relKey]asset.Relationship) []relKey {
	keys := make([]relKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].parent != keys[j].parent {
			return keys[i].parent < keys[j].parent
		}
		if keys[i].child != keys[j].child {
			return keys[i].child < keys[j].child
		}
		return keys[i].kind < keys[j].kind
	})
	return keys
}

// ---------------------------------------------------------------------------
// GRC assessments (append-only) + resilience records (append-only).
// ---------------------------------------------------------------------------

type memoryAssessment struct {
	mu    sync.Mutex
	items map[string]grc.Assessment
}

func (r *memoryAssessment) Create(_ context.Context, a grc.Assessment) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[a.ID()]; exists {
		return fmt.Errorf("%w: assessment %q", ErrDuplicate, a.ID())
	}
	r.items[a.ID()] = a
	return nil
}

func (r *memoryAssessment) Get(_ context.Context, id string) (grc.Assessment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return grc.Assessment{}, fmt.Errorf("%w: assessment %q", ErrNotFound, id)
	}
	return a, nil
}

func (r *memoryAssessment) List(context.Context) ([]grc.Assessment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]grc.Assessment, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

type memoryResilience struct {
	mu    sync.Mutex
	items map[string]grc.ResilienceRecord
}

func (r *memoryResilience) Create(_ context.Context, rec grc.ResilienceRecord) error {
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[rec.ID]; exists {
		return fmt.Errorf("%w: resilience record %q", ErrDuplicate, rec.ID)
	}
	r.items[rec.ID] = rec
	return nil
}

func (r *memoryResilience) Get(_ context.Context, id string) (grc.ResilienceRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.items[id]
	if !ok {
		return grc.ResilienceRecord{}, fmt.Errorf("%w: resilience record %q", ErrNotFound, id)
	}
	return rec, nil
}

func (r *memoryResilience) List(context.Context) ([]grc.ResilienceRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]grc.ResilienceRecord, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Supply chain (append-only; deterministic ids).
// ---------------------------------------------------------------------------

type memoryComponent struct {
	mu    sync.Mutex
	items map[string]supplychain.Component
}

func (r *memoryComponent) Create(_ context.Context, c supplychain.Component) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[c.ID()]; exists {
		return fmt.Errorf("%w: component %q", ErrDuplicate, c.ID())
	}
	r.items[c.ID()] = c
	return nil
}

func (r *memoryComponent) Get(_ context.Context, id string) (supplychain.Component, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.items[id]
	if !ok {
		return supplychain.Component{}, fmt.Errorf("%w: component %q", ErrNotFound, id)
	}
	return c, nil
}

func (r *memoryComponent) List(context.Context) ([]supplychain.Component, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]supplychain.Component, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

type depKey struct{ parent, child, kind string }

type memoryDependency struct {
	mu    sync.Mutex
	items map[depKey]supplychain.Dependency
}

func depKeyOf(d supplychain.Dependency) depKey {
	return depKey{d.ParentID, d.ChildID, string(d.Kind)}
}

func (r *memoryDependency) Append(_ context.Context, d supplychain.Dependency) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[depKeyOf(d)]; exists {
		return fmt.Errorf("%w: dependency %s→%s", ErrDuplicate, d.ParentID, d.ChildID)
	}
	r.items[depKeyOf(d)] = d
	return nil
}

func (r *memoryDependency) links(col string, id string) ([]supplychain.Dependency, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []supplychain.Dependency
	for _, d := range r.items {
		v := d.ParentID
		if col == "child" {
			v = d.ChildID
		}
		if v == id {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ParentID != out[j].ParentID {
			return out[i].ParentID < out[j].ParentID
		}
		if out[i].ChildID != out[j].ChildID {
			return out[i].ChildID < out[j].ChildID
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

func (r *memoryDependency) Children(_ context.Context, parentID string) ([]supplychain.Dependency, error) {
	return r.links("parent", parentID)
}

func (r *memoryDependency) Parents(_ context.Context, childID string) ([]supplychain.Dependency, error) {
	return r.links("child", childID)
}

type memorySBOM struct {
	mu    sync.Mutex
	items map[string]supplychain.SBOM
}

func (r *memorySBOM) Create(_ context.Context, s supplychain.SBOM) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[s.ID()]; exists {
		return fmt.Errorf("%w: sbom %q", ErrDuplicate, s.ID())
	}
	r.items[s.ID()] = s
	return nil
}

func (r *memorySBOM) Get(_ context.Context, id string) (supplychain.SBOM, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.items[id]
	if !ok {
		return supplychain.SBOM{}, fmt.Errorf("%w: sbom %q", ErrNotFound, id)
	}
	return s, nil
}

func (r *memorySBOM) List(context.Context) ([]supplychain.SBOM, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]supplychain.SBOM, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

type memoryPolicy struct {
	mu    sync.Mutex
	items map[string]supplychain.SupplyPolicy
}

func (r *memoryPolicy) Create(_ context.Context, p supplychain.SupplyPolicy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[p.ID]; exists {
		return fmt.Errorf("%w: policy %q", ErrDuplicate, p.ID)
	}
	r.items[p.ID] = p
	return nil
}

func (r *memoryPolicy) Get(_ context.Context, id string) (supplychain.SupplyPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[id]
	if !ok {
		return supplychain.SupplyPolicy{}, fmt.Errorf("%w: policy %q", ErrNotFound, id)
	}
	return p, nil
}

func (r *memoryPolicy) List(context.Context) ([]supplychain.SupplyPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]supplychain.SupplyPolicy, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

type memoryVendor struct {
	mu    sync.Mutex
	items map[string]supplychain.Vendor
}

func (r *memoryVendor) Create(_ context.Context, v supplychain.Vendor) error {
	if err := v.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[v.ID()]; exists {
		return fmt.Errorf("%w: vendor %q", ErrDuplicate, v.ID())
	}
	r.items[v.ID()] = v
	return nil
}

func (r *memoryVendor) Get(_ context.Context, id string) (supplychain.Vendor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[id]
	if !ok {
		return supplychain.Vendor{}, fmt.Errorf("%w: vendor %q", ErrNotFound, id)
	}
	return v, nil
}

func (r *memoryVendor) List(context.Context) ([]supplychain.Vendor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]supplychain.Vendor, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

type memoryVendorAssessment struct {
	mu    sync.Mutex
	items map[string]supplychain.VendorAssessment
}

func (r *memoryVendorAssessment) Create(_ context.Context, a supplychain.VendorAssessment) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[a.ID()]; exists {
		return fmt.Errorf("%w: vendor assessment %q", ErrDuplicate, a.ID())
	}
	r.items[a.ID()] = a
	return nil
}

func (r *memoryVendorAssessment) Get(_ context.Context, id string) (supplychain.VendorAssessment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return supplychain.VendorAssessment{}, fmt.Errorf("%w: vendor assessment %q", ErrNotFound, id)
	}
	return a, nil
}

func (r *memoryVendorAssessment) List(context.Context) ([]supplychain.VendorAssessment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]supplychain.VendorAssessment, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}

type memorySupplyLink struct {
	mu    sync.Mutex
	items map[string]supplychain.SupplyLink
}

func (r *memorySupplyLink) Create(_ context.Context, l supplychain.SupplyLink) error {
	if err := l.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[l.ID()]; exists {
		return fmt.Errorf("%w: supply link %q", ErrDuplicate, l.ID())
	}
	r.items[l.ID()] = l
	return nil
}

func (r *memorySupplyLink) List(context.Context) ([]supplychain.SupplyLink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]supplychain.SupplyLink, 0, len(r.items))
	for _, id := range sortedIDs(r.items) {
		out = append(out, r.items[id])
	}
	return out, nil
}
