// Identity/auth/data asset correlation (13E.6). Principals are modeled as
// OTHER-type assets with a blueveil.identity_principal marker — no new
// asset types. Auto-create is gated on an explicit principal allowlist;
// anything else resolves against existing inventory or stays unresolved.
// Exact principal strings only: similar names never merge.
package identobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

// IdentCorrelateConfig gates principal auto-creation on an explicit
// allowlist of principal names (case-insensitive exact match).
type IdentCorrelateConfig struct {
	AllowedPrincipals []string
	AllowAutoCreate   bool
}

func (c IdentCorrelateConfig) validate() (map[string]bool, error) {
	if !c.AllowAutoCreate && len(c.AllowedPrincipals) > 0 {
		return nil, fmt.Errorf("identobs: allowed principals configured while auto-create disabled")
	}
	if c.AllowAutoCreate && len(c.AllowedPrincipals) == 0 {
		return nil, fmt.Errorf("identobs: auto-create needs at least one allowed principal")
	}
	m := map[string]bool{}
	for _, p := range c.AllowedPrincipals {
		trim := strings.ToLower(strings.TrimSpace(p))
		if trim == "" {
			return nil, fmt.Errorf("identobs: empty allowed principal")
		}
		m[trim] = true
	}
	return m, nil
}

// RelationshipStore is the narrow append boundary the correlator needs.
type RelationshipStore interface {
	Append(ctx context.Context, rel asset.Relationship) error
}

// IdentCorrelator links identity/auth/data observations to assets.
type IdentCorrelator struct {
	mu      sync.Mutex
	mgr     *asset.Manager
	rels    RelationshipStore
	allowed map[string]bool
	auto    bool
}

// NewIdentCorrelator validates configuration up front; invalid config is a
// construction error, never a silent default.
func NewIdentCorrelator(mgr *asset.Manager, rels RelationshipStore, cfg IdentCorrelateConfig) (*IdentCorrelator, error) {
	if mgr == nil {
		return nil, fmt.Errorf("identobs: asset manager is nil")
	}
	if rels == nil {
		return nil, fmt.Errorf("identobs: relationship store is nil")
	}
	allowed, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	return &IdentCorrelator{mgr: mgr, rels: rels, allowed: allowed, auto: cfg.AllowAutoCreate}, nil
}

// IdentCorrelation is the result of linking one observation. Nil assets
// mean "unresolved, telemetry preserved".
type IdentCorrelation struct {
	Obs              Observation
	PrincipalAsset   *v1.Asset
	PrincipalCreated bool
	TargetAsset      *v1.Asset
	RelRecorded      bool
	RelKind          string
}

// Correlate resolves (and optionally observes) the principal, then records
// one explicit relationship when both endpoints are known. All steps are
// idempotent; duplicate relationships are swallowed.
func (c *IdentCorrelator) Correlate(ctx context.Context, event *v1.TelemetryEvent) (IdentCorrelation, error) {
	var corr IdentCorrelation
	obs, err := Parse(event)
	if err != nil {
		return corr, err
	}
	corr.Obs = obs

	c.mu.Lock()
	defer c.mu.Unlock()

	var principal, target, kind string
	switch obs.Type {
	case EventTypeIdentityActivity:
		principal = obs.Identity.Principal
		target = obs.Identity.Target
		if target == "" {
			target = obs.Identity.Role
		}
		if target == "" {
			target = obs.Identity.Group
		}
		switch obs.Identity.Action {
		case "login", "logout":
			kind = asset.RelationAuthenticatesTo
		case "role_change", "permission_change":
			kind = asset.RelationAssumes
		case "group_change":
			kind = asset.RelationMemberOf
		default:
			kind = asset.RelationAssumes
		}
	case EventTypeAuthActivity:
		principal = obs.Auth.Principal
		target = obs.Auth.Target
		kind = asset.RelationAuthenticatesTo
	case EventTypeDataActivity:
		principal = obs.Data.Principal
		target = obs.Data.Resource
		kind = asset.RelationAccesses
	}

	// Data observations may legitimately lack a principal (system action).
	if principal == "" {
		if target != "" {
			if a, err := c.mgr.Resolve(ctx, target); err != nil {
				return corr, fmt.Errorf("identobs: resolve target: %w", err)
			} else if a != nil {
				corr.TargetAsset = a
			} else if a, err := c.resolveOther(ctx, target); err == nil && a != nil {
				corr.TargetAsset = a
			}
		}
		return corr, nil
	}

	pAsset, created, err := c.ensurePrincipal(ctx, principal, obs)
	if err != nil {
		return corr, err
	}
	corr.PrincipalAsset, corr.PrincipalCreated = pAsset, created
	if pAsset == nil || target == "" {
		return corr, nil
	}

	tAsset, err := c.resolveOther(ctx, target)
	if err != nil {
		return corr, fmt.Errorf("identobs: resolve target: %w", err)
	}
	if tAsset == nil && created {
		// Target observed alongside an allowlisted principal: record as
		// OTHER with provenance (never merged, never inferred).
		stored, _, err := c.mgr.Ingest(ctx, asset.Observation{
			Source: obs.Source, Type: v1.AssetType_ASSET_TYPE_OTHER,
			Raw: target, ObservedAt: obs.OccurredAt,
			Attributes: map[string]string{"blueveil.identobs_event": obs.EventID},
		})
		if err != nil {
			if !errors.Is(err, store.ErrDuplicate) {
				return corr, fmt.Errorf("identobs: observe target: %w", err)
			}
			if stored, rerr := c.resolveOther(ctx, target); rerr == nil {
				tAsset = stored
			}
		} else {
			tAsset = stored
		}
	}
	if tAsset == nil {
		return corr, nil
	}
	corr.TargetAsset = tAsset
	if pAsset.GetId() == tAsset.GetId() {
		return corr, nil
	}
	rel := asset.Relationship{
		ParentID: pAsset.GetId(), ChildID: tAsset.GetId(),
		Kind: kind, Source: obs.Source, ObservedAt: obs.OccurredAt,
	}
	if err := c.rels.Append(ctx, rel); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			corr.RelRecorded, corr.RelKind = true, kind
			return corr, nil
		}
		return corr, fmt.Errorf("identobs: append relationship: %w", err)
	}
	corr.RelRecorded, corr.RelKind = true, kind
	return corr, nil
}

// resolveOther looks up an OTHER-type asset by deterministic id. Resolve
// itself only covers strict types, so identity/target OTHER assets need
// the id-first path (exact match, never canonical coercion).
func (c *IdentCorrelator) resolveOther(ctx context.Context, raw string) (*v1.Asset, error) {
	canonical, err := asset.Canonicalize(v1.AssetType_ASSET_TYPE_OTHER, raw)
	if err != nil {
		return nil, err
	}
	a, err := c.mgr.Resolve(ctx, asset.IDFor(v1.AssetType_ASSET_TYPE_OTHER, canonical))
	if err != nil {
		return nil, err
	}
	return a, nil
}

// ensurePrincipal resolves one principal exactly, observing it as an OTHER
// asset only when explicitly allowlisted. Callers hold c.mu.
func (c *IdentCorrelator) ensurePrincipal(ctx context.Context, principal string, obs Observation) (*v1.Asset, bool, error) {
	a, err := c.resolveOther(ctx, principal)
	if err != nil {
		return nil, false, fmt.Errorf("identobs: resolve principal: %w", err)
	}
	if a != nil {
		return a, false, nil
	}
	if !c.auto || !c.allowed[strings.ToLower(principal)] {
		return nil, false, nil
	}
	stored, created, err := c.mgr.Ingest(ctx, asset.Observation{
		Source: obs.Source, Type: v1.AssetType_ASSET_TYPE_OTHER,
		Raw: principal, ObservedAt: obs.OccurredAt,
		Attributes: map[string]string{
			"blueveil.identobs_event":     obs.EventID,
			"blueveil.identity_principal": "true",
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("identobs: observe principal: %w", err)
	}
	return stored, created, nil
}
