// Manager: observation ingest over repository interfaces. The interfaces
// are declared here (narrow, asset-owned) so this package never imports
// the store package — store.AssetRepository satisfies AssetStore implicitly
// (identical method sets), and store provides an adapter for relationships.
// Dependency arrows stay acyclic by construction (verified by go list).
//
// Ingest flow per observation:
//  1. Normalize → deterministic id.
//  2. Get by id: hit → Touch (last_seen bump, STALE/DISCOVERED revive),
//     Save, return (asset, false).
//  3. Miss → Create, then Decompose: derived parents materialize with
//     derivation provenance + CONTAINS relationships appended.
//  4. Touch/Create failures from a concurrent duplicate Create retry once
//     as Touch: the same observation racing itself resolves to one asset.
//
// Not-found/duplicate detection matches on the store sentinel text
// ("not found", "duplicate id"); both paths are covered by tests, so a
// sentinel rename breaks loudly here rather than silently.
package asset

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// AssetStore is the persistence surface the Manager needs. Satisfied by
// store.AssetRepository without importing it.
type AssetStore interface {
	Create(ctx context.Context, a *v1.Asset) error
	Save(ctx context.Context, a *v1.Asset) error
	Get(ctx context.Context, id string) (*v1.Asset, error)
}

// RelationshipStore is the persistence surface for derived links.
type RelationshipStore interface {
	Append(ctx context.Context, rel Relationship) error
}

// Manager owns asset inventory lifecycle above persistence.
type Manager struct {
	mu     sync.Mutex
	assets AssetStore
	rels   RelationshipStore
	clock  func() time.Time
}

// NewManager returns a Manager. Nil stores or clock are rejected.
func NewManager(assets AssetStore, rels RelationshipStore, clock func() time.Time) (*Manager, error) {
	if assets == nil || rels == nil {
		return nil, fmt.Errorf("asset: manager needs asset and relationship stores")
	}
	if clock == nil {
		return nil, fmt.Errorf("asset: manager clock is nil")
	}
	return &Manager{assets: assets, rels: rels, clock: clock}, nil
}

// Ingest normalizes one observation into the inventory. Returns the stored
// asset and whether it was created (false = re-observation touch).
func (m *Manager) Ingest(ctx context.Context, obs Observation) (*v1.Asset, bool, error) {
	now := m.clock()
	if now.IsZero() {
		return nil, false, fmt.Errorf("asset: manager clock returned zero time")
	}
	fresh, err := Normalize(obs)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, err := m.assets.Get(ctx, fresh.GetId())
	if err == nil {
		if terr := Touch(existing, now); terr != nil {
			return nil, false, terr
		}
		if serr := m.assets.Save(ctx, existing); serr != nil {
			return nil, false, fmt.Errorf("asset: touch save: %w", serr)
		}
		return existing, false, nil
	}
	if !isNotFound(err) {
		return nil, false, fmt.Errorf("asset: lookup: %w", err)
	}
	if cerr := m.assets.Create(ctx, fresh); cerr != nil {
		if isDuplicate(cerr) {
			return m.touchAfterRace(ctx, fresh.GetId(), now)
		}
		return nil, false, fmt.Errorf("asset: create: %w", cerr)
	}
	// Materialize namespace decomposition with provenance.
	derived, rels := Decompose(fresh, obs.Source, now)
	for _, d := range derived {
		if derr := m.assets.Create(ctx, d); derr != nil && !isDuplicate(derr) {
			return nil, false, fmt.Errorf("asset: derived create: %w", derr)
		}
	}
	for _, r := range rels {
		if rerr := m.rels.Append(ctx, r); rerr != nil && !isDuplicate(rerr) {
			return nil, false, fmt.Errorf("asset: relationship append: %w", rerr)
		}
	}
	stored, err := m.assets.Get(ctx, fresh.GetId())
	if err != nil {
		return nil, false, fmt.Errorf("asset: re-read: %w", err)
	}
	if verr := contract.ValidateAsset(stored); verr != nil {
		return nil, false, fmt.Errorf("asset: stored record invalid: %v", verr)
	}
	return stored, true, nil
}

func (m *Manager) touchAfterRace(ctx context.Context, id string, now time.Time) (*v1.Asset, bool, error) {
	existing, gerr := m.assets.Get(ctx, id)
	if gerr != nil {
		return nil, false, fmt.Errorf("asset: raced create re-read: %w", gerr)
	}
	if terr := Touch(existing, now); terr != nil {
		return nil, false, terr
	}
	if serr := m.assets.Save(ctx, existing); serr != nil {
		return nil, false, fmt.Errorf("asset: raced touch save: %w", serr)
	}
	return existing, false, nil
}

// Resolve maps a telemetry-style asset reference to a stored asset:
// exact id first, then strict canonical forms (HOST, DOMAIN, IP_ADDRESS,
// URL — fixed order, documented best-effort). Unknown references yield
// (nil, nil): telemetry ingestion never blocks on missing inventory.
func (m *Manager) Resolve(ctx context.Context, ref string) (*v1.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, err := m.assets.Get(ctx, ref); err == nil {
		return a, nil
	} else if !isNotFound(err) {
		return nil, fmt.Errorf("asset: resolve lookup: %w", err)
	}
	for _, typ := range []v1.AssetType{
		v1.AssetType_ASSET_TYPE_HOST,
		v1.AssetType_ASSET_TYPE_DOMAIN,
		v1.AssetType_ASSET_TYPE_IP_ADDRESS,
		v1.AssetType_ASSET_TYPE_URL,
	} {
		canonical, cerr := Canonicalize(typ, ref)
		if cerr != nil {
			continue
		}
		if a, err := m.assets.Get(ctx, IDFor(typ, canonical)); err == nil {
			return a, nil
		} else if !isNotFound(err) {
			return nil, fmt.Errorf("asset: resolve lookup: %w", err)
		}
	}
	return nil, nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

func isDuplicate(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate")
}
