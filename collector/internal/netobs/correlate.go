package netobs

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

// CorrelateConfig controls which endpoints the correlator may legitimately
// observe as new assets. Auto-creation is deliberately narrow: only
// endpoints inside explicitly configured local prefixes, and only when
// AllowAutoCreate is set. Anything else resolves against existing
// inventory or stays unresolved — telemetry is never blocked and assets
// are never merged or inferred (an IP seen beside a domain proves
// nothing about ownership).
type CorrelateConfig struct {
	// LocalPrefixes are CIDRs (e.g. "127.0.0.0/8") whose endpoints the
	// observing source legitimately establishes.
	LocalPrefixes []string
	// AllowAutoCreate permits observing local endpoints as IP_ADDRESS
	// assets. False means resolve-only.
	AllowAutoCreate bool
}

func (c CorrelateConfig) validate() ([]netip.Prefix, error) {
	if !c.AllowAutoCreate && len(c.LocalPrefixes) > 0 {
		return nil, fmt.Errorf("netobs: local prefixes configured while auto-create is disabled")
	}
	if c.AllowAutoCreate && len(c.LocalPrefixes) == 0 {
		return nil, fmt.Errorf("netobs: auto-create needs at least one local prefix")
	}
	out := make([]netip.Prefix, 0, len(c.LocalPrefixes))
	for _, raw := range c.LocalPrefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("netobs: invalid local prefix %q: %v", raw, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// RelationshipStore is the narrow append boundary the correlator needs.
type RelationshipStore interface {
	Append(ctx context.Context, rel asset.Relationship) error
}

// Correlator links normalized network observations to asset inventory:
// resolve each endpoint against existing assets, optionally observe local
// endpoints as new IP_ADDRESS assets, and record one COMMUNICATES_WITH
// relationship per fully-resolved pair. All steps are idempotent;
// duplicate relationships are swallowed (already recorded).
type Correlator struct {
	mu       sync.Mutex
	mgr      *asset.Manager
	rels     RelationshipStore
	prefixes []netip.Prefix
	auto     bool
}

// NewCorrelator validates configuration up front; invalid config is a
// construction error, never a silent default.
func NewCorrelator(mgr *asset.Manager, rels RelationshipStore, cfg CorrelateConfig) (*Correlator, error) {
	if mgr == nil {
		return nil, fmt.Errorf("netobs: asset manager is nil")
	}
	if rels == nil {
		return nil, fmt.Errorf("netobs: relationship store is nil")
	}
	prefixes, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	return &Correlator{mgr: mgr, rels: rels, prefixes: prefixes, auto: cfg.AllowAutoCreate}, nil
}

// Correlation is the result of linking one observation to inventory.
// Nil assets mean "unresolved, telemetry preserved".
type Correlation struct {
	Obs         Observation
	SrcAsset    *v1.Asset
	DstAsset    *v1.Asset
	SrcCreated  bool
	DstCreated  bool
	RelRecorded bool
}

// Correlate resolves (and optionally observes) both endpoints, then
// records the traffic relationship when both sides are known.
func (c *Correlator) Correlate(ctx context.Context, event *v1.TelemetryEvent) (Correlation, error) {
	var corr Correlation
	obs, err := Parse(event)
	if err != nil {
		return corr, err
	}
	corr.Obs = obs

	c.mu.Lock()
	defer c.mu.Unlock()
	src, created, err := c.resolveOrObserve(ctx, obs.SrcIP, obs, "src")
	if err != nil {
		return corr, err
	}
	corr.SrcAsset, corr.SrcCreated = src, created
	dst, created, err := c.resolveOrObserve(ctx, obs.DstIP, obs, "dst")
	if err != nil {
		return corr, err
	}
	corr.DstAsset, corr.DstCreated = dst, created

	if src == nil || dst == nil {
		return corr, nil
	}
	if src.GetId() == dst.GetId() {
		// Self traffic resolves but never self-links (Validate would
		// refuse it); the observation itself is the record.
		return corr, nil
	}
	rel := asset.Relationship{
		ParentID: src.GetId(), ChildID: dst.GetId(),
		Kind:   asset.RelationCommunicatesWith,
		Source: obs.Source, ObservedAt: obs.OccurredAt,
	}
	if err := c.rels.Append(ctx, rel); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			corr.RelRecorded = true
			return corr, nil
		}
		return corr, fmt.Errorf("netobs: append relationship: %w", err)
	}
	corr.RelRecorded = true
	return corr, nil
}

// resolveOrObserve looks up one endpoint in inventory, observing it as a
// new local IP_ADDRESS asset only when explicitly permitted. Callers hold
// c.mu, serializing the resolve-then-create window.
func (c *Correlator) resolveOrObserve(ctx context.Context, ip netip.Addr, obs Observation, role string) (*v1.Asset, bool, error) {
	a, err := c.mgr.Resolve(ctx, ip.String())
	if err != nil {
		return nil, false, fmt.Errorf("netobs: resolve %s: %w", role, err)
	}
	if a != nil {
		return a, false, nil
	}
	if !c.auto || !c.isLocal(ip) {
		return nil, false, nil
	}
	stored, created, err := c.mgr.Ingest(ctx, asset.Observation{
		Source: obs.Source, Type: v1.AssetType_ASSET_TYPE_IP_ADDRESS,
		Raw: ip.String(), ObservedAt: obs.OccurredAt,
		Attributes: map[string]string{
			"blueveil.netobs_event": obs.EventID,
			"blueveil.netobs_role":  role,
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("netobs: observe %s: %w", role, err)
	}
	return stored, created, nil
}

func (c *Correlator) isLocal(ip netip.Addr) bool {
	for _, p := range c.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
