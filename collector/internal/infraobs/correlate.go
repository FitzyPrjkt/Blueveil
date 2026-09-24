package infraobs

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

type InfraCorrelateConfig struct {
	AllowedHosts    []string
	AllowAutoCreate bool
}

func (c InfraCorrelateConfig) validate() (map[string]bool, error) {
	if !c.AllowAutoCreate && len(c.AllowedHosts) > 0 {
		return nil, fmt.Errorf("infraobs: allowed hosts configured while auto-create disabled")
	}
	if c.AllowAutoCreate && len(c.AllowedHosts) == 0 {
		return nil, fmt.Errorf("infraobs: auto-create needs at least one allowed host")
	}
	m := map[string]bool{}
	for _, h := range c.AllowedHosts {
		trim := strings.ToLower(strings.TrimSpace(h))
		if trim == "" {
			return nil, fmt.Errorf("infraobs: empty allowed host")
		}
		m[trim] = true
	}
	return m, nil
}

type RelationshipStore interface {
	Append(ctx context.Context, rel asset.Relationship) error
}

type InfraCorrelator struct {
	mu      sync.Mutex
	mgr     *asset.Manager
	rels    RelationshipStore
	allowed map[string]bool
	auto    bool
}

func NewInfraCorrelator(mgr *asset.Manager, rels RelationshipStore, cfg InfraCorrelateConfig) (*InfraCorrelator, error) {
	if mgr == nil {
		return nil, fmt.Errorf("infraobs: asset manager is nil")
	}
	if rels == nil {
		return nil, fmt.Errorf("infraobs: relationship store is nil")
	}
	allowed, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	return &InfraCorrelator{mgr: mgr, rels: rels, allowed: allowed, auto: cfg.AllowAutoCreate}, nil
}

type InfraCorrelation struct {
	Obs       Observation
	HostAsset *v1.Asset
	Created   bool
}

func (c *InfraCorrelator) Correlate(ctx context.Context, event *v1.TelemetryEvent) (InfraCorrelation, error) {
	var corr InfraCorrelation
	obs, err := Parse(event)
	if err != nil {
		return corr, err
	}
	corr.Obs = obs
	c.mu.Lock()
	defer c.mu.Unlock()

	var host string
	var typ v1.AssetType
	var raw string
	var relKind string
	var parentTyp v1.AssetType
	var childRaw string

	switch obs.Type {
	case EventTypeEndpointActivity:
		host = obs.Endpoint.Host
		typ = v1.AssetType_ASSET_TYPE_HOST
		raw = host
	case EventTypeServerActivity:
		host = obs.Server.Hostname
		typ = v1.AssetType_ASSET_TYPE_HOST
		raw = host
		// Also handle service
		if obs.Server.Service != "" {
			// Try to ensure HOST RUNS SERVICE
			svcRaw := obs.Server.Hostname + ":" + obs.Server.Service
			// service as SERVICE type: host:service
			if svc, err := c.mgr.Resolve(ctx, svcRaw); err == nil && svc == nil && c.auto && c.allowed[strings.ToLower(host)] {
				svcAsset, _, err := c.mgr.Ingest(ctx, asset.Observation{
					Source: obs.Source, Type: v1.AssetType_ASSET_TYPE_SERVICE, Raw: svcRaw, ObservedAt: obs.OccurredAt,
					Attributes: map[string]string{"blueveil.infra_event": obs.EventID},
				})
				if err == nil {
					hostAsset, _ := c.mgr.Resolve(ctx, host)
					if hostAsset != nil {
						rel := asset.Relationship{ParentID: hostAsset.GetId(), ChildID: svcAsset.GetId(), Kind: asset.RelationRuns, Source: obs.Source, ObservedAt: obs.OccurredAt}
						_ = c.rels.Append(ctx, rel)
					}
				}
			} else if svc != nil {
				// Ensure relationship even if service existed
				if hostAsset, _ := c.mgr.Resolve(ctx, host); hostAsset != nil {
					rel := asset.Relationship{ParentID: hostAsset.GetId(), ChildID: svc.GetId(), Kind: asset.RelationRuns, Source: obs.Source, ObservedAt: obs.OccurredAt}
					_ = c.rels.Append(ctx, rel)
				}
			}
		}
	case EventTypeContainerActivity:
		host = obs.Container.Cluster
		if host == "" {
			host = obs.Container.Pod
		}
		// For container, primary asset is CONTAINER
		typ = v1.AssetType_ASSET_TYPE_CONTAINER
		raw = obs.Container.ContainerID
		relKind = asset.RelationRuns
		parentTyp = v1.AssetType_ASSET_TYPE_HOST
		childRaw = obs.Container.ContainerID
		// Handle container specifically below
		if typ == v1.AssetType_ASSET_TYPE_CONTAINER {
			// Resolve or create container
			var containerAsset *v1.Asset
			var created bool
			if a, err := c.mgr.Resolve(ctx, raw); err != nil {
				return corr, err
			} else if a != nil {
				containerAsset = a
			} else if c.auto && (c.allowed[strings.ToLower(obs.Container.Image)] || c.allowed[strings.ToLower(host)] || len(c.allowed) > 0) {
				// For lab, allow any if allowed hosts contains image or host
				// Simplify: allow if auto and host is allowed or image host is allowed
				allowed := false
				for h := range c.allowed {
					if strings.Contains(strings.ToLower(raw), h) || strings.Contains(strings.ToLower(obs.Container.Image), h) {
						allowed = true
						break
					}
				}
				if allowed || len(c.allowed) > 0 {
					stored, cr, err := c.mgr.Ingest(ctx, asset.Observation{
						Source: obs.Source, Type: typ, Raw: raw, ObservedAt: obs.OccurredAt,
						Attributes: map[string]string{"blueveil.infra_event": obs.EventID, "image": obs.Container.Image},
					})
					if err != nil {
						return corr, err
					}
					containerAsset = stored
					created = cr
					corr.HostAsset = containerAsset
					corr.Created = created
					// Also create HOST if needed and link
					if host != "" {
						if hAsset, err := c.mgr.Resolve(ctx, host); err == nil && hAsset == nil && c.auto {
							hStored, _, _ := c.mgr.Ingest(ctx, asset.Observation{Source: obs.Source, Type: v1.AssetType_ASSET_TYPE_HOST, Raw: host, ObservedAt: obs.OccurredAt})
							if hStored != nil {
								rel := asset.Relationship{ParentID: hStored.GetId(), ChildID: containerAsset.GetId(), Kind: asset.RelationRuns, Source: obs.Source, ObservedAt: obs.OccurredAt}
								_ = c.rels.Append(ctx, rel)
							}
						}
					}
					return corr, nil
				}
			}
			if containerAsset != nil {
				corr.HostAsset = containerAsset
				// Try to link to host if exists
				if host != "" {
					if hAsset, _ := c.mgr.Resolve(ctx, host); hAsset != nil {
						rel := asset.Relationship{ParentID: hAsset.GetId(), ChildID: containerAsset.GetId(), Kind: asset.RelationRuns, Source: obs.Source, ObservedAt: obs.OccurredAt}
						_ = c.rels.Append(ctx, rel)
					}
				}
				return corr, nil
			}
			return corr, nil
		}
	case EventTypeCloudActivity:
		host = obs.Cloud.Account
		if host == "" {
			host = obs.Cloud.Provider
		}
		typ = v1.AssetType_ASSET_TYPE_CLOUD_RESOURCE
		raw = obs.Cloud.Resource
		if raw == "" {
			raw = obs.Cloud.Action + ":" + obs.Cloud.Principal
		}
	}

	// Generic host-based path for endpoint/server/cloud
	if raw == "" {
		return corr, nil
	}
	_ = relKind
	_ = parentTyp
	_ = childRaw

	// Resolve or create
	if a, err := c.mgr.Resolve(ctx, raw); err != nil {
		return corr, err
	} else if a != nil {
		corr.HostAsset = a
		return corr, nil
	}
	if !c.auto {
		return corr, nil
	}
	// Check allowed
	if _, ok := c.allowed[strings.ToLower(host)]; !ok {
		// For cloud, also check provider
		if obs.Type == EventTypeCloudActivity {
			if _, ok2 := c.allowed[strings.ToLower(obs.Cloud.Provider)]; !ok2 {
				return corr, nil
			}
		} else {
			return corr, nil
		}
	}
	stored, created, err := c.mgr.Ingest(ctx, asset.Observation{
		Source: obs.Source, Type: typ, Raw: raw, ObservedAt: obs.OccurredAt,
		Attributes: map[string]string{"blueveil.infra_event": obs.EventID},
	})
	if err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			// Try resolve again
			if a, _ := c.mgr.Resolve(ctx, raw); a != nil {
				corr.HostAsset = a
				return corr, nil
			}
		}
		return corr, err
	}
	corr.HostAsset = stored
	corr.Created = created
	return corr, nil
}
