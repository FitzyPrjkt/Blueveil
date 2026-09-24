package httpobs

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

type HTTPCorrelateConfig struct {
	AllowedHosts    []string
	AllowAutoCreate bool
}

func (c HTTPCorrelateConfig) validate() (map[string]bool, error) {
	if !c.AllowAutoCreate && len(c.AllowedHosts) > 0 {
		return nil, fmt.Errorf("httpobs: allowed hosts configured while auto-create disabled")
	}
	if c.AllowAutoCreate && len(c.AllowedHosts) == 0 {
		return nil, fmt.Errorf("httpobs: auto-create needs at least one allowed host")
	}
	m := map[string]bool{}
	for _, h := range c.AllowedHosts {
		trim := strings.ToLower(strings.TrimSpace(h))
		if trim == "" {
			return nil, fmt.Errorf("httpobs: empty allowed host")
		}
		if strings.Contains(trim, " ") || strings.Contains(trim, "/") {
			return nil, fmt.Errorf("httpobs: invalid allowed host %q", h)
		}
		m[trim] = true
	}
	return m, nil
}

type HTTPCorrelator struct {
	mu      sync.Mutex
	mgr     *asset.Manager
	rels    RelationshipStore
	allowed map[string]bool
	auto    bool
}

type RelationshipStore interface {
	Append(ctx context.Context, rel asset.Relationship) error
}

func NewHTTPCorrelator(mgr *asset.Manager, rels RelationshipStore, cfg HTTPCorrelateConfig) (*HTTPCorrelator, error) {
	if mgr == nil {
		return nil, fmt.Errorf("httpobs: asset manager is nil")
	}
	if rels == nil {
		return nil, fmt.Errorf("httpobs: relationship store is nil")
	}
	allowed, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	return &HTTPCorrelator{mgr: mgr, rels: rels, allowed: allowed, auto: cfg.AllowAutoCreate}, nil
}

type HTTPCorrelation struct {
	Obs                 Observation
	URLAsset            *v1.Asset
	URLCreated          bool
	DomainAsset         *v1.Asset
	AppAsset            *v1.Asset
	AppCreated          bool
	ServiceAsset        *v1.Asset
	RelExposesRecorded  bool
	RelServedByRecorded bool
}

func (c *HTTPCorrelator) Correlate(ctx context.Context, event *v1.TelemetryEvent) (HTTPCorrelation, error) {
	var corr HTTPCorrelation
	obs, err := Parse(event)
	if err != nil {
		return corr, err
	}
	corr.Obs = obs
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build canonical URL.
	scheme := obs.Scheme
	if scheme == "" {
		scheme = "https"
	}
	urlStr := fmt.Sprintf("%s://%s%s", scheme, obs.Host, obs.Path)
	// Resolve existing URL first.
	if a, err := c.mgr.Resolve(ctx, urlStr); err != nil {
		return corr, fmt.Errorf("httpobs: resolve url: %w", err)
	} else if a != nil {
		corr.URLAsset = a
	} else if c.auto && c.allowed[strings.ToLower(obs.Host)] {
		// Observe as URL.
		stored, created, err := c.mgr.Ingest(ctx, asset.Observation{
			Source: obs.Source, Type: v1.AssetType_ASSET_TYPE_URL, Raw: urlStr,
			ObservedAt: obs.OccurredAt, Attributes: map[string]string{"blueveil.httpobs_event": obs.EventID},
		})
		if err != nil {
			return corr, fmt.Errorf("httpobs: observe url: %w", err)
		}
		corr.URLAsset = stored
		corr.URLCreated = created
	} else {
		return corr, nil
	}
	// Domain is derived via Decompose, but we can also resolve it.
	if d, err := c.mgr.Resolve(ctx, obs.Host); err == nil && d != nil {
		corr.DomainAsset = d
	}
	// APPLICATION if attribute present.
	if appName := strings.TrimSpace(obs.RawAttrs["http.application"]); appName != "" {
		if a, err := c.mgr.Resolve(ctx, appName); err != nil {
			return corr, fmt.Errorf("httpobs: resolve app: %w", err)
		} else if a != nil {
			corr.AppAsset = a
		} else if c.auto && c.allowed[strings.ToLower(obs.Host)] {
			stored, created, err := c.mgr.Ingest(ctx, asset.Observation{
				Source: obs.Source, Type: v1.AssetType_ASSET_TYPE_APPLICATION, Raw: appName,
				ObservedAt: obs.OccurredAt, Attributes: map[string]string{"blueveil.httpobs_event": obs.EventID},
			})
			if err != nil {
				return corr, fmt.Errorf("httpobs: observe app: %w", err)
			}
			corr.AppAsset = stored
			corr.AppCreated = created
		}
		if corr.AppAsset != nil && corr.URLAsset != nil {
			rel := asset.Relationship{
				ParentID: corr.AppAsset.GetId(), ChildID: corr.URLAsset.GetId(),
				Kind: asset.RelationExposes, Source: obs.Source, ObservedAt: obs.OccurredAt,
			}
			if err := c.rels.Append(ctx, rel); err != nil {
				if errors.Is(err, store.ErrDuplicate) {
					corr.RelExposesRecorded = true
				} else {
					return corr, fmt.Errorf("httpobs: append exposes: %w", err)
				}
			} else {
				corr.RelExposesRecorded = true
			}
		}
	}
	// SERVED_BY: URL -> SERVICE
	if corr.URLAsset != nil {
		// Derive service via host:port
		port := "443"
		if scheme == "http" {
			port = "80"
		}
		svcRaw := obs.Host + ":" + port
		if svc, err := c.mgr.Resolve(ctx, svcRaw); err == nil && svc != nil {
			corr.ServiceAsset = svc
			rel := asset.Relationship{
				ParentID: corr.URLAsset.GetId(), ChildID: svc.GetId(),
				Kind: asset.RelationServedBy, Source: obs.Source, ObservedAt: obs.OccurredAt,
			}
			if err := c.rels.Append(ctx, rel); err != nil {
				if errors.Is(err, store.ErrDuplicate) {
					corr.RelServedByRecorded = true
				} else {
					return corr, fmt.Errorf("httpobs: append served_by: %w", err)
				}
			} else {
				corr.RelServedByRecorded = true
			}
		} else if err != nil && !isNotFound(err) {
			return corr, fmt.Errorf("httpobs: resolve service: %w", err)
		}
	}
	return corr, nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}
