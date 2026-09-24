// Provider registry: register, get, list. Deterministic listing (sorted by
// id). Duplicates, nil providers, and empty ids are rejected. No dynamic
// loading, no WASM, no remote providers — a static map with explicit rules,
// mirroring the Rust core ExtensionRegistry semantics.
package validation

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds validation providers by stable id.
type Registry struct {
	mu        sync.Mutex
	providers map[string]Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: map[string]Provider{}}
}

// Register adds a provider; duplicates, nil providers and empty ids fail.
func (r *Registry) Register(p Provider) error {
	if err := CheckProvider(p); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.providers == nil {
		r.providers = map[string]Provider{}
	}
	id := p.Info().ID
	if _, exists := r.providers[id]; exists {
		return fmt.Errorf("%w: duplicate provider id %q", ErrRegistry, id)
	}
	r.providers[id] = p
	return nil
}

// Get returns the provider for id.
func (r *Registry) Get(id string) (Provider, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[id]
	return p, ok
}

// List returns provider infos in stable id order.
func (r *Registry) List() []ProviderInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.providers))
	for id := range r.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ProviderInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.providers[id].Info())
	}
	return out
}
