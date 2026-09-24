// Read-only architecture context (13I.8): nodes from real assets, edges
// from real relationships. No second graph store, no inferred topology,
// no trust boundaries from thin air — environment labels surface as
// declared boundary context only.
package grc

import (
	"fmt"
	"sort"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
)

// SystemNode is one architecture node with asset provenance.
type SystemNode struct {
	AssetID  string
	Kind     string
	Name     string
	Boundary string
}

// DependencyEdge is one architecture edge with relationship provenance.
type DependencyEdge struct {
	ParentID string
	ChildID  string
	Kind     string
}

// ArchitectureView is the deterministic read model.
type ArchitectureViewModel struct {
	Nodes []SystemNode
	Edges []DependencyEdge
}

// ArchitectureView builds the read model, skipping nothing: callers that
// need strictness use ArchitectureViewChecked.
func ArchitectureView(assets []*v1.Asset, rels []asset.Relationship) ArchitectureViewModel {
	nodes := make([]SystemNode, 0, len(assets))
	for _, a := range assets {
		if a == nil {
			continue
		}
		nodes = append(nodes, SystemNode{
			AssetID: a.GetId(), Kind: a.GetType().String(), Name: a.GetName(),
			Boundary: a.GetEnvironment(),
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].AssetID < nodes[j].AssetID })
	edges := make([]DependencyEdge, 0, len(rels))
	for _, r := range rels {
		edges = append(edges, DependencyEdge{ParentID: r.ParentID, ChildID: r.ChildID, Kind: r.Kind})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ParentID != edges[j].ParentID {
			return edges[i].ParentID < edges[j].ParentID
		}
		if edges[i].ChildID != edges[j].ChildID {
			return edges[i].ChildID < edges[j].ChildID
		}
		return edges[i].Kind < edges[j].Kind
	})
	return ArchitectureViewModel{Nodes: nodes, Edges: edges}
}

// ArchitectureViewChecked is ArchitectureView but rejects unsupported
// relationship kinds instead of passing them through.
func ArchitectureViewChecked(assets []*v1.Asset, rels []asset.Relationship) (ArchitectureViewModel, error) {
	for _, r := range rels {
		if err := r.Validate(); err != nil {
			return ArchitectureViewModel{}, fmt.Errorf("grc: architecture edge: %v", err)
		}
	}
	return ArchitectureView(assets, rels), nil
}
