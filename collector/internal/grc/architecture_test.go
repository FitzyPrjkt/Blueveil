// RED: read-only architecture context over real assets/relationships.
// No inferred topology, no trust boundaries from thin air.
package grc

import (
	"testing"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
)

func TestArchitectureNodesFromAssets(t *testing.T) {
	assets := []*v1.Asset{
		{Id: "ast-1", Type: v1.AssetType_ASSET_TYPE_HOST, Name: "web01"},
		{Id: "ast-2", Type: v1.AssetType_ASSET_TYPE_SERVICE, Name: "web01:443"},
	}
	view := ArchitectureView(assets, nil)
	if len(view.Nodes) != 2 {
		t.Fatalf("want 2 nodes, got %+v", view)
	}
	if view.Nodes[0].AssetID != "ast-1" || view.Nodes[0].Kind != "ASSET_TYPE_HOST" {
		t.Fatalf("node provenance: %+v", view.Nodes[0])
	}
	// Deterministic order by asset id.
	if view.Nodes[0].AssetID > view.Nodes[1].AssetID {
		t.Fatalf("nodes must sort by asset id")
	}
}

func TestArchitectureEdgesReuseRelationships(t *testing.T) {
	rels := []asset.Relationship{
		{ParentID: "ast-1", ChildID: "ast-2", Kind: asset.RelationRuns},
		{ParentID: "ast-2", ChildID: "ast-3", Kind: asset.RelationCommunicatesWith},
	}
	view := ArchitectureView(nil, rels)
	if len(view.Edges) != 2 {
		t.Fatalf("want 2 edges, got %+v", view)
	}
	if view.Edges[0].Kind != "RUNS" || view.Edges[0].ParentID != "ast-1" {
		t.Fatalf("edge provenance: %+v", view.Edges[0])
	}
}

func TestArchitectureRejectsUnknownKinds(t *testing.T) {
	rels := []asset.Relationship{
		{ParentID: "ast-1", ChildID: "ast-2", Kind: "MIND_MELD"},
	}
	if _, err := ArchitectureViewChecked(nil, rels); err == nil {
		t.Errorf("unsupported relationship kind must be rejected")
	}
}

func TestTrustBoundaryDeclaredOnly(t *testing.T) {
	// Environment labels surface as boundary context; nothing is inferred
	// from IP ranges or names.
	assets := []*v1.Asset{
		{Id: "ast-1", Type: v1.AssetType_ASSET_TYPE_HOST, Name: "web01", Environment: "lab"},
		{Id: "ast-2", Type: v1.AssetType_ASSET_TYPE_HOST, Name: "db01"},
	}
	view := ArchitectureView(assets, nil)
	if view.Nodes[0].Boundary != "lab" {
		t.Fatalf("declared environment must surface: %+v", view.Nodes[0])
	}
	if view.Nodes[1].Boundary != "" {
		t.Fatalf("missing environment must stay empty, not inferred: %+v", view.Nodes[1])
	}
}
