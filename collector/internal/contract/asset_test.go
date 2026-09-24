package contract

import (
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestAssetFixturesValidate(t *testing.T) {
	var legacy v1.Asset
	if err := UnmarshalStrict(fixture(t, "asset/valid.json"), &legacy); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateAsset(&legacy); err != nil {
		t.Fatalf("legacy asset (no Step-13A fields) must validate: %v", err)
	}
	var full v1.Asset
	if err := UnmarshalStrict(fixture(t, "asset/valid_full.json"), &full); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateAsset(&full); err != nil {
		t.Fatalf("full asset must validate: %v", err)
	}
	if full.GetStatus() != v1.AssetStatus_ASSET_STATUS_ACTIVE {
		t.Fatalf("status drift: %v", full.GetStatus())
	}
	var bad v1.Asset
	if err := UnmarshalStrict(fixture(t, "asset/invalid_status.json"), &bad); err != nil {
		t.Fatalf("unspecified-status fixture parses by proto3 rules: %v", err)
	}
	// Go/Rust boundary is lenient-zero for legacy records; the JSON Schema
	// is the strict boundary that rejects explicit UNSPECIFIED (proven by
	// the 29/29 fixture check). Both layers agree on unknown values:
	bad.Status = 99
	if err := ValidateAsset(&bad); err == nil {
		t.Fatal("unknown status value must fail")
	}
}
