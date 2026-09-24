// Boundary validation for the Asset contract, mirroring check_asset
// (Rust core) and asset.schema.json. Step-13A fields (environment, status,
// first/last_seen, attributes) are optional for backward compatibility;
// when present they must be explicit.
package contract

import (
	"fmt"

	v1 "blueveil/collector/internal/contract/v1"
)

// ValidateAsset enforces the Asset boundary.
func ValidateAsset(a *v1.Asset) error {
	if a == nil {
		return fmt.Errorf("contract: Asset is nil")
	}
	if a.GetId() == "" {
		return fmt.Errorf("contract: Asset.id: empty")
	}
	name, known := v1.AssetType_name[int32(a.GetType())]
	if !known {
		return fmt.Errorf("contract: Asset.type: unknown value %d", int32(a.GetType()))
	}
	if a.GetType() == v1.AssetType_ASSET_TYPE_UNSPECIFIED {
		return fmt.Errorf("contract: Asset.type must be explicit, never %s", name)
	}
	if a.GetName() == "" {
		return fmt.Errorf("contract: Asset.name: empty")
	}
	for i, id := range a.GetIdentifiers() {
		if id.GetType() == "" || id.GetValue() == "" {
			return fmt.Errorf("contract: Asset.identifiers[%d]: type and value required", i)
		}
	}
	if a.GetCriticality() != v1.Severity_SEVERITY_UNSPECIFIED {
		if _, known := v1.Severity_name[int32(a.GetCriticality())]; !known {
			return fmt.Errorf("contract: Asset.criticality: unknown value %d", int32(a.GetCriticality()))
		}
	}
	// Optional lifecycle fields: absent is legacy-valid; present must be explicit.
	if a.GetStatus() != v1.AssetStatus_ASSET_STATUS_UNSPECIFIED {
		if _, known := v1.AssetStatus_name[int32(a.GetStatus())]; !known {
			return fmt.Errorf("contract: Asset.status: unknown value %d", int32(a.GetStatus()))
		}
	}
	if a.GetFirstSeen() == nil && a.GetLastSeen() != nil {
		return fmt.Errorf("contract: Asset.last_seen without first_seen")
	}
	if a.GetFirstSeen() != nil && a.GetLastSeen() != nil &&
		a.GetLastSeen().AsTime().Before(a.GetFirstSeen().AsTime()) {
		return fmt.Errorf("contract: Asset.last_seen before first_seen")
	}
	return nil
}
