// Lifecycle: DISCOVERED → ACTIVE → STALE → RETIRED, plus STALE → ACTIVE
// on re-observation (revival) and ACTIVE → RETIRED (direct dismissal).
// RETIRED is terminal. STALE means "unobserved lately", never "dead";
// assets are never auto-deleted. Legacy records without a status are
// treated as DISCOVERED (their only legal move is ACTIVE).
package asset

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

// nextStates maps each status to its legal successors.
func nextStates(from v1.AssetStatus) []v1.AssetStatus {
	switch from {
	case v1.AssetStatus_ASSET_STATUS_UNSPECIFIED,
		v1.AssetStatus_ASSET_STATUS_DISCOVERED:
		return []v1.AssetStatus{v1.AssetStatus_ASSET_STATUS_ACTIVE}
	case v1.AssetStatus_ASSET_STATUS_ACTIVE:
		return []v1.AssetStatus{
			v1.AssetStatus_ASSET_STATUS_STALE,
			v1.AssetStatus_ASSET_STATUS_RETIRED,
		}
	case v1.AssetStatus_ASSET_STATUS_STALE:
		return []v1.AssetStatus{
			v1.AssetStatus_ASSET_STATUS_ACTIVE,
			v1.AssetStatus_ASSET_STATUS_RETIRED,
		}
	default:
		return nil
	}
}

// Transition moves an asset exactly one legal step, stamping last_seen.
// Anything else — skips, reversals, moves out of RETIRED, UNSPECIFIED
// targets — is an explicit error, never silent normalization.
func Transition(a *v1.Asset, to v1.AssetStatus, now time.Time) error {
	if a == nil {
		return fmt.Errorf("%w: nil asset", ErrLifecycle)
	}
	if to == v1.AssetStatus_ASSET_STATUS_UNSPECIFIED {
		return fmt.Errorf("%w: target must be explicit", ErrLifecycle)
	}
	legal := false
	for _, s := range nextStates(a.GetStatus()) {
		if s == to {
			legal = true
		}
	}
	if !legal {
		return fmt.Errorf("%w: %v → %v", ErrLifecycle, a.GetStatus(), to)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: transition timestamp is zero", ErrLifecycle)
	}
	a.Status = to
	a.LastSeen = timestamppb.New(now)
	return nil
}

// Touch records a re-observation: last_seen always advances; STALE revives
// to ACTIVE and DISCOVERED confirms to ACTIVE; first_seen never moves.
// Timestamps come from the caller (injected clocks in tests).
func Touch(a *v1.Asset, now time.Time) error {
	if a == nil {
		return fmt.Errorf("%w: nil asset", ErrLifecycle)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: observation timestamp is zero", ErrLifecycle)
	}
	a.LastSeen = timestamppb.New(now)
	switch a.GetStatus() {
	case v1.AssetStatus_ASSET_STATUS_STALE,
		v1.AssetStatus_ASSET_STATUS_DISCOVERED,
		v1.AssetStatus_ASSET_STATUS_UNSPECIFIED:
		a.Status = v1.AssetStatus_ASSET_STATUS_ACTIVE
	}
	return nil
}
