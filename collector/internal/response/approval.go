// Approval: an explicit, bound, expirable authorization for exactly one
// recommendation. Binding fields (recommendation id + operation + target +
// risk) must ALL match at use — an approval for BLOCK target-A never
// authorizes DELETE target-B. Expired approvals reject; consumed approvals
// never run twice (replay protection lives in the Engine).
package response

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// approvalID is deterministic per (recommendation, approver, timestamp).
func approvalID(recID, approver string, now time.Time) string {
	sum := sha256.Sum256([]byte("blueveil-approval-v1\x1f" + recID + "\x1f" + approver + "\x1f" + now.UTC().Format(time.RFC3339Nano)))
	return "appr-" + hex.EncodeToString(sum[:])[:16]
}

// Grant builds an approval bound to rec. ttl == 0 means no expiry; ttl < 0
// is an error (expiry must be explicit, never accidental).
func Grant(rec *v1.ResponseRecommendation, approver, reason string, now time.Time, ttl time.Duration) (*v1.ResponseApproval, error) {
	if rec == nil {
		return nil, fmt.Errorf("%w: recommendation is nil", ErrApprovalInvalid)
	}
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrApprovalInvalid, err)
	}
	if approver == "" || reason == "" {
		return nil, fmt.Errorf("%w: approver and reason are required", ErrApprovalInvalid)
	}
	if now.IsZero() {
		return nil, fmt.Errorf("%w: approval timestamp is zero", ErrApprovalInvalid)
	}
	if ttl < 0 {
		return nil, fmt.Errorf("%w: negative ttl", ErrApprovalInvalid)
	}
	appr := &v1.ResponseApproval{
		Id:               approvalID(rec.GetId(), approver, now),
		RecommendationId: rec.GetId(),
		Operation:        rec.GetOperation(),
		Target:           rec.GetTarget(),
		Risk:             rec.GetRisk(),
		Approver:         approver,
		ApprovedAt:       timestamppb.New(now),
		Reason:           reason,
	}
	if appr.GetApprovedAt() == nil {
		return nil, fmt.Errorf("%w: timestamp out of range", ErrApprovalInvalid)
	}
	if ttl > 0 {
		appr.ExpiresAt = timestamppb.New(now.Add(ttl))
	}
	if err := contract.ValidateResponseApproval(appr); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrApprovalInvalid, err)
	}
	return appr, nil
}

// Covers reports whether approval authorizes rec at time now: same
// recommendation, same operation, same target, same risk, and unexpired.
// Any divergence — including expiry — rejects.
func Covers(approval *v1.ResponseApproval, rec *v1.ResponseRecommendation, now time.Time) bool {
	if approval == nil || rec == nil {
		return false
	}
	if approval.GetRecommendationId() != rec.GetId() {
		return false
	}
	if approval.GetOperation() != rec.GetOperation() {
		return false
	}
	if approval.GetTarget() != rec.GetTarget() {
		return false
	}
	if approval.GetRisk() != rec.GetRisk() {
		return false
	}
	if exp := approval.GetExpiresAt(); exp != nil && !now.Before(exp.AsTime()) {
		return false
	}
	return true
}
