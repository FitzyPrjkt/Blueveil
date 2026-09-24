package response

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

func testRec() *v1.ResponseRecommendation {
	return &v1.ResponseRecommendation{
		Id: "rec-1", IncidentId: "inc-1", Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND,
		Target: "asset-1", Risk: v1.RiskLevel_RISK_LEVEL_HIGH, Reason: "review",
		Status:        v1.ResponseStatus_RESPONSE_STATUS_PENDING_APPROVAL,
		RecommendedAt: timestamppb.New(respClock()), RecommendedBy: RecommenderName,
		ApprovalRequired: true,
	}
}

func TestGrantBindsApproval(t *testing.T) {
	now := respClock()
	appr, err := Grant(testRec(), "test-actor:analyst", "reviewed, proportional", now, time.Hour)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := contract.ValidateResponseApproval(appr); err != nil {
		t.Fatalf("approval must validate: %v", err)
	}
	if appr.GetRecommendationId() != "rec-1" || appr.GetOperation() != testRec().GetOperation() ||
		appr.GetTarget() != "asset-1" || appr.GetRisk() != v1.RiskLevel_RISK_LEVEL_HIGH {
		t.Fatalf("binding fields must mirror the recommendation: %+v", appr)
	}
	if appr.GetExpiresAt() == nil {
		t.Fatal("ttl must set expiry")
	}
	// No ttl → no expiry, still valid.
	forever, err := Grant(testRec(), "test-actor:analyst", "ok", now, 0)
	if err != nil || forever.GetExpiresAt() != nil {
		t.Fatalf("zero ttl means no expiry: %+v %v", forever, err)
	}
}

func TestGrantRejectsBadInput(t *testing.T) {
	now := respClock()
	if _, err := Grant(nil, "a", "r", now, 0); err == nil {
		t.Fatal("nil recommendation must fail")
	}
	if _, err := Grant(testRec(), "", "r", now, 0); err == nil {
		t.Fatal("empty approver must fail")
	}
	if _, err := Grant(testRec(), "a", "", now, 0); err == nil {
		t.Fatal("empty reason must fail")
	}
	if _, err := Grant(testRec(), "a", "r", time.Time{}, 0); err == nil {
		t.Fatal("zero timestamp must fail")
	}
	if _, err := Grant(testRec(), "a", "r", now, -time.Second); err == nil {
		t.Fatal("negative ttl must fail")
	}
}

func TestCoversEnforcesBinding(t *testing.T) {
	now := respClock()
	rec := testRec()
	appr, err := Grant(rec, "test-actor:analyst", "ok", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !Covers(appr, rec, now) {
		t.Fatal("fresh approval must cover")
	}
	// Wrong recommendation.
	other := testRec()
	other.Id = "rec-2"
	if Covers(appr, other, now) {
		t.Fatal("approval must not cover another recommendation")
	}
	// Wrong operation / target / risk.
	for _, mutate := range []func(*v1.ResponseRecommendation){
		func(r *v1.ResponseRecommendation) { r.Operation = v1.OperationType_OPERATION_TYPE_BLOCK },
		func(r *v1.ResponseRecommendation) { r.Target = "asset-2" },
		func(r *v1.ResponseRecommendation) { r.Risk = v1.RiskLevel_RISK_LEVEL_LOW },
	} {
		altered := testRec()
		mutate(altered)
		if Covers(appr, altered, now) {
			t.Fatalf("approval must not cover altered request %+v", altered)
		}
	}
	// Expired approval rejects (deterministic: check after expiry).
	if Covers(appr, rec, now.Add(2*time.Hour)) {
		t.Fatal("expired approval must reject")
	}
	if Covers(nil, rec, now) || Covers(appr, nil, now) {
		t.Fatal("nil inputs must not cover")
	}
}
