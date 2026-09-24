// Recommendation generation: incident data in, proposal data out.
// The recommender NEVER emits destructive operations: every recommendation
// is read-only (OBSERVE/ANALYZE/RECOMMEND) with risk inherited from the
// incident severity. A HIGH incident yields "analyst review", never
// "automatically isolate host". Recommendations authorize nothing.
package response

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// RecommenderName identifies the component (never a human).
const RecommenderName = "blueveil-recommender/1"

// severityOperation maps incident severity to a read-only operation and the
// inherited risk. Fixed table, documented, no inference.
func severityOperation(sev v1.Severity) (v1.OperationType, v1.RiskLevel) {
	switch sev {
	case v1.Severity_SEVERITY_CRITICAL:
		return v1.OperationType_OPERATION_TYPE_ANALYZE, v1.RiskLevel_RISK_LEVEL_CRITICAL
	case v1.Severity_SEVERITY_HIGH:
		return v1.OperationType_OPERATION_TYPE_RECOMMEND, v1.RiskLevel_RISK_LEVEL_HIGH
	case v1.Severity_SEVERITY_MEDIUM:
		return v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_MEDIUM
	default:
		return v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_LOW
	}
}

// recommendationID is deterministic per (incident, alert) pair.
func recommendationID(incidentID, alertID string) string {
	sum := sha256.Sum256([]byte("blueveil-recommendation-v1\x1f" + incidentID + "\x1f" + alertID))
	return "rec-" + hex.EncodeToString(sum[:])[:16]
}

// Recommender builds proposals from validated incident data. Clock supplies
// timestamps; a nil clock is a construction error.
type Recommender struct {
	clock func() time.Time
}

// NewRecommender returns a Recommender.
func NewRecommender(clock func() time.Time) (*Recommender, error) {
	if clock == nil {
		return nil, fmt.Errorf("%w: recommender clock is nil", ErrResponseBuild)
	}
	return &Recommender{clock: clock}, nil
}

// Recommend builds one PROPOSED recommendation for alertID inside incident,
// grounded in the alert/detection/events supplied. approval_required mirrors
// the safety gate rule for read-only operations (HIGH/CRITICAL risk); policy
// re-evaluates independently and never trusts the flag.
func (r *Recommender) Recommend(incident *v1.Incident, alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent) (*v1.ResponseRecommendation, error) {
	if incident == nil || alert == nil || det == nil {
		return nil, fmt.Errorf("%w: incident, alert and detection are required", ErrResponseBuild)
	}
	if err := contract.ValidateIncident(incident); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponseBuild, err)
	}
	if err := contract.ValidateAlert(alert); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponseBuild, err)
	}
	if err := contract.ValidateDetection(det); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponseBuild, err)
	}
	attached := false
	for _, id := range incident.GetAlertIds() {
		if id == alert.GetId() {
			attached = true
		}
	}
	if !attached {
		return nil, fmt.Errorf("%w: alert %q not attached to incident %q",
			ErrResponseBuild, alert.GetId(), incident.GetId())
	}
	assets := map[string]bool{}
	for _, e := range events {
		if e == nil {
			return nil, fmt.Errorf("%w: nil event", ErrResponseBuild)
		}
		if err := contract.ValidateTelemetryEvent(e); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrResponseBuild, err)
		}
		if e.GetAssetId() == "" {
			return nil, fmt.Errorf("%w: contributing event %q has no asset id", ErrResponseBuild, e.GetId())
		}
		assets[e.GetAssetId()] = true
	}
	names := make([]string, 0, len(assets))
	for a := range assets {
		names = append(names, a)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: no target asset", ErrResponseBuild)
	}
	now := r.clock()
	if now.IsZero() {
		return nil, fmt.Errorf("%w: clock returned zero time", ErrResponseBuild)
	}
	op, risk := severityOperation(incident.GetSeverity())
	rec := &v1.ResponseRecommendation{
		Id:               recommendationID(incident.GetId(), alert.GetId()),
		IncidentId:       incident.GetId(),
		Operation:        op,
		Target:           strings.Join(names, ","),
		Risk:             risk,
		Reason:           fmt.Sprintf("incident %s (severity %s, rule %s) requires analyst review; no automated action proposed", incident.GetId(), incident.GetSeverity(), det.GetRuleId()),
		Status:           v1.ResponseStatus_RESPONSE_STATUS_PROPOSED,
		RecommendedAt:    timestamppb.New(now),
		RecommendedBy:    RecommenderName,
		ApprovalRequired: risk == v1.RiskLevel_RISK_LEVEL_HIGH || risk == v1.RiskLevel_RISK_LEVEL_CRITICAL,
	}
	if rec.GetRecommendedAt() == nil {
		return nil, fmt.Errorf("%w: timestamp out of range", ErrResponseBuild)
	}
	if err := contract.ValidateResponseRecommendation(rec); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponseBuild, err)
	}
	return rec, nil
}
