// Request construction: ValidationRequests are built ONLY from real
// Blueveil data (incident, alert, detection, contributing events). Nothing
// is invented: no target URLs, no credentials, no payloads, no CVEs.
//
// Honest field mapping:
//   - control_id: the defense under test, taken from the contributing
//     telemetry's rule/control attributes (e.g. a WAF rule id the source
//     recorded). Absent everywhere → explicit construction error: Blueveil
//     will not validate a control it cannot name.
//   - target: the observed asset ids, sorted and joined.
//   - context: linkage (incident/alert/detection ids) — free-form by design.
//   - id: deterministic per (control, target, incident).
package validation

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

// controlAttributeKeys names the telemetry attributes that may identify
// the defense under test, in priority order. Only these keys are read;
// nothing else in attributes is interpreted as control identity.
// Unexported: importers must not be able to rewrite control identity.
var controlAttributeKeys = []string{"control_id", "rule_id"}

// requestID is deterministic per (control, target, incident).
func requestID(controlID, target, incidentID string) string {
	sum := sha256.Sum256([]byte("blueveil-validation-request-v1\x1f" + controlID + "\x1f" + target + "\x1f" + incidentID))
	return "vreq-" + hex.EncodeToString(sum[:])[:16]
}

// BuildRequest constructs a contract-valid request from validated Blueveil
// objects. Linkage (alert→detection, detection→events) is re-checked: gaps
// are errors, never fabricated references.
func BuildRequest(incident *v1.Incident, alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent, now time.Time) (*v1.ValidationRequest, error) {
	if incident == nil || alert == nil || det == nil {
		return nil, fmt.Errorf("%w: incident, alert and detection are required", ErrValidationBuild)
	}
	if err := contract.ValidateIncident(incident); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValidationBuild, err)
	}
	if err := contract.ValidateAlert(alert); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValidationBuild, err)
	}
	if err := contract.ValidateDetection(det); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValidationBuild, err)
	}
	attached := false
	for _, id := range incident.GetAlertIds() {
		if id == alert.GetId() {
			attached = true
		}
	}
	if !attached {
		return nil, fmt.Errorf("%w: alert %q not attached to incident %q",
			ErrValidationBuild, alert.GetId(), incident.GetId())
	}
	linked := false
	for _, id := range alert.GetDetectionIds() {
		if id == det.GetId() {
			linked = true
		}
	}
	if !linked {
		return nil, fmt.Errorf("%w: alert %q does not reference detection %q",
			ErrValidationBuild, alert.GetId(), det.GetId())
	}
	byID := make(map[string]*v1.TelemetryEvent, len(events))
	for _, e := range events {
		if e == nil {
			return nil, fmt.Errorf("%w: nil contributing event", ErrValidationBuild)
		}
		byID[e.GetId()] = e
	}
	assets := map[string]bool{}
	control := ""
	for _, id := range det.GetTelemetryEventIds() {
		e, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("%w: detection event %q not provided (refusing to fabricate)",
				ErrValidationBuild, id)
		}
		if err := contract.ValidateTelemetryEvent(e); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrValidationBuild, err)
		}
		assets[e.GetAssetId()] = true
		if control == "" {
			for _, key := range controlAttributeKeys {
				if v := e.GetAttributes()[key]; v != "" {
					control = v
					break
				}
			}
		}
	}
	if control == "" {
		return nil, fmt.Errorf("%w: no control identity in contributing telemetry (need %s attributes)",
			ErrValidationBuild, strings.Join(controlAttributeKeys, "/"))
	}
	targets := make([]string, 0, len(assets))
	for a := range assets {
		targets = append(targets, a)
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: no target asset", ErrValidationBuild)
	}
	if now.IsZero() {
		return nil, fmt.Errorf("%w: request timestamp is zero", ErrValidationBuild)
	}
	target := strings.Join(targets, ",")
	req := &v1.ValidationRequest{
		Id:        requestID(control, target, incident.GetId()),
		ControlId: control,
		Target:    target,
		Context: map[string]string{
			"incident_id":  incident.GetId(),
			"alert_id":     alert.GetId(),
			"detection_id": det.GetId(),
		},
		RequestedAt: timestamppb.New(now),
	}
	if req.GetRequestedAt() == nil {
		return nil, fmt.Errorf("%w: timestamp out of range", ErrValidationBuild)
	}
	if err := CheckRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}
