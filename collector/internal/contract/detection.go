// Boundary validation for Detection and Alert contracts.
// Mirrors check_detection / check_alert (Rust core) and
// detection.schema.json / alert.schema.json: required fields present,
// enums explicit (never UNSPECIFIED), timestamps present, id lists
// non-empty, confidence within [0.0, 1.0].
package contract

import (
	"fmt"
	"math"

	v1 "blueveil/collector/internal/contract/v1"
)

// ValidateDetection enforces the Detection boundary.
func ValidateDetection(d *v1.Detection) error {
	if d == nil {
		return fmt.Errorf("contract: Detection is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", d.GetId()},
		{"rule_id", d.GetRuleId()},
		{"rule_name", d.GetRuleName()},
		{"title", d.GetTitle()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: Detection.%s: empty", f.name)
		}
	}
	if len(d.GetTelemetryEventIds()) == 0 {
		return fmt.Errorf("contract: Detection.telemetry_event_ids: requires at least one id")
	}
	for _, id := range d.GetTelemetryEventIds() {
		if id == "" {
			return fmt.Errorf("contract: Detection.telemetry_event_ids[]: empty id")
		}
	}
	if err := requireTimestamp(d.GetDetectedAt(), "Detection.detected_at"); err != nil {
		return err
	}
	if err := checkSeverityValue(int32(d.GetSeverity()), "Detection.severity"); err != nil {
		return err
	}
	// NaN must be rejected explicitly: comparisons are false for NaN,
	// so a range check alone would pass it (parity with core/contracts.rs).
	if c := d.GetConfidence(); math.IsNaN(c) || c < 0.0 || c > 1.0 {
		return fmt.Errorf("contract: Detection.confidence %v out of [0.0, 1.0]", c)
	}
	return nil
}

// ValidateAlert enforces the Alert boundary.
func ValidateAlert(a *v1.Alert) error {
	if a == nil {
		return fmt.Errorf("contract: Alert is nil")
	}
	if a.GetId() == "" {
		return fmt.Errorf("contract: Alert.id: empty")
	}
	if len(a.GetDetectionIds()) == 0 {
		return fmt.Errorf("contract: Alert.detection_ids: requires at least one id")
	}
	for _, id := range a.GetDetectionIds() {
		if id == "" {
			return fmt.Errorf("contract: Alert.detection_ids[]: empty id")
		}
	}
	name, known := v1.AlertStatus_name[int32(a.GetStatus())]
	if !known {
		return fmt.Errorf("contract: Alert.status: unknown value %d", int32(a.GetStatus()))
	}
	if a.GetStatus() == v1.AlertStatus_ALERT_STATUS_UNSPECIFIED {
		return fmt.Errorf("contract: Alert.status must be explicit, never %s", name)
	}
	if err := checkSeverityValue(int32(a.GetSeverity()), "Alert.severity"); err != nil {
		return err
	}
	if err := requireTimestamp(a.GetCreatedAt(), "Alert.created_at"); err != nil {
		return err
	}
	if err := requireTimestamp(a.GetUpdatedAt(), "Alert.updated_at"); err != nil {
		return err
	}
	if a.GetTitle() == "" {
		return fmt.Errorf("contract: Alert.title: empty")
	}
	return nil
}

func checkSeverityValue(v int32, what string) error {
	name, known := v1.Severity_name[v]
	if !known {
		return fmt.Errorf("contract: %s: unknown value %d", what, v)
	}
	if v1.Severity(v) == v1.Severity_SEVERITY_UNSPECIFIED {
		return fmt.Errorf("contract: %s must be explicit, never %s", what, name)
	}
	return nil
}
