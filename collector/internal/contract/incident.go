// Boundary validation for Incident and Evidence contracts.
// Mirrors check_incident / check_evidence (Rust core) and
// incident.schema.json / evidence.schema.json.
package contract

import (
	"fmt"
	"strings"

	v1 "blueveil/collector/internal/contract/v1"
)

// ValidateIncident enforces the Incident boundary: identity, alert linkage,
// explicit status and severity, timestamps, title. Summary is optional.
func ValidateIncident(in *v1.Incident) error {
	if in == nil {
		return fmt.Errorf("contract: Incident is nil")
	}
	if in.GetId() == "" {
		return fmt.Errorf("contract: Incident.id: empty")
	}
	if len(in.GetAlertIds()) == 0 {
		return fmt.Errorf("contract: Incident.alert_ids: requires at least one id")
	}
	for _, id := range in.GetAlertIds() {
		if id == "" {
			return fmt.Errorf("contract: Incident.alert_ids[]: empty id")
		}
	}
	name, known := v1.IncidentStatus_name[int32(in.GetStatus())]
	if !known {
		return fmt.Errorf("contract: Incident.status: unknown value %d", int32(in.GetStatus()))
	}
	if in.GetStatus() == v1.IncidentStatus_INCIDENT_STATUS_UNSPECIFIED {
		return fmt.Errorf("contract: Incident.status must be explicit, never %s", name)
	}
	if err := checkSeverityValue(int32(in.GetSeverity()), "Incident.severity"); err != nil {
		return err
	}
	if err := requireTimestamp(in.GetCreatedAt(), "Incident.created_at"); err != nil {
		return err
	}
	if err := requireTimestamp(in.GetUpdatedAt(), "Incident.updated_at"); err != nil {
		return err
	}
	if in.GetTitle() == "" {
		return fmt.Errorf("contract: Incident.title: empty")
	}
	return nil
}

// ValidateEvidence enforces the Evidence boundary: identity, incident
// linkage, explicit type, provenance (source, media type, timestamp),
// non-empty content. sha256, when present, must be 64 lowercase-hex chars.
func ValidateEvidence(e *v1.Evidence) error {
	if e == nil {
		return fmt.Errorf("contract: Evidence is nil")
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"id", e.GetId()},
		{"incident_id", e.GetIncidentId()},
		{"source", e.GetSource()},
		{"media_type", e.GetMediaType()},
		{"content", e.GetContent()},
	} {
		if f.value == "" {
			return fmt.Errorf("contract: Evidence.%s: empty", f.name)
		}
	}
	name, known := v1.EvidenceType_name[int32(e.GetType())]
	if !known {
		return fmt.Errorf("contract: Evidence.type: unknown value %d", int32(e.GetType()))
	}
	if e.GetType() == v1.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED {
		return fmt.Errorf("contract: Evidence.type must be explicit, never %s", name)
	}
	if err := requireTimestamp(e.GetCollectedAt(), "Evidence.collected_at"); err != nil {
		return err
	}
	if s := e.GetSha256(); s != "" &&
		!(len(s) == 64 && strings.IndexFunc(s, func(r rune) bool {
			return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f')
		}) == -1) {
		return fmt.Errorf("contract: Evidence.sha256: must be 64 lowercase-hex chars when present")
	}
	return nil
}
