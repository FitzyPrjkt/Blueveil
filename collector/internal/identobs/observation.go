// Package identobs normalizes identity/authentication/data-security
// observations carried by the existing TelemetryEvent contract (13E.2-5).
// Event types identity.activity / auth.activity / data.activity, facts in
// identity.* / auth.* / data.* namespaces. Missing optional fields stay
// unknown; malformed required fields fail explicitly. Credentials, tokens,
// session material are redacted before persistence — never stored.
package identobs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

const (
	EventTypeIdentityActivity = "identity.activity"
	EventTypeAuthActivity     = "auth.activity"
	EventTypeDataActivity     = "data.activity"
)

var validIdentityActions = map[string]bool{
	"login": true, "logout": true, "role_change": true, "group_change": true,
	"account_create": true, "account_disable": true, "account_enable": true, "permission_change": true,
}

var validAuthOutcomes = map[string]bool{
	"success": true, "failure": true, "denied": true, "challenged": true, "unknown": true,
}

var validDataActions = map[string]bool{
	"read": true, "write": true, "delete": true, "export": true, "access": true, "permission_change": true,
}

// Attribute redaction uses the canonical contract.SensitiveField; no
// layer keeps its own fragment list (see contract/sensitive.go).

type Observation struct {
	EventID    string
	Source     string
	AssetID    string
	OccurredAt time.Time
	Severity   v1.Severity
	Type       string
	Identity   IdentityObservation
	Auth       AuthObservation
	Data       DataObservation
	RawAttrs   map[string]string
}

type IdentityObservation struct {
	Principal            string
	PrincipalType        string
	Action               string
	Target               string
	TargetType           string
	Result               string
	Provider             string
	Role                 string
	Group                string
	AuthenticationMethod string
	RequestID            string
}

type AuthObservation struct {
	Principal            string
	AuthenticationMethod string
	Outcome              string
	Provider             string
	Target               string
	FailureReason        string
	RequestID            string
	Source               string
}

type DataObservation struct {
	Store          string
	DataType       string
	Resource       string
	Action         string
	Principal      string
	Result         string
	Classification string
	Bytes          int
	HasBytes       bool
	Destination    string
	AccessType     string
}

func Parse(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	if event == nil {
		return o, fmt.Errorf("identobs: nil event")
	}
	switch event.GetEventType() {
	case EventTypeIdentityActivity:
		return parseIdentity(event)
	case EventTypeAuthActivity:
		return parseAuth(event)
	case EventTypeDataActivity:
		return parseData(event)
	default:
		return o, fmt.Errorf("identobs: unknown event_type %q", event.GetEventType())
	}
}

func cleanAttrs(attrs map[string]string) map[string]string {
	clean := map[string]string{}
	for k, v := range attrs {
		if contract.SensitiveField(k) {
			continue
		}
		clean[k] = v
	}
	return clean
}

func parseIdentity(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	attrs := cleanAttrs(event.GetAttributes())
	principal := strings.TrimSpace(attrs["identity.principal"])
	if principal == "" {
		return o, fmt.Errorf("identobs: identity.principal required")
	}
	action := strings.ToLower(strings.TrimSpace(attrs["identity.action"]))
	if action == "" {
		return o, fmt.Errorf("identobs: identity.action required")
	}
	if !validIdentityActions[action] {
		return o, fmt.Errorf("identobs: unknown identity.action %q", action)
	}
	o = Observation{
		EventID: event.GetId(), Source: event.GetSource(), AssetID: event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(), Severity: event.GetSeverity(), Type: EventTypeIdentityActivity,
		Identity: IdentityObservation{
			Principal:            principal,
			PrincipalType:        strings.ToLower(strings.TrimSpace(attrs["identity.principal_type"])),
			Action:               action,
			Target:               strings.TrimSpace(attrs["identity.target"]),
			TargetType:           strings.ToLower(strings.TrimSpace(attrs["identity.target_type"])),
			Result:               strings.ToLower(strings.TrimSpace(attrs["identity.result"])),
			Provider:             strings.TrimSpace(attrs["identity.provider"]),
			Role:                 strings.TrimSpace(attrs["identity.role"]),
			Group:                strings.TrimSpace(attrs["identity.group"]),
			AuthenticationMethod: strings.TrimSpace(attrs["identity.authentication_method"]),
			RequestID:            strings.TrimSpace(attrs["identity.request_id"]),
		},
		RawAttrs: attrs,
	}
	return o, nil
}

func parseAuth(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	attrs := cleanAttrs(event.GetAttributes())
	principal := strings.TrimSpace(attrs["auth.principal"])
	if principal == "" {
		return o, fmt.Errorf("identobs: auth.principal required")
	}
	outcome := strings.ToLower(strings.TrimSpace(attrs["auth.outcome"]))
	if outcome == "" {
		return o, fmt.Errorf("identobs: auth.outcome required")
	}
	if !validAuthOutcomes[outcome] {
		return o, fmt.Errorf("identobs: unknown auth.outcome %q", outcome)
	}
	o = Observation{
		EventID: event.GetId(), Source: event.GetSource(), AssetID: event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(), Severity: event.GetSeverity(), Type: EventTypeAuthActivity,
		Auth: AuthObservation{
			Principal:            principal,
			AuthenticationMethod: strings.TrimSpace(attrs["auth.authentication_method"]),
			Outcome:              outcome,
			Provider:             strings.TrimSpace(attrs["auth.provider"]),
			Target:               strings.TrimSpace(attrs["auth.target"]),
			FailureReason:        strings.TrimSpace(attrs["auth.failure_reason"]),
			RequestID:            strings.TrimSpace(attrs["auth.request_id"]),
			Source:               strings.TrimSpace(attrs["auth.source"]),
		},
		RawAttrs: attrs,
	}
	return o, nil
}

func parseData(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	attrs := cleanAttrs(event.GetAttributes())
	resource := strings.TrimSpace(attrs["data.resource"])
	if resource == "" {
		return o, fmt.Errorf("identobs: data.resource required")
	}
	action := strings.ToLower(strings.TrimSpace(attrs["data.action"]))
	if action == "" {
		return o, fmt.Errorf("identobs: data.action required")
	}
	if !validDataActions[action] {
		return o, fmt.Errorf("identobs: unknown data.action %q", action)
	}
	bytesVal := 0
	hasBytes := false
	if s := strings.TrimSpace(attrs["data.bytes"]); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return o, fmt.Errorf("identobs: invalid data.bytes %q", s)
		}
		bytesVal = n
		hasBytes = true
	}
	o = Observation{
		EventID: event.GetId(), Source: event.GetSource(), AssetID: event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(), Severity: event.GetSeverity(), Type: EventTypeDataActivity,
		Data: DataObservation{
			Store:          strings.TrimSpace(attrs["data.data_store"]),
			DataType:       strings.TrimSpace(attrs["data.data_type"]),
			Resource:       resource,
			Action:         action,
			Principal:      strings.TrimSpace(attrs["data.principal"]),
			Result:         strings.ToLower(strings.TrimSpace(attrs["data.result"])),
			Classification: strings.ToLower(strings.TrimSpace(attrs["data.classification"])),
			Bytes:          bytesVal, HasBytes: hasBytes,
			Destination: strings.TrimSpace(attrs["data.destination"]),
			AccessType:  strings.ToLower(strings.TrimSpace(attrs["data.access_type"])),
		},
		RawAttrs: attrs,
	}
	return o, nil
}

// ID is deterministic over type + key identity fields. Same source event
// always yields the same identity; any material field change moves it.
func (o Observation) ID() string {
	var b strings.Builder
	b.WriteString(o.Type)
	b.WriteString("\x1f")
	switch o.Type {
	case EventTypeIdentityActivity:
		b.WriteString(o.Identity.Principal)
		b.WriteString("\x1f")
		b.WriteString(o.Identity.Action)
		b.WriteString("\x1f")
		b.WriteString(o.Identity.Target)
	case EventTypeAuthActivity:
		b.WriteString(o.Auth.Principal)
		b.WriteString("\x1f")
		b.WriteString(o.Auth.Outcome)
		b.WriteString("\x1f")
		b.WriteString(o.Auth.Target)
	case EventTypeDataActivity:
		b.WriteString(o.Data.Resource)
		b.WriteString("\x1f")
		b.WriteString(o.Data.Action)
		b.WriteString("\x1f")
		b.WriteString(o.Data.Principal)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "identobs-" + hex.EncodeToString(sum[:])[:16]
}
