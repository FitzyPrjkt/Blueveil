// Metadata-level forensic artifacts over already-persisted telemetry.
// Classification is a deterministic function of event type (+ explicit
// action where the source declares one). Artifacts carry provenance and a
// content fingerprint; they never carry secrets and never claim forensic
// certainty. No acquisition of any kind happens here.
package investigate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
)

// ArtifactType is the bounded classification vocabulary.
type ArtifactType string

const (
	ArtifactProcess        ArtifactType = "PROCESS"
	ArtifactFileActivity   ArtifactType = "FILE_ACTIVITY"
	ArtifactService        ArtifactType = "SERVICE"
	ArtifactNetwork        ArtifactType = "NETWORK"
	ArtifactAuthentication ArtifactType = "AUTHENTICATION"
	ArtifactIdentity       ArtifactType = "IDENTITY"
	ArtifactContainer      ArtifactType = "CONTAINER"
	ArtifactCloud          ArtifactType = "CLOUD"
	ArtifactUnknown        ArtifactType = "UNKNOWN"
)

// sensitiveKeys never enter artifact metadata.
var sensitiveKeys = []string{
	"password", "passwd", "token", "secret", "credential", "cookie",
	"private_key", "privatekey", "session", "api_key", "apikey", "mfa",
	"access_key", "auth.password",
}

// Artifact is one metadata-level forensic observation.
type Artifact struct {
	Type       ArtifactType
	EventID    string
	AssetID    string
	Source     string
	ObservedAt time.Time
	Metadata   map[string]string
	Digest     string
}

// Classify maps an event type (+ explicit source-declared action) to an
// artifact type. Unknown types yield UNKNOWN, never a guess.
func Classify(eventType, action string) ArtifactType {
	switch eventType {
	case "endpoint.activity":
		if action == "file_modify" {
			return ArtifactFileActivity
		}
		return ArtifactProcess
	case "server.activity":
		return ArtifactService
	case "net.connection", "http.request", "waf.request_blocked", "waf.request_allowed":
		return ArtifactNetwork
	case "auth.activity":
		return ArtifactAuthentication
	case "identity.activity":
		return ArtifactIdentity
	case "container.activity":
		return ArtifactContainer
	case "cloud.activity":
		return ArtifactCloud
	default:
		return ArtifactUnknown
	}
}

func actionOf(e *v1.TelemetryEvent) string {
	for _, k := range []string{
		"endpoint.action", "server.service_action", "auth.outcome",
		"identity.action", "container.action", "cloud.action",
		"http.method", "net.verdict",
	} {
		if v := e.GetAttributes()[k]; v != "" {
			return strings.ToLower(v)
		}
	}
	return ""
}

// ArtifactFor builds the redacted metadata artifact for one event.
// Secrets are dropped by key fragment; the digest fingerprints the
// surviving canonical content.
func ArtifactFor(e *v1.TelemetryEvent) (Artifact, error) {
	var a Artifact
	if e == nil || e.GetOccurredAt() == nil {
		return a, fmt.Errorf("investigate: corrupt event %s fails closed", idOf(e))
	}
	meta := map[string]string{}
	for k, v := range e.GetAttributes() {
		low := strings.ToLower(k)
		drop := false
		for _, frag := range sensitiveKeys {
			if strings.Contains(low, frag) {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		meta[k] = v
	}
	a = Artifact{
		Type:       Classify(e.GetEventType(), actionOf(e)),
		EventID:    e.GetId(),
		AssetID:    e.GetAssetId(),
		Source:     e.GetSource(),
		ObservedAt: e.GetOccurredAt().AsTime(),
		Metadata:   meta,
		Digest:     fingerprint(e, meta),
	}
	return a, nil
}

func fingerprint(e *v1.TelemetryEvent, meta map[string]string) string {
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(e.GetId())
	b.WriteString("\x1f")
	b.WriteString(e.GetEventType())
	b.WriteString("\x1f")
	b.WriteString(e.GetOccurredAt().AsTime().UTC().Format(time.RFC3339Nano))
	for _, k := range keys {
		b.WriteString("\x1f")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(meta[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
