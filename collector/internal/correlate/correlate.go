// Package correlate attaches purely associative metadata: events sharing
// (source, asset_id, event_type) receive the same correlation id, a stable
// 16-hex digest of that triple. It infers no attack, emits no alert, and
// changes no other field. A source-provided correlation id always wins.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"

	v1 "blueveil/collector/internal/contract/v1"
)

// AttributeKey is the only key this package ever writes.
const AttributeKey = "blueveil.correlation_id"

// KeyOf returns the grouping triple in a fixed encoding.
func KeyOf(source, assetID, eventType string) string {
	return source + "\x1f" + assetID + "\x1f" + eventType
}

// IDFor deterministically derives the correlation id for a triple:
// identical input always yields identical output, in any process, any run.
func IDFor(source, assetID, eventType string) string {
	sum := sha256.Sum256([]byte(KeyOf(source, assetID, eventType)))
	return hex.EncodeToString(sum[:])[:16]
}

// Apply stamps the correlation id unless the source already provided one.
func Apply(event *v1.TelemetryEvent) {
	if event == nil {
		return
	}
	attrs := event.GetAttributes()
	if attrs == nil {
		attrs = make(map[string]string, 1)
		event.Attributes = attrs
	}
	if v, exists := attrs[AttributeKey]; exists && v != "" {
		return
	}
	attrs[AttributeKey] = IDFor(event.GetSource(), event.GetAssetId(), event.GetEventType())
}
