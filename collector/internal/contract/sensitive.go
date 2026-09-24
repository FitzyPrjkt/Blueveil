// Sensitive field redaction (14F): the single canonical fragment list.
// Six layers previously carried divergent substring lists (pipeline
// sinks, API filters, GRC metadata); a key dropped in one layer leaked
// through another. Every redaction surface must use SensitiveField so a
// secret-bearing attribute key is dropped everywhere before persistence
// or exposure. Matching is case-insensitive substring: "access_token"
// matches via "token" AND explicitly, so future renames stay covered.
package contract

import "strings"

// SensitiveFragments is the canonical lower-case substring set. Keep it
// data-only (no behavior): layers combine it with their own extras.
var SensitiveFragments = []string{
	"password", "passwd", "token", "access_token", "refresh_token",
	"secret", "credential", "cookie", "authorization", "session",
	"mfa", "api_key", "api-key", "apikey",
	"private_key", "private-key", "privatekey",
	"access_key", "access-key",
}

// SensitiveField reports whether an attribute/metadata key must never be
// persisted or exposed.
func SensitiveField(key string) bool {
	low := strings.ToLower(key)
	for _, frag := range SensitiveFragments {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}
