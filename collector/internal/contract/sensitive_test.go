// Step 14F: redaction regression tests. Every key in the sensitive
// inventory must be dropped by the canonical matcher, while harmless
// operational metadata (identity, ids, types, statuses, severities,
// timestamps) must survive — no over-redaction.
package contract

import "testing"

func TestSensitiveFieldInventory(t *testing.T) {
	for _, k := range []string{
		"password", "PASSWORD", "user_password", "auth.password",
		"passwd", "token", "access_token", "refresh_token", "api_token",
		"api_key", "apikey", "x-api-key",
		"secret", "client_secret", "secret-token-should-be-redacted",
		"private_key", "privatekey", "credential", "credentials",
		"cookie", "session", "session_id", "mfa", "mfa_code",
		"authorization", "Authorization", "access_key", "aws_access_key",
		"x-api-key", "X-Private-Key", "access-key",
	} {
		if !SensitiveField(k) {
			t.Errorf("key %q must be sensitive", k)
		}
	}
}

func TestSensitiveFieldNoOverRedaction(t *testing.T) {
	for _, k := range []string{
		"asset_id", "event_id", "finding_id", "correlation_id",
		"http.method", "http.host", "http.path", "http.status_code",
		"event_type", "status", "severity", "observed_at",
		"rule_id", "control_id", "principal", "resource", "action",
		"source", "target", "owner", "environment",
	} {
		if SensitiveField(k) {
			t.Errorf("harmless metadata key %q must survive", k)
		}
	}
}
