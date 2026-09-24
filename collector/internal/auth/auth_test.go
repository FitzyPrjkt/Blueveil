// Step 15D RED: provider-neutral authentication. Bearer API keys with
// bcrypt verifiers, expiry, and rotation; failures are bounded sentinels
// carrying no credential material.
package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func mustHash(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestAuthenticateValidKey(t *testing.T) {
	a, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: mustHash(t, "secret-1")},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer secret-1")
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("valid key must authenticate: %v", err)
	}
	if id.KeyID != "k1" || id.Role != RoleRead {
		t.Fatalf("identity drift: %+v", id)
	}
}

func TestAuthenticateFailuresAreBounded(t *testing.T) {
	a, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: mustHash(t, "secret-1")},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		header string
		want   error
	}{
		"missing header":   {"", ErrMissingCredentials},
		"wrong scheme":     {"Basic abc", ErrInvalidCredentials},
		"empty bearer":     {"Bearer ", ErrInvalidCredentials},
		"bearer no space":  {"Bearer", ErrInvalidCredentials},
		"unknown key id":   {"Bearer unknown-secret", ErrInvalidCredentials},
		"wrong secret":     {"Bearer secret-wrong", ErrInvalidCredentials},
		"no bearer prefix": {"secret-1", ErrInvalidCredentials},
	}
	for name, c := range cases {
		req, _ := http.NewRequest("GET", "/api/v1/assets", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		// Secrets match by verifier comparison; unknown secrets must
		// not authenticate and must not reveal which ids exist.
		if _, err := a.Authenticate(req); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
}

func TestExpiredKeyRejected(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	a, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: mustHash(t, "s"), ExpiresAt: now.Add(-time.Hour)},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer s")
	if _, err := a.Authenticate(req); !errors.Is(err, ErrExpiredCredential) {
		t.Fatalf("expired key must fail with ErrExpiredCredential, got %v", err)
	}
}

func TestRotationOldRevokedNewAccepted(t *testing.T) {
	oldAuth, err := NewAPIKeyAuthenticator([]Key{
		{ID: "old", Role: RoleRead, Hash: mustHash(t, "old-secret")},
		{ID: "new", Role: RoleRead, Hash: mustHash(t, "new-secret")},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(secret string) *http.Request {
		req, _ := http.NewRequest("GET", "/api/v1/assets", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return req
	}
	if _, err := oldAuth.Authenticate(mk("old-secret")); err != nil {
		t.Fatalf("old key valid during rotation: %v", err)
	}
	if _, err := oldAuth.Authenticate(mk("new-secret")); err != nil {
		t.Fatalf("new key valid during rotation: %v", err)
	}
	// Rotation completes: old id removed from configuration.
	newAuth, err := NewAPIKeyAuthenticator([]Key{
		{ID: "new", Role: RoleRead, Hash: mustHash(t, "new-secret")},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAuth.Authenticate(mk("old-secret")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("revoked key must fail, got %v", err)
	}
	if _, err := newAuth.Authenticate(mk("new-secret")); err != nil {
		t.Fatalf("retained key must authenticate: %v", err)
	}
}

func TestConstructionRejectsBadConfig(t *testing.T) {
	if _, err := NewAPIKeyAuthenticator(nil, time.Now); err == nil {
		t.Fatalf("empty key set must fail")
	}
	if _, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: "SUPERUSER", Hash: mustHash(t, "s")},
	}, time.Now); err == nil {
		t.Fatalf("unknown role must fail")
	}
	for _, bad := range []string{"read", "Read", " READ", "READ ", "", "ADMIN,READ"} {
		if _, err := NewAPIKeyAuthenticator([]Key{
			{ID: "k1", Role: bad, Hash: mustHash(t, "s")},
		}, time.Now); err == nil {
			t.Fatalf("role %q must fail (exact vocabulary, no normalization)", bad)
		}
	}
	if _, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: "not-a-hash"},
	}, time.Now); err == nil {
		t.Fatalf("malformed hash must fail fast")
	}
	if _, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: mustHash(t, "s")},
		{ID: "k1", Role: RoleAdmin, Hash: mustHash(t, "s2")},
	}, time.Now); err == nil {
		t.Fatalf("duplicate ids must fail")
	}
}

func TestAdversarialHeaders(t *testing.T) {
	a, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: mustHash(t, "secret-1")},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(headers ...string) *http.Request {
		req, _ := http.NewRequest("GET", "/api/v1/assets", nil)
		for i := 0; i < len(headers); i += 2 {
			req.Header.Add(headers[i], headers[i+1])
		}
		return req
	}
	cases := map[string]struct {
		req  *http.Request
		want error
	}{
		"duplicate headers second valid": {
			req:  mk("Authorization", "Bearer wrong", "Authorization", "Bearer secret-1"),
			want: ErrInvalidCredentials, // Go uses the first value; no smuggling
		},
		"leading whitespace": {req: mk("Authorization", "  Bearer secret-1"), want: ErrInvalidCredentials},
		"lowercase scheme":   {req: mk("Authorization", "bearer secret-1"), want: ErrInvalidCredentials},
		"extra inner spaces": {req: mk("Authorization", "Bearer  secret-1"), want: nil},
		"trailing space":     {req: mk("Authorization", "Bearer secret-1 "), want: nil},
		"tab separator":      {req: mk("Authorization", "Bearer\tsecret-1"), want: ErrInvalidCredentials},
		"null byte":          {req: mk("Authorization", "Bearer sec\x00ret-1"), want: ErrInvalidCredentials},
		"newline attempt":    {req: mk("Authorization", "Bearer sec\nret-1"), want: ErrInvalidCredentials},
		"unicode secret":     {req: mk("Authorization", "Bearer sécrèt-1"), want: ErrInvalidCredentials},
		"ten kb credential":  {req: mk("Authorization", "Bearer "+strings.Repeat("x", 10<<10)), want: ErrInvalidCredentials},
		"token scheme":       {req: mk("Authorization", "Token secret-1"), want: ErrInvalidCredentials},
		"empty value":        {req: mk("Authorization", ""), want: ErrMissingCredentials},
	}
	for name, c := range cases {
		_, err := a.Authenticate(c.req)
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: valid credential forms must authenticate: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
	// NOTE: "valid credential with wrong key ID" is N/A by design —
	// credentials carry no key id (secret-only match), so there is no
	// id field to mismatch or enumerate.
}

func TestConcurrentAuthentication(t *testing.T) {
	a, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: mustHash(t, "secret-1")},
		{ID: "k2", Role: RoleAdmin, Hash: mustHash(t, "secret-2")},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 32)
	for i := 0; i < 32; i++ {
		go func(i int) {
			secret := "secret-1"
			if i%2 == 1 {
				secret = "wrong"
			}
			req, _ := http.NewRequest("GET", "/api/v1/assets", nil)
			req.Header.Set("Authorization", "Bearer "+secret)
			_, err := a.Authenticate(req)
			if i%2 == 1 && !errors.Is(err, ErrInvalidCredentials) {
				done <- err
				return
			}
			if i%2 == 0 && err != nil {
				done <- err
				return
			}
			done <- nil
		}(i)
	}
	for i := 0; i < 32; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent auth: %v", err)
		}
	}
}

func TestErrorsCarryNoCredentialMaterial(t *testing.T) {
	a, err := NewAPIKeyAuthenticator([]Key{
		{ID: "k1", Role: RoleRead, Hash: mustHash(t, "top-secret-value")},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer top-secret-wrong")
	_, err = a.Authenticate(req)
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, secret := range []string{"top-secret-value", "top-secret-wrong"} {
		if contains(err.Error(), secret) {
			t.Fatalf("auth error leaks credential: %v", err)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
