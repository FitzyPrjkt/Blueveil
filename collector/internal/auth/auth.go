// Package auth is the provider-neutral authentication and
// authorization foundation for the API boundary. It answers "who is
// this" (Authenticator) and "what may they do" (roles + capability
// mapping). It never authorizes security actions: the response safety
// engine remains authoritative below this layer.
//
// The production mechanism is bearer API keys verified against stored
// password hashes (bcrypt): secrets are never persisted, never logged,
// and compared without leaking which key ids exist. Key sets are small
// (human-managed); every presented secret is compared against every
// verifier so failures are uniform.
package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Roles bound to credentials. READ covers every current read route;
// RESPOND covers asset-observation ingest; VALIDATE is reserved for
// validation-flow endpoints; ADMIN covers lifecycle administration.
// No role creates write APIs: the read-only surface stays read-only.
const (
	RoleRead     = "READ"
	RoleRespond  = "RESPOND"
	RoleValidate = "VALIDATE"
	RoleAdmin    = "ADMIN"
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool {
	switch r {
	case RoleRead, RoleRespond, RoleValidate, RoleAdmin:
		return true
	}
	return false
}

// roleRank orders roles for require-at-least checks: ADMIN implies
// everything below it.
func roleRank(r string) int {
	switch r {
	case RoleRead:
		return 1
	case RoleRespond:
		return 2
	case RoleValidate:
		return 3
	case RoleAdmin:
		return 4
	}
	return 0
}

// Sufficient reports whether the held role covers the required
// capability. Roles form one hierarchy (READ < RESPOND < VALIDATE <
// ADMIN): a higher role includes every lower capability, so an operator
// credential can always read what it may act on.
func Sufficient(held, required string) bool {
	return roleRank(held) >= roleRank(required) && roleRank(required) > 0
}

var (
	// ErrMissingCredentials: no credential presented.
	ErrMissingCredentials = errors.New("auth: missing credentials")
	// ErrInvalidCredentials: malformed, unknown, or mismatched credential.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	// ErrExpiredCredential: the credential was valid but expired.
	ErrExpiredCredential = errors.New("auth: credential expired")
	// ErrForbidden: authenticated identity lacks the required role.
	ErrForbidden = errors.New("auth: forbidden for this role")
)

// Identity is the authenticated caller: a key id plus its role. It
// carries no secret material.
type Identity struct {
	KeyID string
	Role  string
}

// Authenticator verifies one request. Implementations must return only
// the sentinel errors above (wrapping with %w is allowed for context
// that names no secret).
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// Key binds a credential id to a role and a password hash of the
// secret. ExpiresAt is RFC3339 or empty (no expiry).
type Key struct {
	ID        string
	Role      string
	Hash      string
	ExpiresAt time.Time
}

type keyEntry struct {
	id      string
	role    string
	hash    []byte
	expires time.Time
}

// APIKeyAuthenticator verifies Authorization: Bearer <secret> against a
// fixed key set. The set is validated at construction (fail fast); the
// secret is compared against every verifier so unknown secrets fail
// exactly like mismatched ones.
type APIKeyAuthenticator struct {
	keys []keyEntry
	now  func() time.Time
}

// NewAPIKeyAuthenticator builds the verifier. Empty sets, unknown
// roles, duplicate ids, and malformed hashes are construction errors —
// production startup fails before serving.
func NewAPIKeyAuthenticator(keys []Key, now func() time.Time) (*APIKeyAuthenticator, error) {
	if len(keys) == 0 {
		return nil, errors.New("auth: no API keys configured (no default production credential)")
	}
	if now == nil {
		return nil, errors.New("auth: clock is nil")
	}
	seen := map[string]bool{}
	entries := make([]keyEntry, 0, len(keys))
	for _, k := range keys {
		if strings.TrimSpace(k.ID) == "" {
			return nil, errors.New("auth: key id is empty")
		}
		if seen[k.ID] {
			return nil, errors.New("auth: duplicate key id " + k.ID)
		}
		seen[k.ID] = true
		if !ValidRole(k.Role) {
			return nil, errors.New("auth: key " + k.ID + " has unknown role")
		}
		if _, err := bcrypt.Cost([]byte(k.Hash)); err != nil {
			return nil, errors.New("auth: key " + k.ID + " hash is malformed")
		}
		entries = append(entries, keyEntry{id: k.ID, role: k.Role, hash: []byte(k.Hash), expires: k.ExpiresAt})
	}
	return &APIKeyAuthenticator{keys: entries, now: now}, nil
}

// bearerSecret extracts the presented secret. Only the standard
// Authorization: Bearer scheme is honored — identity is never inferred
// from arbitrary headers.
func bearerSecret(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", ErrMissingCredentials
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", ErrInvalidCredentials
	}
	secret := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if secret == "" {
		return "", ErrInvalidCredentials
	}
	return secret, nil
}

// Authenticate implements Authenticator.
func (a *APIKeyAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	secret, err := bearerSecret(r)
	if err != nil {
		return Identity{}, err
	}
	now := a.now()
	var hit *keyEntry
	for i := range a.keys {
		k := &a.keys[i]
		// bcrypt.CompareHashAndPassword is the constant-time comparison.
		// Every verifier is tried even after a match so success/failure
		// timing does not reveal which key (if any) matched.
		if bcrypt.CompareHashAndPassword(k.hash, []byte(secret)) == nil && hit == nil {
			hit = k
		}
	}
	if hit == nil {
		return Identity{}, ErrInvalidCredentials
	}
	if !hit.expires.IsZero() && !now.Before(hit.expires) {
		return Identity{}, ErrExpiredCredential
	}
	return Identity{KeyID: hit.id, Role: hit.role}, nil
}

// CapabilityFor maps an API operation to its required role. The second
// return reports whether the route is protected at all (public paths
// such as health are not). Unknown API paths default to protected READ
// (fail closed), never public.
func CapabilityFor(method, path string) (role string, protected bool) {
	// Health and readiness are observable without credentials (they
	// carry no protected data); everything else under /api/ is gated.
	if method == http.MethodGet && (path == "/api/v1/healthz" || path == "/api/v1/readyz") {
		return "", false
	}
	if method == http.MethodPost && path == "/api/v1/assets/observations" {
		return RoleRespond, true
	}
	if method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/assets/") &&
		strings.HasSuffix(path, "/lifecycle") {
		return RoleAdmin, true
	}
	if strings.HasPrefix(path, "/api/") {
		return RoleRead, true
	}
	return "", false
}
