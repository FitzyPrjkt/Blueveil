// HTTP boundary middleware: request IDs, then authentication, then
// authorization, then the route mux. The chain enforces the layering
//
//	HTTP → Authentication → Authorization → API → (domain, safety engine)
//
// AuthN/AuthZ only gate HTTP reachability. They never approve, execute,
// or bypass the response safety engine: no HTTP surface for approvals
// or execution exists, and none is added here.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	"blueveil/collector/internal/auth"
)

// requestIDKey carries the request id for logging downstream.
type requestIDKey struct{}

// identityKey carries the authenticated identity for handlers.
type identityKey struct{}

// identityCell is a request-scoped mutable carrier: the gate fills it
// downstream of the observability middleware, which reads it after the
// handler returns (context values alone cannot propagate back up).
type identityCell struct {
	id  auth.Identity
	set bool
}

type identityCellKey struct{}

// RequestIDOf returns the request id for logging, or "" when absent.
func RequestIDOf(r *http.Request) string {
	v, _ := r.Context().Value(requestIDKey{}).(string)
	return v
}

// IdentityOf returns the authenticated identity, or false when the gate
// is open (lab) or the path is public.
func IdentityOf(r *http.Request) (auth.Identity, bool) {
	if c, ok := r.Context().Value(identityCellKey{}).(*identityCell); ok && c != nil && c.set {
		return c.id, true
	}
	v, ok := r.Context().Value(identityKey{}).(auth.Identity)
	return v, ok
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-fallback"
	}
	return "req-" + hex.EncodeToString(b[:])
}

// withRequestID propagates a client X-Request-ID or mints one, always
// reflecting it back for cross-tier correlation.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		ctx = context.WithValue(ctx, identityCellKey{}, &identityCell{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Gate enforces authentication + authorization in front of the mux. A
// nil Authenticator means open (lab mode): no behavior change.
type Gate struct {
	auth   auth.Authenticator
	public map[string]bool
}

// UseAuth attaches the gate: every non-public API route requires a
// credential with a sufficient role. Public paths are exact matches
// (health plus explicitly configured extras).
func (s *Server) UseAuth(a auth.Authenticator, public []string) {
	g := &Gate{auth: a, public: map[string]bool{"/api/v1/healthz": true, "/api/v1/readyz": true}}
	for _, p := range public {
		if p != "" {
			g.public[p] = true
		}
	}
	s.gate = g
}

func (g *Gate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.public[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		role, protected := auth.CapabilityFor(r.Method, r.URL.Path)
		if !protected {
			next.ServeHTTP(w, r)
			return
		}
		id, err := g.auth.Authenticate(r)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrMissingCredentials):
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
			case errors.Is(err, auth.ErrExpiredCredential):
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "credential expired")
			default:
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			}
			return
		}
		if !auth.Sufficient(id.Role, role) {
			// 403 names the held role only: never the protected path's
			// contents, never the required role set.
			writeError(w, http.StatusForbidden, "FORBIDDEN", "role "+id.Role+" may not perform this operation")
			return
		}
		if c, ok := r.Context().Value(identityCellKey{}).(*identityCell); ok && c != nil {
			c.id, c.set = id, true
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}
