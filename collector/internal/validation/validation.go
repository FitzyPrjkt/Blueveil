// Package validation is the Validation Contract + Provider Boundary: Blueveil
// performs security validation only through a ValidationProvider behind the
// safety-gated response path, and only contract-valid results enter state.
//
// Three provider kinds exist behind one interface: deterministic native test
// providers, the optional Redveil adapter (external process boundary, never
// a library dependency), and future scanners. Unavailable providers answer
// NOT_TESTED — an honest fact, never a pass. Provider errors stay errors:
// nothing turns a crash into a clean result.
//
// Redveil isolation: this package imports nothing Redveil. The adapter
// invokes an allowlisted external CLI (loopback lab targets only, no shell,
// no user-controlled command strings) or reports unavailable. Core
// detection/incident/response code never names Redveil.
package validation

import "errors"

var (
	// ErrValidationBuild: inputs could not become a contract-valid request.
	ErrValidationBuild = errors.New("validation: request construction failure")
	// ErrProvider: the provider failed (crash, timeout, protocol error).
	// Never converted into NOT_TESTED or any verdict.
	ErrProvider = errors.New("validation: provider failure")
	// ErrProviderOutput: the provider returned contract-invalid output.
	ErrProviderOutput = errors.New("validation: invalid provider output")
	// ErrRegistry: registration failures (duplicates, invalid providers).
	ErrRegistry = errors.New("validation: registry failure")
)
