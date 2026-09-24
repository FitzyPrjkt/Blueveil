// Explicit dependency edges, SBOM metadata records, and declarative
// supply-chain policy. Edges originate from explicit metadata only —
// shared names never imply a dependency. Policies are data, never code:
// no shell, no installation, no upgrades, no registry writes.
package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DependencyKind bounds edge semantics.
type DependencyKind string

const (
	DependencyDependsOn   DependencyKind = "DEPENDS_ON"
	DependencyContains    DependencyKind = "CONTAINS"
	DependencyBuiltFrom   DependencyKind = "BUILT_FROM"
	DependencyDerivedFrom DependencyKind = "DERIVED_FROM"
)

// Dependency is one explicit reliance edge between two identified
// endpoints (assets, components, or repositories — each side named by
// its own stable id).
type Dependency struct {
	ParentID   string
	ParentKind string
	ChildID    string
	Kind       DependencyKind
	Source     string
	ObservedAt time.Time
}

// Validate enforces explicit edges.
func (d Dependency) Validate() error {
	if strings.TrimSpace(d.ParentID) == "" {
		return fmt.Errorf("supplychain: dependency parent required")
	}
	if strings.TrimSpace(d.ChildID) == "" {
		return fmt.Errorf("supplychain: dependency child required")
	}
	if d.ParentID == d.ChildID {
		return fmt.Errorf("supplychain: dependency self-link refused")
	}
	switch d.Kind {
	case DependencyDependsOn, DependencyContains, DependencyBuiltFrom,
		DependencyDerivedFrom:
	default:
		return fmt.Errorf("supplychain: dependency kind %q not in bounded vocabulary", d.Kind)
	}
	if strings.TrimSpace(d.Source) == "" {
		return fmt.Errorf("supplychain: dependency source required")
	}
	if d.ObservedAt.IsZero() {
		return fmt.Errorf("supplychain: dependency observed timestamp required")
	}
	return nil
}

// SBOMFormat bounds supported SBOM metadata formats.
type SBOMFormat string

const (
	SBOMSPDX      SBOMFormat = "SPDX"
	SBOMCycloneDX SBOMFormat = "CycloneDX"
	SBOMUnknown   SBOMFormat = "UNKNOWN"
)

// SBOM is one metadata record about a bill of materials. It describes a
// document that was observed or declared — Blueveil never downloads,
// parses arbitrary external SBOMs, or syncs registries for it.
type SBOM struct {
	Format        SBOMFormat
	FormatVersion string
	ComponentIDs  []string
	GeneratedAt   time.Time
	Source        string
	Digest        string
}

// ID deterministically identifies the SBOM over format + sorted refs.
func (s SBOM) ID() string {
	ids := append([]string(nil), s.ComponentIDs...)
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(append([]string{
		"blueveil-supply-sbom-v1", string(s.Format), s.FormatVersion,
	}, ids...), "\x1f")))
	return "sbom-" + hex.EncodeToString(sum[:])[:16]
}

// Validate enforces explicit SBOM metadata.
func (s SBOM) Validate() error {
	switch s.Format {
	case SBOMSPDX, SBOMCycloneDX, SBOMUnknown:
	default:
		return fmt.Errorf("supplychain: sbom format %q not in bounded vocabulary", s.Format)
	}
	if len(s.ComponentIDs) == 0 {
		return fmt.Errorf("supplychain: sbom needs at least one component reference")
	}
	for _, id := range s.ComponentIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("supplychain: sbom component reference empty")
		}
	}
	if s.GeneratedAt.IsZero() {
		return fmt.Errorf("supplychain: sbom generated timestamp required")
	}
	if strings.TrimSpace(s.Source) == "" {
		return fmt.Errorf("supplychain: sbom source required")
	}
	return nil
}

// SupplyPolicy is one declarative supply-chain policy. Every dimension is
// optional; an empty policy constrains nothing. Minimum versions compare
// dot-separated numeric releases; anything else is unevaluable.
type SupplyPolicy struct {
	ID                string
	Name              string
	Source            string
	AllowedEcosystems []string
	AllowedLicenses   []string
	AllowedProvenance []Provenance
	RequireDigest     bool
	MinVersions       map[string]string
	Prohibited        []string
	RequireSBOM       bool
	ApprovedRepos     []string
}

// Validate enforces explicit policy identity. Constraint lists may be
// empty (no constraint); prohibited entries must be non-empty strings.
func (p SupplyPolicy) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("supplychain: policy id required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("supplychain: policy name required")
	}
	if strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("supplychain: policy source required")
	}
	for _, s := range p.Prohibited {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("supplychain: prohibited entry empty")
		}
	}
	return nil
}

// PolicyVerdict bounds evaluation outcomes. UNKNOWN means the policy
// could not be evaluated (e.g. unparsable version) — never a violation.
type PolicyVerdict string

const (
	PolicyOK        PolicyVerdict = "OK"
	PolicyViolation PolicyVerdict = "VIOLATION"
	PolicyUnknown   PolicyVerdict = "UNKNOWN"
)

// PolicyResult is one deterministic evaluation with basis.
type PolicyResult struct {
	PolicyID    string
	ComponentID string
	Verdict     PolicyVerdict
	Reasons     []string
}

// compareVersions compares dot-separated numeric releases. It reports
// ok=false for anything non-numeric so callers treat the outcome as
// unevaluable rather than guessing.
func compareVersions(have, want string) (cmp int, ok bool) {
	parse := func(s string) ([]int, bool) {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, false
		}
		parts := strings.Split(s, ".")
		out := make([]int, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return nil, false
			}
			out = append(out, n)
		}
		return out, true
	}
	h, okH := parse(have)
	w, okW := parse(want)
	if !okH || !okW {
		return 0, false
	}
	for i := 0; i < len(h) && i < len(w); i++ {
		if h[i] != w[i] {
			if h[i] < w[i] {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case len(h) < len(w):
		return -1, true
	case len(h) > len(w):
		return 1, true
	default:
		return 0, true
	}
}

// EvaluatePolicy checks one component against one policy, collecting
// every violated dimension as basis. Only explicit mismatches violate;
// unevaluable dimensions yield UNKNOWN.
func EvaluatePolicy(c Component, p SupplyPolicy) PolicyResult {
	res := PolicyResult{PolicyID: p.ID, ComponentID: c.ID(), Verdict: PolicyOK}
	violates := func(reason string) {
		res.Verdict = PolicyViolation
		res.Reasons = append(res.Reasons, reason)
	}
	unknown := func(reason string) {
		if res.Verdict == PolicyOK {
			res.Verdict = PolicyUnknown
		}
		res.Reasons = append(res.Reasons, reason)
	}
	if len(p.AllowedEcosystems) > 0 {
		ok := false
		for _, e := range p.AllowedEcosystems {
			if strings.EqualFold(strings.TrimSpace(e), c.Ecosystem) {
				ok = true
				break
			}
		}
		if !ok {
			violates("ecosystem " + c.Ecosystem + " not allowed")
		}
	}
	for _, denied := range p.Prohibited {
		denied = strings.TrimSpace(denied)
		if denied == "" {
			continue
		}
		if strings.EqualFold(denied, c.Ecosystem+"/"+c.Name) || strings.EqualFold(denied, c.ID()) {
			violates("component " + denied + " prohibited")
		}
	}
	if p.RequireDigest && strings.TrimSpace(c.Digest) == "" {
		violates("digest required but absent")
	}
	if min, ok := p.MinVersions[strings.ToLower(c.Ecosystem)]; ok {
		if strings.TrimSpace(c.Version) == "" {
			unknown("no version to compare against minimum " + min)
		} else if cmp, ok := compareVersions(c.Version, min); !ok {
			unknown("version " + c.Version + " not comparable")
		} else if cmp < 0 {
			violates("version " + c.Version + " below minimum " + min)
		}
	}
	if len(p.AllowedLicenses) > 0 {
		if strings.TrimSpace(c.License) == "" {
			unknown("no declared license to check")
		} else {
			ok := false
			for _, l := range p.AllowedLicenses {
				if strings.EqualFold(strings.TrimSpace(l), c.License) {
					ok = true
					break
				}
			}
			if !ok {
				violates("license " + c.License + " not allowed")
			}
		}
	}
	if len(p.AllowedProvenance) > 0 {
		ok := false
		for _, pr := range p.AllowedProvenance {
			if pr == c.Provenance {
				ok = true
				break
			}
		}
		if !ok {
			violates("provenance " + string(c.Provenance) + " not allowed")
		}
	}
	sort.Strings(res.Reasons)
	return res
}
