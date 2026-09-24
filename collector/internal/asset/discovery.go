// Discovery ingest: observations become assets. This is inventory data
// modeling, NOT active scanning — no probes, no DNS, no ports, no packets.
// Accepted sources: telemetry sweeps, collector observations, manually
// supplied inventory, future scanner adapters. Every observation carries
// its source; derived records additionally carry derivation provenance.
package asset

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

// Observation is one asset sighting from a legitimate source.
type Observation struct {
	// Where this came from, e.g. "telemetry-sweep", "seed-inventory".
	Source string
	// Asset type of Raw.
	Type v1.AssetType
	// The raw identifier as observed (canonicalized, never stored raw).
	Raw string
	// When observed. Zero is rejected (no invented time).
	ObservedAt time.Time
	// Deployment context, e.g. "lab". Empty = unknown.
	Environment string
	// Source-supplied facts only.
	Attributes map[string]string
}

// Relationship kinds. v1 has exactly four, with disjoint semantics:
// CONTAINS is namespace ownership (domain CONTAINS url);
// COMMUNICATES_WITH is observed network traffic;
// EXPOSES is APPLICATION exposes URL; SERVED_BY is URL served_by SERVICE.
// Each kind preserves provenance and is idempotent.
const RelationContains = "CONTAINS"

// RelationCommunicatesWith links two endpoint assets (parent = source,
// child = destination) for observed network traffic with provenance.
const RelationCommunicatesWith = "COMMUNICATES_WITH"

// RelationExposes links APPLICATION → URL (application exposes route).
const RelationExposes = "EXPOSES"

// RelationServedBy links URL → SERVICE (URL served by service).
const RelationServedBy = "SERVED_BY"

// RelationRuns links HOST → SERVICE or HOST → CONTAINER.
const RelationRuns = "RUNS"

// RelationHostedOn links CONTAINER → HOST.
const RelationHostedOn = "HOSTED_ON"

// RelationPartOf links CONTAINER → APPLICATION.
const RelationPartOf = "PART_OF"

// RelationBelongsTo links CLOUD_RESOURCE → CLOUD_RESOURCE (account).
const RelationBelongsTo = "BELONGS_TO"

// RelationAccesses links IDENTITY → RESOURCE (observed data access).
const RelationAccesses = "ACCESSES"

// RelationMemberOf links IDENTITY → GROUP (source-declared membership).
const RelationMemberOf = "MEMBER_OF"

// RelationAssumes links IDENTITY → ROLE (source-declared role assumption).
const RelationAssumes = "ASSUMES"

// RelationAuthenticatesTo links IDENTITY → SERVICE (observed authentication).
const RelationAuthenticatesTo = "AUTHENTICATES_TO"

// CheckCanonical enforces the name-is-canonical invariant at repository
// boundaries: for strict types (domain, ip, url, host, service) the stored
// name must equal Canonicalize(type, name), otherwise the record bypassed
// normalization and identity guarantees would silently break. Opaque types
// (application, container, …) accept any non-empty name. Both backends call
// this on Create and Save.
func CheckCanonical(a *v1.Asset) error {
	if a == nil {
		return fmt.Errorf("asset: nil record")
	}
	switch a.GetType() {
	case v1.AssetType_ASSET_TYPE_DOMAIN,
		v1.AssetType_ASSET_TYPE_IP_ADDRESS,
		v1.AssetType_ASSET_TYPE_URL,
		v1.AssetType_ASSET_TYPE_HOST,
		v1.AssetType_ASSET_TYPE_SERVICE:
		canonical, err := Canonicalize(a.GetType(), a.GetName())
		if err != nil || canonical != a.GetName() {
			return fmt.Errorf("%w: name %q is not canonical for %v",
				ErrDiscovery, a.GetName(), a.GetType())
		}
	}
	return nil
}

// Relationship links two asset ids with provenance. Direction: parent
// contains/owns child (CONTAINS), or parent is the traffic source and
// child the destination (COMMUNICATES_WITH).
type Relationship struct {
	ParentID   string
	ChildID    string
	Kind       string
	Source     string
	ObservedAt time.Time
}

// Validate enforces archival rules: both endpoints, explicit known kind,
// source, and timestamp. Self-links are rejected (an asset never contains
// itself, nor communicates with itself as a relationship).
func (r Relationship) Validate() error {
	if r.ParentID == "" || r.ChildID == "" {
		return fmt.Errorf("asset: relationship endpoints required")
	}
	if r.ParentID == r.ChildID {
		return fmt.Errorf("asset: self-link refused")
	}
	switch r.Kind {
	case RelationContains, RelationCommunicatesWith, RelationExposes, RelationServedBy,
		RelationRuns, RelationHostedOn, RelationPartOf, RelationBelongsTo,
		RelationAccesses, RelationMemberOf, RelationAssumes, RelationAuthenticatesTo:
	default:
		return fmt.Errorf("asset: unknown relationship kind %q", r.Kind)
	}
	if r.Source == "" {
		return fmt.Errorf("asset: relationship source required")
	}
	if r.ObservedAt.IsZero() {
		return fmt.Errorf("asset: relationship timestamp zero")
	}
	return nil
}

// Normalize validates one observation into a DISCOVERED asset. The asset id
// is deterministic; name equals the canonical identifier (display
// customization is deferred, not faked); first_seen == last_seen ==
// observed_at; identifiers mirror the canonical value for joinability.
func Normalize(obs Observation) (*v1.Asset, error) {
	if strings.TrimSpace(obs.Source) == "" {
		return nil, fmt.Errorf("%w: source is required", ErrDiscovery)
	}
	if _, known := v1.AssetType_name[int32(obs.Type)]; !known ||
		obs.Type == v1.AssetType_ASSET_TYPE_UNSPECIFIED {
		return nil, fmt.Errorf("%w: explicit asset type required", ErrDiscovery)
	}
	canonical, err := Canonicalize(obs.Type, obs.Raw)
	if err != nil {
		return nil, err
	}
	if obs.ObservedAt.IsZero() {
		return nil, fmt.Errorf("%w: observed_at is zero", ErrDiscovery)
	}
	attrs := map[string]string{}
	for k, v := range obs.Attributes {
		attrs[k] = v
	}
	a := &v1.Asset{
		Id:          IDFor(obs.Type, canonical),
		Type:        obs.Type,
		Name:        canonical,
		Identifiers: []*v1.AssetIdentifier{{Type: IdentifierKind(obs.Type), Value: canonical}},
		Environment: strings.TrimSpace(obs.Environment),
		Status:      v1.AssetStatus_ASSET_STATUS_DISCOVERED,
		FirstSeen:   timestamppb.New(obs.ObservedAt),
		LastSeen:    timestamppb.New(obs.ObservedAt),
		Attributes:  attrs,
	}
	if a.GetFirstSeen() == nil {
		return nil, fmt.Errorf("%w: timestamp out of range", ErrDiscovery)
	}
	if err := contract.ValidateAsset(a); err != nil {
		return nil, err
	}
	return a, nil
}

// Decompose derives namespace relatives from an observed identifier using
// ONLY the bytes already in hand (no lookups, no inference):
//   - URL → its host as DOMAIN (or IP_ADDRESS when literal) + a SERVICE
//     for its port (explicit, else scheme default 80/443).
//
// Derived assets are DISCOVERED with explicit derivation provenance and the
// parent's environment; relationships are CONTAINS from parent to child.
// Non-decomposable types yield nothing (not an error).
func Decompose(a *v1.Asset, source string, observedAt time.Time) ([]*v1.Asset, []Relationship) {
	if a == nil || observedAt.IsZero() {
		return nil, nil
	}
	if a.GetType() != v1.AssetType_ASSET_TYPE_URL {
		return nil, nil
	}
	host, port := splitURLHostPort(a.GetName())
	if host == "" {
		return nil, nil
	}
	derivedAttrs := func(parent string) map[string]string {
		return map[string]string{
			"blueveil.derived_from": parent,
			"blueveil.derivation":   "url-host-decomposition",
		}
	}
	mkDerived := func(typ v1.AssetType, canonical string) *v1.Asset {
		derived, err := Normalize(Observation{
			Source:      source + " (derived)",
			Type:        typ,
			Raw:         canonical,
			ObservedAt:  observedAt,
			Environment: a.GetEnvironment(),
			Attributes:  derivedAttrs(a.GetId()),
		})
		if err != nil {
			return nil
		}
		return derived
	}

	var assets []*v1.Asset
	var rels []Relationship
	addRel := func(parent, child string) {
		rels = append(rels, Relationship{
			ParentID: parent, ChildID: child,
			Kind: RelationContains, Source: source, ObservedAt: observedAt,
		})
	}
	if ip, err := Canonicalize(v1.AssetType_ASSET_TYPE_IP_ADDRESS, host); err == nil {
		if dom := mkDerived(v1.AssetType_ASSET_TYPE_IP_ADDRESS, ip); dom != nil {
			assets = append(assets, dom)
			addRel(dom.GetId(), a.GetId())
		}
	} else if dom, err := Canonicalize(v1.AssetType_ASSET_TYPE_DOMAIN, host); err == nil {
		if d := mkDerived(v1.AssetType_ASSET_TYPE_DOMAIN, dom); d != nil {
			assets = append(assets, d)
			addRel(d.GetId(), a.GetId())
		}
	}
	if port != "" {
		svcRaw := host + ":" + port
		if svc, err := Canonicalize(v1.AssetType_ASSET_TYPE_SERVICE, svcRaw); err == nil {
			if s := mkDerived(v1.AssetType_ASSET_TYPE_SERVICE, svc); s != nil {
				assets = append(assets, s)
				addRel(a.GetId(), s.GetId())
			}
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].GetId() < assets[j].GetId() })
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].ParentID != rels[j].ParentID {
			return rels[i].ParentID < rels[j].ParentID
		}
		return rels[i].ChildID < rels[j].ChildID
	})
	return assets, rels
}

// splitURLHostPort recovers host and port from a canonical URL string.
// Canonical URLs always carry an explicit or scheme-default port decision
// made here from the scheme (no network involved).
func splitURLHostPort(canonical string) (host, port string) {
	rest, ok := splitScheme(canonical)
	if !ok {
		return "", ""
	}
	// Strip path/query: host[:port] is up to the first "/".
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	scheme := canonical[:strings.Index(canonical, "://")]
	if h, p, err := splitHostPort(rest); err == nil {
		return h, p
	}
	// No explicit port: scheme default (only reached for http/https, which
	// canonicalURL guarantees).
	if scheme == "http" {
		return rest, "80"
	}
	return rest, "443"
}

func splitScheme(s string) (string, bool) {
	i := strings.Index(s, "://")
	if i < 0 {
		return "", false
	}
	return s[i+3:], true
}

func splitHostPort(s string) (string, string, error) {
	// Last colon separates a numeric port; IPv6 literals arrive bracketed
	// from canonicalURL? No — canonical URLs keep bare IPv6 hosts, so handle
	// both: try bracketed first, then last-colon-if-numeric.
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("bad host")
		}
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("no port")
		}
		return s[1:end], rest[1:], nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("no port")
	}
	host, port := s[:i], s[i+1:]
	if strings.Contains(host, ":") {
		return "", "", fmt.Errorf("ambiguous bare IPv6 without port")
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", "", fmt.Errorf("bad port")
		}
	}
	return host, port, nil
}
