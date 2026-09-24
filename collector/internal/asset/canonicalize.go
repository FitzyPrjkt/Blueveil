// Package asset is the Asset & Attack Surface domain: deterministic asset
// identity, lifecycle, discovery ingest, and evidence-backed relationships.
//
// Identity rule: asset ID = "ast-" + 16 hex of SHA-256 over
// "<TYPE-NAME>\x1f<canonical>". The same logical asset observed any number
// of times resolves to the same ID; different types never merge even when
// their spellings coincide (host "example.com" ≠ domain "example.com").
//
// Canonicalization rules per type (documented, tested, no over-merging):
//   - DOMAIN: trim space → lowercase → strip one trailing dot → DNS label
//     validation (1–63 chars each, alnum/hyphen, total ≤253). No punycode
//     conversion (documented limitation); case is the only folding.
//   - IP_ADDRESS: trim space → netip.ParseAddr → canonical compressed form.
//     Zones preserved as parsed. Anything unparsable is rejected, never
//     guessed.
//   - URL: trim space → url.Parse → http/https only; scheme+host lowercased;
//     default ports stripped (:80/:443); fragment dropped (never sent to a
//     server); empty path becomes "/". Query is KEPT (dropping it would merge
//     distinct resources); userinfo is rejected (credentials are not asset
//     identity).
//   - HOST: trim space → lowercase; must be non-empty without spaces or
//     slashes. Single-label names ("web01", "localhost") are valid hosts —
//     they are NOT promoted to domains.
//   - SERVICE: "host:port" via net.SplitHostPort (bracketed IPv6 accepted);
//     host part lowercased, port must be numeric 1–65535. Canonical form is
//     "host:port" (IPv6 without brackets when unambiguous? No — preserve
//     brackets for IPv6 literals to stay parseable).
//   - APPLICATION, CONTAINER, CLOUD_RESOURCE, USER_DEVICE, NETWORK, OTHER:
//     trim space + non-empty only. No semantic normalization is defensible
//     for these yet; identity is the exact string (documented limitation).
package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	v1 "blueveil/collector/internal/contract/v1"
)

var (
	// ErrCanonicalize: the raw identifier cannot be an asset of this type.
	ErrCanonicalize = errors.New("asset: cannot canonicalize identifier")
	// ErrLifecycle: illegal lifecycle transition.
	ErrLifecycle = errors.New("asset: illegal lifecycle transition")
	// ErrDiscovery: observation cannot become an asset.
	ErrDiscovery = errors.New("asset: invalid observation")
)

// Canonicalize maps (type, raw) to the canonical identifier string.
func Canonicalize(typ v1.AssetType, raw string) (string, error) {
	switch typ {
	case v1.AssetType_ASSET_TYPE_DOMAIN:
		return canonicalDomain(raw)
	case v1.AssetType_ASSET_TYPE_IP_ADDRESS:
		return canonicalIP(raw)
	case v1.AssetType_ASSET_TYPE_URL:
		return canonicalURL(raw)
	case v1.AssetType_ASSET_TYPE_HOST:
		return canonicalHost(raw)
	case v1.AssetType_ASSET_TYPE_SERVICE:
		return canonicalService(raw)
	case v1.AssetType_ASSET_TYPE_APPLICATION,
		v1.AssetType_ASSET_TYPE_CONTAINER,
		v1.AssetType_ASSET_TYPE_CLOUD_RESOURCE,
		v1.AssetType_ASSET_TYPE_USER_DEVICE,
		v1.AssetType_ASSET_TYPE_NETWORK,
		v1.AssetType_ASSET_TYPE_OTHER:
		return canonicalOpaque(raw)
	default:
		return "", fmt.Errorf("%w: unknown asset type %v", ErrCanonicalize, int32(typ))
	}
}

// IDFor deterministically identifies (type, canonical). Callers must pass
// Canonicalize output, not raw input.
func IDFor(typ v1.AssetType, canonical string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x1f%s", int32(typ), canonical)))
	return "ast-" + hex.EncodeToString(sum[:])[:16]
}

// IdentifierKind is the AssetIdentifier.type string for a canonical value.
func IdentifierKind(typ v1.AssetType) string {
	switch typ {
	case v1.AssetType_ASSET_TYPE_DOMAIN:
		return "domain"
	case v1.AssetType_ASSET_TYPE_IP_ADDRESS:
		return "ip"
	case v1.AssetType_ASSET_TYPE_URL:
		return "url"
	case v1.AssetType_ASSET_TYPE_HOST:
		return "host"
	case v1.AssetType_ASSET_TYPE_SERVICE:
		return "service"
	case v1.AssetType_ASSET_TYPE_APPLICATION:
		return "application"
	case v1.AssetType_ASSET_TYPE_CONTAINER:
		return "container"
	case v1.AssetType_ASSET_TYPE_CLOUD_RESOURCE:
		return "cloud-resource"
	case v1.AssetType_ASSET_TYPE_USER_DEVICE:
		return "user-device"
	case v1.AssetType_ASSET_TYPE_NETWORK:
		return "network"
	default:
		return "other"
	}
}

func canonicalDomain(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", fmt.Errorf("%w: bad domain length %q", ErrCanonicalize, raw)
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("%w: bad domain label in %q", ErrCanonicalize, raw)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("%w: bad character in %q", ErrCanonicalize, raw)
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%w: bad hyphenation in %q", ErrCanonicalize, raw)
		}
	}
	return s, nil
}

func canonicalIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("%w: unparsable IP %q", ErrCanonicalize, raw)
	}
	return addr.String(), nil
}

func canonicalURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: unparsable URL %q", ErrCanonicalize, raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: userinfo is not asset identity", ErrCanonicalize)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%w: unsupported URL scheme %q", ErrCanonicalize, raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%w: empty URL host %q", ErrCanonicalize, raw)
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		if _, err := strconv.Atoi(port); err != nil {
			return "", fmt.Errorf("%w: bad URL port %q", ErrCanonicalize, raw)
		}
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, nil
}

func canonicalHost(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", fmt.Errorf("%w: empty hostname", ErrCanonicalize)
	}
	if strings.ContainsAny(s, " \t/") {
		return "", fmt.Errorf("%w: bad hostname %q", ErrCanonicalize, raw)
	}
	return s, nil
}

func canonicalService(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("%w: want host:port, got %q", ErrCanonicalize, raw)
	}
	host = strings.ToLower(host)
	if host == "" {
		return "", fmt.Errorf("%w: empty service host %q", ErrCanonicalize, raw)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%w: bad service port %q", ErrCanonicalize, raw)
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, n), nil
}

func canonicalOpaque(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: empty identifier", ErrCanonicalize)
	}
	return s, nil
}
