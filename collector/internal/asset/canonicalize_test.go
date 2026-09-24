package asset

import (
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestCanonicalizeDeterministic(t *testing.T) {
	cases := []struct {
		typ  v1.AssetType
		raw  string
		want string
	}{
		{v1.AssetType_ASSET_TYPE_DOMAIN, "Example.COM.", "example.com"},
		{v1.AssetType_ASSET_TYPE_DOMAIN, "  sub.EXAMPLE.com ", "sub.example.com"},
		{v1.AssetType_ASSET_TYPE_IP_ADDRESS, "127.0.0.1", "127.0.0.1"},
		{v1.AssetType_ASSET_TYPE_IP_ADDRESS, "::ffff:127.0.0.1", "::ffff:127.0.0.1"},
		{v1.AssetType_ASSET_TYPE_URL, "https://example.com", "https://example.com/"},
		{v1.AssetType_ASSET_TYPE_URL, "https://example.com/", "https://example.com/"},
		{v1.AssetType_ASSET_TYPE_URL, "HTTPS://Example.COM:443/a?b=1#frag", "https://example.com/a?b=1"},
		{v1.AssetType_ASSET_TYPE_URL, "http://example.com:8080/x", "http://example.com:8080/x"},
		{v1.AssetType_ASSET_TYPE_HOST, "Web01", "web01"},
		{v1.AssetType_ASSET_TYPE_HOST, "localhost", "localhost"},
		{v1.AssetType_ASSET_TYPE_SERVICE, "Web01:443", "web01:443"},
		{v1.AssetType_ASSET_TYPE_SERVICE, "[::1]:5432", "[::1]:5432"},
	}
	for _, c := range cases {
		got, err := Canonicalize(c.typ, c.raw)
		if err != nil || got != c.want {
			t.Errorf("Canonicalize(%v,%q) = %q,%v; want %q", c.typ, c.raw, got, err, c.want)
		}
		// Idempotency: canonicalizing the canonical form is a fixed point.
		again, err := Canonicalize(c.typ, got)
		if err != nil || again != got {
			t.Errorf("not idempotent: %q → %q (%v)", got, again, err)
		}
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	cases := []struct {
		typ v1.AssetType
		raw string
	}{
		{v1.AssetType_ASSET_TYPE_DOMAIN, ""},
		{v1.AssetType_ASSET_TYPE_DOMAIN, "-bad-.com"},
		{v1.AssetType_ASSET_TYPE_DOMAIN, "has space.com"},
		{v1.AssetType_ASSET_TYPE_IP_ADDRESS, "999.1.1.1"},
		{v1.AssetType_ASSET_TYPE_IP_ADDRESS, "not-an-ip"},
		{v1.AssetType_ASSET_TYPE_URL, "not a url"},
		{v1.AssetType_ASSET_TYPE_URL, "ftp://example.com/x"},
		{v1.AssetType_ASSET_TYPE_URL, "https://user:pass@example.com/"},
		{v1.AssetType_ASSET_TYPE_HOST, ""},
		{v1.AssetType_ASSET_TYPE_HOST, "has space"},
		{v1.AssetType_ASSET_TYPE_SERVICE, "noport"},
		{v1.AssetType_ASSET_TYPE_SERVICE, "host:99999"},
		{v1.AssetType_ASSET_TYPE_OTHER, "   "},
		{v1.AssetType_ASSET_TYPE_UNSPECIFIED, "x"},
		{v1.AssetType(99), "x"},
	}
	for _, c := range cases {
		if got, err := Canonicalize(c.typ, c.raw); err == nil {
			t.Errorf("Canonicalize(%v,%q) = %q, want error", c.typ, c.raw, got)
		}
	}
}

func TestIdentitySeparatesTypes(t *testing.T) {
	// Same spelling, different types → different assets. No merging.
	hostID := IDFor(v1.AssetType_ASSET_TYPE_HOST, "example.com")
	domainID := IDFor(v1.AssetType_ASSET_TYPE_DOMAIN, "example.com")
	if hostID == domainID {
		t.Fatal("host and domain must not share identity")
	}
	a, _ := Canonicalize(v1.AssetType_ASSET_TYPE_URL, "https://example.com")
	b, _ := Canonicalize(v1.AssetType_ASSET_TYPE_URL, "https://example.com/")
	if IDFor(v1.AssetType_ASSET_TYPE_URL, a) != IDFor(v1.AssetType_ASSET_TYPE_URL, b) {
		t.Fatal("trailing-slash URLs must resolve to one asset")
	}
	if len(hostID) == 0 || hostID[:4] != "ast-" {
		t.Fatalf("id shape: %q", hostID)
	}
}
