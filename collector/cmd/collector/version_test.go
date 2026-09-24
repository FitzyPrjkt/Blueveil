package main

import (
	"strings"
	"testing"
)

func TestVersionStringIdentifiesBinary(t *testing.T) {
	v := versionString()
	if !strings.HasPrefix(v, "blueveil ") || !strings.Contains(v, "go1.") {
		t.Fatalf("version must identify module and toolchain: %q", v)
	}
}
