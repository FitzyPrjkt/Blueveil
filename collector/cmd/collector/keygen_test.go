package main

import (
	"encoding/json"
	"strings"
	"testing"

	"blueveil/collector/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

func TestMakeKeyEntryRoundTrip(t *testing.T) {
	frag, err := makeKeyEntry("ingest-01", auth.RoleRespond, "operator-secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(frag, "operator-secret") {
		t.Fatalf("fragment leaks secret: %s", frag)
	}
	var decoded struct {
		ID   string `json:"id"`
		Role string `json:"role"`
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal([]byte(frag), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != "ingest-01" || decoded.Role != auth.RoleRespond {
		t.Fatalf("fragment identity drift: %+v", decoded)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(decoded.Hash), []byte("operator-secret")); err != nil {
		t.Fatalf("hash must verify: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(decoded.Hash), []byte("wrong")); err == nil {
		t.Fatalf("wrong secret must not verify")
	}
}

func TestMakeKeyEntryRejects(t *testing.T) {
	if _, err := makeKeyEntry("", auth.RoleRead, "s"); err == nil {
		t.Fatalf("empty id must fail")
	}
	if _, err := makeKeyEntry("k", "SUPERUSER", "s"); err == nil {
		t.Fatalf("unknown role must fail")
	}
	if _, err := makeKeyEntry("k", auth.RoleRead, ""); err == nil {
		t.Fatalf("empty secret must fail")
	}
}
