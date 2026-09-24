package config

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func testHash(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}
