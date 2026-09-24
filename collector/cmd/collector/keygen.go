// Step 16K: API key generation for private operators. The secret is
// read from stdin (piped or redirected) — never from argv, which leaks
// via ps. Output is a JSON config fragment holding only the id, role,
// and bcrypt hash: safe to paste into config.json.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"blueveil/collector/internal/auth"
)

// makeKeyEntry validates role/secret and returns the JSON fragment.
func makeKeyEntry(id, role, secret string) (string, error) {
	if strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("keygen: id is empty")
	}
	if !auth.ValidRole(role) {
		return "", fmt.Errorf("keygen: unknown role %q", role)
	}
	if secret == "" {
		return "", fmt.Errorf("keygen: empty secret refused")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("keygen: hash: %v", err)
	}
	out, err := json.MarshalIndent(map[string]string{
		"id": id, "role": role, "hash": string(h),
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func runKeygen(id, role string, stdin io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return fmt.Errorf("keygen: read secret: %v", err)
	}
	secret := strings.TrimSpace(string(raw))
	frag, err := makeKeyEntry(id, role, secret)
	if err != nil {
		return err
	}
	fmt.Println(frag)
	return nil
}
