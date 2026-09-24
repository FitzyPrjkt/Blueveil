// Step 20E: connection-string quoting. Values with spaces, quotes, or
// backslashes must round-trip through libpq parsing identically —
// never re-parse into different keywords.
package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestQuoteConnValueRoundTrip(t *testing.T) {
	for _, v := range []string{
		"simple", "with space", "with'quote", `with\backslash`,
		"p@ss:w0rd/with.dots-and_dashes", "dbname=x host=y", "",
		"Ünïcodé", "tab\there", "semi;colon", "hash#tag",
	} {
		q := QuoteConnValue(v)
		cfg, err := pgx.ParseConfig("user=test password=" + q + " dbname=db host=h")
		if err != nil {
			t.Fatalf("quoted %q must parse: %v", v, err)
		}
		if cfg.Password != v {
			t.Fatalf("round trip drift: %q -> %q -> %q", v, q, cfg.Password)
		}
	}
	// Plain values stay bare (readable connection strings, stable tests).
	for _, v := range []string{"blueveil", "127.0.0.1", "/tmp/pgtest"} {
		if got := QuoteConnValue(v); got != v {
			t.Fatalf("safe value %q must stay bare, got %q", v, got)
		}
	}
}

func TestEvilPasswordConnectsRightDBOrFails(t *testing.T) {
	// A password carrying conninfo metacharacters must not redirect the
	// connection: this instance trusts local peers (password ignored by
	// the server), so a successful open MUST land on the intended
	// database — proving no keyword injection. Requires the live test
	// instance; skipped otherwise (nothing faked).
	if os.Getenv("BLUEVEIL_TEST_POSTGRES") == "" {
		t.Skip("BLUEVEIL_TEST_POSTGRES unset: live connstring test skipped")
	}
	ctx := context.Background()
	db, err := Open(ctx, Config{
		Host: "/tmp/pgtest", Port: 55433, User: "blueveil_test",
		Password: "p@ss word'with\\tricks dbname=other", DBName: "blueveil_test",
		SSLMode: "disable",
	})
	if err != nil {
		t.Fatalf("evil password must not break parsing: %v", err)
	}
	defer db.Close()
	var current string
	if err := db.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current != "blueveil_test" {
		t.Fatalf("connected to %q, not the intended database: keyword injection", current)
	}
}
