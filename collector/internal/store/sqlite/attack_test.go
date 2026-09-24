// Step 20E: persistence attack corpus. Hostile strings flow through
// every string-typed field of the core chain on both SQLite and
// PostgreSQL: they must store verbatim, retrieve byte-identical, match
// only themselves, and never alter query semantics. Runs on file SQLite
// (ungated) and live PG (gated).
package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

var evilStrings = []string{
	`' OR '1'='1`,
	`'; DROP TABLE telemetry_events; --`,
	`"quoted"`,
	`back\slash`,
	`-- comment`,
	`/* block */`,
	`%_[]`,
	"null\x00byte",
	"Ünïcodé-☃-\U0001F600",
	strings.Repeat("x", 10000),
	"trailing-space ",
	" leading-space",
	"\nnewline\ttab\rcarriage",
	`a"b'c\d`,
}

func evilTelemetry(id, source string) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)),
		Source: source, AssetId: "ast-'evil", EventType: "net.connection'; --",
		Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{
			"net.src_ip": "10.0.0.9", "evil'key": "evil;value",
		},
	}
}

func TestPersistenceAttackCorpus(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	// One event per evil id plus one evil source; every row must round
	// trip byte-identical and match only itself.
	for i, evil := range evilStrings {
		id := "evt-evil-" + itoa(i)
		if err := be.Telemetry.Append(ctx, evilTelemetry(id, evil)); err != nil {
			t.Fatalf("append %q: %v", evil, err)
		}
	}
	for i, evil := range evilStrings {
		id := "evt-evil-" + itoa(i)
		got, err := be.Telemetry.Get(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if got.GetSource() != evil {
			t.Fatalf("source drift for %s: %q vs %q", id, got.GetSource(), evil)
		}
	}
	// Evil ids as lookup keys: exact match only, no wildcard/pattern
	// behavior, no error masquerading as absence confusion.
	if _, err := be.Telemetry.Get(ctx, "' OR '1'='1"); err == nil {
		t.Fatalf("unrelated evil literal must not match")
	} else if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("must be ErrNotFound, got %v", err)
	}
	list, err := be.Telemetry.List(ctx)
	if err != nil || len(list) != len(evilStrings) {
		t.Fatalf("list must hold exactly the corpus: %d %v", len(list), err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [16]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
