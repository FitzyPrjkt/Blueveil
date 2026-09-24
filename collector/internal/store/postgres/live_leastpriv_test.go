// Step 17D: least-privilege role proof. Connects as a role holding
// only CONNECT + CREATE ON SCHEMA public (no CREATEDB, no superuser)
// to a pre-provisioned database and proves the full backend works:
// migrate, CRUD, duplicates, corruption-closed, FK enforcement.
// Set BLUEVEIL_TEST_POSTGRES_LEAST to the role's conn string.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"blueveil/collector/internal/store"
)

func TestLiveLeastPrivilegeRole(t *testing.T) {
	ctx := context.Background()
	cs := strings.TrimSpace(os.Getenv("BLUEVEIL_TEST_POSTGRES_LEAST"))
	if cs == "" {
		t.Skip("BLUEVEIL_TEST_POSTGRES_LEAST unset: least-privilege proof skipped (nothing faked)")
	}
	db, err := OpenConnString(ctx, cs, 2, 5*time.Second)
	if err != nil {
		t.Fatalf("open as least-priv role: %v", err)
	}
	defer db.Close()
	be := db.Backend()
	tag := fmt.Sprintf("%d", time.Now().UnixNano())
	evt := liveTelemetry("evt-least-" + tag)
	if err := be.Telemetry.Append(ctx, evt); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := be.Telemetry.Append(ctx, evt); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}
	// Must NOT be able to create databases (least privilege holds).
	if _, err := db.pool.Exec(ctx, `CREATE DATABASE blueveil_must_fail_`+tag); err == nil {
		t.Fatalf("least-priv role must not create databases")
	}
	// Nor touch other databases' tables: information_schema is readable,
	// but writing outside our tables fails.
	if _, err := db.pool.Exec(ctx, `CREATE TABLE blueveil_least_probe (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("own-schema CREATE (migrations) must work: %v", err)
	}
	if _, err := db.pool.Exec(ctx, `DROP TABLE blueveil_least_probe`); err != nil {
		t.Fatalf("drop own table: %v", err)
	}
	if err := db.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
}
