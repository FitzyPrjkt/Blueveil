// Versioned schema: migrations v1–v5 apply in order inside one
// transaction; the version gate rejects anything this code did not
// create. CurrentSchemaVersion is the only version spoken; the mechanism
// (not just the tables) is what's tested.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type migration struct {
	version int
	name    string
	ddl     []string
}

var migrations = []migration{
	{
		version: 1,
		name:    "v1-initial",
		ddl: []string{
			`CREATE TABLE schema_version (version INTEGER PRIMARY KEY)`,
			`CREATE TABLE telemetry_events (
				id TEXT PRIMARY KEY,
				occurred_at TEXT NOT NULL,
				source TEXT NOT NULL,
				asset_id TEXT NOT NULL,
				identity_id TEXT,
				event_type TEXT NOT NULL,
				severity INTEGER NOT NULL,
				attributes TEXT NOT NULL,
				raw TEXT NOT NULL
			)`,
			`CREATE TABLE detections (
				id TEXT PRIMARY KEY,
				rule_id TEXT NOT NULL,
				rule_name TEXT NOT NULL,
				event_ids TEXT NOT NULL,
				detected_at TEXT NOT NULL,
				severity INTEGER NOT NULL,
				confidence REAL NOT NULL,
				title TEXT NOT NULL,
				description TEXT,
				attributes TEXT NOT NULL
			)`,
			`CREATE TABLE alerts (
				id TEXT PRIMARY KEY,
				detection_ids TEXT NOT NULL,
				status INTEGER NOT NULL,
				severity INTEGER NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				title TEXT NOT NULL
			)`,
			`CREATE TABLE incidents (
				id TEXT PRIMARY KEY,
				alert_ids TEXT NOT NULL,
				status INTEGER NOT NULL,
				severity INTEGER NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				title TEXT NOT NULL,
				summary TEXT
			)`,
			`CREATE TABLE evidence (
				id TEXT PRIMARY KEY,
				incident_id TEXT NOT NULL REFERENCES incidents(id),
				type INTEGER NOT NULL,
				collected_at TEXT NOT NULL,
				source TEXT NOT NULL,
				media_type TEXT NOT NULL,
				sha256 TEXT,
				content TEXT NOT NULL
			)`,
			`CREATE INDEX idx_evidence_incident ON evidence(incident_id)`,
			`CREATE TABLE response_recommendations (
				id TEXT PRIMARY KEY,
				incident_id TEXT NOT NULL,
				operation INTEGER NOT NULL,
				target TEXT NOT NULL,
				risk INTEGER NOT NULL,
				reason TEXT NOT NULL,
				status INTEGER NOT NULL,
				recommended_at TEXT NOT NULL,
				recommended_by TEXT NOT NULL,
				approval_required INTEGER NOT NULL
			)`,
			`CREATE TABLE response_approvals (
				id TEXT PRIMARY KEY,
				recommendation_id TEXT NOT NULL REFERENCES response_recommendations(id),
				operation INTEGER NOT NULL,
				target TEXT NOT NULL,
				risk INTEGER NOT NULL,
				approver TEXT NOT NULL,
				approved_at TEXT NOT NULL,
				expires_at TEXT,
				reason TEXT NOT NULL
			)`,
			`CREATE TABLE response_executions (
				id TEXT PRIMARY KEY,
				recommendation_id TEXT NOT NULL REFERENCES response_recommendations(id),
				approval_id TEXT,
				operation INTEGER NOT NULL,
				target TEXT NOT NULL,
				started_at TEXT NOT NULL,
				finished_at TEXT NOT NULL,
				success INTEGER NOT NULL,
				detail TEXT NOT NULL
			)`,
			`CREATE TABLE response_verifications (
				id TEXT PRIMARY KEY,
				execution_id TEXT NOT NULL REFERENCES response_executions(id),
				outcome INTEGER NOT NULL,
				verified_at TEXT NOT NULL,
				detail TEXT NOT NULL
			)`,
			`CREATE TABLE validation_requests (
				id TEXT PRIMARY KEY,
				control_id TEXT NOT NULL,
				target TEXT NOT NULL,
				context TEXT NOT NULL,
				requested_at TEXT NOT NULL
			)`,
			`CREATE TABLE validation_results (
				id TEXT PRIMARY KEY,
				request_id TEXT NOT NULL REFERENCES validation_requests(id),
				control_id TEXT NOT NULL,
				provider TEXT NOT NULL,
				provider_version TEXT,
				contract_version TEXT NOT NULL,
				verdict INTEGER NOT NULL,
				validated_at TEXT NOT NULL,
				evidence_ids TEXT NOT NULL,
				note TEXT
			)`,
			`CREATE TABLE audit_entries (
				id TEXT PRIMARY KEY,
				decided_at TEXT NOT NULL,
				actor TEXT NOT NULL,
				operation INTEGER NOT NULL,
				risk INTEGER NOT NULL,
				decision TEXT NOT NULL,
				reason TEXT NOT NULL,
				result TEXT NOT NULL,
				response_id TEXT NOT NULL,
				phase TEXT NOT NULL
			)`,
		},
	},
	{
		// Step 13A: asset inventory. name carries the canonical identifier
		// (see asset.CheckCanonical); the composite unique key enforces
		// deterministic identity at the storage layer too.
		version: 2,
		name:    "v2-assets",
		ddl: []string{
			`CREATE TABLE assets (
				id TEXT PRIMARY KEY,
				type INTEGER NOT NULL,
				name TEXT NOT NULL,
				identifiers TEXT NOT NULL,
				criticality INTEGER NOT NULL DEFAULT 0,
				environment TEXT NOT NULL DEFAULT '',
				status INTEGER NOT NULL DEFAULT 0,
				first_seen TEXT,
				last_seen TEXT,
				attributes TEXT NOT NULL,
				UNIQUE (type, name)
			)`,
			`CREATE INDEX idx_assets_type ON assets(type)`,
			`CREATE INDEX idx_assets_status ON assets(status)`,
			`CREATE TABLE asset_relationships (
				parent_id TEXT NOT NULL REFERENCES assets(id),
				child_id TEXT NOT NULL REFERENCES assets(id),
				kind TEXT NOT NULL,
				source TEXT NOT NULL,
				observed_at TEXT NOT NULL,
				PRIMARY KEY (parent_id, child_id, kind)
			)`,
			`CREATE INDEX idx_asset_rel_parent ON asset_relationships(parent_id)`,
			`CREATE INDEX idx_asset_rel_child ON asset_relationships(child_id)`,
		},
	},
	{
		// v3 adds validation campaigns + purple-team exercises as
		// append-mostly JSON payloads keyed by deterministic id. No
		// existing table is touched.
		version: 3,
		name:    "v3-validation-campaigns",
		ddl: []string{
			`CREATE TABLE validation_campaigns (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
			`CREATE TABLE purple_team_exercises (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
		},
	},
	{
		// v4 adds GRC assessments + resilience records as append-only
		// JSON payloads keyed by deterministic id. No existing table
		// is touched.
		version: 4,
		name:    "v4-grc-governance",
		ddl: []string{
			`CREATE TABLE grc_assessments (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
			`CREATE TABLE resilience_records (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
		},
	},
	{
		// v5 adds supply-chain entities as append-only JSON payloads
		// keyed by deterministic id. Dependencies carry parent/child
		// columns for link queries. No existing table is touched.
		version: 5,
		name:    "v5-supply-chain",
		ddl: []string{
			`CREATE TABLE supply_components (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
			`CREATE TABLE supply_dependencies (
				parent_id TEXT NOT NULL,
				child_id TEXT NOT NULL,
				kind TEXT NOT NULL,
				payload TEXT NOT NULL,
				PRIMARY KEY (parent_id, child_id, kind)
			)`,
			`CREATE INDEX idx_supply_dep_parent ON supply_dependencies(parent_id)`,
			`CREATE INDEX idx_supply_dep_child ON supply_dependencies(child_id)`,
			`CREATE TABLE supply_sboms (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
			`CREATE TABLE supply_policies (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
			`CREATE TABLE supply_vendors (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
			`CREATE TABLE supply_vendor_assessments (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
			`CREATE TABLE supply_links (
				id TEXT PRIMARY KEY,
				payload TEXT NOT NULL
			)`,
		},
	},
}

// SchemaVersion reads the stored version, or -1 when the database was never
// initialized by this backend.
func SchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	err := db.QueryRowContext(ctx, `SELECT version FROM schema_version`).Scan(&v)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		// Only a missing version table means "never initialized here".
		// Any other read failure (I/O, corruption) is explicit, never
		// mistaken for a fresh database.
		if strings.Contains(err.Error(), "no such table") {
			return -1, nil
		}
		return -1, fmt.Errorf("sqlite: read schema version: %w", err)
	}
	return v, nil
}

// migrate brings the database to CurrentSchemaVersion or fails explicitly:
// fresh databases apply every migration; older known versions apply only
// the pending ones, additively, in one transaction; unknown or newer
// versions are incompatibilities, never silently adopted; there is no
// destructive path by default. The version table always ends with exactly
// one row holding CurrentSchemaVersion.
func migrate(ctx context.Context, db *sql.DB) error {
	current, err := SchemaVersion(ctx, db)
	if err != nil {
		return err
	}
	if current == CurrentSchemaVersion {
		return nil
	}
	if current > CurrentSchemaVersion {
		return fmt.Errorf("sqlite: schema version %d unsupported (code speaks %d): refusing to open",
			current, CurrentSchemaVersion)
	}
	known := current == -1
	for _, m := range migrations {
		if m.version == current {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("sqlite: unknown schema version %d: refusing to open", current)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: migrate begin: %w", err)
	}
	defer tx.Rollback()
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		for _, stmt := range m.ddl {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("sqlite: migrate %s: %w", m.name, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM schema_version`); err != nil {
		return fmt.Errorf("sqlite: migrate version reset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, CurrentSchemaVersion); err != nil {
		return fmt.Errorf("sqlite: migrate version stamp: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: migrate commit: %w", err)
	}
	return nil
}
