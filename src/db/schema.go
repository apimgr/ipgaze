// Package db provides the database schema and schema management for ipgaze.
// Per AI.md PART 10: no migration files, no version tracking — all schema changes
// are idempotent and run on every startup via EnsureSchema.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// createStatements are the idempotent CREATE TABLE / CREATE INDEX statements
// that establish the full server.db schema per AI.md PART 5 / PART 10.
// Each statement is safe to run on an existing database.
var createStatements = []string{
	// ----------------------------------------------------------------------------
	// Rate limiting (sliding window counters)
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS rate_limits (
    key          TEXT PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 1,
    prev_count   INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at   INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
)`,

	`CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)`,

	// ----------------------------------------------------------------------------
	// Audit log (config changes, request log, security events)
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    level       TEXT NOT NULL DEFAULT 'info',
    category    TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor_ip    TEXT,
    target_type TEXT,
    target_id   TEXT,
    details     TEXT,
    success     INTEGER NOT NULL DEFAULT 1
)`,

	`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_category  ON audit_log(category)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_actor_ip  ON audit_log(actor_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_target    ON audit_log(target_type, target_id)`,

	// ----------------------------------------------------------------------------
	// Scheduler — background task definitions
	// Column names match AI.md PART 10 exactly: id / name (not task_id / task_name).
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS scheduler_tasks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    schedule    TEXT NOT NULL,
    last_run    INTEGER,
    next_run    INTEGER,
    last_status TEXT,
    last_error  TEXT,
    run_count   INTEGER NOT NULL DEFAULT 0,
    fail_count  INTEGER NOT NULL DEFAULT 0
)`,

	`CREATE INDEX IF NOT EXISTS idx_scheduler_next_run ON scheduler_tasks(next_run)`,
	`CREATE INDEX IF NOT EXISTS idx_scheduler_enabled  ON scheduler_tasks(enabled)`,

	// Scheduler run history
	`CREATE TABLE IF NOT EXISTS scheduler_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER,
    status      TEXT NOT NULL,
    error       TEXT,
    duration_ms INTEGER
)`,

	`CREATE INDEX IF NOT EXISTS idx_scheduler_history_task    ON scheduler_history(task_id)`,
	`CREATE INDEX IF NOT EXISTS idx_scheduler_history_started ON scheduler_history(started_at)`,

	// ----------------------------------------------------------------------------
	// Backups — backup history and metadata
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS backups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    filename   TEXT NOT NULL UNIQUE,
    filepath   TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    type       TEXT NOT NULL DEFAULT 'auto',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    checksum   TEXT,
    notes      TEXT
)`,

	`CREATE INDEX IF NOT EXISTS idx_backups_created ON backups(created_at)`,

	// ----------------------------------------------------------------------------
	// Owners — anonymous, credential-only identities.
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS owners (
    id            TEXT PRIMARY KEY,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_seen_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
)`,

	// ----------------------------------------------------------------------------
	// API tokens — server-generated owner and linked tokens.
	// The server.token (server.yml) is NOT stored here; it is validated directly
	// from config via constant-time SHA-256 comparison (AI.md PART 11).
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS api_tokens (
    id            TEXT PRIMARY KEY,
    owner_id      TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('primary', 'linked')),
    name          TEXT,
    scope         TEXT NOT NULL DEFAULT 'read-write' CHECK (scope IN ('read', 'read-write', 'global')),
    token_hash    TEXT NOT NULL UNIQUE,
    token_prefix  TEXT NOT NULL,
    token_last4   TEXT NOT NULL,
    token_enc     TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    rotated_at    INTEGER,
    expires_at    INTEGER,
    last_used_at  INTEGER,
    revoked_at    INTEGER,
    revoked_reason TEXT
)`,

	`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_primary ON api_tokens(owner_id) WHERE kind = 'primary' AND revoked_at IS NULL`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_linked_name ON api_tokens(owner_id, name) WHERE kind = 'linked'`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash     ON api_tokens(token_hash)`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix   ON api_tokens(token_prefix)`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_owner    ON api_tokens(owner_id)`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_active   ON api_tokens(revoked_at) WHERE revoked_at IS NULL`,

	// ----------------------------------------------------------------------------
	// app_secrets — key/value secrets and rotation bookkeeping (AI.md PART 10/11).
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS app_secrets (
    name       TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
)`,

	// ----------------------------------------------------------------------------
	// pgp_keypairs — metadata about the project-level GPG keypair (AI.md PART 11
	// "GPG Keypair Management"). The keys themselves live on disk under
	// {config_dir}/security/; this table only tracks properties. One row per
	// generation/rotation so fingerprint history survives deletion.
	// keyservers_published is a JSON object: {"host": unix_timestamp, ...}.
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS pgp_keypairs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint           TEXT NOT NULL UNIQUE,
    created_at            INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at            INTEGER NOT NULL,
    last_rotated_at       INTEGER,
    keyservers_published  TEXT NOT NULL DEFAULT '{}',
    revoked               INTEGER NOT NULL DEFAULT 0
)`,

	`CREATE INDEX IF NOT EXISTS idx_pgp_keypairs_revoked ON pgp_keypairs(revoked)`,

	// ----------------------------------------------------------------------------
	// ip_blocks — temporary abuse blocks survive server restarts. Permanent
	// blocks remain operator-managed config entries (AI.md PART 11).
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS ip_blocks (
    ip            TEXT PRIMARY KEY,
    reason        TEXT NOT NULL DEFAULT '',
    blocked_at    INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at    INTEGER NOT NULL,
    offense_count INTEGER NOT NULL DEFAULT 1,
    auto_blocked  INTEGER NOT NULL DEFAULT 1
)`,

	`CREATE INDEX IF NOT EXISTS idx_ip_blocks_expiry ON ip_blocks(expires_at)`,

	// ----------------------------------------------------------------------------
	// security_reports — encrypted coordinated-disclosure submissions. PII and
	// vulnerability details are encrypted before storage (AI.md PART 11).
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS security_reports (
    tracking_id        TEXT PRIMARY KEY,
    security_id        TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL,
    component          TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'received',
    body_enc           BLOB NOT NULL,
    body_alg           TEXT NOT NULL CHECK (body_alg IN ('pgp', 'aes-256-gcm')),
    contact_enc        BLOB,
    researcher_comment TEXT NOT NULL DEFAULT '',
    disclosure_date    DATE,
    cve_requested      BOOLEAN NOT NULL DEFAULT FALSE,
    token_hash         TEXT NOT NULL,
    token_last_used    DATE,
    created_at         INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at         INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    closed_at          INTEGER,
    credit_preference  TEXT NOT NULL DEFAULT 'no',
    credit_name        TEXT NOT NULL DEFAULT '',
    disclosed_year     INTEGER,
    short_credit       TEXT NOT NULL DEFAULT ''
)`,
	`CREATE TABLE IF NOT EXISTS captcha_challenges (
    id          VARCHAR(32) PRIMARY KEY,
    answer_hash VARCHAR(64) NOT NULL,
    expires_at  TIMESTAMP NOT NULL
)`,
	`CREATE INDEX IF NOT EXISTS idx_captcha_challenges_expires ON captcha_challenges(expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_security_reports_public ON security_reports(status, created_at)`,
}

// schemaUpdates are idempotent ALTER TABLE / CREATE INDEX statements applied
// after the base schema is in place.  Each entry is safe to run on a database
// that already has the column / index.  Errors that indicate the object already
// exists are silently ignored (see isAlreadyExistsError).
var schemaUpdates = []string{
	// v1.1.0 — rate-limit window index (also in createStatements; harmless duplicate)
	`CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)`,
	// v1.2.0 — audit category index
	`CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category)`,
	`CREATE INDEX IF NOT EXISTS idx_security_reports_public ON security_reports(status, created_at)`,
	`ALTER TABLE rate_limits ADD COLUMN prev_count INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE api_tokens ADD COLUMN token_last4 TEXT NOT NULL DEFAULT ''`,
}

// migrationTimeout is the AI.md PART 10 "Query Timeouts" ceiling for schema
// changes: migrations get 5 minutes.
const migrationTimeout = 5 * time.Minute

// EnsureSchema creates all required tables and applies idempotent schema updates
// under the PART 10 migration timeout.
// Existing application data is preserved. Legacy tables remain intact and
// canonical tables and columns are added without destructive replacement.
// Call once at startup, before the server accepts requests.
func EnsureSchema(store *Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), migrationTimeout)
	defer cancel()
	return EnsureSchemaContext(ctx, store)
}

// EnsureSchemaContext is EnsureSchema bound to a caller-supplied context, so a
// shutdown signal or an outer deadline can abort a migration in progress.
func EnsureSchemaContext(ctx context.Context, store *Store) error {
	if err := store.Write(ctx, func(tx *sql.Tx) error {
		if store.remoteDB {
			if err := adoptLegacyRemoteNames(ctx, tx); err != nil {
				return fmt.Errorf("db: remote naming migration: %w", err)
			}
		}
		if err := upgradeAppSecretsSchema(ctx, tx); err != nil {
			return fmt.Errorf("db: app_secrets migration: %w", err)
		}
		if err := renameCanonicalSchedulerColumns(ctx, tx); err != nil {
			return fmt.Errorf("db: scheduler_tasks/scheduler_history migration: %w", err)
		}
		if err := upgradeAPITokensSchema(ctx, tx); err != nil {
			return fmt.Errorf("db: api_tokens migration: %w", err)
		}
		if err := upgradeSecurityReportsSchema(ctx, tx); err != nil {
			return fmt.Errorf("db: security_reports migration: %w", err)
		}
		for _, stmt := range createStatements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("db: migration statement %q failed: %w", stmt, err)
			}
		}
		for _, stmt := range schemaUpdates {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				if isAlreadyExistsError(err) {
					continue
				}
				return fmt.Errorf("db: migration statement %q failed: %w", stmt, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO owners(id) VALUES('system') ON CONFLICT(id) DO NOTHING`); err != nil {
			return fmt.Errorf("db: ensure system owner: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	rows, err := store.QueryContext(ctx, `PRAGMA table_info(api_tokens)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primary int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primary); err != nil {
			return err
		}
		if name == "id" && strings.Contains(strings.ToUpper(columnType), "INT") {
			store.tokenIDColumn = "public_id"
			return rows.Err()
		}
	}
	return rows.Err()
}

// adoptLegacyRemoteNames preserves data created before the required srv_ prefix
// was introduced. Existing tables are renamed in place, and legacy indexes are
// recreated by the normal idempotent schema statements under their new names.
func adoptLegacyRemoteNames(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return err
	}
	existing := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		existing[strings.ToLower(name)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for name := range databaseObjectNames {
		if strings.HasPrefix(name, "idx_") {
			continue
		}
		if _, legacyExists := existing[name]; !legacyExists {
			continue
		}
		remoteName := strings.ToLower(DatabaseObjectName("libsql", name))
		if _, remoteExists := existing[remoteName]; remoteExists {
			return fmt.Errorf("both legacy %q and prefixed %q exist; refusing to choose or discard data", name, remoteName)
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+name+` RENAME TO `+remoteName); err != nil {
			return fmt.Errorf("rename legacy table %q: %w", name, err)
		}
	}
	for name := range databaseObjectNames {
		if !strings.HasPrefix(name, "idx_") {
			continue
		}
		if _, legacyExists := existing[name]; !legacyExists {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DROP INDEX `+name); err != nil {
			return fmt.Errorf("drop legacy index %q: %w", name, err)
		}
	}
	return nil
}

// upgradeAppSecretsSchema moves legacy inline rotation fields into the
// canonical app_secrets key/value rows without discarding any stored secret.
func upgradeAppSecretsSchema(ctx context.Context, tx *sql.Tx) error {
	columns, exists, err := schemaTableColumns(ctx, tx, "app_secrets")
	if err != nil || !exists || columns["updated_at"] {
		return err
	}
	if !columns["previous_value"] || !columns["previous_until"] || !columns["rotated_at"] {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE app_secrets ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE app_secrets SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE updated_at = ''`)
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT name, value, previous_value, previous_until, rotated_at FROM app_secrets`)
	if err != nil {
		return err
	}
	type secretRow struct {
		name, value              string
		previous                 sql.NullString
		previousUntil, rotatedAt sql.NullInt64
	}
	var secrets []secretRow
	for rows.Next() {
		var row secretRow
		if err := rows.Scan(&row.name, &row.value, &row.previous, &row.previousUntil, &row.rotatedAt); err != nil {
			_ = rows.Close()
			return err
		}
		secrets = append(secrets, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE app_secrets RENAME TO app_secrets_legacy`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE app_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		return err
	}
	insert := `INSERT INTO app_secrets(name, value, updated_at) VALUES(?, ?, ?)`
	for _, row := range secrets {
		updated := time.Now().UTC().Format(time.RFC3339Nano)
		if row.rotatedAt.Valid {
			updated = time.Unix(row.rotatedAt.Int64, 0).UTC().Format(time.RFC3339Nano)
		}
		if _, err := tx.ExecContext(ctx, insert, row.name, row.value, updated); err != nil {
			return err
		}
		if row.previous.Valid {
			if _, err := tx.ExecContext(ctx, insert, row.name+"_previous", row.previous.String, updated); err != nil {
				return err
			}
		}
		if row.previousUntil.Valid {
			until := time.Unix(row.previousUntil.Int64, 0).UTC().Format(time.RFC3339Nano)
			if _, err := tx.ExecContext(ctx, insert, row.name+"_previous_until", until, updated); err != nil {
				return err
			}
		}
	}
	return nil
}

func renameCanonicalSchedulerColumns(ctx context.Context, tx *sql.Tx) error {
	for _, table := range []struct {
		name    string
		renames [][2]string
		columns map[string]string
	}{
		{
			name:    "scheduler_tasks",
			renames: [][2]string{{"task_id", "id"}, {"task_name", "name"}},
			columns: map[string]string{
				"id": `TEXT`, "name": `TEXT NOT NULL DEFAULT ''`, "enabled": `INTEGER NOT NULL DEFAULT 1`,
				"schedule": `TEXT NOT NULL DEFAULT ''`, "last_run": `INTEGER`, "next_run": `INTEGER`,
				"last_status": `TEXT`, "last_error": `TEXT`, "run_count": `INTEGER NOT NULL DEFAULT 0`, "fail_count": `INTEGER NOT NULL DEFAULT 0`,
			},
		},
		{
			name:    "scheduler_history",
			renames: [][2]string{{"ran_at", "started_at"}},
			columns: map[string]string{
				"id": `INTEGER`, "task_id": `TEXT NOT NULL DEFAULT ''`, "started_at": `INTEGER NOT NULL DEFAULT 0`,
				"finished_at": `INTEGER`, "status": `TEXT NOT NULL DEFAULT 'failed'`, "error": `TEXT`, "duration_ms": `INTEGER`,
			},
		},
	} {
		columns, exists, err := schemaTableColumns(ctx, tx, table.name)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		for _, rename := range table.renames {
			if columns[rename[0]] && !columns[rename[1]] {
				statement := `ALTER TABLE ` + table.name + ` RENAME COLUMN ` + rename[0] + ` TO ` + rename[1]
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return fmt.Errorf("db: migration statement %q failed: %w", statement, err)
				}
				delete(columns, rename[0])
				columns[rename[1]] = true
			}
		}
		for name, declaration := range table.columns {
			if columns[name] {
				continue
			}
			statement := `ALTER TABLE ` + table.name + ` ADD COLUMN ` + name + ` ` + declaration
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("db: migration statement %q failed: %w", statement, err)
			}
		}
	}
	return nil
}

func schemaTableColumns(ctx context.Context, tx *sql.Tx, table string) (map[string]bool, bool, error) {
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil {
		return nil, false, err
	}
	if exists == 0 {
		return nil, false, nil
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, false, err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return nil, false, err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, false, err
	}
	if err := rows.Close(); err != nil {
		return nil, false, err
	}
	return columns, true, nil
}

// upgradeAPITokensSchema adds the canonical token columns in place while
// retaining legacy columns and rows, as required by PART 10's additive schema
// contract.
func upgradeAPITokensSchema(ctx context.Context, db *sql.Tx) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(api_tokens)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	idType := ""
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return errors.Join(err, rows.Close())
		}
		columns[name] = true
		if name == "id" {
			idType = strings.ToUpper(columnType)
		}
	}
	if err := rows.Err(); err != nil {
		return errors.Join(err, rows.Close())
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(columns) == 0 {
		return nil
	}
	legacyID := strings.Contains(idType, "INT")
	additions := []struct{ name, definition string }{
		{"owner_id", `TEXT`},
		{"kind", `TEXT NOT NULL DEFAULT 'linked'`},
		{"name", `TEXT`},
		{"scope", `TEXT NOT NULL DEFAULT 'read-write' CHECK (scope IN ('read', 'read-write', 'global'))`},
		{"token_enc", `TEXT NOT NULL DEFAULT ''`},
		{"token_last4", `TEXT NOT NULL DEFAULT ''`},
		{"rotated_at", `INTEGER`},
		{"expires_at", `INTEGER`},
		{"last_used_at", `INTEGER`},
		{"revoked_at", `INTEGER`},
		{"revoked_reason", `TEXT`},
	}
	for _, addition := range additions {
		if columns[addition.name] {
			continue
		}
		statement := `ALTER TABLE api_tokens ADD COLUMN ` + addition.name + ` ` + addition.definition
		if _, err := db.ExecContext(ctx, statement); err != nil && !isAlreadyExistsError(err) {
			return fmt.Errorf("db: migration statement %q failed: %w", statement, err)
		}
	}
	if legacyID {
		if !columns["public_id"] {
			if _, err := db.ExecContext(ctx, `ALTER TABLE api_tokens ADD COLUMN public_id TEXT`); err != nil && !isAlreadyExistsError(err) {
				return err
			}
		}
		rows, err := db.QueryContext(ctx, `SELECT id FROM api_tokens WHERE public_id IS NULL OR public_id = ''`)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, id := range ids {
			publicID, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generate public token UUID: %w", err)
			}
			if _, err := db.ExecContext(ctx, `UPDATE api_tokens SET public_id = ? WHERE id = ? AND (public_id IS NULL OR public_id = '')`, publicID.String(), id); err != nil {
				return err
			}
		}
		if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_public_id ON api_tokens(public_id)`); err != nil {
			return err
		}
	}
	statement := `UPDATE api_tokens SET scope = 'global' WHERE kind = 'primary' AND scope <> 'global'`
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("db: migration statement %q failed: %w", statement, err)
	}
	return nil
}

// upgradeSecurityReportsSchema adds canonical columns in place and copies
// values from legacy aliases while retaining all legacy columns and rows.
func upgradeSecurityReportsSchema(ctx context.Context, db *sql.Tx) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(security_reports)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(columns) == 0 {
		return nil
	}
	additions := []struct{ name, definition string }{
		{"security_id", `TEXT NOT NULL DEFAULT ''`}, {"severity", `TEXT NOT NULL DEFAULT 'low'`},
		{"component", `TEXT NOT NULL DEFAULT ''`}, {"status", `TEXT NOT NULL DEFAULT 'received'`},
		{"body_enc", `BLOB NOT NULL DEFAULT X''`}, {"body_alg", `TEXT NOT NULL DEFAULT 'aes-256-gcm'`},
		{"contact_enc", `BLOB`}, {"researcher_comment", `TEXT NOT NULL DEFAULT ''`},
		{"disclosure_date", `DATE`}, {"cve_requested", `BOOLEAN NOT NULL DEFAULT FALSE`},
		{"token_hash", `TEXT NOT NULL DEFAULT ''`}, {"token_last_used", `DATE`},
		{"created_at", `INTEGER NOT NULL DEFAULT 0`}, {"updated_at", `INTEGER NOT NULL DEFAULT 0`},
		{"closed_at", `INTEGER`}, {"credit_preference", `TEXT NOT NULL DEFAULT 'no'`},
		{"credit_name", `TEXT NOT NULL DEFAULT ''`}, {"disclosed_year", `INTEGER`},
		{"short_credit", `TEXT NOT NULL DEFAULT ''`},
	}
	for _, addition := range additions {
		if columns[addition.name] {
			continue
		}
		statement := `ALTER TABLE security_reports ADD COLUMN ` + addition.name + ` ` + addition.definition
		if _, err := db.ExecContext(ctx, statement); err != nil && !isAlreadyExistsError(err) {
			return fmt.Errorf("db: migration statement %q failed: %w", statement, err)
		}
	}
	for target, source := range map[string]string{"body_enc": "encrypted_body", "component": "affected_component", "researcher_comment": "maintainer_comment", "token_hash": "access_token_hash", "token_last_used": "last_access_day"} {
		if !columns[target] && columns[source] {
			statement := `UPDATE security_reports SET ` + target + ` = ` + source + ` WHERE ` + source + ` IS NOT NULL`
			if _, err := db.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("db: migration statement %q failed: %w", statement, err)
			}
		}
	}
	if !columns["body_alg"] && columns["encryption"] {
		statement := `UPDATE security_reports SET body_alg = encryption WHERE encryption IS NOT NULL`
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("db: migration statement %q failed: %w", statement, err)
		}
	}
	return nil
}

// isAlreadyExistsError returns true when err indicates that a column, index,
// table, or trigger already exists — all of which are harmless in this context.
func isAlreadyExistsError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "duplicate column")
}
