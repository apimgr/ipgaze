// Package db provides the database schema and schema management for ipgaze.
// Per AI.md PART 10: no migration files, no version tracking — all schema changes
// are idempotent and run on every startup via EnsureSchema.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// createStatements are the idempotent CREATE TABLE / CREATE INDEX statements
// that establish the full server.db schema per AI.md PART 5 / PART 10.
// Each statement is safe to run on an existing database.
var createStatements = []string{
	// ----------------------------------------------------------------------------
	// Config key-value storage (mirrors YAML structure as flat keys)
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'string',
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
)`,

	// Config metadata for change detection (single row, id=1 always)
	`CREATE TABLE IF NOT EXISTS config_meta (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    version    INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
)`,

	// Seed the single metadata row if not present
	`INSERT OR IGNORE INTO config_meta (id, version) VALUES (1, 1)`,

	// Auto-increment config version on INSERT
	`CREATE TRIGGER IF NOT EXISTS config_version_bump_insert
AFTER INSERT ON config
BEGIN
    UPDATE config_meta SET
        version    = version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id = 1;
END`,

	// Auto-increment config version on UPDATE
	`CREATE TRIGGER IF NOT EXISTS config_version_bump_update
AFTER UPDATE ON config
BEGIN
    UPDATE config_meta SET
        version    = version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id = 1;
END`,

	// Auto-increment config version on DELETE
	`CREATE TRIGGER IF NOT EXISTS config_version_bump_delete
AFTER DELETE ON config
BEGIN
    UPDATE config_meta SET
        version    = version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id = 1;
END`,

	// Fast prefix scan (e.g. all "ssl.*" keys)
	`CREATE INDEX IF NOT EXISTS idx_config_key_prefix ON config(key)`,

	// ----------------------------------------------------------------------------
	// Rate limiting (sliding window counters)
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS rate_limits (
    key          TEXT PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 1,
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
	// API tokens — server-generated resource-owner tokens.
	// The server.token (server.yml) is NOT stored here; it is validated directly
	// from config via constant-time SHA-256 comparison (AI.md PART 11).
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash    TEXT NOT NULL UNIQUE,
    token_prefix  TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at    INTEGER,
    last_used_at  INTEGER,
    revoked_at    INTEGER,
    revoked_reason TEXT
)`,

	`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash     ON api_tokens(token_hash)`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix   ON api_tokens(token_prefix)`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_resource ON api_tokens(resource_type, resource_id)`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_active   ON api_tokens(revoked_at) WHERE revoked_at IS NULL`,

	// ----------------------------------------------------------------------------
	// app_secrets — server-generated root secrets with independent rotation
	// lifecycles (AI.md PART 11). Rows: installation_secret, cookie_signing_key,
	// csrf_token_secret. Values are base64-encoded. previous_value/previous_until
	// support the 7-day grace-overlap window during rotation.
	// ----------------------------------------------------------------------------
	`CREATE TABLE IF NOT EXISTS app_secrets (
    name            TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    previous_value  TEXT,
    previous_until  INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    rotated_at      INTEGER
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
}

// migrationTimeout is the AI.md PART 10 "Query Timeouts" ceiling for schema
// changes: migrations get 5 minutes.
const migrationTimeout = 5 * time.Minute

// EnsureSchema creates all required tables and applies idempotent schema updates
// under the PART 10 migration timeout.
// It is safe to call on an existing database; nothing is dropped or truncated.
// Call once at startup, before the server accepts requests.
func EnsureSchema(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), migrationTimeout)
	defer cancel()
	return EnsureSchemaContext(ctx, db)
}

// EnsureSchemaContext is EnsureSchema bound to a caller-supplied context, so a
// shutdown signal or an outer deadline can abort a migration in progress.
func EnsureSchemaContext(ctx context.Context, db *sql.DB) error {
	for _, stmt := range createStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("db: create schema: %w", err)
		}
	}

	for _, stmt := range schemaUpdates {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			// Silently ignore "already exists" errors — these are expected on
			// databases that were created with a later version of the schema.
			if isAlreadyExistsError(err) {
				continue
			}
			return fmt.Errorf("db: schema update: %w", err)
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
