// Package db provides the database schema and schema management for ipgaze.
// Per AI.md PART 10: no migration files, no version tracking — all schema changes
// are idempotent and run on every startup via EnsureSchema.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('primary', 'linked')),
    name          TEXT,
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
	`CREATE TABLE IF NOT EXISTS contact_captcha_challenges (
    token_hash  TEXT PRIMARY KEY,
    answer_hash TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
)`,
	`CREATE INDEX IF NOT EXISTS idx_contact_captcha_challenges_expires ON contact_captcha_challenges(expires_at)`,
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
	if err := upgradeAPITokensSchema(ctx, db); err != nil {
		return fmt.Errorf("db: upgrade API tokens schema: %w", err)
	}
	for _, stmt := range createStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("db: create schema: %w", err)
		}
	}
	if err := upgradeSecurityReportsSchema(ctx, db); err != nil {
		return fmt.Errorf("db: upgrade security reports schema: %w", err)
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

// upgradeAPITokensSchema preserves the earlier resource-bound token table
// before installing the owner-token schema required by AI.md PART 8.
func upgradeAPITokensSchema(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(api_tokens)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return errors.Join(err, rows.Close())
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return errors.Join(err, rows.Close())
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(columns) == 0 || (columns["owner_id"] && columns["kind"] && columns["token_enc"]) {
		return nil
	}

	var legacyTable string
	err = db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='api_tokens_legacy'`).Scan(&legacyTable)
	if err == nil {
		return errors.New("api_tokens_legacy already exists; refusing to replace or discard token data")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			slog.Warn("legacy API token schema rollback failed", "error", rollbackErr)
		}
	}()
	if _, err := tx.ExecContext(ctx, `ALTER TABLE api_tokens RENAME TO api_tokens_legacy`); err != nil {
		return err
	}
	for _, index := range []string{"idx_api_tokens_hash", "idx_api_tokens_prefix", "idx_api_tokens_resource", "idx_api_tokens_active"} {
		if _, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS `+index); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// upgradeSecurityReportsSchema rebuilds pre-contract tables into the canonical
// PART 11 shape while copying their encrypted payloads and project-specific
// researcher credit metadata without loss.
func upgradeSecurityReportsSchema(ctx context.Context, db *sql.DB) error {
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
	canonical := []string{"security_id", "severity", "component", "status", "body_enc", "body_alg", "contact_enc", "researcher_comment", "disclosure_date", "cve_requested", "token_hash", "token_last_used", "created_at", "updated_at", "closed_at", "credit_preference", "credit_name", "disclosed_year", "short_credit"}
	complete := true
	for _, column := range canonical {
		if !columns[column] {
			complete = false
			break
		}
	}
	if complete {
		return nil
	}
	if !columns["tracking_id"] {
		return errors.New("security_reports has no tracking_id column")
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS security_reports_upgrade`); err != nil {
		return err
	}
	const create = `CREATE TABLE security_reports_upgrade (
tracking_id TEXT PRIMARY KEY,
security_id TEXT NOT NULL DEFAULT '',
severity TEXT NOT NULL,
component TEXT NOT NULL,
status TEXT NOT NULL DEFAULT 'received',
body_enc BLOB NOT NULL,
body_alg TEXT NOT NULL CHECK (body_alg IN ('pgp', 'aes-256-gcm')),
contact_enc BLOB,
researcher_comment TEXT NOT NULL DEFAULT '',
disclosure_date DATE,
cve_requested BOOLEAN NOT NULL DEFAULT FALSE,
token_hash TEXT NOT NULL,
token_last_used DATE,
created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
closed_at INTEGER,
credit_preference TEXT NOT NULL DEFAULT 'no',
credit_name TEXT NOT NULL DEFAULT '',
disclosed_year INTEGER,
short_credit TEXT NOT NULL DEFAULT ''
)`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return err
	}
	col := func(name, fallback string) string {
		if columns[name] {
			return name
		}
		return fallback
	}
	body := col("body_enc", col("encrypted_body", "X''"))
	bodyAlg := col("body_alg", col("encryption", "'aes-256-gcm'"))
	component := col("component", col("affected_component", "''"))
	comment := col("researcher_comment", "COALESCE(maintainer_comment, '')")
	tokenHash := col("token_hash", col("access_token_hash", "''"))
	used := col("token_last_used", "last_access_day")
	if !columns["token_last_used"] && !columns["last_access_day"] {
		used = "NULL"
	}
	created := col("created_at", "strftime('%s', 'now')")
	updated := col("updated_at", created)
	closed := col("closed_at", "NULL")
	disclosure := col("disclosure_date", "NULL")
	disclosure = "CASE WHEN " + disclosure + " IS NULL THEN NULL WHEN typeof(" + disclosure + ") = 'integer' THEN DATE(" + disclosure + ", 'unixepoch') ELSE " + disclosure + " END"
	if used != "NULL" && used == "last_access_day" {
		used = "CASE WHEN last_access_day IS NULL THEN NULL WHEN typeof(last_access_day) = 'integer' THEN DATE(last_access_day * 86400, 'unixepoch') ELSE last_access_day END"
	}
	securityID := col("security_id", "''")
	contact := col("contact_enc", "NULL")
	cve := col("cve_requested", "0")
	creditPref := col("credit_preference", "'no'")
	creditName := col("credit_name", "''")
	disclosedYear := col("disclosed_year", "NULL")
	shortCredit := col("short_credit", "''")
	status := col("status", "'received'")
	status = `CASE ` + status + ` WHEN 'Received' THEN 'received' WHEN 'Triaged' THEN 'triaged' WHEN 'Confirmed' THEN 'confirmed' WHEN 'Patching' THEN 'patching' WHEN 'Disclosed' THEN 'disclosed' WHEN 'Won''t Fix' THEN 'wont_fix' ELSE ` + status + ` END`
	query := `INSERT INTO security_reports_upgrade (tracking_id, security_id, severity, component, status, body_enc, body_alg, contact_enc, researcher_comment, disclosure_date, cve_requested, token_hash, token_last_used, created_at, updated_at, closed_at, credit_preference, credit_name, disclosed_year, short_credit)
SELECT tracking_id, ` + securityID + `, severity, ` + component + `, ` + status + `, ` + body + `, ` + bodyAlg + `, ` + contact + `, ` + comment + `, ` + disclosure + `, ` + cve + `, ` + tokenHash + `, ` + used + `, ` + created + `, ` + updated + `, ` + closed + `, ` + creditPref + `, ` + creditName + `, ` + disclosedYear + `, ` + shortCredit + ` FROM security_reports`
	if _, err := db.ExecContext(ctx, query); err != nil {
		_, _ = db.ExecContext(ctx, `DROP TABLE IF EXISTS security_reports_upgrade`)
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DROP TABLE security_reports`); err == nil {
		_, err = tx.ExecContext(ctx, `ALTER TABLE security_reports_upgrade RENAME TO security_reports`)
	}
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// isAlreadyExistsError returns true when err indicates that a column, index,
// table, or trigger already exists — all of which are harmless in this context.
func isAlreadyExistsError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "duplicate column")
}
