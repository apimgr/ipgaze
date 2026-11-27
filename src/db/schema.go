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
    id            TEXT PRIMARY KEY,
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
	return store.Write(ctx, func(tx *sql.Tx) error {
		if err := renameCanonicalSchedulerColumns(ctx, tx); err != nil {
			return fmt.Errorf("db: rename scheduler columns: %w", err)
		}
		if err := upgradeAPITokensSchema(ctx, tx); err != nil {
			return fmt.Errorf("db: upgrade API tokens schema: %w", err)
		}
		if err := upgradeSecurityReportsSchema(ctx, tx); err != nil {
			return fmt.Errorf("db: upgrade security reports schema: %w", err)
		}
		for _, stmt := range createStatements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("db: create schema: %w", err)
			}
		}
		for _, stmt := range schemaUpdates {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				if isAlreadyExistsError(err) {
					continue
				}
				return fmt.Errorf("db: schema update: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO owners(id) VALUES('system') ON CONFLICT(id) DO NOTHING`); err != nil {
			return fmt.Errorf("db: ensure system owner: %w", err)
		}
		return nil
	})
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
				if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table.name+` RENAME COLUMN `+rename[0]+` TO `+rename[1]); err != nil {
					return fmt.Errorf("rename %s.%s to %s: %w", table.name, rename[0], rename[1], err)
				}
				delete(columns, rename[0])
				columns[rename[1]] = true
			}
		}
		for name, declaration := range table.columns {
			if columns[name] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table.name+` ADD COLUMN `+name+` `+declaration); err != nil {
				return fmt.Errorf("add %s.%s: %w", table.name, name, err)
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
	if len(columns) == 0 {
		return nil
	}
	additions := []struct{ name, definition string }{
		{"owner_id", `TEXT`},
		{"kind", `TEXT NOT NULL DEFAULT 'linked'`},
		{"name", `TEXT`},
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
		if _, err := db.ExecContext(ctx, `ALTER TABLE api_tokens ADD COLUMN `+addition.name+` `+addition.definition); err != nil && !isAlreadyExistsError(err) {
			return err
		}
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
		if _, err := db.ExecContext(ctx, `ALTER TABLE security_reports ADD COLUMN `+addition.name+` `+addition.definition); err != nil && !isAlreadyExistsError(err) {
			return err
		}
	}
	for target, source := range map[string]string{"body_enc": "encrypted_body", "component": "affected_component", "researcher_comment": "maintainer_comment", "token_hash": "access_token_hash", "token_last_used": "last_access_day"} {
		if !columns[target] && columns[source] {
			if _, err := db.ExecContext(ctx, `UPDATE security_reports SET `+target+` = `+source+` WHERE `+source+` IS NOT NULL`); err != nil {
				return err
			}
		}
	}
	if !columns["body_alg"] && columns["encryption"] {
		if _, err := db.ExecContext(ctx, `UPDATE security_reports SET body_alg = encryption WHERE encryption IS NOT NULL`); err != nil {
			return err
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

// AdoptLegacyAPITokenIDs performs the documented one-time, operator-invoked
// migration from integer token row IDs to UUIDv7 text IDs. Call only after a
// verified offline backup; startup schema application never invokes it.
func AdoptLegacyAPITokenIDs(store *Store) error {
	return store.Write(context.Background(), func(tx *sql.Tx) error {
		rows, err := tx.Query(`PRAGMA table_info(api_tokens)`)
		if err != nil {
			return err
		}
		idType := ""
		columns := map[string]bool{}
		for rows.Next() {
			var cid, notNull, primary int
			var name, kind string
			var defaultValue sql.NullString
			if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
				_ = rows.Close()
				return err
			}
			columns[name] = true
			if name == "id" {
				idType = strings.ToUpper(kind)
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if strings.Contains(idType, "TEXT") {
			return nil
		}
		if !strings.Contains(idType, "INT") {
			return fmt.Errorf("api_tokens.id has unsupported type %q", idType)
		}
		for _, required := range []string{"owner_id", "kind", "name", "token_hash", "token_prefix", "token_last4", "token_enc", "created_at", "rotated_at", "expires_at", "last_used_at", "revoked_at", "revoked_reason"} {
			if !columns[required] {
				return fmt.Errorf("legacy api_tokens is missing %s; adoption refused", required)
			}
		}
		type tokenRow struct {
			owner, kind, name, hash, prefix, last4, enc, reason sql.NullString
			created, rotated, expires, used, revoked            sql.NullInt64
		}
		rows, err = tx.Query(`SELECT owner_id,kind,name,token_hash,token_prefix,token_last4,token_enc,created_at,rotated_at,expires_at,last_used_at,revoked_at,revoked_reason FROM api_tokens`)
		if err != nil {
			return err
		}
		var records []tokenRow
		for rows.Next() {
			var record tokenRow
			if err := rows.Scan(&record.owner, &record.kind, &record.name, &record.hash, &record.prefix, &record.last4, &record.enc, &record.created, &record.rotated, &record.expires, &record.used, &record.revoked, &record.reason); err != nil {
				_ = rows.Close()
				return err
			}
			records = append(records, record)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if _, err := tx.Exec(`CREATE TABLE api_tokens_v7 (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE, kind TEXT NOT NULL CHECK(kind IN ('primary','linked')), name TEXT, token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL, token_last4 TEXT NOT NULL, token_enc TEXT NOT NULL, created_at INTEGER NOT NULL, rotated_at INTEGER, expires_at INTEGER, last_used_at INTEGER, revoked_at INTEGER, revoked_reason TEXT)`); err != nil {
			return err
		}
		for _, record := range records {
			id, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generate canonical token UUID: %w", err)
			}
			if _, err := tx.Exec(`INSERT INTO api_tokens_v7(id,owner_id,kind,name,token_hash,token_prefix,token_last4,token_enc,created_at,rotated_at,expires_at,last_used_at,revoked_at,revoked_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id.String(), record.owner, record.kind, record.name, record.hash, record.prefix, record.last4, record.enc, record.created, record.rotated, record.expires, record.used, record.revoked, record.reason); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`DROP TABLE api_tokens`); err != nil {
			return err
		}
		if _, err := tx.Exec(`ALTER TABLE api_tokens_v7 RENAME TO api_tokens`); err != nil {
			return err
		}
		for _, statement := range []string{
			`CREATE UNIQUE INDEX idx_api_tokens_primary ON api_tokens(owner_id) WHERE kind='primary' AND revoked_at IS NULL`,
			`CREATE UNIQUE INDEX idx_api_tokens_linked_name ON api_tokens(owner_id,name) WHERE kind='linked'`,
			`CREATE INDEX idx_api_tokens_hash ON api_tokens(token_hash)`, `CREATE INDEX idx_api_tokens_prefix ON api_tokens(token_prefix)`, `CREATE INDEX idx_api_tokens_owner ON api_tokens(owner_id)`, `CREATE INDEX idx_api_tokens_active ON api_tokens(revoked_at) WHERE revoked_at IS NULL`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				return err
			}
		}
		check, err := tx.Query(`PRAGMA foreign_key_check`)
		if err != nil {
			return err
		}
		defer check.Close()
		if check.Next() {
			return errors.New("foreign_key_check failed after API token adoption")
		}
		return check.Err()
	})
}

// RequireCanonicalAPITokenIDs rejects startup on a legacy integer-key table;
// the operator must run the offline token adopt-ids maintenance command first.
func RequireCanonicalAPITokenIDs(store *Store) error {
	rows, err := store.QueryContext(context.Background(), `PRAGMA table_info(api_tokens)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			return err
		}
		if name == "id" && !strings.Contains(strings.ToUpper(kind), "TEXT") {
			return errors.New("api_tokens.id is legacy; run `ipgaze --maintenance token adopt-ids` before starting this version")
		}
	}
	return rows.Err()
}
