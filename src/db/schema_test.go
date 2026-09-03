package db

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// openMemDB opens an in-memory SQLite database via the pure-Go driver.
func openMemDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ---------------------------------------------------------------------------
// EnsureSchema — happy path
// ---------------------------------------------------------------------------

func TestEnsureSchema_CreatesAllTables(t *testing.T) {
	db := openMemDB(t)

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	expected := []string{
		"config",
		"config_meta",
		"rate_limits",
		"audit_log",
		"scheduler_tasks",
		"scheduler_history",
		"backups",
		"api_tokens",
	}
	for _, tbl := range expected {
		var name string
		row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl)
		if err := row.Scan(&name); err != nil {
			t.Errorf("table %q not found after EnsureSchema: %v", tbl, err)
		}
	}
}

// EnsureSchema must be safe to call twice on the same database (idempotent).
func TestEnsureSchema_Idempotent(t *testing.T) {
	db := openMemDB(t)

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("first EnsureSchema: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("second EnsureSchema (idempotency): %v", err)
	}
}

// Verify the config_meta seed row is present after schema creation.
func TestEnsureSchema_SeedsConfigMeta(t *testing.T) {
	db := openMemDB(t)

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id, version int
	row := db.QueryRow("SELECT id, version FROM config_meta WHERE id = 1")
	if err := row.Scan(&id, &version); err != nil {
		t.Fatalf("config_meta row missing: %v", err)
	}
	if id != 1 {
		t.Errorf("config_meta.id = %d, want 1", id)
	}
	if version < 1 {
		t.Errorf("config_meta.version = %d, want >= 1", version)
	}
}

// Insert into config should trigger the version bump trigger.
func TestEnsureSchema_ConfigVersionTrigger(t *testing.T) {
	db := openMemDB(t)

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var before int
	if err := db.QueryRow("SELECT version FROM config_meta WHERE id=1").Scan(&before); err != nil {
		t.Fatalf("read before version: %v", err)
	}

	if _, err := db.Exec("INSERT INTO config(key, value, type) VALUES('test.key', 'v', 'string')"); err != nil {
		t.Fatalf("insert config: %v", err)
	}

	var after int
	if err := db.QueryRow("SELECT version FROM config_meta WHERE id=1").Scan(&after); err != nil {
		t.Fatalf("read after version: %v", err)
	}
	if after <= before {
		t.Errorf("config_meta.version did not increment: before=%d after=%d", before, after)
	}
}

// All required indexes must be present.
func TestEnsureSchema_CreatesIndexes(t *testing.T) {
	db := openMemDB(t)

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	expected := []string{
		"idx_config_key_prefix",
		"idx_rate_limits_window",
		"idx_audit_timestamp",
		"idx_audit_category",
		"idx_audit_actor_ip",
		"idx_audit_target",
		"idx_scheduler_next_run",
		"idx_scheduler_enabled",
		"idx_scheduler_history_task",
		"idx_scheduler_history_started",
		"idx_backups_created",
		"idx_api_tokens_hash",
		"idx_api_tokens_prefix",
	}
	for _, idx := range expected {
		var name string
		row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx)
		if err := row.Scan(&name); err != nil {
			t.Errorf("index %q not found after EnsureSchema", idx)
		}
	}
}

// EnsureSchema must return an error when the DB is closed.
func TestEnsureSchema_ClosedDB_ReturnsError(t *testing.T) {
	db := openMemDB(t)
	db.Close()

	err := EnsureSchema(db)
	if err == nil {
		t.Error("EnsureSchema with closed DB: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// isAlreadyExistsError
// ---------------------------------------------------------------------------

func TestIsAlreadyExistsError_MatchesKnownMessages(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"table foo already exists", true},
		{"index idx_foo already exists", true},
		{"duplicate column name: bar", true},
		{"ALREADY EXISTS in schema", true},
		{"near \"CREATE\": syntax error", false},
		{"", false},
	}
	for _, tc := range cases {
		err := fakeError(tc.msg)
		got := isAlreadyExistsError(err)
		if got != tc.want {
			t.Errorf("isAlreadyExistsError(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// fakeError wraps a string as an error for testing isAlreadyExistsError.
type fakeError string

func (e fakeError) Error() string { return string(e) }

// ---------------------------------------------------------------------------
// Schema DML — basic insert/query round-trips prove table definitions are correct
// ---------------------------------------------------------------------------

func TestSchema_AuditLog_InsertQuery(t *testing.T) {
	db := openMemDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	_, err := db.Exec(`INSERT INTO audit_log(category, action, actor_ip) VALUES(?, ?, ?)`,
		"auth", "login", "1.2.3.4")
	if err != nil {
		t.Fatalf("insert audit_log: %v", err)
	}

	var cat, action, ip string
	if err := db.QueryRow("SELECT category, action, actor_ip FROM audit_log LIMIT 1").
		Scan(&cat, &action, &ip); err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if cat != "auth" || action != "login" || ip != "1.2.3.4" {
		t.Errorf("audit_log round-trip: got (%s,%s,%s), want (auth,login,1.2.3.4)", cat, action, ip)
	}
}

func TestSchema_SchedulerTasks_InsertQuery(t *testing.T) {
	db := openMemDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	_, err := db.Exec(`INSERT INTO scheduler_tasks(id, name, schedule) VALUES(?,?,?)`,
		"task-1", "geoip_update", "@daily")
	if err != nil {
		t.Fatalf("insert scheduler_tasks: %v", err)
	}

	var id, name, sched string
	if err := db.QueryRow("SELECT id, name, schedule FROM scheduler_tasks WHERE id=?", "task-1").
		Scan(&id, &name, &sched); err != nil {
		t.Fatalf("query scheduler_tasks: %v", err)
	}
	if id != "task-1" || name != "geoip_update" || sched != "@daily" {
		t.Errorf("scheduler_tasks round-trip: got (%s,%s,%s)", id, name, sched)
	}
}

func TestSchema_ApiTokens_UniqueHash(t *testing.T) {
	db := openMemDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	insert := func(hash, prefix string) error {
		_, err := db.Exec(
			`INSERT INTO api_tokens(token_hash, token_prefix, resource_type, resource_id) VALUES(?,?,?,?)`,
			hash, prefix, "user", "u1")
		return err
	}

	if err := insert("hash-abc", "tok_abc"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insert("hash-abc", "tok_abc"); err == nil {
		t.Error("duplicate token_hash should have been rejected by UNIQUE constraint")
	}
}

// Verify that the `config` table correctly stores and retrieves a value.
func TestSchema_Config_KeyValueRoundTrip(t *testing.T) {
	db := openMemDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO config(key, value, type) VALUES(?,?,?)`,
		"ssl.enabled", "true", "bool"); err != nil {
		t.Fatalf("insert config: %v", err)
	}

	var val string
	if err := db.QueryRow("SELECT value FROM config WHERE key=?", "ssl.enabled").Scan(&val); err != nil {
		t.Fatalf("select config: %v", err)
	}
	if val != "true" {
		t.Errorf("config value = %q, want %q", val, "true")
	}
}

// Duplicate config key must be rejected (PRIMARY KEY constraint).
func TestSchema_Config_DuplicateKeyRejected(t *testing.T) {
	db := openMemDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	ins := func() error {
		_, err := db.Exec(`INSERT INTO config(key,value,type) VALUES(?,?,?)`, "k", "v", "string")
		return err
	}
	if err := ins(); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := ins(); err == nil {
		t.Error("duplicate config key should be rejected by PRIMARY KEY constraint")
	}
}

// ---------------------------------------------------------------------------
// isAlreadyExistsError — case-insensitive matching
// ---------------------------------------------------------------------------

func TestIsAlreadyExistsError_CaseInsensitive(t *testing.T) {
	cases := []string{
		"ALREADY EXISTS",
		"Already Exists",
		"already exists",
		"DUPLICATE COLUMN",
	}
	for _, msg := range cases {
		if !isAlreadyExistsError(fakeError(msg)) {
			t.Errorf("isAlreadyExistsError(%q) = false, want true", msg)
		}
	}
}

// ---------------------------------------------------------------------------
// schemaUpdates — running them against an already-up-to-date schema must not error
// ---------------------------------------------------------------------------

func TestSchemaUpdates_IdempotentOnFreshDB(t *testing.T) {
	db := openMemDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	for _, stmt := range schemaUpdates {
		if _, err := db.Exec(stmt); err != nil {
			if !isAlreadyExistsError(err) {
				preview := stmt
				if len(preview) > 60 {
					preview = preview[:60]
				}
				t.Errorf("schemaUpdate %q: unexpected error: %v",
					strings.TrimSpace(preview), err)
			}
		}
	}
}
