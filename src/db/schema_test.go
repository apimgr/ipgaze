package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// openMemDB opens an in-memory SQLite database via the pure-Go driver.
func openMemDB(t *testing.T) *Store {
	t.Helper()
	db, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
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
		"rate_limits",
		"audit_log",
		"scheduler_tasks",
		"scheduler_history",
		"backups",
		"owners",
		"api_tokens",
		"captcha_challenges",
	}
	for _, tbl := range expected {
		var name string
		row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl)
		if err := row.Scan(&name); err != nil {
			t.Errorf("table %q not found after EnsureSchema: %v", tbl, err)
		}
	}
}

func TestEnsureSchemaMigratesLegacyAppSecretRotationRows(t *testing.T) {
	db := openMemDB(t)
	if _, err := db.Exec(`CREATE TABLE app_secrets(name TEXT PRIMARY KEY, value TEXT NOT NULL, previous_value TEXT, previous_until INTEGER, created_at INTEGER, rotated_at INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO app_secrets(name, value, previous_value, previous_until, rotated_at) VALUES('installation_secret', 'current', 'previous', 1790000000, 1780000000)`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"installation_secret":                "current",
		"installation_secret_previous":       "previous",
		"installation_secret_previous_until": "2026-09-21T14:13:20Z",
	} {
		var got string
		if err := db.QueryRow(`SELECT value FROM app_secrets WHERE name = ?`, name).Scan(&got); err != nil {
			t.Fatalf("read migrated %s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	rows, err := db.Query(`PRAGMA table_info(app_secrets)`)
	if err != nil {
		t.Fatal(err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(columns) != 3 || !columns["name"] || !columns["value"] || !columns["updated_at"] {
		t.Errorf("canonical app_secrets columns = %#v", columns)
	}
}

func TestEnsureSchemaDoesNotCreateConfigurationTables(t *testing.T) {
	db := openMemDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	for _, table := range []string{"config", "config_meta"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			t.Fatalf("check %s table: %v", table, err)
		}
		if count != 0 {
			t.Errorf("configuration table %q was created; configuration belongs in files", table)
		}
	}
}

func TestEnsureSchemaPreservesLegacyConfigurationTableData(t *testing.T) {
	db := openMemDB(t)
	for _, statement := range []string{
		`CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE config_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO config(key,value) VALUES('server.port','64580')`,
		`INSERT INTO config_meta(key,value) VALUES('schema_version','1')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("prepare legacy configuration state: %v", err)
		}
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	for _, test := range []struct {
		table string
		key   string
		want  string
	}{
		{table: "config", key: "server.port", want: "64580"},
		{table: "config_meta", key: "schema_version", want: "1"},
	} {
		var got string
		query := `SELECT value FROM ` + test.table + ` WHERE key=?`
		if err := db.QueryRow(query, test.key).Scan(&got); err != nil {
			t.Fatalf("read preserved legacy %s value: %v", test.table, err)
		}
		if got != test.want {
			t.Errorf("legacy %s value = %q, want %q", test.table, got, test.want)
		}
	}
}

func TestEnsureSchemaPreservesLegacyCaptchaChallenges(t *testing.T) {
	db := openMemDB(t)
	if _, err := db.Exec(`CREATE TABLE contact_captcha_challenges (
		token_hash TEXT PRIMARY KEY, answer_hash TEXT NOT NULL,
		created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER
	)`); err != nil {
		t.Fatalf("create legacy captcha table: %v", err)
	}
	if _, err := db.Exec(`CREATE INDEX idx_contact_captcha_challenges_expires ON contact_captcha_challenges(expires_at)`); err != nil {
		t.Fatalf("create legacy captcha index: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO contact_captcha_challenges VALUES ('legacy', 'answer', 1, 2, NULL)`); err != nil {
		t.Fatalf("insert legacy captcha row: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='contact_captcha_challenges'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("legacy captcha table was not preserved")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM contact_captcha_challenges WHERE token_hash='legacy'`).Scan(&count); err != nil {
		t.Fatalf("query preserved legacy captcha row: %v", err)
	}
	if count != 1 {
		t.Fatalf("legacy captcha table contains %d preserved rows, want 1", count)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("second EnsureSchema: %v", err)
	}
}

func TestEnsureSchemaUsesUUIDv7TextTokenIDs(t *testing.T) {
	store := openMemDB(t)
	if err := EnsureSchema(store); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	rows, err := store.Query(`PRAGMA table_info(api_tokens)`)
	if err != nil {
		t.Fatal(err)
	}
	var idType string
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			t.Fatal(err)
		}
		if name == "id" {
			idType = strings.ToUpper(kind)
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(idType, "TEXT") {
		t.Fatalf("api_tokens.id type = %q, want TEXT", idType)
	}
}

func TestEnsureSchemaAddsTokenScopeAndPromotesPrimaryTokens(t *testing.T) {
	store := openMemDB(t)
	if _, err := store.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`CREATE TABLE api_tokens (
		id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES owners(id), kind TEXT NOT NULL,
		name TEXT, token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL,
		token_last4 TEXT NOT NULL, token_enc TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 1,
		rotated_at INTEGER, expires_at INTEGER, last_used_at INTEGER, revoked_at INTEGER, revoked_reason TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`INSERT INTO owners(id) VALUES('scope-owner')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`INSERT INTO api_tokens(id,owner_id,kind,token_hash,token_prefix,token_last4,token_enc) VALUES('scope-primary','scope-owner','primary','scope-hash','own_scope','last','enc')`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(store); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var scope string
	if err := store.QueryRow(`SELECT scope FROM api_tokens WHERE id='scope-primary'`).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if scope != "global" {
		t.Fatalf("migrated primary scope = %q, want global", scope)
	}
	if _, err := store.Exec(`INSERT INTO api_tokens(id,owner_id,kind,token_hash,token_prefix,token_last4,token_enc) VALUES('scope-linked','scope-owner','linked','scope-hash-2','own_scope2','last','enc')`); err != nil {
		t.Fatalf("linked token default scope: %v", err)
	}
	if err := store.QueryRow(`SELECT scope FROM api_tokens WHERE id='scope-linked'`).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if scope != "read-write" {
		t.Fatalf("default linked scope = %q, want read-write", scope)
	}
}

func TestEnsureSchemaPreservesLegacyIntegerTokenIDs(t *testing.T) {
	store := openMemDB(t)
	if _, err := store.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL DEFAULT 0, last_seen_at INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`CREATE TABLE api_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id TEXT NOT NULL REFERENCES owners(id), kind TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'read-write', name TEXT, token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL, token_last4 TEXT NOT NULL, token_enc TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 1, rotated_at INTEGER, expires_at INTEGER, last_used_at INTEGER, revoked_at INTEGER, revoked_reason TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`INSERT INTO owners(id) VALUES('legacy-owner')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`INSERT INTO api_tokens(owner_id,kind,scope,token_hash,token_prefix,token_last4,token_enc) VALUES('legacy-owner','primary','global','legacy-hash','own_prefix','last','enc')`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(store); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var id int64
	var publicID, owner, hash string
	if err := store.QueryRow(`SELECT id,public_id,owner_id,token_hash FROM api_tokens`).Scan(&id, &publicID, &owner, &hash); err != nil {
		t.Fatal(err)
	}
	parsed, err := uuid.Parse(publicID)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("public_id = %q, want UUIDv7: %v", publicID, err)
	}
	if id != 1 || owner != "legacy-owner" || hash != "legacy-hash" {
		t.Fatalf("legacy row changed: id=%d owner=%q hash=%q", id, owner, hash)
	}
	if store.APITokenIDColumn() != "public_id" {
		t.Fatalf("token id column = %q, want public_id", store.APITokenIDColumn())
	}
	if err := EnsureSchema(store); err != nil {
		t.Fatalf("second EnsureSchema: %v", err)
	}
	var after int64
	if err := store.QueryRow(`SELECT id FROM api_tokens WHERE public_id = ?`, publicID).Scan(&after); err != nil || after != id {
		t.Fatalf("legacy id after repeat migration = %d, err=%v", after, err)
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

func TestEnsureSchema_AddsPreviousRateLimitWindow(t *testing.T) {
	db := openMemDB(t)
	if _, err := db.Exec(`CREATE TABLE rate_limits (
		key TEXT PRIMARY KEY,
		count INTEGER NOT NULL DEFAULT 1,
		window_start INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatalf("create legacy rate_limits table: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var previousCount int
	if err := db.QueryRow(`SELECT prev_count FROM rate_limits WHERE key='missing'`).Scan(&previousCount); err == nil {
		t.Fatal("unexpected row in empty rate_limits table")
	}
	if _, err := db.Exec(`INSERT INTO rate_limits (key) VALUES ('test')`); err != nil {
		t.Fatalf("insert rate limit row: %v", err)
	}
	if err := db.QueryRow(`SELECT prev_count FROM rate_limits WHERE key='test'`).Scan(&previousCount); err != nil {
		t.Fatalf("read previous count: %v", err)
	}
	if previousCount != 0 {
		t.Fatalf("prev_count = %d, want 0", previousCount)
	}
}

func TestEnsureSchemaRenamesCanonicalSchedulerColumnsInPlace(t *testing.T) {
	store := openMemDB(t)
	if _, err := store.Exec(`CREATE TABLE scheduler_tasks(task_id TEXT PRIMARY KEY, task_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, schedule TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`CREATE TABLE scheduler_history(id INTEGER PRIMARY KEY, task_id TEXT NOT NULL, ran_at INTEGER NOT NULL, status TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`INSERT INTO scheduler_tasks(task_id,task_name,schedule) VALUES('task-1','Legacy task','@every 1h'); INSERT INTO scheduler_history(task_id,ran_at,status) VALUES('task-1',123,'success')`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(store); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var name, schedule string
	if err := store.QueryRow(`SELECT name,schedule FROM scheduler_tasks WHERE id='task-1'`).Scan(&name, &schedule); err != nil {
		t.Fatal(err)
	}
	if name != "Legacy task" || schedule != "@every 1h" {
		t.Fatalf("renamed scheduler task = %q / %q", name, schedule)
	}
	var startedAt int64
	if err := store.QueryRow(`SELECT started_at FROM scheduler_history WHERE task_id='task-1'`).Scan(&startedAt); err != nil {
		t.Fatal(err)
	}
	if startedAt != 123 {
		t.Fatalf("renamed scheduler history timestamp = %d, want 123", startedAt)
	}
	for _, table := range []string{"scheduler_tasks", "scheduler_history"} {
		rows, err := store.QueryContext(context.Background(), `PRAGMA table_info(`+table+`)`)
		if err != nil {
			t.Fatal(err)
		}
		columns := make(map[string]bool)
		for rows.Next() {
			var cid, notNull, primaryKey int
			var columnName, kind string
			var defaultValue any
			if err := rows.Scan(&cid, &columnName, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			columns[columnName] = true
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if columns["task_id"] && table == "scheduler_tasks" || columns["task_name"] || columns["ran_at"] {
			t.Fatalf("legacy column remains in %s: %v", table, columns)
		}
	}
}

// All required indexes must be present.
func TestEnsureSchema_CreatesIndexes(t *testing.T) {
	db := openMemDB(t)

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	expected := []string{
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
		"idx_api_tokens_primary",
		"idx_api_tokens_linked_name",
		"idx_api_tokens_hash",
		"idx_api_tokens_prefix",
		"idx_api_tokens_owner",
		"idx_api_tokens_active",
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
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

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
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		_, err = db.Exec(
			`INSERT INTO api_tokens(id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES(?,?,?,?,?,?,?)`,
			id.String(), "owner-1", "primary", hash, prefix, "last", "encrypted")
		return err
	}
	if _, err := db.Exec(`INSERT INTO owners(id) VALUES(?)`, "owner-1"); err != nil {
		t.Fatalf("insert owner: %v", err)
	}

	if err := insert("hash-abc", "own_abc"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insert("hash-abc", "own_abc"); err == nil {
		t.Error("duplicate token_hash should have been rejected by UNIQUE constraint")
	}
}

func TestEnsureSchema_MigratesLegacyResourceTokensWithoutDiscardingRows(t *testing.T) {
	db := openMemDB(t)
	if _, err := db.Exec(`CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER,
    last_used_at INTEGER,
    revoked_at INTEGER,
    revoked_reason TEXT
)`); err != nil {
		t.Fatalf("create legacy token table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO api_tokens(token_hash, token_prefix, resource_type, resource_id) VALUES(?,?,?,?)`, "legacy-hash", "own_legacy", "lookup", "8.8.8.8"); err != nil {
		t.Fatalf("insert legacy token: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var got string
	var resourceType, resourceID string
	if err := db.QueryRow(`SELECT token_hash,resource_type,resource_id FROM api_tokens WHERE token_hash=?`, "legacy-hash").Scan(&got, &resourceType, &resourceID); err != nil {
		t.Fatalf("read preserved legacy token: %v", err)
	}
	if got != "legacy-hash" {
		t.Fatalf("preserved token hash = %q, want legacy-hash", got)
	}
	if resourceType != "lookup" || resourceID != "8.8.8.8" {
		t.Fatalf("preserved legacy resource = %q / %q, want lookup / 8.8.8.8", resourceType, resourceID)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("second EnsureSchema: %v", err)
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
