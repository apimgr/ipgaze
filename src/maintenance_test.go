package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/db"
	paths "github.com/apimgr/ipgaze/src/path"
	"github.com/apimgr/ipgaze/src/pgp"
	"github.com/apimgr/ipgaze/src/security"
)

// openTestDB returns an in-memory sqlite database with the full application
// schema applied, for exercising maintenance-command DB logic in isolation.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.EnsureSchema(conn); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return conn
}

func TestIsDatabaseEmpty_EmptyDatabase(t *testing.T) {
	conn := openTestDB(t)
	if !isDatabaseEmpty(conn) {
		t.Error("isDatabaseEmpty on fresh schema = false, want true")
	}
}

func TestIsDatabaseEmpty_WithAuditRow(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO audit_log (category, action) VALUES ('x','y')`); err != nil {
		t.Fatalf("insert audit_log: %v", err)
	}
	if isDatabaseEmpty(conn) {
		t.Error("isDatabaseEmpty with audit row = true, want false")
	}
}

func TestIsDatabaseEmpty_WithTokenRow(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO api_tokens (token_hash, token_prefix, resource_type, resource_id) VALUES ('h','p','t','r')`); err != nil {
		t.Fatalf("insert api_tokens: %v", err)
	}
	if isDatabaseEmpty(conn) {
		t.Error("isDatabaseEmpty with token row = true, want false")
	}
}

func TestIsDatabaseEmpty_MissingTable(t *testing.T) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer conn.Close()
	if isDatabaseEmpty(conn) {
		t.Error("isDatabaseEmpty on schemaless db = true, want false")
	}
}

func TestMaintenanceMode_NoArgs_DefaultsToProduction(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Mode = ""
	out := captureStdout(func() { maintenanceMode(nil, cfg) })
	if !strings.Contains(out, "Current mode: production") {
		t.Errorf("output = %q, want it to contain 'Current mode: production'", out)
	}
}

func TestMaintenanceMode_NoArgs_ReportsConfiguredMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Mode = "development"
	out := captureStdout(func() { maintenanceMode(nil, cfg) })
	if !strings.Contains(out, "Current mode: development") {
		t.Errorf("output = %q, want it to contain 'Current mode: development'", out)
	}
}

func TestMaintenanceCompliance_ReportsConfiguredValues(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Compliance.Enabled = true
	cfg.Server.Privacy.Data.Sold = false
	cfg.Server.Privacy.Retention.Period = "90d"
	out := captureStdout(func() { maintenanceCompliance(nil, cfg) })
	if !strings.Contains(out, "IPGaze Compliance Report") {
		t.Errorf("output missing report header: %q", out)
	}
	if !strings.Contains(out, "Compliance mode enabled:  true") {
		t.Errorf("output missing compliance flag: %q", out)
	}
	if !strings.Contains(out, "Retention period:  90d") {
		t.Errorf("output missing retention period: %q", out)
	}
}

func TestMaintenanceCompliance_ReportSubcommandAccepted(t *testing.T) {
	cfg := config.DefaultConfig()
	out := captureStdout(func() { maintenanceCompliance([]string{"report"}, cfg) })
	if !strings.Contains(out, "IPGaze Compliance Report") {
		t.Errorf("output missing report header: %q", out)
	}
}

func TestMaintenanceTokenList_EmptyDatabase(t *testing.T) {
	conn := openTestDB(t)
	out := captureStdout(func() { maintenanceTokenList(conn) })
	if !strings.Contains(out, "No tokens found.") {
		t.Errorf("output = %q, want it to contain 'No tokens found.'", out)
	}
}

func TestMaintenanceTokenList_ListsActiveAndRevoked(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO api_tokens (token_hash, token_prefix, resource_type, resource_id) VALUES ('h1','abc123','cli','op')`); err != nil {
		t.Fatalf("insert active token: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO api_tokens (token_hash, token_prefix, resource_type, resource_id, revoked_at) VALUES ('h2','def456','cli','op', 1)`); err != nil {
		t.Fatalf("insert revoked token: %v", err)
	}
	out := captureStdout(func() { maintenanceTokenList(conn) })
	if !strings.Contains(out, "abc123") || !strings.Contains(out, "active") {
		t.Errorf("output missing active token row: %q", out)
	}
	if !strings.Contains(out, "def456") || !strings.Contains(out, "revoked") {
		t.Errorf("output missing revoked token row: %q", out)
	}
}

func TestMaintenanceTokenRevoke_UnknownPrefix(t *testing.T) {
	conn := openTestDB(t)
	logsDir := t.TempDir()
	cfg := config.DefaultConfig()
	out := captureStdout(func() { maintenanceTokenRevoke(conn, "nosuch", logsDir, cfg) })
	if !strings.Contains(out, `No active token found with prefix "nosuch"`) {
		t.Errorf("output = %q, want unknown-prefix message", out)
	}
}

func TestMaintenanceTokenRevoke_RevokesMatchingToken(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO api_tokens (token_hash, token_prefix, resource_type, resource_id) VALUES ('h1','xyz789','cli','op')`); err != nil {
		t.Fatalf("insert token: %v", err)
	}
	logsDir := t.TempDir()
	cfg := config.DefaultConfig()
	out := captureStdout(func() { maintenanceTokenRevoke(conn, "xyz789", logsDir, cfg) })
	if !strings.Contains(out, "Token xyz789 revoked.") {
		t.Errorf("output = %q, want revocation confirmation", out)
	}
	var revokedAt sql.NullInt64
	if err := conn.QueryRow(`SELECT revoked_at FROM api_tokens WHERE token_prefix = 'xyz789'`).Scan(&revokedAt); err != nil {
		t.Fatalf("query revoked_at: %v", err)
	}
	if !revokedAt.Valid {
		t.Error("revoked_at not set after revoke")
	}
}

func TestMaintenanceDataExport_ReportsTableCountsAndPolicy(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO api_tokens (token_hash, token_prefix, resource_type, resource_id) VALUES ('h1','abc','cli','op')`); err != nil {
		t.Fatalf("insert token: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Server.Privacy.Data.Sold = false
	cfg.Server.Privacy.Retention.Period = "30d"
	out := captureStdout(func() { maintenanceDataExport(conn, cfg) })

	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}
	policy, ok := report["privacy_policy"].(map[string]any)
	if !ok {
		t.Fatalf("privacy_policy missing or wrong type: %v", report["privacy_policy"])
	}
	if policy["retention_period"] != "30d" {
		t.Errorf("retention_period = %v, want 30d", policy["retention_period"])
	}
	counts, ok := report["table_row_counts"].(map[string]any)
	if !ok {
		t.Fatalf("table_row_counts missing or wrong type: %v", report["table_row_counts"])
	}
	if counts["api_tokens"] != float64(1) {
		t.Errorf("table_row_counts[api_tokens] = %v, want 1", counts["api_tokens"])
	}
}

func TestMaintenanceDataDelete_CancelledWithoutConfirmation(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO rate_limits (key, count) VALUES ('1.2.3.4','1')`); err != nil {
		t.Fatalf("insert rate_limits: %v", err)
	}
	logsDir := t.TempDir()
	cfg := config.DefaultConfig()

	// requireTypedConfirmation reads from os.Stdin; with nothing piped in the
	// test process it reads EOF immediately, which never matches the expected
	// phrase, exercising the "cancelled" branch without any os.Exit path.
	out := captureStdout(func() { maintenanceDataDelete(conn, logsDir, cfg) })
	if !strings.Contains(out, "Data delete cancelled.") {
		t.Errorf("output = %q, want cancellation message", out)
	}
	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM rate_limits`).Scan(&count); err != nil {
		t.Fatalf("count rate_limits: %v", err)
	}
	if count != 1 {
		t.Errorf("rate_limits count = %d, want 1 (delete should have been cancelled)", count)
	}
}

func TestBuildLogConfig_MapsLoggingFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Logging.Level = "debug"
	cfg.Server.Logging.Access.Filename = "access.log"
	lc := buildLogConfig(cfg)
	if lc.Level != "debug" {
		t.Errorf("Level = %q, want debug", lc.Level)
	}
	if lc.Access.Filename != "access.log" {
		t.Errorf("Access.Filename = %q, want access.log", lc.Access.Filename)
	}
}

func TestRequireTypedConfirmation_EOFReturnsFalse(t *testing.T) {
	out := captureStdout(func() {
		if requireTypedConfirmation("EXPECTED PHRASE", "confirm: ") {
			t.Error("requireTypedConfirmation with no stdin input = true, want false")
		}
	})
	if !strings.Contains(out, "confirm: ") {
		t.Errorf("output = %q, want prompt to be printed", out)
	}
}

func TestOpenMaintenanceDB_CreatesSqliteFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Server.Database.Driver = "sqlite"
	// openMaintenanceDB resolves the sqlite path from dirs.Data (NewDB
	// appends "db/server.db"), so Data must point at the tempdir. Setting
	// only DB left Data empty, causing NewDB to create db/server.db relative
	// to the test's working directory (src/db/server.db) instead.
	dirs := paths.Directories{Data: tmpDir, DB: filepath.Join(tmpDir, "db")}

	conn, err := openMaintenanceDB(cfg, dirs)
	if err != nil {
		t.Fatalf("openMaintenanceDB: %v", err)
	}
	defer conn.Close()
	if !isDatabaseEmpty(conn) {
		t.Error("freshly created db reported non-empty")
	}
}

// TestRotateInstallationSecret_ReencryptsPGPKey covers the installation_secret
// branch of `--maintenance secret rotate` (AI.md PART 11 "Secret Rotation"):
// the secret must change and the on-disk PGP private key must remain
// decryptable, now under the new secret.
func TestRotateInstallationSecret_ReencryptsPGPKey(t *testing.T) {
	conn := openTestDB(t)
	configDir := t.TempDir()

	oldSecret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		t.Fatalf("GetOrCreateSecret: %v", err)
	}

	const wantArmor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----\n"
	kp := &pgp.Keypair{PublicArmor: "pub", PrivateArmor: wantArmor}
	if err := pgp.Save(configDir, kp, oldSecret); err != nil {
		t.Fatalf("pgp.Save: %v", err)
	}

	rotateInstallationSecret(conn, configDir, nil)

	newSecret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		t.Fatalf("GetOrCreateSecret after rotate: %v", err)
	}
	if string(newSecret) == string(oldSecret) {
		t.Fatal("installation_secret did not change after rotation")
	}

	gotArmor, err := pgp.LoadPrivateArmor(configDir, newSecret)
	if err != nil {
		t.Fatalf("LoadPrivateArmor with new secret: %v", err)
	}
	if gotArmor != wantArmor {
		t.Errorf("re-encrypted private key = %q, want %q", gotArmor, wantArmor)
	}
}

// TestRotateEncryptionKey_RotatesAndPersists covers the encryption_key branch
// of `--maintenance secret rotate` (AI.md PART 11 "Secret Rotation"): the key
// must change, the previous key must be retained with a grace window, and
// the result must be persisted to server.yml.
func TestRotateEncryptionKey_RotatesAndPersists(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "server.yml")
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}

	oldKey := make([]byte, 32)
	oldKeyB64 := base64.StdEncoding.EncodeToString(oldKey)
	cfg.Server.Security.EncryptionKey = oldKeyB64

	rotateEncryptionKey(t.TempDir(), cfg, nil)

	if cfg.Server.Security.EncryptionKey == oldKeyB64 {
		t.Fatal("encryption_key did not change after rotation")
	}
	if cfg.Server.Security.PreviousEncryptionKey != oldKeyB64 {
		t.Errorf("previous_encryption_key = %q, want %q", cfg.Server.Security.PreviousEncryptionKey, oldKeyB64)
	}
	if cfg.Server.Security.PreviousEncryptionKeyUntil <= time.Now().Unix() {
		t.Error("previous_encryption_key_until is not in the future")
	}

	reloaded, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if reloaded.Server.Security.EncryptionKey != cfg.Server.Security.EncryptionKey {
		t.Error("rotated encryption_key was not persisted to server.yml")
	}
}

func TestPgpExportMarkerPath_JoinsConfigDir(t *testing.T) {
	got := pgpExportMarkerPath("/etc/ipgaze")
	want := filepath.Join("/etc/ipgaze", "security", ".private_key_export_at")
	if got != want {
		t.Errorf("pgpExportMarkerPath = %q, want %q", got, want)
	}
}

func TestPgpExportRateLimitRemaining_NoMarker(t *testing.T) {
	if remaining := pgpExportRateLimitRemaining(t.TempDir()); remaining != 0 {
		t.Errorf("remaining = %v, want 0 when no marker exists", remaining)
	}
}

func TestPgpMarkExportTimestamp_ThenRateLimited(t *testing.T) {
	configDir := t.TempDir()

	pgpMarkExportTimestamp(configDir)

	if _, err := os.Stat(pgpExportMarkerPath(configDir)); err != nil {
		t.Fatalf("marker file was not created: %v", err)
	}

	remaining := pgpExportRateLimitRemaining(configDir)
	if remaining <= 0 || remaining > time.Hour {
		t.Errorf("remaining = %v, want between 0 and 1h just after marking", remaining)
	}
}

func TestOldRecFingerprint(t *testing.T) {
	if got := oldRecFingerprint(nil); got != "" {
		t.Errorf("oldRecFingerprint(nil) = %q, want empty string", got)
	}
	rec := &pgp.Record{Fingerprint: "ABCD1234"}
	if got := oldRecFingerprint(rec); got != "ABCD1234" {
		t.Errorf("oldRecFingerprint = %q, want %q", got, "ABCD1234")
	}
}

func TestGenerateOperatorToken_UniqueAndPrefixed(t *testing.T) {
	tok1, err := generateOperatorToken()
	if err != nil {
		t.Fatalf("generateOperatorToken: %v", err)
	}
	if !strings.HasPrefix(tok1, "tok_") {
		t.Errorf("token %q missing tok_ prefix", tok1)
	}
	tok2, err := generateOperatorToken()
	if err != nil {
		t.Fatalf("generateOperatorToken: %v", err)
	}
	if tok1 == tok2 {
		t.Error("two generated tokens were identical")
	}
}
