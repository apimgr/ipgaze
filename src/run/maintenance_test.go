package run

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/db"
	"github.com/apimgr/ipgaze/src/paths"
	"github.com/apimgr/ipgaze/src/pgp"
	"github.com/apimgr/ipgaze/src/security"
)

// openTestDB returns an in-memory sqlite database with the full application
// schema applied, for exercising maintenance-command DB logic in isolation.
func openTestDB(t *testing.T) *db.Store {
	t.Helper()
	conn, err := db.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	if err := db.EnsureSchema(conn); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return conn
}

func TestRemoteDatabaseHasDataDistinguishesSchemaDefaultsFromUserState(t *testing.T) {
	conn := openTestDB(t)
	hasData, err := remoteDatabaseHasData(conn)
	if err != nil || hasData {
		t.Fatalf("empty database hasData = %v, err=%v; want false, nil", hasData, err)
	}
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES('restored-owner')`); err != nil {
		t.Fatal(err)
	}
	hasData, err = remoteDatabaseHasData(conn)
	if err != nil || !hasData {
		t.Fatalf("database with an owner hasData = %v, err=%v; want true, nil", hasData, err)
	}
}

func ensureTestOwner(t *testing.T, conn *db.Store, owner string) {
	t.Helper()
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES(?) ON CONFLICT(id) DO NOTHING`, owner); err != nil {
		t.Fatal(err)
	}
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
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES ('owner-token-test')`); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO api_tokens (id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES ('00000000-0000-7000-8000-000000000001','owner-token-test','primary','h','own_test','last','encrypted')`); err != nil {
		t.Fatalf("insert api_tokens: %v", err)
	}
	if isDatabaseEmpty(conn) {
		t.Error("isDatabaseEmpty with token row = true, want false")
	}
}

func TestIsDatabaseEmpty_MissingTable(t *testing.T) {
	conn, err := db.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = conn.Close() }()
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
	logsDir := t.TempDir()
	out := captureStdout(func() { maintenanceCompliance(nil, cfg, logsDir, nil) })
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
	logsDir := t.TempDir()
	out := captureStdout(func() { maintenanceCompliance([]string{"report"}, cfg, logsDir, nil) })
	if !strings.Contains(out, "IPGaze Compliance Report") {
		t.Errorf("output missing report header: %q", out)
	}
}

func TestComplianceCountsAreOwnerScopedAndExcludeClosedReports(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES ('owner-a'), ('owner-b')`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO api_tokens(id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES ('00000000-0000-7000-8000-000000000002','owner-a','primary','h-a','prefix-a','last','enc')`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO security_reports(tracking_id, severity, component, body_enc, body_alg, token_hash, closed_at) VALUES ('open','low','api',X'00','aes-256-gcm','h1',NULL), ('closed','low','api',X'00','aes-256-gcm','h2',1)`); err != nil {
		t.Fatal(err)
	}
	owners, tokens, reports, err := complianceCounts(conn)
	if err != nil {
		t.Fatal(err)
	}
	if owners != 2 || tokens != 1 || reports != 1 {
		t.Fatalf("counts = owners:%d tokens:%d reports:%d", owners, tokens, reports)
	}
}

func TestVerifyAuditLogIntegrityChecksHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	first := `{"prev":"` + strings.Repeat("0", 64) + `","event":"one"}`
	if err := os.WriteFile(path, []byte(first+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entries, brokenLine, err := verifyAuditLogIntegrity(path)
	if err != nil || entries != 1 || brokenLine != 0 {
		t.Fatalf("valid one-entry chain = (%d,%d,%v)", entries, brokenLine, err)
	}
	if err := os.WriteFile(path, []byte(first+"\n"+`{"prev":"wrong","event":"two"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entries, brokenLine, err = verifyAuditLogIntegrity(path)
	if err != nil || entries != 2 || brokenLine != 2 {
		t.Fatalf("broken chain = (%d,%d,%v), want broken line 2", entries, brokenLine, err)
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
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES ('owner-active'), ('owner-revoked')`); err != nil {
		t.Fatalf("insert owners: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO api_tokens (id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES ('00000000-0000-7000-8000-000000000003','owner-active','primary','h1','abc123','last','encrypted')`); err != nil {
		t.Fatalf("insert active token: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO api_tokens (id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc, revoked_at) VALUES ('00000000-0000-7000-8000-000000000004','owner-revoked','primary','h2','def456','last','encrypted', 1)`); err != nil {
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
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES ('owner-revoke-test')`); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	ensureTestOwner(t, conn, "owner-revoke-test")
	if _, err := conn.Exec(`INSERT INTO api_tokens (id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES ('00000000-0000-7000-8000-000000000005','owner-revoke-test','primary','h1','xyz789','last','encrypted')`); err != nil {
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

func TestMaintenanceDataExport_WritesOwnerScopedDisclosure(t *testing.T) {
	conn := openTestDB(t)
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES ('owner-export-test')`); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	ensureTestOwner(t, conn, "owner-export-test")
	if _, err := conn.Exec(`INSERT INTO api_tokens (id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES ('00000000-0000-7000-8000-000000000006','owner-export-test','primary','h1','abc','last','encrypted')`); err != nil {
		t.Fatalf("insert token: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO owners(id) VALUES ('owner-other-test')`); err != nil {
		t.Fatal(err)
	}
	ensureTestOwner(t, conn, "owner-other-test")
	if _, err := conn.Exec(`INSERT INTO api_tokens (id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES ('00000000-0000-7000-8000-000000000007','owner-other-test','primary','h2','other-prefix','last','other-encrypted')`); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "owner-export.json")
	if err := maintenanceDataExport(conn, "owner-export-test", outputPath, t.TempDir(), config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	var report map[string]any
	if err := json.Unmarshal(contents, &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, contents)
	}
	if report["format"] != float64(1) || report["owner"].(map[string]any)["id"] != "owner-export-test" {
		t.Errorf("unexpected owner disclosure: %v", report)
	}
	if report["resources"].([]any) == nil || len(report["resources"].([]any)) != 0 {
		t.Errorf("resources = %v, want empty list for this stateless product", report["resources"])
	}
	if strings.Contains(string(contents), "encrypted") || !strings.Contains(string(contents), "abc") {
		t.Errorf("export leaked token material or omitted prefix: %s", contents)
	}
	if strings.Contains(string(contents), "owner-other-test") || strings.Contains(string(contents), "other-prefix") {
		t.Errorf("export included another owner's data: %s", contents)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("export permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestMaintenanceDataDelete_DeletesOnlyOwnerAndTokens(t *testing.T) {
	conn := openTestDB(t)
	for _, owner := range []string{"owner-delete-test", "owner-keep-test"} {
		if _, err := conn.Exec(`INSERT INTO owners(id) VALUES (?)`, owner); err != nil {
			t.Fatal(err)
		}
		ensureTestOwner(t, conn, owner)
		tokenID, idErr := uuid.NewV7()
		if idErr != nil {
			t.Fatal(idErr)
		}
		if _, err := conn.Exec(`INSERT INTO api_tokens(id,owner_id, kind, token_hash, token_prefix, token_last4, token_enc) VALUES (?, ?, 'primary', ?, ?, 'last', 'encrypted')`, tokenID.String(), owner, owner+"-hash", owner+"-prefix"); err != nil {
			t.Fatal(err)
		}
	}
	if err := maintenanceDataDelete(conn, "owner-delete-test", t.TempDir(), config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	var owners, tokens int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM owners WHERE id = 'owner-delete-test'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE owner_id = 'owner-delete-test'`).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if owners != 0 || tokens != 0 {
		t.Fatalf("deleted owner/tokens remain: %d/%d", owners, tokens)
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM owners WHERE id = 'owner-keep-test'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Fatalf("unrelated owner count = %d, want 1", owners)
	}
	var auditCount int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 0 {
		t.Errorf("data deletion rewrote the append-only database audit log: count %d", auditCount)
	}
	var rateLimits int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM rate_limits`).Scan(&rateLimits); err != nil {
		t.Fatal(err)
	}
	if rateLimits != 0 {
		t.Errorf("unexpected rate-limit rows: %d", rateLimits)
	}
	if _, err := conn.Exec(`INSERT INTO rate_limits(key, count) VALUES('preserve','1')`); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM rate_limits`).Scan(&rateLimits); err != nil || rateLimits != 1 {
		t.Errorf("operational data unexpectedly affected: count=%d err=%v", rateLimits, err)
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
	defer func() { _ = conn.Close() }()
	if !isDatabaseEmpty(conn) {
		t.Error("freshly created db reported non-empty")
	}
}

func TestMaintenanceBackupTestDecryptsExtractedKey(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	dirs := paths.Directories{Data: tmpDir, DB: filepath.Join(tmpDir, "db")}
	cfg := config.DefaultConfig()
	cfg.Server.Database.Driver = "sqlite"
	conn, err := openMaintenanceDB(cfg, dirs)
	if err != nil {
		t.Fatalf("openMaintenanceDB: %v", err)
	}
	secret, err := security.GetOrCreateSecret(conn, security.SecretInstallationSecret)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("GetOrCreateSecret: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	keypair, err := pgp.Generate("IPGaze", "security@example.test")
	if err != nil {
		t.Fatalf("generate PGP keypair: %v", err)
	}
	cfg.Server.Security.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	serverYAML := "server:\n  security:\n    encryption_key: " + cfg.Server.Security.EncryptionKey + "\n"
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "server.yml"), []byte(serverYAML), 0600); err != nil {
		t.Fatalf("write server.yml: %v", err)
	}
	if err := pgp.SaveKeypair(configDir, keypair, secret); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}
	archivePath := filepath.Join(tmpDir, "backup.tar.gz")
	if err := maintenanceBackup(cfg, configDir, tmpDir, dirs.DB, archivePath, true, true, false, nil); err != nil {
		t.Fatalf("maintenanceBackup: %v", err)
	}
	if err := maintenanceBackupTest(configDir, cfg, dirs, archivePath); err != nil {
		t.Fatalf("maintenanceBackupTest: %v", err)
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
	if err := pgp.SaveKeypair(configDir, kp, oldSecret); err != nil {
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

	rotateEncryptionKey(openTestDB(t), t.TempDir(), cfg, nil)

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

func TestSecurityReportMaintenanceHelpers(t *testing.T) {
	handleSecurityMaintenance([]string{"help"}, "", nil)
	id, status, comment, date, err := parseSecurityReportUpdateArgs([]string{"sec_test", "--status", "disclosed", "--disclosure-date", "2027-02-03", "--comment", "Fix released"})
	if err != nil || id != "sec_test" || status == nil || *status != "disclosed" || comment == nil || *comment != "Fix released" || date == nil || date.Format("2006-01-02") != "2027-02-03" {
		t.Fatalf("parsed update args = (%q, %v, %v, %v, %v)", id, status, comment, date, err)
	}
	if _, _, _, _, err := parseSecurityReportUpdateArgs([]string{"sec_test"}); err == nil {
		t.Fatal("update without fields was accepted")
	}
	if filter, err := parseSecurityListArgs([]string{"--status", "triaged"}); err != nil || filter != "triaged" {
		t.Fatalf("status filter = %q, %v; want triaged", filter, err)
	}

	conn := openTestDB(t)
	if err := security.StoreSecurityReport(conn, security.SecurityReportMetadata{
		TrackingID: "sec_list", Ciphertext: []byte("encrypted private report"), Encryption: "aes-256-gcm",
		Severity: "high", AffectedComponent: "api", AccessTokenHash: "hash",
	}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := listSecurityReports(conn, &output, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "sec_list") || !strings.Contains(output.String(), "received") || strings.Contains(output.String(), "encrypted private report") {
		t.Errorf("security report list exposed unexpected data: %q", output.String())
	}
	var details bytes.Buffer
	if err := showSecurityReport(conn, &details, "sec_list"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details.String(), "Tracking ID: sec_list") || strings.Contains(details.String(), "encrypted private report") {
		t.Errorf("security report show exposed unexpected data: %q", details.String())
	}
	newComment := "Investigating fix"
	oldStatus, newStatus, err := security.UpdateSecurityReport(conn, "sec_list", nil, &newComment, nil, time.Now())
	if err != nil || oldStatus != "received" || newStatus != "received" {
		t.Fatalf("comment update status = %q → %q, %v", oldStatus, newStatus, err)
	}
}

func TestMaintenanceOperatorIP(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "2001:db8::1 43210 22")
	t.Setenv("SSH_CLIENT", "192.0.2.44 43210 22")
	if got := maintenanceOperatorIP(); got != "2001:db8::1" {
		t.Errorf("maintenanceOperatorIP() = %q, want SSH client address", got)
	}
	t.Setenv("SSH_CONNECTION", "")
	if got := maintenanceOperatorIP(); got != "192.0.2.44" {
		t.Errorf("maintenanceOperatorIP() fallback = %q, want SSH_CLIENT address", got)
	}
	t.Setenv("SSH_CLIENT", "")
	if got := maintenanceOperatorIP(); got != "127.0.0.1" {
		t.Errorf("maintenanceOperatorIP() local = %q, want loopback", got)
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
	if !strings.HasPrefix(tok1, "adm_") {
		t.Errorf("token %q missing adm_ prefix", tok1)
	}
	tok2, err := generateOperatorToken()
	if err != nil {
		t.Fatalf("generateOperatorToken: %v", err)
	}
	if tok1 == tok2 {
		t.Error("two generated tokens were identical")
	}
	metricsToken, err := generateTokenWithPrefix("mtr")
	if err != nil {
		t.Fatalf("generateTokenWithPrefix: %v", err)
	}
	if !strings.HasPrefix(metricsToken, "mtr_") {
		t.Errorf("metrics token %q missing mtr_ prefix", metricsToken)
	}
}

func TestParseEmailTestArgs_DefaultAndExplicitRecipients(t *testing.T) {
	options, err := parseEmailTestArgs([]string{"test"}, "operator@example.test", "en")
	if err != nil {
		t.Fatal(err)
	}
	if options.recipient != "operator@example.test" || options.dryRun {
		t.Fatalf("options = %#v", options)
	}
	options, err = parseEmailTestArgs([]string{"test", "--to", "other@example.test", "--dry-run"}, "", "en")
	if err != nil {
		t.Fatal(err)
	}
	if options.recipient != "other@example.test" || !options.dryRun {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseEmailTestArgs_RequiresRecipientForSend(t *testing.T) {
	if _, err := parseEmailTestArgs([]string{"test"}, "", "en"); err == nil {
		t.Fatal("missing recipient accepted")
	}
	if _, err := parseEmailTestArgs([]string{"test", "--to", "bad address"}, "", "en"); err == nil {
		t.Fatal("invalid recipient accepted")
	}
}

func TestParseEmailTestArgs_RejectsUnknownOperation(t *testing.T) {
	if _, err := parseEmailTestArgs([]string{"send"}, "operator@example.test", "en"); err == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestEmailTestSampleVariablesUsesConfiguredIdentity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Branding.Title = "Test IPGaze"
	cfg.Server.FQDN = "ips.example.test"
	cfg.Server.Notifications.Email.ReplyTo = "ops@example.test"
	variables := emailTestSampleVariables(cfg)
	if variables["app_name"] != "Test IPGaze" || variables["app_url"] != "https://ips.example.test" || variables["notification_reply_to"] != "ops@example.test" {
		t.Fatalf("sample variables = %#v", variables)
	}
}

func TestBackupTestSkippedReportsEachDependentCheck(t *testing.T) {
	out := captureStdout(func() {
		reportBackupTestSkipped("archive decryption failed", "Manifest", "Manifest checksums", "PGP fingerprint match")
	})
	for _, expected := range []string{
		"Manifest: NOT CHECKED (archive decryption failed)",
		"Manifest checksums: NOT CHECKED (archive decryption failed)",
		"PGP fingerprint match: NOT CHECKED (archive decryption failed)",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("backup test skip report missing %q: %q", expected, out)
		}
	}
}
