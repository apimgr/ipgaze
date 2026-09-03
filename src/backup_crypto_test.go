package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

// maliciousTarGz builds an in-memory tar.gz with a single entry whose name
// is a path-traversal attempt, to exercise extractBackupArchive's zip-slip guard.
func maliciousTarGz(t *testing.T, entryName string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := []byte("evil payload")
	if err := tw.WriteHeader(&tar.Header{Name: entryName, Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func TestEncryptDecryptBackupArchive_RoundTrip(t *testing.T) {
	plaintext := []byte("this is a fake tar.gz archive payload")
	enc, err := encryptBackupArchive(plaintext, "correct-password")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(enc) <= backupSaltLen+backupNonceLen {
		t.Fatalf("encrypted output too short: %d bytes", len(enc))
	}
	dec, err := decryptBackupArchive(enc, "correct-password")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(dec) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", dec, plaintext)
	}
}

func TestEncryptBackupArchive_EmptyPassword(t *testing.T) {
	if _, err := encryptBackupArchive([]byte("data"), ""); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestDecryptBackupArchive_WrongPassword(t *testing.T) {
	enc, err := encryptBackupArchive([]byte("secret data"), "right-password")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptBackupArchive(enc, "wrong-password"); err == nil {
		t.Fatal("expected error decrypting with wrong password")
	}
}

func TestDecryptBackupArchive_EmptyPassword(t *testing.T) {
	enc, err := encryptBackupArchive([]byte("secret data"), "right-password")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptBackupArchive(enc, ""); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestDecryptBackupArchive_TooShort(t *testing.T) {
	if _, err := decryptBackupArchive([]byte("short"), "password"); err == nil {
		t.Fatal("expected error for too-short input")
	}
}

func TestDecryptBackupArchive_CorruptedCiphertext(t *testing.T) {
	enc, err := encryptBackupArchive([]byte("secret data"), "right-password")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	enc[len(enc)-1] ^= 0xFF
	if _, err := decryptBackupArchive(enc, "right-password"); err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}

func TestDeriveBackupKey_DeterministicAndLength(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := deriveBackupKey("password", salt)
	k2 := deriveBackupKey("password", salt)
	if len(k1) != backupKeyLen {
		t.Fatalf("key length = %d, want %d", len(k1), backupKeyLen)
	}
	if string(k1) != string(k2) {
		t.Fatal("derived key not deterministic for same password/salt")
	}
	k3 := deriveBackupKey("different", salt)
	if string(k1) == string(k3) {
		t.Fatal("different passwords produced the same key")
	}
}

func TestPromptBackupPassword_NonTerminal(t *testing.T) {
	if _, err := promptBackupPassword("Password: "); err == nil {
		t.Fatal("expected error when stdin is not a terminal")
	}
}

func TestResolveBackupEncryptionPassword_NilConfig(t *testing.T) {
	pw, err := resolveBackupEncryptionPassword(nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "" {
		t.Fatalf("expected empty password, got %q", pw)
	}
}

func TestResolveBackupEncryptionPassword_Default(t *testing.T) {
	cfg := config.DefaultConfig()
	pw, err := resolveBackupEncryptionPassword(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "" {
		t.Fatalf("expected unencrypted default, got password %q", pw)
	}
}

func TestResolveBackupEncryptionPassword_ConfiguredNonInteractive(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Backup.Encryption.Enabled = true
	cfg.Server.Backup.Encryption.EncryptionPassword = "configured-pw"
	pw, err := resolveBackupEncryptionPassword(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "configured-pw" {
		t.Fatalf("password = %q, want configured-pw", pw)
	}
}

func TestResolveBackupEncryptionPassword_EnabledButNoPasswordNonInteractive(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Backup.Encryption.Enabled = true
	if _, err := resolveBackupEncryptionPassword(cfg, false); err == nil {
		t.Fatal("expected error when encryption enabled but no password configured, non-interactive")
	}
}

func TestResolveBackupEncryptionPassword_ComplianceBlocksUnencrypted(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Compliance.Enabled = true
	if _, err := resolveBackupEncryptionPassword(cfg, false); err == nil {
		t.Fatal("expected compliance mode to block unencrypted backups")
	}
}

func TestResolveBackupEncryptionPassword_ComplianceWithPasswordConfigured(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Compliance.Enabled = true
	cfg.Server.Backup.Encryption.Enabled = true
	cfg.Server.Backup.Encryption.EncryptionPassword = "compliance-pw"
	pw, err := resolveBackupEncryptionPassword(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "compliance-pw" {
		t.Fatalf("password = %q, want compliance-pw", pw)
	}
}

func TestBuildAndExtractBackupArchive_RoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	configDir := filepath.Join(srcDir, "config")
	dataDir := filepath.Join(srcDir, "data")
	dbDir := filepath.Join(srcDir, "db")
	if err := os.MkdirAll(filepath.Join(configDir, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatalf("mkdir db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "server.yml"), []byte("port: 8080\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "sub", "nested.yml"), []byte("nested: true\n"), 0o600); err != nil {
		t.Fatalf("write nested config file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "ipgaze.db"), []byte("fake db content"), 0o600); err != nil {
		t.Fatalf("write db file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "extra.dat"), []byte("data payload"), 0o600); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	layout := backupArchiveLayout{configDir: configDir, dataDir: dataDir, dbDir: dbDir, includeSSL: false, includeData: true}
	manifest := map[string]interface{}{"encrypted": false}
	archive, err := buildBackupArchive(manifest, layout)
	if err != nil {
		t.Fatalf("buildBackupArchive: %v", err)
	}
	if len(archive) == 0 {
		t.Fatal("archive is empty")
	}

	destDir := t.TempDir()
	if err := extractBackupArchive(archive, destDir); err != nil {
		t.Fatalf("extractBackupArchive: %v", err)
	}

	gotManifestBytes, err := os.ReadFile(filepath.Join(destDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read extracted manifest: %v", err)
	}
	var gotManifest map[string]interface{}
	if err := json.Unmarshal(gotManifestBytes, &gotManifest); err != nil {
		t.Fatalf("parse extracted manifest: %v", err)
	}
	if gotManifest["encrypted"] != false {
		t.Fatalf("manifest encrypted field mismatch: %v", gotManifest["encrypted"])
	}
	contents, _ := gotManifest["contents"].([]interface{})
	if len(contents) == 0 {
		t.Fatal("manifest contents missing/empty")
	}
	var hasData bool
	for _, c := range contents {
		if c == "data/" {
			hasData = true
		}
		if c == "ssl/" {
			t.Fatalf("manifest contents should not list ssl/ when includeSSL is false: %v", contents)
		}
	}
	if !hasData {
		t.Fatalf("manifest contents missing data/ when includeData is true: %v", contents)
	}
	checksum, _ := gotManifest["checksum"].(string)
	if !strings.HasPrefix(checksum, "sha256:") {
		t.Fatalf("manifest checksum missing or malformed: %q", checksum)
	}
	wantChecksum, err := computeBackupContentChecksum(layout)
	if err != nil {
		t.Fatalf("computeBackupContentChecksum: %v", err)
	}
	if checksum != wantChecksum {
		t.Fatalf("manifest checksum = %q, want %q", checksum, wantChecksum)
	}

	gotServerYML, err := os.ReadFile(filepath.Join(destDir, "config", "server.yml"))
	if err != nil {
		t.Fatalf("read extracted server.yml: %v", err)
	}
	if string(gotServerYML) != "port: 8080\n" {
		t.Fatalf("server.yml mismatch: %q", gotServerYML)
	}

	gotNested, err := os.ReadFile(filepath.Join(destDir, "config", "sub", "nested.yml"))
	if err != nil {
		t.Fatalf("read extracted nested.yml: %v", err)
	}
	if string(gotNested) != "nested: true\n" {
		t.Fatalf("nested.yml mismatch: %q", gotNested)
	}

	gotDB, err := os.ReadFile(filepath.Join(destDir, "db", "ipgaze.db"))
	if err != nil {
		t.Fatalf("read extracted db file: %v", err)
	}
	if string(gotDB) != "fake db content" {
		t.Fatalf("db content mismatch: %q", gotDB)
	}

	gotData, err := os.ReadFile(filepath.Join(destDir, "data", "extra.dat"))
	if err != nil {
		t.Fatalf("read extracted data file: %v", err)
	}
	if string(gotData) != "data payload" {
		t.Fatalf("data content mismatch: %q", gotData)
	}
}

func TestBuildBackupArchive_DefaultExcludesSSLAndData(t *testing.T) {
	srcDir := t.TempDir()
	configDir := filepath.Join(srcDir, "config")
	dataDir := filepath.Join(srcDir, "data")
	dbDir := filepath.Join(srcDir, "db")
	sslDir := filepath.Join(configDir, "ssl")
	if err := os.MkdirAll(sslDir, 0o700); err != nil {
		t.Fatalf("mkdir ssl: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatalf("mkdir db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "server.yml"), []byte("port: 8080\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sslDir, "key.pem"), []byte("private key material"), 0o600); err != nil {
		t.Fatalf("write ssl key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "secret.dat"), []byte("sensitive data"), 0o600); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	layout := backupArchiveLayout{configDir: configDir, dataDir: dataDir, dbDir: dbDir}
	manifest := map[string]interface{}{"encrypted": false}
	archive, err := buildBackupArchive(manifest, layout)
	if err != nil {
		t.Fatalf("buildBackupArchive: %v", err)
	}

	destDir := t.TempDir()
	if err := extractBackupArchive(archive, destDir); err != nil {
		t.Fatalf("extractBackupArchive: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "config", "ssl", "key.pem")); err == nil {
		t.Fatal("ssl/ was included in the archive despite includeSSL=false")
	}
	if _, err := os.Stat(filepath.Join(destDir, "data")); err == nil {
		t.Fatal("data/ was included in the archive despite includeData=false")
	}

	gotManifestBytes, err := os.ReadFile(filepath.Join(destDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read extracted manifest: %v", err)
	}
	var gotManifest map[string]interface{}
	if err := json.Unmarshal(gotManifestBytes, &gotManifest); err != nil {
		t.Fatalf("parse extracted manifest: %v", err)
	}
	contents, _ := gotManifest["contents"].([]interface{})
	for _, c := range contents {
		if c == "ssl/" || c == "data/" {
			t.Fatalf("manifest contents should not list %v by default: %v", c, contents)
		}
	}
}

func TestBuildBackupArchive_IncludeSSLOnly(t *testing.T) {
	srcDir := t.TempDir()
	configDir := filepath.Join(srcDir, "config")
	dataDir := filepath.Join(srcDir, "data")
	dbDir := filepath.Join(srcDir, "db")
	sslDir := filepath.Join(configDir, "ssl")
	if err := os.MkdirAll(sslDir, 0o700); err != nil {
		t.Fatalf("mkdir ssl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sslDir, "key.pem"), []byte("private key material"), 0o600); err != nil {
		t.Fatalf("write ssl key: %v", err)
	}

	layout := backupArchiveLayout{configDir: configDir, dataDir: dataDir, dbDir: dbDir, includeSSL: true}
	manifest := map[string]interface{}{"encrypted": false}
	archive, err := buildBackupArchive(manifest, layout)
	if err != nil {
		t.Fatalf("buildBackupArchive: %v", err)
	}
	destDir := t.TempDir()
	if err := extractBackupArchive(archive, destDir); err != nil {
		t.Fatalf("extractBackupArchive: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "config", "ssl", "key.pem"))
	if err != nil {
		t.Fatalf("ssl/ was not included despite includeSSL=true: %v", err)
	}
	if string(got) != "private key material" {
		t.Fatalf("ssl key content mismatch: %q", got)
	}
	if _, err := os.Stat(filepath.Join(destDir, "data")); err == nil {
		t.Fatal("data/ was included in the archive despite includeData=false")
	}
}

func TestBuildBackupArchive_MissingDirsSkipped(t *testing.T) {
	tmp := t.TempDir()
	layout := backupArchiveLayout{
		configDir:   filepath.Join(tmp, "no-config"),
		dataDir:     filepath.Join(tmp, "no-data"),
		dbDir:       filepath.Join(tmp, "no-db"),
		includeData: true,
	}
	manifest := map[string]interface{}{"encrypted": false}
	archive, err := buildBackupArchive(manifest, layout)
	if err != nil {
		t.Fatalf("buildBackupArchive with missing dirs: %v", err)
	}
	destDir := t.TempDir()
	if err := extractBackupArchive(archive, destDir); err != nil {
		t.Fatalf("extractBackupArchive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "manifest.json")); err != nil {
		t.Fatalf("manifest missing from extracted archive: %v", err)
	}
}

func TestExtractBackupArchive_EncryptedRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	configDir := filepath.Join(srcDir, "config")
	dataDir := filepath.Join(srcDir, "data")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "server.yml"), []byte("port: 9090\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	layout := backupArchiveLayout{configDir: configDir, dataDir: dataDir, dbDir: filepath.Join(srcDir, "db")}
	manifest := map[string]interface{}{"encrypted": true, "encryption_method": "AES-256-GCM"}
	archive, err := buildBackupArchive(manifest, layout)
	if err != nil {
		t.Fatalf("buildBackupArchive: %v", err)
	}
	enc, err := encryptBackupArchive(archive, "restore-password")
	if err != nil {
		t.Fatalf("encryptBackupArchive: %v", err)
	}
	dec, err := decryptBackupArchive(enc, "restore-password")
	if err != nil {
		t.Fatalf("decryptBackupArchive: %v", err)
	}
	destDir := t.TempDir()
	if err := extractBackupArchive(dec, destDir); err != nil {
		t.Fatalf("extractBackupArchive: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "config", "server.yml"))
	if err != nil {
		t.Fatalf("read extracted server.yml: %v", err)
	}
	if string(got) != "port: 9090\n" {
		t.Fatalf("server.yml mismatch: %q", got)
	}
}

func TestExtractBackupArchive_RejectsCorruptGzip(t *testing.T) {
	if err := extractBackupArchive([]byte("not a gzip archive"), t.TempDir()); err == nil {
		t.Fatal("expected error extracting non-gzip data")
	}
}

func TestExtractBackupArchive_RejectsPathTraversal(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"../escape.txt",
		"/etc/passwd",
		"config/../../../etc/passwd",
	}
	for _, name := range cases {
		archive := maliciousTarGz(t, name)
		destDir := t.TempDir()
		if err := extractBackupArchive(archive, destDir); err == nil {
			t.Fatalf("expected path-traversal rejection for entry %q", name)
		}
		if _, statErr := os.Stat(filepath.Join(destDir, "..", "escape.txt")); statErr == nil {
			t.Fatalf("entry %q escaped destination directory", name)
		}
	}
}
