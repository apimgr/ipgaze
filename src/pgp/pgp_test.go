package pgp

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/apimgr/ipgaze/src/db"
)

// openMemDB opens an in-memory SQLite database with the full schema applied.
func openMemDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.EnsureSchema(conn); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return conn
}

// ---------------------------------------------------------------------------
// Generate / Rotate / armor round-trip
// ---------------------------------------------------------------------------

func TestGenerate_RoundTrip(t *testing.T) {
	kp, err := Generate("ipgaze", "security@example.com")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if kp.Fingerprint == "" {
		t.Fatal("Fingerprint is empty")
	}
	if !strings.Contains(kp.PublicArmor, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatal("PublicArmor missing armor header")
	}
	if !strings.Contains(kp.PrivateArmor, "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Fatal("PrivateArmor missing armor header")
	}
	if !kp.ExpiresAt.After(kp.CreatedAt) {
		t.Fatal("ExpiresAt should be after CreatedAt")
	}
	if got, want := kp.ExpiresAt.Sub(kp.CreatedAt), KeyLifetime; got < want-time.Minute || got > want+time.Minute {
		t.Fatalf("ExpiresAt-CreatedAt = %v, want ~%v", got, want)
	}

	entity, err := ParsePrivate(kp.PrivateArmor)
	if err != nil {
		t.Fatalf("ParsePrivate: %v", err)
	}
	if got := Fingerprint(entity); got != kp.Fingerprint {
		t.Fatalf("Fingerprint mismatch: got %s want %s", got, kp.Fingerprint)
	}
}

func TestRotate_CrossSignsWithOldKey(t *testing.T) {
	old, err := Generate("ipgaze", "security@example.com")
	if err != nil {
		t.Fatalf("Generate old: %v", err)
	}

	next, err := Rotate("ipgaze", "security@example.com", old.Entity)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if next.Fingerprint == old.Fingerprint {
		t.Fatal("rotated key should have a different fingerprint")
	}

	found := false
	for _, ident := range next.Entity.Identities {
		for _, sig := range ident.Signatures {
			if sig.IssuerFingerprint != nil {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected at least one signature with an issuer fingerprint on the rotated identity")
	}
}

func TestRotate_NilOldKeyOK(t *testing.T) {
	kp, err := Rotate("ipgaze", "security@example.com", nil)
	if err != nil {
		t.Fatalf("Rotate with nil old key: %v", err)
	}
	if kp.Fingerprint == "" {
		t.Fatal("Fingerprint is empty")
	}
}

func TestIdentity(t *testing.T) {
	got := Identity("ipgaze", "security@example.com")
	want := "ipgaze Security <security@example.com>"
	if got != want {
		t.Fatalf("Identity() = %q, want %q", got, want)
	}
}

func TestParsePrivate_RejectsPublicArmor(t *testing.T) {
	kp, err := Generate("ipgaze", "security@example.com")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ParsePrivate(kp.PublicArmor); err == nil {
		t.Fatal("expected ParsePrivate to reject a public-key armor block")
	}
}

// ---------------------------------------------------------------------------
// Save / Load / Exists / Delete
// ---------------------------------------------------------------------------

func TestStore_SaveLoadDelete(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("0123456789abcdef0123456789abcdef")

	kp, err := Generate("ipgaze", "security@example.com")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if Exists(dir) {
		t.Fatal("Exists should be false before Save")
	}

	if err := Save(dir, kp, secret); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if !Exists(dir) {
		t.Fatal("Exists should be true after Save")
	}

	gotPub, err := LoadPublic(dir)
	if err != nil {
		t.Fatalf("LoadPublic: %v", err)
	}
	if gotPub != kp.PublicArmor {
		t.Fatal("LoadPublic did not round-trip")
	}

	gotPriv, err := LoadPrivateArmor(dir, secret)
	if err != nil {
		t.Fatalf("LoadPrivateArmor: %v", err)
	}
	if gotPriv != kp.PrivateArmor {
		t.Fatal("LoadPrivateArmor did not round-trip")
	}

	// Wrong secret must fail to decrypt.
	if _, err := LoadPrivateArmor(dir, []byte("wrong-secret-wrong-secret-wrong")); err == nil {
		t.Fatal("expected LoadPrivateArmor to fail with the wrong secret")
	}

	// Private key file must not be world/group readable.
	info, err := os.Stat(filepath.Join(dir, SecurityDirName, privateKeyFile))
	if err != nil {
		t.Fatalf("stat private key file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key file mode = %v, want 0600", info.Mode().Perm())
	}

	if err := Delete(dir); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if Exists(dir) {
		t.Fatal("Exists should be false after Delete")
	}

	// Delete on an already-empty dir must not error.
	if err := Delete(dir); err != nil {
		t.Fatalf("Delete on empty dir: %v", err)
	}
}

func TestKeyserversState_WriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fp := "AAAABBBBCCCCDDDD"

	got, err := ReadKeyserversState(dir, fp)
	if err != nil {
		t.Fatalf("ReadKeyserversState before write: %v", err)
	}
	if got != nil {
		t.Fatalf("ReadKeyserversState before write = %v, want nil", got)
	}

	published := map[string]int64{
		"keys.openpgp.org":     1700000000,
		"keyserver.ubuntu.com": 1700000100,
	}
	if err := WriteKeyserversState(dir, fp, published); err != nil {
		t.Fatalf("WriteKeyserversState: %v", err)
	}

	// State file must not be world/group readable.
	info, err := os.Stat(filepath.Join(dir, SecurityDirName, keyserversFile))
	if err != nil {
		t.Fatalf("stat keyservers state file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("keyservers state file mode = %v, want 0600", info.Mode().Perm())
	}

	got, err = ReadKeyserversState(dir, fp)
	if err != nil {
		t.Fatalf("ReadKeyserversState after write: %v", err)
	}
	if len(got) != len(published) {
		t.Fatalf("ReadKeyserversState = %v, want %v", got, published)
	}
	for host, ts := range published {
		if got[host] != ts {
			t.Fatalf("ReadKeyserversState[%s] = %d, want %d", host, got[host], ts)
		}
	}

	// A different fingerprint must not match a stale state file (e.g. after rotation).
	got, err = ReadKeyserversState(dir, "other-fingerprint")
	if err != nil {
		t.Fatalf("ReadKeyserversState wrong fingerprint: %v", err)
	}
	if got != nil {
		t.Fatalf("ReadKeyserversState wrong fingerprint = %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// DB metadata (pgp_keypairs)
// ---------------------------------------------------------------------------

func TestRecord_InsertRotateRevokeActive(t *testing.T) {
	conn := openMemDB(t)

	now := time.Now()
	fp1 := "AAAA1111"
	if err := InsertRecord(conn, fp1, now, now.Add(KeyLifetime)); err != nil {
		t.Fatalf("InsertRecord: %v", err)
	}

	active, err := ActiveRecord(conn)
	if err != nil {
		t.Fatalf("ActiveRecord: %v", err)
	}
	if active == nil || active.Fingerprint != fp1 {
		t.Fatalf("ActiveRecord = %+v, want fingerprint %s", active, fp1)
	}
	if active.Revoked {
		t.Fatal("newly inserted record should not be revoked")
	}
	if active.LastRotatedAt != nil {
		t.Fatal("newly inserted record should have no LastRotatedAt")
	}

	if err := MarkRotated(conn, fp1); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	active, err = ActiveRecord(conn)
	if err != nil {
		t.Fatalf("ActiveRecord after rotate: %v", err)
	}
	if active.LastRotatedAt == nil {
		t.Fatal("expected LastRotatedAt to be set after MarkRotated")
	}

	if err := MarkRevoked(conn, fp1); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}
	active, err = ActiveRecord(conn)
	if err != nil {
		t.Fatalf("ActiveRecord after revoke: %v", err)
	}
	if active != nil {
		t.Fatalf("ActiveRecord should be nil once the only record is revoked, got %+v", active)
	}
}

func TestActiveRecord_NoneExists(t *testing.T) {
	conn := openMemDB(t)
	active, err := ActiveRecord(conn)
	if err != nil {
		t.Fatalf("ActiveRecord: %v", err)
	}
	if active != nil {
		t.Fatalf("ActiveRecord should be nil on an empty table, got %+v", active)
	}
}

func TestRecordKeyserverPublish(t *testing.T) {
	conn := openMemDB(t)
	now := time.Now()
	fp := "BBBB2222"
	if err := InsertRecord(conn, fp, now, now.Add(KeyLifetime)); err != nil {
		t.Fatalf("InsertRecord: %v", err)
	}

	published := now.Truncate(time.Second)
	if err := RecordKeyserverPublish(conn, fp, "keys.openpgp.org", published); err != nil {
		t.Fatalf("RecordKeyserverPublish: %v", err)
	}
	if err := RecordKeyserverPublish(conn, fp, "keyserver.ubuntu.com", published); err != nil {
		t.Fatalf("RecordKeyserverPublish second host: %v", err)
	}

	active, err := ActiveRecord(conn)
	if err != nil {
		t.Fatalf("ActiveRecord: %v", err)
	}
	if len(active.KeyserversPublished) != 2 {
		t.Fatalf("KeyserversPublished = %+v, want 2 entries", active.KeyserversPublished)
	}
	if active.KeyserversPublished["keys.openpgp.org"] != published.Unix() {
		t.Fatalf("keys.openpgp.org timestamp = %d, want %d", active.KeyserversPublished["keys.openpgp.org"], published.Unix())
	}
}

// ---------------------------------------------------------------------------
// Keyserver publish
// ---------------------------------------------------------------------------

// withTestKeyserver points vksScheme/publishRetries/publishBackoff at
// fast, local-HTTP-friendly values for the duration of a test.
func withTestKeyserver(t *testing.T) {
	t.Helper()
	origScheme, origRetries, origBackoff := vksScheme, publishRetries, publishBackoff
	vksScheme = "http"
	publishRetries = 2
	publishBackoff = 10 * time.Millisecond
	t.Cleanup(func() {
		vksScheme, publishRetries, publishBackoff = origScheme, origRetries, origBackoff
	})
}

func TestPublish_Success(t *testing.T) {
	withTestKeyserver(t)
	conn := openMemDB(t)
	now := time.Now()
	fp := "CCCC3333"
	if err := InsertRecord(conn, fp, now, now.Add(KeyLifetime)); err != nil {
		t.Fatalf("InsertRecord: %v", err)
	}

	var gotKeytext string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vks/v1/upload" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body struct {
			Keytext string `json:"keytext"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		gotKeytext = body.Keytext
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	results := Publish(conn, fp, "ARMORED-KEY-DATA", []string{host})

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("publish error: %v", results[0].Err)
	}
	if gotKeytext != "ARMORED-KEY-DATA" {
		t.Fatalf("keytext = %q, want ARMORED-KEY-DATA", gotKeytext)
	}

	active, err := ActiveRecord(conn)
	if err != nil {
		t.Fatalf("ActiveRecord: %v", err)
	}
	if _, ok := active.KeyserversPublished[host]; !ok {
		t.Fatalf("expected %s to be recorded as published, got %+v", host, active.KeyserversPublished)
	}
}

func TestPublish_FailureRecordsError(t *testing.T) {
	withTestKeyserver(t)
	conn := openMemDB(t)
	now := time.Now()
	fp := "DDDD4444"
	if err := InsertRecord(conn, fp, now, now.Add(KeyLifetime)); err != nil {
		t.Fatalf("InsertRecord: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	results := Publish(conn, fp, "ARMORED-KEY-DATA", []string{host})

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("expected an error result for a 500 response")
	}

	active, err := ActiveRecord(conn)
	if err != nil {
		t.Fatalf("ActiveRecord: %v", err)
	}
	if _, ok := active.KeyserversPublished[host]; ok {
		t.Fatal("host should not be recorded as published after a failure")
	}
}
