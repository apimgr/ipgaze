package security

import (
	"bytes"
	"database/sql"
	"testing"

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
// EncryptWithSecret / DecryptWithSecret
// ---------------------------------------------------------------------------

func TestEncryptDecryptWithSecret_RoundTrip(t *testing.T) {
	secret := []byte("a-32-byte-or-longer-secret-value")
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ciphertext, err := EncryptWithSecret(secret, plaintext, "test:info")
	if err != nil {
		t.Fatalf("EncryptWithSecret() error: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("EncryptWithSecret() returned plaintext unchanged")
	}

	got, err := DecryptWithSecret(secret, ciphertext, "test:info")
	if err != nil {
		t.Fatalf("DecryptWithSecret() error: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("DecryptWithSecret() = %q, want %q", got, plaintext)
	}
}

func TestEncryptWithSecret_NondeterministicNonce(t *testing.T) {
	secret := []byte("a-32-byte-or-longer-secret-value")
	plaintext := []byte("same plaintext")

	c1, err := EncryptWithSecret(secret, plaintext, "test:info")
	if err != nil {
		t.Fatalf("EncryptWithSecret() error: %v", err)
	}
	c2, err := EncryptWithSecret(secret, plaintext, "test:info")
	if err != nil {
		t.Fatalf("EncryptWithSecret() error: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Error("EncryptWithSecret() produced identical ciphertext across calls (nonce should differ)")
	}
}

func TestDecryptWithSecret_WrongSecretFails(t *testing.T) {
	secret := []byte("a-32-byte-or-longer-secret-value")
	wrongSecret := []byte("a-different-32-byte-secret-value")
	plaintext := []byte("secret payload")

	ciphertext, err := EncryptWithSecret(secret, plaintext, "test:info")
	if err != nil {
		t.Fatalf("EncryptWithSecret() error: %v", err)
	}

	if _, err := DecryptWithSecret(wrongSecret, ciphertext, "test:info"); err == nil {
		t.Error("DecryptWithSecret() succeeded with wrong secret, want error")
	}
}

func TestDecryptWithSecret_WrongInfoFails(t *testing.T) {
	secret := []byte("a-32-byte-or-longer-secret-value")
	plaintext := []byte("secret payload")

	ciphertext, err := EncryptWithSecret(secret, plaintext, "test:info-a")
	if err != nil {
		t.Fatalf("EncryptWithSecret() error: %v", err)
	}

	if _, err := DecryptWithSecret(secret, ciphertext, "test:info-b"); err == nil {
		t.Error("DecryptWithSecret() succeeded with mismatched info, want error")
	}
}

func TestDecryptWithSecret_TamperedCiphertextFails(t *testing.T) {
	secret := []byte("a-32-byte-or-longer-secret-value")
	plaintext := []byte("secret payload")

	ciphertext, err := EncryptWithSecret(secret, plaintext, "test:info")
	if err != nil {
		t.Fatalf("EncryptWithSecret() error: %v", err)
	}
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := DecryptWithSecret(secret, tampered, "test:info"); err == nil {
		t.Error("DecryptWithSecret() succeeded with tampered ciphertext, want error")
	}
}

func TestDecryptWithSecret_TooShortCiphertext(t *testing.T) {
	secret := []byte("a-32-byte-or-longer-secret-value")

	if _, err := DecryptWithSecret(secret, []byte("short"), "test:info"); err == nil {
		t.Error("DecryptWithSecret() succeeded with too-short ciphertext, want error")
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateSecret / RotateSecret / PreviousSecret
// ---------------------------------------------------------------------------

func TestGetOrCreateSecret_CreatesAndPersists(t *testing.T) {
	conn := openMemDB(t)

	first, err := GetOrCreateSecret(conn, SecretCookieSigningKey)
	if err != nil {
		t.Fatalf("GetOrCreateSecret() error: %v", err)
	}
	if len(first) != 32 {
		t.Errorf("GetOrCreateSecret() len = %d, want 32", len(first))
	}

	second, err := GetOrCreateSecret(conn, SecretCookieSigningKey)
	if err != nil {
		t.Fatalf("GetOrCreateSecret() second call error: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("GetOrCreateSecret() returned different values on second call")
	}
}

func TestGetOrCreateSecret_DifferentNamesDifferentValues(t *testing.T) {
	conn := openMemDB(t)

	a, err := GetOrCreateSecret(conn, SecretInstallationSecret)
	if err != nil {
		t.Fatalf("GetOrCreateSecret(installation) error: %v", err)
	}
	b, err := GetOrCreateSecret(conn, SecretCSRFTokenSecret)
	if err != nil {
		t.Fatalf("GetOrCreateSecret(csrf) error: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("GetOrCreateSecret() returned identical values for different secret names")
	}
}

func TestPreviousSecret_NoneBeforeRotation(t *testing.T) {
	conn := openMemDB(t)

	if _, err := GetOrCreateSecret(conn, SecretCookieSigningKey); err != nil {
		t.Fatalf("GetOrCreateSecret() error: %v", err)
	}

	prev, err := PreviousSecret(conn, SecretCookieSigningKey)
	if err != nil {
		t.Fatalf("PreviousSecret() error: %v", err)
	}
	if prev != nil {
		t.Errorf("PreviousSecret() = %v, want nil before any rotation", prev)
	}
}

func TestRotateSecret_ChangesCurrentAndKeepsPrevious(t *testing.T) {
	conn := openMemDB(t)

	before, err := GetOrCreateSecret(conn, SecretCookieSigningKey)
	if err != nil {
		t.Fatalf("GetOrCreateSecret() error: %v", err)
	}

	if err := RotateSecret(conn, SecretCookieSigningKey); err != nil {
		t.Fatalf("RotateSecret() error: %v", err)
	}

	after, err := GetOrCreateSecret(conn, SecretCookieSigningKey)
	if err != nil {
		t.Fatalf("GetOrCreateSecret() after rotate error: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Error("RotateSecret() did not change the current secret value")
	}

	prev, err := PreviousSecret(conn, SecretCookieSigningKey)
	if err != nil {
		t.Fatalf("PreviousSecret() error: %v", err)
	}
	if !bytes.Equal(prev, before) {
		t.Errorf("PreviousSecret() = %v, want previous value %v", prev, before)
	}
}

func TestPreviousSecret_UnknownName(t *testing.T) {
	conn := openMemDB(t)

	prev, err := PreviousSecret(conn, SecretName("does-not-exist"))
	if err != nil {
		t.Fatalf("PreviousSecret() error: %v", err)
	}
	if prev != nil {
		t.Errorf("PreviousSecret() = %v, want nil for unknown secret name", prev)
	}
}
