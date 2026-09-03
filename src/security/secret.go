// Package security provides cryptographic utilities for ipgaze.
// See AI.md PART 11 for security requirements.
package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Query timeouts per the AI.md PART 10 table: simple SELECTs get 5 seconds,
// writes get 10 seconds.
const (
	secretReadTimeout  = 5 * time.Second
	secretWriteTimeout = 10 * time.Second
)

// SecretName identifies a row in the app_secrets table (AI.md PART 11).
type SecretName string

const (
	// SecretInstallationSecret is the root secret for all derived cryptographic
	// material (PGP private-key KDF, {security_id} HMACs).
	SecretInstallationSecret SecretName = "installation_secret"
	// SecretCookieSigningKey signs session cookies to detect tampering.
	SecretCookieSigningKey SecretName = "cookie_signing_key"
	// SecretCSRFTokenSecret is the HMAC base for CSRF tokens (double-submit pattern).
	SecretCSRFTokenSecret SecretName = "csrf_token_secret"
)

// secretGraceWindow is how long the previous value of a rotated secret
// remains valid for in-flight validation (AI.md PART 11).
const secretGraceWindow = 7 * 24 * time.Hour

// GetOrCreateSecret returns the current value of the named app_secrets row,
// generating and persisting a new 32-byte random secret if the row does not
// yet exist. Safe to call concurrently at startup.
func GetOrCreateSecret(db *sql.DB, name SecretName) ([]byte, error) {
	readCtx, cancelRead := context.WithTimeout(context.Background(), secretReadTimeout)
	defer cancelRead()

	var encoded string
	err := db.QueryRowContext(readCtx, `SELECT value FROM app_secrets WHERE name = ?`, string(name)).Scan(&encoded)
	if err == nil {
		return base64.StdEncoding.DecodeString(encoded)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("security: query %s: %w", name, err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("security: generate %s: %w", name, err)
	}
	encoded = base64.StdEncoding.EncodeToString(raw)

	writeCtx, cancelWrite := context.WithTimeout(context.Background(), secretWriteTimeout)
	defer cancelWrite()

	_, err = db.ExecContext(writeCtx,
		`INSERT INTO app_secrets (name, value) VALUES (?, ?)
		 ON CONFLICT(name) DO NOTHING`,
		string(name), encoded,
	)
	if err != nil {
		return nil, fmt.Errorf("security: persist %s: %w", name, err)
	}

	reloadCtx, cancelReload := context.WithTimeout(context.Background(), secretReadTimeout)
	defer cancelReload()

	// Another goroutine/process may have won the race; re-read to be sure
	// every caller observes the same canonical value.
	if err := db.QueryRowContext(reloadCtx, `SELECT value FROM app_secrets WHERE name = ?`, string(name)).Scan(&encoded); err != nil {
		return nil, fmt.Errorf("security: reload %s: %w", name, err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// RotateSecret generates a fresh random value for the named secret, keeping
// the previous value valid for secretGraceWindow (AI.md PART 11). Callers are
// responsible for the sensitive-operation auth gate and audit logging.
func RotateSecret(db *sql.DB, name SecretName) error {
	current, err := GetOrCreateSecret(db, name)
	if err != nil {
		return err
	}

	next := make([]byte, 32)
	if _, err := rand.Read(next); err != nil {
		return fmt.Errorf("security: generate replacement %s: %w", name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), secretWriteTimeout)
	defer cancel()

	previousUntil := time.Now().Add(secretGraceWindow).Unix()
	_, err = db.ExecContext(ctx,
		`UPDATE app_secrets
		 SET value = ?, previous_value = ?, previous_until = ?, rotated_at = strftime('%s', 'now')
		 WHERE name = ?`,
		base64.StdEncoding.EncodeToString(next),
		base64.StdEncoding.EncodeToString(current),
		previousUntil,
		string(name),
	)
	if err != nil {
		return fmt.Errorf("security: rotate %s: %w", name, err)
	}
	return nil
}

// PreviousSecret returns the pre-rotation value of name if it is still
// within its grace window, for validating in-flight tokens/URLs signed
// before a rotation. Returns (nil, nil) if there is no live previous value.
func PreviousSecret(db *sql.DB, name SecretName) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretReadTimeout)
	defer cancel()

	var previous sql.NullString
	var previousUntil sql.NullInt64
	err := db.QueryRowContext(ctx,
		`SELECT previous_value, previous_until FROM app_secrets WHERE name = ?`,
		string(name),
	).Scan(&previous, &previousUntil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("security: query previous %s: %w", name, err)
	}
	if !previous.Valid || !previousUntil.Valid {
		return nil, nil
	}
	if time.Now().Unix() > previousUntil.Int64 {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(previous.String)
}

// deriveAESKey derives a 32-byte AES-256 key from secret using HKDF-SHA256,
// scoped by info so different purposes never share the same derived key.
func deriveAESKey(secret []byte, info string) ([]byte, error) {
	kdf := hkdf.New(sha256.New, secret, nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("security: derive key: %w", err)
	}
	return key, nil
}

// EncryptWithSecret encrypts plaintext with AES-256-GCM using a key derived
// from secret via HKDF-SHA256 (scoped by info). Returns nonce||ciphertext.
func EncryptWithSecret(secret, plaintext []byte, info string) ([]byte, error) {
	key, err := deriveAESKey(secret, info)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("security: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("security: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("security: generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptWithSecret reverses EncryptWithSecret.
func DecryptWithSecret(secret, ciphertext []byte, info string) ([]byte, error) {
	key, err := deriveAESKey(secret, info)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("security: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("security: new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("security: ciphertext too short")
	}
	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, sealed, nil)
}
