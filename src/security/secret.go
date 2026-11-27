// Package security provides cryptographic utilities for ipgaze.
// See AI.md PART 11 for security requirements.
package security

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	dbstore "github.com/apimgr/ipgaze/src/db"
	"github.com/apimgr/ipgaze/src/security/cryptoutil"
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
func GetOrCreateSecret(db *dbstore.Store, name SecretName) ([]byte, error) {
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
		`INSERT INTO app_secrets (name, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(name) DO NOTHING`,
		string(name), encoded, time.Now().UTC().Format(time.RFC3339Nano),
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

// RotateSecretIfDue rotates a secret after its configured lifetime.
func RotateSecretIfDue(db *dbstore.Store, name SecretName, lifetime time.Duration, now time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretReadTimeout)
	defer cancel()
	var updatedAt string
	if err := db.QueryRowContext(ctx, `SELECT updated_at FROM app_secrets WHERE name = ?`, string(name)).Scan(&updatedAt); err != nil {
		return false, fmt.Errorf("security: read rotation time for %s: %w", name, err)
	}
	rotatedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return false, fmt.Errorf("security: parse rotation time for %s: %w", name, err)
	}
	if now.Sub(rotatedAt) < lifetime {
		return false, nil
	}
	if err := RotateSecret(db, name); err != nil {
		return false, err
	}
	return true, nil
}

// RotateSecret generates a fresh random value for the named secret, keeping
// the previous value valid for secretGraceWindow (AI.md PART 11). Callers are
// responsible for the sensitive-operation auth gate and audit logging.
func RotateSecret(db *dbstore.Store, name SecretName) error {
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
	updatedAt := time.Now().UTC().Format(time.RFC3339Nano)
	err = db.Write(ctx, func(tx *sql.Tx) error {
		for key, value := range map[string]string{
			string(name) + "_previous":       base64.StdEncoding.EncodeToString(current),
			string(name) + "_previous_until": time.Unix(previousUntil, 0).UTC().Format(time.RFC3339Nano),
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO app_secrets(name, value, updated_at) VALUES(?, ?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, updatedAt); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE app_secrets SET value = ?, updated_at = ? WHERE name = ?`, base64.StdEncoding.EncodeToString(next), updatedAt, string(name))
		return err
	})
	if err != nil {
		return fmt.Errorf("security: rotate %s: %w", name, err)
	}
	return nil
}

// PreviousSecret returns the pre-rotation value of name if it is still
// within its grace window, for validating in-flight tokens/URLs signed
// before a rotation. Returns (nil, nil) if there is no live previous value.
func PreviousSecret(db *dbstore.Store, name SecretName) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretReadTimeout)
	defer cancel()

	var previous string
	var previousUntil string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM app_secrets WHERE name = ?`, string(name)+"_previous",
	).Scan(&previous)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("security: query previous %s: %w", name, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name = ?`, string(name)+"_previous_until").Scan(&previousUntil); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("security: query previous expiry for %s: %w", name, err)
	}
	until, err := time.Parse(time.RFC3339Nano, previousUntil)
	if err != nil {
		return nil, fmt.Errorf("security: parse previous expiry for %s: %w", name, err)
	}
	if previous == "" {
		return nil, nil
	}
	if time.Now().After(until) {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(previous)
}

// EncryptWithSecret encrypts plaintext with AES-256-GCM using a key derived
// from secret via HKDF-SHA256 (scoped by info). Returns nonce||ciphertext.
func EncryptWithSecret(secret, plaintext []byte, info string) ([]byte, error) {
	return cryptoutil.EncryptWithSecret(secret, plaintext, info)
}

// DecryptWithSecret reverses EncryptWithSecret.
func DecryptWithSecret(secret, ciphertext []byte, info string) ([]byte, error) {
	return cryptoutil.DecryptWithSecret(secret, ciphertext, info)
}
