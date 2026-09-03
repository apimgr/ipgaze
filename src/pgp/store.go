package pgp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apimgr/ipgaze/src/security"
)

// Query timeouts per the AI.md PART 10 table: simple SELECTs get 5 seconds,
// writes get 10 seconds.
const (
	storeReadTimeout  = 5 * time.Second
	storeWriteTimeout = 10 * time.Second
)

// SecurityDirName is the subdirectory of {config_dir} holding the keypair
// and keyserver publish state.
const SecurityDirName = "security"

const (
	publicKeyFile     = "pgp.pub.asc"
	privateKeyFile    = "pgp.priv.asc.enc"
	keyserversFile    = "keyservers.state"
	privateKeyKDFInfo = "ipgaze:pgp-private-key:v1"
)

// SecurityDir returns {config_dir}/security, creating it (mode 0700) if needed.
func SecurityDir(configDir string) (string, error) {
	dir := filepath.Join(configDir, SecurityDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("pgp: create security dir: %w", err)
	}
	return dir, nil
}

// Save writes the public key (plaintext) and private key (AES-256-GCM
// encrypted with a key derived from installationSecret) to disk.
func Save(configDir string, kp *Keypair, installationSecret []byte) error {
	dir, err := SecurityDir(configDir)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, publicKeyFile), []byte(kp.PublicArmor), 0o644); err != nil {
		return fmt.Errorf("pgp: write public key: %w", err)
	}

	sealed, err := security.EncryptWithSecret(installationSecret, []byte(kp.PrivateArmor), privateKeyKDFInfo)
	if err != nil {
		return fmt.Errorf("pgp: encrypt private key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), sealed, 0o600); err != nil {
		return fmt.Errorf("pgp: write private key: %w", err)
	}

	return nil
}

// LoadPublic returns the ASCII-armored public key, or ("", os.ErrNotExist)
// if no keypair has been generated.
func LoadPublic(configDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(configDir, SecurityDirName, publicKeyFile))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadPrivateArmor decrypts and returns the ASCII-armored private key.
func LoadPrivateArmor(configDir string, installationSecret []byte) (string, error) {
	sealed, err := os.ReadFile(filepath.Join(configDir, SecurityDirName, privateKeyFile))
	if err != nil {
		return "", err
	}
	plain, err := security.DecryptWithSecret(installationSecret, sealed, privateKeyKDFInfo)
	if err != nil {
		return "", fmt.Errorf("pgp: decrypt private key: %w", err)
	}
	return string(plain), nil
}

// ReencryptPrivateKey decrypts the on-disk private key with oldSecret and
// re-writes it encrypted with newSecret, leaving the public key and DB
// records untouched. Used by `--maintenance secret rotate installation_secret`
// (AI.md PART 11 "Secret Rotation": "Rotation re-encrypts the PGP private key").
// A no-op (returns nil) if no keypair exists on disk yet.
func ReencryptPrivateKey(configDir string, oldSecret, newSecret []byte) error {
	if !Exists(configDir) {
		return nil
	}
	armor, err := LoadPrivateArmor(configDir, oldSecret)
	if err != nil {
		return fmt.Errorf("pgp: load private key for re-encryption: %w", err)
	}
	dir, err := SecurityDir(configDir)
	if err != nil {
		return err
	}
	sealed, err := security.EncryptWithSecret(newSecret, []byte(armor), privateKeyKDFInfo)
	if err != nil {
		return fmt.Errorf("pgp: re-encrypt private key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), sealed, 0o600); err != nil {
		return fmt.Errorf("pgp: write re-encrypted private key: %w", err)
	}
	return nil
}

// Exists reports whether a keypair is currently on disk.
func Exists(configDir string) bool {
	_, err := os.Stat(filepath.Join(configDir, SecurityDirName, publicKeyFile))
	return err == nil
}

// Delete removes both key files from disk. Missing files are not an error.
func Delete(configDir string) error {
	dir := filepath.Join(configDir, SecurityDirName)
	for _, name := range []string{publicKeyFile, privateKeyFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("pgp: delete %s: %w", name, err)
		}
	}
	return nil
}

// -----------------------------------------------------------------------
// DB metadata (pgp_keypairs table) — AI.md PART 11 "Keypair properties
// stored in DB". The keys themselves never touch this table.
// -----------------------------------------------------------------------

// Record mirrors a row of the pgp_keypairs table.
type Record struct {
	ID                  int64
	Fingerprint         string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	LastRotatedAt       *time.Time
	KeyserversPublished map[string]int64
	Revoked             bool
}

// InsertRecord records a newly generated/rotated keypair's metadata.
func InsertRecord(db *sql.DB, fingerprint string, createdAt, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()

	_, err := db.ExecContext(ctx,
		`INSERT INTO pgp_keypairs (fingerprint, created_at, expires_at, keyservers_published, revoked)
		 VALUES (?, ?, ?, '{}', 0)`,
		fingerprint, createdAt.Unix(), expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("pgp: insert keypair record: %w", err)
	}
	return nil
}

// MarkRotated stamps last_rotated_at on the active (non-revoked) keypair row
// that preceded the rotation, identified by fingerprint.
func MarkRotated(db *sql.DB, fingerprint string) error {
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()

	_, err := db.ExecContext(ctx,
		`UPDATE pgp_keypairs SET last_rotated_at = strftime('%s', 'now') WHERE fingerprint = ?`,
		fingerprint,
	)
	if err != nil {
		return fmt.Errorf("pgp: mark rotated: %w", err)
	}
	return nil
}

// MarkRevoked sets revoked = 1 on the given fingerprint's row (AI.md PART 11
// "Delete" — the key file may be gone but the fingerprint stays in audit history).
func MarkRevoked(db *sql.DB, fingerprint string) error {
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()

	_, err := db.ExecContext(ctx, `UPDATE pgp_keypairs SET revoked = 1 WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return fmt.Errorf("pgp: mark revoked: %w", err)
	}
	return nil
}

// ActiveRecord returns the most recent non-revoked keypair record, or
// (nil, nil) if none exists.
func ActiveRecord(db *sql.DB) (*Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), storeReadTimeout)
	defer cancel()

	row := db.QueryRowContext(ctx,
		`SELECT id, fingerprint, created_at, expires_at, last_rotated_at, keyservers_published, revoked
		 FROM pgp_keypairs WHERE revoked = 0 ORDER BY created_at DESC LIMIT 1`,
	)
	return scanRecord(row)
}

func scanRecord(row *sql.Row) (*Record, error) {
	var (
		id            int64
		fingerprint   string
		createdAt     int64
		expiresAt     int64
		lastRotatedAt sql.NullInt64
		keyserversRaw string
		revoked       int
	)
	err := row.Scan(&id, &fingerprint, &createdAt, &expiresAt, &lastRotatedAt, &keyserversRaw, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("pgp: scan keypair record: %w", err)
	}

	published := map[string]int64{}
	_ = json.Unmarshal([]byte(keyserversRaw), &published)

	rec := &Record{
		ID:                  id,
		Fingerprint:         fingerprint,
		CreatedAt:           time.Unix(createdAt, 0),
		ExpiresAt:           time.Unix(expiresAt, 0),
		KeyserversPublished: published,
		Revoked:             revoked != 0,
	}
	if lastRotatedAt.Valid {
		t := time.Unix(lastRotatedAt.Int64, 0)
		rec.LastRotatedAt = &t
	}
	return rec, nil
}

// RecordKeyserverPublish updates keyservers_published for fingerprint with
// the given host and publish timestamp.
func RecordKeyserverPublish(db *sql.DB, fingerprint, host string, publishedAt time.Time) error {
	readCtx, cancelRead := context.WithTimeout(context.Background(), storeReadTimeout)
	defer cancelRead()

	var raw string
	err := db.QueryRowContext(readCtx, `SELECT keyservers_published FROM pgp_keypairs WHERE fingerprint = ?`, fingerprint).Scan(&raw)
	if err != nil {
		return fmt.Errorf("pgp: load keyservers_published: %w", err)
	}

	published := map[string]int64{}
	_ = json.Unmarshal([]byte(raw), &published)
	published[host] = publishedAt.Unix()

	encoded, err := json.Marshal(published)
	if err != nil {
		return fmt.Errorf("pgp: encode keyservers_published: %w", err)
	}

	writeCtx, cancelWrite := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancelWrite()

	_, err = db.ExecContext(writeCtx, `UPDATE pgp_keypairs SET keyservers_published = ? WHERE fingerprint = ?`, string(encoded), fingerprint)
	if err != nil {
		return fmt.Errorf("pgp: persist keyservers_published: %w", err)
	}
	return nil
}

// keyserversState is the on-disk shape of {config_dir}/security/keyservers.state
// (AI.md PART 11 "Backup Integration (PART 21)": "Per-keyserver publish
// state, so a restore doesn't double-submit.").
type keyserversState struct {
	Fingerprint string           `json:"fingerprint"`
	Published   map[string]int64 `json:"published"`
}

// WriteKeyserversState mirrors the DB's keyservers_published map to
// {config_dir}/security/keyservers.state. Called after a successful publish
// so a backup taken afterward carries the same state a restore needs to
// avoid re-submitting to keyservers that already have the key.
func WriteKeyserversState(configDir, fingerprint string, published map[string]int64) error {
	dir, err := SecurityDir(configDir)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(keyserversState{Fingerprint: fingerprint, Published: published}, "", "  ")
	if err != nil {
		return fmt.Errorf("pgp: encode keyservers state: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyserversFile), encoded, 0o600); err != nil {
		return fmt.Errorf("pgp: write keyservers state: %w", err)
	}
	return nil
}

// ReadKeyserversState reads {config_dir}/security/keyservers.state. Returns
// (nil, nil) if the file does not exist (no publishes have happened yet, or
// this is a fresh restore predating the feature). Callers use this on
// restore to avoid re-publishing to keyservers already recorded here.
func ReadKeyserversState(configDir, fingerprint string) (map[string]int64, error) {
	data, err := os.ReadFile(filepath.Join(configDir, SecurityDirName, keyserversFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("pgp: read keyservers state: %w", err)
	}

	var state keyserversState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("pgp: decode keyservers state: %w", err)
	}
	if state.Fingerprint != fingerprint {
		return nil, nil
	}
	return state.Published, nil
}
