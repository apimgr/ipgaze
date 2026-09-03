package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apimgr/ipgaze/src/config"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// Backup encryption per AI.md PART 21:
// - Algorithm: AES-256-GCM
// - Key Derivation: Argon2id (password -> 256-bit key)
// - File Extension: .tar.gz (unencrypted) or .tar.gz.enc (encrypted)
// - Password Storage: never persisted by this code path beyond the
//   optionally-configured server.yml value; interactive prompts are never
//   echoed and are never accepted via a CLI flag.

const (
	backupSaltLen  = 16
	backupNonceLen = 12
	backupKeyLen   = 32 // AES-256
)

// Argon2id tuning per OWASP minimum recommendations for interactive use.
const (
	backupArgonTime    = 1
	backupArgonMemory  = 64 * 1024 // 64 MiB
	backupArgonThreads = 4
)

// deriveBackupKey derives a 256-bit AES key from a password and salt via Argon2id.
func deriveBackupKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, backupArgonTime, backupArgonMemory, backupArgonThreads, backupKeyLen)
}

// encryptBackupArchive encrypts an in-memory tar.gz archive with AES-256-GCM.
// Output layout: salt(16) || nonce(12) || ciphertext(+GCM tag).
// The unencrypted archive is only ever held in memory by the caller — it is
// never written to disk before this function returns.
func encryptBackupArchive(plaintext []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("encryptBackupArchive: empty password")
	}
	salt := make([]byte, backupSaltLen)
	if _, err := io.ReadFull(cryptorand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	key := deriveBackupKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	nonce := make([]byte, backupNonceLen)
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptBackupArchive reverses encryptBackupArchive.
func decryptBackupArchive(data []byte, password string) ([]byte, error) {
	if len(data) < backupSaltLen+backupNonceLen {
		return nil, errors.New("decryptBackupArchive: file too short to contain salt and nonce")
	}
	if password == "" {
		return nil, errors.New("decryptBackupArchive: empty password")
	}
	salt := data[:backupSaltLen]
	nonce := data[backupSaltLen : backupSaltLen+backupNonceLen]
	ciphertext := data[backupSaltLen+backupNonceLen:]
	key := deriveBackupKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: wrong password or corrupted archive: %w", err)
	}
	return plaintext, nil
}

// promptBackupPassword reads a password from the controlling terminal without
// echoing it. Per AI.md PART 21 there is no password flag — passwords on the
// command line leak via shell history and process lists.
func promptBackupPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("promptBackupPassword: stdin is not a terminal; cannot prompt for a password")
	}
	fmt.Print(prompt)
	pwBytes, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(pwBytes), nil
}

// resolveBackupEncryptionPassword decides whether a backup should be
// encrypted and, if so, returns the password to use. Per AI.md PART 21:
//   - Compliance disabled, no password configured -> unencrypted
//   - Compliance disabled, password configured    -> encrypted
//   - Compliance enabled, no password configured   -> blocked
//   - Compliance enabled, password configured       -> encrypted (required)
//
// interactive controls whether a CLI-style password prompt may be used
// (scheduled/background backups must never prompt).
func resolveBackupEncryptionPassword(cfg *config.AppConfig, interactive bool) (string, error) {
	if cfg == nil {
		return "", nil
	}
	compliance := cfg.Server.Compliance.Enabled
	configured := cfg.Server.Backup.Encryption.EncryptionPassword
	encConfigured := cfg.Server.Backup.Encryption.Enabled || configured != ""

	switch {
	case encConfigured && interactive:
		// The CLI always prompts interactively when encryption is configured;
		// per AI.md PART 21 there is no password flag.
		pw, err := promptBackupPassword("Backup encryption password: ")
		if err != nil {
			return "", err
		}
		return pw, nil
	case encConfigured:
		if configured == "" {
			return "", errors.New("backup encryption is enabled but no password is configured for a non-interactive backup")
		}
		return configured, nil
	case compliance:
		return "", errors.New("compliance mode enabled: backups are blocked until an encryption password is configured (server.backup.encryption)")
	default:
		return "", nil
	}
}

// backupArchiveLayout describes which directories a specific backup archive
// includes. Per AI.md PART 21, backups are non-credential by default: SSL
// private keys and the full data directory are excluded unless the operator
// opts in via --include-ssl / --include-data. server.yml, server.db,
// template/, and theme/ are always included.
type backupArchiveLayout struct {
	configDir   string
	dataDir     string
	dbDir       string
	includeSSL  bool
	includeData bool
}

// sslDir returns {config_dir}/ssl per AI.md PART 4/21.
func (l backupArchiveLayout) sslDir() string {
	return filepath.Join(l.configDir, "ssl")
}

// dbNestedInData reports whether dbDir sits inside dataDir. The relationship
// varies per platform/privilege branch (src/paths/paths.go) — e.g. Linux
// root/user and macOS user nest db/ under the data dir, while Windows root,
// macOS root, and container mode keep them as independent siblings — so this
// must be detected at runtime rather than assumed fixed.
func (l backupArchiveLayout) dbNestedInData() bool {
	return isUnderDir(l.dbDir, l.dataDir)
}

// configExcludes returns subtrees of configDir to skip when hashing/archiving
// it: the ssl/ directory, unless --include-ssl was passed.
func (l backupArchiveLayout) configExcludes() []string {
	if l.includeSSL {
		return nil
	}
	return []string{l.sslDir()}
}

// dataExcludes returns subtrees of dataDir to skip when hashing/archiving it:
// dbDir's subtree, if it happens to be nested under dataDir on this
// platform, so the db/ archive entry is never duplicated.
func (l backupArchiveLayout) dataExcludes() []string {
	if l.dbNestedInData() {
		return []string{l.dbDir}
	}
	return nil
}

// isUnderDir reports whether path equals dir or is nested inside it.
func isUnderDir(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}
	cleanPath := filepath.Clean(path)
	cleanDir := filepath.Clean(dir)
	return cleanPath == cleanDir || strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator))
}

// isExcludedPath reports whether p falls under any of the given excludes.
func isExcludedPath(p string, excludes []string) bool {
	for _, ex := range excludes {
		if isUnderDir(p, ex) {
			return true
		}
	}
	return false
}

// fileExists reports whether p exists and is a regular file.
func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// dirExists reports whether p exists and is a directory.
func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// backupArchiveContents returns the manifest.json "contents" list reflecting
// what this specific archive actually includes (AI.md PART 21 Backup
// Contents table) — dynamic per the layout's flags and what exists on disk,
// never a hardcoded list.
func backupArchiveContents(layout backupArchiveLayout) []string {
	var contents []string
	if fileExists(filepath.Join(layout.configDir, "server.yml")) {
		contents = append(contents, "server.yml")
	}
	if dirExists(layout.dbDir) {
		contents = append(contents, "server.db")
	}
	if dirExists(filepath.Join(layout.configDir, "template")) {
		contents = append(contents, "template/")
	}
	if dirExists(filepath.Join(layout.configDir, "theme")) {
		contents = append(contents, "theme/")
	}
	if layout.includeSSL && dirExists(layout.sslDir()) {
		contents = append(contents, "ssl/")
	}
	if layout.includeData && dirExists(layout.dataDir) {
		contents = append(contents, "data/")
	}
	return contents
}

// hashBackupDirInto feeds every regular file under dir (recursively, minus
// excludes) into h, in filepath.Walk order. Missing dirs are silently
// skipped, matching addBackupDirToTar's behavior so the checksum always
// matches what was archived.
func hashBackupDirInto(h hash.Hash, dir string, excludes ...string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return filepath.Walk(dir, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if isExcludedPath(p, excludes) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", p, readErr)
		}
		_, _ = h.Write(data)
		return nil
	})
}

// computeBackupContentChecksum returns the "sha256:<hex>" digest of every
// file this layout includes: configDir (minus ssl/ unless included), dbDir
// (always), then dataDir (minus dbDir's subtree) if includeData. Used both to
// populate manifest.json's checksum field at backup time and to re-verify
// content integrity after extraction (AI.md PART 21 verification: "Checksum
// valid").
func computeBackupContentChecksum(layout backupArchiveLayout) (string, error) {
	h := sha256.New()
	if err := hashBackupDirInto(h, layout.configDir, layout.configExcludes()...); err != nil {
		return "", err
	}
	if err := hashBackupDirInto(h, layout.dbDir); err != nil {
		return "", err
	}
	if layout.includeData {
		if err := hashBackupDirInto(h, layout.dataDir, layout.dataExcludes()...); err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// buildBackupArchive assembles an in-memory tar.gz containing manifest.json,
// the config directory (minus ssl/ unless layout.includeSSL), a fixed "db"
// entry for layout.dbDir (always included per AI.md PART 21), and the data
// directory only when layout.includeData is set. Building in memory (rather
// than shelling out to tar against a disk file) lets the caller encrypt the
// bytes before anything unencrypted touches disk. manifest["checksum"] and
// manifest["contents"] are populated from the layout actually archived.
func buildBackupArchive(manifest map[string]interface{}, layout backupArchiveLayout) ([]byte, error) {
	checksum, err := computeBackupContentChecksum(layout)
	if err != nil {
		return nil, fmt.Errorf("compute checksum: %w", err)
	}
	manifest["checksum"] = checksum
	manifest["contents"] = backupArchiveContents(layout)

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := addBackupFileToTar(tw, "manifest.json", manifestBytes); err != nil {
		return nil, err
	}
	if err := addBackupDirToTar(tw, layout.configDir, filepath.Base(layout.configDir), layout.configExcludes()...); err != nil {
		return nil, err
	}
	if err := addBackupDirToTar(tw, layout.dbDir, "db"); err != nil {
		return nil, err
	}
	if layout.includeData {
		if err := addBackupDirToTar(tw, layout.dataDir, filepath.Base(layout.dataDir), layout.dataExcludes()...); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}
	return buf.Bytes(), nil
}

func addBackupFileToTar(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write content %s: %w", name, err)
	}
	return nil
}

func addBackupDirToTar(tw *tar.Writer, srcDir, archivePrefix string, excludes ...string) error {
	info, err := os.Stat(srcDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", srcDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", srcDir)
	}
	return filepath.Walk(srcDir, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if isExcludedPath(p, excludes) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(srcDir, p)
		if relErr != nil {
			return relErr
		}
		name := archivePrefix
		if rel != "." {
			name = filepath.Join(archivePrefix, rel)
		}
		if fi.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0o700, Typeflag: tar.TypeDir})
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", p, readErr)
		}
		return addBackupFileToTar(tw, name, data)
	})
}

// extractBackupArchive extracts an in-memory tar.gz archive to destDir,
// guarding against path-traversal entries (zip-slip style attacks).
func extractBackupArchive(archiveBytes []byte, destDir string) error {
	gr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gr.Close()

	cleanDest := filepath.Clean(destDir)
	tr := tar.NewReader(gr)
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return fmt.Errorf("tar read: %w", terr)
		}
		cleanName := filepath.Clean(hdr.Name)
		if cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) || filepath.IsAbs(cleanName) {
			return fmt.Errorf("archive entry escapes destination: %s", hdr.Name)
		}
		target := filepath.Join(cleanDest, cleanName)
		if target != cleanDest && !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("archive entry escapes destination: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("mkdir parent of %s: %w", target, err)
			}
			f, ferr := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if ferr != nil {
				return fmt.Errorf("create %s: %w", target, ferr)
			}
			if _, cerr := io.Copy(f, tr); cerr != nil {
				f.Close()
				return fmt.Errorf("write %s: %w", target, cerr)
			}
			f.Close()
		default:
			// Skip symlinks, hardlinks, and other non-regular entries.
		}
	}
	return nil
}
