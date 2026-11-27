package run

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/apimgr/ipgaze/src/config"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Backup encryption per AI.md PART 21:
// - Algorithm: AES-256-GCM
// - Key Derivation: Argon2id (password -> 256-bit key)
// - File Extension: .tar.gz (unencrypted) or .tar.gz.enc (encrypted)
// - Password Storage: never persisted by this code path beyond the
//   optionally-configured server.yml value; interactive prompts are never
//   echoed and are never accepted via a CLI flag.

const (
	backupSaltLen         = 16
	backupNonceLen        = 12
	backupHeaderMagic     = "BKUP1"
	backupHeaderFixedLen  = 55
	backupMinArgonMemory  = 8192
	backupMaxArgonMemory  = 1048576
	backupMinArgonTime    = 1
	backupMaxArgonTime    = 10
	backupMinArgonThreads = 1
	backupMaxArgonThreads = 16
	// AES-256
	backupKeyLen = 32
)

// BackupRestoreLimits bounds archive memory and disk expansion during restore.
type BackupRestoreLimits struct {
	MaxArchiveSize  int64
	MaxExpandedSize int64
	MaxFiles        int
	MaxFileSize     int64
	MaxRatio        int64
}

func defaultBackupRestoreLimits() BackupRestoreLimits {
	return BackupRestoreLimits{MaxArchiveSize: 1 << 30, MaxExpandedSize: 4 << 30, MaxFiles: 10000, MaxFileSize: 512 << 20, MaxRatio: 100}
}

// Argon2id tuning per OWASP minimum recommendations for interactive use.
const (
	backupArgonTime = 3
	// 64 MiB
	backupArgonMemory  = 64 * 1024
	backupArgonThreads = 4
)

// deriveBackupKey derives a 256-bit AES key from a password and archive KDF parameters.
func deriveBackupKeyWithParams(password string, salt []byte, memory, iterations, threads uint32) []byte {
	return argon2.IDKey([]byte(password), salt, iterations, memory, uint8(threads), backupKeyLen)
}

func deriveBackupKey(password string, salt []byte) []byte {
	return deriveBackupKeyWithParams(password, salt, backupArgonMemory, backupArgonTime, backupArgonThreads)
}

type backupEncryptionHeader struct {
	salt                        []byte
	memory, iterations, threads uint32
	nonce                       []byte
	keyID                       string
	baseName                    string
	raw                         []byte
}

func backupKeyID(key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("key-id"))
	return hex.EncodeToString(mac.Sum(nil)[:4])
}

func readBackupEncryptionHeader(data []byte) (backupEncryptionHeader, error) {
	if len(data) < backupHeaderFixedLen || string(data[:5]) != backupHeaderMagic {
		return backupEncryptionHeader{}, errors.New("corrupt backup header: missing BKUP1 header")
	}
	header := backupEncryptionHeader{salt: append([]byte(nil), data[5:21]...), memory: binary.BigEndian.Uint32(data[21:25]), iterations: binary.BigEndian.Uint32(data[25:29]), threads: binary.BigEndian.Uint32(data[29:33]), nonce: append([]byte(nil), data[33:45]...), keyID: string(data[45:53])}
	baseLen := int(binary.BigEndian.Uint16(data[53:55]))
	if baseLen > 255 || len(data) < backupHeaderFixedLen+baseLen+16 {
		return backupEncryptionHeader{}, errors.New("corrupt backup header: invalid base name length or truncated header")
	}
	keyIDBytes, keyIDErr := hex.DecodeString(header.keyID)
	if keyIDErr != nil || len(keyIDBytes) != 4 || strings.ToLower(header.keyID) != header.keyID {
		return backupEncryptionHeader{}, errors.New("corrupt backup header: invalid key identifier")
	}
	if baseLen > 0 {
		name := string(data[55 : 55+baseLen])
		if !utf8.ValidString(name) || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
			return backupEncryptionHeader{}, errors.New("corrupt backup header: invalid base filename")
		}
		header.baseName = name
	}
	if header.memory < backupMinArgonMemory || header.memory > backupMaxArgonMemory || header.iterations < backupMinArgonTime || header.iterations > backupMaxArgonTime || header.threads < backupMinArgonThreads || header.threads > backupMaxArgonThreads || header.memory < 8*header.threads {
		return backupEncryptionHeader{}, errors.New("corrupt backup header: Argon2id parameters exceed allowed bounds")
	}
	header.raw = data[:backupHeaderFixedLen+baseLen]
	return header, nil
}

// encryptBackupArchive writes the authenticated BKUP1 header and ciphertext.
// An optional base filename identifies an incremental archive in cleartext.
func encryptBackupArchive(plaintext []byte, password string, baseNames ...string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("encryptBackupArchive: empty password")
	}
	salt := make([]byte, backupSaltLen)
	if _, err := io.ReadFull(cryptorand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	nonce := make([]byte, backupNonceLen)
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	baseName := ""
	if len(baseNames) > 0 && baseNames[0] != "" {
		baseName = baseNames[0]
	}
	if len(baseName) > 255 || !utf8.ValidString(baseName) || strings.ContainsAny(baseName, `/\\`) {
		return nil, errors.New("encryptBackupArchive: invalid base filename")
	}
	key := deriveBackupKey(password, salt)
	header := make([]byte, 0, backupHeaderFixedLen+len(baseName))
	header = append(header, backupHeaderMagic...)
	header = append(header, salt...)
	var field [4]byte
	binary.BigEndian.PutUint32(field[:], backupArgonMemory)
	header = append(header, field[:]...)
	binary.BigEndian.PutUint32(field[:], backupArgonTime)
	header = append(header, field[:]...)
	binary.BigEndian.PutUint32(field[:], backupArgonThreads)
	header = append(header, field[:]...)
	header = append(header, nonce...)
	header = append(header, backupKeyID(key)...)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(baseName)))
	header = append(header, length[:]...)
	header = append(header, baseName...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, header)
	return append(header, ciphertext...), nil
}

// decryptBackupArchive validates attacker-controlled KDF parameters before
// deriving a key and authenticates the complete cleartext header as GCM AAD.
func decryptBackupArchive(data []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("decryptBackupArchive: empty password")
	}
	header, err := readBackupEncryptionHeader(data)
	if err != nil {
		return nil, err
	}
	key := deriveBackupKeyWithParams(password, header.salt, header.memory, header.iterations, header.threads)
	if !hmac.Equal([]byte(backupKeyID(key)), []byte(header.keyID)) {
		return nil, errors.New("decrypt: wrong password or corrupted archive")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, header.nonce, data[len(header.raw):], header.raw)
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
	compliance := cfg.Server.Compliance.IsEnabled()
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
// includes. Per AI.md PART 21, backups are non-credential by default: the
// secrets.yml copy blanks the host token and backup password, SSL private keys
// and the full data directory are excluded unless --include-ssl / --include-data
// is set, while server.yml, server.db, template/, and theme/ are always included.
type backupArchiveLayout struct {
	configDir   string
	dataDir     string
	dbDir       string
	cacheDBPath string
	includeSSL  bool
	includeData bool
}

// backupFileRecord describes one regular file in a full or incremental
// archive. Paths use slash separators and are relative to the archive root.
type backupFileRecord struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime string `json:"mtime"`
	SHA256  string `json:"sha256"`
	data    []byte `json:"-"`
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

func (l backupArchiveLayout) connectionTLSFiles() []string {
	if l.includeSSL {
		return nil
	}
	var candidates []string
	_ = filepath.Walk(l.configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path != l.configDir && (info.Mode()&os.ModeSymlink != 0 || filepath.Clean(path) == filepath.Clean(l.sslDir())) {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || (filepath.Ext(path) != ".yml" && filepath.Ext(path) != ".yaml") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var document yaml.Node
		if yaml.Unmarshal(data, &document) != nil || len(document.Content) == 0 {
			return nil
		}
		collectConnectionTLSPaths(document.Content[0], "", &candidates)
		return nil
	})
	root, err := filepath.Abs(l.sslDir())
	if err != nil {
		return nil
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	files := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		path := candidate
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			continue
		}
		linkInfo, err := os.Lstat(path)
		if err != nil || linkInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || seen[path] {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		seen[path] = true
		files = append(files, path)
	}
	sort.Strings(files)
	return files
}

func collectConnectionTLSPaths(node *yaml.Node, prefix string, paths *[]string) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index].Value, node.Content[index+1]
			full := key
			if prefix != "" {
				full = prefix + "." + key
			}
			switch full {
			case "server.database.ssl_ca", "server.database.ssl_cert", "server.database.ssl_key", "server.cache.tls_ca", "server.cache.tls_cert", "server.cache.tls_key":
				if value.Kind == yaml.ScalarNode && strings.TrimSpace(value.Value) != "" {
					*paths = append(*paths, strings.TrimSpace(value.Value))
				}
			default:
				collectConnectionTLSPaths(value, full, paths)
			}
		}
		return
	}
	for _, child := range node.Content {
		collectConnectionTLSPaths(child, prefix, paths)
	}
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
	contents := []string{"app_secrets.json"}
	if fileExists(filepath.Join(layout.configDir, "server.yml")) {
		contents = append(contents, "server.yml")
	}
	if fileExists(filepath.Join(layout.configDir, "secrets.yml")) {
		contents = append(contents, "secrets.yml")
	}
	if dirExists(filepath.Join(layout.configDir, "yaml.d")) {
		contents = append(contents, "yaml.d/")
	}
	if fileExists(filepath.Join(layout.dbDir, "server.db")) || (layout.cacheDBPath != "" && fileExists(layout.cacheDBPath)) {
		contents = append(contents, "server.db")
	}
	if dirExists(filepath.Join(layout.configDir, "template")) {
		contents = append(contents, "template/")
	}
	if dirExists(filepath.Join(layout.configDir, "theme")) {
		contents = append(contents, "theme/")
	}
	if dirExists(filepath.Join(layout.configDir, "security")) {
		contents = append(contents, "security/")
	}
	if dirExists(filepath.Join(layout.configDir, "html")) {
		contents = append(contents, "html/")
	}
	if layout.includeSSL && dirExists(layout.sslDir()) {
		contents = append(contents, "ssl/")
	} else if len(layout.connectionTLSFiles()) > 0 {
		contents = append(contents, "connection TLS files")
	}
	if layout.includeData && dirExists(layout.dataDir) {
		contents = append(contents, "data/")
	}
	return contents
}

// computeBackupContentChecksum returns the "sha256:<hex>" digest of every
// file this layout includes: configDir (minus ssl/ unless included), dbDir
// (always), then dataDir (minus dbDir's subtree) if includeData. Used both to
// populate manifest.json's checksum field at backup time and to re-verify
// content integrity after extraction (AI.md PART 21 verification: "Checksum
// valid").
func computeBackupContentChecksum(layout backupArchiveLayout) (string, error) {
	files, err := collectBackupFiles(layout)
	if err != nil {
		return "", err
	}
	return checksumBackupFiles(files), nil
}

// collectBackupFiles reads the exact regular-file set represented by layout.
// It keeps each file's data in memory so an incremental archive is built from
// one captured state and never needs an unencrypted staging file on disk.
func collectBackupFiles(layout backupArchiveLayout) ([]backupFileRecord, error) {
	var files []backupFileRecord
	walk := func(root, prefix string, excludes ...string) error {
		info, err := os.Stat(root)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", root, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", root)
		}
		return filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if isExcludedPath(path, excludes) {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			name := prefix
			if rel != "." {
				name = filepath.Join(prefix, rel)
			}
			name = filepath.ToSlash(name)
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if filepath.ToSlash(rel) == "secrets.yml" {
				data, err = redactBackupSecrets(data)
				if err != nil {
					return fmt.Errorf("redact backup secrets: %w", err)
				}
			}
			digest := sha256.Sum256(data)
			files = append(files, backupFileRecord{
				Path: name, Size: int64(len(data)), ModTime: fi.ModTime().UTC().Truncate(time.Second).Format(time.RFC3339Nano),
				SHA256: hex.EncodeToString(digest[:]), data: data,
			})
			return nil
		})
	}
	if err := walk(layout.configDir, filepath.Base(layout.configDir), layout.configExcludes()...); err != nil {
		return nil, err
	}
	if !layout.includeSSL {
		for _, path := range layout.connectionTLSFiles() {
			rel, err := filepath.Rel(layout.configDir, path)
			if err != nil {
				return nil, err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read connection TLS file: %w", err)
			}
			info, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("stat connection TLS file: %w", err)
			}
			digest := sha256.Sum256(data)
			files = append(files, backupFileRecord{
				Path: filepath.ToSlash(filepath.Join(filepath.Base(layout.configDir), rel)), Size: int64(len(data)),
				ModTime: info.ModTime().UTC().Truncate(time.Second).Format(time.RFC3339Nano),
				SHA256:  hex.EncodeToString(digest[:]), data: data,
			})
		}
	}
	if err := walk(layout.dbDir, "db"); err != nil {
		return nil, err
	}
	if layout.includeData {
		if err := walk(layout.dataDir, filepath.Base(layout.dataDir), layout.dataExcludes()...); err != nil {
			return nil, err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// redactBackupSecrets blanks credentials that must remain local to the source
// host. It edits only the in-memory YAML copy captured for the archive.
func redactBackupSecrets(data []byte) ([]byte, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse secrets.yml: %w", err)
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("secrets.yml root must be a mapping")
	}
	server := yamlMappingValue(document.Content[0], "server")
	if server == nil {
		return data, nil
	}
	if server.Kind != yaml.MappingNode {
		return nil, errors.New("secrets.yml server section must be a mapping")
	}
	blankYAMLValue(yamlMappingValue(server, "token"))
	backup := yamlMappingValue(server, "backup")
	if backup != nil {
		if backup.Kind != yaml.MappingNode {
			return nil, errors.New("secrets.yml server.backup section must be a mapping")
		}
		blankYAMLValue(yamlMappingValue(backup, "encryption_password"))
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, fmt.Errorf("encode redacted secrets.yml: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("finish redacted secrets.yml: %w", err)
	}
	return output.Bytes(), nil
}

func yamlMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func blankYAMLValue(value *yaml.Node) {
	if value == nil {
		return
	}
	value.Kind = yaml.ScalarNode
	value.Tag = "!!str"
	value.Value = ""
	value.Content = nil
	value.Style = yaml.DoubleQuotedStyle
}

// restoreBackupOperatorToken writes the target host's operator token into the
// extracted secrets file before the restored config replaces the live one.
func restoreBackupOperatorToken(configDir, token string) error {
	if token == "" {
		return errors.New("target operator token is empty")
	}
	path := filepath.Join(configDir, "secrets.yml")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read extracted secrets.yml: %w", err)
	}
	var document yaml.Node
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &document); err != nil {
			return fmt.Errorf("parse extracted secrets.yml: %w", err)
		}
	}
	if len(document.Content) == 0 {
		document.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return errors.New("extracted secrets.yml root must be a mapping")
	}
	server := yamlMappingValue(root, "server")
	if server == nil {
		server = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "server"}, server)
	} else if server.Kind != yaml.MappingNode {
		return errors.New("extracted secrets.yml server section must be a mapping")
	}
	setYAMLMappingValue(server, "token", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: token})
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return fmt.Errorf("encode extracted secrets.yml: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("finish extracted secrets.yml: %w", err)
	}
	if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write extracted secrets.yml: %w", err)
	}
	return nil
}

func setYAMLMappingValue(mapping *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1] = value
			return
		}
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func checksumBackupFiles(files []backupFileRecord) string {
	h := sha256.New()
	for _, file := range files {
		_, _ = io.WriteString(h, file.Path)
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(file.data)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func backupFileManifest(files []backupFileRecord) []backupFileRecord {
	manifest := make([]backupFileRecord, len(files))
	for i, file := range files {
		manifest[i] = backupFileRecord{Path: file.Path, Size: file.Size, ModTime: file.ModTime, SHA256: file.SHA256}
	}
	return manifest
}

// buildBackupArchive assembles an in-memory tar.gz containing manifest.json,
// the config directory (minus ssl/ unless layout.includeSSL), a fixed "db"
// entry for layout.dbDir (always included per AI.md PART 21), and the data
// directory only when layout.includeData is set. Building in memory (rather
// than shelling out to tar against a disk file) lets the caller encrypt the
// bytes before anything unencrypted touches disk. manifest["checksum"] and
// manifest["contents"] are populated from the layout actually archived.
func buildBackupArchive(manifest map[string]interface{}, layout backupArchiveLayout) ([]byte, error) {
	files, err := collectBackupFiles(layout)
	if err != nil {
		return nil, fmt.Errorf("collect backup files: %w", err)
	}
	return buildBackupArchiveFromFiles(manifest, layout, files)
}

func buildBackupArchiveFromFiles(manifest map[string]interface{}, layout backupArchiveLayout, files []backupFileRecord) ([]byte, error) {
	checksum := checksumBackupFiles(files)
	manifest["checksum"] = checksum
	manifest["sha256"] = checksum
	manifest["type"] = "full"
	if _, ok := manifest["snapshot_at"]; !ok {
		manifest["snapshot_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	manifest["files"] = backupFileManifest(files)
	manifest["contents"] = backupArchiveContents(layout)

	return encodeBackupFiles(manifest, files)
}

func buildIncrementalBackupArchiveFromFiles(manifest map[string]interface{}, current []backupFileRecord, baseArchiveBytes []byte, baseName, baseSHA256 string, layout backupArchiveLayout) ([]byte, error) {
	baseManifest, err := readBackupManifest(baseArchiveBytes)
	if err != nil {
		return nil, fmt.Errorf("read base manifest: %w", err)
	}
	if kind, _ := baseManifest["type"].(string); kind != "full" {
		return nil, fmt.Errorf("incremental base %q is not a full backup", baseName)
	}
	if !backupManifestContentsCompatible(baseManifest, layout) {
		return nil, fmt.Errorf("incremental base %q has different optional contents from the current backup layout", baseName)
	}
	baseFiles, err := parseBackupFileManifest(baseManifest["files"])
	if err != nil {
		return nil, fmt.Errorf("read base file list: %w", err)
	}
	baseByPath := make(map[string]backupFileRecord, len(baseFiles))
	for _, file := range baseFiles {
		baseByPath[file.Path] = file
	}
	currentByPath := make(map[string]backupFileRecord, len(current))
	var changed []backupFileRecord
	for _, file := range current {
		currentByPath[file.Path] = file
		old, exists := baseByPath[file.Path]
		if !exists || old.Size != file.Size || old.ModTime != file.ModTime || old.SHA256 != file.SHA256 {
			changed = append(changed, file)
		}
	}
	deleted := make([]string, 0)
	for path := range baseByPath {
		if _, ok := currentByPath[path]; !ok {
			deleted = append(deleted, path)
		}
	}
	sort.Strings(deleted)
	manifest["type"] = "incremental"
	if _, ok := manifest["snapshot_at"]; !ok {
		manifest["snapshot_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	manifest["base_backup"] = filepath.Base(baseName)
	manifest["base_sha256"] = baseSHA256
	manifest["deleted"] = deleted
	manifest["files"] = backupFileManifest(changed)
	manifest["checksum"] = checksumBackupFiles(changed)
	manifest["sha256"] = manifest["checksum"]
	manifest["contents"] = []string{"incremental"}
	return encodeBackupFiles(manifest, changed)
}

func backupManifestContentsCompatible(manifest map[string]interface{}, layout backupArchiveLayout) bool {
	raw, ok := manifest["contents"].([]interface{})
	if !ok {
		return false
	}
	actual := make([]string, 0, len(raw))
	for _, value := range raw {
		name, ok := value.(string)
		if !ok {
			return false
		}
		actual = append(actual, name)
	}
	expected := backupArchiveContents(layout)
	sort.Strings(actual)
	sort.Strings(expected)
	if len(actual) != len(expected) {
		return false
	}
	for i := range actual {
		if actual[i] != expected[i] {
			return false
		}
	}
	return true
}

func parseBackupFileManifest(value interface{}) ([]backupFileRecord, error) {
	entries, ok := value.([]interface{})
	if !ok {
		return nil, errors.New("files list is missing")
	}
	files := make([]backupFileRecord, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		fields, ok := entry.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid file record")
		}
		path, ok := fields["path"].(string)
		if !ok || !validBackupArchivePath(path) {
			return nil, fmt.Errorf("invalid file path %q", path)
		}
		if _, exists := seen[path]; exists {
			return nil, fmt.Errorf("duplicate file path %q", path)
		}
		seen[path] = struct{}{}
		size, ok := fields["size"].(float64)
		if !ok || size < 0 {
			return nil, fmt.Errorf("invalid size for %q", path)
		}
		mtime, ok := fields["mtime"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid mtime for %q", path)
		}
		digest, ok := fields["sha256"].(string)
		if !ok || len(digest) != sha256.Size*2 {
			return nil, fmt.Errorf("invalid SHA-256 for %q", path)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("invalid SHA-256 for %q", path)
		}
		if _, err := time.Parse(time.RFC3339Nano, mtime); err != nil {
			return nil, fmt.Errorf("invalid mtime for %q", path)
		}
		files = append(files, backupFileRecord{Path: path, Size: int64(size), ModTime: mtime, SHA256: digest})
	}
	return files, nil
}

func validBackupArchivePath(name string) bool {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	return name != "" && clean == name && clean != "." && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/")
}

func encodeBackupFiles(manifest map[string]interface{}, files []backupFileRecord) ([]byte, error) {
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
	for _, file := range files {
		if err := addBackupFileRecordToTar(tw, file); err != nil {
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

func addBackupFileRecordToTar(tw *tar.Writer, file backupFileRecord) error {
	modTime, err := time.Parse(time.RFC3339Nano, file.ModTime)
	if err != nil {
		return fmt.Errorf("parse mtime for %s: %w", file.Path, err)
	}
	hdr := &tar.Header{Name: file.Path, Mode: 0o600, Size: int64(len(file.data)), ModTime: modTime}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write header %s: %w", file.Path, err)
	}
	if _, err := tw.Write(file.data); err != nil {
		return fmt.Errorf("write content %s: %w", file.Path, err)
	}
	return nil
}

// readBackupArchiveFiles reads regular files from a tar.gz while excluding
// manifest.json, retaining their archive paths for integrity verification.
func readBackupArchiveFiles(archiveBytes []byte) ([]backupFileRecord, error) {
	gr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	var files []backupFileRecord
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name == "manifest.json" {
			continue
		}
		name := filepath.ToSlash(hdr.Name)
		if !validBackupArchivePath(name) {
			return nil, fmt.Errorf("invalid archive file path %q", hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
		if err != nil {
			return nil, fmt.Errorf("read archive file %q: %w", hdr.Name, err)
		}
		if int64(len(data)) != hdr.Size {
			return nil, fmt.Errorf("archive file %q size mismatch", hdr.Name)
		}
		digest := sha256.Sum256(data)
		files = append(files, backupFileRecord{Path: name, Size: hdr.Size, ModTime: hdr.ModTime.UTC().Format(time.RFC3339Nano), SHA256: hex.EncodeToString(digest[:]), data: data})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func validateBackupManifestFiles(manifest map[string]interface{}, archiveFiles []backupFileRecord) error {
	listed, err := parseBackupFileManifest(manifest["files"])
	if err != nil {
		return err
	}
	if len(listed) != len(archiveFiles) {
		return fmt.Errorf("manifest lists %d files but archive contains %d", len(listed), len(archiveFiles))
	}
	actualByPath := make(map[string]backupFileRecord, len(archiveFiles))
	for _, file := range archiveFiles {
		actualByPath[file.Path] = file
	}
	for _, listedFile := range listed {
		actual, ok := actualByPath[listedFile.Path]
		if !ok || actual.Size != listedFile.Size || actual.SHA256 != listedFile.SHA256 || actual.ModTime != listedFile.ModTime {
			return fmt.Errorf("manifest file metadata mismatch for %q", listedFile.Path)
		}
	}
	return nil
}

// applyBackupDeletions removes incremental tombstones from an extracted tree.
// Each path is validated before joining to prevent archive metadata traversal.
func applyBackupDeletions(root string, value interface{}) error {
	entries, ok := value.([]interface{})
	if !ok {
		return errors.New("incremental deleted list is missing")
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	for _, raw := range entries {
		name, ok := raw.(string)
		if !ok || !validBackupArchivePath(name) {
			return fmt.Errorf("invalid deleted path %q", raw)
		}
		target := filepath.Join(cleanRoot, filepath.FromSlash(name))
		if target == cleanRoot || !strings.HasPrefix(target, cleanRoot+string(os.PathSeparator)) {
			return fmt.Errorf("deleted path escapes restore directory: %q", name)
		}
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete restored path %q: %w", name, err)
		}
	}
	return nil
}

func backupBytesSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// validateCombinedBackupLimits applies restore limits to all archives in an
// incremental restore as one logical expansion, including the base archive.
func validateCombinedBackupLimits(archives [][]byte, limits BackupRestoreLimits) error {
	var compressed, expanded int64
	files := 0
	for _, archive := range archives {
		if len(archive) == 0 || int64(len(archive)) > limits.MaxArchiveSize {
			return fmt.Errorf("archive size %d exceeds limit %d", len(archive), limits.MaxArchiveSize)
		}
		compressed += int64(len(archive))
		gr, err := gzip.NewReader(bytes.NewReader(archive))
		if err != nil {
			return fmt.Errorf("gzip open: %w", err)
		}
		tr := tar.NewReader(gr)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				_ = gr.Close()
				return fmt.Errorf("tar read: %w", err)
			}
			if hdr.Size < 0 || hdr.Size > limits.MaxFileSize {
				_ = gr.Close()
				return fmt.Errorf("archive entry %q size %d exceeds limit %d", hdr.Name, hdr.Size, limits.MaxFileSize)
			}
			if hdr.Typeflag == tar.TypeReg {
				files++
				if files > limits.MaxFiles {
					_ = gr.Close()
					return fmt.Errorf("archive file count exceeds limit %d", limits.MaxFiles)
				}
			}
			if hdr.Size > 0 {
				if expanded > limits.MaxExpandedSize-hdr.Size {
					_ = gr.Close()
					return fmt.Errorf("expanded archive size exceeds limit %d", limits.MaxExpandedSize)
				}
				expanded += hdr.Size
			}
		}
		if err := gr.Close(); err != nil {
			return fmt.Errorf("close gzip reader: %w", err)
		}
	}
	if compressed > 0 && float64(expanded)/float64(compressed) > float64(limits.MaxRatio) {
		return fmt.Errorf("archive compression ratio exceeds limit %d", limits.MaxRatio)
	}
	return nil
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

// extractBackupArchive extracts an in-memory tar.gz archive to destDir,
// guarding against path-traversal entries (zip-slip style attacks).
func extractBackupArchive(archiveBytes []byte, destDir string) (retErr error) {
	return extractBackupArchiveWithLimits(archiveBytes, destDir, defaultBackupRestoreLimits())
}

func extractBackupArchiveWithLimits(archiveBytes []byte, destDir string, limits BackupRestoreLimits) (retErr error) {
	if len(archiveBytes) == 0 || int64(len(archiveBytes)) > limits.MaxArchiveSize {
		return fmt.Errorf("archive size %d exceeds limit %d", len(archiveBytes), limits.MaxArchiveSize)
	}
	gr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, gr.Close()) }()

	cleanDest := filepath.Clean(destDir)
	tr := tar.NewReader(gr)
	fileCount := 0
	var expandedSize int64
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return fmt.Errorf("tar read: %w", terr)
		}
		if hdr.Size < 0 || hdr.Size > limits.MaxFileSize {
			return fmt.Errorf("archive entry %q size %d exceeds limit %d", hdr.Name, hdr.Size, limits.MaxFileSize)
		}
		if hdr.Typeflag == tar.TypeReg {
			fileCount++
			if fileCount > limits.MaxFiles {
				return fmt.Errorf("archive file count exceeds limit %d", limits.MaxFiles)
			}
		}
		if hdr.Size > 0 {
			if expandedSize > limits.MaxExpandedSize-hdr.Size {
				return fmt.Errorf("expanded archive size exceeds limit %d", limits.MaxExpandedSize)
			}
			expandedSize += hdr.Size
			if float64(expandedSize)/float64(len(archiveBytes)) > float64(limits.MaxRatio) {
				return fmt.Errorf("archive compression ratio exceeds limit %d", limits.MaxRatio)
			}
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
			if _, cerr := io.CopyN(f, tr, hdr.Size); cerr != nil {
				return errors.Join(fmt.Errorf("write %s: %w", target, cerr), f.Close())
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("close %s: %w", target, err)
			}
		default:
			// Skip symlinks, hardlinks, and other non-regular entries.
		}
	}
	return nil
}
