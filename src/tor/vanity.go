package tor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// onionChecksumPrefix is the domain-separation string Tor's rend-spec-v3
// prepends to the public key when computing a v3 address checksum.
const onionChecksumPrefix = ".onion checksum"

// onionVersion is the v3 hidden-service address version byte (rend-spec-v3).
const onionVersion byte = 0x03

// secretKeyHeader is the 32-byte NUL-padded header Tor writes at the start
// of hs_ed25519_secret_key.
const secretKeyHeader = "== ed25519v1-secret: type0 =="

// publicKeyHeader is the 32-byte NUL-padded header Tor writes at the start
// of hs_ed25519_public_key.
const publicKeyHeader = "== ed25519v1-public: type0 =="

// onionKeyFiles are the three files that together define a hidden service
// identity under HiddenServiceDir.
var onionKeyFiles = []string{"hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname"}

// onionBase32 encodes v3 onion addresses: RFC 4648 base32, no padding.
// Tor addresses are lowercase, so callers lowercase the result.
var onionBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrVanitySearchRunning is returned when a second search is requested while
// one is already in progress for this manager.
var ErrVanitySearchRunning = errors.New("a vanity search is already running")

// OnionAddress derives the v3 .onion hostname for an ed25519 public key per
// rend-spec-v3: base32(PUBKEY || CHECKSUM || VERSION) + ".onion", where
// CHECKSUM is SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2].
func OnionAddress(pub ed25519.PublicKey) string {
	var buf [35]byte
	copy(buf[:32], pub)
	sum := onionChecksum(pub)
	buf[32] = sum[0]
	buf[33] = sum[1]
	buf[34] = onionVersion
	return strings.ToLower(onionBase32.EncodeToString(buf[:])) + ".onion"
}

// onionChecksum computes the two-byte v3 address checksum for a public key.
func onionChecksum(pub ed25519.PublicKey) [2]byte {
	h := sha3.New256()
	h.Write([]byte(onionChecksumPrefix))
	h.Write(pub)
	h.Write([]byte{onionVersion})
	digest := h.Sum(nil)
	return [2]byte{digest[0], digest[1]}
}

// EncodeSecretKeyFile renders the on-disk hs_ed25519_secret_key bytes for a
// Go ed25519 private key: the 32-byte NUL-padded header followed by the
// 64-byte expanded secret (clamped SHA-512 of the seed), per Tor's format.
func EncodeSecretKeyFile(priv ed25519.PrivateKey) []byte {
	out := make([]byte, 96)
	copy(out[:32], secretKeyHeader)
	expanded := sha512.Sum512(priv.Seed())
	expanded[0] &= 248
	expanded[31] &= 127
	expanded[31] |= 64
	copy(out[32:], expanded[:])
	return out
}

// EncodePublicKeyFile renders the on-disk hs_ed25519_public_key bytes: the
// 32-byte NUL-padded header followed by the raw 32-byte public key.
func EncodePublicKeyFile(pub ed25519.PublicKey) []byte {
	out := make([]byte, 64)
	copy(out[:32], publicKeyHeader)
	copy(out[32:], pub)
	return out
}

// DecodePublicKeyFile extracts the raw public key from hs_ed25519_public_key
// bytes, validating the header and total length.
func DecodePublicKeyFile(data []byte) (ed25519.PublicKey, error) {
	if len(data) != 64 {
		return nil, fmt.Errorf("public key file is %d bytes, want 64", len(data))
	}
	if string(trimNUL(data[:32])) != publicKeyHeader {
		return nil, errors.New("public key file header mismatch")
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, data[32:])
	return pub, nil
}

// trimNUL strips trailing NUL padding from a fixed-width header field.
func trimNUL(b []byte) []byte {
	return []byte(strings.TrimRight(string(b), "\x00"))
}

// MaxVanityPrefixLen is the longest prefix the built-in CPU search accepts.
// Expected work scales as 32^len, so 7+ characters are external-only
// (AI.md PART 31.1 "7+ characters are external-only").
const MaxVanityPrefixLen = 6

// ValidateVanityPrefix rejects prefixes a v3 address can never start with and
// prefixes beyond what the in-process CPU search is meant to attempt.
// Addresses are lowercase RFC 4648 base32, so only a-z and 2-7 are legal.
func ValidateVanityPrefix(prefix string) error {
	if prefix == "" {
		return errors.New("vanity prefix must not be empty")
	}
	if len(prefix) > MaxVanityPrefixLen {
		return fmt.Errorf("vanity prefix %q is %d characters — the built-in search accepts at most %d; "+
			"generate longer prefixes with a GPU-capable tool such as mkp224o and install the result with `tor import-keys <path>`",
			prefix, len(prefix), MaxVanityPrefixLen)
	}
	for _, c := range prefix {
		if (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') {
			continue
		}
		return fmt.Errorf("vanity prefix %q contains %q — only base32 characters a-z and 2-7 are valid", prefix, string(c))
	}
	return nil
}

// Vanity search states reported by `tor status` and /server/tor/status.
const (
	// VanityStateIdle means no search is running and no candidate exists.
	VanityStateIdle = "idle"
	// VanityStateRunning means workers are currently generating keys.
	VanityStateRunning = "running"
	// VanityStateFound means at least one candidate is waiting on disk and
	// no search is running.
	VanityStateFound = "found"
)

// VanityStatus is the point-in-time view of a vanity search, reported by
// `tor status` and by the /server/tor/status endpoint. Field names are fixed
// by AI.md PART 31.1 "Vanity Onion Address Search" → Progress.
type VanityStatus struct {
	State          string   `json:"state"`
	Prefix         string   `json:"prefix,omitempty"`
	Workers        int      `json:"workers,omitempty"`
	Attempts       uint64   `json:"attempts"`
	Rate           float64  `json:"rate"`
	ElapsedSeconds float64  `json:"elapsed_seconds"`
	Candidates     []string `json:"candidates,omitempty"`
	LastError      string   `json:"last_error,omitempty"`
}

// vanitySearch holds the state of a background vanity address search.
type vanitySearch struct {
	mu        sync.Mutex
	running   bool
	prefix    string
	workers   int
	startedAt time.Time
	stoppedAt time.Time
	attempts  atomic.Uint64
	found     []string
	lastErr   error
	cancel    context.CancelFunc
}

// elapsed reports how long the search ran (or has been running). It returns
// zero when no search has ever been started. Callers hold vs.mu.
func (vs *vanitySearch) elapsed() time.Duration {
	if vs.startedAt.IsZero() {
		return 0
	}
	if !vs.running && !vs.stoppedAt.IsZero() {
		return vs.stoppedAt.Sub(vs.startedAt)
	}
	return time.Since(vs.startedAt)
}

// VanityDir is the directory holding vanity candidates found for this
// server: {data_dir}/tor/vanity/{onion-address}/.
func (m *TorManager) VanityDir() string {
	return filepath.Join(m.cfg.DataDir, "tor", "vanity")
}

// DefaultVanityWorkers is the worker count used when the caller does not pick
// one: logical CPUs minus one (minimum one), leaving a core free to serve
// traffic while the search runs (AI.md PART 31.1).
func DefaultVanityWorkers() int {
	if n := runtime.NumCPU() - 1; n > 1 {
		return n
	}
	return 1
}

// StartVanitySearch begins a background search for a v3 address whose
// hostname starts with prefix. It returns as soon as the workers are
// launched; progress is reported by VanitySearchStatus. Passing workers <= 0
// defaults to DefaultVanityWorkers(); a count above the logical CPU count is
// clamped down to it.
func (m *TorManager) StartVanitySearch(prefix string, workers int) error {
	if err := ValidateVanityPrefix(prefix); err != nil {
		return err
	}
	if workers <= 0 {
		workers = DefaultVanityWorkers()
	}
	if max := runtime.NumCPU(); workers > max {
		workers = max
	}

	m.mu.Lock()
	if m.vanity == nil {
		m.vanity = &vanitySearch{}
	}
	vs := m.vanity
	m.mu.Unlock()

	vs.mu.Lock()
	if vs.running {
		running := vs.prefix
		vs.mu.Unlock()
		return fmt.Errorf("%w for prefix %q", ErrVanitySearchRunning, running)
	}
	ctx, cancel := context.WithCancel(context.Background())
	vs.running = true
	vs.prefix = prefix
	vs.workers = workers
	vs.startedAt = time.Now()
	vs.stoppedAt = time.Time{}
	vs.found = nil
	vs.lastErr = nil
	vs.cancel = cancel
	vs.attempts.Store(0)
	vs.mu.Unlock()

	outDir := m.VanityDir()
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		cancel()
		vs.mu.Lock()
		vs.running = false
		vs.stoppedAt = time.Now()
		vs.lastErr = err
		vs.mu.Unlock()
		return fmt.Errorf("create vanity dir: %w", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vanityWorker(ctx, vs, prefix, outDir)
		}()
	}
	go func() {
		wg.Wait()
		vs.mu.Lock()
		vs.running = false
		vs.stoppedAt = time.Now()
		vs.mu.Unlock()
		cancel()
	}()
	return nil
}

// StopVanitySearch cancels a running search, keeping any candidates already
// written to disk. It reports whether a search was actually running, so the
// caller can render the no-op message AI.md PART 31.1 mandates.
func (m *TorManager) StopVanitySearch() bool {
	m.mu.RLock()
	vs := m.vanity
	m.mu.RUnlock()
	if vs == nil {
		return false
	}
	vs.mu.Lock()
	running := vs.running
	cancel := vs.cancel
	vs.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return running
}

// vanityWorker generates keypairs until ctx is cancelled, persisting every
// address that matches prefix into its own directory under outDir.
func vanityWorker(ctx context.Context, vs *vanitySearch, prefix, outDir string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			vs.mu.Lock()
			vs.lastErr = err
			vs.mu.Unlock()
			return
		}
		vs.attempts.Add(1)
		addr := OnionAddress(pub)
		if !strings.HasPrefix(addr, prefix) {
			continue
		}
		if err := writeCandidate(outDir, addr, pub, priv); err != nil {
			vs.mu.Lock()
			vs.lastErr = err
			vs.mu.Unlock()
			return
		}
		vs.mu.Lock()
		vs.found = append(vs.found, addr)
		vs.mu.Unlock()
	}
}

// candidateTempPrefix marks the staging directory a candidate is built in
// before it is renamed into place; VanityCandidates skips these.
const candidateTempPrefix = ".vanity-"

// writeCandidate publishes a found keypair as {outDir}/{addr}/ atomically:
// the three files are written into a sibling staging directory that is then
// renamed into place, so a reader never observes a half-written candidate
// (AI.md PART 31.1 "written atomically (temp dir + rename)").
func writeCandidate(outDir, addr string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	tmp, err := os.MkdirTemp(outDir, candidateTempPrefix+"*")
	if err != nil {
		return fmt.Errorf("create candidate staging dir: %w", err)
	}
	if err := WriteKeySet(tmp, pub, priv); err != nil {
		os.RemoveAll(tmp) //nolint:errcheck
		return err
	}
	dst := filepath.Join(outDir, addr)
	if err := os.Rename(tmp, dst); err != nil {
		os.RemoveAll(tmp) //nolint:errcheck
		return fmt.Errorf("publish candidate %s: %w", addr, err)
	}
	return nil
}

// WriteKeySet writes the three hidden-service identity files for a keypair
// into dir, creating it 0700 with 0600 files per AI.md PART 31.1.
func WriteKeySet(dir string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod key dir: %w", err)
	}
	files := map[string][]byte{
		"hs_ed25519_secret_key": EncodeSecretKeyFile(priv),
		"hs_ed25519_public_key": EncodePublicKeyFile(pub),
		"hostname":              []byte(OnionAddress(pub) + "\n"),
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("chmod %s: %w", name, err)
		}
	}
	return nil
}

// VanitySearchStatus reports the current search progress and any candidates
// already found, including candidates persisted by an earlier search.
func (m *TorManager) VanitySearchStatus() VanityStatus {
	st := VanityStatus{State: VanityStateIdle}
	m.mu.RLock()
	vs := m.vanity
	m.mu.RUnlock()
	running := false
	if vs != nil {
		vs.mu.Lock()
		running = vs.running
		st.Prefix = vs.prefix
		st.Workers = vs.workers
		elapsed := vs.elapsed()
		if vs.lastErr != nil {
			st.LastError = shortErrMsg(vs.lastErr)
		}
		vs.mu.Unlock()
		st.Attempts = vs.attempts.Load()
		secs := elapsed.Seconds()
		// Milliseconds are enough resolution for a progress report and keep
		// the payload readable; the rate is derived from the exact duration.
		st.ElapsedSeconds = math.Round(secs*1000) / 1000
		if secs > 0 {
			st.Rate = math.Round(float64(st.Attempts)/secs*100) / 100
		}
	}
	st.Candidates = m.VanityCandidates()
	switch {
	case running:
		st.State = VanityStateRunning
	case len(st.Candidates) > 0:
		st.State = VanityStateFound
	}
	return st
}

// VanityCandidates lists the addresses stored under the vanity directory.
func (m *TorManager) VanityCandidates() []string {
	entries, err := os.ReadDir(m.VanityDir())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), candidateTempPrefix) {
			continue
		}
		if !hasKeySet(filepath.Join(m.VanityDir(), e.Name())) {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

// hasKeySet reports whether dir contains all three identity files.
func hasKeySet(dir string) bool {
	for _, f := range onionKeyFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return false
		}
	}
	return true
}

// ApplyVanityAddress installs a previously found vanity identity as the live
// hidden service: Stop Tor → replace the keys in the site dir → Start Tor,
// per AI.md PART 31.1's restart-trigger table. The argument may be a full
// candidate address or any unique prefix of one; it may be omitted entirely
// when exactly one candidate exists. The applied candidate's directory is
// removed afterwards, and any other candidates are kept.
func (m *TorManager) ApplyVanityAddress(address string) (string, error) {
	candidates := m.VanityCandidates()
	if len(candidates) == 0 {
		return "", errors.New("no vanity candidates found — run a vanity search first")
	}
	address, err := resolveVanityCandidate(address, candidates)
	if err != nil {
		return "", err
	}
	src := filepath.Join(m.VanityDir(), address)
	if !hasKeySet(src) {
		return "", fmt.Errorf("vanity candidate %q not found", address)
	}
	live, err := m.replaceSiteKeys(src)
	if err != nil {
		return "", err
	}
	// The candidate now lives in the site dir; drop the staging copy so the
	// same identity is not offered twice (AI.md PART 31.1 handoff step 5).
	if err := os.RemoveAll(src); err != nil {
		return "", fmt.Errorf("remove applied candidate %s: %w", src, err)
	}
	return live, nil
}

// resolveVanityCandidate maps the `tor vanity apply` argument onto exactly one
// candidate: an empty argument selects the sole candidate, an exact address
// wins outright, and anything else is treated as an address prefix. Zero or
// ambiguous matches are errors listing the candidates.
func resolveVanityCandidate(address string, candidates []string) (string, error) {
	if address == "" {
		if len(candidates) > 1 {
			return "", fmt.Errorf("multiple vanity candidates available (%s) — specify which address to apply", strings.Join(candidates, ", "))
		}
		return candidates[0], nil
	}
	var matches []string
	for _, c := range candidates {
		if c == address {
			return c, nil
		}
		if strings.HasPrefix(c, address) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no vanity candidate matches %q — available candidates: %s", address, strings.Join(candidates, ", "))
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("%q matches multiple vanity candidates (%s) — use a longer prefix", address, strings.Join(matches, ", "))
	}
}

// ImportKeys installs an external hidden-service identity from srcDir:
// Stop Tor → replace the keys in the site dir → Start Tor. The hostname file
// is optional in srcDir; it is derived from the public key when absent.
func (m *TorManager) ImportKeys(srcDir string) (string, error) {
	if srcDir == "" {
		return "", errors.New("import path must not be empty")
	}
	for _, f := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key"} {
		if _, err := os.Stat(filepath.Join(srcDir, f)); err != nil {
			return "", fmt.Errorf("missing %s in %s", f, srcDir)
		}
	}
	return m.replaceSiteKeys(srcDir)
}

// replaceSiteKeys stops Tor, copies the identity files from srcDir into the
// hidden-service site directory, and starts Tor again. Returns the resulting
// .onion address.
func (m *TorManager) replaceSiteKeys(srcDir string) (string, error) {
	if err := m.Stop(); err != nil {
		return "", fmt.Errorf("stop tor: %w", err)
	}

	siteDir := filepath.Join(m.cfg.DataDir, "tor", "site")
	if err := os.MkdirAll(siteDir, 0o700); err != nil {
		return "", fmt.Errorf("create site dir: %w", err)
	}
	if err := os.Chmod(siteDir, 0o700); err != nil {
		return "", fmt.Errorf("chmod site dir: %w", err)
	}

	pubData, err := os.ReadFile(filepath.Join(srcDir, "hs_ed25519_public_key"))
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}
	pub, err := DecodePublicKeyFile(pubData)
	if err != nil {
		return "", err
	}
	secData, err := os.ReadFile(filepath.Join(srcDir, "hs_ed25519_secret_key"))
	if err != nil {
		return "", fmt.Errorf("read secret key: %w", err)
	}
	if len(secData) != 96 || string(trimNUL(secData[:32])) != secretKeyHeader {
		return "", errors.New("secret key file is not in Tor's hs_ed25519_secret_key format")
	}
	address := OnionAddress(pub)

	writes := map[string][]byte{
		"hs_ed25519_secret_key": secData,
		"hs_ed25519_public_key": pubData,
		"hostname":              []byte(address + "\n"),
	}
	for name, data := range writes {
		path := filepath.Join(siteDir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return "", fmt.Errorf("chmod %s: %w", name, err)
		}
	}

	if err := m.Start(); err != nil {
		return "", fmt.Errorf("start tor: %w", err)
	}
	// AI.md PART 31.1 handoff step 4: a published hostname that differs from
	// the address derived from the installed key means Tor is serving an
	// identity nobody asked for — fail loudly instead of reporting it as OK.
	if live := m.GetHostname(); live != "" && live != address {
		log.Printf("Tor: ERROR: published hostname %s does not match the installed key's address %s", live, address)
		return "", fmt.Errorf("published hostname %s does not match the installed key's address %s", live, address)
	}
	return address, nil
}
