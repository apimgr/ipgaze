// Package i2p implements the OPTIONAL I2P eepsite subsystem per AI.md
// PART 31.2. Unlike Tor (PART 31.1, auto-enabled when the tor binary is
// found), I2P is opt-in: no provider is contacted, no port is allocated,
// and no files are written unless server.i2p.enabled is true.
package i2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// I2PServiceConfig holds I2P eepsite configuration per AI.md PART 31.2.
type I2PServiceConfig struct {
	ConfigDir string
	DataDir   string
	LogDir    string
	// OPT-IN: the eepsite is created only when Enabled is true.
	Enabled bool
	// Binary is the path to the i2pd binary; empty = auto-detect.
	Binary string
	// SAMAddress is the SAMv3 bridge address for Model B, used only when
	// no i2pd binary is found. Default "127.0.0.1:7656".
	SAMAddress string
	// VirtualPort is the port exposed on the .b32.i2p address (default 80).
	VirtualPort int
	// InboundLength/OutboundLength are tunnel hop counts (0-7, default 3).
	InboundLength  int
	OutboundLength int
	// InboundQuantity/OutboundQuantity are parallel tunnel counts (1-16, default 5).
	InboundQuantity  int
	OutboundQuantity int
	// SignatureType is the SAM/destination signature type (7 = EdDSA-SHA512-Ed25519).
	SignatureType int
	// BootstrapTimeout is the destination/tunnel readiness wait, in seconds (default 300).
	BootstrapTimeout int
}

// Provider identifies which backend created the eepsite.
type Provider int

const (
	// ProviderNone means no provider was available (I2P disabled or unreachable).
	ProviderNone Provider = iota
	// ProviderI2PD spawns and manages a dedicated i2pd process (Model A).
	ProviderI2PD
	// ProviderSAM uses an external SAMv3 bridge (Model B).
	ProviderSAM
)

func (p Provider) String() string {
	switch p {
	case ProviderI2PD:
		return "i2pd"
	case ProviderSAM:
		return "sam"
	default:
		return "none"
	}
}

// service wraps a running eepsite. Unlike Tor's PROXY-protocol backend,
// I2P/SAM never prepend a PROXY header, so the backend listener here is
// plain — no go-proxyproto wrapping.
type service struct {
	provider       Provider
	eepsiteAddress string
	i2pBackendPort int
	// backendLn is the dedicated plain loopback listener the eepsite
	// forwards to.
	backendLn net.Listener
	// backendSrv serves the app's HTTP handler on backendLn, once attached
	// via I2PManager.ServeBackend.
	backendSrv *http.Server
	// i2pd is the managed i2pd process (Model A only).
	i2pd *exec.Cmd
	// samConn is the live SAM control connection (Model B only), kept open
	// for the session lifetime (STREAM FORWARD requires it to stay up).
	samConn net.Conn
}

// I2PManager manages the I2P eepsite lifecycle. It stores no backend port
// itself — the dedicated port is allocated inside startDedicated, only
// once a provider is confirmed available.
// ErrNoProvider reports that I2P is enabled but neither an i2pd binary nor a
// reachable SAM bridge was found. Per AI.md PART 31.2 this is a WARN-and-
// continue condition, not a server error, but it is a distinct reported state
// ("No Provider") rather than a plain failure.
var ErrNoProvider = errors.New("i2p enabled but no provider available")

type I2PManager struct {
	cfg     I2PServiceConfig
	mu      sync.RWMutex
	svc     *service
	running bool
	// startErr holds the last start failure so Status()/GetInfo() can report
	// the "error:{short message}" and "no provider" states.
	startErr error
	// pendingHandler is applied to the backend listener once Start()
	// creates it, and re-applied on every Restart()/regenerate cycle.
	pendingHandler http.Handler
}

// NewI2PManager creates a new I2P manager. I2P stays disabled until
// Start() is called and cfg.Enabled is true.
func NewI2PManager(cfg I2PServiceConfig) *I2PManager {
	return &I2PManager{cfg: cfg}
}

// resolveI2PDBinary locates the i2pd executable: an explicit cfg.Binary
// override wins, then common install locations, then $PATH. Returns ""
// when no i2pd binary is available — the caller falls back to SAM.
func (m *I2PManager) resolveI2PDBinary() string {
	if m.cfg.Binary != "" {
		if _, err := os.Stat(m.cfg.Binary); err == nil {
			return m.cfg.Binary
		}
		return ""
	}
	for _, p := range []string{
		"/usr/bin/i2pd",
		"/usr/sbin/i2pd",
		"/usr/local/bin/i2pd",
		"/opt/homebrew/bin/i2pd",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("i2pd"); err == nil {
		return p
	}
	return ""
}

// samReachable reports whether a SAMv3 bridge is accepting connections at addr.
func samReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// IsAvailable reports whether I2P is enabled and at least one provider
// (i2pd binary or reachable SAM bridge) can be found. It does not spawn
// or connect to anything persistent.
func (m *I2PManager) IsAvailable() bool {
	if !m.cfg.Enabled {
		return false
	}
	if m.resolveI2PDBinary() != "" {
		return true
	}
	samAddr := m.cfg.SAMAddress
	if samAddr == "" {
		samAddr = "127.0.0.1:7656"
	}
	return samReachable(samAddr)
}

// Start creates the eepsite when I2P is enabled and a provider is
// available. I2P is opt-in and optional — disabled, or no provider found,
// is logged at WARN/INFO, never an error, and the server continues.
func (m *I2PManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}
	if !m.cfg.Enabled {
		return nil
	}

	svc, err := m.startDedicated(context.Background())
	if err != nil {
		// I2P is opt-in and optional: a missing provider or a failed start
		// is recorded and reported by Status()/GetInfo(), never fatal.
		m.startErr = err
		log.Printf("I2P not started: %v", err)
		return nil
	}
	m.startErr = nil
	m.svc = svc
	m.running = true

	if m.pendingHandler != nil {
		m.attachBackendHandlerLocked(m.pendingHandler)
	}

	log.Printf("I2P eepsite started (%s): %s", svc.provider, svc.eepsiteAddress)
	return nil
}

// ServeBackend attaches the app's HTTP handler to the dedicated plain
// backend listener so requests forwarded by the I2P provider
// (.b32.i2p:{virtual_port} -> 127.0.0.1:{i2p_backend_port}) are actually
// served. Safe to call before or after Start(); the handler is retained
// and re-attached across Restart()/regenerate cycles.
func (m *I2PManager) ServeBackend(handler http.Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingHandler = handler
	if m.running && m.svc != nil {
		m.attachBackendHandlerLocked(handler)
	}
}

func (m *I2PManager) attachBackendHandlerLocked(handler http.Handler) {
	if m.svc == nil || m.svc.backendLn == nil || m.svc.backendSrv != nil {
		return
	}
	srv := &http.Server{Handler: handler}
	m.svc.backendSrv = srv
	go func() {
		if err := srv.Serve(m.svc.backendLn); err != nil && err != http.ErrServerClosed {
			log.Printf("I2P: backend listener error: %v", err)
		}
	}()
}

// closeServiceLocked shuts down the provider (i2pd process or SAM
// session) and the backend listener. Callers must hold m.mu.
func closeServiceLocked(svc *service) error {
	if svc == nil {
		return nil
	}
	if svc.backendSrv != nil {
		_ = svc.backendSrv.Close()
	}
	if svc.samConn != nil {
		svc.samConn.Close()
		svc.samConn = nil
	}
	if svc.i2pd != nil && svc.i2pd.Process != nil {
		err := svc.i2pd.Process.Signal(os.Interrupt)
		svc.i2pd = nil
		return err
	}
	return nil
}

// Stop terminates the I2P provider and its dedicated backend listener.
func (m *I2PManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running || m.svc == nil {
		return nil
	}
	err := closeServiceLocked(m.svc)
	m.svc = nil
	m.running = false
	log.Println("I2P: eepsite stopped")
	return err
}

// Restart stops and starts I2P — used for config changes and recovery.
func (m *I2PManager) Restart() error {
	if err := m.Stop(); err != nil {
		log.Printf("I2P: restart - stop error: %v", err)
	}
	return m.Start()
}

// UpdateConfig applies new settings and restarts I2P. If the new config
// disables I2P, Start() returns early and the eepsite stays down —
// opt-in respected.
func (m *I2PManager) UpdateConfig(cfg I2PServiceConfig) error {
	if err := m.Stop(); err != nil {
		log.Printf("I2P: update config - stop error: %v", err)
	}
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
	return m.Start()
}

// RegenerateAddress deletes the current destination key and starts a
// fresh eepsite, which causes a brand new destination to be generated.
// Returns the new .b32.i2p address.
func (m *I2PManager) RegenerateAddress() (string, error) {
	if err := m.Stop(); err != nil {
		log.Printf("I2P: regenerate - stop error: %v", err)
	}

	m.mu.RLock()
	dataDir := m.cfg.DataDir
	m.mu.RUnlock()

	siteDir := filepath.Join(dataDir, "i2p", "site")
	if err := os.RemoveAll(siteDir); err != nil {
		return "", fmt.Errorf("remove old i2p keys: %w", err)
	}

	if err := m.Start(); err != nil {
		return "", err
	}
	return m.EepsiteAddress(), nil
}

// EepsiteAddress returns the current .b32.i2p address (empty if not running).
func (m *I2PManager) EepsiteAddress() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.svc == nil {
		return ""
	}
	return m.svc.eepsiteAddress
}

// IsRunning returns true if the eepsite is running.
func (m *I2PManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Status returns the current status string.
func (m *I2PManager) Status() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.statusLocked()
}

func (m *I2PManager) statusLocked() string {
	if !m.running {
		if !m.cfg.Enabled {
			return "disabled"
		}
		if errors.Is(m.startErr, ErrNoProvider) {
			return "no provider"
		}
		if m.startErr != nil {
			return "error:" + shortErrorMessage(m.startErr)
		}
		return "stopped"
	}
	if m.svc == nil || m.svc.eepsiteAddress == "" {
		return "starting"
	}
	return "healthy"
}

// shortErrorMessage renders err as the single-line, bounded summary the
// health payload's "error:{short message}" form expects.
func shortErrorMessage(err error) string {
	const maxLen = 120
	msg := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if len(msg) > maxLen {
		msg = msg[:maxLen]
	}
	return msg
}

// Info holds status fields returned by the API/CLI.
type Info struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Provider string `json:"provider,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// GetInfo returns current I2P info for API/CLI responses.
func (m *I2PManager) GetInfo() Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hostname := ""
	provider := ProviderNone.String()
	if m.svc != nil {
		hostname = m.svc.eepsiteAddress
		provider = m.svc.provider.String()
	}
	return Info{
		Enabled:  m.cfg.Enabled,
		Running:  m.running,
		Status:   m.statusLocked(),
		Provider: provider,
		Hostname: hostname,
	}
}

// GetHostname returns the .b32.i2p hostname (with .b32.i2p suffix).
func (m *I2PManager) GetHostname() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.svc == nil {
		return ""
	}
	return m.svc.eepsiteAddress
}

// Close shuts down the I2P provider. Equivalent to Stop() — provided to
// match the AI.md PART 31.2 I2PManager.Close naming.
func (m *I2PManager) Close() error {
	return m.Stop()
}

// getI2PTunnelsConf generates the i2pd server-tunnel definition (Model A).
// tunnels.conf is derived state, regenerated on every startup from
// I2PServiceConfig + the current backend port. The destination identity
// persists via keysPath (site-keys.dat), NOT via tunnels.conf, so
// overwriting it is always safe.
func getI2PTunnelsConf(cfg I2PServiceConfig, keysPath string, i2pBackendPort int) string {
	return fmt.Sprintf(`[site]
type = server
host = 127.0.0.1
port = %d
keys = %s
inbound.length = %d
outbound.length = %d
inbound.quantity = %d
outbound.quantity = %d
signaturetype = %d
`, i2pBackendPort, keysPath,
		cfg.InboundLength, cfg.OutboundLength,
		cfg.InboundQuantity, cfg.OutboundQuantity, cfg.SignatureType)
}

// ensureI2PDirs creates all I2P directories with correct permissions
// BEFORE any file is written (mirrors ensureTorDirs), re-enforcing
// chmod/chown on every call.
func ensureI2PDirs(configDir, dataDir string) error {
	dirs := []string{
		filepath.Join(configDir, "i2p"),
		filepath.Join(dataDir, "i2p"),
		filepath.Join(dataDir, "i2p", "site"),
	}
	uid := os.Getuid()
	gid := os.Getgid()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create i2p dir %s: %w", d, err)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return fmt.Errorf("chmod i2p dir %s: %w", d, err)
		}
		if runtime.GOOS != "windows" {
			if err := os.Chown(d, uid, gid); err != nil {
				return fmt.Errorf("chown i2p dir %s: %w", d, err)
			}
		}
	}
	return nil
}

// updateI2PTunnels (over)writes tunnels.conf with the given content,
// re-enforcing permissions every call. Called at every startup — the
// backend port changes each run, so tunnels.conf is always regenerated
// (never preserved).
func updateI2PTunnels(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write tunnels.conf: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod tunnels.conf: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chown(path, os.Getuid(), os.Getgid()); err != nil {
			return fmt.Errorf("chown tunnels.conf: %w", err)
		}
	}
	return nil
}

// getRandomAvailablePort binds a loopback listener on a random free port
// and returns both the listener and its port — a dedicated PLAIN backend
// (no PROXY-protocol, unlike Tor), never the clearnet HTTP port, never
// persisted across restarts.
func getRandomAvailablePort() (net.Listener, int, error) {
	for attempt := 0; attempt < 20; attempt++ {
		b := make([]byte, 2)
		if _, err := rand.Read(b); err != nil {
			return nil, 0, fmt.Errorf("read random bytes: %w", err)
		}
		port := 64000 + (int(b[0])<<8|int(b[1]))%1000
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return ln, port, nil
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, fmt.Errorf("bind loopback listener: %w", err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
}

// b32Address derives the .b32.i2p address: base32(sha256(destination))
// without padding, lowercased, plus the ".b32.i2p" suffix.
func b32Address(destBinary []byte) string {
	sum := sha256.Sum256(destBinary)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(sum[:])) + ".b32.i2p"
}

// i2pBase64 is the I2P variant of base64: the standard alphabet with '+' and
// '/' replaced by '-' and '~'. SAM returns destinations in this encoding.
var i2pBase64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")

// decodeDestination decodes an I2P base64 destination string into its binary
// form. Padding is optional in SAM replies, so it is accepted either way.
func decodeDestination(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty destination")
	}
	if raw, err := i2pBase64.DecodeString(value); err == nil {
		return raw, nil
	}
	raw, err := i2pBase64.WithPadding(base64.NoPadding).DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode i2p destination: %w", err)
	}
	return raw, nil
}

// b32AddressFromBase64 derives the .b32.i2p address from an I2P base64
// destination string as returned by SAM (DEST GENERATE PUB= / NAMING LOOKUP
// VALUE=). The hash is taken over the decoded binary destination, never over
// the base64 text.
func b32AddressFromBase64(value string) (string, error) {
	raw, err := decodeDestination(value)
	if err != nil {
		return "", err
	}
	return b32Address(raw), nil
}

// destinationPrefixLen returns the length of the Destination structure at the
// start of an i2pd keys file: 256-byte public key + 128-byte signing key +
// a 3-byte certificate header (type byte plus a big-endian uint16 length)
// plus the certificate payload itself.
func destinationPrefixLen(data []byte) (int, error) {
	const headerLen = 384
	if len(data) < headerLen+3 {
		return 0, fmt.Errorf("i2p keys file too short (%d bytes)", len(data))
	}
	certLen := int(binary.BigEndian.Uint16(data[headerLen+1 : headerLen+3]))
	total := headerLen + 3 + certLen
	if len(data) < total {
		return 0, fmt.Errorf("i2p keys file truncated: need %d bytes, have %d", total, len(data))
	}
	return total, nil
}

// destinationFromKeysFile extracts the public Destination from the private key
// file i2pd persists. The file begins with the Destination structure, which is
// what the .b32.i2p address hashes — hashing the whole file (private key
// material included) yields an address the router never publishes.
func destinationFromKeysFile(data []byte) ([]byte, error) {
	n, err := destinationPrefixLen(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

// startDedicated resolves the I2P provider (i2pd binary preferred, else
// a reachable SAM bridge), allocates the dedicated plain backend port
// only once a provider is confirmed, and starts the eepsite. Returns an
// error (never fatal to the caller — see Start()) when I2P is disabled
// or no provider is available.
func (m *I2PManager) startDedicated(ctx context.Context) (*service, error) {
	if !m.cfg.Enabled {
		return nil, fmt.Errorf("i2p disabled (opt-in) - eepsite not started")
	}

	samAddr := m.cfg.SAMAddress
	if samAddr == "" {
		samAddr = "127.0.0.1:7656"
	}

	provider := ProviderNone
	i2pdBinary := m.resolveI2PDBinary()
	switch {
	case i2pdBinary != "":
		provider = ProviderI2PD
	case samReachable(samAddr):
		provider = ProviderSAM
	default:
		return nil, fmt.Errorf("%w (no i2pd binary, SAM %s unreachable)", ErrNoProvider, samAddr)
	}

	configDir := m.cfg.ConfigDir
	dataDir := m.cfg.DataDir
	if err := ensureI2PDirs(configDir, dataDir); err != nil {
		return nil, fmt.Errorf("i2p dirs: %w", err)
	}

	rawLn, i2pBackendPort, err := getRandomAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("allocate i2p backend port: %w", err)
	}

	keysPath := filepath.Join(dataDir, "i2p", "site", "site-keys.dat")
	svc := &service{provider: provider, i2pBackendPort: i2pBackendPort, backendLn: rawLn}

	switch provider {
	case ProviderI2PD:
		addr, err := m.startI2PD(ctx, i2pdBinary, keysPath, i2pBackendPort, svc)
		if err != nil {
			rawLn.Close()
			return nil, err
		}
		svc.eepsiteAddress = addr
	case ProviderSAM:
		addr, err := m.startSAMEepsite(samAddr, keysPath, i2pBackendPort, svc)
		if err != nil {
			rawLn.Close()
			return nil, err
		}
		svc.eepsiteAddress = addr
	}

	return svc, nil
}

// startI2PD writes tunnels.conf (regenerated each run) and starts a
// dedicated i2pd child process, then waits for the destination key file
// to appear so the .b32.i2p address can be derived from it. i2pd
// creates/persists site-keys.dat at keysPath.
func (m *I2PManager) startI2PD(ctx context.Context, binary, keysPath string, i2pBackendPort int, svc *service) (string, error) {
	tunnelsPath := filepath.Join(m.cfg.ConfigDir, "i2p", "tunnels.conf")
	logDir := m.cfg.LogDir
	if logDir == "" {
		logDir = m.cfg.DataDir
	}

	conf := getI2PTunnelsConf(m.cfg, keysPath, i2pBackendPort)
	if err := updateI2PTunnels(tunnelsPath, []byte(conf)); err != nil {
		return "", fmt.Errorf("failed to write tunnels.conf: %w", err)
	}
	log.Printf("Regenerated i2p tunnels.conf at %s (backend port %d)", tunnelsPath, i2pBackendPort)

	cmd := exec.CommandContext(ctx, binary,
		"--datadir", filepath.Join(m.cfg.DataDir, "i2p"),
		"--tunconf", tunnelsPath,
		"--log", "file",
		"--logfile", filepath.Join(logDir, "i2pd.log"),
	)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start i2pd: %w", err)
	}
	svc.i2pd = cmd

	bootstrapTimeout := m.cfg.BootstrapTimeout
	if bootstrapTimeout <= 0 {
		bootstrapTimeout = 300
	}
	deadline := time.Duration(bootstrapTimeout) * time.Second

	addr, err := waitForI2PDAddress(keysPath, deadline)
	if err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
		return "", err
	}
	return addr, nil
}

// waitForI2PDAddress polls for the destination key file i2pd persists at
// keysPath and derives the .b32.i2p address from the public Destination stored
// at the head of that file once it is complete.
func waitForI2PDAddress(keysPath string, timeout time.Duration) (string, error) {
	deadlineAt := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadlineAt) {
		if data, err := os.ReadFile(keysPath); err == nil && len(data) > 0 {
			dest, derr := destinationFromKeysFile(data)
			if derr == nil {
				return b32Address(dest), nil
			}
			// i2pd writes the file incrementally, so a short read is
			// expected until the key material is fully flushed.
			lastErr = derr
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return "", fmt.Errorf("timed out reading i2pd destination at %s: %w", keysPath, lastErr)
	}
	return "", fmt.Errorf("timed out waiting for i2pd destination at %s", keysPath)
}

// samDestination holds the private and public halves of a persisted SAM
// destination.
type samDestination struct {
	// priv is the I2P base64 private destination handed back to SESSION CREATE.
	priv string
	// pub is the I2P base64 public destination the .b32.i2p address hashes.
	pub string
}

// samPublicKeysPath returns the companion file holding the public half of the
// destination stored at keysPath. SAM only ever returns PUB= once, at DEST
// GENERATE time, so it must be persisted alongside the private key or the
// advertised address cannot be recomputed on a later start.
func samPublicKeysPath(keysPath string) string {
	return keysPath + ".pub"
}

// readSAMReply reads one line from the SAM control connection and
// verifies it begins with the expected reply prefix.
func readSAMReply(r *bufio.Reader, expectPrefix string) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read SAM reply: %w", err)
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, expectPrefix) {
		return "", fmt.Errorf("unexpected SAM reply (want %q): %q", expectPrefix, line)
	}
	if !strings.Contains(line, "RESULT=OK") {
		return "", fmt.Errorf("SAM error reply: %q", line)
	}
	return line, nil
}

// loadOrCreateSAMDestination loads the persisted destination from
// keysPath, or generates a new one via SAM DEST GENERATE and persists it,
// when none exists yet.
func loadOrCreateSAMDestination(conn net.Conn, r *bufio.Reader, keysPath string, sigType int) (samDestination, error) {
	if data, err := os.ReadFile(keysPath); err == nil && len(data) > 0 {
		priv := strings.TrimSpace(string(data))
		var pub string
		if pubData, perr := os.ReadFile(samPublicKeysPath(keysPath)); perr == nil {
			pub = strings.TrimSpace(string(pubData))
		}
		return samDestination{priv: priv, pub: pub}, nil
	}

	if _, err := fmt.Fprintf(conn, "DEST GENERATE SIGNATURE_TYPE=%d\n", sigType); err != nil {
		return samDestination{}, err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return samDestination{}, fmt.Errorf("read DEST GENERATE reply: %w", err)
	}
	line = strings.TrimSpace(line)

	var pub, priv string
	for _, field := range strings.Fields(line) {
		switch {
		case strings.HasPrefix(field, "PUB="):
			pub = strings.TrimPrefix(field, "PUB=")
		case strings.HasPrefix(field, "PRIV="):
			priv = strings.TrimPrefix(field, "PRIV=")
		}
	}
	if priv == "" || pub == "" {
		return samDestination{}, fmt.Errorf("malformed DEST GENERATE reply: %q", line)
	}

	if err := os.MkdirAll(filepath.Dir(keysPath), 0o700); err != nil {
		return samDestination{}, fmt.Errorf("create keys dir: %w", err)
	}
	if err := os.WriteFile(keysPath, []byte(priv), 0o600); err != nil {
		return samDestination{}, fmt.Errorf("persist destination key: %w", err)
	}
	pubPath := samPublicKeysPath(keysPath)
	if err := os.WriteFile(pubPath, []byte(pub), 0o600); err != nil {
		return samDestination{}, fmt.Errorf("persist public destination: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chown(keysPath, os.Getuid(), os.Getgid())
		_ = os.Chown(pubPath, os.Getuid(), os.Getgid())
	}

	return samDestination{priv: priv, pub: pub}, nil
}

// startSAMEepsite opens a SAMv3 control connection, loads (or generates
// and persists) the destination, creates a STREAM session, and forwards
// incoming streams to the dedicated backend port. Returns the .b32.i2p
// address. Model B: no PROXY-protocol header is ever sent by SAM/i2pd, so
// svc.backendLn (allocated by the caller) is served plain.
func (m *I2PManager) startSAMEepsite(samAddr, keysPath string, i2pBackendPort int, svc *service) (string, error) {
	conn, err := net.DialTimeout("tcp", samAddr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to dial SAM %s: %w", samAddr, err)
	}
	r := bufio.NewReader(conn)

	if _, err := fmt.Fprintf(conn, "HELLO VERSION MIN=3.0 MAX=3.3\n"); err != nil {
		conn.Close()
		return "", err
	}
	if _, err := readSAMReply(r, "HELLO REPLY"); err != nil {
		conn.Close()
		return "", err
	}

	dest, err := loadOrCreateSAMDestination(conn, r, keysPath, m.cfg.SignatureType)
	if err != nil {
		conn.Close()
		return "", err
	}

	if _, err := fmt.Fprintf(conn, "SESSION CREATE STYLE=STREAM ID=site DESTINATION=%s "+
		"inbound.length=%d outbound.length=%d inbound.quantity=%d outbound.quantity=%d\n",
		dest.priv, m.cfg.InboundLength, m.cfg.OutboundLength, m.cfg.InboundQuantity, m.cfg.OutboundQuantity); err != nil {
		conn.Close()
		return "", err
	}
	if _, err := readSAMReply(r, "SESSION STATUS"); err != nil {
		conn.Close()
		return "", err
	}

	if _, err := fmt.Fprintf(conn, "STREAM FORWARD ID=site PORT=%d HOST=127.0.0.1\n", i2pBackendPort); err != nil {
		conn.Close()
		return "", err
	}
	if _, err := readSAMReply(r, "STREAM STATUS"); err != nil {
		conn.Close()
		return "", err
	}

	svc.samConn = conn

	if dest.pub == "" {
		// The destination came from a key file persisted before the public
		// half was recorded, so ask the router for this session's own
		// destination and persist it for the next start.
		if _, err := fmt.Fprintf(conn, "NAMING LOOKUP NAME=ME\n"); err != nil {
			return "", fmt.Errorf("naming lookup: %w", err)
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read NAMING REPLY: %w", err)
		}
		line = strings.TrimSpace(line)
		for _, field := range strings.Fields(line) {
			if !strings.HasPrefix(field, "VALUE=") {
				continue
			}
			value := strings.TrimPrefix(field, "VALUE=")
			addr, aerr := b32AddressFromBase64(value)
			if aerr != nil {
				return "", fmt.Errorf("naming lookup returned an undecodable destination: %w", aerr)
			}
			if werr := os.WriteFile(samPublicKeysPath(keysPath), []byte(value), 0o600); werr != nil {
				return "", fmt.Errorf("persist public destination: %w", werr)
			}
			return addr, nil
		}
		return "", fmt.Errorf("unable to derive .b32.i2p address for persisted destination")
	}

	addr, err := b32AddressFromBase64(dest.pub)
	if err != nil {
		return "", fmt.Errorf("derive .b32.i2p address: %w", err)
	}
	return addr, nil
}
