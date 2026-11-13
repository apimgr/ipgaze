package tor

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apimgr/ipgaze/src/server/metrics"
	"github.com/cretz/bine/control"
	binetorcmd "github.com/cretz/bine/tor"
	"github.com/pires/go-proxyproto"
)

// TorServiceConfig holds Tor hidden service configuration per AI.md PART 31.1.
type TorServiceConfig struct {
	ConfigDir string
	DataDir   string
	// LogDir is where torrc points its `Log notice file` directive.
	LogDir string
	// Binary is the path to the Tor binary; empty = auto-detect.
	Binary string
	// UseNetwork routes outbound connections through Tor.
	UseNetwork bool
	// MaxCircuits caps Tor circuits under construction; AI.md PART 31.1 maps
	// this to MaxClientCircuitsPending with a default of 32.
	MaxCircuits int
	// CircuitTimeout is circuit timeout in seconds.
	CircuitTimeout int
	// BootstrapTimeout is bootstrap timeout in seconds.
	BootstrapTimeout int
	// StartupTimeout bounds waiting for the control-port file, in seconds.
	StartupTimeout int
	// SafeLogging scrubs sensitive data from Tor logs.
	SafeLogging bool
	// MaxStreamsPerCircuit limits concurrent streams per circuit.
	MaxStreamsPerCircuit int
	// CloseCircuitOnStreamLimit closes a circuit when the stream limit is hit.
	CloseCircuitOnStreamLimit bool
	// BandwidthRate is the max bandwidth rate string (e.g. "1 MB").
	BandwidthRate string
	// BandwidthBurst is the max bandwidth burst string (e.g. "2 MB").
	BandwidthBurst string
	// MaxMonthlyBandwidth is monthly bandwidth limit (e.g. "100 GB", "unlimited").
	MaxMonthlyBandwidth string
	// NumIntroPoints is the number of introduction points (3-10).
	NumIntroPoints int
	// VirtualPort is the port exposed on the .onion address (default 80).
	VirtualPort int
}

var outboundHTTP = struct {
	sync.RWMutex
	transport http.RoundTripper
}{}

// SetOutboundHTTPClient configures the shared transport used by server-owned
// outbound HTTP clients. Passing nil restores direct connections.
func SetOutboundHTTPClient(client *http.Client) {
	outboundHTTP.Lock()
	defer outboundHTTP.Unlock()
	if client == nil {
		outboundHTTP.transport = nil
		return
	}
	if client.Transport == nil {
		outboundHTTP.transport = http.DefaultTransport
		return
	}
	outboundHTTP.transport = client.Transport
}

// NewHTTPClient creates a server-owned HTTP client using the configured Tor
// transport when outbound routing is enabled.
func NewHTTPClient(timeout time.Duration) *http.Client {
	outboundHTTP.RLock()
	transport := outboundHTTP.transport
	outboundHTTP.RUnlock()
	return &http.Client{Timeout: timeout, Transport: transport}
}

// ApplyOutboundTransport routes an existing client through Tor while keeping
// its TLS settings. It leaves the client untouched when Tor routing is off.
func ApplyOutboundTransport(client *http.Client) error {
	if client == nil {
		return errors.New("tor outbound HTTP client is nil")
	}
	outboundHTTP.RLock()
	transport := outboundHTTP.transport
	outboundHTTP.RUnlock()
	if transport == nil {
		return nil
	}
	torTransport, ok := transport.(*http.Transport)
	if !ok {
		return errors.New("tor outbound transport is not an HTTP transport")
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok {
		if client.Transport != nil {
			return errors.New("client transport cannot be safely routed through Tor")
		}
		base = http.DefaultTransport.(*http.Transport)
	}
	routed := base.Clone()
	routed.Proxy = nil
	routed.DialContext = torTransport.DialContext
	// ACME requests are short-lived; avoid reusing a pooled connection after a
	// managed Tor restart, when that connection may belong to the old process.
	routed.DisableKeepAlives = true
	client.Transport = routed
	return nil
}

// service owns the Tor child process, its control connection and hidden service.
// Per AI.md PART 31.1: the hidden service is declared in torrc via
// HiddenServiceDir/HiddenServicePort — never via control-port ADD_ONION.
// Tor itself generates and persists the v3 key + hostname under
// HiddenServiceDir; onionAddress is simply read from that hostname file.
type service struct {
	t              *binetorcmd.Tor
	cmd            *managedTorProcess
	ctrl           *control.Conn
	onionAddress   string
	torBackendPort int
	// backendLn is the dedicated PROXY-protocol loopback listener the
	// hidden service forwards to (HiddenServiceExportCircuitID haproxy).
	backendLn net.Listener
	// backendSrv serves the app's HTTP handler on backendLn, once attached
	// via TorManager.ServeBackend.
	backendSrv *http.Server
	dialer     *binetorcmd.Dialer
}

// TorManager manages the Tor hidden service via github.com/cretz/bine,
// declaring the hidden service in torrc (HiddenServiceDir/HiddenServicePort)
// rather than via the control-port ADD_ONION API.
type TorManager struct {
	cfg     TorServiceConfig
	mu      sync.RWMutex
	svc     *service
	running bool
	// outboundTransport resolves the current managed Tor dialer for each new
	// connection, so clients created before a restart follow the replacement.
	outboundTransport *http.Transport
	// pendingHandler is applied to the backend listener once Start()
	// creates it, and re-applied on every Restart()/regenerate cycle.
	pendingHandler http.Handler
	// lastErr is the reason the most recent Start() failed, surfaced in
	// the health payload as `features.tor.status: "error:{short message}"`
	// per AI.md PART 13's documented status format. Cleared on the next
	// successful Start().
	lastErr error
	// vanity holds the state of the background vanity-address search driven
	// by `tor vanity start` (see vanity.go). Nil until the first search.
	vanity *vanitySearch
}

// Validate re-checks the Tor installation and on-disk layout the way
// `{project_name} tor validate` reports it (AI.md PART 31.1): the binary must
// resolve, and the config/data/site directories plus torrc must be readable
// when they already exist. Returns nil when the configuration is usable.
func (m *TorManager) Validate() error {
	if m.resolveBinary() == "" {
		return errors.New("tor binary not found")
	}
	torrcPath := filepath.Join(m.cfg.ConfigDir, "tor", "torrc")
	if info, err := os.Stat(torrcPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory, expected the torrc file", torrcPath)
		}
		if _, err := os.ReadFile(torrcPath); err != nil {
			return fmt.Errorf("read torrc: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat torrc: %w", err)
	}
	for _, d := range []string{
		filepath.Join(m.cfg.ConfigDir, "tor"),
		filepath.Join(m.cfg.DataDir, "tor"),
		filepath.Join(m.cfg.DataDir, "tor", "site"),
	} {
		info, err := os.Stat(d)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", d, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", d)
		}
	}
	return nil
}

// TorrcPath returns the path to the generated torrc file.
func (m *TorManager) TorrcPath() string {
	return filepath.Join(m.cfg.ConfigDir, "tor", "torrc")
}

// SiteDir returns the hidden-service directory holding the v3 identity files.
func (m *TorManager) SiteDir() string {
	return filepath.Join(m.cfg.DataDir, "tor", "site")
}

// BackendPort returns the loopback port the hidden service forwards to, or 0
// when Tor is not running.
func (m *TorManager) BackendPort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.svc == nil {
		return 0
	}
	return m.svc.torBackendPort
}

// NewTorManager creates a new Tor manager.
// Auto-enabled when tor binary is found per AI.md PART 31.1.
func NewTorManager(cfg TorServiceConfig) *TorManager {
	m := &TorManager{cfg: cfg}
	m.outboundTransport = &http.Transport{DialContext: m.dialTor}
	return m
}

func (m *TorManager) dialTor(ctx context.Context, network, address string) (net.Conn, error) {
	m.mu.RLock()
	if !m.running || m.svc == nil || m.svc.dialer == nil {
		m.mu.RUnlock()
		return nil, errors.New("tor outbound routing is enabled but unavailable")
	}
	dialer := m.svc.dialer
	m.mu.RUnlock()
	return dialer.DialContext(ctx, network, address)
}

// resolveBinary locates the tor executable per AI.md PART 31.1's discovery
// order: configured server.tor.binary path, then common per-OS install
// locations, then PATH. Returns "" when tor cannot be found.
func (m *TorManager) resolveBinary() string {
	if m.cfg.Binary != "" {
		if _, err := os.Stat(m.cfg.Binary); err == nil {
			return m.cfg.Binary
		}
		return ""
	}
	// Common per-OS locations. Paths for other operating systems stat-fail
	// harmlessly, so the whole list is safe to probe on any platform.
	for _, p := range []string{
		"/usr/bin/tor",
		"/usr/sbin/tor",
		"/usr/local/bin/tor",
		"/opt/homebrew/bin/tor",
		"/opt/tor/bin/tor",
		`C:\Program Files\Tor\tor.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("tor"); err == nil {
		return p
	}
	return ""
}

// IsAvailable returns true if the tor binary is reachable.
func (m *TorManager) IsAvailable() bool {
	return m.resolveBinary() != ""
}

// Start starts the dedicated Tor process and creates the hidden service.
// Tor is optional — a missing binary is logged at INFO, not an error, and
// the server continues without a hidden service.
func (m *TorManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	if !m.IsAvailable() {
		metrics.TorEnabled.Set(0)
		metrics.TorRunning.Set(0)
		metrics.TorCircuitEstablished.Set(0)
		log.Println("Tor binary not found, hidden service disabled")
		return nil
	}
	metrics.TorEnabled.Set(1)

	svc, err := m.startDedicated(context.Background())
	if err != nil {
		metrics.TorRunning.Set(0)
		metrics.TorCircuitEstablished.Set(0)
		m.lastErr = err
		return err
	}
	m.svc = svc
	m.running = true
	m.lastErr = nil
	metrics.TorRunning.Set(1)
	metrics.TorCircuitEstablished.Set(1)

	if m.pendingHandler != nil {
		m.attachBackendHandlerLocked(m.pendingHandler)
	}

	// onionAddress already carries the .onion suffix straight from the
	// hidden-service hostname file; appending another one printed a
	// non-resolvable "…onion.onion".
	log.Printf("Tor: %s", svc.onionAddress)
	return nil
}

// ServeBackend attaches the app's HTTP handler to the dedicated
// PROXY-protocol backend listener so requests forwarded by Tor
// (.onion:{virtual_port} → 127.0.0.1:{tor_backend_port}) are actually
// served. Safe to call before or after Start(); the handler is retained
// and re-attached across Restart()/regenerate cycles.
func (m *TorManager) ServeBackend(handler http.Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingHandler = handler
	if m.running && m.svc != nil {
		m.attachBackendHandlerLocked(handler)
	}
}

// attachBackendHandlerLocked starts an http.Server on the dedicated
// PROXY-protocol backend listener. Callers must hold m.mu.
func (m *TorManager) attachBackendHandlerLocked(handler http.Handler) {
	if m.svc == nil || m.svc.backendLn == nil || m.svc.backendSrv != nil {
		return
	}
	countedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.TorRequestsTotal.Inc()
		handler.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: countedHandler}
	m.svc.backendSrv = srv
	go func() {
		if err := srv.Serve(m.svc.backendLn); err != nil && err != http.ErrServerClosed {
			log.Printf("Tor: backend listener error: %v", err)
		}
	}()
}

// Stop terminates the Tor process and its dedicated backend listener.
func (m *TorManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// A deliberate Stop() is not a failure condition — clear any stale
	// lastErr so a subsequent status query reports "stopped", not a
	// leftover error from an earlier failed Start(). This applies even
	// when there is nothing running to stop.
	m.lastErr = nil

	if !m.running || m.svc == nil {
		return nil
	}
	if m.svc.backendSrv != nil {
		_ = m.svc.backendSrv.Close()
	} else if m.svc.backendLn != nil {
		_ = m.svc.backendLn.Close()
	}
	if m.outboundTransport != nil {
		m.outboundTransport.CloseIdleConnections()
	}
	err := stopTor(m.svc.cmd, m.svc.ctrl)
	m.svc = nil
	m.running = false
	metrics.TorRunning.Set(0)
	metrics.TorCircuitEstablished.Set(0)
	log.Println("Tor: hidden service stopped")
	return err
}

// Restart stops and starts Tor — used for config changes and recovery.
func (m *TorManager) Restart() error {
	if err := m.Stop(); err != nil {
		log.Printf("Tor: restart — stop error: %v", err)
	}
	return m.Start()
}

// HealthCheck pings the live Tor control connection per AI.md PART 31.1's
// Tor Process Monitoring section. A GETINFO round-trip is the only reliable
// signal that the child process is still responsive — a live PID says
// nothing about a hung Tor. Returns nil when Tor is not running, so a
// disabled or unavailable Tor never reports as a failure.
func (m *TorManager) HealthCheck() error {
	m.mu.RLock()
	svc := m.svc
	running := m.running
	m.mu.RUnlock()

	if !running || svc == nil || svc.ctrl == nil {
		return nil
	}
	if _, err := svc.ctrl.GetInfo("version"); err != nil {
		metrics.TorRunning.Set(0)
		metrics.TorCircuitEstablished.Set(0)
		return fmt.Errorf("tor control probe failed: %w", err)
	}
	metrics.TorRunning.Set(1)
	return nil
}

// RegenerateAddress deletes the current hidden-service keys and starts a
// fresh Tor process, which causes Tor to generate a brand new v3 address
// under HiddenServiceDir. Returns the new .onion address.
func (m *TorManager) RegenerateAddress() (string, error) {
	m.mu.Lock()
	if m.running && m.svc != nil {
		if m.svc.backendSrv != nil {
			_ = m.svc.backendSrv.Close()
		} else if m.svc.backendLn != nil {
			_ = m.svc.backendLn.Close()
		}
		_ = stopTor(m.svc.cmd, m.svc.ctrl)
		m.svc = nil
		m.running = false
	}
	m.mu.Unlock()

	// Remove only the three v3 identity files, not the whole directory —
	// Tor regenerates them on the next start, and anything else the operator
	// keeps under HiddenServiceDir survives.
	siteDir := filepath.Join(m.cfg.DataDir, "tor", "site")
	for _, f := range onionKeyFiles {
		if err := os.Remove(filepath.Join(siteDir, f)); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("remove old key %s: %w", f, err)
		}
	}

	if err := m.Start(); err != nil {
		return "", err
	}
	return m.GetHostname(), nil
}

// ApplyKeys stops Tor, installs privateKey as the hidden service's v3
// identity, and restarts so the service comes up on that address. Returns
// the resulting .onion address. Per AI.md PART 32 this is the shared
// backend for both `vanity apply` and `import-keys`.
func (m *TorManager) ApplyKeys(privateKey []byte) (string, error) {
	// Reject anything that is not a real Tor expanded secret key before
	// stopping the running service, so a bad payload cannot take the hidden
	// service offline. Same check ImportKeys applies to its source file.
	if len(privateKey) != 96 || string(trimNUL(privateKey[:32])) != secretKeyHeader {
		return "", errors.New("private key is not in Tor's hs_ed25519_secret_key format")
	}

	if err := m.Stop(); err != nil {
		return "", fmt.Errorf("stop tor: %w", err)
	}

	siteDir := filepath.Join(m.cfg.DataDir, "tor", "site")
	if err := os.MkdirAll(siteDir, 0o700); err != nil {
		return "", fmt.Errorf("create site dir: %w", err)
	}

	// The public key and hostname are both derived from the secret key, so a
	// leftover pair from the previous identity would contradict the new one
	// and make Tor refuse to start. Remove them and let Tor regenerate both.
	for _, f := range []string{"hs_ed25519_public_key", "hostname"} {
		if err := os.Remove(filepath.Join(siteDir, f)); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("remove stale %s: %w", f, err)
		}
	}

	keyPath := filepath.Join(siteDir, "hs_ed25519_secret_key")
	if err := os.WriteFile(keyPath, privateKey, 0o600); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}

	if err := m.Start(); err != nil {
		return "", err
	}
	return m.GetHostname(), nil
}

// GetHostname returns the .onion hostname (with .onion suffix).
func (m *TorManager) GetHostname() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.svc == nil {
		return ""
	}
	return m.svc.onionAddress
}

// IsRunning returns true if tor is running.
func (m *TorManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Status returns the current status string.
func (m *TorManager) Status() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.statusLocked()
}

// statusLocked computes the status string. Callers must already hold
// m.mu (for reading) — this exists so callers that already hold RLock
// (e.g. GetInfo) never re-acquire it, which would deadlock against a
// concurrent writer waiting on Lock() (sync.RWMutex read locks are not
// reentrant once a writer is blocked).
func (m *TorManager) statusLocked() string {
	if !m.running {
		if !m.IsAvailable() {
			return "unavailable"
		}
		if m.lastErr != nil {
			return "error:" + shortErrMsg(m.lastErr)
		}
		return "stopped"
	}
	if m.svc == nil || m.svc.onionAddress == "" {
		return "starting"
	}
	return "healthy"
}

// shortErrMsg reduces an error to a single-line, length-capped message
// suitable for the `features.tor.status: "error:{short message}"` health
// field (AI.md PART 13) — long multi-line wrapped errors (e.g. from the
// underlying tor process) would otherwise bloat the health response.
func shortErrMsg(err error) string {
	msg := strings.ReplaceAll(err.Error(), "\n", " ")
	const maxLen = 120
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "…"
	}
	return msg
}

// Info holds status fields returned by the API.
type Info struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Hostname string `json:"hostname,omitempty"`
}

// GetInfo returns current tor info for API responses.
func (m *TorManager) GetInfo() Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hostname := ""
	if m.svc != nil {
		hostname = m.svc.onionAddress
	}
	return Info{
		Enabled:  m.IsAvailable(),
		Running:  m.running,
		Status:   m.statusLocked(),
		Hostname: hostname,
	}
}

// GetHTTPClient returns an HTTP client optionally routed through Tor.
func (m *TorManager) GetHTTPClient(useTor bool) *http.Client {
	if !useTor {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: m.outboundTransport,
	}
}

// getTorConfig generates torrc content per AI.md PART 31.1.
// The hidden service is declared here via HiddenServiceDir/HiddenServicePort
// — Tor itself generates and persists the v3 key + hostname under hsDir.
// All ports use runtime "auto" except the dedicated backend loopback port,
// which is allocated once per startup and never reused across restarts.
func getTorConfig(cfg TorServiceConfig, hsDir string, torBackendPort int) string {
	safeLogging := "1"
	if !cfg.SafeLogging {
		safeLogging = "0"
	}

	socksConfig := "SocksPort 0"
	if cfg.UseNetwork {
		// Bound to loopback only, with an explicit policy — never reachable
		// from the hidden-service listener — per AI.md PART 31.1's
		// "App-Scoped Only" torrc hardening rule.
		socksConfig = "SocksPort 127.0.0.1:auto\nSocksPolicy accept 127.0.0.1"
	}

	bwRate := cfg.BandwidthRate
	if bwRate == "" {
		bwRate = "1 MB"
	}
	bwBurst := cfg.BandwidthBurst
	if bwBurst == "" {
		bwBurst = "2 MB"
	}

	accountingConfig := ""
	if cfg.MaxMonthlyBandwidth != "" && cfg.MaxMonthlyBandwidth != "unlimited" {
		accountingConfig = fmt.Sprintf("\n# Monthly bandwidth limit\nAccountingStart month 1 00:00\nAccountingMax %s", cfg.MaxMonthlyBandwidth)
	}

	virtualPort := cfg.VirtualPort
	if virtualPort == 0 {
		virtualPort = 80
	}
	maxCircuits := cfg.MaxCircuits
	if maxCircuits <= 0 {
		maxCircuits = 32
	}

	// AI.md PART 31.1 pins the Tor log to {log_dir}/tor.log. Without this
	// directive Tor logged to stdout only and the documented file never
	// appeared. Omitted when no log directory was supplied.
	logConfig := ""
	if cfg.LogDir != "" {
		logConfig = fmt.Sprintf("\n# Tor log file\nLog notice file %s\n", filepath.Join(cfg.LogDir, "tor.log"))
	}

	// AI.md PART 31 pins the Tor PID file to {data_dir}/tor/tor.pid so an
	// operator (and the service scripts) can find the process without
	// scanning the process table.
	torDataDir := filepath.Join(cfg.DataDir, "tor")
	if cfg.DataDir != "" {
		logConfig += fmt.Sprintf("PidFile %s\n", filepath.Join(cfg.DataDir, "tor", "tor.pid"))
	}

	// Global circuit tuning from server.yml. Parsed into the config struct but
	// never emitted before, so changing circuit_timeout had no effect.
	circuitConfig := ""
	if cfg.CircuitTimeout > 0 {
		circuitConfig = fmt.Sprintf("CircuitBuildTimeout %d\n", cfg.CircuitTimeout)
	}

	// Per-hidden-service knobs. Tor scopes these to the preceding
	// HiddenServiceDir block, so they are emitted after it, not with the
	// global options above.
	closeOnLimit := "0"
	if cfg.CloseCircuitOnStreamLimit {
		closeOnLimit = "1"
	}
	hsTuning := fmt.Sprintf("HiddenServiceMaxStreamsCloseCircuit %s\n", closeOnLimit)
	if cfg.MaxStreamsPerCircuit > 0 {
		hsTuning = fmt.Sprintf("HiddenServiceMaxStreams %d\n", cfg.MaxStreamsPerCircuit) + hsTuning
	}
	if cfg.NumIntroPoints > 0 {
		hsTuning += fmt.Sprintf("HiddenServiceNumIntroductionPoints %d\n", cfg.NumIntroPoints)
	}

	return fmt.Sprintf(`# ============================================================
# Tor Configuration - Generated by server binary
# Regenerated every startup: backend port changes each run.
# The .onion identity persists via the keys under HiddenServiceDir.
# ============================================================

# SOCKS port for outbound connections (0 = disabled, auto = runtime port)
%s

# Control connection - runtime localhost port, never hardcoded. Start offline
# so the controller subscribes to bootstrap events before networking begins.
DataDirectory %s
ControlPort 127.0.0.1:auto
ControlPortWriteToFile %s
CookieAuthentication 1
DisableNetwork 1
__OwningControllerProcess %d

SafeLogging %s
%s
MaxCircuitDirtiness 600
MaxClientCircuitsPending %d
%s
BandwidthRate %s
BandwidthBurst %s
%s

ExitRelay 0
ExitPolicy reject *:*
PublishServerDescriptor 0
ORPort 0
DirPort 0

# Guard-discovery-attack defense (vanguards-lite) - built into Tor >= 0.4.7
VanguardsLiteEnabled 1

HiddenServiceSingleHopMode 0

FetchDirInfoEarly 1
FetchDirInfoExtraEarly 1

DisableDebuggerAttachment 1

# ============================================================
# Hidden Service (v3) - Tor generates and persists the key + hostname here
# ============================================================
HiddenServiceDir %s
HiddenServiceVersion 3
HiddenServicePort %d 127.0.0.1:%d
# Export per-rendezvous-circuit ID via HAProxy PROXY protocol (opaque token, not an IP)
HiddenServiceExportCircuitID haproxy
%s`, socksConfig, torDataDir, filepath.Join(torDataDir, "control_port"), os.Getpid(), safeLogging, logConfig, maxCircuits, circuitConfig, bwRate, bwBurst, accountingConfig, hsDir, virtualPort, torBackendPort, hsTuning)
}

// ensureTorDirs creates required Tor directories with secure permissions,
// re-enforcing chmod/chown on every call (idempotent, per AI.md PART 31.1).
func ensureTorDirs(configDir, dataDir string) error {
	dirs := []string{
		filepath.Join(configDir, "tor"),
		filepath.Join(dataDir, "tor"),
		filepath.Join(dataDir, "tor", "site"),
	}
	uid := os.Getuid()
	gid := os.Getgid()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return fmt.Errorf("chmod tor dir %s: %w", d, err)
		}
		if runtime.GOOS != "windows" {
			if err := os.Chown(d, uid, gid); err != nil {
				return fmt.Errorf("chown tor dir %s: %w", d, err)
			}
		}
	}
	return nil
}

// updateTorrc (over)writes torrc with the given content, re-enforcing
// permissions every call. Called at every startup — the backend port
// changes each run, so torrc is always regenerated (never preserved).
func updateTorrc(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write torrc: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod torrc: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chown(path, os.Getuid(), os.Getgid()); err != nil {
			return fmt.Errorf("chown torrc: %w", err)
		}
	}
	return nil
}

// getRandomAvailablePort binds a loopback listener on a random free port
// and returns both the listener and its port. Random-unused-port detection
// matching the server's own port allocation, but for the dedicated
// PROXY-protocol backend that the hidden service forwards to — never the
// clearnet HTTP port, and never persisted across restarts.
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
	// Fall back to letting the OS pick any free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, fmt.Errorf("bind loopback listener: %w", err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
}

// startDedicated starts a dedicated Tor process via bine and declares the
// hidden service in torrc (HiddenServiceDir/HiddenServicePort) — NOT via
// control-port ADD_ONION. Per AI.md PART 31.1: ControlPort 127.0.0.1:auto,
// HiddenServiceVersion 3, dedicated PROXY-protocol backend loopback port.
func (m *TorManager) startDedicated(ctx context.Context) (*service, error) {
	configDir := m.cfg.ConfigDir
	dataDir := m.cfg.DataDir

	if err := ensureTorDirs(configDir, dataDir); err != nil {
		return nil, fmt.Errorf("tor dirs: %w", err)
	}

	// Allocate the dedicated PROXY-protocol loopback port only now that Tor
	// is confirmed available. Not persisted: a fresh port is chosen each
	// run and torrc is regenerated to match.
	rawLn, torBackendPort, err := getRandomAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("allocate tor backend port: %w", err)
	}
	backendLn := &proxyproto.Listener{Listener: rawLn}

	torrcPath := filepath.Join(configDir, "tor", "torrc")
	torDataDir := filepath.Join(dataDir, "tor")
	hsDir := filepath.Join(dataDir, "tor", "site")
	hostnamePath := filepath.Join(hsDir, "hostname")

	torrcContent := getTorConfig(m.cfg, hsDir, torBackendPort)
	if err := updateTorrc(torrcPath, []byte(torrcContent)); err != nil {
		_ = backendLn.Close()
		return nil, fmt.Errorf("torrc: %w", err)
	}
	bin := m.resolveBinary()
	if bin == "" {
		bin = "tor"
	}
	controlPortFile := filepath.Join(torDataDir, "control_port")
	if err := removeStaleControlPort(controlPortFile); err != nil {
		_ = backendLn.Close()
		return nil, fmt.Errorf("remove stale Tor control-port file: %w", err)
	}
	child, err := spawnTor(ctx, bin, torrcPath)
	if err != nil {
		_ = backendLn.Close()
		return nil, fmt.Errorf("tor start: %w", err)
	}

	startupTimeout := time.Duration(m.cfg.StartupTimeout) * time.Second
	if startupTimeout <= 0 {
		startupTimeout = 60 * time.Second
	}
	controlAddr, err := waitControlPort(ctx, child, controlPortFile, startupTimeout)
	if err != nil {
		_ = stopTor(child, nil)
		_ = backendLn.Close()
		return nil, fmt.Errorf("tor control port (torrc %s): %w", torrcPath, err)
	}
	ctrl, controlConn, err := dialControl(ctx, controlAddr)
	if err != nil {
		_ = stopTor(child, nil)
		_ = backendLn.Close()
		return nil, fmt.Errorf("tor control authentication: %w", err)
	}

	events := make(chan control.Event, 64)
	if err := ctrl.AddEventListener(events, control.EventCodeStatusClient, control.EventCodeHSDesc); err != nil {
		_ = stopTor(child, ctrl)
		_ = backendLn.Close()
		return nil, fmt.Errorf("subscribe to Tor events: %w", err)
	}
	bootstrapTimeout := time.Duration(m.cfg.BootstrapTimeout) * time.Second
	if bootstrapTimeout <= 0 {
		bootstrapTimeout = 180 * time.Second
	}
	bootstrapCtx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer cancel()

	// Check the current phase after subscribing so a bootstrap event that
	// happened just before the request cannot leave startup waiting forever.
	bootstrapped, err := torAlreadyBootstrapped(ctrl)
	if err != nil {
		_ = stopTor(child, ctrl)
		_ = backendLn.Close()
		return nil, fmt.Errorf("read Tor bootstrap phase: %w", err)
	}
	if err := ctrl.SetConf(&control.KeyVal{Key: "DisableNetwork", Val: "0"}); err != nil {
		_ = stopTor(child, ctrl)
		_ = backendLn.Close()
		return nil, fmt.Errorf("enable Tor network: %w", err)
	}
	if !bootstrapped {
		if err := waitForTorEvent(bootstrapCtx, ctrl, controlConn, events, func(event control.Event) (bool, error) {
			status, ok := event.(*control.StatusEvent)
			if !ok || status.Type != control.EventCodeStatusClient || status.Action != "BOOTSTRAP" {
				return false, nil
			}
			if status.Severity == "WARN" || status.Severity == "ERR" {
				log.Printf("Tor bootstrap status: %s", status.Raw)
			}
			return status.Arguments["PROGRESS"] == "100", nil
		}); err != nil {
			_ = stopTor(child, ctrl)
			_ = backendLn.Close()
			return nil, fmt.Errorf("tor bootstrap timed out or failed: %w", err)
		}
	}

	onionAddress, err := waitHostname(bootstrapCtx, child, hostnamePath)
	if err != nil {
		_ = stopTor(child, ctrl)
		_ = backendLn.Close()
		return nil, fmt.Errorf("wait for Tor hostname: %w", err)
	}

	t := &binetorcmd.Tor{Control: ctrl}
	svc := &service{
		t:              t,
		cmd:            child,
		ctrl:           ctrl,
		onionAddress:   onionAddress,
		torBackendPort: torBackendPort,
		backendLn:      backendLn,
	}

	if m.cfg.UseNetwork {
		dialer, dialErr := t.Dialer(ctx, &binetorcmd.DialConf{SkipEnableNetwork: true})
		if dialErr != nil {
			log.Printf("Tor: warning: failed to create dialer: %v", dialErr)
		} else {
			svc.dialer = dialer
			log.Printf("Tor outbound connections enabled")
		}
	}

	// The loopback backend port is an internal implementation detail and is
	// deliberately kept out of the startup log (AI.md PART 31.1).
	log.Printf("Tor hidden service started: %s:%d", onionAddress, m.cfg.VirtualPort)
	descCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = waitForTorEvent(descCtx, ctrl, controlConn, events, func(event control.Event) (bool, error) {
		desc, ok := event.(*control.HSDescEvent)
		if ok && desc.Action == "FAILED" {
			log.Printf("Tor hidden service descriptor upload failed: %s", desc.Raw)
		}
		return ok && desc.Action == "UPLOADED", nil
	})
	cancel()
	if err != nil {
		log.Printf("Tor hidden service descriptor upload not confirmed: %v", err)
	}
	return svc, nil
}

var controlPortLine = regexp.MustCompile(`^PORT=(127\.0\.0\.1:[0-9]{1,5})\n$`)
var hostnameLine = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

func removeStaleControlPort(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func parseControlPortFile(contents []byte) (string, bool) {
	match := controlPortLine.FindSubmatch(contents)
	if match == nil {
		return "", false
	}
	_, portText, err := net.SplitHostPort(string(match[1]))
	if err != nil {
		return "", false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	return string(match[1]), true
}

type managedTorProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	waitErr error
	stdout  *tailBuffer
	stderr  *tailBuffer
}

type tailBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.limit <= 0 {
		b.limit = 8192
	}
	if len(p) >= b.limit {
		b.buf.Reset()
		p = p[len(p)-b.limit:]
	} else if b.buf.Len()+len(p) > b.limit {
		_, _ = b.buf.Read(make([]byte, b.buf.Len()+len(p)-b.limit))
	}
	_, _ = b.buf.Write(p)
	return n, nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func spawnTor(ctx context.Context, binary, torrcPath string) (*managedTorProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	child := &managedTorProcess{
		cmd:    exec.Command(binary, "-f", torrcPath),
		done:   make(chan struct{}),
		stdout: &tailBuffer{limit: 8192},
		stderr: &tailBuffer{limit: 8192},
	}
	child.cmd.Stdout = child.stdout
	child.cmd.Stderr = child.stderr
	if err := child.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		err := child.cmd.Wait()
		child.mu.Lock()
		child.waitErr = err
		child.mu.Unlock()
		close(child.done)
	}()
	return child, nil
}

func (p *managedTorProcess) exitError() error {
	if p == nil {
		return errors.New("tor process unavailable")
	}
	select {
	case <-p.done:
		p.mu.Lock()
		err := p.waitErr
		p.mu.Unlock()
		if err == nil {
			err = errors.New("tor process exited")
		}
		if stderr := strings.TrimSpace(p.stderr.String()); stderr != "" {
			return fmt.Errorf("%w; stderr: %s", err, stderr)
		}
		return err
	default:
		return nil
	}
}

func waitControlPort(ctx context.Context, child *managedTorProcess, file string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := child.exitError(); err != nil {
			return "", fmt.Errorf("tor exited before opening the control port: %w", err)
		}
		if contents, err := os.ReadFile(file); err == nil {
			if address, valid := parseControlPortFile(contents); valid {
				return address, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-child.done:
			return "", fmt.Errorf("tor exited before opening the control port: %w", child.exitError())
		case <-deadline.C:
			stderr := strings.TrimSpace(child.stderr.String())
			if stderr != "" {
				return "", fmt.Errorf("control_port file not ready after %s; stderr: %s", timeout, stderr)
			}
			return "", fmt.Errorf("control_port file not ready after %s", timeout)
		case <-ticker.C:
		}
	}
}

func dialControl(ctx context.Context, address string) (*control.Conn, net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	ctrl := control.NewConn(textproto.NewConn(conn))
	if err := ctrl.Authenticate(""); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return ctrl, conn, nil
}

func torAlreadyBootstrapped(ctrl *control.Conn) (bool, error) {
	values, err := ctrl.GetInfo("status/bootstrap-phase")
	if err != nil {
		return false, err
	}
	for _, value := range values {
		if value.Key == "status/bootstrap-phase" && strings.Contains(value.Val, "PROGRESS=100") {
			return true, nil
		}
	}
	return false, nil
}

func waitForTorEvent(ctx context.Context, ctrl *control.Conn, conn net.Conn, events <-chan control.Event, match func(control.Event) (bool, error)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		err := ctrl.HandleNextEvent()
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		for {
			select {
			case event := <-events:
				matched, err := match(event)
				if err != nil {
					return err
				}
				if matched {
					return nil
				}
			default:
				goto nextEvent
			}
		}
	nextEvent:
	}
}

func waitHostname(ctx context.Context, child *managedTorProcess, file string) (string, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := child.exitError(); err != nil {
			return "", fmt.Errorf("tor exited before writing hostname: %w", err)
		}
		if contents, err := os.ReadFile(file); err == nil {
			address := strings.TrimSpace(string(contents))
			if hostnameLine.MatchString(address) {
				return address, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-child.done:
			return "", fmt.Errorf("tor exited before writing hostname: %w", child.exitError())
		case <-ticker.C:
		}
	}
}

func stopTor(child *managedTorProcess, ctrl *control.Conn) error {
	if ctrl != nil {
		_ = ctrl.Signal("SHUTDOWN")
		_ = ctrl.Close()
	}
	if child == nil || child.cmd == nil || child.cmd.Process == nil {
		return nil
	}
	select {
	case <-child.done:
		return nil
	case <-time.After(10 * time.Second):
	}
	_ = child.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-child.done:
		return nil
	case <-time.After(5 * time.Second):
	}
	_ = child.cmd.Process.Kill()
	<-child.done
	return nil
}
