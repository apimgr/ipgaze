// Package i2p implements the OPTIONAL I2P eepsite subsystem per AI.md
// PART 31.2. Unlike Tor (PART 31.1, auto-enabled when the tor binary is
// found), I2P is enabled by default only in containers. Elsewhere it remains
// opt-in; no provider is contacted unless server.i2p.enabled is true.
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

	"github.com/apimgr/ipgaze/src/common/i18n"
)

// I2PServiceConfig holds I2P eepsite configuration per AI.md PART 31.2.
type I2PServiceConfig struct {
	ConfigDir string
	DataDir   string
	LogDir    string
	// Enabled is resolved from config, environment, flags, and the container default.
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

// String returns the provider's config-file name ("i2pd", "sam", or "none").
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
	// for the session lifetime.
	samConn       net.Conn
	forwardConn   net.Conn
	samLost       chan error
	i2pdExited    chan struct{}
	monitorCancel context.CancelFunc
	status        string
}

// I2PManager manages the I2P eepsite lifecycle. It stores no backend port
// itself — the dedicated port is allocated inside startDedicated, only
// once a provider is confirmed available.
// ErrNoProvider reports that I2P is enabled but neither an i2pd binary nor a
// reachable SAM bridge was found. Per AI.md PART 31.2 this is a WARN-and-
// continue condition, not a server error, but it is a distinct reported state
// ("No Provider") rather than a plain failure.
var ErrNoProvider = errors.New("i2p enabled but no provider available")

// ErrI2PDisabled marks the normal opt-out state for direct startup attempts.
var ErrI2PDisabled = errors.New("i2p disabled (opt-in)")

const i2pdSAMStartupTimeout = 60 * time.Second

func bootstrapTimeout(seconds int) (time.Duration, error) {
	if seconds == 0 {
		seconds = 300
	}
	if seconds < 30 || seconds > 600 {
		return 0, fmt.Errorf("bootstrap timeout outside 30-600 seconds")
	}
	return time.Duration(seconds) * time.Second, nil
}

// I2PManager owns the lifecycle of the I2P eepsite backend — provider
// detection, start/stop, and the status reported to operators.
type I2PManager struct {
	cfg             I2PServiceConfig
	mu              sync.RWMutex
	svc             *service
	running         bool
	starting        bool
	phase           string
	provider        Provider
	startupAddress  string
	addressHandlers []func(string)
	startCancel     context.CancelFunc
	startDone       chan struct{}
	recoveryCancel  context.CancelFunc
	recoveryWait    func(context.Context, time.Duration) bool
	recovering      bool
	stopping        bool
	stopDone        chan struct{}
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
	_ = conn.Close()
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
// available. I2P is optional — disabled or unavailable providers never fail
// server startup.
func (m *I2PManager) Start() error {
	return m.start()
}

// StartAsync begins I2P initialization in the background so listener startup
// never waits for router bootstrap or tunnel creation.
func (m *I2PManager) StartAsync() {
	ctx, cancel, done, shouldStart := m.beginStart()
	if !shouldStart {
		return
	}
	go func() {
		if err := m.finishStart(ctx, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("WARN: I2P eepsite startup failed: %v", err)
		}
	}()
}

// AddAddressHandler registers a callback for the generated eepsite identity.
// If startup already discovered the address, it is delivered immediately.
func (m *I2PManager) AddAddressHandler(handler func(string)) {
	if handler == nil {
		return
	}
	m.mu.Lock()
	m.addressHandlers = append(m.addressHandlers, handler)
	address := m.startupAddress
	if address == "" && m.svc != nil {
		address = m.svc.eepsiteAddress
	}
	m.mu.Unlock()
	if address != "" {
		handler(address)
	}
}

// WaitForAddress waits up to timeout for the destination address to be
// generated, without waiting for tunnel bootstrap to complete.
func (m *I2PManager) WaitForAddress(timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		m.mu.RLock()
		address := m.startupAddress
		if address == "" && m.svc != nil {
			address = m.svc.eepsiteAddress
		}
		finishedWithoutAddress := !m.starting && m.svc == nil && address == ""
		m.mu.RUnlock()
		if address != "" || finishedWithoutAddress || time.Until(deadline) <= 0 {
			return address
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (m *I2PManager) publishAddress(address string) {
	m.mu.Lock()
	m.startupAddress = address
	handlers := append([]func(string){}, m.addressHandlers...)
	m.mu.Unlock()
	for _, handler := range handlers {
		handler(address)
	}
}

func (m *I2PManager) start() error {
	ctx, cancel, done, shouldStart := m.beginStart()
	if !shouldStart {
		return nil
	}
	return m.finishStart(ctx, cancel, done)
}

func (m *I2PManager) beginStart() (context.Context, context.CancelFunc, chan struct{}, bool) {
	m.mu.Lock()
	if m.running || m.starting || m.stopping {
		m.mu.Unlock()
		return nil, nil, nil, false
	}
	if !m.cfg.Enabled {
		m.phase = "disabled"
		m.mu.Unlock()
		return nil, nil, nil, false
	}
	m.starting = true
	m.phase = "starting"
	m.provider = ProviderNone
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.startCancel = cancel
	m.startDone = done
	m.mu.Unlock()
	return ctx, cancel, done, true
}

func (m *I2PManager) finishStart(ctx context.Context, cancel context.CancelFunc, done chan struct{}) error {
	defer func() {
		m.mu.Lock()
		if m.startDone == done {
			m.startDone = nil
		}
		close(done)
		m.mu.Unlock()
	}()
	svc, err := m.startDedicated(ctx)
	wasCanceled := ctx.Err() != nil
	cancel()
	m.mu.Lock()
	m.startCancel = nil
	m.starting = false
	if wasCanceled {
		m.phase = "disabled"
		m.startErr = nil
		m.mu.Unlock()
		if svc != nil {
			m.mu.Lock()
			_ = closeServiceLocked(svc)
			m.mu.Unlock()
		}
		return context.Canceled
	}
	if err != nil {
		// A missing provider or failed start is recorded for status reporting,
		// never returned as a fatal server-startup error.
		m.startErr = err
		if errors.Is(err, ErrNoProvider) {
			m.provider = ProviderNone
			m.phase = "no_provider"
		} else {
			m.phase = "error"
		}
		m.mu.Unlock()
		log.Printf("WARN: I2P eepsite unavailable: %v", err)
		return nil
	}
	m.startErr = nil
	m.svc = svc
	m.provider = svc.provider
	m.running = true
	m.phase = "running"

	if m.pendingHandler != nil {
		m.attachBackendHandlerLocked(m.pendingHandler)
	}
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	svc.monitorCancel = monitorCancel
	m.mu.Unlock()
	go m.monitorService(monitorCtx, svc)

	log.Printf("I2P eepsite ready (%s)", svc.provider)
	return nil
}

func (m *I2PManager) monitorService(ctx context.Context, svc *service) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	m.monitorServiceWithProbe(ctx, svc, ticker.C, m.probeSAM)
}

func (m *I2PManager) probeSAM(ctx context.Context) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m.mu.RLock()
	samAddr := m.cfg.SAMAddress
	m.mu.RUnlock()
	if samAddr == "" {
		samAddr = "127.0.0.1:7656"
	}
	conn, _, err := samDial(probeCtx, samAddr)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(conn, "QUIT")
	closeErr := conn.Close()
	return errors.Join(writeErr, closeErr)
}

func (m *I2PManager) monitorServiceWithProbe(ctx context.Context, svc *service, ticks <-chan time.Time, probe func(context.Context) error) {
	failures := 0
	for {
		failed := false
		failureCause := error(nil)
		select {
		case <-ctx.Done():
			return
		case err := <-svc.samLost:
			failed = true
			if err != nil {
				failureCause = fmt.Errorf("SAM session lost: %w", err)
			}
		case <-ticks:
		}
		if svc.provider == ProviderI2PD {
			select {
			case <-svc.i2pdExited:
				failed = true
				failureCause = errors.New("i2pd process exited")
			default:
			}
		} else if !failed {
			if probe == nil {
				probe = m.probeSAM
			}
			if err := probe(ctx); err == nil {
				failures = 0
			} else {
				failures++
				failed = failures >= 3
				if failed {
					failureCause = fmt.Errorf("SAM liveness probe failed three consecutive times: %w", err)
				}
			}
		}
		if !failed {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if failureCause == nil {
			failureCause = errors.New("I2P provider session lost")
		}
		m.markUnavailable(svc, failureCause)
		m.recoverAfterFailure(svc)
		return
	}
}

// HealthCheck probes the active provider and starts recovery after a failure.
func (m *I2PManager) HealthCheck() {
	m.mu.RLock()
	svc := m.svc
	running := m.running
	m.mu.RUnlock()
	if !running || svc == nil {
		return
	}
	var err error
	if svc.provider == ProviderI2PD {
		select {
		case <-svc.i2pdExited:
			err = errors.New("i2pd process exited")
		default:
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		samAddr := m.cfg.SAMAddress
		if samAddr == "" {
			samAddr = "127.0.0.1:7656"
		}
		conn, _, dialErr := samDial(ctx, samAddr)
		if dialErr != nil {
			err = dialErr
		} else {
			_, _ = fmt.Fprintln(conn, "QUIT")
			_ = conn.Close()
		}
	}
	if err != nil {
		m.markUnavailable(svc, err)
		go m.recoverAfterFailure(svc)
	}
}

// recoverAfterFailure recreates the provider session with the persisted key,
// backing off from five seconds to five minutes between failed starts.
func (m *I2PManager) recoverAfterFailure(failed *service) {
	m.mu.Lock()
	if m.svc != failed || m.stopping || m.recovering {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.recovering = true
	m.recoveryCancel = cancel
	if failed.monitorCancel != nil {
		failed.monitorCancel()
		failed.monitorCancel = nil
	}
	m.svc = nil
	m.running = false
	m.provider = ProviderNone
	_ = closeServiceLocked(failed)
	m.mu.Unlock()

	defer func() {
		cancel()
		m.mu.Lock()
		m.recovering = false
		m.recoveryCancel = nil
		m.mu.Unlock()
	}()

	delay := 5 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		wait := m.recoveryWait
		if wait == nil {
			wait = waitForRecoveryDelay
		}
		if !wait(ctx, delay) {
			return
		}
		m.mu.RLock()
		stopping := m.stopping
		m.mu.RUnlock()
		if stopping || ctx.Err() != nil {
			return
		}
		if err := m.Start(); err == nil && m.IsRunning() {
			return
		}
		delay = nextRecoveryDelay(delay)
	}
}

func waitForRecoveryDelay(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextRecoveryDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 5 * time.Second
	}
	if delay >= 5*time.Minute {
		return 5 * time.Minute
	}
	delay *= 2
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}

func (m *I2PManager) markUnavailable(svc *service, cause error) {
	m.mu.Lock()
	newFailure := m.svc == svc && svc.status != "error"
	if m.svc == svc {
		m.startErr = cause
		svc.status = "error"
		m.phase = "error"
	}
	m.mu.Unlock()
	if newFailure {
		log.Printf("WARN: I2P eepsite unavailable: %v", cause)
	}
}

func watchSAMConnection(reader *bufio.Reader) <-chan error {
	lost := make(chan error, 1)
	go func() {
		_, err := reader.ReadByte()
		if err == nil {
			err = errors.New("unexpected data on idle SAM session socket")
		}
		lost <- err
	}()
	return lost
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
	var closeErr error
	if svc.monitorCancel != nil {
		svc.monitorCancel()
		svc.monitorCancel = nil
	}
	if svc.backendSrv != nil {
		closeErr = errors.Join(closeErr, svc.backendSrv.Close())
	}
	if svc.forwardConn != nil {
		closeErr = errors.Join(closeErr, svc.forwardConn.Close())
		svc.forwardConn = nil
	}
	if svc.samConn != nil {
		closeErr = errors.Join(closeErr, svc.samConn.Close())
		svc.samConn = nil
	}
	if svc.i2pd != nil && svc.i2pd.Process != nil {
		closeErr = errors.Join(closeErr, stopI2PD(svc.i2pd, svc.i2pdExited))
		svc.i2pd = nil
	}
	return closeErr
}

// Stop terminates the I2P provider and its dedicated backend listener.
func (m *I2PManager) Stop() error {
	m.mu.Lock()
	if m.stopping {
		done := m.stopDone
		m.mu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	m.stopping = true
	if m.recoveryCancel != nil {
		m.recoveryCancel()
	}
	stopDone := make(chan struct{})
	m.stopDone = stopDone
	if m.startCancel != nil {
		m.startCancel()
	}
	startDone := m.startDone
	m.mu.Unlock()
	if startDone != nil {
		<-startDone
	}
	m.mu.Lock()
	var err error
	if !m.running || m.svc == nil {
		m.phase = "disabled"
		m.startErr = nil
	} else {
		err = closeServiceLocked(m.svc)
		m.svc = nil
		m.running = false
		m.provider = ProviderNone
		m.phase = "disabled"
		log.Println("I2P: eepsite stopped")
	}
	m.startCancel = nil
	m.stopping = false
	m.stopDone = nil
	close(stopDone)
	m.mu.Unlock()
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
	if address := m.EepsiteAddress(); address != "" {
		return address, nil
	}
	m.mu.RLock()
	err := m.startErr
	enabled := m.cfg.Enabled
	m.mu.RUnlock()
	if err == nil && !enabled {
		err = ErrI2PDisabled
	}
	if err == nil {
		err = errors.New("I2P eepsite did not start")
	}
	return "", fmt.Errorf("regenerate I2P address: %w", err)
}

// EepsiteAddress returns the current .b32.i2p address (empty if not running).
func (m *I2PManager) EepsiteAddress() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.svc == nil || m.svc.status == "error" {
		return ""
	}
	return m.svc.eepsiteAddress
}

// IsRunning returns true if the eepsite is running.
func (m *I2PManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running && m.svc != nil && m.svc.status != "error"
}

// Status returns the current status string.
func (m *I2PManager) Status() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.statusLocked()
}

// ProviderName reports the detected provider without probing an external SAM
// service from a health request.
func (m *I2PManager) ProviderName() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.svc != nil {
		return m.svc.provider.String()
	}
	return m.provider.String()
}

func (m *I2PManager) statusLocked() string {
	if m.svc != nil && m.svc.status != "" {
		return m.svc.status
	}
	if !m.running {
		if !m.cfg.Enabled {
			return "disabled"
		}
		if errors.Is(m.startErr, ErrNoProvider) {
			return "no_provider"
		}
		if m.startErr != nil {
			return "error"
		}
		if m.phase != "" {
			return m.phase
		}
		return "starting"
	}
	if m.svc == nil || m.svc.eepsiteAddress == "" {
		return "starting"
	}
	return "running"
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
		if m.svc.status != "error" {
			hostname = m.svc.eepsiteAddress
		}
		provider = m.svc.provider.String()
	}
	return Info{
		Enabled:  m.cfg.Enabled && !errors.Is(m.startErr, ErrNoProvider),
		Running:  m.running && m.svc != nil && m.svc.status != "error",
		Status:   m.statusLocked(),
		Provider: provider,
		Hostname: hostname,
	}
}

// GetHostname returns the .b32.i2p hostname (with .b32.i2p suffix).
func (m *I2PManager) GetHostname() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.svc == nil || m.svc.status == "error" {
		return ""
	}
	return m.svc.eepsiteAddress
}

// Close shuts down the I2P provider. Equivalent to Stop() — provided to
// match the AI.md PART 31.2 I2PManager.Close naming.
func (m *I2PManager) Close() error {
	return m.Stop()
}

// getI2PTunnelsConf returns an empty tunnel file: the eepsite is driven only
// through SAM, and loading any tunnel definition would violate provider isolation.
func getI2PTunnelsConf(cfg I2PServiceConfig, keysPath string, i2pBackendPort int) string {
	return ""
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

// destinationBytes decodes a SAM PRIV value and returns its destination.
// The certificate length is encoded as a big-endian uint16 at offsets 385–386.
func destinationBytes(priv string) ([]byte, error) {
	raw, err := i2pBase64.DecodeString(priv)
	if err != nil || len(raw) < 387 {
		return nil, fmt.Errorf("invalid destination key")
	}
	destinationLength := 387 + int(binary.BigEndian.Uint16(raw[385:387]))
	if len(raw) < destinationLength {
		return nil, fmt.Errorf("truncated destination key")
	}
	return raw[:destinationLength], nil
}

// startDedicated resolves the I2P provider (i2pd binary preferred, else
// a reachable SAM bridge), allocates the dedicated plain backend port
// only once a provider is confirmed, and starts the eepsite. Returns an
// error (never fatal to the caller — see Start()) when I2P is disabled
// or no provider is available.
func (m *I2PManager) startDedicated(ctx context.Context) (*service, error) {
	if !m.cfg.Enabled {
		return nil, ErrI2PDisabled
	}
	if _, err := bootstrapTimeout(m.cfg.BootstrapTimeout); err != nil {
		return nil, fmt.Errorf("I2P bootstrap_timeout must be between 30 and 600 seconds")
	}

	samAddr := m.cfg.SAMAddress
	if samAddr == "" {
		samAddr = "127.0.0.1:7656"
	}

	i2pdBinary := m.resolveI2PDBinary()
	provider := ProviderSAM
	if i2pdBinary != "" {
		provider = ProviderI2PD
	} else if !samReachable(samAddr) {
		return nil, fmt.Errorf("%w (no i2pd binary, SAM %s unreachable)", ErrNoProvider, samAddr)
	}
	m.mu.Lock()
	m.provider = provider
	m.phase = "starting"
	m.mu.Unlock()

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
	svc.backendSrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		handler := m.pendingHandler
		m.mu.RUnlock()
		if handler == nil {
			http.Error(w, i18n.T(r.Context(), "errors.maintenance_mode"), http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})}
	go func() {
		if err := svc.backendSrv.Serve(rawLn); err != nil && err != http.ErrServerClosed {
			log.Printf("I2P: backend listener error: %v", err)
		}
	}()

	switch provider {
	case ProviderI2PD:
		samAddr, err := m.startI2PD(ctx, i2pdBinary, keysPath, i2pBackendPort, svc)
		if err != nil {
			_ = closeServiceLocked(svc)
			return nil, err
		}
		addr, err := m.startSAMEepsite(ctx, samAddr, keysPath, i2pBackendPort, svc)
		if err != nil {
			_ = closeServiceLocked(svc)
			_ = rawLn.Close()
			return nil, err
		}
		svc.eepsiteAddress = addr
	case ProviderSAM:
		addr, err := m.startSAMEepsite(ctx, samAddr, keysPath, i2pBackendPort, svc)
		if err != nil {
			_ = closeServiceLocked(svc)
			return nil, err
		}
		svc.eepsiteAddress = addr
	}

	return svc, nil
}

// startI2PD creates an isolated router configuration, starts the managed
// process, and returns its private random SAM endpoint for the common SAM path.
func (m *I2PManager) startI2PD(ctx context.Context, binary, keysPath string, i2pBackendPort int, svc *service) (string, error) {
	_ = keysPath
	_ = i2pBackendPort
	confDir := filepath.Join(m.cfg.ConfigDir, "i2p")
	dataDir := filepath.Join(m.cfg.DataDir, "i2p")
	logDir := m.cfg.LogDir
	if logDir == "" {
		logDir = m.cfg.DataDir
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return "", fmt.Errorf("create i2pd log directory: %w", err)
	}
	tunnelsDir := filepath.Join(confDir, "tunnels.d")
	if err := os.RemoveAll(tunnelsDir); err != nil {
		return "", fmt.Errorf("clear isolated i2pd tunnels directory: %w", err)
	}
	if err := os.MkdirAll(tunnelsDir, 0o700); err != nil {
		return "", fmt.Errorf("create empty i2pd tunnels directory: %w", err)
	}
	_ = os.Chmod(tunnelsDir, 0o700)
	tunnelsPath := filepath.Join(confDir, "tunnels.conf")
	if err := updateI2PTunnels(tunnelsPath, nil); err != nil {
		return "", err
	}
	samPort, err := randomUnusedPort()
	if err != nil {
		return "", err
	}
	confPath := filepath.Join(confDir, "i2pd.conf")
	conf := buildI2PDConfig(filepath.Join(logDir, "i2pd.log"), samPort)
	if err := writePrivateFile(confPath, []byte(conf)); err != nil {
		return "", fmt.Errorf("write i2pd.conf: %w", err)
	}
	pidPath := filepath.Join(dataDir, "i2pd.pid")
	if err := reapStaleI2PD(pidPath, binary); err != nil {
		return "", err
	}
	cmd := exec.Command(binary, "--conf", confPath, "--tunconf", tunnelsPath,
		"--tunnelsdir", tunnelsDir, "--datadir", dataDir,
		"--pidfile", pidPath)
	setParentDeathSignal(cmd)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start i2pd: %w", err)
	}
	svc.i2pd = cmd
	svc.i2pdExited = make(chan struct{})
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("I2P: i2pd exited: %v", err)
		}
		close(svc.i2pdExited)
	}()
	samAddr := fmt.Sprintf("127.0.0.1:%d", samPort)
	deadline := time.Now().Add(i2pdSAMStartupTimeout)
	for time.Now().Before(deadline) {
		probeTimeout := 10 * time.Second
		if remaining := time.Until(deadline); remaining < probeTimeout {
			probeTimeout = remaining
		}
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		conn, _, dialErr := samDial(probeCtx, samAddr)
		cancel()
		if dialErr == nil {
			_ = conn.Close()
			return samAddr, nil
		}
		select {
		case <-svc.i2pdExited:
			return "", fmt.Errorf("i2pd exited before its SAM port opened: %v", cmd.ProcessState)
		case <-ctx.Done():
			_ = stopI2PD(cmd, svc.i2pdExited)
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	_ = stopI2PD(cmd, svc.i2pdExited)
	return "", fmt.Errorf("i2pd SAM port not ready after %s; see %s", i2pdSAMStartupTimeout, filepath.Join(logDir, "i2pd.log"))
}

func buildI2PDConfig(logPath string, samPort int) string {
	return fmt.Sprintf(`daemon = false
ipv4 = true
ipv6 = false
notransit = true
floodfill = false
log = file
logfile = %s
loglevel = warn

[http]
enabled = false
[httpproxy]
enabled = false
[socksproxy]
enabled = false
[sam]
enabled = true
address = 127.0.0.1
port = %d
[bob]
enabled = false
[i2cp]
enabled = false
[i2pcontrol]
enabled = false
[upnp]
enabled = false
`, logPath, samPort)
}

func randomUnusedPort() (int, error) {
	ln, _, err := getRandomAvailablePort()
	if err != nil {
		return 0, err
	}
	if err := ln.Close(); err != nil {
		return 0, fmt.Errorf("close temporary port listener: %w", err)
	}
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chown(path, os.Getuid(), os.Getgid()); err != nil {
			return err
		}
	}
	return nil
}

func reapStaleI2PD(pidPath, binary string) error {
	data, err := os.ReadFile(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read i2pd pid file: %w", err)
	}
	pid := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil || pid <= 1 {
		return fmt.Errorf("invalid i2pd pid file %s", pidPath)
	}
	return terminateStaleI2PD(pid, filepath.Base(binary), pidPath)
}

func stopI2PD(cmd *exec.Cmd, exited <-chan struct{}) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	signalErr := signalI2PD(cmd.Process)
	if exited != nil {
		select {
		case <-exited:
			return nil
		case <-time.After(10 * time.Second):
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		return errors.Join(signalErr, err)
	}
	return nil
}

// samDestination holds the persisted private destination used to create a SAM session.
type samDestination struct {
	priv string
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

func samCommand(conn net.Conn, reader *bufio.Reader, timeout time.Duration, command string) (reply string, resultErr error) {
	if timeout <= 0 {
		return "", fmt.Errorf("invalid SAM command timeout")
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("set SAM deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("clear SAM deadline: %w", err))
		}
	}()
	if _, err := fmt.Fprintln(conn, command); err != nil {
		return "", fmt.Errorf("SAM command write failed")
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("SAM command reply failed: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func samDial(ctx context.Context, address string) (net.Conn, *bufio.Reader, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	helloTimeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < helloTimeout {
			helloTimeout = remaining
		}
	}
	line, err := samCommand(conn, reader, helloTimeout, "HELLO VERSION MIN=3.1 MAX=3.3")
	if err != nil || !strings.HasPrefix(line, "HELLO REPLY") || !strings.Contains(line, "RESULT=OK") {
		_ = conn.Close()
		if err == nil {
			err = fmt.Errorf("SAM HELLO rejected; SAM 3.1 or newer is required")
		}
		return nil, nil, err
	}
	return conn, reader, nil
}

// loadOrCreateSAMDestination loads the persisted destination from
// keysPath, or generates a new one via SAM DEST GENERATE and persists it,
// when none exists yet.
func loadOrCreateSAMDestination(conn net.Conn, r *bufio.Reader, keysPath string, sigType int) (destination samDestination, resultErr error) {
	if data, err := os.ReadFile(keysPath); err == nil && len(data) > 0 {
		priv := strings.TrimSpace(string(data))
		if _, err := destinationBytes(priv); err != nil {
			return samDestination{}, fmt.Errorf("corrupt destination key file %s: %w", keysPath, err)
		}
		return samDestination{priv: priv}, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return samDestination{}, fmt.Errorf("read destination key file: %w", err)
	}
	line, err := samCommand(conn, r, 10*time.Second, fmt.Sprintf("DEST GENERATE SIGNATURE_TYPE=%d", sigType))
	if err != nil {
		return samDestination{}, fmt.Errorf("DEST GENERATE: %w", err)
	}
	if !strings.HasPrefix(line, "DEST REPLY") || (strings.Contains(line, "RESULT=") && !strings.Contains(line, "RESULT=OK")) {
		return samDestination{}, fmt.Errorf("DEST GENERATE rejected: %s", samResult(line))
	}
	var priv string
	for _, field := range strings.Fields(line) {
		switch {
		case strings.HasPrefix(field, "PRIV="):
			priv = strings.TrimPrefix(field, "PRIV=")
		}
	}
	if _, err := destinationBytes(priv); err != nil {
		return samDestination{}, fmt.Errorf("DEST GENERATE returned an invalid private destination")
	}

	if err := os.MkdirAll(filepath.Dir(keysPath), 0o700); err != nil {
		return samDestination{}, fmt.Errorf("create keys dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(keysPath), ".site-keys-*.tmp")
	if err != nil {
		return samDestination{}, fmt.Errorf("create destination temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary destination key: %w", err))
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return samDestination{}, errors.Join(err, tmp.Close())
	}
	if _, err := tmp.WriteString(priv); err != nil {
		return samDestination{}, errors.Join(fmt.Errorf("write destination key: %w", err), tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return samDestination{}, errors.Join(fmt.Errorf("sync destination key: %w", err), tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return samDestination{}, fmt.Errorf("close destination key: %w", err)
	}
	if err := os.Rename(tmpName, keysPath); err != nil {
		return samDestination{}, fmt.Errorf("persist destination key: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chown(keysPath, os.Getuid(), os.Getgid()); err != nil {
			return samDestination{}, fmt.Errorf("set destination key owner: %w", err)
		}
	}
	return samDestination{priv: priv}, nil
}

// startSAMEepsite opens a SAMv3 control connection, loads (or generates
// and persists) the destination, creates a STREAM session, and forwards
// incoming streams to the dedicated backend port. Returns the .b32.i2p
// address. Model B: no PROXY-protocol header is ever sent by SAM/i2pd, so
// svc.backendLn (allocated by the caller) is served plain.
func (m *I2PManager) startSAMEepsite(ctx context.Context, samAddr, keysPath string, i2pBackendPort int, svc *service) (string, error) {
	conn, r, err := samDial(ctx, samAddr)
	if err != nil {
		return "", fmt.Errorf("failed to dial SAM %s: %w", samAddr, err)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	watchDone := make(chan struct{})
	defer close(watchDone)
	if svc.i2pdExited != nil {
		go func() {
			select {
			case <-svc.i2pdExited:
				_ = conn.Close()
			case <-watchDone:
			}
		}()
	}
	dest, err := loadOrCreateSAMDestination(conn, r, keysPath, m.cfg.SignatureType)
	if err != nil {
		_ = conn.Close()
		return "", err
	}
	privateDestination, err := destinationBytes(dest.priv)
	if err != nil {
		_ = conn.Close()
		return "", fmt.Errorf("invalid persisted destination key: %w", err)
	}
	addr := b32Address(privateDestination)
	svc.eepsiteAddress = addr
	m.publishAddress(addr)
	id := fmt.Sprintf("site-%d", os.Getpid())
	bootstrap, err := bootstrapTimeout(m.cfg.BootstrapTimeout)
	if err != nil {
		_ = conn.Close()
		return "", fmt.Errorf("I2P bootstrap_timeout must be between 30 and 600 seconds")
	}
	var reply string
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			id = fmt.Sprintf("%s-%d", id, time.Now().UnixNano())
		}
		cmd := fmt.Sprintf("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s i2cp.leaseSetEncType=4 inbound.length=%d outbound.length=%d inbound.quantity=%d outbound.quantity=%d", id, dest.priv, m.cfg.InboundLength, m.cfg.OutboundLength, m.cfg.InboundQuantity, m.cfg.OutboundQuantity)
		m.setServiceStatus(svc, "building")
		reply, err = samCommand(conn, r, bootstrap, cmd)
		if err != nil {
			_ = conn.Close()
			return "", fmt.Errorf("SESSION CREATE: %w", err)
		}
		if strings.Contains(reply, "RESULT=DUPLICATED_ID") && attempt == 0 {
			continue
		}
		if !strings.Contains(reply, "RESULT=OK") {
			_ = conn.Close()
			return "", fmt.Errorf("SESSION CREATE rejected: %s", samResult(reply))
		}
		break
	}
	// The plain backend listener was bound before reaching this function.
	forward, fr, err := samDial(ctx, samAddr)
	if err != nil {
		_ = conn.Close()
		return "", fmt.Errorf("open SAM forward socket: %w", err)
	}
	stopForwardClose := context.AfterFunc(ctx, func() { _ = forward.Close() })
	defer stopForwardClose()
	reply, err = samCommand(forward, fr, 10*time.Second, fmt.Sprintf("STREAM FORWARD ID=%s PORT=%d SILENT=true", id, i2pBackendPort))
	if err != nil || !strings.Contains(reply, "RESULT=OK") {
		_ = forward.Close()
		_ = conn.Close()
		return "", fmt.Errorf("STREAM FORWARD rejected: %s", samResult(reply))
	}
	svc.samConn, svc.forwardConn = conn, forward
	svc.samLost = make(chan error, 2)
	for _, reader := range []*bufio.Reader{r, fr} {
		watch := watchSAMConnection(reader)
		go func() { svc.samLost <- <-watch }()
	}
	m.setServiceStatus(svc, "running")
	return addr, nil
}

func samResult(reply string) string {
	for _, field := range strings.Fields(reply) {
		if strings.HasPrefix(field, "RESULT=") {
			return strings.TrimPrefix(field, "RESULT=")
		}
	}
	return "invalid SAM reply"
}

func (m *I2PManager) setServiceStatus(svc *service, status string) {
	m.mu.Lock()
	svc.status = status
	if m.svc == svc || m.starting {
		m.phase = status
	}
	m.mu.Unlock()
}
