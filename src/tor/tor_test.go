package tor

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeTempDirs creates a temp config/data dir pair for testing.
func makeTempDirs(t *testing.T) (configDir, dataDir string) {
	t.Helper()
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-tor-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	configDir = filepath.Join(base, "config")
	dataDir = filepath.Join(base, "data")
	return configDir, dataDir
}

// defaultCfg returns a minimal TorServiceConfig pointing at temp dirs.
func defaultCfg(t *testing.T) TorServiceConfig {
	t.Helper()
	configDir, dataDir := makeTempDirs(t)
	return TorServiceConfig{
		ConfigDir:   configDir,
		DataDir:     dataDir,
		VirtualPort: 8080,
	}
}

func init() {
	os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0o755)
}

// ---------------------------------------------------------------------------
// NewTorManager
// ---------------------------------------------------------------------------

func TestNewManager_ReturnsNonNil(t *testing.T) {
	cfg := defaultCfg(t)
	m := NewTorManager(cfg)
	if m == nil {
		t.Fatal("NewTorManager returned nil")
	}
}

func TestNewManager_StoresConfig(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.VirtualPort = 9001
	m := NewTorManager(cfg)
	if m.cfg.VirtualPort != 9001 {
		t.Errorf("VirtualPort = %d, want 9001", m.cfg.VirtualPort)
	}
}

func TestNewManager_InitialState(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	if m.running {
		t.Error("running should be false after NewTorManager")
	}
	if m.svc != nil {
		t.Error("svc should be nil after NewTorManager")
	}
}

// ---------------------------------------------------------------------------
// IsAvailable
// ---------------------------------------------------------------------------

func TestIsAvailable_ExplicitBinary_Exists(t *testing.T) {
	tmp, err := os.CreateTemp(os.TempDir(), "fake-tor-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg := defaultCfg(t)
	cfg.Binary = tmp.Name()
	m := NewTorManager(cfg)
	if !m.IsAvailable() {
		t.Error("IsAvailable() = false, want true for existing binary")
	}
}

func TestIsAvailable_ExplicitBinary_Missing(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = "/nonexistent/path/to/tor-binary-xyz"
	m := NewTorManager(cfg)
	if m.IsAvailable() {
		t.Error("IsAvailable() = true, want false for missing binary")
	}
}

func TestIsAvailable_AutoDetect_NoBinary(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = ""
	m := NewTorManager(cfg)
	// We cannot assert a definite value here because the test host may or
	// may not have Tor installed; we just ensure it doesn't panic.
	_ = m.IsAvailable()
}

// ---------------------------------------------------------------------------
// IsRunning / GetHostname / Status before Start
// ---------------------------------------------------------------------------

func TestIsRunning_InitiallyFalse(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	if m.IsRunning() {
		t.Error("IsRunning() = true before Start, want false")
	}
}

func TestGetHostname_EmptyBeforeStart(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	if h := m.GetHostname(); h != "" {
		t.Errorf("GetHostname() = %q before Start, want empty string", h)
	}
}

func TestStatus_UnavailableWhenNoBinaryAndNotRunning(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = "/nonexistent/tor-binary-xyz"
	m := NewTorManager(cfg)
	s := m.Status()
	if s != "unavailable" {
		t.Errorf("Status() = %q, want %q", s, "unavailable")
	}
}

func TestStatus_StoppedWhenBinaryExistsButNotRunning(t *testing.T) {
	tmp, err := os.CreateTemp(os.TempDir(), "fake-tor-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg := defaultCfg(t)
	cfg.Binary = tmp.Name()
	m := NewTorManager(cfg)
	s := m.Status()
	if s != "stopped" {
		t.Errorf("Status() = %q, want %q", s, "stopped")
	}
}

// ---------------------------------------------------------------------------
// Stop (no-op when not running)
// ---------------------------------------------------------------------------

func TestStop_WhenNotRunning_ReturnsNil(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() when not running returned error: %v", err)
	}
}

func TestStop_WhenAlreadyStopped_IsIdempotent(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	if err := m.Stop(); err != nil {
		t.Errorf("first Stop() error: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Errorf("second Stop() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Start (binary missing → graceful no-op)
// ---------------------------------------------------------------------------

func TestStart_WhenBinaryMissing_ReturnsNil(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = "/nonexistent/tor-binary-xyz"
	m := NewTorManager(cfg)
	if err := m.Start(); err != nil {
		t.Errorf("Start() with missing binary returned error: %v", err)
	}
	if m.IsRunning() {
		t.Error("IsRunning() = true after Start with missing binary, want false")
	}
}

func TestStart_WhenAlreadyRunning_IsIdempotent(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	m.mu.Lock()
	m.running = true
	m.mu.Unlock()

	if err := m.Start(); err != nil {
		t.Errorf("Start() when already running returned error: %v", err)
	}
	if !m.IsRunning() {
		t.Error("IsRunning() = false after idempotent Start, want true")
	}

	m.mu.Lock()
	m.running = false
	m.mu.Unlock()
}

func TestStart_WithNonExecutableBinary_ReturnsError(t *testing.T) {
	tmp, err := os.CreateTemp(os.TempDir(), "fake-tor-noexec-start-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg := defaultCfg(t)
	cfg.Binary = tmp.Name()
	m := NewTorManager(cfg)

	// The binary exists so IsAvailable() returns true, startDedicated runs and fails.
	err = m.Start()
	if err == nil {
		t.Fatal("Start() with non-executable binary returned nil error, want error")
	}
}

func TestStatus_ErrorAfterFailedStart(t *testing.T) {
	tmp, err := os.CreateTemp(os.TempDir(), "fake-tor-noexec-status-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg := defaultCfg(t)
	cfg.Binary = tmp.Name()
	m := NewTorManager(cfg)

	if err := m.Start(); err == nil {
		t.Fatal("Start() with non-executable binary returned nil error, want error")
	}

	s := m.Status()
	if !strings.HasPrefix(s, "error:") {
		t.Errorf("Status() after failed Start = %q, want prefix %q", s, "error:")
	}
}

func TestStop_ClearsLastErrAfterFailedStart(t *testing.T) {
	tmp, err := os.CreateTemp(os.TempDir(), "fake-tor-noexec-stopclear-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg := defaultCfg(t)
	cfg.Binary = tmp.Name()
	m := NewTorManager(cfg)

	if err := m.Start(); err == nil {
		t.Fatal("Start() with non-executable binary returned nil error, want error")
	}
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() after failed Start returned error: %v", err)
	}

	s := m.Status()
	if s != "stopped" {
		t.Errorf("Status() after Stop() = %q, want %q (lastErr should be cleared)", s, "stopped")
	}
}

func TestShortErrMsg_ShortMessagePassesThrough(t *testing.T) {
	err := &testError{msg: "permission denied"}
	if got := shortErrMsg(err); got != "permission denied" {
		t.Errorf("shortErrMsg() = %q, want %q", got, "permission denied")
	}
}

func TestShortErrMsg_TruncatesLongMessage(t *testing.T) {
	long := strings.Repeat("x", 200)
	got := shortErrMsg(&testError{msg: long})
	if len(got) > 130 {
		t.Errorf("shortErrMsg() length = %d, want <= 130 (truncated)", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("shortErrMsg() = %q, want truncated with ellipsis suffix", got)
	}
}

func TestShortErrMsg_StripsNewlines(t *testing.T) {
	got := shortErrMsg(&testError{msg: "line one\nline two"})
	if strings.Contains(got, "\n") {
		t.Errorf("shortErrMsg() = %q, want no newlines", got)
	}
}

// testError is a minimal error implementation for shortErrMsg tests.
type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// GetInfo
// ---------------------------------------------------------------------------

func TestGetInfo_DefaultState(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = "/nonexistent/tor-binary-xyz"
	m := NewTorManager(cfg)
	info := m.GetInfo()

	if info.Running {
		t.Error("Info.Running = true before Start, want false")
	}
	if info.Hostname != "" {
		t.Errorf("Info.Hostname = %q before Start, want empty", info.Hostname)
	}
	if info.Status != "unavailable" {
		t.Errorf("Info.Status = %q, want %q", info.Status, "unavailable")
	}
	if info.Enabled {
		t.Error("Info.Enabled = true with missing binary, want false")
	}
}

func TestGetInfo_EnabledWhenBinaryExists(t *testing.T) {
	tmp, err := os.CreateTemp(os.TempDir(), "fake-tor-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg := defaultCfg(t)
	cfg.Binary = tmp.Name()
	m := NewTorManager(cfg)
	info := m.GetInfo()
	if !info.Enabled {
		t.Error("Info.Enabled = false with existing binary, want true")
	}
}

func TestGetInfo_WithRunningService(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = "/nonexistent/tor-binary-xyz"
	m := NewTorManager(cfg)
	m.mu.Lock()
	m.running = true
	m.svc = &service{onionAddress: "myonionservice1234567890abcd.onion"}
	m.mu.Unlock()

	info := m.GetInfo()
	if !info.Running {
		t.Error("Info.Running = false, want true")
	}
	if info.Hostname != "myonionservice1234567890abcd.onion" {
		t.Errorf("Info.Hostname = %q, want %q", info.Hostname, "myonionservice1234567890abcd.onion")
	}

	m.mu.Lock()
	m.running = false
	m.svc = nil
	m.mu.Unlock()
}

// ---------------------------------------------------------------------------
// GetHTTPClient
// ---------------------------------------------------------------------------

func TestGetHTTPClient_NoTor_ReturnsPlainClient(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	client := m.GetHTTPClient(false)
	if client == nil {
		t.Fatal("GetHTTPClient(false) returned nil")
	}
	if _, ok := client.Transport.(*http.Transport); ok {
		t.Error("expected plain client without custom transport")
	}
}

func TestGetHTTPClient_UseTorTrue_SvcNil_ReturnsPlainClient(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	client := m.GetHTTPClient(true)
	if client == nil {
		t.Fatal("GetHTTPClient(true) with nil svc returned nil")
	}
	if client.Timeout == 0 {
		t.Error("expected non-zero timeout on plain client")
	}
}

func TestGetHTTPClient_PlainClientTimeout(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	client := m.GetHTTPClient(false)
	if client.Timeout.Seconds() != 30 {
		t.Errorf("plain client Timeout = %v, want 30s", client.Timeout)
	}
}

func TestGetHTTPClient_WithNilDialer_ReturnsPlainClient(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	m.mu.Lock()
	m.running = true
	m.svc = &service{onionAddress: "fakeonionid.onion", dialer: nil}
	m.mu.Unlock()

	// useTor=true with nil dialer still returns plain client (safety path).
	client := m.GetHTTPClient(true)
	if client == nil {
		t.Fatal("GetHTTPClient(true) returned nil")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout for nil dialer path, got %v", client.Timeout)
	}

	m.mu.Lock()
	m.running = false
	m.svc = nil
	m.mu.Unlock()
}

// ---------------------------------------------------------------------------
// getTorConfig
// ---------------------------------------------------------------------------

func TestGetTorConfig_SafeLoggingTrue(t *testing.T) {
	cfg := TorServiceConfig{SafeLogging: true}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if !strings.Contains(out, "SafeLogging 1") {
		t.Errorf("expected SafeLogging 1 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_SafeLoggingFalse(t *testing.T) {
	cfg := TorServiceConfig{SafeLogging: false}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if !strings.Contains(out, "SafeLogging 0") {
		t.Errorf("expected SafeLogging 0 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_UseNetworkTrue_SocksAuto(t *testing.T) {
	cfg := TorServiceConfig{UseNetwork: true}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if !strings.Contains(out, "SocksPort 127.0.0.1:auto") {
		t.Errorf("expected SocksPort 127.0.0.1:auto with UseNetwork=true, got:\n%s", out)
	}
	if !strings.Contains(out, "SocksPolicy accept 127.0.0.1") {
		t.Errorf("expected SocksPolicy accept 127.0.0.1 with UseNetwork=true, got:\n%s", out)
	}
}

func TestGetTorConfig_UseNetworkFalse_SocksDisabled(t *testing.T) {
	cfg := TorServiceConfig{UseNetwork: false}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if !strings.Contains(out, "SocksPort 0") {
		t.Errorf("expected SocksPort 0 with UseNetwork=false, got:\n%s", out)
	}
}

func TestGetTorConfig_DefaultBandwidth(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if !strings.Contains(out, "BandwidthRate 1 MB") {
		t.Errorf("expected default BandwidthRate 1 MB, got:\n%s", out)
	}
	if !strings.Contains(out, "BandwidthBurst 2 MB") {
		t.Errorf("expected default BandwidthBurst 2 MB, got:\n%s", out)
	}
}

func TestGetTorConfig_CustomBandwidth(t *testing.T) {
	cfg := TorServiceConfig{BandwidthRate: "5 MB", BandwidthBurst: "10 MB"}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if !strings.Contains(out, "BandwidthRate 5 MB") {
		t.Errorf("expected BandwidthRate 5 MB, got:\n%s", out)
	}
	if !strings.Contains(out, "BandwidthBurst 10 MB") {
		t.Errorf("expected BandwidthBurst 10 MB, got:\n%s", out)
	}
}

func TestGetTorConfig_UnlimitedBandwidth_NoAccounting(t *testing.T) {
	cfg := TorServiceConfig{MaxMonthlyBandwidth: "unlimited"}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if strings.Contains(out, "AccountingMax") {
		t.Errorf("expected no AccountingMax for unlimited bandwidth, got:\n%s", out)
	}
}

func TestGetTorConfig_EmptyBandwidth_NoAccounting(t *testing.T) {
	cfg := TorServiceConfig{MaxMonthlyBandwidth: ""}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if strings.Contains(out, "AccountingMax") {
		t.Errorf("expected no AccountingMax for empty bandwidth, got:\n%s", out)
	}
}

func TestGetTorConfig_MonthlyBandwidthLimit(t *testing.T) {
	cfg := TorServiceConfig{MaxMonthlyBandwidth: "50 GB"}
	out := getTorConfig(cfg, "/tmp/hs", 12345)
	if !strings.Contains(out, "AccountingMax 50 GB") {
		t.Errorf("expected AccountingMax 50 GB, got:\n%s", out)
	}
	if !strings.Contains(out, "AccountingStart month 1 00:00") {
		t.Errorf("expected AccountingStart month 1 00:00, got:\n%s", out)
	}
}

func TestGetTorConfig_AlwaysHasControlPort(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if !strings.Contains(out, "ControlPort 127.0.0.1:auto") {
		t.Errorf("expected ControlPort 127.0.0.1:auto in config, got:\n%s", out)
	}
}

func TestGetTorConfig_NoExitRelay(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if !strings.Contains(out, "ExitRelay 0") {
		t.Errorf("expected ExitRelay 0 in config, got:\n%s", out)
	}
	if !strings.Contains(out, "ExitPolicy reject *:*") {
		t.Errorf("expected ExitPolicy reject *:* in config, got:\n%s", out)
	}
}

func TestGetTorConfig_NoORPortDirective_DirPortZero(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if strings.Contains(out, "ORPort") {
		t.Errorf("expected no ORPort directive in config (client + hidden service only), got:\n%s", out)
	}
	if !strings.Contains(out, "DirPort 0") {
		t.Errorf("expected DirPort 0 in config, got:\n%s", out)
	}
	if !strings.Contains(out, "PublishServerDescriptor 0") {
		t.Errorf("expected PublishServerDescriptor 0 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_DisableDebuggerAttachment(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if !strings.Contains(out, "DisableDebuggerAttachment 1") {
		t.Errorf("expected DisableDebuggerAttachment 1 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_FetchDirEarly(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if !strings.Contains(out, "FetchDirInfoEarly 1") {
		t.Errorf("expected FetchDirInfoEarly 1 in config, got:\n%s", out)
	}
	if !strings.Contains(out, "FetchDirInfoExtraEarly 1") {
		t.Errorf("expected FetchDirInfoExtraEarly 1 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_IsNonEmpty(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if strings.TrimSpace(out) == "" {
		t.Error("getTorConfig() returned empty string")
	}
}

func TestGetTorConfig_SingleHopModeDisabled(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if !strings.Contains(out, "HiddenServiceSingleHopMode 0") {
		t.Errorf("expected HiddenServiceSingleHopMode 0 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_MaxCircuitDirtiness(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if !strings.Contains(out, "MaxCircuitDirtiness 600") {
		t.Errorf("expected MaxCircuitDirtiness 600 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_DeclaresHiddenServiceDir(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/tor-hs-dir", 55555)
	if !strings.Contains(out, "HiddenServiceDir /tmp/tor-hs-dir") {
		t.Errorf("expected HiddenServiceDir /tmp/tor-hs-dir in config, got:\n%s", out)
	}
	if !strings.Contains(out, "HiddenServiceVersion 3") {
		t.Errorf("expected HiddenServiceVersion 3 in config, got:\n%s", out)
	}
	if !strings.Contains(out, "HiddenServicePort 80 127.0.0.1:55555") {
		t.Errorf("expected HiddenServicePort 80 127.0.0.1:55555 in config, got:\n%s", out)
	}
	if !strings.Contains(out, "HiddenServiceExportCircuitID haproxy") {
		t.Errorf("expected HiddenServiceExportCircuitID haproxy in config, got:\n%s", out)
	}
}

func TestGetTorConfig_CustomVirtualPort(t *testing.T) {
	cfg := TorServiceConfig{VirtualPort: 8443}
	out := getTorConfig(cfg, "/tmp/hs", 55555)
	if !strings.Contains(out, "HiddenServicePort 8443 127.0.0.1:55555") {
		t.Errorf("expected HiddenServicePort 8443 127.0.0.1:55555 in config, got:\n%s", out)
	}
}

func TestGetTorConfig_NoADDONION(t *testing.T) {
	out := getTorConfig(TorServiceConfig{}, "/tmp/hs", 12345)
	if strings.Contains(out, "ADD_ONION") {
		t.Errorf("torrc must never reference ADD_ONION (spec requires HiddenServiceDir), got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// ensureTorDirs
// ---------------------------------------------------------------------------

func TestEnsureTorDirs_CreatesAllDirs(t *testing.T) {
	configDir, dataDir := makeTempDirs(t)
	if err := ensureTorDirs(configDir, dataDir); err != nil {
		t.Fatalf("ensureTorDirs() error: %v", err)
	}

	expected := []string{
		filepath.Join(configDir, "tor"),
		filepath.Join(dataDir, "tor"),
		filepath.Join(dataDir, "tor", "site"),
	}
	for _, d := range expected {
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("dir %s not created: %v", d, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
	}
}

func TestEnsureTorDirs_DirsHaveSecurePermissions(t *testing.T) {
	configDir, dataDir := makeTempDirs(t)
	if err := ensureTorDirs(configDir, dataDir); err != nil {
		t.Fatalf("ensureTorDirs() error: %v", err)
	}

	torConfigDir := filepath.Join(configDir, "tor")
	info, err := os.Stat(torConfigDir)
	if err != nil {
		t.Fatalf("Stat %s: %v", torConfigDir, err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir %s has perms %04o, want 0700", torConfigDir, perm)
	}
}

func TestEnsureTorDirs_Idempotent(t *testing.T) {
	configDir, dataDir := makeTempDirs(t)
	if err := ensureTorDirs(configDir, dataDir); err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if err := ensureTorDirs(configDir, dataDir); err != nil {
		t.Fatalf("second call error: %v", err)
	}
}

func TestEnsureTorDirs_UnwritableParent_ReturnsError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, can't test permission denial")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(base, 0o700) //nolint:errcheck

	err := ensureTorDirs(filepath.Join(base, "config"), filepath.Join(base, "data"))
	if err == nil {
		t.Error("ensureTorDirs() with unwritable parent returned nil error, want error")
	}
}

// ---------------------------------------------------------------------------
// updateTorrc — always regenerates torrc (never preserved) per PART 31.1
// ---------------------------------------------------------------------------

func TestUpdateTorrc_CreatesFile(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "subdir", "torrc")
	content := []byte("ControlPort 127.0.0.1:auto\n")

	if err := updateTorrc(path, content); err != nil {
		t.Fatalf("updateTorrc() error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("torrc content = %q, want %q", got, content)
	}
}

func TestUpdateTorrc_FilePermissions(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "torrc")
	content := []byte("ControlPort 127.0.0.1:auto\n")

	if err := updateTorrc(path, content); err != nil {
		t.Fatalf("updateTorrc() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("torrc perms = %04o, want 0600", perm)
	}
}

func TestUpdateTorrc_OverwritesExistingFile(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "torrc")
	if err := os.WriteFile(path, []byte("# original content\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := updateTorrc(path, []byte("# new content\n")); err != nil {
		t.Fatalf("updateTorrc() error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "# new content\n" {
		t.Errorf("torrc = %q, want regenerated content (torrc is never preserved)", got)
	}
}

func TestUpdateTorrc_FixesPermissionsOnExistingFile(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "torrc")
	if err := os.WriteFile(path, []byte("data\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := updateTorrc(path, []byte("new\n")); err != nil {
		t.Fatalf("updateTorrc() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("existing file perms after updateTorrc = %04o, want 0600", perm)
	}
}

func TestUpdateTorrc_CreatesParentDir(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested", "deep", "torrc")
	content := []byte("ControlPort 127.0.0.1:auto\n")

	if err := updateTorrc(path, content); err != nil {
		t.Fatalf("updateTorrc() with nested path error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("torrc not created at nested path: %v", err)
	}
}

func TestUpdateTorrc_EmptyContent(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "torrc")
	if err := updateTorrc(path, []byte{}); err != nil {
		t.Fatalf("updateTorrc() with empty content error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("torrc not created for empty content: %v", err)
	}
}

func TestUpdateTorrc_UnwritableParent_ReturnsError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, can't test permission denial")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(base, 0o700) //nolint:errcheck

	path := filepath.Join(base, "nested", "torrc")
	err := updateTorrc(path, []byte("test"))
	if err == nil {
		t.Error("updateTorrc() with unwritable parent returned nil error, want error")
	}
}

// ---------------------------------------------------------------------------
// getRandomAvailablePort
// ---------------------------------------------------------------------------

func TestGetRandomAvailablePort_ReturnsUsableListener(t *testing.T) {
	ln, port, err := getRandomAvailablePort()
	if err != nil {
		t.Fatalf("getRandomAvailablePort() error: %v", err)
	}
	defer ln.Close()
	if port <= 0 || port > 65535 {
		t.Errorf("port = %d, want a valid TCP port", port)
	}
	if ln.Addr() == nil {
		t.Error("listener Addr() is nil")
	}
}

func TestGetRandomAvailablePort_UniqueAcrossCalls(t *testing.T) {
	ln1, port1, err := getRandomAvailablePort()
	if err != nil {
		t.Fatalf("first getRandomAvailablePort() error: %v", err)
	}
	defer ln1.Close()

	ln2, port2, err := getRandomAvailablePort()
	if err != nil {
		t.Fatalf("second getRandomAvailablePort() error: %v", err)
	}
	defer ln2.Close()

	if port1 == port2 {
		t.Errorf("expected distinct ports while both listeners are open, got %d twice", port1)
	}
}

// ---------------------------------------------------------------------------
// Status state transitions (without real Tor)
// ---------------------------------------------------------------------------

func TestStatus_Starting_WhenRunningButNoOnionAddress(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	m.mu.Lock()
	m.running = true
	m.svc = &service{onionAddress: ""}
	m.mu.Unlock()

	s := m.Status()
	if s != "starting" {
		t.Errorf("Status() = %q, want %q", s, "starting")
	}

	m.mu.Lock()
	m.running = false
	m.svc = nil
	m.mu.Unlock()
}

func TestStatus_Healthy_WhenRunningWithOnionAddress(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	m.mu.Lock()
	m.running = true
	m.svc = &service{onionAddress: "abcdefghijklmnop.onion"}
	m.mu.Unlock()

	s := m.Status()
	if s != "healthy" {
		t.Errorf("Status() = %q, want %q", s, "healthy")
	}

	m.mu.Lock()
	m.running = false
	m.svc = nil
	m.mu.Unlock()
}

// ---------------------------------------------------------------------------
// GetHostname with internal service state
// ---------------------------------------------------------------------------

func TestGetHostname_WithOnionAddress(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	m.mu.Lock()
	m.svc = &service{onionAddress: "testserviceid12345678901234.onion"}
	m.mu.Unlock()

	hostname := m.GetHostname()
	want := "testserviceid12345678901234.onion"
	if hostname != want {
		t.Errorf("GetHostname() = %q, want %q", hostname, want)
	}

	m.mu.Lock()
	m.svc = nil
	m.mu.Unlock()
}

// ---------------------------------------------------------------------------
// startDedicated error paths (no real Tor binary)
// ---------------------------------------------------------------------------

func TestStartDedicated_FailsWhenDirsUnwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, can't test permission denial")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(base, 0o700) //nolint:errcheck

	cfg := TorServiceConfig{
		ConfigDir:   filepath.Join(base, "config"),
		DataDir:     filepath.Join(base, "data"),
		VirtualPort: 8080,
		Binary:      "/nonexistent/tor",
	}
	m := NewTorManager(cfg)
	_, err := m.startDedicated(context.Background())
	if err == nil {
		t.Fatal("startDedicated() with unwritable dirs returned nil error, want error")
	}
}

func TestStartDedicated_FailsWhenBinaryNotExecutable(t *testing.T) {
	tmp, err := os.CreateTemp(os.TempDir(), "fake-tor-noexec-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	// A file that exists but is not an executable Tor binary will cause bine to fail.
	cfg := defaultCfg(t)
	cfg.Binary = tmp.Name()
	m := NewTorManager(cfg)

	_, err = m.startDedicated(context.Background())
	if err == nil {
		t.Fatal("startDedicated() with non-executable file returned nil error, want error")
	}
}

// ---------------------------------------------------------------------------
// RegenerateAddress / Restart with no binary (graceful, non-fatal)
// ---------------------------------------------------------------------------

func TestRegenerateAddress_WhenBinaryMissing_ReturnsEmptyNoError(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = "/nonexistent/tor-binary-xyz"
	m := NewTorManager(cfg)

	hostname, err := m.RegenerateAddress()
	if err != nil {
		t.Errorf("RegenerateAddress() with missing binary returned error: %v", err)
	}
	if hostname != "" {
		t.Errorf("RegenerateAddress() hostname = %q, want empty when Tor unavailable", hostname)
	}
}

func TestRestart_WhenBinaryMissing_ReturnsNil(t *testing.T) {
	cfg := defaultCfg(t)
	cfg.Binary = "/nonexistent/tor-binary-xyz"
	m := NewTorManager(cfg)

	if err := m.Restart(); err != nil {
		t.Errorf("Restart() with missing binary returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ServeBackend: no-op safety when Tor is not running
// ---------------------------------------------------------------------------

func TestServeBackend_BeforeStart_DoesNotPanic(t *testing.T) {
	m := NewTorManager(defaultCfg(t))
	m.ServeBackend(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if m.pendingHandler == nil {
		t.Error("ServeBackend() did not retain pendingHandler")
	}
}
