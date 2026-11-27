package i2p

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func checkTestConnClose(t *testing.T, conn interface{ Close() error }) {
	t.Helper()
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close test connection: %v", err)
	}
}

func TestProviderString(t *testing.T) {
	cases := []struct {
		p    Provider
		want string
	}{
		{ProviderNone, "none"},
		{ProviderI2PD, "i2pd"},
		{ProviderSAM, "sam"},
		{Provider(99), "none"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("Provider(%d).String() = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestB32Address(t *testing.T) {
	// Known vector: sha256("") base32-encoded (no padding), lowercased, +.b32.i2p.
	got := b32Address([]byte(""))
	if !strings.HasSuffix(got, ".b32.i2p") {
		t.Fatalf("b32Address missing .b32.i2p suffix: %q", got)
	}
	if strings.ToLower(got) != got {
		t.Fatalf("b32Address not lowercased: %q", got)
	}
	if strings.Contains(got, "=") {
		t.Fatalf("b32Address must not be padded: %q", got)
	}
	// Deterministic for the same input.
	got2 := b32Address([]byte(""))
	if got != got2 {
		t.Fatalf("b32Address not deterministic: %q vs %q", got, got2)
	}
	// Different input yields a different address.
	other := b32Address([]byte("destination-bytes"))
	if other == got {
		t.Fatalf("b32Address collision for different inputs")
	}
}

func TestGetI2PTunnelsConf(t *testing.T) {
	if got := getI2PTunnelsConf(I2PServiceConfig{}, "ignored", 64123); got != "" {
		t.Fatalf("tunnels.conf = %q, want empty so SAM owns the eepsite", got)
	}
}

func TestEnsureI2PDirs(t *testing.T) {
	tmp := t.TempDir()
	configDir := filepath.Join(tmp, "config")
	dataDir := filepath.Join(tmp, "data")

	if err := ensureI2PDirs(configDir, dataDir); err != nil {
		t.Fatalf("ensureI2PDirs: %v", err)
	}
	for _, d := range []string{
		filepath.Join(configDir, "i2p"),
		filepath.Join(dataDir, "i2p"),
		filepath.Join(dataDir, "i2p", "site"),
	} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatalf("expected dir %s to exist: %v", d, err)
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("%s perm = %o, want 0700", d, info.Mode().Perm())
		}
	}
	// Idempotent — calling again must not error.
	if err := ensureI2PDirs(configDir, dataDir); err != nil {
		t.Fatalf("ensureI2PDirs (second call): %v", err)
	}
}

func TestUpdateI2PTunnels(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "i2p", "tunnels.conf")

	if err := updateI2PTunnels(path, []byte("first")); err != nil {
		t.Fatalf("updateI2PTunnels: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tunnels.conf: %v", err)
	}
	if string(data) != "first" {
		t.Fatalf("tunnels.conf content = %q, want %q", data, "first")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat tunnels.conf: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("tunnels.conf perm = %o, want 0600", info.Mode().Perm())
	}

	// Regenerated (overwritten) on every call — never preserved.
	if err := updateI2PTunnels(path, []byte("second")); err != nil {
		t.Fatalf("updateI2PTunnels (overwrite): %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tunnels.conf (2): %v", err)
	}
	if string(data) != "second" {
		t.Fatalf("tunnels.conf content = %q, want %q", data, "second")
	}
}

func TestGetRandomAvailablePort(t *testing.T) {
	ln1, port1, err := getRandomAvailablePort()
	if err != nil {
		t.Fatalf("getRandomAvailablePort: %v", err)
	}
	defer func() {
		if err := ln1.Close(); err != nil {
			t.Errorf("close first listener: %v", err)
		}
	}()
	if port1 <= 0 {
		t.Fatalf("port1 = %d, want > 0", port1)
	}

	ln2, port2, err := getRandomAvailablePort()
	if err != nil {
		t.Fatalf("getRandomAvailablePort (2): %v", err)
	}
	defer func() {
		if err := ln2.Close(); err != nil {
			t.Errorf("close second listener: %v", err)
		}
	}()
	if port2 <= 0 {
		t.Fatalf("port2 = %d, want > 0", port2)
	}
	if port1 == port2 {
		t.Errorf("expected distinct ports, got %d twice", port1)
	}
}

func TestSamReachable(t *testing.T) {
	if samReachable("127.0.0.1:1") {
		t.Error("samReachable(127.0.0.1:1) = true, want false (nothing listening)")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if err := c.Close(); err != nil {
				t.Errorf("close accepted connection: %v", err)
			}
		}
	}()
	if !samReachable(ln.Addr().String()) {
		t.Errorf("samReachable(%s) = false, want true", ln.Addr().String())
	}
}

func TestResolveI2PDBinary_NotFound(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Binary: "/nonexistent/path/to/i2pd"})
	if got := m.resolveI2PDBinary(); got != "" {
		t.Errorf("resolveI2PDBinary() = %q, want empty for missing explicit binary", got)
	}
}

func TestResolveI2PDBinary_ExplicitFound(t *testing.T) {
	tmp := t.TempDir()
	fakeBinary := filepath.Join(tmp, "i2pd")
	if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	m := NewI2PManager(I2PServiceConfig{Binary: fakeBinary})
	if got := m.resolveI2PDBinary(); got != fakeBinary {
		t.Errorf("resolveI2PDBinary() = %q, want %q", got, fakeBinary)
	}
}

func TestIsAvailable_DisabledByDefault(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	if m.IsAvailable() {
		t.Error("IsAvailable() = true for disabled I2P, want false (opt-in)")
	}
}

func TestIsAvailable_EnabledNoProvider(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{
		Enabled:    true,
		Binary:     "/nonexistent/i2pd",
		SAMAddress: "127.0.0.1:1",
	})
	if m.IsAvailable() {
		t.Error("IsAvailable() = true with no i2pd binary and unreachable SAM, want false")
	}
}

func TestStart_DisabledIsNoop(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	if err := m.Start(); err != nil {
		t.Fatalf("Start() on disabled I2P returned error, want nil (opt-in, never fatal): %v", err)
	}
	if m.IsRunning() {
		t.Error("IsRunning() = true after Start() on disabled I2P")
	}
	if got := m.Status(); got != "disabled" {
		t.Errorf("Status() = %q, want %q", got, "disabled")
	}
}

func TestStart_EnabledNoProviderNeverFatal(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{
		Enabled:    true,
		Binary:     "/nonexistent/i2pd",
		SAMAddress: "127.0.0.1:1",
	})
	if err := m.Start(); err != nil {
		t.Fatalf("Start() with no provider returned error, want nil (never fatal): %v", err)
	}
	if m.IsRunning() {
		t.Error("IsRunning() = true after failed Start()")
	}
	if got := m.Status(); got != "no_provider" {
		t.Errorf("Status() = %q, want %q", got, "no_provider")
	}
}

func TestStop_WhenNeverStartedIsNoop(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop() on never-started manager returned error: %v", err)
	}
}

func TestEepsiteAddressAndGetHostname_EmptyWhenNotRunning(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{})
	if got := m.EepsiteAddress(); got != "" {
		t.Errorf("EepsiteAddress() = %q, want empty", got)
	}
	if got := m.GetHostname(); got != "" {
		t.Errorf("GetHostname() = %q, want empty", got)
	}
}

func TestGetInfo_Disabled(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	info := m.GetInfo()
	if info.Enabled {
		t.Error("GetInfo().Enabled = true, want false")
	}
	if info.Running {
		t.Error("GetInfo().Running = true, want false")
	}
	if info.Status != "disabled" {
		t.Errorf("GetInfo().Status = %q, want %q", info.Status, "disabled")
	}
	if info.Hostname != "" {
		t.Errorf("GetInfo().Hostname = %q, want empty", info.Hostname)
	}
}

func TestUnavailableServiceHidesAddressAndRunningState(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: true})
	m.running = true
	m.svc = &service{provider: ProviderI2PD, eepsiteAddress: "example.b32.i2p", status: "error"}

	if m.IsRunning() {
		t.Fatal("IsRunning() = true while provider status is error")
	}
	if got := m.GetHostname(); got != "" {
		t.Fatalf("GetHostname() = %q while unavailable, want empty", got)
	}
	info := m.GetInfo()
	if info.Running || info.Hostname != "" || info.Status != "error" {
		t.Fatalf("GetInfo() = %+v, want unavailable with no hostname", info)
	}
}

func TestAddressHandlerReceivesStartupIdentity(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{})
	const address = "example.b32.i2p"
	m.publishAddress(address)
	if got := m.WaitForAddress(time.Second); got != address {
		t.Fatalf("WaitForAddress() = %q, want %q", got, address)
	}
	var received string
	m.AddAddressHandler(func(value string) { received = value })
	if received != address {
		t.Fatalf("address handler received %q, want %q", received, address)
	}
}

func TestServeBackend_BeforeStartIsSafe(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Must not panic even though no service exists yet.
	m.ServeBackend(handler)
	if err := m.Start(); err != nil {
		t.Fatalf("Start() after ServeBackend returned error: %v", err)
	}
}

func TestClose_IsAliasForStop(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	if err := m.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
}

func TestRestart_DisabledNeverFatal(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	if err := m.Restart(); err != nil {
		t.Fatalf("Restart() on disabled I2P returned error: %v", err)
	}
}

func TestReadSAMReply(t *testing.T) {
	t.Run("valid reply", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("HELLO REPLY RESULT=OK VERSION=3.3\n"))
		line, err := readSAMReply(r, "HELLO REPLY")
		if err != nil {
			t.Fatalf("readSAMReply: %v", err)
		}
		if !strings.Contains(line, "RESULT=OK") {
			t.Errorf("line = %q, want RESULT=OK", line)
		}
	})

	t.Run("wrong prefix", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("SESSION STATUS RESULT=OK\n"))
		if _, err := readSAMReply(r, "HELLO REPLY"); err == nil {
			t.Fatal("readSAMReply with mismatched prefix = nil error, want error")
		}
	})

	t.Run("error result", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("HELLO REPLY RESULT=NOVERSION\n"))
		if _, err := readSAMReply(r, "HELLO REPLY"); err == nil {
			t.Fatal("readSAMReply with RESULT!=OK = nil error, want error")
		}
	})
}

func TestStatusLocked_Transitions(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: true})
	if got := m.Status(); got != "starting" {
		t.Errorf("Status() (enabled, not running) = %q, want %q", got, "starting")
	}

	m.mu.Lock()
	m.running = true
	m.svc = &service{}
	m.mu.Unlock()
	if got := m.Status(); got != "starting" {
		t.Errorf("Status() (running, no address yet) = %q, want %q", got, "starting")
	}

	m.mu.Lock()
	m.svc.eepsiteAddress = "abcd1234.b32.i2p"
	m.mu.Unlock()
	if got := m.Status(); got != "running" {
		t.Errorf("Status() (running, address set) = %q, want %q", got, "running")
	}
	m.mu.Lock()
	m.svc.status = "building"
	m.mu.Unlock()
	if got := m.Status(); got != "building" {
		t.Errorf("Status() during tunnel build = %q, want building", got)
	}
	m.mu.Lock()
	m.svc.status = "error"
	m.mu.Unlock()
	if got := m.Status(); got != "error" {
		t.Errorf("Status() after session loss = %q, want error", got)
	}
	m.mu.Lock()
	m.svc.status = ""
	m.mu.Unlock()
	m.mu.Lock()
	m.running = false
	m.svc = nil
	m.startErr = ErrNoProvider
	m.mu.Unlock()
	if got := m.Status(); got != "no_provider" {
		t.Errorf("Status() without provider = %q, want no_provider", got)
	}
	m.mu.Lock()
	m.startErr = fmt.Errorf("startup failed")
	m.mu.Unlock()
	if got := m.Status(); got != "error" {
		t.Errorf("Status() after startup error = %q, want error", got)
	}
	m.mu.Lock()
	m.cfg.Enabled = false
	m.startErr = nil
	m.mu.Unlock()
	if got := m.Status(); got != "disabled" {
		t.Errorf("Status() disabled = %q, want disabled", got)
	}
}

func TestAttachBackendHandlerLocked_ServesRequests(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := NewI2PManager(I2PServiceConfig{})
	m.mu.Lock()
	m.svc = &service{backendLn: ln}
	m.running = true
	m.mu.Unlock()

	m.ServeBackend(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	// Give the goroutine a moment to start serving.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + ln.Addr().String() + "/")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET backend listener: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTeapot)
	}

	_ = m.Stop()
}

func TestHTTPTestServerSanity(t *testing.T) {
	// Sanity check that httptest works in this environment (used implicitly
	// by the backend-listener test above via the real net.Listener path).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestUpdateConfig_DisablesEepsite(t *testing.T) {
	tmp := t.TempDir()
	m := NewI2PManager(I2PServiceConfig{Enabled: false, DataDir: tmp, ConfigDir: tmp})
	if err := m.UpdateConfig(I2PServiceConfig{Enabled: false, DataDir: tmp, ConfigDir: tmp}); err != nil {
		t.Fatalf("UpdateConfig() error = %v, want nil", err)
	}
	if m.IsRunning() {
		t.Error("IsRunning() = true after UpdateConfig with Enabled=false, want false")
	}
	if got := m.Status(); got != "disabled" {
		t.Errorf("Status() = %q, want %q", got, "disabled")
	}
}

func TestUpdateConfig_EnabledNoProviderNeverFatal(t *testing.T) {
	tmp := t.TempDir()
	m := NewI2PManager(I2PServiceConfig{Enabled: false, DataDir: tmp, ConfigDir: tmp})
	err := m.UpdateConfig(I2PServiceConfig{
		Enabled:    true,
		DataDir:    tmp,
		ConfigDir:  tmp,
		Binary:     "/nonexistent/i2pd",
		SAMAddress: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("UpdateConfig() error = %v, want nil (never fatal)", err)
	}
	if m.IsRunning() {
		t.Error("IsRunning() = true with no provider available, want false")
	}
}

func TestRegenerateAddressReturnsErrorWhenProviderUnavailable(t *testing.T) {
	tmp := t.TempDir()
	m := NewI2PManager(I2PServiceConfig{
		Enabled:    true,
		DataDir:    tmp,
		ConfigDir:  tmp,
		Binary:     filepath.Join(tmp, "missing-i2pd"),
		SAMAddress: "127.0.0.1:1",
	})
	if _, err := m.RegenerateAddress(); err == nil {
		t.Fatal("RegenerateAddress() error = nil when no provider is available")
	}
}

func fakeSAMPrivateKey() string {
	destination := make([]byte, 387)
	for i := range destination[:384] {
		destination[i] = byte(i % 251)
	}
	return i2pBase64.EncodeToString(destination)
}

func TestLoadOrCreateSAMDestination_LoadsPersistedKeyWithoutTouchingConn(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site-keys.dat")
	priv := fakeSAMPrivateKey()
	if err := os.WriteFile(keysPath, []byte(priv+"\n"), 0o600); err != nil {
		t.Fatalf("seed keysPath: %v", err)
	}
	dest, err := loadOrCreateSAMDestination(nil, nil, keysPath, 7)
	if err != nil {
		t.Fatalf("loadOrCreateSAMDestination() error = %v", err)
	}
	if dest.priv != priv {
		t.Errorf("dest.priv = %q, want persisted key", dest.priv)
	}
}

func TestLoadOrCreateSAMDestination_InvalidKeyDoesNotRegenerate(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site-keys.dat")
	secret := "DO-NOT-LOG-THIS-PRIV"
	if err := os.WriteFile(keysPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer checkTestConnClose(t, client)
	defer checkTestConnClose(t, server)
	logOutput := &strings.Builder{}
	originalWriter := log.Writer()
	log.SetOutput(logOutput)
	t.Cleanup(func() { log.SetOutput(originalWriter) })
	_, err := loadOrCreateSAMDestination(client, bufio.NewReader(client), keysPath, 7)
	if err == nil || !strings.Contains(err.Error(), keysPath) {
		t.Fatalf("invalid destination error = %v, want an error naming %s", err, keysPath)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(logOutput.String(), secret) {
		t.Fatal("invalid destination private value appeared in error or logs")
	}
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := bufio.NewReader(server).ReadString('\n'); err == nil {
		t.Fatal("invalid persisted key triggered a SAM command")
	}
}

func TestLoadOrCreateSAMDestination_GeneratesAndPersistsAtomically(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site", "site-keys.dat")
	server, client := net.Pipe()
	t.Cleanup(func() { checkTestConnClose(t, server) })
	t.Cleanup(func() { checkTestConnClose(t, client) })
	priv := fakeSAMPrivateKey()
	go func() {
		r := bufio.NewReader(server)
		line, _ := r.ReadString('\n')
		if !strings.HasPrefix(line, "DEST GENERATE SIGNATURE_TYPE=7") {
			t.Errorf("server received %q, want DEST GENERATE", line)
		}
		_, _ = server.Write([]byte("DEST REPLY PUB=public PRIV=" + priv + "\n"))
	}()
	dest, err := loadOrCreateSAMDestination(client, bufio.NewReader(client), keysPath, 7)
	if err != nil {
		t.Fatalf("loadOrCreateSAMDestination() error = %v", err)
	}
	if dest.priv != priv {
		t.Fatalf("generated key differs from SAM PRIV")
	}
	persisted, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if string(persisted) != priv {
		t.Errorf("persisted key must contain the bare PRIV value without a trailing newline")
	}
	info, err := os.Stat(keysPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file permissions = %v, error=%v; want 0600", info, err)
	}
}

func TestStartSAMEepsite_UsesSAM31AndSeparateSilentForwardSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { checkTestConnClose(t, ln) })
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	backendPort := backend.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { checkTestConnClose(t, backend) })
	priv := fakeSAMPrivateKey()
	logOutput := &strings.Builder{}
	originalLogWriter := log.Writer()
	log.SetOutput(logOutput)
	t.Cleanup(func() { log.SetOutput(originalLogWriter) })
	commands := make(chan []string, 2)
	serverErr := make(chan error, 1)
	release := make(chan struct{})
	go func() {
		readConn := func(wantPrefix string, reply string) ([]string, net.Conn, error) {
			c, e := ln.Accept()
			if e != nil {
				return nil, nil, e
			}
			r := bufio.NewReader(c)
			var got []string
			for _, step := range []struct{ prefix, response string }{{"HELLO VERSION", "HELLO REPLY RESULT=OK VERSION=3.3\n"}, {wantPrefix, reply}} {
				line, re := r.ReadString('\n')
				if re != nil {
					checkTestConnClose(t, c)
					return nil, nil, re
				}
				got = append(got, strings.TrimSpace(line))
				if !strings.HasPrefix(line, step.prefix) {
					checkTestConnClose(t, c)
					return nil, nil, fmt.Errorf("got %q, want %s", line, step.prefix)
				}
				if _, re = c.Write([]byte(step.response)); re != nil {
					checkTestConnClose(t, c)
					return nil, nil, re
				}
			}
			return got, c, nil
		}
		control, controlConn, e := readConn("DEST GENERATE", "DEST REPLY PUB=public PRIV="+priv+"\n")
		if e != nil {
			serverErr <- e
			return
		}
		line, e := bufio.NewReader(controlConn).ReadString('\n')
		if e != nil || !strings.HasPrefix(line, "SESSION CREATE") {
			checkTestConnClose(t, controlConn)
			serverErr <- fmt.Errorf("SESSION CREATE missing: %q (%v)", line, e)
			return
		}
		firstSession := strings.TrimSpace(line)
		control = append(control, firstSession)
		_, e = controlConn.Write([]byte("SESSION STATUS RESULT=DUPLICATED_ID\n"))
		if e != nil {
			checkTestConnClose(t, controlConn)
			serverErr <- e
			return
		}
		line, e = bufio.NewReader(controlConn).ReadString('\n')
		if e != nil || !strings.HasPrefix(line, "SESSION CREATE") {
			checkTestConnClose(t, controlConn)
			serverErr <- fmt.Errorf("SESSION CREATE retry missing: %q (%v)", line, e)
			return
		}
		secondSession := strings.TrimSpace(line)
		control = append(control, secondSession)
		if firstSession == secondSession {
			checkTestConnClose(t, controlConn)
			serverErr <- fmt.Errorf("duplicate session retry reused session ID: %q", secondSession)
			return
		}
		_, e = controlConn.Write([]byte("SESSION STATUS RESULT=OK\n"))
		if e != nil {
			checkTestConnClose(t, controlConn)
			serverErr <- e
			return
		}
		forward, forwardConn, e := readConn("STREAM FORWARD", "STREAM STATUS RESULT=OK\n")
		if e != nil {
			checkTestConnClose(t, controlConn)
			serverErr <- e
			return
		}
		commands <- control
		commands <- forward
		<-release
		checkTestConnClose(t, controlConn)
		checkTestConnClose(t, forwardConn)
	}()
	m := NewI2PManager(I2PServiceConfig{Enabled: true, ConfigDir: t.TempDir(), DataDir: t.TempDir(), SAMAddress: ln.Addr().String(), SignatureType: 7, InboundLength: 3, OutboundLength: 3, InboundQuantity: 5, OutboundQuantity: 5, BootstrapTimeout: 30})
	svc := &service{}
	addr, err := m.startSAMEepsite(context.Background(), ln.Addr().String(), filepath.Join(t.TempDir(), "site", "site-keys.dat"), backendPort, svc)
	if err != nil {
		t.Fatalf("startSAMEepsite(): %v", err)
	}
	control, forward := <-commands, <-commands
	if len(control) != 4 || !strings.HasPrefix(control[0], "HELLO VERSION MIN=3.1 MAX=3.3") || !strings.HasPrefix(control[1], "DEST GENERATE") {
		t.Errorf("control socket did not negotiate SAM 3.1 and create session: %v", control)
	}
	if len(control) == 4 && (!strings.Contains(control[2], "DESTINATION="+priv) || !strings.Contains(control[3], "DESTINATION="+priv)) {
		t.Errorf("DUPLICATED_ID retry did not reuse the persisted destination key: %v", control)
	}
	if len(forward) != 2 || !strings.HasPrefix(forward[0], "HELLO VERSION MIN=3.1 MAX=3.3") || !strings.Contains(forward[1], "SILENT=true") || !strings.Contains(forward[1], fmt.Sprintf("PORT=%d", backendPort)) || strings.Contains(forward[1], "HOST=") {
		t.Errorf("forward socket did not use only the backend port with SILENT=true: %v", forward)
	}
	if svc.samConn == nil || svc.forwardConn == nil || svc.samConn == svc.forwardConn {
		t.Error("control and forward connections must be distinct and retained")
	}
	if want := b32Address(mustDestination(t, priv)); addr != want {
		t.Errorf("address = %q, want %q", addr, want)
	}
	if strings.Contains(logOutput.String(), priv) || strings.Contains(logOutput.String(), "PRIV=") {
		t.Error("I2P private destination appeared in logs")
	}
	_ = svc.forwardConn.Close()
	_ = svc.samConn.Close()
	close(release)
	select {
	case e := <-serverErr:
		t.Errorf("SAM mock: %v", e)
	default:
	}
}

func TestStartSAMEepsiteInvalidKeyPreservesPersistedIdentity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer checkTestConnClose(t, ln)
	priv := fakeSAMPrivateKey()
	keysPath := filepath.Join(t.TempDir(), "site-keys.dat")
	if err := os.WriteFile(keysPath, []byte(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	command := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer checkTestConnClose(t, conn)
		reader := bufio.NewReader(conn)
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if !strings.HasPrefix(line, "HELLO VERSION MIN=3.1 MAX=3.3") {
			serverErr <- fmt.Errorf("HELLO = %q", line)
			return
		}
		_, _ = conn.Write([]byte("HELLO REPLY RESULT=OK VERSION=3.3\n"))
		line, readErr = reader.ReadString('\n')
		if readErr != nil {
			serverErr <- readErr
			return
		}
		command <- strings.TrimSpace(line)
		_, _ = conn.Write([]byte("SESSION STATUS RESULT=INVALID_KEY\n"))
		line, readErr = reader.ReadString('\n')
		if readErr == nil && strings.HasPrefix(line, "DEST GENERATE") {
			serverErr <- errors.New("invalid key caused automatic destination regeneration")
			return
		}
		serverErr <- nil
	}()
	m := NewI2PManager(I2PServiceConfig{Enabled: true, SAMAddress: ln.Addr().String(), BootstrapTimeout: 30})
	_, err = m.startSAMEepsite(context.Background(), ln.Addr().String(), keysPath, 12345, &service{})
	if err == nil || !strings.Contains(err.Error(), "INVALID_KEY") {
		t.Fatalf("startSAMEepsite() error = %v, want INVALID_KEY", err)
	}
	gotCommand := <-command
	if !strings.HasPrefix(gotCommand, "SESSION CREATE") || !strings.Contains(gotCommand, "DESTINATION="+priv) {
		t.Fatalf("SAM command = %q, want SESSION CREATE with persisted key", gotCommand)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(keysPath)
	if err != nil || string(persisted) != priv {
		t.Fatalf("persisted key changed after INVALID_KEY: got %q, err %v", persisted, err)
	}
}

func mustDestination(t *testing.T, priv string) []byte {
	t.Helper()
	dest, err := destinationBytes(priv)
	if err != nil {
		t.Fatal(err)
	}
	return dest
}

func TestBootstrapTimeoutRange(t *testing.T) {
	for _, tc := range []struct {
		seconds int
		want    time.Duration
		valid   bool
	}{{0, 300 * time.Second, true}, {30, 30 * time.Second, true}, {600, 600 * time.Second, true}, {29, 0, false}, {601, 0, false}} {
		got, err := bootstrapTimeout(tc.seconds)
		if (err == nil) != tc.valid || got != tc.want {
			t.Errorf("bootstrapTimeout(%d) = %v, %v", tc.seconds, got, err)
		}
	}
	if i2pdSAMStartupTimeout != 60*time.Second {
		t.Errorf("Model A SAM startup bound = %v, want 60s per Part 31.2", i2pdSAMStartupTimeout)
	}
}

func TestStartAsyncMarksStartingSynchronously(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: true, SAMAddress: "127.0.0.1:1"})
	m.StartAsync()
	if got := m.Status(); got != "starting" {
		t.Fatalf("Status() immediately after StartAsync() = %q, want starting", got)
	}
	_ = m.Stop()
}

func TestI2PDConfigDisablesUnrelatedServicesAndUsesPrivateSAMPort(t *testing.T) {
	conf := buildI2PDConfig("/var/log/ipgaze/i2pd.log", 54321)
	for _, expected := range []string{
		"daemon = false", "notransit = true", "floodfill = false", "loglevel = warn",
		"logfile = /var/log/ipgaze/i2pd.log", "[sam]\nenabled = true\naddress = 127.0.0.1\nport = 54321",
		"[http]\nenabled = false", "[httpproxy]\nenabled = false", "[socksproxy]\nenabled = false",
		"[bob]\nenabled = false", "[i2cp]\nenabled = false", "[i2pcontrol]\nenabled = false", "[upnp]\nenabled = false",
	} {
		if !strings.Contains(conf, expected) {
			t.Errorf("i2pd.conf missing %q", expected)
		}
	}
	for _, forbiddenPort := range []string{"7070", "4444", "4447", "7654"} {
		if strings.Contains(conf, forbiddenPort) {
			t.Errorf("i2pd.conf unexpectedly references forbidden service port %s", forbiddenPort)
		}
	}
}

func TestSAMDialRequiresVersion31(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { checkTestConnClose(t, ln) })
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer checkTestConnClose(t, conn)
		line, _ := bufio.NewReader(conn).ReadString('\n')
		if !strings.Contains(line, "MIN=3.1 MAX=3.3") {
			t.Errorf("HELLO = %q, want SAM 3.1 range", line)
		}
		_, _ = conn.Write([]byte("HELLO REPLY RESULT=NOVERSION MESSAGE=unsupported\n"))
	}()
	conn, _, err := samDial(context.Background(), ln.Addr().String())
	if err == nil {
		checkTestConnClose(t, conn)
		t.Fatal("samDial accepted a router without SAM 3.1")
	}
}

func TestSAMCommandHasDeadline(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { checkTestConnClose(t, client) })
	t.Cleanup(func() { checkTestConnClose(t, server) })
	go func() { _, _ = bufio.NewReader(server).ReadString('\n') }()
	if _, err := samCommand(client, bufio.NewReader(client), 20*time.Millisecond, "SESSION STATUS"); err == nil {
		t.Fatal("samCommand without a reply succeeded; expected deadline error")
	}
}

func TestSAMCommandAllowsSixtySecondSessionBootstrap(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { checkTestConnClose(t, client) })
	t.Cleanup(func() { checkTestConnClose(t, server) })
	serverErr := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(server).ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if !strings.HasPrefix(line, "SESSION CREATE") {
			serverErr <- fmt.Errorf("command = %q, want SESSION CREATE", line)
			return
		}
		time.Sleep(60 * time.Second)
		_, err = server.Write([]byte("SESSION STATUS RESULT=OK\n"))
		serverErr <- err
	}()
	_, err := samCommand(client, bufio.NewReader(client), 90*time.Second, "SESSION CREATE STYLE=STREAM")
	if err != nil {
		t.Fatalf("samCommand() after 60-second tunnel build: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("SAM mock: %v", err)
	}
}

func TestMonitorSAMErrorsAfterThreeConsecutiveProbeFailures(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: true})
	svc := &service{provider: ProviderSAM, status: "running", samLost: make(chan error, 1)}
	m.svc = svc
	m.running = true
	m.provider = ProviderSAM
	ticks := make(chan time.Time, 3)
	for range 3 {
		ticks <- time.Now()
	}
	probes := 0
	var recoveryDelay time.Duration
	m.recoveryWait = func(_ context.Context, delay time.Duration) bool {
		recoveryDelay = delay
		return false
	}
	m.monitorServiceWithProbe(context.Background(), svc, ticks, func(context.Context) error {
		probes++
		return errors.New("SAM probe failed")
	})
	if probes != 3 || recoveryDelay != 5*time.Second {
		t.Fatalf("probe count/recovery delay = %d/%s, want 3/5s", probes, recoveryDelay)
	}
	if got := m.Status(); got != "error" {
		t.Fatalf("Status() = %q after three probe failures, want error", got)
	}
}

func TestRecoveryBackoffCapsAtFiveMinutes(t *testing.T) {
	delay := 5 * time.Second
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for _, expected := range want {
		delay = nextRecoveryDelay(delay)
		if delay != expected {
			t.Fatalf("nextRecoveryDelay() = %s, want %s", delay, expected)
		}
	}
}

func TestSAMSessionLossRecoversUsingPersistedDestination(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer checkTestConnClose(t, ln)
	type readySession struct {
		control net.Conn
		command string
	}
	ready := make(chan readySession, 2)
	serverErr := make(chan error, 1)
	priv := fakeSAMPrivateKey()
	go func() {
		generation := 0
		for generation < 2 {
			control, acceptErr := ln.Accept()
			if acceptErr != nil {
				serverErr <- acceptErr
				return
			}
			reader := bufio.NewReader(control)
			line, readErr := reader.ReadString('\n')
			if readErr != nil || !strings.HasPrefix(line, "HELLO VERSION") {
				_ = control.Close()
				continue
			}
			_, _ = control.Write([]byte("HELLO REPLY RESULT=OK VERSION=3.3\n"))
			line, readErr = reader.ReadString('\n')
			if readErr != nil {
				serverErr <- readErr
				return
			}
			if generation == 0 {
				if !strings.HasPrefix(line, "DEST GENERATE") {
					serverErr <- fmt.Errorf("first generation command = %q, want DEST GENERATE", line)
					return
				}
				_, _ = control.Write([]byte("DEST REPLY PUB=public PRIV=" + priv + "\n"))
				line, readErr = reader.ReadString('\n')
				if readErr != nil {
					serverErr <- readErr
					return
				}
			} else if !strings.HasPrefix(line, "SESSION CREATE") {
				serverErr <- fmt.Errorf("recovery command = %q, want SESSION CREATE without DEST GENERATE", line)
				return
			}
			sessionCommand := strings.TrimSpace(line)
			if !strings.Contains(sessionCommand, "DESTINATION="+priv) {
				serverErr <- errors.New("session did not reuse the persisted destination key")
				return
			}
			_, _ = control.Write([]byte("SESSION STATUS RESULT=OK\n"))
			forward, acceptErr := ln.Accept()
			if acceptErr != nil {
				serverErr <- acceptErr
				return
			}
			forwardReader := bufio.NewReader(forward)
			for _, step := range []struct{ prefix, response string }{
				{"HELLO VERSION", "HELLO REPLY RESULT=OK VERSION=3.3\n"},
				{"STREAM FORWARD", "STREAM STATUS RESULT=OK\n"},
			} {
				command, commandErr := forwardReader.ReadString('\n')
				if commandErr != nil {
					serverErr <- commandErr
					return
				}
				if !strings.HasPrefix(command, step.prefix) {
					serverErr <- fmt.Errorf("forward command = %q, want %s", command, step.prefix)
					return
				}
				_, _ = forward.Write([]byte(step.response))
			}
			ready <- readySession{control: control, command: sessionCommand}
			generation++
			if generation == 1 {
				continue
			}
			_, _ = io.Copy(io.Discard, control)
		}
	}()
	m := NewI2PManager(I2PServiceConfig{
		Enabled: true, ConfigDir: t.TempDir(), DataDir: t.TempDir(),
		Binary: filepath.Join(t.TempDir(), "missing-i2pd"), SAMAddress: ln.Addr().String(),
		SignatureType: 7, InboundLength: 3, OutboundLength: 3, InboundQuantity: 5, OutboundQuantity: 5, BootstrapTimeout: 30,
	})
	recoveryWaits := 0
	m.recoveryWait = func(ctx context.Context, delay time.Duration) bool {
		recoveryWaits++
		return delay == 5*time.Second && ctx.Err() == nil
	}
	if err := m.Start(); err != nil {
		t.Fatalf("initial Start(): %v", err)
	}
	var first readySession
	select {
	case first = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("initial SAM session did not start: status=%s", m.Status())
	}
	address := m.EepsiteAddress()
	_ = first.control.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (!m.IsRunning() || recoveryWaits == 0) {
		time.Sleep(10 * time.Millisecond)
	}
	var second readySession
	select {
	case second = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("SAM session was not recovered: status=%s", m.Status())
	}
	if !strings.Contains(first.command, "DESTINATION="+priv) || !strings.Contains(second.command, "DESTINATION="+priv) {
		t.Fatalf("recovery did not reuse the same destination key: first=%q second=%q", first.command, second.command)
	}
	if m.EepsiteAddress() != address || !m.IsRunning() {
		t.Fatalf("recovered address/running = %q/%t, want stable address %q and running", m.EepsiteAddress(), m.IsRunning(), address)
	}
	if recoveryWaits != 1 {
		t.Fatalf("recovery wait count = %d, want one 5-second backoff", recoveryWaits)
	}
	if err := m.Stop(); err != nil {
		t.Errorf("Stop(): %v", err)
	}
	_ = second.control.Close()
	select {
	case serverErr := <-serverErr:
		if serverErr != nil && !errors.Is(serverErr, net.ErrClosed) {
			t.Errorf("SAM mock: %v", serverErr)
		}
	default:
	}
}

func TestSAMHealthProbeUsesSeparateHelloAndQuitOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer checkTestConnClose(t, ln)
	commands := make(chan []string, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer checkTestConnClose(t, conn)
		reader := bufio.NewReader(conn)
		var got []string
		for len(got) < 2 {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			got = append(got, strings.TrimSpace(line))
			if strings.HasPrefix(line, "HELLO VERSION") {
				_, _ = conn.Write([]byte("HELLO REPLY RESULT=OK VERSION=3.3\n"))
			}
		}
		commands <- got
	}()
	m := NewI2PManager(I2PServiceConfig{SAMAddress: ln.Addr().String()})
	if err := m.probeSAM(context.Background()); err != nil {
		t.Fatalf("probeSAM(): %v", err)
	}
	got := <-commands
	if len(got) != 2 || !strings.HasPrefix(got[0], "HELLO VERSION MIN=3.1 MAX=3.3") || got[1] != "QUIT" {
		t.Fatalf("SAM probe commands = %v, want only HELLO and QUIT", got)
	}
}

func TestWatchSAMConnectionReportsCloseWithoutPollingReads(t *testing.T) {
	local, remote := net.Pipe()
	t.Cleanup(func() { checkTestConnClose(t, local) })
	reader := bufio.NewReader(local)
	lost := watchSAMConnection(reader)
	if err := remote.Close(); err != nil {
		t.Fatalf("close SAM peer: %v", err)
	}
	select {
	case err := <-lost:
		if err == nil {
			t.Fatal("watchSAMConnection returned nil after peer close")
		}
	case <-time.After(time.Second):
		t.Fatal("watchSAMConnection did not report peer close")
	}
}

func TestWatchSAMConnectionRejectsUnexpectedIdleData(t *testing.T) {
	local, remote := net.Pipe()
	t.Cleanup(func() { checkTestConnClose(t, local) })
	t.Cleanup(func() { checkTestConnClose(t, remote) })
	lost := watchSAMConnection(bufio.NewReader(local))
	writeDone := make(chan error, 1)
	go func() {
		_, err := remote.Write([]byte("unexpected"))
		writeDone <- err
	}()
	select {
	case err := <-lost:
		if err == nil || !strings.Contains(err.Error(), "unexpected data") {
			t.Fatalf("watchSAMConnection error = %v, want unexpected-data error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("watchSAMConnection did not report unexpected data")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write SAM peer data: %v", err)
	}
}

func TestStartDedicatedRejectsBootstrapTimeoutOutsideRange(t *testing.T) {
	for _, seconds := range []int{29, 601} {
		m := NewI2PManager(I2PServiceConfig{Enabled: true, BootstrapTimeout: seconds})
		if _, err := m.startDedicated(context.Background()); err == nil || !strings.Contains(err.Error(), "30 and 600") {
			t.Errorf("startDedicated timeout %d: error=%v, want range validation", seconds, err)
		}
	}
}

func TestStopI2PDWaitsForChildExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX sleep command")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	if err := stopI2PD(cmd, exited); err != nil {
		t.Fatalf("stopI2PD(): %v", err)
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("child was not reaped")
	}
}

func TestStartDedicated_DisabledReturnsError(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{Enabled: false})
	if _, err := m.startDedicated(context.Background()); err == nil {
		t.Error("startDedicated() error = nil, want error when disabled")
	}
}

func TestStartDedicated_NoProviderReturnsError(t *testing.T) {
	tmp := t.TempDir()
	m := NewI2PManager(I2PServiceConfig{
		Enabled:    true,
		DataDir:    tmp,
		ConfigDir:  tmp,
		LogDir:     tmp,
		Binary:     "/nonexistent/i2pd",
		SAMAddress: "127.0.0.1:1",
	})
	if _, err := m.startDedicated(context.Background()); err == nil {
		t.Error("startDedicated() error = nil, want error when no provider available")
	}
}
