package i2p

import (
	"bufio"
	"context"
	"fmt"
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

func TestRegenerateAddress_EnabledNoProviderReturnsEmptyNoError(t *testing.T) {
	// Mirrors Tor's TestRegenerateAddress_WhenBinaryMissing_ReturnsEmptyNoError:
	// Start() swallows the "no provider available" error (logged, non-fatal,
	// per AI.md PART 31.2's "log WARN, continue without I2P" behavior), so
	// RegenerateAddress must also return an empty address with a nil error.
	tmp := t.TempDir()
	m := NewI2PManager(I2PServiceConfig{
		Enabled:    true,
		DataDir:    tmp,
		ConfigDir:  tmp,
		Binary:     "/nonexistent/i2pd",
		SAMAddress: "127.0.0.1:1",
	})
	addr, err := m.RegenerateAddress()
	if err != nil {
		t.Fatalf("RegenerateAddress() with no provider = error %v, want nil", err)
	}
	if addr != "" {
		t.Errorf("RegenerateAddress() address = %q, want empty", addr)
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

func TestLoadOrCreateSAMDestination_GeneratesAndPersistsAtomically(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site", "site-keys.dat")
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	priv := fakeSAMPrivateKey()
	go func() {
		r := bufio.NewReader(server)
		line, _ := r.ReadString('\n')
		if !strings.HasPrefix(line, "DEST GENERATE SIGNATURE_TYPE=7") {
			t.Errorf("server received %q, want DEST GENERATE", line)
		}
		_, _ = server.Write([]byte("DEST REPLY RESULT=OK PRIV=" + priv + "\n"))
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
	if string(persisted) != priv+"\n" {
		t.Errorf("persisted key does not contain the single PRIV line")
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
	defer ln.Close()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	backendPort := backend.Addr().(*net.TCPAddr).Port
	defer backend.Close()
	priv := fakeSAMPrivateKey()
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
					c.Close()
					return nil, nil, re
				}
				got = append(got, strings.TrimSpace(line))
				if !strings.HasPrefix(line, step.prefix) {
					c.Close()
					return nil, nil, fmt.Errorf("got %q, want %s", line, step.prefix)
				}
				if _, re = c.Write([]byte(step.response)); re != nil {
					c.Close()
					return nil, nil, re
				}
			}
			return got, c, nil
		}
		control, controlConn, e := readConn("DEST GENERATE", "DEST REPLY RESULT=OK PRIV="+priv+"\n")
		if e != nil {
			serverErr <- e
			return
		}
		line, e := bufio.NewReader(controlConn).ReadString('\n')
		if e != nil || !strings.HasPrefix(line, "SESSION CREATE") {
			controlConn.Close()
			serverErr <- fmt.Errorf("SESSION CREATE missing: %q (%v)", line, e)
			return
		}
		control = append(control, strings.TrimSpace(line))
		_, e = controlConn.Write([]byte("SESSION STATUS RESULT=OK\n"))
		if e != nil {
			controlConn.Close()
			serverErr <- e
			return
		}
		forward, forwardConn, e := readConn("STREAM FORWARD", "STREAM STATUS RESULT=OK\n")
		if e != nil {
			controlConn.Close()
			serverErr <- e
			return
		}
		commands <- control
		commands <- forward
		<-release
		controlConn.Close()
		forwardConn.Close()
	}()
	m := NewI2PManager(I2PServiceConfig{Enabled: true, ConfigDir: t.TempDir(), DataDir: t.TempDir(), SAMAddress: ln.Addr().String(), SignatureType: 7, InboundLength: 3, OutboundLength: 3, InboundQuantity: 5, OutboundQuantity: 5, BootstrapTimeout: 30})
	svc := &service{}
	addr, err := m.startSAMEepsite(ln.Addr().String(), filepath.Join(t.TempDir(), "site", "site-keys.dat"), backendPort, svc)
	if err != nil {
		t.Fatalf("startSAMEepsite(): %v", err)
	}
	control, forward := <-commands, <-commands
	if len(control) != 3 || !strings.HasPrefix(control[0], "HELLO VERSION MIN=3.1 MAX=3.3") {
		t.Errorf("control socket did not negotiate SAM 3.1 and create session: %v", control)
	}
	if len(forward) != 2 || !strings.HasPrefix(forward[0], "HELLO VERSION MIN=3.1 MAX=3.3") || !strings.Contains(forward[1], "SILENT=true") {
		t.Errorf("forward socket did not negotiate SAM 3.1 and use SILENT=true: %v", forward)
	}
	if svc.samConn == nil || svc.forwardConn == nil || svc.samConn == svc.forwardConn {
		t.Error("control and forward connections must be distinct and retained")
	}
	if want := b32Address(mustDestination(t, priv)); addr != want {
		t.Errorf("address = %q, want %q", addr, want)
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

func mustDestination(t *testing.T, priv string) []byte {
	t.Helper()
	dest, err := destinationBytes(priv)
	if err != nil {
		t.Fatal(err)
	}
	return dest
}

func TestBootstrapTimeoutRangeAndRecoveryBackoff(t *testing.T) {
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
	backoff := 0 * time.Second
	for _, want := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 300 * time.Second, 300 * time.Second} {
		backoff = recoveryBackoff(backoff)
		if backoff != want {
			t.Fatalf("recoveryBackoff = %v, want %v", backoff, want)
		}
	}
	if i2pdSAMStartupTimeout != 60*time.Second {
		t.Errorf("Model A SAM startup bound = %v, want 60s per Part 31.2", i2pdSAMStartupTimeout)
	}
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
}

func TestSAMDialRequiresVersion31(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		if !strings.Contains(line, "MIN=3.1 MAX=3.3") {
			t.Errorf("HELLO = %q, want SAM 3.1 range", line)
		}
		_, _ = conn.Write([]byte("HELLO REPLY RESULT=NOVERSION MESSAGE=unsupported\n"))
	}()
	conn, _, err := samDial(context.Background(), ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("samDial accepted a router without SAM 3.1")
	}
}

func TestSAMCommandHasDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = bufio.NewReader(server).ReadString('\n') }()
	if _, err := samCommand(client, bufio.NewReader(client), 20*time.Millisecond, "SESSION STATUS"); err == nil {
		t.Fatal("samCommand without a reply succeeded; expected deadline error")
	}
}

func TestWatchSAMConnectionReportsCloseWithoutPollingReads(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
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
	defer local.Close()
	defer remote.Close()
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
