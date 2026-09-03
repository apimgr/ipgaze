package i2p

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	cfg := I2PServiceConfig{
		InboundLength:    3,
		OutboundLength:   3,
		InboundQuantity:  5,
		OutboundQuantity: 5,
		SignatureType:    7,
	}
	conf := getI2PTunnelsConf(cfg, "/data/i2p/site/site-keys.dat", 64123)
	for _, want := range []string{
		"[site]",
		"type = server",
		"host = 127.0.0.1",
		"port = 64123",
		"keys = /data/i2p/site/site-keys.dat",
		"inbound.length = 3",
		"outbound.length = 3",
		"inbound.quantity = 5",
		"outbound.quantity = 5",
		"signaturetype = 7",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("tunnels.conf missing %q; got:\n%s", want, conf)
		}
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
	defer ln1.Close()
	if port1 <= 0 {
		t.Fatalf("port1 = %d, want > 0", port1)
	}

	ln2, port2, err := getRandomAvailablePort()
	if err != nil {
		t.Fatalf("getRandomAvailablePort (2): %v", err)
	}
	defer ln2.Close()
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
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
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
	if got := m.Status(); got != "no provider" {
		t.Errorf("Status() = %q, want %q", got, "no provider")
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
	if got := m.Status(); got != "stopped" {
		t.Errorf("Status() (enabled, not running) = %q, want %q", got, "stopped")
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
	if got := m.Status(); got != "healthy" {
		t.Errorf("Status() (running, address set) = %q, want %q", got, "healthy")
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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

func TestWaitForI2PDAddress_SucceedsOnceKeyfileAppears(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site-keys.dat")

	keys := fakeKeysFileBytes()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(keysPath, keys, 0o600)
	}()

	addr, err := waitForI2PDAddress(keysPath, 2*time.Second)
	if err != nil {
		t.Fatalf("waitForI2PDAddress() error = %v, want nil", err)
	}
	if !strings.HasSuffix(addr, ".b32.i2p") {
		t.Errorf("waitForI2PDAddress() = %q, want .b32.i2p suffix", addr)
	}
	want := b32Address(keys[:387])
	if addr != want {
		t.Errorf("waitForI2PDAddress() = %q, want %q (hash of the Destination only, not the private key)", addr, want)
	}
}

// fakeKeysFileBytes builds a keys file shaped like the one i2pd persists: a
// 387-byte Destination (256-byte public key, 128-byte signing key, and an
// empty certificate) followed by private key material that must never
// contribute to the .b32.i2p address.
func fakeKeysFileBytes() []byte {
	data := make([]byte, 387+64)
	for i := range data {
		data[i] = byte(i % 251)
	}
	data[384] = 0
	data[385] = 0
	data[386] = 0
	return data
}

func TestWaitForI2PDAddress_TimesOutWhenKeyfileNeverAppears(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "never-written.dat")

	if _, err := waitForI2PDAddress(keysPath, 100*time.Millisecond); err == nil {
		t.Fatal("waitForI2PDAddress() error = nil, want timeout error")
	}
}

func TestLoadOrCreateSAMDestination_LoadsPersistedKeyWithoutTouchingConn(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site-keys.dat")
	if err := os.WriteFile(keysPath, []byte("persisted-priv-key\n"), 0o600); err != nil {
		t.Fatalf("seed keysPath: %v", err)
	}

	// nil conn/reader is safe here: the persisted-key branch returns before
	// ever touching either argument.
	dest, err := loadOrCreateSAMDestination(nil, nil, keysPath, 7)
	if err != nil {
		t.Fatalf("loadOrCreateSAMDestination() error = %v, want nil", err)
	}
	if dest.priv != "persisted-priv-key" {
		t.Errorf("dest.priv = %q, want %q", dest.priv, "persisted-priv-key")
	}
}

func TestLoadOrCreateSAMDestination_GeneratesAndPersistsWhenAbsent(t *testing.T) {
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site", "site-keys.dat")

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		r := bufio.NewReader(server)
		line, _ := r.ReadString('\n')
		if !strings.HasPrefix(line, "DEST GENERATE") {
			t.Errorf("server received %q, want DEST GENERATE request", line)
		}
		_, _ = server.Write([]byte("DEST REPLY PUB=abc123pub PRIV=xyz789priv\n"))
	}()

	r := bufio.NewReader(client)
	dest, err := loadOrCreateSAMDestination(client, r, keysPath, 7)
	if err != nil {
		t.Fatalf("loadOrCreateSAMDestination() error = %v, want nil", err)
	}
	if dest.priv != "xyz789priv" || string(dest.pub) != "abc123pub" {
		t.Errorf("dest = %+v, want priv=xyz789priv pub=abc123pub", dest)
	}
	persisted, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if string(persisted) != "xyz789priv" {
		t.Errorf("persisted key = %q, want %q", persisted, "xyz789priv")
	}
}

func TestStartSAMEepsite_FullMockProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	backendPort := backendLn.Addr().(*net.TCPAddr).Port
	backendLn.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)

		if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "HELLO VERSION") {
			t.Errorf("server: unexpected line %q, want HELLO VERSION", line)
			return
		}
		_, _ = conn.Write([]byte("HELLO REPLY RESULT=OK VERSION=3.3\n"))

		if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "DEST GENERATE") {
			t.Errorf("server: unexpected line %q, want DEST GENERATE", line)
			return
		}
		_, _ = conn.Write([]byte("DEST REPLY PUB=mockpubkey PRIV=mockprivkey\n"))

		if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "SESSION CREATE") {
			t.Errorf("server: unexpected line %q, want SESSION CREATE", line)
			return
		}
		_, _ = conn.Write([]byte("SESSION STATUS RESULT=OK\n"))

		if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "STREAM FORWARD") {
			t.Errorf("server: unexpected line %q, want STREAM FORWARD", line)
			return
		}
		_, _ = conn.Write([]byte("STREAM STATUS RESULT=OK\n"))
	}()

	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "site", "site-keys.dat")
	m := NewI2PManager(I2PServiceConfig{
		Enabled:          true,
		DataDir:          tmp,
		ConfigDir:        tmp,
		SAMAddress:       ln.Addr().String(),
		SignatureType:    7,
		InboundLength:    3,
		OutboundLength:   3,
		InboundQuantity:  5,
		OutboundQuantity: 5,
	})

	svc := &service{}
	addr, err := m.startSAMEepsite(ln.Addr().String(), keysPath, backendPort, svc)
	if err != nil {
		t.Fatalf("startSAMEepsite() error = %v, want nil", err)
	}
	wantAddr, werr := b32AddressFromBase64("mockpubkey")
	if werr != nil {
		t.Fatalf("b32AddressFromBase64() error = %v", werr)
	}
	if addr != wantAddr {
		t.Errorf("startSAMEepsite() = %q, want %q", addr, wantAddr)
	}
	if svc.samConn == nil {
		t.Error("svc.samConn = nil, want the live SAM control connection retained")
	}
	svc.samConn.Close()
}

// fakeI2PDScript writes a minimal shell script standing in for the real
// i2pd binary: it ignores its flags and simply writes a destination file
// at keysPath, so startI2PD's waitForI2PDAddress polling loop observes
// the file and returns.
func fakeI2PDScript(t *testing.T, keysPath string) string {
	t.Helper()
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "fake-i2pd.sh")
	sourcePath := filepath.Join(dir, "fake-keys.dat")
	if err := os.WriteFile(sourcePath, fakeKeysFileBytes(), 0o600); err != nil {
		t.Fatalf("write fake keys file: %v", err)
	}
	script := "#!/bin/sh\n" +
		"sleep 0.05\n" +
		"mkdir -p \"" + filepath.Dir(keysPath) + "\"\n" +
		"cp \"" + sourcePath + "\" \"" + keysPath + "\"\n" +
		"sleep 5\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake i2pd script: %v", err)
	}
	return scriptPath
}

func TestStartI2PD_SucceedsOnceProcessWritesKeyfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake i2pd script is a POSIX shell script")
	}
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "i2p", "site", "site-keys.dat")
	binary := fakeI2PDScript(t, keysPath)

	m := NewI2PManager(I2PServiceConfig{
		Enabled:          true,
		DataDir:          tmp,
		ConfigDir:        tmp,
		LogDir:           tmp,
		Binary:           binary,
		VirtualPort:      80,
		InboundLength:    3,
		OutboundLength:   3,
		InboundQuantity:  5,
		OutboundQuantity: 5,
		BootstrapTimeout: 5,
	})

	svc := &service{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addr, err := m.startI2PD(ctx, binary, keysPath, 12345, svc)
	if err != nil {
		t.Fatalf("startI2PD() error = %v, want nil", err)
	}
	wantAddr := b32Address(fakeKeysFileBytes()[:387])
	if addr != wantAddr {
		t.Errorf("startI2PD() = %q, want %q", addr, wantAddr)
	}
	if svc.i2pd == nil || svc.i2pd.Process == nil {
		t.Fatal("svc.i2pd process not recorded")
	}
	_ = svc.i2pd.Process.Signal(os.Interrupt)
	_ = svc.i2pd.Wait()
}

func TestStartI2PD_ReturnsErrorWhenProcessNeverWritesKeyfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake i2pd script is a POSIX shell script")
	}
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "i2p", "site", "site-keys.dat")

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "fake-i2pd-slow.sh")
	script := "#!/bin/sh\nsleep 5\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake i2pd script: %v", err)
	}

	m := NewI2PManager(I2PServiceConfig{
		Enabled:          true,
		DataDir:          tmp,
		ConfigDir:        tmp,
		LogDir:           tmp,
		Binary:           scriptPath,
		BootstrapTimeout: 1,
	})

	svc := &service{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	addr, err := m.startI2PD(ctx, scriptPath, keysPath, 12346, svc)
	if err == nil {
		if svc.i2pd != nil && svc.i2pd.Process != nil {
			_ = svc.i2pd.Process.Signal(os.Interrupt)
			_ = svc.i2pd.Wait()
		}
		t.Fatal("startI2PD() error = nil, want timeout error")
	}
	if addr != "" {
		t.Errorf("startI2PD() address = %q, want empty on timeout", addr)
	}
}

func TestResolveI2PDBinary_EmptyConfigScansCommonPathsAndPATH(t *testing.T) {
	m := NewI2PManager(I2PServiceConfig{})
	got := m.resolveI2PDBinary()
	if got != "" {
		if _, err := os.Stat(got); err != nil {
			t.Errorf("resolveI2PDBinary() = %q, but Stat failed: %v", got, err)
		}
	}
}

func TestStartDedicated_FullHappyPathWithI2PDProvider(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake i2pd script is a POSIX shell script")
	}
	tmp := t.TempDir()
	keysPath := filepath.Join(tmp, "i2p", "site", "site-keys.dat")
	binary := fakeI2PDScript(t, keysPath)

	m := NewI2PManager(I2PServiceConfig{
		Enabled:          true,
		DataDir:          tmp,
		ConfigDir:        tmp,
		LogDir:           tmp,
		Binary:           binary,
		VirtualPort:      80,
		InboundLength:    3,
		OutboundLength:   3,
		InboundQuantity:  5,
		OutboundQuantity: 5,
		BootstrapTimeout: 5,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc, err := m.startDedicated(ctx)
	if err != nil {
		t.Fatalf("startDedicated() error = %v, want nil", err)
	}
	defer func() {
		if svc.i2pd != nil && svc.i2pd.Process != nil {
			_ = svc.i2pd.Process.Signal(os.Interrupt)
			_ = svc.i2pd.Wait()
		}
		if svc.backendLn != nil {
			_ = svc.backendLn.Close()
		}
	}()

	if svc.provider != ProviderI2PD {
		t.Errorf("provider = %v, want ProviderI2PD", svc.provider)
	}
	if svc.i2pBackendPort <= 0 {
		t.Errorf("i2pBackendPort = %d, want > 0", svc.i2pBackendPort)
	}
	wantAddr := b32Address(fakeKeysFileBytes()[:387])
	if svc.eepsiteAddress != wantAddr {
		t.Errorf("eepsiteAddress = %q, want %q", svc.eepsiteAddress, wantAddr)
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
