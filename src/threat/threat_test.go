package threat

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates a file with the given content under dir.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestKindSetContains(t *testing.T) {
	ks := kindSet{}
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
	ks.nets = append(ks.nets, ipnet)
	ks.singles = append(ks.singles, net.ParseIP("192.168.1.1"))

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"192.168.1.1", true},
		{"172.16.0.1", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		got := ks.contains(ip)
		if got != c.want {
			t.Errorf("contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestLookupNil(t *testing.T) {
	l := &Lookup{}
	if l.IsTor(nil) {
		t.Error("IsTor(nil) should return false")
	}
	if l.IsVPN(nil) {
		t.Error("IsVPN(nil) should return false")
	}
	if l.IsProxy(nil) {
		t.Error("IsProxy(nil) should return false")
	}
}

func TestLoadDirAndLookup(t *testing.T) {
	dir := t.TempDir()

	// Write test lists.
	writeFile(t, dir, "tor.txt", "# comment\n1.2.3.4\n10.0.0.0/8\n")
	writeFile(t, dir, "vpn.txt", "; comment\n5.6.7.8\n172.16.0.0/12\n")
	writeFile(t, dir, "proxy.txt", "9.10.11.12\n192.168.0.0/16\n")

	sources := []Source{
		{Name: "tor", URL: "", File: "tor.txt", Kind: "tor"},
		{Name: "vpn", URL: "", File: "vpn.txt", Kind: "vpn"},
		{Name: "proxy", URL: "", File: "proxy.txt", Kind: "proxy"},
	}

	l := &Lookup{}
	if err := l.LoadDir(dir, sources); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	// Tor matches.
	if !l.IsTor(net.ParseIP("1.2.3.4")) {
		t.Error("IsTor(1.2.3.4) should be true")
	}
	if !l.IsTor(net.ParseIP("10.5.5.5")) {
		t.Error("IsTor(10.5.5.5) should be true — in 10.0.0.0/8")
	}
	if l.IsTor(net.ParseIP("8.8.8.8")) {
		t.Error("IsTor(8.8.8.8) should be false")
	}

	// VPN matches.
	if !l.IsVPN(net.ParseIP("5.6.7.8")) {
		t.Error("IsVPN(5.6.7.8) should be true")
	}
	if !l.IsVPN(net.ParseIP("172.17.0.1")) {
		t.Error("IsVPN(172.17.0.1) should be true — in 172.16.0.0/12")
	}
	if l.IsVPN(net.ParseIP("8.8.8.8")) {
		t.Error("IsVPN(8.8.8.8) should be false")
	}

	// Proxy matches.
	if !l.IsProxy(net.ParseIP("9.10.11.12")) {
		t.Error("IsProxy(9.10.11.12) should be true")
	}
	if !l.IsProxy(net.ParseIP("192.168.5.5")) {
		t.Error("IsProxy(192.168.5.5) should be true — in 192.168.0.0/16")
	}
	if l.IsProxy(net.ParseIP("8.8.8.8")) {
		t.Error("IsProxy(8.8.8.8) should be false")
	}
}

func TestLoadDirMissingFile(t *testing.T) {
	dir := t.TempDir()
	// vpn.txt exists, tor.txt does not — should not error.
	writeFile(t, dir, "vpn.txt", "5.6.7.8\n")
	sources := []Source{
		{Name: "tor", URL: "", File: "tor.txt", Kind: "tor"},
		{Name: "vpn", URL: "", File: "vpn.txt", Kind: "vpn"},
	}
	l := &Lookup{}
	if err := l.LoadDir(dir, sources); err != nil {
		t.Fatalf("LoadDir with missing file: %v", err)
	}
	if !l.IsVPN(net.ParseIP("5.6.7.8")) {
		t.Error("IsVPN should still work when tor.txt is absent")
	}
}

func TestLoadDirUnknownKind(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.txt", "1.2.3.4\n")
	sources := []Source{
		{Name: "bad", URL: "", File: "bad.txt", Kind: "unknown"},
	}
	l := &Lookup{}
	// Non-fatal: unknown kind logs and continues.
	_ = l.LoadDir(dir, sources)
}

func TestParseFileInlineCommentStrip(t *testing.T) {
	dir := t.TempDir()
	// Lines with trailing comments after whitespace.
	writeFile(t, dir, "tor.txt", "1.2.3.4 # tor exit\n10.0.0.0/8 some-label\n")
	sources := []Source{
		{Name: "tor", URL: "", File: "tor.txt", Kind: "tor"},
	}
	l := &Lookup{}
	if err := l.LoadDir(dir, sources); err != nil {
		t.Fatal(err)
	}
	if !l.IsTor(net.ParseIP("1.2.3.4")) {
		t.Error("IsTor(1.2.3.4) should be true after stripping inline comment")
	}
	if !l.IsTor(net.ParseIP("10.5.6.7")) {
		t.Error("IsTor(10.5.6.7) should be true after stripping label")
	}
}

func TestNewManager(t *testing.T) {
	dir := t.TempDir()

	// Empty sources → defaults.
	m := NewManager(dir, nil)
	if len(m.sources) != len(DefaultSources) {
		t.Errorf("NewManager(nil) sources len = %d, want %d", len(m.sources), len(DefaultSources))
	}

	// Custom sources passed through.
	custom := []Source{{Name: "test", URL: "", File: "t.txt", Kind: "tor"}}
	m2 := NewManager(dir, custom)
	if len(m2.sources) != 1 {
		t.Errorf("NewManager(custom) sources len = %d, want 1", len(m2.sources))
	}
}

func TestManagerInitializeNoDownload(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate files so Initialize does not attempt a download.
	writeFile(t, dir, "tor.txt", "1.2.3.4\n")
	sources := []Source{
		{Name: "tor", URL: "http://invalid.invalid/tor.txt", File: "tor.txt", Kind: "tor"},
	}

	m := NewManager(dir, sources)
	lk, err := m.Initialize()
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if !lk.IsTor(net.ParseIP("1.2.3.4")) {
		t.Error("IsTor(1.2.3.4) should be true after Initialize with pre-populated file")
	}
}

func TestManagerInitializeDownloadFail(t *testing.T) {
	dir := t.TempDir()
	// No pre-populated file, bad URL → download fails but Initialize returns a Lookup (empty).
	sources := []Source{
		{Name: "tor", URL: "http://invalid.invalid/tor.txt", File: "tor.txt", Kind: "tor"},
	}
	m := NewManager(dir, sources)
	// Should not panic; returns empty Lookup and no error (download failure is non-fatal).
	lk, _ := m.Initialize()
	if lk == nil {
		t.Error("Initialize should return a non-nil Lookup even when download fails")
	}
}

func TestManagerUpdateFromServer(t *testing.T) {
	// Serve a small IP list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# test\n2.3.4.5\n10.0.0.0/8\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	lk := &Lookup{}
	sources := []Source{
		{Name: "tor", URL: srv.URL, File: "tor.txt", Kind: "tor"},
	}
	m := NewManager(dir, sources)
	if err := m.Update(lk); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !lk.IsTor(net.ParseIP("2.3.4.5")) {
		t.Error("IsTor(2.3.4.5) should be true after Update")
	}
	// Verify .last_updated was written.
	if _, err := os.Stat(filepath.Join(dir, ".last_updated")); err != nil {
		t.Error("Update did not write .last_updated")
	}
}

func TestManagerUpdateHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	lk := &Lookup{}
	sources := []Source{
		{Name: "tor", URL: srv.URL, File: "tor.txt", Kind: "tor"},
	}
	m := NewManager(dir, sources)
	err := m.Update(lk)
	if err == nil {
		t.Error("Update should return error on HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should mention HTTP 500, got: %v", err)
	}
}

func TestDefaultSourcesCount(t *testing.T) {
	if len(DefaultSources) != 5 {
		t.Errorf("DefaultSources len = %d, want 5", len(DefaultSources))
	}
	for _, s := range DefaultSources {
		if s.Name == "" || s.URL == "" || s.File == "" || s.Kind == "" {
			t.Errorf("DefaultSource has empty field: %+v", s)
		}
	}
}
