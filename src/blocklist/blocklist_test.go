package blocklist

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// NewBlocklistManager
// ---------------------------------------------------------------------------

func TestNewBlocklistManager_DefaultSources(t *testing.T) {
	m := NewBlocklistManager("/tmp/testbl", nil)
	if len(m.sources) != len(DefaultSources) {
		t.Errorf("sources len = %d, want %d (defaults)", len(m.sources), len(DefaultSources))
	}
}

func TestNewBlocklistManager_CustomSources(t *testing.T) {
	custom := []Source{{Name: "test", URL: "http://example.com", File: "test.txt"}}
	m := NewBlocklistManager("/tmp/testbl", custom)
	if len(m.sources) != 1 || m.sources[0].Name != "test" {
		t.Errorf("sources = %+v, want custom source", m.sources)
	}
}

func TestNewBlocklistManager_EmptySources_FallsBackToDefaults(t *testing.T) {
	m := NewBlocklistManager("/tmp/testbl", []Source{})
	if len(m.sources) != len(DefaultSources) {
		t.Errorf("empty sources should fall back to defaults; got %d, want %d",
			len(m.sources), len(DefaultSources))
	}
}

// ---------------------------------------------------------------------------
// Lookup.LoadDir — file parsing and Contains
// ---------------------------------------------------------------------------

// writeTxt writes a blocklist .txt file to dir.
func writeTxt(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writeTxt(%q): %v", name, err)
	}
}

func TestLookup_LoadDir_EmptyDir_NoError(t *testing.T) {
	var l Lookup
	dir := t.TempDir()
	if err := l.LoadDir(dir); err != nil {
		t.Errorf("LoadDir on empty dir: %v", err)
	}
}

func TestLookup_LoadDir_NonExistentDir_NoError(t *testing.T) {
	var l Lookup
	if err := l.LoadDir("/tmp/this-dir-does-not-exist-ipgaze-test"); err != nil {
		t.Errorf("LoadDir on non-existent dir: %v", err)
	}
}

func TestLookup_Contains_SingleIP(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "ips.txt", "1.2.3.4\n192.168.0.1\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},
		{"192.168.0.1", true},
		{"1.2.3.5", false},
		{"10.0.0.1", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := l.Contains(ip); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestLookup_Contains_CIDR(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "nets.txt", "10.0.0.0/8\n172.16.0.0/12\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.0.0.0", true},
		{"10.255.255.255", true},
		{"172.20.0.1", true},
		{"192.168.0.1", false},
		{"11.0.0.1", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := l.Contains(ip); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// Comments and blank lines must be skipped.
func TestLookup_LoadDir_SkipsCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "mix.txt",
		"# this is a comment\n"+
			"; also a comment\n"+
			"\n"+
			"5.5.5.5\n"+
			"  \n"+
			"# another comment\n"+
			"6.6.6.6\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	for _, ip := range []string{"5.5.5.5", "6.6.6.6"} {
		if !l.Contains(net.ParseIP(ip)) {
			t.Errorf("Contains(%q) = false, want true (comment/blank skipping broken)", ip)
		}
	}
}

// Inline comments after an IP/CIDR must be stripped.
func TestLookup_LoadDir_StripsInlineComments(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "inline.txt", "7.7.7.7 # some note\n8.8.0.0/16 ; another note\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	if !l.Contains(net.ParseIP("7.7.7.7")) {
		t.Error("Contains(7.7.7.7) = false after stripping inline comment")
	}
	if !l.Contains(net.ParseIP("8.8.1.2")) {
		t.Error("Contains(8.8.1.2) = false after stripping inline comment from CIDR")
	}
}

// Non-.txt files in the directory must be ignored.
func TestLookup_LoadDir_IgnoresNonTxtFiles(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "bad.csv", "9.9.9.9\n")
	if err := os.WriteFile(filepath.Join(dir, "info.json"), []byte(`{"ip":"9.9.9.9"}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	if l.Contains(net.ParseIP("9.9.9.9")) {
		t.Error("Contains(9.9.9.9) = true, but non-.txt file should be ignored")
	}
}

// Multiple .txt files must all be loaded.
func TestLookup_LoadDir_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "a.txt", "11.0.0.1\n")
	writeTxt(t, dir, "b.txt", "11.0.0.2\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	for _, ip := range []string{"11.0.0.1", "11.0.0.2"} {
		if !l.Contains(net.ParseIP(ip)) {
			t.Errorf("Contains(%q) = false, want true", ip)
		}
	}
}

// LoadDir called a second time should replace (not accumulate) the previous data.
func TestLookup_LoadDir_Replaces_PreviousData(t *testing.T) {
	dir1 := t.TempDir()
	writeTxt(t, dir1, "a.txt", "20.0.0.1\n")

	dir2 := t.TempDir()
	writeTxt(t, dir2, "b.txt", "20.0.0.2\n")

	var l Lookup
	if err := l.LoadDir(dir1); err != nil {
		t.Fatalf("first LoadDir: %v", err)
	}
	if err := l.LoadDir(dir2); err != nil {
		t.Fatalf("second LoadDir: %v", err)
	}

	if l.Contains(net.ParseIP("20.0.0.1")) {
		t.Error("Contains(20.0.0.1) = true after reload: old data should be gone")
	}
	if !l.Contains(net.ParseIP("20.0.0.2")) {
		t.Error("Contains(20.0.0.2) = false: new data not loaded")
	}
}

// ---------------------------------------------------------------------------
// Lookup.Contains — edge cases
// ---------------------------------------------------------------------------

func TestLookup_Contains_NilIP(t *testing.T) {
	var l Lookup
	if l.Contains(nil) {
		t.Error("Contains(nil) = true, want false")
	}
}

func TestLookup_Contains_EmptyLookup(t *testing.T) {
	var l Lookup
	ip := net.ParseIP("1.2.3.4")
	if l.Contains(ip) {
		t.Error("Contains on zero-value Lookup returned true")
	}
}

func TestLookup_Contains_IPv6SingleIP(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "v6.txt", "2001:db8::1\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	if !l.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("Contains(2001:db8::1) = false, want true")
	}
	if l.Contains(net.ParseIP("2001:db8::2")) {
		t.Error("Contains(2001:db8::2) = true, want false")
	}
}

func TestLookup_Contains_IPv6CIDR(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "v6net.txt", "2001:db8::/32\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	if !l.Contains(net.ParseIP("2001:db8::ffff")) {
		t.Error("Contains(2001:db8::ffff) = false for IP in covered CIDR")
	}
	if l.Contains(net.ParseIP("2001:db9::1")) {
		t.Error("Contains(2001:db9::1) = true for IP outside CIDR")
	}
}

// Malformed lines (invalid IPs/CIDRs) must be silently ignored.
func TestLookup_LoadDir_IgnoresMalformedLines(t *testing.T) {
	dir := t.TempDir()
	writeTxt(t, dir, "bad.txt",
		"not-an-ip\n"+
			"300.0.0.1\n"+
			"1.2.3.4/99\n"+
			"99.99.99.99\n")

	var l Lookup
	if err := l.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir with malformed lines: %v", err)
	}

	// Only the valid IP should match.
	if !l.Contains(net.ParseIP("99.99.99.99")) {
		t.Error("Contains(99.99.99.99) = false; valid IP in file should be loaded")
	}
}

// ---------------------------------------------------------------------------
// BlocklistManager.Update — success path using httptest
// ---------------------------------------------------------------------------

func TestUpdate_DownloadsAllSources(t *testing.T) {
	dir := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("1.2.3.4\n10.0.0.0/8\n")) //nolint:errcheck
	}))
	defer srv.Close()

	sources := []Source{
		{Name: "src1", URL: srv.URL, File: "src1.txt"},
		{Name: "src2", URL: srv.URL, File: "src2.txt"},
	}
	m := NewBlocklistManager(dir, sources)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	for _, src := range sources {
		p := filepath.Join(dir, src.File)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file %q not found after Update: %v", p, err)
		}
	}
}

func TestUpdate_WritesTimestampFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("1.1.1.1\n")) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	sources := []Source{{Name: "s", URL: srv.URL, File: "s.txt"}}
	m := NewBlocklistManager(dir, sources)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	ts, err := os.ReadFile(filepath.Join(dir, ".last_updated"))
	if err != nil {
		t.Fatalf(".last_updated not written: %v", err)
	}
	if strings.TrimSpace(string(ts)) == "" {
		t.Error(".last_updated is empty")
	}
}

func TestUpdate_CreatesDirIfMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("2.2.2.2\n")) //nolint:errcheck
	}))
	defer srv.Close()

	base := t.TempDir()
	dir := filepath.Join(base, "nested", "blocklists")
	sources := []Source{{Name: "s", URL: srv.URL, File: "s.txt"}}
	m := NewBlocklistManager(dir, sources)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("dataDir was not created: %v", err)
	}
}

// Update must return the last error but continue downloading remaining sources.
func TestUpdate_PartialFailure_ReturnsLastError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "fail") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("3.3.3.3\n")) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	sources := []Source{
		{Name: "ok", URL: srv.URL + "/ok", File: "ok.txt"},
		{Name: "fail", URL: srv.URL + "/fail", File: "fail.txt"},
	}
	m := NewBlocklistManager(dir, sources)

	err := m.Update()
	if err == nil {
		t.Error("Update() with one failing source: expected error, got nil")
	}

	// The successful source must still be downloaded.
	if _, statErr := os.Stat(filepath.Join(dir, "ok.txt")); statErr != nil {
		t.Error("ok.txt not downloaded despite partial failure")
	}
}

// ---------------------------------------------------------------------------
// DefaultSources — basic sanity
// ---------------------------------------------------------------------------

func TestDefaultSources_NotEmpty(t *testing.T) {
	if len(DefaultSources) == 0 {
		t.Error("DefaultSources is empty")
	}
}

func TestDefaultSources_FieldsNonEmpty(t *testing.T) {
	for _, src := range DefaultSources {
		if src.Name == "" {
			t.Errorf("DefaultSources entry has empty Name: %+v", src)
		}
		if src.URL == "" {
			t.Errorf("DefaultSources[%q] has empty URL", src.Name)
		}
		if src.File == "" {
			t.Errorf("DefaultSources[%q] has empty File", src.Name)
		}
		if !strings.HasSuffix(src.File, ".txt") {
			t.Errorf("DefaultSources[%q].File = %q, want *.txt suffix", src.Name, src.File)
		}
	}
}
