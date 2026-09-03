package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/client/api"
)

// ---------------------------------------------------------------------------
// PlatformKey
// ---------------------------------------------------------------------------

func TestPlatformKey_Format(t *testing.T) {
	got := PlatformKey()
	// Must be "goos-goarch"
	if !strings.Contains(got, "-") {
		t.Errorf("PlatformKey() = %q, want format 'goos-goarch'", got)
	}
	parts := strings.SplitN(got, "-", 2)
	if parts[0] == "" || parts[1] == "" {
		t.Errorf("PlatformKey() = %q has empty component", got)
	}
}

func TestPlatformKey_MatchesRuntimeValues(t *testing.T) {
	got := PlatformKey()
	want := runtime.GOOS + "-" + runtime.GOARCH
	if got != want {
		t.Errorf("PlatformKey() = %q, want %q", got, want)
	}
}

func TestPlatformKey_Idempotent(t *testing.T) {
	a := PlatformKey()
	b := PlatformKey()
	if a != b {
		t.Errorf("PlatformKey() not idempotent: %q vs %q", a, b)
	}
}

// ---------------------------------------------------------------------------
// BinaryFilename
// ---------------------------------------------------------------------------

func TestBinaryFilename_ContainsProjectName(t *testing.T) {
	got := BinaryFilename("ipgaze")
	if !strings.HasPrefix(got, "ipgaze-cli-") {
		t.Errorf("BinaryFilename = %q, want prefix ipgaze-cli-", got)
	}
}

func TestBinaryFilename_ContainsOSAndArch(t *testing.T) {
	got := BinaryFilename("ipgaze")
	if !strings.Contains(got, runtime.GOOS) {
		t.Errorf("BinaryFilename = %q does not contain GOOS %q", got, runtime.GOOS)
	}
	if !strings.Contains(got, runtime.GOARCH) {
		t.Errorf("BinaryFilename = %q does not contain GOARCH %q", got, runtime.GOARCH)
	}
}

func TestBinaryFilename_WindowsHasExeSuffix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only test")
	}
	got := BinaryFilename("ipgaze")
	if !strings.HasSuffix(got, ".exe") {
		t.Errorf("BinaryFilename on Windows = %q, want .exe suffix", got)
	}
}

func TestBinaryFilename_NonWindowsNoExeSuffix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only test")
	}
	got := BinaryFilename("ipgaze")
	if strings.HasSuffix(got, ".exe") {
		t.Errorf("BinaryFilename on non-Windows = %q should not have .exe", got)
	}
}

// ---------------------------------------------------------------------------
// CheckResult.NeedsUpdate
// ---------------------------------------------------------------------------

func TestNeedsUpdate_WhenVersionsDiffer(t *testing.T) {
	r := &CheckResult{Current: "1.0.0", Available: "1.1.0"}
	if !r.NeedsUpdate() {
		t.Error("NeedsUpdate() = false when versions differ, want true")
	}
}

func TestNeedsUpdate_WhenVersionsSame(t *testing.T) {
	r := &CheckResult{Current: "1.1.0", Available: "1.1.0"}
	if r.NeedsUpdate() {
		t.Error("NeedsUpdate() = true when versions same, want false")
	}
}

func TestNeedsUpdate_WhenAvailableEmpty(t *testing.T) {
	r := &CheckResult{Current: "1.0.0", Available: ""}
	if r.NeedsUpdate() {
		t.Error("NeedsUpdate() = true when Available is empty, want false")
	}
}

func TestNeedsUpdate_WhenCurrentEmpty(t *testing.T) {
	// Edge: server has a version, client reports empty string
	r := &CheckResult{Current: "", Available: "1.0.0"}
	if !r.NeedsUpdate() {
		t.Error("NeedsUpdate() = false when Current='' and Available is set, want true")
	}
}

// ---------------------------------------------------------------------------
// isOlderVersion (internal)
// ---------------------------------------------------------------------------

func TestIsOlderVersion_OlderReturnsTrue(t *testing.T) {
	cases := []struct{ a, b string }{
		{"1.0.0", "1.0.1"},
		{"1.0.0", "1.1.0"},
		{"1.0.0", "2.0.0"},
		{"0.9.9", "1.0.0"},
	}
	for _, tc := range cases {
		if !isOlderVersion(tc.a, tc.b) {
			t.Errorf("isOlderVersion(%q, %q) = false, want true", tc.a, tc.b)
		}
	}
}

func TestIsOlderVersion_SameReturnsFalse(t *testing.T) {
	if isOlderVersion("1.2.3", "1.2.3") {
		t.Error("isOlderVersion(same) = true, want false")
	}
}

func TestIsOlderVersion_NewerReturnsFalse(t *testing.T) {
	cases := []struct{ a, b string }{
		{"1.0.1", "1.0.0"},
		{"2.0.0", "1.9.9"},
		{"1.1.0", "1.0.9"},
	}
	for _, tc := range cases {
		if isOlderVersion(tc.a, tc.b) {
			t.Errorf("isOlderVersion(%q, %q) = true, want false (a is newer)", tc.a, tc.b)
		}
	}
}

func TestIsOlderVersion_EmptyStrings(t *testing.T) {
	// both empty — not older
	if isOlderVersion("", "") {
		t.Error("isOlderVersion('', '') = true, want false")
	}
}

// ---------------------------------------------------------------------------
// verifyChecksum (internal)
// ---------------------------------------------------------------------------

func writeFileWithContent(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
	return path
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestVerifyChecksum_Valid(t *testing.T) {
	content := []byte("fake binary bytes for checksum test")
	path := writeFileWithContent(t, t.TempDir(), "bin.tmp", content)
	expected := sha256Hex(content)

	if err := verifyChecksum(path, expected); err != nil {
		t.Errorf("verifyChecksum with correct hash: %v", err)
	}
}

func TestVerifyChecksum_WrongHash(t *testing.T) {
	content := []byte("real binary content")
	path := writeFileWithContent(t, t.TempDir(), "bin.tmp", content)

	err := verifyChecksum(path, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error from wrong checksum, got nil")
	}
	if !strings.Contains(err.Error(), "want") {
		t.Errorf("error %q should describe the expected hash", err.Error())
	}
}

func TestVerifyChecksum_MissingFile(t *testing.T) {
	err := verifyChecksum(filepath.Join(t.TempDir(), "nonexistent.bin"), "abc")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestVerifyChecksum_EmptyFile(t *testing.T) {
	path := writeFileWithContent(t, t.TempDir(), "empty.bin", []byte{})
	expected := sha256Hex([]byte{})

	if err := verifyChecksum(path, expected); err != nil {
		t.Errorf("verifyChecksum on empty file with correct hash: %v", err)
	}
}

func TestVerifyChecksum_UppercaseHashRejected(t *testing.T) {
	// sha256Hex returns lowercase; uppercase must not match.
	content := []byte("data")
	path := writeFileWithContent(t, t.TempDir(), "bin.tmp", content)
	lower := sha256Hex(content)
	upper := strings.ToUpper(lower)

	err := verifyChecksum(path, upper)
	if err == nil {
		t.Error("verifyChecksum accepted uppercase hex when function uses lowercase, want mismatch error")
	}
}

// ---------------------------------------------------------------------------
// checkWritable (internal)
// ---------------------------------------------------------------------------

func TestCheckWritable_WritableFile(t *testing.T) {
	path := writeFileWithContent(t, t.TempDir(), "writable.bin", []byte("hello"))
	if err := checkWritable(path); err != nil {
		t.Errorf("checkWritable on writable file: %v", err)
	}
}

func TestCheckWritable_ReadOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-only semantics differ on Windows")
	}
	path := writeFileWithContent(t, t.TempDir(), "readonly.bin", []byte("hello"))
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root; read-only file is still writable")
	}
	err := checkWritable(path)
	if err == nil {
		t.Error("expected error for read-only file, got nil")
	}
}

func TestCheckWritable_MissingFile(t *testing.T) {
	err := checkWritable(filepath.Join(t.TempDir(), "no-such-file"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// ---------------------------------------------------------------------------
// CheckForUpdates — uses httptest.NewServer via api.NewAPIClient
// ---------------------------------------------------------------------------

func autodiscoverServer(t *testing.T, payload interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/autodiscover" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	}))
	return srv
}

func TestCheckForUpdates_NeedsUpdate(t *testing.T) {
	platform := PlatformKey()
	payload := map[string]interface{}{
		"server_name": "ipgaze",
		"version":     "1.2.0",
		"api_version": "v1",
		"base_url":    "https://ifcfg.us",
		"cli_versions": map[string]interface{}{
			platform: map[string]string{
				"version": "1.2.0",
				"sha256":  "deadbeef",
			},
		},
		"cli_min_version": "1.0.0",
	}
	srv := autodiscoverServer(t, payload)
	defer srv.Close()

	c := api.NewAPIClient(srv.URL, "", "test/1", "")
	result, err := CheckForUpdates(context.Background(), c, "1.0.0")
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if result.Current != "1.0.0" {
		t.Errorf("Current = %q, want 1.0.0", result.Current)
	}
	if result.Available != "1.2.0" {
		t.Errorf("Available = %q, want 1.2.0", result.Available)
	}
	if result.SHA256 != "deadbeef" {
		t.Errorf("SHA256 = %q, want deadbeef", result.SHA256)
	}
	if !result.NeedsUpdate() {
		t.Error("NeedsUpdate() = false, want true")
	}
}

func TestCheckForUpdates_AlreadyUpToDate(t *testing.T) {
	platform := PlatformKey()
	payload := map[string]interface{}{
		"server_name": "ipgaze",
		"version":     "1.0.0",
		"cli_versions": map[string]interface{}{
			platform: map[string]string{"version": "1.0.0", "sha256": "aabbcc"},
		},
		"cli_min_version": "",
	}
	srv := autodiscoverServer(t, payload)
	defer srv.Close()

	c := api.NewAPIClient(srv.URL, "", "", "")
	result, err := CheckForUpdates(context.Background(), c, "1.0.0")
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if result.NeedsUpdate() {
		t.Error("NeedsUpdate() = true, want false (already current)")
	}
}

func TestCheckForUpdates_PlatformMissing(t *testing.T) {
	// Server has no entry for this platform — Available must be empty.
	payload := map[string]interface{}{
		"server_name":     "ipgaze",
		"version":         "1.5.0",
		"cli_versions":    map[string]interface{}{},
		"cli_min_version": "",
	}
	srv := autodiscoverServer(t, payload)
	defer srv.Close()

	c := api.NewAPIClient(srv.URL, "", "", "")
	result, err := CheckForUpdates(context.Background(), c, "1.0.0")
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if result.Available != "" {
		t.Errorf("Available = %q, want empty when platform not in cli_versions", result.Available)
	}
	if result.NeedsUpdate() {
		t.Error("NeedsUpdate() = true when platform not listed, want false")
	}
}

func TestCheckForUpdates_BelowMinVersion(t *testing.T) {
	platform := PlatformKey()
	payload := map[string]interface{}{
		"server_name": "ipgaze",
		"version":     "2.0.0",
		"cli_versions": map[string]interface{}{
			platform: map[string]string{"version": "2.0.0", "sha256": "cc"},
		},
		"cli_min_version": "1.5.0",
	}
	srv := autodiscoverServer(t, payload)
	defer srv.Close()

	c := api.NewAPIClient(srv.URL, "", "", "")
	result, err := CheckForUpdates(context.Background(), c, "1.2.0")
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if !result.BelowMin {
		t.Error("BelowMin = false, want true for version below cli_min_version")
	}
	if result.MinVersion != "1.5.0" {
		t.Errorf("MinVersion = %q, want 1.5.0", result.MinVersion)
	}
}

func TestCheckForUpdates_AutodiscoverError(t *testing.T) {
	// Server returns non-200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	c := api.NewAPIClient(srv.URL, "", "", "")
	_, err := CheckForUpdates(context.Background(), c, "1.0.0")
	if err == nil {
		t.Fatal("expected error from autodiscover failure, got nil")
	}
}

func TestCheckForUpdates_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := api.NewAPIClient(srv.URL, "", "", "")
	_, err := CheckForUpdates(ctx, c, "1.0.0")
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

// ---------------------------------------------------------------------------
// Do — happy path: up-to-date exits early
// ---------------------------------------------------------------------------

func TestDo_AlreadyUpToDate_NoDownload(t *testing.T) {
	platform := PlatformKey()
	payload := map[string]interface{}{
		"server_name": "ipgaze",
		"version":     "1.0.0",
		"cli_versions": map[string]interface{}{
			platform: map[string]string{"version": "1.0.0", "sha256": ""},
		},
		"cli_min_version": "",
	}

	downloadCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/autodiscover" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(payload)
			return
		}
		// Any call to /cli/binaries/ is unexpected.
		downloadCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := api.NewAPIClient(srv.URL, "", "", "")
	err := Do(context.Background(), c, "ipgaze", srv.URL, "1.0.0")
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if downloadCalled {
		t.Error("Do called download path even though already up to date")
	}
}

// ---------------------------------------------------------------------------
// Do — checksum mismatch causes early abort with no replacement
// ---------------------------------------------------------------------------

func TestDo_ChecksumMismatch_Aborts(t *testing.T) {
	platform := PlatformKey()
	binaryContent := []byte("fake binary v1.1.0")
	correctHash := sha256Hex(binaryContent)
	wrongHash := strings.Repeat("a", 64)
	if wrongHash == correctHash {
		wrongHash = strings.Repeat("b", 64)
	}
	filename := fmt.Sprintf("ipgaze-cli-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}

	payload := map[string]interface{}{
		"server_name": "ipgaze",
		"version":     "1.1.0",
		"cli_versions": map[string]interface{}{
			platform: map[string]string{"version": "1.1.0", "sha256": wrongHash},
		},
		"cli_min_version": "",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/autodiscover":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(payload)
		case "/cli/binaries/" + filename:
			w.Write(binaryContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := api.NewAPIClient(srv.URL, "", "", "")
	err := Do(context.Background(), c, "ipgaze", srv.URL, "1.0.0")
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("error %q does not mention 'checksum'", err.Error())
	}
}
