package path

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withEnv temporarily sets environment variables for the duration of the test.
// It restores both set and previously-unset variables via t.Cleanup.
func withEnv(t *testing.T, kvs map[string]string) {
	t.Helper()
	saved := make(map[string]string, len(kvs))
	for k, v := range kvs {
		old, exists := os.LookupEnv(k)
		if exists {
			saved[k] = old
		} else {
			saved[k] = "\x00" // sentinel: "was not set"
		}
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for k, old := range saved {
			if old == "\x00" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, old)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// ConfigDir — Linux/default (XDG_CONFIG_HOME)
// ---------------------------------------------------------------------------

func TestConfigDir_XDGSet(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG test only runs on Linux/BSD")
	}
	tmp := t.TempDir()
	withEnv(t, map[string]string{"XDG_CONFIG_HOME": tmp})

	got := ConfigDir()
	want := filepath.Join(tmp, "apimgr", "ipgaze")
	if got != want {
		t.Errorf("ConfigDir() = %q, want %q", got, want)
	}
}

func TestConfigDir_XDGUnset_FallsBackToHome(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG fallback test only runs on Linux/BSD")
	}
	withEnv(t, map[string]string{"XDG_CONFIG_HOME": ""})

	home, _ := os.UserHomeDir()
	got := ConfigDir()
	want := filepath.Join(home, ".config", "apimgr", "ipgaze")
	if got != want {
		t.Errorf("ConfigDir() = %q, want %q", got, want)
	}
}

func TestConfigDir_ContainsProjectName(t *testing.T) {
	got := ConfigDir()
	if !strings.Contains(got, "ipgaze") {
		t.Errorf("ConfigDir() = %q does not contain 'ipgaze'", got)
	}
	if !strings.Contains(got, "apimgr") {
		t.Errorf("ConfigDir() = %q does not contain 'apimgr'", got)
	}
}

func TestConfigDir_IsAbsolute(t *testing.T) {
	got := ConfigDir()
	if !filepath.IsAbs(got) {
		t.Errorf("ConfigDir() = %q is not absolute", got)
	}
}

// ---------------------------------------------------------------------------
// DataDir
// ---------------------------------------------------------------------------

func TestDataDir_XDGSet(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG test only runs on Linux/BSD")
	}
	tmp := t.TempDir()
	withEnv(t, map[string]string{"XDG_DATA_HOME": tmp})

	got := DataDir()
	want := filepath.Join(tmp, "apimgr", "ipgaze")
	if got != want {
		t.Errorf("DataDir() = %q, want %q", got, want)
	}
}

func TestDataDir_XDGUnset_FallsBackToHome(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG fallback test only runs on Linux/BSD")
	}
	withEnv(t, map[string]string{"XDG_DATA_HOME": ""})

	home, _ := os.UserHomeDir()
	got := DataDir()
	want := filepath.Join(home, ".local", "share", "apimgr", "ipgaze")
	if got != want {
		t.Errorf("DataDir() = %q, want %q", got, want)
	}
}

func TestDataDir_ContainsProjectName(t *testing.T) {
	got := DataDir()
	if !strings.Contains(got, "ipgaze") {
		t.Errorf("DataDir() = %q does not contain 'ipgaze'", got)
	}
}

func TestDataDir_IsAbsolute(t *testing.T) {
	got := DataDir()
	if !filepath.IsAbs(got) {
		t.Errorf("DataDir() = %q is not absolute", got)
	}
}

// AI.md PART 32's client table groups Linux and macOS together, so darwin uses
// the same XDG-style layout and must NOT use ~/Library/Application Support.
func TestDataDir_MacOS_UsesXDGLayout(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only test")
	}
	got := DataDir()
	if strings.Contains(got, "Application Support") {
		t.Errorf("DataDir() on macOS = %q, want the ~/.local/share layout", got)
	}
	if !strings.HasSuffix(got, filepath.Join("apimgr", "ipgaze")) {
		t.Errorf("DataDir() on macOS = %q, want suffix apimgr/ipgaze", got)
	}
}

// Windows DataDir must carry the explicit data sub-directory.
func TestDataDir_WindowsHasDataSuffix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only test")
	}
	got := DataDir()
	if !strings.HasSuffix(got, "data") {
		t.Errorf("DataDir() on Windows = %q, want suffix 'data'", got)
	}
}

// ---------------------------------------------------------------------------
// CacheDir
// ---------------------------------------------------------------------------

func TestCacheDir_XDGSet(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG test only runs on Linux/BSD")
	}
	tmp := t.TempDir()
	withEnv(t, map[string]string{"XDG_CACHE_HOME": tmp})

	got := CacheDir()
	want := filepath.Join(tmp, "apimgr", "ipgaze")
	if got != want {
		t.Errorf("CacheDir() = %q, want %q", got, want)
	}
}

func TestCacheDir_XDGUnset_FallsBackToHome(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG fallback test only runs on Linux/BSD")
	}
	withEnv(t, map[string]string{"XDG_CACHE_HOME": ""})

	home, _ := os.UserHomeDir()
	got := CacheDir()
	want := filepath.Join(home, ".cache", "apimgr", "ipgaze")
	if got != want {
		t.Errorf("CacheDir() = %q, want %q", got, want)
	}
}

func TestCacheDir_ContainsProjectName(t *testing.T) {
	got := CacheDir()
	if !strings.Contains(got, "ipgaze") {
		t.Errorf("CacheDir() = %q does not contain 'ipgaze'", got)
	}
}

func TestCacheDir_IsAbsolute(t *testing.T) {
	got := CacheDir()
	if !filepath.IsAbs(got) {
		t.Errorf("CacheDir() = %q is not absolute", got)
	}
}

func TestCacheDir_WindowsHasCacheSuffix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only test")
	}
	got := CacheDir()
	if !strings.HasSuffix(got, "cache") {
		t.Errorf("CacheDir() on Windows = %q, want suffix 'cache'", got)
	}
}

// ---------------------------------------------------------------------------
// LogDir
// ---------------------------------------------------------------------------

func TestLogDir_UsesHomeLocalLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("home-relative log path test does not apply to Windows")
	}
	home, _ := os.UserHomeDir()
	got := LogDir()
	want := filepath.Join(home, ".local", "log", "apimgr", "ipgaze")
	if got != want {
		t.Errorf("LogDir() = %q, want %q", got, want)
	}
}

// There is no XDG variable for logs, so XDG_STATE_HOME must not affect LogDir.
func TestLogDir_IgnoresXDGStateHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("home-relative log path test does not apply to Windows")
	}
	withEnv(t, map[string]string{"XDG_STATE_HOME": t.TempDir()})

	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".local", "log", "apimgr", "ipgaze")
	if got := LogDir(); got != want {
		t.Errorf("LogDir() = %q, want %q", got, want)
	}
}

func TestLogDir_ContainsProjectName(t *testing.T) {
	got := LogDir()
	if !strings.Contains(got, "ipgaze") {
		t.Errorf("LogDir() = %q does not contain 'ipgaze'", got)
	}
}

func TestLogDir_IsAbsolute(t *testing.T) {
	got := LogDir()
	if !filepath.IsAbs(got) {
		t.Errorf("LogDir() = %q is not absolute", got)
	}
}

// Windows logs live in a singular "log" directory under %LOCALAPPDATA%.
func TestLogDir_WindowsUsesSingularLog(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only test")
	}
	got := LogDir()
	if !strings.HasSuffix(got, "log") || strings.HasSuffix(got, "logs") {
		t.Errorf("LogDir() on Windows = %q, want suffix 'log'", got)
	}
}

// ---------------------------------------------------------------------------
// ConfigFile
// ---------------------------------------------------------------------------

func TestConfigFile_EndsWithCliYml(t *testing.T) {
	got := ConfigFile()
	if !strings.HasSuffix(got, "cli.yml") {
		t.Errorf("ConfigFile() = %q, want suffix cli.yml", got)
	}
}

func TestConfigFile_IsUnderConfigDir(t *testing.T) {
	dir := ConfigDir()
	file := ConfigFile()
	if !strings.HasPrefix(file, dir) {
		t.Errorf("ConfigFile() = %q is not under ConfigDir() = %q", file, dir)
	}
}

func TestConfigFile_IsAbsolute(t *testing.T) {
	got := ConfigFile()
	if !filepath.IsAbs(got) {
		t.Errorf("ConfigFile() = %q is not absolute", got)
	}
}

// ---------------------------------------------------------------------------
// LogFile
// ---------------------------------------------------------------------------

func TestLogFile_EndsWithLogFilename(t *testing.T) {
	got := LogFile()
	if !strings.HasSuffix(got, "cli.log") {
		t.Errorf("LogFile() = %q, want suffix cli.log", got)
	}
}

func TestLogFile_IsUnderLogDir(t *testing.T) {
	dir := LogDir()
	file := LogFile()
	if !strings.HasPrefix(file, dir) {
		t.Errorf("LogFile() = %q is not under LogDir() = %q", file, dir)
	}
}

func TestLogFile_IsAbsolute(t *testing.T) {
	got := LogFile()
	if !filepath.IsAbs(got) {
		t.Errorf("LogFile() = %q is not absolute", got)
	}
}

// ---------------------------------------------------------------------------
// Path separation — ensure all paths use the OS separator (no mixing)
// ---------------------------------------------------------------------------

func TestAllPaths_UseOSSeparator(t *testing.T) {
	paths := map[string]string{
		"ConfigDir":  ConfigDir(),
		"DataDir":    DataDir(),
		"CacheDir":   CacheDir(),
		"LogDir":     LogDir(),
		"ConfigFile": ConfigFile(),
		"LogFile":    LogFile(),
	}
	wrong := "/"
	if runtime.GOOS == "windows" {
		wrong = "\\"
	}
	if runtime.GOOS == "windows" {
		for name, p := range paths {
			if strings.Contains(p, wrong) {
				t.Errorf("%s = %q contains forward slash on Windows", name, p)
			}
		}
	} else {
		// On Unix forward slash is correct; just ensure no backslash leaks in.
		for name, p := range paths {
			if strings.Contains(p, "\\") {
				t.Errorf("%s = %q contains backslash on Unix", name, p)
			}
			_ = wrong
		}
	}
}

// ---------------------------------------------------------------------------
// Idempotency — calling each function twice must return the same result
// ---------------------------------------------------------------------------

func TestPaths_Idempotent(t *testing.T) {
	cases := []struct {
		name string
		fn   func() string
	}{
		{"ConfigDir", ConfigDir},
		{"DataDir", DataDir},
		{"CacheDir", CacheDir},
		{"LogDir", LogDir},
		{"ConfigFile", ConfigFile},
		{"LogFile", LogFile},
	}
	for _, tc := range cases {
		a := tc.fn()
		b := tc.fn()
		if a != b {
			t.Errorf("%s(): first=%q second=%q (not idempotent)", tc.name, a, b)
		}
	}
}

// ---------------------------------------------------------------------------
// Platform branching — on this OS, ensure the right base is embedded
// ---------------------------------------------------------------------------

func TestConfigDir_Platform(t *testing.T) {
	got := ConfigDir()
	switch runtime.GOOS {
	case "windows":
		// On Windows APPDATA must be embedded; in the test environment it may
		// be empty so only check that the suffix is correct.
		if !strings.HasSuffix(got, filepath.Join("apimgr", "ipgaze")) {
			t.Errorf("ConfigDir() on Windows = %q, want suffix apimgr\\ipgaze", got)
		}
	default:
		// Linux / BSD: must use .config or XDG_CONFIG_HOME
		if !strings.Contains(got, ".config") && os.Getenv("XDG_CONFIG_HOME") == "" {
			// XDG_CONFIG_HOME was not set so we expect the ~/.config fallback
			t.Errorf("ConfigDir() on Linux = %q, want .config fallback", got)
		}
	}
}

// ---------------------------------------------------------------------------
// ResolveConfigPath / ResolveYamlExtension — the --config flag resolution table
// ---------------------------------------------------------------------------

func TestResolveConfigPath_Unspecified(t *testing.T) {
	got, err := ResolveConfigPath("")
	if err != nil {
		t.Fatalf("ResolveConfigPath(\"\"): %v", err)
	}
	if got != ConfigFile() {
		t.Errorf("ResolveConfigPath(\"\") = %q, want %q", got, ConfigFile())
	}
}

func TestResolveConfigPath_BareName(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG test only runs on Linux/BSD")
	}
	tmp := t.TempDir()
	withEnv(t, map[string]string{"XDG_CONFIG_HOME": tmp})

	got, err := ResolveConfigPath("test")
	if err != nil {
		t.Fatalf("ResolveConfigPath: %v", err)
	}
	want := filepath.Join(tmp, "apimgr", "ipgaze", "test.yml")
	if got != want {
		t.Errorf("ResolveConfigPath(test) = %q, want %q", got, want)
	}
}

func TestResolveConfigPath_NameWithExtension(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG test only runs on Linux/BSD")
	}
	tmp := t.TempDir()
	withEnv(t, map[string]string{"XDG_CONFIG_HOME": tmp})

	got, err := ResolveConfigPath("dev.yml")
	if err != nil {
		t.Fatalf("ResolveConfigPath: %v", err)
	}
	want := filepath.Join(tmp, "apimgr", "ipgaze", "dev.yml")
	if got != want {
		t.Errorf("ResolveConfigPath(dev.yml) = %q, want %q", got, want)
	}
}

func TestResolveConfigPath_AbsolutePathKept(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX absolute path test")
	}
	got, err := ResolveConfigPath("/etc/app/prod.yml")
	if err != nil {
		t.Fatalf("ResolveConfigPath: %v", err)
	}
	if got != "/etc/app/prod.yml" {
		t.Errorf("ResolveConfigPath(/etc/app/prod.yml) = %q, want it unchanged", got)
	}
}

func TestResolveConfigPath_TildeExpanded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tilde expansion test does not apply to Windows")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	got, err := ResolveConfigPath("~/testing/app.yml")
	if err != nil {
		t.Fatalf("ResolveConfigPath: %v", err)
	}
	want := filepath.Join(home, "testing", "app.yml")
	if got != want {
		t.Errorf("ResolveConfigPath(~/testing/app.yml) = %q, want %q", got, want)
	}
}

func TestResolveYamlExtension_PrefersExistingYaml(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "profile")
	if err := os.WriteFile(base+".yaml", []byte("debug: no\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := ResolveYamlExtension(base); got != base+".yaml" {
		t.Errorf("ResolveYamlExtension = %q, want the existing .yaml file", got)
	}
}

func TestResolveYamlExtension_PrefersYmlOverYaml(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "profile")
	for _, ext := range []string{".yml", ".yaml"} {
		if err := os.WriteFile(base+ext, []byte("debug: no\n"), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if got := ResolveYamlExtension(base); got != base+".yml" {
		t.Errorf("ResolveYamlExtension = %q, want the .yml file", got)
	}
}

func TestResolveYamlExtension_DefaultsToYml(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "brand-new")
	if got := ResolveYamlExtension(base); got != base+".yml" {
		t.Errorf("ResolveYamlExtension = %q, want %q", got, base+".yml")
	}
}

func TestResolveYamlExtension_OtherExtensionUntouched(t *testing.T) {
	in := filepath.Join(t.TempDir(), "settings.conf")
	if got := ResolveYamlExtension(in); got != in {
		t.Errorf("ResolveYamlExtension(%q) = %q, want it unchanged", in, got)
	}
}
