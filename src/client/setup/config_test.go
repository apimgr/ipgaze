package setup

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	paths "github.com/apimgr/ipgaze/src/client/path"
)

// saveDefault writes cfg to the default config path, the behaviour the
// pre---config-flag SaveCLIConfigToFile had.
func saveDefault(cfg *CLIConfig) error {
	return SaveCLIConfigToFile(cfg, paths.ConfigFile())
}

// redirectConfigDir temporarily redirects the paths package's ConfigDir to
// a test temp directory by overriding the appropriate XDG/platform env var.
// On non-Linux/BSD platforms we cannot cleanly override without forking the
// paths package, so those tests are skipped.
func redirectConfigDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("setup redirect test requires XDG on Linux/BSD")
	}
	tmp := t.TempDir()
	old, exists := os.LookupEnv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmp)
	t.Cleanup(func() {
		if exists {
			os.Setenv("XDG_CONFIG_HOME", old)
		} else {
			os.Unsetenv("XDG_CONFIG_HOME")
		}
	})
	return tmp
}

// ---------------------------------------------------------------------------
// LoadCLIConfigFromFile — missing file returns empty struct (not error)
// ---------------------------------------------------------------------------

func TestLoadCLIConfigFromFile_MissingFile_ReturnsEmpty(t *testing.T) {
	redirectConfigDir(t)

	cfg, err := LoadCLIConfigFromFile()
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil CLIConfig, got nil")
	}
	if cfg.Server.Primary != "" {
		t.Errorf("Server = %q, want empty", cfg.Server.Primary)
	}
	if cfg.Auth.Token != "" {
		t.Errorf("Token = %q, want empty", cfg.Auth.Token)
	}
}

// ---------------------------------------------------------------------------
// SaveCLIConfigToFile + LoadCLIConfigFromFile — round-trip
// ---------------------------------------------------------------------------

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	redirectConfigDir(t)

	in := &CLIConfig{
		Server: ServerConfig{Primary: "https://ifcfg.us"},
		Auth:   AuthConfig{Token: "tok-abc123"},
		Update: UpdateConfig{
			Auto:          "true",
			CheckInterval: "per_invocation",
			Channel:       "stable",
		},
		Display: DisplayConfig{
			Mode: "tui",
		},
	}

	if err := saveDefault(in); err != nil {
		t.Fatalf("SaveCLIConfigToFile: %v", err)
	}

	out, err := LoadCLIConfigFromFile()
	if err != nil {
		t.Fatalf("LoadCLIConfigFromFile: %v", err)
	}

	if out.Server.Primary != in.Server.Primary {
		t.Errorf("Server = %q, want %q", out.Server.Primary, in.Server.Primary)
	}
	if out.Auth.Token != in.Auth.Token {
		t.Errorf("Token = %q, want %q", out.Auth.Token, in.Auth.Token)
	}
	if out.Update.Auto != in.Update.Auto {
		t.Errorf("Update.Auto = %q, want %q", out.Update.Auto, in.Update.Auto)
	}
	if !out.UpdateAuto() {
		t.Error("UpdateAuto() = false, want true")
	}
	if out.Update.CheckInterval != in.Update.CheckInterval {
		t.Errorf("Update.CheckInterval = %q, want %q", out.Update.CheckInterval, in.Update.CheckInterval)
	}
	if out.Update.Channel != in.Update.Channel {
		t.Errorf("Update.Channel = %q, want %q", out.Update.Channel, in.Update.Channel)
	}
	if out.Display.Mode != in.Display.Mode {
		t.Errorf("Display.Mode = %q, want %q", out.Display.Mode, in.Display.Mode)
	}
}

// ---------------------------------------------------------------------------
// SaveCLIConfigToFile — creates parent directory (0700) if absent
// ---------------------------------------------------------------------------

func TestSaveCreatesDirectory(t *testing.T) {
	redirectConfigDir(t)

	cfg := &CLIConfig{Server: ServerConfig{Primary: "https://ifcfg.us"}}
	if err := saveDefault(cfg); err != nil {
		t.Fatalf("SaveCLIConfigToFile: %v", err)
	}

	// The config dir must now exist.
	// Retrieve config dir path by reading the file we just wrote.
	// We know XDG_CONFIG_HOME was set to tmp, so config dir is tmp/apimgr/ipgaze.
	xdg := os.Getenv("XDG_CONFIG_HOME")
	expectedDir := filepath.Join(xdg, "apimgr", "ipgaze")
	info, err := os.Stat(expectedDir)
	if err != nil {
		t.Fatalf("config dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("config dir path is not a directory: %s", expectedDir)
	}
}

// ---------------------------------------------------------------------------
// SaveCLIConfigToFile — written file has mode 0600
// ---------------------------------------------------------------------------

func TestSave_FileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode test does not apply to Windows")
	}
	redirectConfigDir(t)

	cfg := &CLIConfig{Server: ServerConfig{Primary: "https://ifcfg.us"}, Auth: AuthConfig{Token: "secret"}}
	if err := saveDefault(cfg); err != nil {
		t.Fatalf("SaveCLIConfigToFile: %v", err)
	}

	xdg := os.Getenv("XDG_CONFIG_HOME")
	file := filepath.Join(xdg, "apimgr", "ipgaze", "cli.yml")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat %s: %v", file, err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}
}

// ---------------------------------------------------------------------------
// LoadCLIConfigFromFile — corrupted YAML returns error
// ---------------------------------------------------------------------------

func TestLoad_CorruptYAML_ReturnsError(t *testing.T) {
	redirectConfigDir(t)

	xdg := os.Getenv("XDG_CONFIG_HOME")
	dir := filepath.Join(xdg, "apimgr", "ipgaze")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	file := filepath.Join(dir, "cli.yml")
	// Write deliberately invalid YAML (mapping key without value, unclosed brace).
	if err := os.WriteFile(file, []byte("server: {unclosed\ntoken: [bad"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadCLIConfigFromFile()
	if err == nil {
		t.Fatal("expected error from corrupt YAML, got nil")
	}
}

// ---------------------------------------------------------------------------
// Idempotency — saving twice and loading returns the last saved value
// ---------------------------------------------------------------------------

func TestSave_Idempotent(t *testing.T) {
	redirectConfigDir(t)

	first := &CLIConfig{Server: ServerConfig{Primary: "https://first.example.com"}, Auth: AuthConfig{Token: "tok1"}}
	if err := saveDefault(first); err != nil {
		t.Fatalf("first save: %v", err)
	}

	second := &CLIConfig{Server: ServerConfig{Primary: "https://second.example.com"}, Auth: AuthConfig{Token: "tok2"}}
	if err := saveDefault(second); err != nil {
		t.Fatalf("second save: %v", err)
	}

	got, err := LoadCLIConfigFromFile()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Server.Primary != second.Server.Primary {
		t.Errorf("Server = %q, want %q (second save)", got.Server.Primary, second.Server.Primary)
	}
	if got.Auth.Token != second.Auth.Token {
		t.Errorf("Token = %q, want %q (second save)", got.Auth.Token, second.Auth.Token)
	}
}

// ---------------------------------------------------------------------------
// Zero-value CLIConfig serialises and deserialises cleanly
// ---------------------------------------------------------------------------

func TestSave_ZeroValue(t *testing.T) {
	redirectConfigDir(t)

	if err := saveDefault(&CLIConfig{}); err != nil {
		t.Fatalf("SaveCLIConfigToFile (zero): %v", err)
	}

	got, err := LoadCLIConfigFromFile()
	if err != nil {
		t.Fatalf("LoadCLIConfigFromFile (zero): %v", err)
	}
	if got.Server.Primary != "" || got.Auth.Token != "" {
		t.Errorf("zero-value round-trip: Server=%q Token=%q, want both empty", got.Server.Primary, got.Auth.Token)
	}
}

// ---------------------------------------------------------------------------
// CLIConfig struct field defaults
// ---------------------------------------------------------------------------

func TestUpdateConfig_AutoFalseByDefault(t *testing.T) {
	cfg := &CLIConfig{}
	if cfg.UpdateAuto() {
		t.Error("UpdateAuto() should default to false")
	}
}

// ---------------------------------------------------------------------------
// Truthy config decoding — every boolean setting goes through config.IsTruthy
// ---------------------------------------------------------------------------

func TestTruthyAccessors_LocaleForms(t *testing.T) {
	cases := []struct {
		name string
		in   Truthy
		want bool
	}{
		{"yes", "yes", true},
		{"on", "on", true},
		{"enabled", "enabled", true},
		{"1", "1", true},
		{"true", "true", true},
		{"no", "no", false},
		{"off", "off", false},
		{"disabled", "disabled", false},
		{"0", "0", false},
		{"false", "false", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &CLIConfig{
				TUI:    TUIConfig{Enabled: c.in, Mouse: c.in, Unicode: c.in},
				Cache:  CacheConfig{Enabled: c.in},
				Output: OutputConfig{Quiet: c.in, Verbose: c.in},
				Update: UpdateConfig{Auto: c.in},
				Debug:  c.in,
			}
			if got := cfg.TUIEnabled(); got != c.want {
				t.Errorf("TUIEnabled(%q) = %v, want %v", c.in, got, c.want)
			}
			if got := cfg.CacheEnabled(); got != c.want {
				t.Errorf("CacheEnabled(%q) = %v, want %v", c.in, got, c.want)
			}
			if got := cfg.OutputQuiet(); got != c.want {
				t.Errorf("OutputQuiet(%q) = %v, want %v", c.in, got, c.want)
			}
			if got := cfg.DebugEnabled(); got != c.want {
				t.Errorf("DebugEnabled(%q) = %v, want %v", c.in, got, c.want)
			}
			if got := cfg.UpdateAuto(); got != c.want {
				t.Errorf("UpdateAuto(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// Unset truthy values fall back to the compiled default, not to false.
func TestTruthyAccessors_UnsetUsesCompiledDefault(t *testing.T) {
	cfg := &CLIConfig{}
	if !cfg.TUIEnabled() {
		t.Error("TUIEnabled() default = false, want true")
	}
	if !cfg.TUIMouse() {
		t.Error("TUIMouse() default = false, want true")
	}
	if !cfg.TUIUnicode() {
		t.Error("TUIUnicode() default = false, want true")
	}
	if !cfg.CacheEnabled() {
		t.Error("CacheEnabled() default = false, want true")
	}
	if cfg.OutputQuiet() || cfg.OutputVerbose() || cfg.DebugEnabled() {
		t.Error("quiet/verbose/debug defaults should all be false")
	}
}

// ---------------------------------------------------------------------------
// String / numeric / duration accessors
// ---------------------------------------------------------------------------

func TestAccessorDefaults(t *testing.T) {
	cfg := &CLIConfig{}
	if got := cfg.APIVersion(); got != DefaultAPIVersion {
		t.Errorf("APIVersion() = %q, want %q", got, DefaultAPIVersion)
	}
	if got := cfg.RequestTimeout().String(); got != "30s" {
		t.Errorf("RequestTimeout() = %s, want 30s", got)
	}
	if got := cfg.RetryAttempts(); got != DefaultRetry {
		t.Errorf("RetryAttempts() = %d, want %d", got, DefaultRetry)
	}
	if got := cfg.RetryDelay().String(); got != "1s" {
		t.Errorf("RetryDelay() = %s, want 1s", got)
	}
	if got := cfg.OutputFormat(); got != DefaultOutputFormat {
		t.Errorf("OutputFormat() = %q, want %q", got, DefaultOutputFormat)
	}
	if got := cfg.OutputColor(); got != DefaultColor {
		t.Errorf("OutputColor() = %q, want %q", got, DefaultColor)
	}
	if got := cfg.TUITheme(); got != DefaultTUITheme {
		t.Errorf("TUITheme() = %q, want %q", got, DefaultTUITheme)
	}
	if got := cfg.LogLevel(); got != DefaultLogLevel {
		t.Errorf("LogLevel() = %q, want %q", got, DefaultLogLevel)
	}
	if got := cfg.LogMaxFiles(); got != DefaultLogMaxFiles {
		t.Errorf("LogMaxFiles() = %d, want %d", got, DefaultLogMaxFiles)
	}
	if got := cfg.CacheTTL().String(); got != "5m0s" {
		t.Errorf("CacheTTL() = %s, want 5m0s", got)
	}
	if got := cfg.DefaultLang(); got != DefaultDefaultsLang {
		t.Errorf("DefaultLang() = %q, want %q", got, DefaultDefaultsLang)
	}
	if got := cfg.UpdateChannel(); got != DefaultUpdateChannel {
		t.Errorf("UpdateChannel() = %q, want %q", got, DefaultUpdateChannel)
	}
}

func TestRequestTimeout_InvalidFallsBackToDefault(t *testing.T) {
	cfg := &CLIConfig{Server: ServerConfig{Timeout: "not-a-duration"}}
	if got := cfg.RequestTimeout().String(); got != "30s" {
		t.Errorf("RequestTimeout() = %s, want 30s", got)
	}
}

func TestLogFilePath_EmptyUsesPathsLogFile(t *testing.T) {
	cfg := &CLIConfig{}
	if got := cfg.LogFilePath(); got != paths.LogFile() {
		t.Errorf("LogFilePath() = %q, want %q", got, paths.LogFile())
	}
	cfg.Logging.File = "/var/log/custom.log"
	if got := cfg.LogFilePath(); got != "/var/log/custom.log" {
		t.Errorf("LogFilePath() = %q, want the configured override", got)
	}
}

// ---------------------------------------------------------------------------
// Output format validation
// ---------------------------------------------------------------------------

func TestIsValidOutputFormat(t *testing.T) {
	for _, ok := range []string{"table", "json", "yaml", "plain", "csv"} {
		if !IsValidOutputFormat(ok) {
			t.Errorf("IsValidOutputFormat(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "auto", "xml", "TABLE"} {
		if IsValidOutputFormat(bad) {
			t.Errorf("IsValidOutputFormat(%q) = true, want false", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// EnsureConfigFile — auto-creation on first run
// ---------------------------------------------------------------------------

func TestEnsureConfigFile_CreatesWithDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode test does not apply to Windows")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "nested", "cli.yml")

	created, err := EnsureConfigFile(file)
	if err != nil {
		t.Fatalf("EnsureConfigFile: %v", err)
	}
	if !created {
		t.Fatal("EnsureConfigFile reported no creation on a missing file")
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}

	cfg, err := LoadCLIConfigFrom(file)
	if err != nil {
		t.Fatalf("LoadCLIConfigFrom: %v", err)
	}
	if cfg.OutputFormat() != "table" {
		t.Errorf("default output.format = %q, want table", cfg.OutputFormat())
	}
	if !cfg.TUIEnabled() {
		t.Error("default tui.enabled should be truthy")
	}
	if cfg.APIVersion() != "v1" {
		t.Errorf("default server.api_version = %q, want v1", cfg.APIVersion())
	}
}

func TestEnsureConfigFile_ExistingFileUntouched(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cli.yml")
	if err := os.WriteFile(file, []byte("debug: yes\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	created, err := EnsureConfigFile(file)
	if err != nil {
		t.Fatalf("EnsureConfigFile: %v", err)
	}
	if created {
		t.Error("EnsureConfigFile overwrote an existing config file")
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "debug: yes\n" {
		t.Errorf("existing file changed: %q", string(data))
	}
}

// The commented default template must itself be valid YAML that round-trips.
func TestDefaultConfigYAML_ParsesToDefaults(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cli.yml")
	if err := os.WriteFile(file, DefaultConfigYAML(), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadCLIConfigFrom(file)
	if err != nil {
		t.Fatalf("template is not valid YAML: %v", err)
	}
	if cfg.Update.CheckInterval != "per_invocation" {
		t.Errorf("update.check_interval = %q, want per_invocation", cfg.Update.CheckInterval)
	}
	if cfg.Display.Mode != "auto" {
		t.Errorf("display.mode = %q, want auto", cfg.Display.Mode)
	}
}

func TestDisplayConfig_ModeEmpty(t *testing.T) {
	cfg := &CLIConfig{}
	if cfg.Display.Mode != "" {
		t.Errorf("Display.Mode = %q, want empty string default", cfg.Display.Mode)
	}
}

// ---------------------------------------------------------------------------
// SaveCLIConfigToFile YAML output contains expected keys
// ---------------------------------------------------------------------------

func TestSave_YAMLContainsServerKey(t *testing.T) {
	redirectConfigDir(t)

	cfg := &CLIConfig{Server: ServerConfig{Primary: "https://ifcfg.us"}}
	if err := saveDefault(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	xdg := os.Getenv("XDG_CONFIG_HOME")
	data, err := os.ReadFile(filepath.Join(xdg, "apimgr", "ipgaze", "cli.yml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "server:") {
		t.Errorf("YAML output = %q, missing 'server:' key", string(data))
	}
}

// ---------------------------------------------------------------------------
// SaveIfEmptyOrInvalid
// ---------------------------------------------------------------------------

func TestSaveIfEmptyOrInvalid_FlagEmpty_ReturnsCurrent(t *testing.T) {
	alwaysValid := func(s string) bool { return true }
	got := SaveIfEmptyOrInvalid("current", "", alwaysValid)
	if got != "current" {
		t.Errorf("SaveIfEmptyOrInvalid(current, \"\", valid) = %q, want %q", got, "current")
	}
}

func TestSaveIfEmptyOrInvalid_FlagInvalid_ReturnsCurrent(t *testing.T) {
	neverValid := func(s string) bool { return false }
	got := SaveIfEmptyOrInvalid("current", "invalid", neverValid)
	if got != "current" {
		t.Errorf("SaveIfEmptyOrInvalid(current, invalid, neverValid) = %q, want %q", got, "current")
	}
}

func TestSaveIfEmptyOrInvalid_CurrentEmpty_ReturnsFlag(t *testing.T) {
	alwaysValid := func(s string) bool { return true }
	got := SaveIfEmptyOrInvalid("", "newval", alwaysValid)
	if got != "newval" {
		t.Errorf("SaveIfEmptyOrInvalid(\"\", newval, valid) = %q, want %q", got, "newval")
	}
}

func TestSaveIfEmptyOrInvalid_CurrentInvalid_ReturnsFlag(t *testing.T) {
	// Validate returns false for "bad", true for everything else
	validate := func(s string) bool { return s != "bad" }
	got := SaveIfEmptyOrInvalid("bad", "good", validate)
	if got != "good" {
		t.Errorf("SaveIfEmptyOrInvalid(bad, good, validate) = %q, want %q", got, "good")
	}
}

func TestSaveIfEmptyOrInvalid_BothValid_ReturnsFlag(t *testing.T) {
	alwaysValid := func(s string) bool { return true }
	got := SaveIfEmptyOrInvalid("current", "override", alwaysValid)
	if got != "override" {
		t.Errorf("SaveIfEmptyOrInvalid(current, override, valid) = %q, want %q", got, "override")
	}
}

// ---------------------------------------------------------------------------
// ValidateServerURL / ValidateToken
// ---------------------------------------------------------------------------

func TestValidateServerURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"valid https", "https://example.com", true},
		{"valid http", "http://localhost:8080", true},
		{"no scheme", "example.com", false},
		{"no host", "https://", false},
		{"unsupported scheme", "ftp://example.com", false},
		{"not a url", "not a url", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ValidateServerURL(c.in); got != c.want {
				t.Errorf("ValidateServerURL(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	if ValidateToken("") {
		t.Error("ValidateToken(\"\") = true, want false")
	}
	if !ValidateToken("some-token") {
		t.Error("ValidateToken(\"some-token\") = false, want true")
	}
}
