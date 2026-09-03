package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetGlobals clears the package-level singletons between tests so they don't
// bleed state into each other.
func resetGlobals() {
	mu.Lock()
	current = nil
	configPath = ""
	mu.Unlock()
}

// writeTempYAML creates a temp file with the given content and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTempYAML: %v", err)
	}
	return path
}

// ───────────────────────────── DefaultConfig ─────────────────────────────────

func TestDefaultConfig_ServerDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Address != "[::]" {
		t.Errorf("Address: got %q, want %q", cfg.Server.Address, "[::]")
	}
	if cfg.Server.Mode != "production" {
		t.Errorf("Mode: got %q, want %q", cfg.Server.Mode, "production")
	}
	if cfg.Server.UpdateBranch != "stable" {
		t.Errorf("UpdateBranch: got %q, want %q", cfg.Server.UpdateBranch, "stable")
	}
	if cfg.Server.CLIMinVersion != "1.0.0" {
		t.Errorf("CLIMinVersion: got %q, want %q", cfg.Server.CLIMinVersion, "1.0.0")
	}
}

func TestDefaultConfig_ScheduleDefaults(t *testing.T) {
	cfg := DefaultConfig()
	s := cfg.Server.Schedule

	if !s.Enabled {
		t.Error("Schedule.Enabled: want true")
	}
	if s.GeoIPUpdate != "weekly" {
		t.Errorf("GeoIPUpdate: got %q, want %q", s.GeoIPUpdate, "weekly")
	}
	if s.Timezone != "America/New_York" {
		t.Errorf("Timezone: got %q, want %q", s.Timezone, "America/New_York")
	}
	if s.CatchUpWindow != "1h" {
		t.Errorf("CatchUpWindow: got %q, want %q", s.CatchUpWindow, "1h")
	}
}

func TestDefaultConfig_TorDefaults(t *testing.T) {
	cfg := DefaultConfig()
	tor := cfg.Server.Tor

	if tor.UseNetwork {
		t.Error("Tor.UseNetwork: want false")
	}
	if !tor.AllowUserPreference {
		t.Error("Tor.AllowUserPreference: want true")
	}
	if tor.MaxCircuits != 32 {
		t.Errorf("Tor.MaxCircuits: got %d, want 32", tor.MaxCircuits)
	}
	if tor.CircuitTimeout != 60 {
		t.Errorf("Tor.CircuitTimeout: got %d, want 60", tor.CircuitTimeout)
	}
	if tor.BootstrapTimeout != 180 {
		t.Errorf("Tor.BootstrapTimeout: got %d, want 180", tor.BootstrapTimeout)
	}
	if !tor.SafeLogging {
		t.Error("Tor.SafeLogging: want true")
	}
	if tor.MaxStreamsPerCircuit != 100 {
		t.Errorf("Tor.MaxStreamsPerCircuit: got %d, want 100", tor.MaxStreamsPerCircuit)
	}
	if tor.BandwidthRate != "1 MB" {
		t.Errorf("Tor.BandwidthRate: got %q, want %q", tor.BandwidthRate, "1 MB")
	}
	if tor.VirtualPort != 80 {
		t.Errorf("Tor.VirtualPort: got %d, want 80", tor.VirtualPort)
	}
}

func TestDefaultConfig_MetricsDefaults(t *testing.T) {
	cfg := DefaultConfig()
	m := cfg.Server.Metrics

	if m.Enabled {
		t.Error("Metrics.Enabled: want false")
	}
	if !m.Root.Enabled {
		t.Error("Metrics.Root.Enabled: want true")
	}
	if m.Auth.AllowUnauthenticated {
		t.Error("Metrics.Auth.AllowUnauthenticated: want false")
	}
	if m.Auth.Tokens.Prometheus != "" || m.Auth.Tokens.Grafana != "" || m.Auth.Tokens.Loki != "" {
		t.Error("Metrics.Auth.Tokens: want all empty by default")
	}
	if m.Loki.MaxEntries != 1000 {
		t.Errorf("Metrics.Loki.MaxEntries: got %d, want 1000", m.Loki.MaxEntries)
	}
	if m.Loki.MaxAge != "1h" {
		t.Errorf("Metrics.Loki.MaxAge: got %q, want %q", m.Loki.MaxAge, "1h")
	}
	if !m.IncludeSystem {
		t.Error("Metrics.IncludeSystem: want true")
	}
}

func TestDefaultConfig_LoggingDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Logging.AccessFormat != "apache" {
		t.Errorf("Logging.AccessFormat: got %q, want %q", cfg.Server.Logging.AccessFormat, "apache")
	}
	if cfg.Server.Logging.Level != "warn" {
		t.Errorf("Logging.Level: got %q, want %q", cfg.Server.Logging.Level, "warn")
	}
}

func TestDefaultConfig_I18nDefaults(t *testing.T) {
	cfg := DefaultConfig()
	i := cfg.Server.I18n

	if !i.Enabled {
		t.Error("I18n.Enabled: want true")
	}
	if i.DefaultLanguage != "en" {
		t.Errorf("I18n.DefaultLanguage: got %q, want %q", i.DefaultLanguage, "en")
	}
	if i.FallbackLanguage != "en" {
		t.Errorf("I18n.FallbackLanguage: got %q, want %q", i.FallbackLanguage, "en")
	}
	if len(i.AvailableLanguages) == 0 {
		t.Error("I18n.AvailableLanguages: want non-empty")
	}
}

func TestDefaultConfig_PrivacyDefaults(t *testing.T) {
	cfg := DefaultConfig()
	p := cfg.Server.Privacy

	// PrivacyConfig uses nested structs per AI.md PART 16.
	// Verify the retention period is set to the default GDPR sentence.
	if p.Retention.Period == "" {
		t.Error("Privacy.Retention.Period: want non-empty default")
	}
	// Consent.DefaultEnabled should be true by default (opt-out model, AI.md PART 12).
	if !p.Consent.DefaultEnabled {
		t.Error("Privacy.Consent.DefaultEnabled: want true")
	}
	// Data.Sold should be false by default.
	if p.Data.Sold {
		t.Error("Privacy.Data.Sold: want false")
	}
}

func TestDefaultConfig_CacheDefaults(t *testing.T) {
	cfg := DefaultConfig()
	c := cfg.Server.Cache

	if c.Type != "memory" {
		t.Errorf("Cache.Type: got %q, want %q", c.Type, "memory")
	}
	// TTL is a string duration (default "1h").
	if c.TTL != "1h" {
		t.Errorf("Cache.TTL: got %q, want %q", c.TTL, "1h")
	}
}

func TestDefaultConfig_RateLimitDefaults(t *testing.T) {
	cfg := DefaultConfig()
	rl := cfg.Server.RateLimit

	if !rl.Enabled {
		t.Error("RateLimit.Enabled: want true")
	}
	if rl.Read.Requests != 120 {
		t.Errorf("RateLimit.Read.Requests: got %d, want 120", rl.Read.Requests)
	}
	if rl.Read.Window != 60 {
		t.Errorf("RateLimit.Read.Window: got %d, want 60", rl.Read.Window)
	}
	if rl.Write.Requests != 10 {
		t.Errorf("RateLimit.Write.Requests: got %d, want 10", rl.Write.Requests)
	}
	if rl.GlobalBurst != 240 {
		t.Errorf("RateLimit.GlobalBurst: got %d, want 240", rl.GlobalBurst)
	}
}

func TestDefaultConfig_LimitsDefaults(t *testing.T) {
	cfg := DefaultConfig()
	lim := cfg.Server.Limits

	if lim.MaxBodySize != "10MB" {
		t.Errorf("Limits.MaxBodySize: got %q, want %q", lim.MaxBodySize, "10MB")
	}
	if lim.ReadTimeout != "30s" {
		t.Errorf("Limits.ReadTimeout: got %q, want %q", lim.ReadTimeout, "30s")
	}
	if lim.WriteTimeout != "30s" {
		t.Errorf("Limits.WriteTimeout: got %q, want %q", lim.WriteTimeout, "30s")
	}
	if lim.IdleTimeout != "120s" {
		t.Errorf("Limits.IdleTimeout: got %q, want %q", lim.IdleTimeout, "120s")
	}
}

func TestDefaultConfig_CompressionDefaults(t *testing.T) {
	cfg := DefaultConfig()
	comp := cfg.Server.Compression

	if !comp.Enabled {
		t.Error("Compression.Enabled: want true")
	}
	if comp.Level != 5 {
		t.Errorf("Compression.Level: got %d, want 5", comp.Level)
	}
	if len(comp.Types) == 0 {
		t.Error("Compression.Types: want non-empty default list")
	}
}

func TestDefaultConfig_BrandingDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Branding.ThemeColor != "#bd93f9" {
		t.Errorf("Branding.ThemeColor: got %q, want %q", cfg.Server.Branding.ThemeColor, "#bd93f9")
	}
}

func TestDefaultConfig_WebUIDefaults(t *testing.T) {
	cfg := DefaultConfig()
	w := cfg.Web.UI

	if w.Theme != "dark" {
		t.Errorf("Web.UI.Theme: got %q, want %q", w.Theme, "dark")
	}
	if !w.Notifications.Enabled {
		t.Error("Web.UI.Notifications.Enabled: want true")
	}
}

func TestDefaultConfig_WebRobotsDefaults(t *testing.T) {
	cfg := DefaultConfig()
	r := cfg.Web.Robots

	if len(r.Allow) == 0 {
		t.Error("Web.Robots.Allow: want non-empty")
	}
	if len(r.Deny) == 0 {
		t.Error("Web.Robots.Deny: want non-empty")
	}
}

func TestDefaultConfig_WebSecurityDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Web.CORS != "*" {
		t.Errorf("Web.CORS: got %q, want %q", cfg.Web.CORS, "*")
	}
}

func TestDefaultConfig_HealthzRootEnabled(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Healthz.Root.Enabled {
		t.Error("Healthz.Root.Enabled: want false (opt-in root alias, AI.md PART 5/13)")
	}
}

// ──────────────────────────── DatabaseConfig ─────────────────────────────────

func TestDatabaseConfig_NormalizedDriver(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"sqlite", "sqlite"},
		{"sqlite2", "sqlite"},
		{"sqlite3", "sqlite"},
		{"SQLITE3", "sqlite"},
		{"", "sqlite"},
		{"libsql", "libsql"},
		{"turso", "libsql"},
		{"TURSO", "libsql"},
		{"postgres", "postgres"},
		{"mysql", "mysql"},
	}
	for _, tc := range cases {
		d := DatabaseConfig{Driver: tc.input}
		got := d.NormalizedDriver()
		if got != tc.want {
			t.Errorf("NormalizedDriver(%q): got %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestDatabaseConfig_ValidateLibSQL_NoError_SQLite(t *testing.T) {
	d := DatabaseConfig{Driver: "sqlite"}
	if err := d.ValidateLibSQL(); err != nil {
		t.Errorf("ValidateLibSQL with sqlite: unexpected error: %v", err)
	}
}

func TestDatabaseConfig_ValidateLibSQL_NoError_EmptyDriver(t *testing.T) {
	d := DatabaseConfig{Driver: ""}
	if err := d.ValidateLibSQL(); err != nil {
		t.Errorf("ValidateLibSQL with empty driver: unexpected error: %v", err)
	}
}

func TestDatabaseConfig_ValidateLibSQL_ErrorWhenNoURL(t *testing.T) {
	d := DatabaseConfig{Driver: "libsql", URL: ""}
	if err := d.ValidateLibSQL(); err == nil {
		t.Error("ValidateLibSQL with libsql and no URL: want error, got nil")
	}
}

func TestDatabaseConfig_ValidateLibSQL_TursoNoURL(t *testing.T) {
	d := DatabaseConfig{Driver: "turso", URL: ""}
	if err := d.ValidateLibSQL(); err == nil {
		t.Error("ValidateLibSQL with turso and no URL: want error, got nil")
	}
}

func TestDatabaseConfig_ValidateLibSQL_OKWithURL(t *testing.T) {
	d := DatabaseConfig{Driver: "libsql", URL: "libsql://example.turso.io?authToken=xxx"}
	if err := d.ValidateLibSQL(); err != nil {
		t.Errorf("ValidateLibSQL with URL set: unexpected error: %v", err)
	}
}

// ────────────────────────────── IsDebug ───────────────────────────────

func TestIsDebug_FalseByDefault(t *testing.T) {
	os.Unsetenv("DEBUG")
	cfg := DefaultConfig()
	if cfg.IsDebug() {
		t.Error("IsDebug: want false when DEBUG env unset and mode is production")
	}
}

func TestIsDebug_TrueViaDEBUGEnvVar(t *testing.T) {
	os.Setenv("DEBUG", "true")
	defer os.Unsetenv("DEBUG")

	cfg := DefaultConfig()
	if !cfg.IsDebug() {
		t.Error("IsDebug: want true when DEBUG=true")
	}
}

func TestIsDebug_TrueViaDEBUGEnvVar_Truthy(t *testing.T) {
	truthyInputs := []string{"1", "yes", "on", "enabled", "enable"}
	for _, v := range truthyInputs {
		os.Setenv("DEBUG", v)
		cfg := DefaultConfig()
		if !cfg.IsDebug() {
			t.Errorf("IsDebug: want true when DEBUG=%q", v)
		}
	}
	os.Unsetenv("DEBUG")
}

func TestIsDebug_FalseViaDEBUGEnvVar_Falsy(t *testing.T) {
	falsyInputs := []string{"0", "no", "off", "false", "disabled"}
	for _, v := range falsyInputs {
		os.Setenv("DEBUG", v)
		cfg := DefaultConfig()
		if cfg.IsDebug() {
			t.Errorf("IsDebug: want false when DEBUG=%q", v)
		}
	}
	os.Unsetenv("DEBUG")
}

func TestIsDebug_TrueViaEnv(t *testing.T) {
	// Debug is enabled via DEBUG env var, not via mode.
	t.Setenv("DEBUG", "true")
	cfg := DefaultConfig()
	if !cfg.IsDebug() {
		t.Error("IsDebug: want true when DEBUG=true")
	}
}

func TestIsDebug_FalseViaModeProduction(t *testing.T) {
	os.Unsetenv("DEBUG")
	cfg := DefaultConfig()
	cfg.Server.Mode = "production"
	if cfg.IsDebug() {
		t.Error("IsDebug: want false when mode=production and no DEBUG env")
	}
}

// ─────────────────────────────── Sanitized ───────────────────────────────────

func TestSanitized_RedactsServerToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Token = "supersecret123"
	sanitized := cfg.Sanitized()

	if sanitized.Server.Token != "xxxxx" {
		t.Errorf("Sanitized.Server.Token: got %q, want %q", sanitized.Server.Token, "xxxxx")
	}
}

func TestSanitized_RedactsMetricsTokens(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Metrics.Auth.Tokens.Prometheus = "promsecret"
	cfg.Server.Metrics.Auth.Tokens.Grafana = "grafanasecret"
	cfg.Server.Metrics.Auth.Tokens.Loki = "lokisecret"
	sanitized := cfg.Sanitized()

	tokens := sanitized.Server.Metrics.Auth.Tokens
	if tokens.Prometheus != "xxxxx" || tokens.Grafana != "xxxxx" || tokens.Loki != "xxxxx" {
		t.Errorf("Sanitized metrics tokens: got %+v, want all xxxxx", tokens)
	}
}

func TestGeoIPPresets_DefaultEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Server.GeoIP.Presets) != 0 {
		t.Errorf("GeoIP.Presets: got %d entries, want 0", len(cfg.Server.GeoIP.Presets))
	}
	if len(cfg.Server.GeoIP.ResolvedDenyCountries()) != 0 {
		t.Error("ResolvedDenyCountries: want empty on a default config")
	}
	if len(cfg.Server.GeoIP.ResolvedAllowCountries()) != 0 {
		t.Error("ResolvedAllowCountries: want empty on a default config")
	}
}

func TestGeoIPPresets_ExpandInDenyAndAllow(t *testing.T) {
	g := GeoIPConfig{
		DenyCountries:  []string{"blocked", "kp"},
		AllowCountries: []string{"trusted"},
		Presets: map[string][]string{
			"blocked": {"cn", "RU", "CN"},
			"trusted": {"US", "CA"},
		},
	}
	deny := g.ResolvedDenyCountries()
	want := []string{"CN", "RU", "KP"}
	if len(deny) != len(want) {
		t.Fatalf("ResolvedDenyCountries: got %v, want %v", deny, want)
	}
	for i := range want {
		if deny[i] != want[i] {
			t.Fatalf("ResolvedDenyCountries: got %v, want %v", deny, want)
		}
	}
	allow := g.ResolvedAllowCountries()
	if len(allow) != 2 || allow[0] != "US" || allow[1] != "CA" {
		t.Errorf("ResolvedAllowCountries: got %v, want [US CA]", allow)
	}
}

func TestGeoIPPresets_NeverAutoApplied(t *testing.T) {
	g := GeoIPConfig{
		Presets: map[string][]string{"blocked": {"CN", "RU"}},
	}
	if got := g.ResolvedDenyCountries(); len(got) != 0 {
		t.Errorf("ResolvedDenyCountries: got %v, want empty — presets are never auto-applied", got)
	}
	if got := g.ResolvedAllowCountries(); len(got) != 0 {
		t.Errorf("ResolvedAllowCountries: got %v, want empty — presets are never auto-applied", got)
	}
}

func TestSanitized_EmptyTokensLeftAlone(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Token = ""
	cfg.Server.Metrics.Auth.Tokens.Prometheus = ""
	sanitized := cfg.Sanitized()

	if sanitized.Server.Token != "" {
		t.Errorf("Sanitized.Server.Token with empty input: got %q, want %q", sanitized.Server.Token, "")
	}
	if sanitized.Server.Metrics.Auth.Tokens.Prometheus != "" {
		t.Errorf("Sanitized prometheus token with empty input: got %q, want %q", sanitized.Server.Metrics.Auth.Tokens.Prometheus, "")
	}
}

func TestSanitized_DoesNotMutateOriginal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Token = "original-secret"
	_ = cfg.Sanitized()

	if cfg.Server.Token != "original-secret" {
		t.Errorf("Sanitized mutated original: Server.Token is now %q", cfg.Server.Token)
	}
}

func TestSanitized_RedactsEncryptionKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Security.EncryptionKey = "base64keymaterial"
	sanitized := cfg.Sanitized()

	if sanitized.Server.Security.EncryptionKey != "xxxxx" {
		t.Errorf("Sanitized.Server.Security.EncryptionKey: got %q, want %q", sanitized.Server.Security.EncryptionKey, "xxxxx")
	}
	if cfg.Server.Security.EncryptionKey != "base64keymaterial" {
		t.Errorf("Sanitized mutated original: Server.Security.EncryptionKey is now %q", cfg.Server.Security.EncryptionKey)
	}
}

func TestSanitized_RedactsDNSCredentialsEncrypted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted = "ciphertext-blob"
	sanitized := cfg.Sanitized()

	if sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted != "xxxxx" {
		t.Errorf("Sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted: got %q, want %q",
			sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted, "xxxxx")
	}
}

func TestSanitized_EmptyEncryptionKeyAndDNSCredentialsLeftAlone(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Security.EncryptionKey = ""
	cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted = ""
	sanitized := cfg.Sanitized()

	if sanitized.Server.Security.EncryptionKey != "" {
		t.Errorf("Sanitized.Server.Security.EncryptionKey with empty input: got %q, want %q", sanitized.Server.Security.EncryptionKey, "")
	}
	if sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted != "" {
		t.Errorf("Sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted with empty input: got %q, want %q",
			sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted, "")
	}
}

func TestSanitized_OtherFieldsPreserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Token = "secret"
	cfg.Server.Port = "9999"
	sanitized := cfg.Sanitized()

	if sanitized.Server.Port != "9999" {
		t.Errorf("Sanitized should preserve Port: got %q", sanitized.Server.Port)
	}
}

// ─────────────────────────────── GetCORS ─────────────────────────────────────

func TestGetCORS_DefaultIsWildcard(t *testing.T) {
	resetGlobals()
	cors := GetCORS()
	if cors != "*" {
		t.Errorf("GetCORS with default config: got %q, want %q", cors, "*")
	}
}

func TestGetCORS_EmptyCORSFallsBackToWildcard(t *testing.T) {
	resetGlobals()
	mu.Lock()
	cfg := DefaultConfig()
	cfg.Web.CORS = ""
	current = cfg
	mu.Unlock()

	cors := GetCORS()
	if cors != "*" {
		t.Errorf("GetCORS with empty CORS: got %q, want %q", cors, "*")
	}
}

func TestGetCORS_ReturnsConfiguredValue(t *testing.T) {
	resetGlobals()
	mu.Lock()
	cfg := DefaultConfig()
	cfg.Web.CORS = "https://example.com"
	current = cfg
	mu.Unlock()

	cors := GetCORS()
	if cors != "https://example.com" {
		t.Errorf("GetCORS: got %q, want %q", cors, "https://example.com")
	}
}

// ─────────────────────────────── GetTheme ────────────────────────────────────

func TestGetTheme_DefaultIsDark(t *testing.T) {
	resetGlobals()
	theme := getTheme()
	if theme != "dark" {
		t.Errorf("GetTheme with default config: got %q, want %q", theme, "dark")
	}
}

func TestGetTheme_ReturnsConfiguredValue(t *testing.T) {
	resetGlobals()
	mu.Lock()
	cfg := DefaultConfig()
	cfg.Web.UI.Theme = "light"
	current = cfg
	mu.Unlock()

	theme := getTheme()
	if theme != "light" {
		t.Errorf("GetTheme: got %q, want %q", theme, "light")
	}
}

// ──────────────────────────── getCurrentConfig ────────────────────────────────

func TestGetCurrentConfig_ReturnsDefaultWhenNil(t *testing.T) {
	resetGlobals()
	cfg := getCurrentConfig()
	if cfg == nil {
		t.Fatal("getCurrentConfig: got nil, want default")
	}
	if cfg.Server.Mode != "production" {
		t.Errorf("getCurrentConfig: Mode: got %q, want %q", cfg.Server.Mode, "production")
	}
}

func TestGetCurrentConfig_ReturnsCurrent(t *testing.T) {
	resetGlobals()
	mu.Lock()
	loaded := DefaultConfig()
	loaded.Server.Port = "8080"
	current = loaded
	mu.Unlock()

	got := getCurrentConfig()
	if got.Server.Port != "8080" {
		t.Errorf("getCurrentConfig: Port: got %q, want %q", got.Server.Port, "8080")
	}
}

// ──────────────────────────── getConfigPath ───────────────────────────────────

func TestGetConfigPath_EmptyWhenNotLoaded(t *testing.T) {
	resetGlobals()
	if p := getConfigPath(); p != "" {
		t.Errorf("getConfigPath before load: got %q, want empty", p)
	}
}

// ──────────────────────────── LoadConfigFromFile ─────────────────────────────

func TestLoadConfigFromFile_CreatesDefaultWhenMissing(t *testing.T) {
	resetGlobals()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")

	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile on missing file: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfigFromFile: returned nil config")
	}
	// File must have been created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("LoadConfigFromFile: config file was not created")
	}
	if cfg.Server.Mode != "production" {
		t.Errorf("Created default: Mode: got %q, want production", cfg.Server.Mode)
	}
}

func TestLoadConfigFromFile_SeedsBrandingFromInitOnlyEnv(t *testing.T) {
	resetGlobals()
	t.Setenv("APPLICATION_NAME", "TestApp")
	t.Setenv("APPLICATION_TAGLINE", "Test Tagline")
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")

	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if cfg.Server.Branding.Title != "TestApp" {
		t.Errorf("Branding.Title: got %q, want %q", cfg.Server.Branding.Title, "TestApp")
	}
	if cfg.Server.Branding.Tagline != "Test Tagline" {
		t.Errorf("Branding.Tagline: got %q, want %q", cfg.Server.Branding.Tagline, "Test Tagline")
	}
}

func TestLoadConfigFromFile_ExistingConfigIgnoresApplicationNameEnv(t *testing.T) {
	resetGlobals()
	t.Setenv("APPLICATION_NAME", "ShouldNotApply")
	path := writeTempYAML(t, `
server:
  branding:
    title: PersistedTitle
`)

	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if cfg.Server.Branding.Title != "PersistedTitle" {
		t.Errorf("Branding.Title: got %q, want %q (APPLICATION_NAME is Init-Only, must not override an existing file)", cfg.Server.Branding.Title, "PersistedTitle")
	}
}

func TestLoadConfigFromFile_RuntimeDatabaseEnvOverridesPersisted(t *testing.T) {
	resetGlobals()
	t.Setenv("DATABASE_DRIVER", "libsql")
	t.Setenv("DATABASE_URL", "libsql://example.turso.io")
	path := writeTempYAML(t, `
server:
  database:
    driver: sqlite
    url: ""
`)

	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if cfg.Server.Database.Driver != "libsql" {
		t.Errorf("Database.Driver: got %q, want %q", cfg.Server.Database.Driver, "libsql")
	}
	if cfg.Server.Database.URL != "libsql://example.turso.io" {
		t.Errorf("Database.URL: got %q, want %q", cfg.Server.Database.URL, "libsql://example.turso.io")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "libsql") {
		t.Error("DATABASE_DRIVER/DATABASE_URL are Runtime env vars and must not be persisted to server.yml")
	}
}

func TestLoadConfigFromFile_ParsesValidYAML(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `
server:
  port: "9000"
  mode: development
  logging:
    level: debug
`)
	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if cfg.Server.Port != "9000" {
		t.Errorf("Port: got %q, want %q", cfg.Server.Port, "9000")
	}
	if cfg.Server.Mode != "development" {
		t.Errorf("Mode: got %q, want %q", cfg.Server.Mode, "development")
	}
	if cfg.Server.Logging.Level != "debug" {
		t.Errorf("Logging.Level: got %q, want %q", cfg.Server.Logging.Level, "debug")
	}
}

func TestLoadConfigFromFile_SetsConfigPath(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server: {}`)
	if _, err := LoadConfigFromFile(path); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if got := getConfigPath(); got != path {
		t.Errorf("getConfigPath: got %q, want %q", got, path)
	}
}

func TestLoadConfigFromFile_MissingFieldsGetDefaults(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server:
  port: "7777"
`)
	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	// Address was not in the file — should keep the default
	if cfg.Server.Address != "[::]" {
		t.Errorf("Address fallback: got %q, want %q", cfg.Server.Address, "[::]")
	}
}

func TestLoadConfigFromFile_InvalidYAML(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server: {bad yaml: [unclosed`)
	_, err := LoadConfigFromFile(path)
	if err == nil {
		t.Error("LoadConfigFromFile: want error on invalid YAML, got nil")
	}
}

func TestLoadConfigFromFile_UpdatesCurrentGlobal(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server:
  port: "6543"
`)
	if _, err := LoadConfigFromFile(path); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	got := getCurrentConfig()
	if got.Server.Port != "6543" {
		t.Errorf("Current config after load: Port: got %q, want %q", got.Server.Port, "6543")
	}
}

// ──────────────────────────── migrateYamlToYml ────────────────────────────────

func TestMigrateYamlToYml_NoYamlFileNoChange(t *testing.T) {
	dir := t.TempDir()
	ymlPath := filepath.Join(dir, "server.yml")
	got := migrateYamlToYml(ymlPath)
	if got != ymlPath {
		t.Errorf("migrateYamlToYml: got %q, want %q", got, ymlPath)
	}
}

func TestMigrateYamlToYml_RenamesWhenYmlMissing(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "server.yaml")
	ymlPath := filepath.Join(dir, "server.yml")

	if err := os.WriteFile(yamlPath, []byte("server: {}"), 0644); err != nil {
		t.Fatal(err)
	}

	got := migrateYamlToYml(ymlPath)
	if got != ymlPath {
		t.Errorf("migrateYamlToYml return: got %q, want %q", got, ymlPath)
	}
	// .yaml should be gone, .yml should exist
	if _, err := os.Stat(yamlPath); !os.IsNotExist(err) {
		t.Error("migrateYamlToYml: .yaml file still exists after migration")
	}
	if _, err := os.Stat(ymlPath); os.IsNotExist(err) {
		t.Error("migrateYamlToYml: .yml file not created")
	}
}

func TestMigrateYamlToYml_BothExistNoRename(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "server.yaml")
	ymlPath := filepath.Join(dir, "server.yml")

	os.WriteFile(yamlPath, []byte("yaml: content"), 0644)
	os.WriteFile(ymlPath, []byte("yml: content"), 0644)

	got := migrateYamlToYml(ymlPath)
	if got != ymlPath {
		t.Errorf("migrateYamlToYml return: got %q, want %q", got, ymlPath)
	}
	// Both files should remain unchanged
	if _, err := os.Stat(yamlPath); err != nil {
		t.Error("migrateYamlToYml: .yaml file removed when both exist")
	}
}

func TestMigrateYamlToYml_NonYmlPathPassthrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	got := migrateYamlToYml(path)
	if got != path {
		t.Errorf("migrateYamlToYml with .yaml path: got %q, want original %q", got, path)
	}
}

// ─────────────────────────── SaveConfigToFile ────────────────────────────────

func TestSaveConfigToFile_ErrorWhenNoConfigLoaded(t *testing.T) {
	resetGlobals()
	if err := SaveConfigToFile(); err == nil {
		t.Error("SaveConfigToFile with no config: want error, got nil")
	}
}

func TestSaveConfigToFile_WritesFile(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server:
  port: "5555"
`)
	if _, err := LoadConfigFromFile(path); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if err := SaveConfigToFile(); err != nil {
		t.Fatalf("SaveConfigToFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after save: %v", err)
	}
	if len(data) == 0 {
		t.Error("SaveConfigToFile: wrote empty file")
	}
}

func TestSaveConfigToFile_RoundTripsEncryptionKeyAndDNSCredentials(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server:
  port: "5555"
`)
	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}

	cfg.Server.Security.EncryptionKey = "dGVzdC1rZXktbWF0ZXJpYWw="
	cfg.Server.SSL.LetsEncrypt.DNSProvider = "cloudflare"
	cfg.Server.SSL.LetsEncrypt.DNSCredentials = DNSCredentialsConfig{
		Provider:             "cloudflare",
		CredentialsEncrypted: "ZmFrZS1jaXBoZXJ0ZXh0",
		ValidatedAt:          "2026-01-01T00:00:00Z",
	}
	if err := SaveConfigToFile(); err != nil {
		t.Fatalf("SaveConfigToFile: %v", err)
	}

	resetGlobals()
	reloaded, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile (reload): %v", err)
	}

	if reloaded.Server.Security.EncryptionKey != "dGVzdC1rZXktbWF0ZXJpYWw=" {
		t.Errorf("EncryptionKey round-trip: got %q", reloaded.Server.Security.EncryptionKey)
	}
	if reloaded.Server.SSL.LetsEncrypt.DNSCredentials.Provider != "cloudflare" {
		t.Errorf("DNSCredentials.Provider round-trip: got %q", reloaded.Server.SSL.LetsEncrypt.DNSCredentials.Provider)
	}
	if reloaded.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted != "ZmFrZS1jaXBoZXJ0ZXh0" {
		t.Errorf("DNSCredentials.CredentialsEncrypted round-trip: got %q", reloaded.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted)
	}
	if reloaded.Server.SSL.LetsEncrypt.DNSCredentials.ValidatedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("DNSCredentials.ValidatedAt round-trip: got %q", reloaded.Server.SSL.LetsEncrypt.DNSCredentials.ValidatedAt)
	}
}

// ──────────────────────────── reloadConfigFromFile ───────────────────────────

func TestReloadConfigFromFile_ErrorWhenNoPathSet(t *testing.T) {
	resetGlobals()
	if err := reloadConfigFromFile(); err == nil {
		t.Error("reloadConfigFromFile with no path: want error, got nil")
	}
}

func TestReloadConfigFromFile_PicksUpChanges(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server:
  port: "1111"
`)
	if _, err := LoadConfigFromFile(path); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}

	// Write a different port to the file
	if err := os.WriteFile(path, []byte("server:\n  port: \"2222\"\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := reloadConfigFromFile(); err != nil {
		t.Fatalf("reloadConfigFromFile: %v", err)
	}

	got := getCurrentConfig()
	if got.Server.Port != "2222" {
		t.Errorf("After reload: Port: got %q, want %q", got.Server.Port, "2222")
	}
}

func TestReloadConfigFromFile_InvalidYAML(t *testing.T) {
	resetGlobals()
	path := writeTempYAML(t, `server:
  port: "3333"
`)
	if _, err := LoadConfigFromFile(path); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}

	os.WriteFile(path, []byte("{broken yaml: ["), 0644)

	if err := reloadConfigFromFile(); err == nil {
		t.Error("reloadConfigFromFile on invalid YAML: want error, got nil")
	}
}

// ─────────────────────────── formatStringSlice ───────────────────────────────

func TestFormatStringSlice_Empty(t *testing.T) {
	got := formatStringSlice(nil)
	if got != "[]" {
		t.Errorf("formatStringSlice(nil): got %q, want %q", got, "[]")
	}
	got = formatStringSlice([]string{})
	if got != "[]" {
		t.Errorf("formatStringSlice([]): got %q, want %q", got, "[]")
	}
}

func TestFormatStringSlice_SingleElement(t *testing.T) {
	got := formatStringSlice([]string{"foo"})
	if got != `["foo"]` {
		t.Errorf("formatStringSlice single: got %q, want %q", got, `["foo"]`)
	}
}

func TestFormatStringSlice_MultipleElements(t *testing.T) {
	got := formatStringSlice([]string{"a", "b", "c"})
	want := `["a", "b", "c"]`
	if got != want {
		t.Errorf("formatStringSlice multi: got %q, want %q", got, want)
	}
}

// ─────────────────────────── generateConfigYAML ──────────────────────────────

func TestGenerateConfigYAML_ContainsRequiredKeys(t *testing.T) {
	cfg := DefaultConfig()
	yaml := generateConfigYAML(cfg)

	requiredKeys := []string{
		"server:",
		"web:",
		"port:",
		"metrics:",
		"logging:",
		"geoip:",
		"tor:",
		"cache:",
		"branding:",
	}
	for _, key := range requiredKeys {
		if !strings.Contains(yaml, key) {
			t.Errorf("generateConfigYAML: missing key %q in output", key)
		}
	}
}

func TestGenerateConfigYAML_IsRoundtrippable(t *testing.T) {
	resetGlobals()
	original := DefaultConfig()
	original.Server.Port = "7890"
	original.Server.Logging.Level = "debug"

	yamlContent := generateConfigYAML(original)

	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile on generated YAML: %v", err)
	}
	if loaded.Server.Port != "7890" {
		t.Errorf("Round-trip Port: got %q, want %q", loaded.Server.Port, "7890")
	}
	if loaded.Server.Logging.Level != "debug" {
		t.Errorf("Round-trip Level: got %q, want %q", loaded.Server.Logging.Level, "debug")
	}
}

// ────────────────────────────── ConfigManager ────────────────────────────────

func TestGenerateConfigYAML_RoundTripsNewFields(t *testing.T) {
	resetGlobals()
	original := DefaultConfig()
	original.Server.Token = "op-token-xyz789"
	original.Server.Database.Driver = "libsql"
	original.Server.Database.URL = "libsql://example.turso.io"
	original.Server.Database.Token = "db-token-abc123"
	original.Server.Security.Allowlist = []AllowlistEntry{
		{CIDR: "127.0.0.1/32", Description: "loopback"},
		{CIDR: "10.0.0.0/8", Description: "internal net"},
	}
	enabled := false
	original.Server.Schedule.Tasks.SSLRenewal = TaskScheduleConfig{Schedule: "0 0 * * *", Enabled: &enabled}
	original.Server.RateLimit.Read.Requests = 42
	original.Server.Limits.MaxBodySize = "5MB"
	original.Server.Compression.Types = []string{"text/html", "application/json"}
	original.Server.TrustedProxies.Additional = []string{"192.168.1.0/24"}
	original.Server.URLDetection.MinSamples = 7
	original.Server.Logging.Security.Filename = "security-custom.log"
	original.Server.Debug.LogBodies = true
	original.Server.Debug.MaxBodyLogSize = "20KB"

	yamlContent := generateConfigYAML(original)

	path := writeTempYAML(t, yamlContent)
	loaded, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile on generated YAML: %v", err)
	}

	if loaded.Server.Token != original.Server.Token {
		t.Errorf("Round-trip Token: got %q, want %q", loaded.Server.Token, original.Server.Token)
	}
	if loaded.Server.Database.Driver != "libsql" || loaded.Server.Database.URL != "libsql://example.turso.io" || loaded.Server.Database.Token != "db-token-abc123" {
		t.Errorf("Round-trip Database: got %+v", loaded.Server.Database)
	}
	if len(loaded.Server.Security.Allowlist) != 2 || loaded.Server.Security.Allowlist[0].CIDR != "127.0.0.1/32" || loaded.Server.Security.Allowlist[1].Description != "internal net" {
		t.Errorf("Round-trip Allowlist: got %+v", loaded.Server.Security.Allowlist)
	}
	if loaded.Server.Schedule.Tasks.SSLRenewal.Schedule != "0 0 * * *" || loaded.Server.Schedule.Tasks.SSLRenewal.Enabled == nil || *loaded.Server.Schedule.Tasks.SSLRenewal.Enabled != false {
		t.Errorf("Round-trip Schedule.Tasks.SSLRenewal: got %+v", loaded.Server.Schedule.Tasks.SSLRenewal)
	}
	if loaded.Server.RateLimit.Read.Requests != 42 {
		t.Errorf("Round-trip RateLimit.Read.Requests: got %d, want 42", loaded.Server.RateLimit.Read.Requests)
	}
	if loaded.Server.Limits.MaxBodySize != "5MB" {
		t.Errorf("Round-trip Limits.MaxBodySize: got %q, want %q", loaded.Server.Limits.MaxBodySize, "5MB")
	}
	if len(loaded.Server.Compression.Types) != 2 || loaded.Server.Compression.Types[1] != "application/json" {
		t.Errorf("Round-trip Compression.Types: got %+v", loaded.Server.Compression.Types)
	}
	if len(loaded.Server.TrustedProxies.Additional) != 1 || loaded.Server.TrustedProxies.Additional[0] != "192.168.1.0/24" {
		t.Errorf("Round-trip TrustedProxies.Additional: got %+v", loaded.Server.TrustedProxies.Additional)
	}
	if loaded.Server.URLDetection.MinSamples != 7 {
		t.Errorf("Round-trip URLDetection.MinSamples: got %d, want 7", loaded.Server.URLDetection.MinSamples)
	}
	if loaded.Server.Logging.Security.Filename != "security-custom.log" {
		t.Errorf("Round-trip Logging.Security.Filename: got %q, want %q", loaded.Server.Logging.Security.Filename, "security-custom.log")
	}
	if !loaded.Server.Debug.LogBodies || loaded.Server.Debug.MaxBodyLogSize != "20KB" {
		t.Errorf("Round-trip Debug: got LogBodies=%v MaxBodyLogSize=%q", loaded.Server.Debug.LogBodies, loaded.Server.Debug.MaxBodyLogSize)
	}
}

func TestNewConfigManager_NonExistentFile(t *testing.T) {
	m := NewConfigManager("/nonexistent/path/server.yml")
	if m == nil {
		t.Fatal("NewConfigManager: got nil")
	}
	// modTime should be zero since file doesn't exist
	if !m.lastFileModTime.IsZero() {
		t.Error("NewConfigManager: lastFileModTime should be zero for non-existent file")
	}
}

func TestNewConfigManager_ExistingFile(t *testing.T) {
	path := writeTempYAML(&testing.T{}, `server: {}`)
	m := NewConfigManager(path)
	if m.lastFileModTime.IsZero() {
		t.Error("NewConfigManager: lastFileModTime should not be zero for existing file")
	}
}

func TestConfigManager_PendingRestart_InitiallyFalse(t *testing.T) {
	m := &ConfigManager{}
	if m.PendingRestart() {
		t.Error("PendingRestart: want false initially")
	}
}

func TestConfigManager_RestartSettings_InitiallyEmpty(t *testing.T) {
	m := &ConfigManager{}
	if s := m.RestartSettings(); len(s) != 0 {
		t.Errorf("RestartSettings: want empty, got %v", s)
	}
}

func TestConfigManager_ClearPendingRestart(t *testing.T) {
	m := &ConfigManager{
		pendingRestart:  true,
		restartSettings: []string{"server.port"},
	}
	m.ClearPendingRestart()

	if m.PendingRestart() {
		t.Error("ClearPendingRestart: pendingRestart still true")
	}
	if s := m.RestartSettings(); len(s) != 0 {
		t.Errorf("ClearPendingRestart: restartSettings not cleared: %v", s)
	}
}

func TestConfigManager_RestartSettings_ReturnsCopy(t *testing.T) {
	m := &ConfigManager{
		restartSettings: []string{"server.port"},
	}
	settings := m.RestartSettings()
	settings[0] = "mutated"

	// Internal state must not be affected
	internal := m.RestartSettings()
	if internal[0] == "mutated" {
		t.Error("RestartSettings: returned a reference to internal slice, not a copy")
	}
}

func TestConfigManager_Start_StopCleanly(t *testing.T) {
	path := writeTempYAML(t, `server: {}`)
	m := NewConfigManager(path)
	stop := m.Start()
	// Must not block or panic
	stop()
}

// ─────────────────────────── categorizeChanges ───────────────────────────────

func TestCategorizeChanges_RestartRequired(t *testing.T) {
	restartTriggers := []string{
		"server.port",
		"server.address",
		"ssl.enabled",
		"ssl.cert",
		"ssl.key",
		"ssl.min_version",
		"server.daemonize",
		"database.path",
		"tor.enabled",
	}
	for _, trigger := range restartTriggers {
		hotReload, needsRestart := categorizeChanges([]string{trigger})
		if len(needsRestart) == 0 {
			t.Errorf("categorizeChanges(%q): want in needsRestart, got hotReload", trigger)
		}
		if len(hotReload) != 0 {
			t.Errorf("categorizeChanges(%q): should not be in hotReload", trigger)
		}
	}
}

func TestCategorizeChanges_RestartRequired_WholeSectionPrefixes(t *testing.T) {
	// AI.md PART 12's restartRequiredSettings treats ssl./database./tor. as
	// whole-section prefixes, not just the specific subkeys in the other
	// restart-required test above — any change within these sections must
	// recreate the TLS listener, connection pool, or Tor child process.
	restartTriggers := []string{
		"ssl.min_version",
		"ssl.hsts_max_age",
		"database.driver",
		"database.host",
		"tor.socks_port",
		"tor.control_port",
	}
	for _, trigger := range restartTriggers {
		hotReload, needsRestart := categorizeChanges([]string{trigger})
		if len(needsRestart) == 0 {
			t.Errorf("categorizeChanges(%q): want in needsRestart, got hotReload", trigger)
		}
		if len(hotReload) != 0 {
			t.Errorf("categorizeChanges(%q): should not be in hotReload", trigger)
		}
	}
}

func TestCategorizeChanges_HotReloadable(t *testing.T) {
	hotKeys := []string{
		"logging.level",
		"cors",
		"branding.title",
		"ratelimit.enabled",
	}
	for _, key := range hotKeys {
		hotReload, needsRestart := categorizeChanges([]string{key})
		if len(hotReload) == 0 {
			t.Errorf("categorizeChanges(%q): want in hotReload, got needsRestart", key)
		}
		if len(needsRestart) != 0 {
			t.Errorf("categorizeChanges(%q): should not be in needsRestart", key)
		}
	}
}

func TestCategorizeChanges_Mixed(t *testing.T) {
	changes := []string{"server.port", "logging.level", "cors"}
	hotReload, needsRestart := categorizeChanges(changes)
	if len(hotReload) != 2 {
		t.Errorf("categorizeChanges mixed: hotReload len: got %d, want 2", len(hotReload))
	}
	if len(needsRestart) != 1 {
		t.Errorf("categorizeChanges mixed: needsRestart len: got %d, want 1", len(needsRestart))
	}
}

func TestCategorizeChanges_Empty(t *testing.T) {
	hotReload, needsRestart := categorizeChanges(nil)
	if len(hotReload) != 0 || len(needsRestart) != 0 {
		t.Error("categorizeChanges(nil): want both slices empty")
	}
}

// ──────────────────────────── compareConfigs ─────────────────────────────────

func TestCompareConfigs_NoChanges(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	changes := compareConfigs(a, b)
	if len(changes) != 0 {
		t.Errorf("compareConfigs on identical configs: got changes %v", changes)
	}
}

func TestCompareConfigs_PortChange(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.Port = "9999"
	changes := compareConfigs(a, b)
	if !contains(changes, "server.port") {
		t.Errorf("compareConfigs: expected server.port in %v", changes)
	}
}

func TestCompareConfigs_AddressChange(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.Address = "0.0.0.0"
	changes := compareConfigs(a, b)
	if !contains(changes, "server.address") {
		t.Errorf("compareConfigs: expected server.address in %v", changes)
	}
}

func TestCompareConfigs_LoggingLevelChange(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.Logging.Level = "debug"
	changes := compareConfigs(a, b)
	if !contains(changes, "logging.level") {
		t.Errorf("compareConfigs: expected logging.level in %v", changes)
	}
}

func TestCompareConfigs_RateLimitChange(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.RateLimit.Enabled = false
	changes := compareConfigs(a, b)
	if !contains(changes, "ratelimit.enabled") {
		t.Errorf("compareConfigs: expected ratelimit.enabled in %v", changes)
	}
}

func TestCompareConfigs_CORSChange(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Web.CORS = "https://example.com"
	changes := compareConfigs(a, b)
	if !contains(changes, "cors") {
		t.Errorf("compareConfigs: expected cors in %v", changes)
	}
}

func TestCompareConfigs_BrandingChanges(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.Branding.Title = "My App"
	b.Server.Branding.Tagline = "Fast"
	b.Server.Branding.Description = "Desc"
	b.Server.Branding.LogoURL = "https://logo.png"
	b.Server.Branding.FaviconURL = "https://favicon.ico"
	b.Server.Branding.ThemeColor = "#ff0000"
	changes := compareConfigs(a, b)

	for _, key := range []string{"branding.title", "branding.tagline", "branding.description", "branding.logo_url", "branding.favicon_url", "branding.theme_color"} {
		if !contains(changes, key) {
			t.Errorf("compareConfigs: expected %q in %v", key, changes)
		}
	}
}

func TestCompareConfigs_RateLimitReadRequests(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.RateLimit.Read.Requests = 50
	changes := compareConfigs(a, b)
	if !contains(changes, "ratelimit.read.requests") {
		t.Errorf("compareConfigs: expected ratelimit.read.requests in %v", changes)
	}
}

func TestCompareConfigs_RateLimitReadWindow(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.RateLimit.Read.Window = 30
	changes := compareConfigs(a, b)
	if !contains(changes, "ratelimit.read.window") {
		t.Errorf("compareConfigs: expected ratelimit.read.window in %v", changes)
	}
}

func TestCompareConfigs_GlobalBurst(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	b.Server.RateLimit.GlobalBurst = 100
	changes := compareConfigs(a, b)
	if !contains(changes, "ratelimit.global_burst") {
		t.Errorf("compareConfigs: expected ratelimit.global_burst in %v", changes)
	}
}

// ────────────────────────────── loadConfigFromFile (internal) ─────────────────

func TestLoadConfigFromFileInternal_InvalidPath(t *testing.T) {
	_, err := loadConfigFromFile("/nonexistent/path/server.yml")
	if err == nil {
		t.Error("loadConfigFromFile non-existent: want error, got nil")
	}
}

func TestLoadConfigFromFileInternal_ValidYAML(t *testing.T) {
	path := writeTempYAML(t, `server:
  port: "4444"
`)
	cfg, err := loadConfigFromFile(path)
	if err != nil {
		t.Fatalf("loadConfigFromFile: %v", err)
	}
	if cfg.Server.Port != "4444" {
		t.Errorf("Port: got %q, want %q", cfg.Server.Port, "4444")
	}
}

// ──────────────────────────── applyConfigChanges (integration) ────────────────

func TestApplyConfigChanges_NilOldConfigNoOp(t *testing.T) {
	resetGlobals()
	m := &ConfigManager{}
	newCfg := DefaultConfig()
	// Must not panic when current == nil
	m.applyConfigChanges(newCfg)
}

func TestApplyConfigChanges_HotReloadUpdatesGlobal(t *testing.T) {
	resetGlobals()
	mu.Lock()
	base := DefaultConfig()
	current = base
	mu.Unlock()

	m := &ConfigManager{}
	newCfg := DefaultConfig()
	newCfg.Server.Logging.Level = "debug"
	m.applyConfigChanges(newCfg)

	got := getCurrentConfig()
	if got.Server.Logging.Level != "debug" {
		t.Errorf("applyConfigChanges hot-reload: Level: got %q, want debug", got.Server.Logging.Level)
	}
}

func TestApplyConfigChanges_RestartRequiredSetsFlag(t *testing.T) {
	resetGlobals()
	mu.Lock()
	base := DefaultConfig()
	current = base
	mu.Unlock()

	m := &ConfigManager{}
	newCfg := DefaultConfig()
	newCfg.Server.Port = "9999"
	m.applyConfigChanges(newCfg)

	if !m.PendingRestart() {
		t.Error("applyConfigChanges: port change should set pendingRestart")
	}
	settings := m.RestartSettings()
	if !contains(settings, "server.port") {
		t.Errorf("applyConfigChanges: server.port not in restartSettings: %v", settings)
	}
}

func TestApplyConfigChanges_NoChangesNoRestart(t *testing.T) {
	resetGlobals()
	mu.Lock()
	base := DefaultConfig()
	current = base
	mu.Unlock()

	m := &ConfigManager{}
	identical := DefaultConfig()
	m.applyConfigChanges(identical)

	if m.PendingRestart() {
		t.Error("applyConfigChanges with no changes: should not set pendingRestart")
	}
}

// ───────────────────────────── IsDebug / Get ─────────────────────────

func TestAppConfig_IsDebug_EnvUnset(t *testing.T) {
	os.Unsetenv("DEBUG")
	cfg := DefaultConfig()
	if cfg.IsDebug() {
		t.Error("IsDebug() should be false when DEBUG env is unset")
	}
}

func TestAppConfig_IsDebug_EnvSet(t *testing.T) {
	os.Setenv("DEBUG", "1")
	t.Cleanup(func() { os.Unsetenv("DEBUG") })

	cfg := DefaultConfig()
	if !cfg.IsDebug() {
		t.Error("IsDebug() should be true when DEBUG=1")
	}
}

func TestGet_ReturnsCurrentConfig(t *testing.T) {
	resetGlobals()
	mu.Lock()
	current = DefaultConfig()
	current.Server.Port = "9999"
	mu.Unlock()

	got := Get()
	if got.Server.Port != "9999" {
		t.Errorf("Get().Server.Port = %s, want 9999", got.Server.Port)
	}
}

func TestPrivacyConfig_GetConsentMessage(t *testing.T) {
	cfg := DefaultConfig()
	msg := cfg.Server.Privacy.GetConsentMessage()
	if msg == "" {
		t.Error("GetConsentMessage() should not be empty")
	}
}

func TestPrivacyConfig_GetAnalyticsDescription(t *testing.T) {
	cfg := DefaultConfig()
	desc := cfg.Server.Privacy.GetAnalyticsDescription()
	if desc == "" {
		t.Error("GetAnalyticsDescription() should not be empty")
	}
}

func TestPrivacyConfig_GetDataUsageContent(t *testing.T) {
	cfg := DefaultConfig()
	// Just call it to increase coverage; content may be empty in default config
	_ = cfg.Server.Privacy.GetDataUsageContent()
}

func TestPrivacyConfig_IsCCPAApplicable(t *testing.T) {
	cfg := DefaultConfig()
	// Should not panic; result depends on default config
	_ = cfg.Server.Privacy.IsCCPAApplicable()
}

// ───────────────────────────── TorIdentityConfig ─────────────────────────────

func TestTorIdentityConfig_DefaultEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Tor.OnionAddress != "" {
		t.Errorf("Tor.OnionAddress default = %q, want empty", cfg.Tor.OnionAddress)
	}
	if cfg.Tor.ContactEmail != "" {
		t.Errorf("Tor.ContactEmail default = %q, want empty", cfg.Tor.ContactEmail)
	}
}

func TestTorIdentityConfig_YAMLRoundTrip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tor.OnionAddress = "abc123def456.onion"
	cfg.Tor.ContactEmail = "contact@abc123def456.onion"

	yaml := generateConfigYAML(cfg)
	if !strings.Contains(yaml, "abc123def456.onion") {
		t.Error("generated YAML missing onion_address value")
	}
	if !strings.Contains(yaml, "contact@abc123def456.onion") {
		t.Error("generated YAML missing contact_email value")
	}
}

func TestTorIdentityConfig_IsTopLevelKey(t *testing.T) {
	empty := AppConfig{}
	yaml := generateConfigYAML(&empty)
	if !strings.Contains(yaml, "\ntor:\n") {
		t.Error("generated YAML is missing top-level 'tor:' section")
	}
}

// ───────────────────────────── validateConfig ─────────────────────────────────

func TestValidateConfig_InvalidCacheType_ResetToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Cache.Type = "bogus"
	validateConfig(cfg)
	if cfg.Server.Cache.Type != DefaultConfig().Server.Cache.Type {
		t.Errorf("Cache.Type = %q, want default", cfg.Server.Cache.Type)
	}
}

func TestValidateConfig_ValidCacheTypes_Preserved(t *testing.T) {
	for _, ct := range []string{"none", "memory", "valkey", "redis"} {
		cfg := DefaultConfig()
		cfg.Server.Cache.Type = ct
		validateConfig(cfg)
		if cfg.Server.Cache.Type != ct {
			t.Errorf("Cache.Type = %q, want preserved %q", cfg.Server.Cache.Type, ct)
		}
	}
}

func TestValidateConfig_NonPositivePoolSize_ResetToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Cache.PoolSize = 0
	validateConfig(cfg)
	if cfg.Server.Cache.PoolSize != DefaultConfig().Server.Cache.PoolSize {
		t.Errorf("Cache.PoolSize = %d, want default", cfg.Server.Cache.PoolSize)
	}
}

func TestValidateConfig_PositivePoolSize_Preserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Cache.PoolSize = 42
	validateConfig(cfg)
	if cfg.Server.Cache.PoolSize != 42 {
		t.Errorf("Cache.PoolSize = %d, want 42", cfg.Server.Cache.PoolSize)
	}
}

func TestValidateConfig_DiskThresholdOutOfRange_ResetToDefault(t *testing.T) {
	for _, v := range []int{0, -1, 101} {
		cfg := DefaultConfig()
		cfg.Server.Maintenance.Cleanup.DiskThreshold = v
		validateConfig(cfg)
		if cfg.Server.Maintenance.Cleanup.DiskThreshold != DefaultConfig().Server.Maintenance.Cleanup.DiskThreshold {
			t.Errorf("DiskThreshold(%d) = %d, want default", v, cfg.Server.Maintenance.Cleanup.DiskThreshold)
		}
	}
}

func TestValidateConfig_DiskThresholdInRange_Preserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Maintenance.Cleanup.DiskThreshold = 50
	validateConfig(cfg)
	if cfg.Server.Maintenance.Cleanup.DiskThreshold != 50 {
		t.Errorf("DiskThreshold = %d, want 50", cfg.Server.Maintenance.Cleanup.DiskThreshold)
	}
}

func TestValidateConfig_NonPositiveLogRetentionDays_ResetToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Maintenance.Cleanup.LogRetentionDays = 0
	validateConfig(cfg)
	if cfg.Server.Maintenance.Cleanup.LogRetentionDays != DefaultConfig().Server.Maintenance.Cleanup.LogRetentionDays {
		t.Errorf("LogRetentionDays = %d, want default", cfg.Server.Maintenance.Cleanup.LogRetentionDays)
	}
}

func TestValidateConfig_PositiveLogRetentionDays_Preserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Maintenance.Cleanup.LogRetentionDays = 30
	validateConfig(cfg)
	if cfg.Server.Maintenance.Cleanup.LogRetentionDays != 30 {
		t.Errorf("LogRetentionDays = %d, want 30", cfg.Server.Maintenance.Cleanup.LogRetentionDays)
	}
}

func TestValidateConfig_InvalidDatabaseDriver_ResetToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Database.Driver = "bogus"
	validateConfig(cfg)
	if cfg.Server.Database.Driver != DefaultConfig().Server.Database.Driver {
		t.Errorf("Database.Driver = %q, want default", cfg.Server.Database.Driver)
	}
}

func TestValidateConfig_ValidDatabaseDrivers_Preserved(t *testing.T) {
	for _, d := range []string{"sqlite", "sqlite2", "sqlite3", "libsql", "turso"} {
		cfg := DefaultConfig()
		cfg.Server.Database.Driver = d
		validateConfig(cfg)
		if cfg.Server.Database.Driver != d {
			t.Errorf("Database.Driver = %q, want preserved %q", cfg.Server.Database.Driver, d)
		}
	}
}

func TestValidateConfig_InvalidLoggingLevel_ResetToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Logging.Level = "bogus"
	validateConfig(cfg)
	if cfg.Server.Logging.Level != DefaultConfig().Server.Logging.Level {
		t.Errorf("Logging.Level = %q, want default", cfg.Server.Logging.Level)
	}
}

func TestValidateConfig_ValidLoggingLevels_Preserved(t *testing.T) {
	for _, l := range []string{"error", "warn", "info", "debug"} {
		cfg := DefaultConfig()
		cfg.Server.Logging.Level = l
		validateConfig(cfg)
		if cfg.Server.Logging.Level != l {
			t.Errorf("Logging.Level = %q, want preserved %q", cfg.Server.Logging.Level, l)
		}
	}
}

func TestValidateConfig_EmptyMode_ResetToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Mode = ""
	validateConfig(cfg)
	if cfg.Server.Mode != DefaultConfig().Server.Mode {
		t.Errorf("Server.Mode = %q, want default", cfg.Server.Mode)
	}
}

func TestValidateConfig_NonEmptyMode_Preserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Mode = "development"
	validateConfig(cfg)
	if cfg.Server.Mode != "development" {
		t.Errorf("Server.Mode = %q, want preserved", cfg.Server.Mode)
	}
}

func TestValidateConfig_EmptyKeyservers_ResetToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Web.Security.Keyservers = nil
	validateConfig(cfg)
	if len(cfg.Web.Security.Keyservers) == 0 {
		t.Error("Web.Security.Keyservers is empty, want reset to default")
	}
}

func TestValidateConfig_NonEmptyKeyservers_Preserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Web.Security.Keyservers = []string{"custom.example.com"}
	validateConfig(cfg)
	if len(cfg.Web.Security.Keyservers) != 1 || cfg.Web.Security.Keyservers[0] != "custom.example.com" {
		t.Errorf("Web.Security.Keyservers = %v, want preserved custom value", cfg.Web.Security.Keyservers)
	}
}

// ─────────────────────── PrivacyConfig accessors ──────────────────────────────

func TestGetConsentMessage_NotSold(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: false}, Consent: ConsentConfig{Message: "not sold msg", MessageIfSold: "sold msg"}}
	if got := p.GetConsentMessage(); got != "not sold msg" {
		t.Errorf("GetConsentMessage() = %q, want %q", got, "not sold msg")
	}
}

func TestGetConsentMessage_Sold(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: true}, Consent: ConsentConfig{Message: "not sold msg", MessageIfSold: "sold msg"}}
	if got := p.GetConsentMessage(); got != "sold msg" {
		t.Errorf("GetConsentMessage() = %q, want %q", got, "sold msg")
	}
}

func TestGetDataUsageContent_NotSold(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: false}, Content: PrivacyContent{DataUsage: "not sold content", DataUsageIfSold: "sold content"}}
	if got := p.GetDataUsageContent(); got != "not sold content" {
		t.Errorf("GetDataUsageContent() = %q, want %q", got, "not sold content")
	}
}

func TestGetDataUsageContent_Sold(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: true}, Content: PrivacyContent{DataUsage: "not sold content", DataUsageIfSold: "sold content"}}
	if got := p.GetDataUsageContent(); got != "sold content" {
		t.Errorf("GetDataUsageContent() = %q, want %q", got, "sold content")
	}
}

func TestGetAnalyticsDescription_NotSold(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: false}}
	p.Cookies.Analytics.Description = "base desc"
	p.Cookies.Analytics.DescriptionSuffixNotSold = "not sold suffix"
	p.Cookies.Analytics.DescriptionSuffixSold = "sold suffix"
	want := "base desc not sold suffix"
	if got := p.GetAnalyticsDescription(); got != want {
		t.Errorf("GetAnalyticsDescription() = %q, want %q", got, want)
	}
}

func TestGetAnalyticsDescription_Sold(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: true}}
	p.Cookies.Analytics.Description = "base desc"
	p.Cookies.Analytics.DescriptionSuffixNotSold = "not sold suffix"
	p.Cookies.Analytics.DescriptionSuffixSold = "sold suffix"
	want := "base desc sold suffix"
	if got := p.GetAnalyticsDescription(); got != want {
		t.Errorf("GetAnalyticsDescription() = %q, want %q", got, want)
	}
}

func TestIsCCPAApplicable_True(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: true}}
	if !p.IsCCPAApplicable() {
		t.Error("IsCCPAApplicable() = false, want true when Data.Sold is true")
	}
}

func TestIsCCPAApplicable_False(t *testing.T) {
	p := &PrivacyConfig{Data: DataPolicy{Sold: false}}
	if p.IsCCPAApplicable() {
		t.Error("IsCCPAApplicable() = true, want false when Data.Sold is false")
	}
}

func TestTrackingConfig_TypeName_Known(t *testing.T) {
	tr := TrackingConfig{Type: "plausible"}
	if got := tr.TypeName(); got != "Plausible Analytics" {
		t.Errorf("TypeName() = %q, want %q", got, "Plausible Analytics")
	}
}

func TestTrackingConfig_TypeName_Unknown(t *testing.T) {
	tr := TrackingConfig{Type: "not-a-real-provider"}
	if got := tr.TypeName(); got != "" {
		t.Errorf("TypeName() = %q, want empty string for unrecognized type", got)
	}
}

func TestTrackingConfig_TypeName_Empty(t *testing.T) {
	tr := TrackingConfig{}
	if got := tr.TypeName(); got != "" {
		t.Errorf("TypeName() = %q, want empty string when tracking disabled", got)
	}
}

// ─────────────────────────── validateAllowlist ────────────────────────────────

func TestValidateAllowlist_RejectsOverlyBroadUnconfirmed(t *testing.T) {
	entries := []AllowlistEntry{
		{CIDR: "10.0.0.0/8", Description: "narrow v4, kept"},
		{CIDR: "0.0.0.0/0", Description: "broad v4, unconfirmed, dropped"},
		{CIDR: "1.0.0.0/7", Description: "broad v4 boundary, unconfirmed, dropped"},
		{CIDR: "::/0", Description: "broad v6, unconfirmed, dropped"},
		{CIDR: "2001:db8::/15", Description: "broad v6 boundary, unconfirmed, dropped"},
		{CIDR: "2001:db8::/16", Description: "narrow v6 boundary, kept"},
		{CIDR: "2001:db8::/48", Description: "narrow v6, kept"},
		{CIDR: "203.0.113.50", Description: "bare v4 IP, kept"},
	}
	got := validateAllowlist(entries)
	want := []string{"10.0.0.0/8", "2001:db8::/16", "2001:db8::/48", "203.0.113.50"}
	if len(got) != len(want) {
		t.Fatalf("validateAllowlist() kept %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].CIDR != w {
			t.Errorf("entry %d: CIDR = %q, want %q", i, got[i].CIDR, w)
		}
	}
}

func TestValidateAllowlist_KeepsBroadWhenConfirmed(t *testing.T) {
	entries := []AllowlistEntry{
		{CIDR: "0.0.0.0/0", Description: "broad v4, confirmed", Confirmed: true},
		{CIDR: "::/0", Description: "broad v6, confirmed", Confirmed: true},
	}
	got := validateAllowlist(entries)
	if len(got) != 2 {
		t.Fatalf("validateAllowlist() kept %d entries, want 2: %+v", len(got), got)
	}
}

func TestIsOverlyBroadAllowlistRange(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"10.0.0.0/8", false},
		{"1.0.0.0/7", true},
		{"0.0.0.0/0", true},
		{"192.168.1.0/24", false},
		{"2001:db8::/15", true},
		{"2001:db8::/16", false},
		{"::/0", true},
		{"203.0.113.50", false},
		{"2001:db8::1", false},
		{"not-a-cidr", false},
	}
	for _, c := range cases {
		if got := isOverlyBroadAllowlistRange(c.cidr); got != c.want {
			t.Errorf("isOverlyBroadAllowlistRange(%q) = %v, want %v", c.cidr, got, c.want)
		}
	}
}

// ───────────────────────────── helper ────────────────────────────────────────

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
