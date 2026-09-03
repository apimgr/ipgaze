package config

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete server configuration
// TorIdentityConfig holds the public-facing Tor hidden service identity per AI.md PART 12.
// These are separate from the operational Tor settings under server.tor.
// They control how the server presents itself to clients connecting over Tor.
type TorIdentityConfig struct {
	// OnionAddress is the .onion hostname (without http:// prefix).
	// When set, requests with this Host header are treated as Tor requests.
	// Request detection is priority 0 — evaluated before proxy headers, always trusted.
	OnionAddress string `yaml:"onion_address"`
	// ContactEmail is shown on Tor-served pages (security.txt, contact pages, error pages).
	// When unset, no email is shown — never falls back to the clearnet contact email.
	ContactEmail string `yaml:"contact_email"`
}

type AppConfig struct {
	Server ServerConfig      `yaml:"server"`
	Tor    TorIdentityConfig `yaml:"tor"`
	Web    WebConfig         `yaml:"web"`
	Data   DataConfig        `yaml:"data"`
}

// DataConfig contains data source configuration per AI.md PART 20
// "Default Data Sources (Non-GeoIP)". GeoIP and blocklist sources live
// under server.geoip / server.security.blocklists respectively.
type DataConfig struct {
	CVE CVEDataConfig `yaml:"cve"`
}

// CVEDataConfig configures the CVE (NVD) feed per AI.md PART 20.
type CVEDataConfig struct {
	// Source is the CVE feed URL. Empty means use the compiled-in
	// NVD CVE API 2.0 default (cve.NVDAPIURL).
	Source string `yaml:"source"`
	// FilterByCPE would restrict downloads to CVEs relevant to the
	// project's own dependencies. Left false by default: no verified
	// mapping from Go module paths to CPE (Common Platform Enumeration)
	// strings exists, so filtering could silently drop a real CVE
	// affecting a real dependency. See AI.md PART 20.
	FilterByCPE bool `yaml:"filter_by_cpe"`
}

// WebConfig holds all web-layer settings per AI.md PART 16.
// YAML key: web (nested: web.ui, web.robots, web.cors, web.csrf, web.security).
type WebConfig struct {
	UI       WebUIConfig       `yaml:"ui"`
	Robots   WebRobotsConfig   `yaml:"robots"`
	CORS     string            `yaml:"cors"`
	CSRF     CSRFConfig        `yaml:"csrf"`
	Security WebSecurityConfig `yaml:"security"`
	Footer   FooterConfig      `yaml:"footer"`
	// HSTS controls the Strict-Transport-Security header (AI.md PART 11
	// "Security Header Config").
	HSTS HSTSConfig `yaml:"hsts"`
	// PermissionsPolicy maps a browser feature name to its allowlist value
	// ("()" to deny everywhere, "(self)" to allow same-origin). An empty value
	// omits the feature so the browser default applies (AI.md PART 11
	// "Generation rule").
	PermissionsPolicy map[string]string `yaml:"permissions_policy"`
	// CSP controls the Content-Security-Policy header.
	CSP CSPConfig `yaml:"csp"`
	// Headers holds the modern / privacy / cross-origin response headers.
	Headers SecurityHeadersConfig `yaml:"headers"`
	// Reports controls the public browser-report endpoints.
	Reports ReportsConfig `yaml:"reports"`
}

// HSTSConfig controls Strict-Transport-Security per AI.md PART 11.
// The header is only emitted when SSL is enabled.
type HSTSConfig struct {
	// Enabled gates the header. Set false only for HTTP-only deployments.
	Enabled bool `yaml:"enabled"`
	// MaxAgeSeconds defaults to 63072000 (2 years, preload-list eligible).
	MaxAgeSeconds int `yaml:"max_age_seconds"`
	// IncludeSubdomains appends "; includeSubDomains".
	IncludeSubdomains bool `yaml:"include_subdomains"`
	// Preload appends "; preload" for public preload-list submission.
	Preload bool `yaml:"preload"`
}

// CSPConfig controls the Content-Security-Policy header per AI.md PART 11
// "Configuration (per-directive append)". Each *Extra value is appended to the
// built-in default for that directive; each *Override replaces it outright.
type CSPConfig struct {
	// Enabled emits the header at all.
	Enabled bool `yaml:"enabled"`
	// Mode is "enforce" or "report-only". Empty means automatic: report-only in
	// development/debug, enforcing otherwise.
	Mode string `yaml:"mode"`
	// e.g. "https://js.stripe.com https://www.google.com/recaptcha/"
	ScriptSrcExtra string `yaml:"script_src_extra"`
	// e.g. "https://fonts.googleapis.com"
	StyleSrcExtra string `yaml:"style_src_extra"`
	// Rarely needed — the default already covers https:
	ImgSrcExtra string `yaml:"img_src_extra"`
	// Rarely needed — the default already covers https:
	FontSrcExtra string `yaml:"font_src_extra"`
	// e.g. "https://api.stripe.com wss://realtime.example.com"
	ConnectSrcExtra string `yaml:"connect_src_extra"`
	// e.g. "https://www.youtube.com https://player.vimeo.com"
	FrameSrcExtra string `yaml:"frame_src_extra"`
	// e.g. "https://accounts.google.com" for OAuth submit
	FormActionExtra string `yaml:"form_action_extra"`
	// Override-style keys REPLACE the directive instead of appending.
	ScriptSrcOverride string `yaml:"script_src_override"`
	// Replaces style-src entirely.
	StyleSrcOverride string `yaml:"style_src_override"`
	// Replaces img-src entirely.
	ImgSrcOverride string `yaml:"img_src_override"`
	// Replaces font-src entirely.
	FontSrcOverride string `yaml:"font_src_override"`
	// Replaces connect-src entirely.
	ConnectSrcOverride string `yaml:"connect_src_override"`
	// Replaces frame-src entirely.
	FrameSrcOverride string `yaml:"frame_src_override"`
	// Replaces form-action entirely.
	FormActionOverride string `yaml:"form_action_override"`
	// ReportsEnabled POSTs violations to the CSP report endpoint.
	ReportsEnabled bool `yaml:"reports_enabled"`
	// ReportsSampleRate is 0.0..1.0 — sample to control volume on busy sites.
	ReportsSampleRate float64 `yaml:"reports_sample_rate"`
}

// ClearSiteDataConfig controls when the Clear-Site-Data header is emitted per
// AI.md PART 11.
type ClearSiteDataConfig struct {
	// OnTokenRevocation clears client state when a token is revoked.
	OnTokenRevocation bool `yaml:"on_token_revocation"`
	// OnConsentWithdrawal clears client state when consent is withdrawn.
	OnConsentWithdrawal bool `yaml:"on_consent_withdrawal"`
	// ExecutionContexts also reloads open SPA tabs on token revocation.
	ExecutionContexts bool `yaml:"execution_contexts"`
}

// NELConfig controls the Network Error Logging policy header per AI.md PART 11.
type NELConfig struct {
	// Enabled emits the NEL header.
	Enabled bool `yaml:"enabled"`
	// MaxAgeSeconds defaults to 2592000 (30 days).
	MaxAgeSeconds int `yaml:"max_age_seconds"`
	// IncludeSubdomains applies the policy to subdomains too.
	IncludeSubdomains bool `yaml:"include_subdomains"`
	// SampleRate is 0.0..1.0 — sample failures to control report volume.
	SampleRate float64 `yaml:"sample_rate"`
}

// SecurityHeadersConfig holds the modern / privacy / cross-origin response
// headers under web.headers per AI.md PART 11 "Security Header Config".
// An empty string value means "omit the header, browser default applies".
type SecurityHeadersConfig struct {
	// ContentTypeOptions sets X-Content-Type-Options.
	ContentTypeOptions string `yaml:"content_type_options"`
	// FrameOptions sets X-Frame-Options.
	FrameOptions string `yaml:"frame_options"`
	// XSSProtection sets the legacy X-XSS-Protection header.
	XSSProtection string `yaml:"xss_protection"`
	// ReferrerPolicy sets Referrer-Policy.
	ReferrerPolicy string `yaml:"referrer_policy"`
	// COOP sets Cross-Origin-Opener-Policy.
	COOP string `yaml:"coop"`
	// COEP sets Cross-Origin-Embedder-Policy.
	COEP string `yaml:"coep"`
	// CORP sets Cross-Origin-Resource-Policy.
	CORP string `yaml:"corp"`
	// OriginAgentCluster emits "Origin-Agent-Cluster: ?1".
	OriginAgentCluster bool `yaml:"origin_agent_cluster"`
	// CrossDomainPolicies sets X-Permitted-Cross-Domain-Policies.
	CrossDomainPolicies string `yaml:"cross_domain_policies"`
	// DNSPrefetchControl sets X-DNS-Prefetch-Control; "" omits it,
	// "off" is privacy-strict.
	DNSPrefetchControl string `yaml:"dns_prefetch_control"`
	// HonorSecGPC treats "Sec-GPC: 1" as an opt-out signal.
	HonorSecGPC bool `yaml:"honor_sec_gpc"`
	// HonorDNT honours the legacy DNT header; dead in modern browsers.
	HonorDNT bool `yaml:"honor_dnt"`
	// SecFetchValidation rejects cross-site state-changing requests.
	SecFetchValidation bool `yaml:"sec_fetch_validation"`
	// ServerTimingInDebugOnly keeps Server-Timing out of production responses.
	ServerTimingInDebugOnly bool `yaml:"server_timing_in_debug_only"`
	// ClearSiteData controls the Clear-Site-Data header.
	ClearSiteData ClearSiteDataConfig `yaml:"clear_site_data"`
	// NEL controls the Network Error Logging policy header.
	NEL NELConfig `yaml:"nel"`
}

// ReportsConfig limits the public browser-report endpoints per AI.md PART 11
// "Security Header Config" → web.reports.
type ReportsConfig struct {
	// RateLimitPerMinute is the maximum reports per minute per IP across all
	// report types.
	RateLimitPerMinute int `yaml:"rate_limit_per_minute"`
	// RateLimitPerIPBurst is the short-burst allowance per IP.
	RateLimitPerIPBurst int `yaml:"rate_limit_per_ip_burst"`
}

// DefaultHSTSConfig returns the AI.md PART 11 Strict-Transport-Security
// defaults: 2 years, subdomains included, preload-list eligible.
func DefaultHSTSConfig() HSTSConfig {
	return HSTSConfig{
		Enabled:           true,
		MaxAgeSeconds:     63072000,
		IncludeSubdomains: true,
		Preload:           true,
	}
}

// DefaultCSPConfig returns the AI.md PART 11 CSP defaults. Mode is left empty
// so development runs report-only and production enforces.
func DefaultCSPConfig() CSPConfig {
	return CSPConfig{
		Enabled:           true,
		Mode:              "",
		ReportsEnabled:    true,
		ReportsSampleRate: 1.0,
	}
}

// DefaultSecurityHeaders returns the AI.md PART 11 defaults for web.headers.
func DefaultSecurityHeaders() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentTypeOptions:      "nosniff",
		FrameOptions:            "SAMEORIGIN",
		XSSProtection:           "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		COOP:                    "unsafe-none",
		COEP:                    "unsafe-none",
		CORP:                    "cross-origin",
		OriginAgentCluster:      true,
		CrossDomainPolicies:     "none",
		DNSPrefetchControl:      "",
		HonorSecGPC:             true,
		HonorDNT:                false,
		SecFetchValidation:      true,
		ServerTimingInDebugOnly: true,
		ClearSiteData: ClearSiteDataConfig{
			OnTokenRevocation:   true,
			OnConsentWithdrawal: true,
			ExecutionContexts:   false,
		},
		NEL: NELConfig{
			Enabled:           true,
			MaxAgeSeconds:     2592000,
			IncludeSubdomains: true,
			SampleRate:        1.0,
		},
	}
}

// DefaultReportsConfig returns the AI.md PART 11 web.reports rate limits.
func DefaultReportsConfig() ReportsConfig {
	return ReportsConfig{
		RateLimitPerMinute:  60,
		RateLimitPerIPBurst: 10,
	}
}

// DefaultDatabasePoolConfig returns the AI.md PART 10 pool defaults for the
// single-writer SQLite deployment this project ships with.
func DefaultDatabasePoolConfig() DatabasePoolConfig {
	return DatabasePoolConfig{
		MaxOpen:     5,
		MaxIdle:     2,
		MaxLifetime: "5m",
		MaxIdleTime: "1m",
	}
}

// DefaultPermissionsPolicy returns the AI.md PART 11 Permissions-Policy
// feature allowlist. "()" denies the feature everywhere; "(self)" allows it
// same-origin only.
func DefaultPermissionsPolicy() map[string]string {
	return map[string]string{
		"accelerometer":                   "()",
		"ambient-light-sensor":            "()",
		"attribution-reporting":           "()",
		"autoplay":                        "(self)",
		"battery":                         "()",
		"browsing-topics":                 "()",
		"camera":                          "()",
		"cross-origin-isolated":           "()",
		"display-capture":                 "()",
		"document-domain":                 "()",
		"encrypted-media":                 "(self)",
		"execution-while-not-rendered":    "()",
		"execution-while-out-of-viewport": "()",
		"fullscreen":                      "(self)",
		"geolocation":                     "()",
		"gyroscope":                       "()",
		"interest-cohort":                 "()",
		"keyboard-map":                    "()",
		"magnetometer":                    "()",
		"microphone":                      "()",
		"midi":                            "()",
		"navigation-override":             "()",
		"payment":                         "(self)",
		"picture-in-picture":              "(self)",
		"publickey-credentials-get":       "(self)",
		"screen-wake-lock":                "()",
		"storage-access":                  "(self)",
		"sync-xhr":                        "()",
		"usb":                             "()",
		"web-share":                       "(self)",
		"xr-spatial-tracking":             "()",
	}
}

// FooterConfig controls operator-supplied footer branding per AI.md PART 16
// "Footer Customization". CustomHTML sits above the built-in Application
// Footer and is sanitized before rendering (see src/config/footer.go).
type FooterConfig struct {
	// CustomHTML is operator branding HTML rendered above the Application
	// Footer. Semantics per AI.md PART 16:
	//   - unset / "" : use the default built-in branding row
	//   - " " (single space): disable branding, show only the Application Footer
	//   - any other value: render this sanitized HTML in place of default branding
	// The value is always sanitized (bluemonday strict policy) before rendering;
	// scripts, event handlers, javascript: URLs, and the style attribute are stripped.
	CustomHTML string `yaml:"custom_html"`
}

// WebSecurityConfig controls the security.txt / GPG keypair surface per AI.md PART 11.
type WebSecurityConfig struct {
	// Keyservers are the HTTP submission endpoints the project's PGP public key
	// is published to on generate/rotate/publish (e.g. keys.openpgp.org).
	Keyservers []string `yaml:"keyservers"`
	// PublishPGPKey gates whether the Encryption: line is advertised in security.txt
	// and whether /.well-known/pgp-key.asc is served. Set false by `--maintenance pgp delete`.
	PublishPGPKey bool `yaml:"publish_pgp_key"`
	// Contact is the secondary/CC mailto address for security.txt and the PGP
	// key identity ("{app_name} Security <{contact}>"), per AI.md PART 11.
	// Never the primary reporting channel — see report_url.
	Contact string `yaml:"contact"`
}

// ServerConfig contains server-related settings
type ServerConfig struct {
	// Token is the operator token (server.token).
	// Auto-generated on first run, stored in server.yml.
	// Never stored in the DB — validated via SHA-256 hash comparison in memory.
	Token        string       `yaml:"token"`
	Port         string       `yaml:"port"`
	FQDN         string       `yaml:"fqdn"`
	BaseURL      string       `yaml:"baseurl"`
	Address      string       `yaml:"address"`
	Mode         string       `yaml:"mode"`
	UpdateBranch string       `yaml:"update_branch"`
	Update       UpdateConfig `yaml:"update"`
	// CLIMinVersion is the minimum CLI version the server accepts (AI.md PART 32).
	// CLIs older than this version are refused until updated.
	CLIMinVersion string `yaml:"cli_min_version"`
	// Daemonize forks the process and detaches from the terminal on startup.
	// Default false — modern service managers (systemd, launchd, runit) prefer foreground.
	// Ignored when started via --service start (service manager controls daemonization).
	Daemonize      bool                      `yaml:"daemonize"`
	Database       DatabaseConfig            `yaml:"database"`
	Schedule       ScheduleConfig            `yaml:"schedule"`
	Metrics        MetricsConfig             `yaml:"metrics"`
	Logging        LoggingConfig             `yaml:"logging"`
	GeoIP          GeoIPConfig               `yaml:"geoip"`
	Security       SecurityConfig            `yaml:"security"`
	Tor            TorConfig                 `yaml:"tor"`
	I2P            I2PConfig                 `yaml:"i2p"`
	I18n           I18nConfig                `yaml:"i18n"`
	Healthz        HealthzConfig             `yaml:"healthz"`
	Contact        ContactConfig             `yaml:"contact"`
	Tracking       TrackingConfig            `yaml:"tracking"`
	Privacy        PrivacyConfig             `yaml:"privacy"`
	Cache          CacheConfig               `yaml:"cache"`
	SSL            SSLConfig                 `yaml:"ssl"`
	Maintenance    MaintenanceConfig         `yaml:"maintenance"`
	Branding       BrandingConfig            `yaml:"branding"`
	SEO            SEOConfig                 `yaml:"seo"`
	RateLimit      RateLimitConfig           `yaml:"rate_limit"`
	Limits         LimitsConfig              `yaml:"limits"`
	Compression    CompressionConfig         `yaml:"compression"`
	TrustedProxies TrustedProxiesConfig      `yaml:"trusted_proxies"`
	URLDetection   URLDetectionConfig        `yaml:"url_detection"`
	Notifications  ServerNotificationsConfig `yaml:"notifications"`
	Backup         BackupConfig              `yaml:"backup"`
	Compliance     ComplianceConfig          `yaml:"compliance"`
	CLI            CLIConfig                 `yaml:"cli"`
	Debug          DebugConfig               `yaml:"debug"`
}

// DebugConfig contains debug-only diagnostic settings per AI.md PART 6.
// Every setting here is gated by the debug flag (--debug CLI > DEBUG env >
// MODE=debug alias) — NOT by development mode — and has no effect at all
// unless AppConfig.IsDebug() is also true.
type DebugConfig struct {
	// Pprof enables the /debug/pprof/* profiling endpoints.
	Pprof bool `yaml:"pprof"`
	// LogQueries logs every SQL query's text, args, duration, and error.
	LogQueries bool `yaml:"log_queries"`
	// LogCache logs cache operations (hits, misses, evictions).
	LogCache bool `yaml:"log_cache"`
	// LogBodies logs request/response bodies, capped at MaxBodyLogSize.
	LogBodies bool `yaml:"log_bodies"`
	// MaxBodyLogSize caps how much of a request/response body is logged
	// (e.g. "10KB"). Only meaningful when LogBodies is true.
	MaxBodyLogSize string `yaml:"max_body_log_size"`
	// BlockProfileRate sets runtime.SetBlockProfileRate. 0 disables block profiling.
	BlockProfileRate int `yaml:"block_profile_rate"`
	// MutexProfileFraction sets runtime.SetMutexProfileFraction. 0 disables mutex profiling.
	MutexProfileFraction int `yaml:"mutex_profile_fraction"`
	// RuntimeEndpoints enables the non-pprof /debug/* endpoints (vars, config,
	// routes, cache, db, scheduler, memory, goroutines).
	RuntimeEndpoints bool `yaml:"runtime_endpoints"`
}

// MaxBodyLogSizeBytes parses MaxBodyLogSize (e.g. "10KB") into a byte count.
// Returns the AI.md-documented default of 10KB if unset or invalid.
func (d DebugConfig) MaxBodyLogSizeBytes() int64 {
	n, err := ParseByteSize(d.MaxBodyLogSize)
	if err != nil || n <= 0 {
		return 10 * 1024
	}
	return n
}

// ParseByteSize parses sizes like "500B", "10KB", "5MB", "1GB", "1TB", or a
// plain byte count, per AI.md PART 6's max_body_log_size format.
func ParseByteSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "TB"):
		mult = 1 << 40
		s = strings.TrimSuffix(s, "TB")
	case strings.HasSuffix(s, "GB"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	return int64(n * float64(mult)), nil
}

// HealthzConfig controls the /healthz endpoint behaviour.
type HealthzConfig struct {
	Root RootHealthzConfig `yaml:"root"`
}

// RootHealthzConfig controls whether the root healthz endpoint is enabled.
type RootHealthzConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ContactConfig holds contact addresses for the four standard contact roles per AI.md PART 12.
// Roles: admin (internal alerts), security (vulnerability reports), abuse (policy violations),
// general (public contact form). Empty role email falls back to admin email.
type ContactConfig struct {
	Admin    ContactEntry `yaml:"admin"`
	Security ContactEntry `yaml:"security"`
	// Abuse receives spam/harassment/DMCA/TOS-violation reports.
	// Default "" — never auto-advertised (unlike security@); operator must opt in.
	Abuse   ContactEntry `yaml:"abuse"`
	General ContactEntry `yaml:"general"`
}

// ContactEntry holds an email address and optional webhook transports for a contact role.
type ContactEntry struct {
	Email    string         `yaml:"email"`
	Webhooks WebhooksConfig `yaml:"webhooks"`
}

// ResolvedContact is the effective email + per-transport webhook URL/secret
// pairs for a contact role, after applying AI.md PART 12's fallback chains.
// Computed fresh per call — never cached — so a live config edit takes
// effect on the very next dispatch.
type ResolvedContact struct {
	Email                        string
	Telegram, TelegramSecret     string
	Discord, DiscordSecret       string
	Slack, SlackSecret           string
	Mattermost, MattermostSecret string
	Pushover, PushoverSecret     string
	Gotify, GotifySecret         string
	Generic, GenericSecret       string
}

// ResolveContactRole resolves the effective email and webhook set for one of
// the four standard contact roles ("admin", "security", "abuse", "general"),
// applying the fallback chains in AI.md PART 12 → "Resolution Order Per
// Role". Each field falls back independently, not the entry as a whole.
func ResolveContactRole(cfg *AppConfig, role string) ResolvedContact {
	c := cfg.Server.Contact
	switch role {
	case "admin":
		return resolveContactChain(c.Admin)
	case "security":
		return resolveContactChain(c.Security, c.Admin)
	case "abuse":
		return resolveContactChain(c.Abuse, c.General, c.Admin)
	case "general":
		return resolveContactChain(c.General, c.Admin)
	default:
		return ResolvedContact{}
	}
}

// resolveContactChain walks entries in priority order, filling each field of
// the result from the first entry that has it set. A webhook URL and its
// secret are always taken from the same entry, never mixed across entries.
func resolveContactChain(entries ...ContactEntry) ResolvedContact {
	var r ResolvedContact
	for _, e := range entries {
		if r.Email == "" {
			r.Email = e.Email
		}
		if r.Telegram == "" && e.Webhooks.Telegram != "" {
			r.Telegram, r.TelegramSecret = e.Webhooks.Telegram, e.Webhooks.TelegramSecret
		}
		if r.Discord == "" && e.Webhooks.Discord != "" {
			r.Discord, r.DiscordSecret = e.Webhooks.Discord, e.Webhooks.DiscordSecret
		}
		if r.Slack == "" && e.Webhooks.Slack != "" {
			r.Slack, r.SlackSecret = e.Webhooks.Slack, e.Webhooks.SlackSecret
		}
		if r.Mattermost == "" && e.Webhooks.Mattermost != "" {
			r.Mattermost, r.MattermostSecret = e.Webhooks.Mattermost, e.Webhooks.MattermostSecret
		}
		if r.Pushover == "" && e.Webhooks.Pushover != "" {
			r.Pushover, r.PushoverSecret = e.Webhooks.Pushover, e.Webhooks.PushoverSecret
		}
		if r.Gotify == "" && e.Webhooks.Gotify != "" {
			r.Gotify, r.GotifySecret = e.Webhooks.Gotify, e.Webhooks.GotifySecret
		}
		if r.Generic == "" && e.Webhooks.Generic != "" {
			r.Generic, r.GenericSecret = e.Webhooks.Generic, e.Webhooks.GenericSecret
		}
	}
	return r
}

// WebhooksConfig holds named outbound webhook URLs per AI.md PART 12.
// Each field is the full webhook URL for that service; empty means disabled.
// Each URL has a matching <name>_secret field: a random 32-byte value
// auto-generated when the URL is first saved, used as the HMAC-SHA256 key
// for the outbound X-Webhook-Signature header (AI.md PART 12 → "Outbound
// webhook signing"). Operators never set the secret themselves.
type WebhooksConfig struct {
	// Telegram: https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT}
	Telegram       string `yaml:"telegram"`
	TelegramSecret string `yaml:"telegram_secret"`
	// Discord: https://discord.com/api/webhooks/{ID}/{TOKEN}
	Discord       string `yaml:"discord"`
	DiscordSecret string `yaml:"discord_secret"`
	// Slack: https://hooks.slack.com/services/{T}/{B}/{X}
	Slack       string `yaml:"slack"`
	SlackSecret string `yaml:"slack_secret"`
	// Mattermost: incoming webhook URL (Slack-compatible)
	Mattermost       string `yaml:"mattermost"`
	MattermostSecret string `yaml:"mattermost_secret"`
	// Pushover: Pushover API URL with user/token query params
	Pushover       string `yaml:"pushover"`
	PushoverSecret string `yaml:"pushover_secret"`
	// Gotify: {url}/message?token={token}
	Gotify       string `yaml:"gotify"`
	GotifySecret string `yaml:"gotify_secret"`
	// Generic: any HTTPS URL — POSTed JSON body per spec
	Generic       string `yaml:"generic"`
	GenericSecret string `yaml:"generic_secret"`
}

// EnsureSecrets generates a random 32-byte hex secret for any webhook URL
// that is set but has no matching secret yet. Returns true if any secret
// was generated (caller should persist the config in that case).
func (w *WebhooksConfig) EnsureSecrets() bool {
	changed := false
	pairs := []struct {
		url    string
		secret *string
	}{
		{w.Telegram, &w.TelegramSecret},
		{w.Discord, &w.DiscordSecret},
		{w.Slack, &w.SlackSecret},
		{w.Mattermost, &w.MattermostSecret},
		{w.Pushover, &w.PushoverSecret},
		{w.Gotify, &w.GotifySecret},
		{w.Generic, &w.GenericSecret},
	}
	for _, p := range pairs {
		if p.url != "" && *p.secret == "" {
			*p.secret = generateWebhookSecret()
			changed = true
		}
	}
	return changed
}

// generateWebhookSecret returns a random 32-byte value hex-encoded, used as
// the per-webhook HMAC-SHA256 signing key (AI.md PART 12).
func generateWebhookSecret() string {
	b := make([]byte, 32)
	// crypto/rand.Read only fails if the OS entropy source is unavailable,
	// which is unrecoverable here; falling back to a zero-value secret would
	// be silently insecure, so panic is the correct behavior.
	if _, err := cryptorand.Read(b); err != nil {
		panic("config: failed to generate webhook secret: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// EnsureContactWebhookSecrets generates secrets for every configured contact
// webhook URL across all four roles that doesn't already have one. Returns
// true if any secret was generated (caller should persist via
// SaveConfigToFile in that case).
func EnsureContactWebhookSecrets(cfg *AppConfig) bool {
	a := cfg.Server.Contact.Admin.Webhooks.EnsureSecrets()
	s := cfg.Server.Contact.Security.Webhooks.EnsureSecrets()
	ab := cfg.Server.Contact.Abuse.Webhooks.EnsureSecrets()
	g := cfg.Server.Contact.General.Webhooks.EnsureSecrets()
	return a || s || ab || g
}

// TrackingConfig holds unified analytics configuration per AI.md PART 12.
// Type selects the analytics platform; ID and URL are platform-specific.
type TrackingConfig struct {
	// Type is the analytics platform: google, matomo, piwik, owa, fathom,
	// plausible, umami, simple, cloudflare, or empty/"none" to disable.
	Type string `yaml:"type"`
	// ID is the tracking/site ID (format depends on Type).
	ID string `yaml:"id"`
	// URL is the self-hosted endpoint (required for: matomo, piwik, owa, umami;
	// optional for: fathom, plausible; not used for: google, simple, cloudflare).
	URL string `yaml:"url"`
}

// trackingTypeNames maps a TrackingConfig.Type value to its human-readable
// display name, used by privacy.tmpl's "Analytics Cookies" section (AI.md
// PART 16 "/server/privacy") to name the configured provider.
var trackingTypeNames = map[string]string{
	"google":     "Google Analytics",
	"matomo":     "Matomo",
	"piwik":      "Piwik",
	"owa":        "Open Web Analytics",
	"fathom":     "Fathom Analytics",
	"plausible":  "Plausible Analytics",
	"umami":      "Umami",
	"simple":     "Simple Analytics",
	"cloudflare": "Cloudflare Web Analytics",
}

// TypeName returns the human-readable display name for the configured
// analytics platform, or "" when tracking is disabled/unrecognized.
func (t TrackingConfig) TypeName() string {
	return trackingTypeNames[t.Type]
}

// PrivacyConfig controls data handling, consent, cookies, and retention per AI.md PART 16.
type PrivacyConfig struct {
	Data       DataPolicy       `yaml:"data"`
	Retention  RetentionPolicy  `yaml:"retention"`
	Consent    ConsentConfig    `yaml:"consent"`
	Cookies    CookieCategories `yaml:"cookies"`
	ThirdParty ThirdPartyConfig `yaml:"third_party"`
	Content    PrivacyContent   `yaml:"content"`
}

// DataPolicy controls data handling and CCPA compliance.
type DataPolicy struct {
	Sold           bool               `yaml:"sold"`
	StoredOnServer bool               `yaml:"stored_on_server"`
	Sharing        []SharingCondition `yaml:"sharing"`
}

// SharingCondition describes when and what data is shared with third parties.
type SharingCondition struct {
	Condition string `yaml:"condition" json:"condition"`
	When      string `yaml:"when" json:"when"`
	Data      string `yaml:"data" json:"data"`
}

// RetentionPolicy sets data retention periods and export/deletion options.
type RetentionPolicy struct {
	Period            string `yaml:"period"`
	ExportAvailable   bool   `yaml:"export_available"`
	DeletionAvailable bool   `yaml:"deletion_available"`
}

// ConsentConfig controls the cookie consent banner appearance and text.
type ConsentConfig struct {
	ShowUntilAcknowledged bool   `yaml:"show_until_acknowledged"`
	DefaultEnabled        bool   `yaml:"default_enabled"`
	Message               string `yaml:"message"`
	MessageIfSold         string `yaml:"message_if_sold"`
	Policy                struct {
		Text string `yaml:"text"`
		URL  string `yaml:"url"`
	} `yaml:"policy"`
	Buttons struct {
		Decline string `yaml:"decline"`
		Accept  string `yaml:"accept"`
	} `yaml:"buttons"`
	Position        string `yaml:"position"`
	ShowPreferences bool   `yaml:"show_preferences"`
	PreferencesText string `yaml:"preferences_text"`
}

// consentDefaults returns the default consent banner configuration per AI.md PART 12.
func consentDefaults() ConsentConfig {
	c := ConsentConfig{
		ShowUntilAcknowledged: true,
		DefaultEnabled:        true,
		Message:               "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data is stored on our servers and is never sold.",
		MessageIfSold:         "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data may be shared with or sold to third parties as described in our Privacy Policy.",
		Position:              "bottom",
		ShowPreferences:       true,
		PreferencesText:       "Manage Preferences",
	}
	c.Policy.Text = "Privacy Policy"
	c.Policy.URL = "/server/privacy"
	c.Buttons.Decline = "Decline"
	c.Buttons.Accept = "I Agree"
	return c
}

// CookieCategories describes cookie groupings shown in the consent UI.
type CookieCategories struct {
	Essential   CookieCategory  `yaml:"essential"`
	Preferences CookieCategory  `yaml:"preferences"`
	Analytics   AnalyticsCookie `yaml:"analytics"`
}

// CookieCategory is a single cookie consent category.
type CookieCategory struct {
	Enabled     bool   `yaml:"enabled"`
	Description string `yaml:"description"`
}

// AnalyticsCookie extends CookieCategory with sold/not-sold description suffixes.
type AnalyticsCookie struct {
	CookieCategory           `yaml:",inline"`
	DescriptionSuffixNotSold string `yaml:"description_suffix_not_sold"`
	DescriptionSuffixSold    string `yaml:"description_suffix_sold"`
}

// ThirdPartyConfig lists third-party services disclosed in the privacy policy.
type ThirdPartyConfig struct {
	Services []ThirdPartyService `yaml:"services"`
}

// ThirdPartyService is a single third-party service entry.
type ThirdPartyService struct {
	Name      string `yaml:"name" json:"name"`
	Purpose   string `yaml:"purpose" json:"purpose"`
	DataSent  string `yaml:"data_sent" json:"data_sent"`
	PolicyURL string `yaml:"policy_url" json:"policy_url"`
}

// PrivacyContent holds the Markdown content blocks for the privacy page.
type PrivacyContent struct {
	DataCollection  string `yaml:"data_collection"`
	DataUsage       string `yaml:"data_usage"`
	DataUsageIfSold string `yaml:"data_usage_if_sold"`
	DataSecurity    string `yaml:"data_security"`
}

// GetConsentMessage returns the appropriate consent message based on the data.sold setting.
func (p *PrivacyConfig) GetConsentMessage() string {
	if p.Data.Sold {
		return p.Consent.MessageIfSold
	}
	return p.Consent.Message
}

// GetAnalyticsDescription returns the analytics cookie description with the appropriate suffix.
// Exported: called directly from privacy.tmpl (`.Privacy.GetAnalyticsDescription`) per AI.md PART 16.
func (p *PrivacyConfig) GetAnalyticsDescription() string {
	base := p.Cookies.Analytics.Description
	if p.Data.Sold {
		return base + " " + p.Cookies.Analytics.DescriptionSuffixSold
	}
	return base + " " + p.Cookies.Analytics.DescriptionSuffixNotSold
}

// GetDataUsageContent returns the appropriate data-usage content based on the data.sold setting.
// Exported: called directly from privacy.tmpl (`.Privacy.GetDataUsageContent`) per AI.md PART 16.
func (p *PrivacyConfig) GetDataUsageContent() string {
	if p.Data.Sold {
		return p.Content.DataUsageIfSold
	}
	return p.Content.DataUsage
}

// IsCCPAApplicable returns true when CCPA "Do Not Sell" disclosure is required.
// Exported per AI.md PART 16's PrivacyConfig method signature.
func (p *PrivacyConfig) IsCCPAApplicable() bool {
	return p.Data.Sold
}

// CacheConfig defines the caching backend and its connection parameters.
type CacheConfig struct {
	// Type is the cache backend: "none", "memory" (default), "valkey", or "redis".
	Type string `yaml:"type"`
	// URL is the full connection string (takes precedence over host/port when set).
	URL string `yaml:"url"`
	// Host, Port, Username, Password, and DB provide individual connection settings.
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	// TLS enables encrypted connections; TLSSkipVerify disables cert verification.
	TLS           bool `yaml:"tls"`
	TLSSkipVerify bool `yaml:"tls_skip_verify"`
	// PoolSize and MinIdle control the connection pool.
	PoolSize int `yaml:"pool_size"`
	MinIdle  int `yaml:"min_idle"`
	// Timeout is the connection/operation timeout (e.g. "5s").
	Timeout string `yaml:"timeout"`
	// Prefix is prepended to all cache keys to avoid collisions.
	Prefix string `yaml:"prefix"`
	// TTL is the default cache entry time-to-live (e.g. "1h", "5m", "300s").
	TTL string `yaml:"ttl"`
}

// SSLConfig controls TLS and Let's Encrypt settings per AI.md PART 15.
type SSLConfig struct {
	// Enabled forces HTTPS; when false the server uses HTTP only.
	Enabled bool `yaml:"enabled"`
	// LetsEncrypt controls ACME certificate issuance and renewal.
	LetsEncrypt LetsEncryptConfig `yaml:"letsencrypt"`
}

// LetsEncryptConfig holds ACME/Let's Encrypt options per AI.md PART 15.
type LetsEncryptConfig struct {
	// Enabled activates automatic certificate provisioning via ACME.
	Enabled bool `yaml:"enabled"`
	// Email is the contact address sent to Let's Encrypt for expiry notices.
	Email string `yaml:"email"`
	// Staging uses the Let's Encrypt staging environment (no rate limits).
	Staging bool `yaml:"staging"`
	// Challenge selects the ACME challenge type: "http-01" (default), "tls-alpn-01", or "dns-01".
	Challenge string `yaml:"challenge"`
	// DNSProvider is the lego DNS provider name (e.g. "cloudflare", "route53", "digitalocean"),
	// used only when Challenge is "dns-01". See https://go-acme.github.io/lego/dns/ for the full list.
	DNSProvider string `yaml:"dns_provider"`
	// DNSCredentials holds the DNS-01 provider credentials, encrypted at rest with
	// server.security.encryption_key (AES-256-GCM), used only when Challenge is "dns-01".
	DNSCredentials DNSCredentialsConfig `yaml:"dns_credentials"`
}

// DNSCredentialsConfig stores DNS-01 provider credentials encrypted at rest per AI.md PART 15.
// The plaintext credential map is never persisted to server.yml — only the encrypted blob.
type DNSCredentialsConfig struct {
	// Provider identifies which DNS provider the credentials belong to (e.g. "cloudflare", "route53").
	Provider string `yaml:"provider"`
	// CredentialsEncrypted is the base64-encoded AES-256-GCM ciphertext of the JSON-encoded
	// provider credential map (e.g. {"CLOUDFLARE_API_TOKEN": "..."}), encrypted with
	// server.security.encryption_key. Decrypted only in memory, at the point of use.
	CredentialsEncrypted string `yaml:"credentials_encrypted"`
	// ValidatedAt is the RFC3339 timestamp of the last successful credential validation
	// (checked on startup and before every certificate request), per AI.md PART 15.
	ValidatedAt string `yaml:"validated_at"`
}

// MaintenanceConfig controls self-healing, auto-cleanup, and maintenance notifications.
type MaintenanceConfig struct {
	SelfHealing MaintenanceSelfHealingConfig `yaml:"self_healing"`
	Cleanup     MaintenanceCleanupConfig     `yaml:"cleanup"`
	Notify      MaintenanceNotifyConfig      `yaml:"notify"`
}

// MaintenanceSelfHealingConfig sets automatic recovery behaviour.
type MaintenanceSelfHealingConfig struct {
	Enabled       bool   `yaml:"enabled"`
	RetryInterval string `yaml:"retry_interval"`
	MaxAttempts   int    `yaml:"max_attempts"`
}

// MaintenanceCleanupConfig sets disk and log cleanup thresholds.
type MaintenanceCleanupConfig struct {
	DiskThreshold    int `yaml:"disk_threshold"`
	LogRetentionDays int `yaml:"log_retention_days"`
	BackupKeepCount  int `yaml:"backup_keep_count"`
}

// MaintenanceNotifyConfig controls when maintenance-mode notifications are sent.
type MaintenanceNotifyConfig struct {
	OnEnter bool `yaml:"on_enter"`
	OnExit  bool `yaml:"on_exit"`
}

// BrandingConfig holds site identity and theme customisation values.
type BrandingConfig struct {
	Title       string `yaml:"title"`
	Tagline     string `yaml:"tagline"`
	Description string `yaml:"description"`
	LogoURL     string `yaml:"logo_url"`
	FaviconURL  string `yaml:"favicon_url"`
	ThemeColor  string `yaml:"theme_color"`
}

// SEOConfig holds search-engine metadata used to build the meta tags,
// OpenGraph/Twitter cards, and sitemap (AI.md PART 24 "Branding & SEO").
type SEOConfig struct {
	// Keywords populates the meta keywords tag.
	Keywords []string `yaml:"keywords"`
	// Author populates the meta author tag.
	Author string `yaml:"author"`
	// OGImage is the OpenGraph and Twitter card image URL.
	OGImage string `yaml:"og_image"`
	// TwitterHandle is the @handle credited on Twitter cards.
	TwitterHandle string `yaml:"twitter_handle"`
	// Verification holds per-provider site-ownership codes.
	Verification SEOVerificationConfig `yaml:"verification"`
	// Sitemap controls /sitemap.xml generation.
	Sitemap SitemapConfig `yaml:"sitemap"`
}

// SEOVerificationConfig holds search-engine site-ownership codes. Every value
// is validated against its provider's documented format before it is rendered;
// an invalid code is dropped rather than echoed into the page (AI.md PART 24
// "Site Verification Meta Tags").
type SEOVerificationConfig struct {
	// Google Search Console code.
	Google string `yaml:"google"`
	// Bing Webmaster Tools code.
	Bing string `yaml:"bing"`
	// Yandex Webmaster code.
	Yandex string `yaml:"yandex"`
	// Baidu Webmaster code.
	Baidu string `yaml:"baidu"`
	// Pinterest verification code.
	Pinterest string `yaml:"pinterest"`
	// Facebook domain verification code.
	Facebook string `yaml:"facebook"`
	// Custom holds additional verification meta tags.
	Custom []SEOCustomVerificationTag `yaml:"custom"`
}

// SEOCustomVerificationTag is one operator-supplied verification meta tag.
// Exactly one of Name or Property must be set.
type SEOCustomVerificationTag struct {
	// Name renders as <meta name="...">.
	Name string `yaml:"name,omitempty"`
	// Property renders as <meta property="...">.
	Property string `yaml:"property,omitempty"`
	// Content is the verification value, max 256 characters.
	Content string `yaml:"content"`
}

// SitemapConfig controls the generated /sitemap.xml.
type SitemapConfig struct {
	// Enabled serves /sitemap.xml. Default true.
	Enabled bool `yaml:"enabled"`
	// MaxURLs is the sitemap protocol limit of 50000 entries per file.
	MaxURLs int `yaml:"max_urls"`
	// IncludeImages adds image entries to each URL.
	IncludeImages bool `yaml:"include_images"`
}

// DefaultSEOConfig returns the AI.md PART 24 defaults: no operator metadata,
// sitemap enabled at the protocol's 50000-URL ceiling.
func DefaultSEOConfig() SEOConfig {
	return SEOConfig{
		Sitemap: SitemapConfig{
			Enabled: true,
			MaxURLs: 50000,
		},
	}
}

// seoVerificationPatterns maps each provider to its documented code format
// (AI.md PART 24 "Validation Rules").
var seoVerificationPatterns = map[string]*regexp.Regexp{
	"google":    regexp.MustCompile(`^[a-zA-Z0-9_-]{1,43}$`),
	"bing":      regexp.MustCompile(`^[A-F0-9]{1,32}$`),
	"yandex":    regexp.MustCompile(`^[a-f0-9]{1,32}$`),
	"baidu":     regexp.MustCompile(`^[a-zA-Z0-9]{1,32}$`),
	"pinterest": regexp.MustCompile(`^[a-f0-9]{1,32}$`),
	"facebook":  regexp.MustCompile(`^[a-z0-9]{1,64}$`),
}

// seoCustomTagNamePattern constrains custom meta attribute names to characters
// that cannot break out of the attribute and inject markup.
var seoCustomTagNamePattern = regexp.MustCompile(`^[a-zA-Z0-9:._-]{1,64}$`)

// ValidVerificationCodes returns only the provider codes that pass their
// documented format check, keyed by the meta tag's attribute name. Invalid or
// empty codes are dropped: AI.md PART 24 forbids rendering them.
func (v SEOVerificationConfig) ValidVerificationCodes() map[string]string {
	candidates := map[string]string{
		"google":    v.Google,
		"bing":      v.Bing,
		"yandex":    v.Yandex,
		"baidu":     v.Baidu,
		"pinterest": v.Pinterest,
		"facebook":  v.Facebook,
	}
	metaNames := map[string]string{
		"google":    "google-site-verification",
		"bing":      "msvalidate.01",
		"yandex":    "yandex-verification",
		"baidu":     "baidu-site-verification",
		"pinterest": "p:domain_verify",
		"facebook":  "fb:domain_verification",
	}
	valid := make(map[string]string, len(candidates))
	for provider, code := range candidates {
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}
		if pattern, ok := seoVerificationPatterns[provider]; ok && pattern.MatchString(code) {
			valid[metaNames[provider]] = code
			continue
		}
		warnConfigReplaced("server.seo.verification."+provider, code, "(dropped: invalid format)")
	}
	return valid
}

// ValidCustomTags returns the custom verification tags that pass validation.
// A tag needs exactly one of name/property, a safe attribute name, and non-empty
// content of at most 256 characters.
func (v SEOVerificationConfig) ValidCustomTags() []SEOCustomVerificationTag {
	valid := make([]SEOCustomVerificationTag, 0, len(v.Custom))
	for _, tag := range v.Custom {
		name := strings.TrimSpace(tag.Name)
		property := strings.TrimSpace(tag.Property)
		content := strings.TrimSpace(tag.Content)
		attribute := name
		if attribute == "" {
			attribute = property
		}
		switch {
		case (name == "") == (property == ""):
			warnConfigReplaced("server.seo.verification.custom", attribute, "(dropped: needs exactly one of name/property)")
		case content == "" || len(content) > 256:
			warnConfigReplaced("server.seo.verification.custom", attribute, "(dropped: content empty or over 256 chars)")
		case !seoCustomTagNamePattern.MatchString(attribute):
			warnConfigReplaced("server.seo.verification.custom", attribute, "(dropped: invalid attribute name)")
		default:
			valid = append(valid, SEOCustomVerificationTag{Name: name, Property: property, Content: content})
		}
	}
	return valid
}

// TorConfig contains Tor hidden service settings per AI.md PART 31.
// The hidden service is auto-enabled when the Tor binary is found.
type TorConfig struct {
	// Binary is the path to the Tor binary. Leave empty for auto-detection.
	Binary string `yaml:"binary"`
	// UseNetwork routes all outbound connections through Tor.
	UseNetwork bool `yaml:"use_network"`
	// AllowUserPreference lets users set their own Tor network preference.
	AllowUserPreference bool `yaml:"allow_user_preference"`
	// MaxCircuits is the maximum open circuits (higher = faster, more memory).
	MaxCircuits int `yaml:"max_circuits"`
	// CircuitTimeout is how long (in seconds) to wait before giving up on a circuit.
	CircuitTimeout int `yaml:"circuit_timeout"`
	// BootstrapTimeout is how long (in seconds) to wait for Tor network bootstrap.
	BootstrapTimeout int `yaml:"bootstrap_timeout"`
	// SafeLogging scrubs sensitive info from Tor logs.
	SafeLogging bool `yaml:"safe_logging"`
	// MaxStreamsPerCircuit limits concurrent streams per circuit.
	MaxStreamsPerCircuit int `yaml:"max_streams_per_circuit"`
	// CloseCircuitOnStreamLimit closes a circuit when the stream limit is hit.
	CloseCircuitOnStreamLimit bool `yaml:"close_circuit_on_stream_limit"`
	// BandwidthRate is the maximum bandwidth rate (e.g. "1 MB").
	BandwidthRate string `yaml:"bandwidth_rate"`
	// BandwidthBurst is the maximum bandwidth burst (e.g. "2 MB").
	BandwidthBurst string `yaml:"bandwidth_burst"`
	// MaxMonthlyBandwidth is the monthly cap (e.g. "100 GB", "unlimited").
	MaxMonthlyBandwidth string `yaml:"max_monthly_bandwidth"`
	// NumIntroPoints is the number of introduction points (3–10).
	NumIntroPoints int `yaml:"num_intro_points"`
	// VirtualPort is the port exposed on the .onion address (default 80).
	VirtualPort int `yaml:"virtual_port"`
}

// I2PConfig contains I2P eepsite configuration per AI.md PART 31.2.
// OPT-IN: unlike Tor (auto-enabled when the binary is found), the eepsite
// is created only when Enabled is true.
type I2PConfig struct {
	// Enabled opts into the I2P eepsite. Default false.
	Enabled bool `yaml:"enabled"`
	// Binary is the path to the i2pd binary. Leave empty for auto-detection.
	// When found, the app spawns/manages a dedicated i2pd process (Model A).
	Binary string `yaml:"binary"`
	// SAMAddress is the SAMv3 bridge address for Model B, used only when no
	// i2pd binary is found. Default "127.0.0.1:7656".
	SAMAddress string `yaml:"sam_address"`
	// VirtualPort is the port exposed on the .b32.i2p address (default 80).
	VirtualPort int `yaml:"virtual_port"`
	// InboundLength/OutboundLength are tunnel hop counts (0-7, default 3).
	InboundLength  int `yaml:"inbound_length"`
	OutboundLength int `yaml:"outbound_length"`
	// InboundQuantity/OutboundQuantity are parallel tunnel counts (1-16, default 5).
	InboundQuantity  int `yaml:"inbound_quantity"`
	OutboundQuantity int `yaml:"outbound_quantity"`
	// SignatureType is the SAM/destination signature type (7 = EdDSA-SHA512-Ed25519).
	SignatureType int `yaml:"signature_type"`
	// BootstrapTimeout is how long (in seconds) to wait for the destination
	// and tunnels to become ready.
	BootstrapTimeout int `yaml:"bootstrap_timeout"`
}

// I18nConfig contains internationalisation settings.
type I18nConfig struct {
	Enabled            bool     `yaml:"enabled"`
	DefaultLanguage    string   `yaml:"default_language"`
	AvailableLanguages []string `yaml:"supported"`
	FallbackLanguage   string   `yaml:"fallback_language"`
}

// DatabaseConfig holds database driver selection and connection settings per AI.md PART 10.
// Default driver is sqlite (modernc.org/sqlite — CGO_ENABLED=0 safe).
// Alternate driver is libsql (Turso/libSQL remote — tursodatabase/libsql-client-go).
type DatabaseConfig struct {
	// Driver selects the database backend.
	// Accepted values: "sqlite", "sqlite2", "sqlite3" → sqlite; "libsql", "turso" → libsql.
	Driver string `yaml:"driver"`
	// URL is only used when driver is libsql/turso.
	// Formats: libsql://your-db.turso.io?authToken=xxx  OR  https://your-db.turso.io
	URL string `yaml:"url"`
	// Token is the Turso auth token when URL does not embed authToken.
	// Never stored in the DB — stays in server.yml only.
	Token string `yaml:"token"`
	// Pool holds the connection pool settings applied by src/db.
	Pool DatabasePoolConfig `yaml:"pool"`
}

// DatabasePoolConfig holds connection pool settings per AI.md PART 10
// "Connection Pooling". Values map directly onto database/sql's
// SetMaxOpenConns / SetMaxIdleConns / SetConnMaxLifetime / SetConnMaxIdleTime.
// SQLite uses a single writer, so the defaults match the spec's Development row.
type DatabasePoolConfig struct {
	// MaxOpen is the maximum number of open connections.
	MaxOpen int `yaml:"max_open"`
	// MaxIdle is the maximum number of idle connections.
	MaxIdle int `yaml:"max_idle"`
	// MaxLifetime is the maximum connection lifetime as a Go duration string.
	MaxLifetime string `yaml:"max_lifetime"`
	// MaxIdleTime is the maximum idle time before a connection is closed,
	// as a Go duration string.
	MaxIdleTime string `yaml:"max_idle_time"`
}

// ResolvedMaxLifetime parses MaxLifetime, falling back to the AI.md PART 10
// default of 5m when unset or unparseable.
func (p DatabasePoolConfig) ResolvedMaxLifetime() time.Duration {
	return parsePoolDuration(p.MaxLifetime, 5*time.Minute)
}

// ResolvedMaxIdleTime parses MaxIdleTime, falling back to the AI.md PART 10
// default of 1m when unset or unparseable.
func (p DatabasePoolConfig) ResolvedMaxIdleTime() time.Duration {
	return parsePoolDuration(p.MaxIdleTime, time.Minute)
}

// parsePoolDuration parses a pool duration string, returning fallback for an
// empty, unparseable, or non-positive value.
func parsePoolDuration(value string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// NormalizedDriver maps user-friendly config aliases to canonical Go driver names.
// sqlite2/sqlite3 → "sqlite" (modernc.org/sqlite); turso → "libsql" (tursodatabase).
func (d *DatabaseConfig) NormalizedDriver() string {
	switch strings.ToLower(d.Driver) {
	case "sqlite", "sqlite2", "sqlite3", "":
		return "sqlite"
	case "libsql", "turso":
		return "libsql"
	default:
		return d.Driver
	}
}

// ValidateLibSQL returns an error when the driver is libsql but no URL was provided.
func (d *DatabaseConfig) ValidateLibSQL() error {
	if d.NormalizedDriver() != "libsql" {
		return nil
	}
	if d.URL == "" {
		return fmt.Errorf("libsql driver requires url: use libsql://host?authToken=xxx or https://host with token field")
	}
	return nil
}

// ScheduleConfig contains scheduler settings per AI.md PART 18.
// Individual task schedules can be overridden here; defaults are used when empty.
type ScheduleConfig struct {
	Enabled       bool                `yaml:"enabled"`
	GeoIPUpdate   string              `yaml:"geoip_update"`
	Timezone      string              `yaml:"timezone"`
	CatchUpWindow string              `yaml:"catch_up_window"`
	Tasks         ScheduleTasksConfig `yaml:"tasks"`
}

// ScheduleTasksConfig holds per-task schedule overrides.
type ScheduleTasksConfig struct {
	SSLRenewal      TaskScheduleConfig `yaml:"ssl_renewal"`
	GeoIPUpdate     TaskScheduleConfig `yaml:"geoip_update"`
	BlocklistUpdate TaskScheduleConfig `yaml:"blocklist_update"`
	ThreatUpdate    TaskScheduleConfig `yaml:"threat_update"`
	CVEUpdate       TaskScheduleConfig `yaml:"cve_update"`
	UpdateCheck     TaskScheduleConfig `yaml:"update_check"`
	TokenCleanup    TaskScheduleConfig `yaml:"token_cleanup"`
	LogRotation     TaskScheduleConfig `yaml:"log_rotation"`
	BackupDaily     TaskScheduleConfig `yaml:"backup_daily"`
	BackupHourly    TaskScheduleConfig `yaml:"backup_hourly"`
	HealthcheckSelf TaskScheduleConfig `yaml:"healthcheck_self"`
	TorHealth       TaskScheduleConfig `yaml:"tor_health"`
}

// TaskScheduleConfig holds per-task scheduling overrides.
type TaskScheduleConfig struct {
	// Schedule is a cron expression or @every interval; empty means use the default.
	Schedule string `yaml:"schedule"`
	// Enabled controls whether the task runs (nil means use the built-in default).
	Enabled *bool `yaml:"enabled"`
}

// MetricsRootConfig gates the root aliases /metrics and /metrics/{service}
// per AI.md PART 20. Enabled by default because Prometheus scrapers default
// to /metrics.
type MetricsRootConfig struct {
	Enabled bool `yaml:"enabled"`
}

// MetricsTokensConfig holds the per-service bearer tokens per AI.md PART 20.
// An empty value disables that service's endpoints, which then answer 403
// with an empty body.
type MetricsTokensConfig struct {
	Prometheus string `yaml:"prometheus"`
	Grafana    string `yaml:"grafana"`
	Loki       string `yaml:"loki"`
}

// MetricsAuthConfig configures metrics authentication per AI.md PART 20.
type MetricsAuthConfig struct {
	// AllowUnauthenticated skips token checks for ALL metrics services.
	// Firewalled internal networks only; never on a publicly reachable server.
	AllowUnauthenticated bool `yaml:"allow_unauthenticated"`
	// Tokens are the per-service bearer tokens.
	Tokens MetricsTokensConfig `yaml:"tokens"`
}

// MetricsLokiConfig bounds how much recent log the loki service serves.
type MetricsLokiConfig struct {
	// MaxEntries is the maximum number of log lines returned. Default 1000.
	MaxEntries int `yaml:"max_entries"`
	// MaxAge is the oldest log line age returned, as a Go duration. Default 1h.
	MaxAge string `yaml:"max_age"`
}

// MetricsConfig contains metrics settings per AI.md PART 20.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	// Root gates the /metrics and /metrics/{service} root aliases.
	Root MetricsRootConfig `yaml:"root"`
	// Auth holds the per-service tokens and the unauthenticated escape hatch.
	Auth MetricsAuthConfig `yaml:"auth"`
	// IncludeSystem includes CPU, memory, and disk gauges.
	IncludeSystem bool `yaml:"include_system"`
	// Loki bounds the recent-log window served by the loki service.
	Loki MetricsLokiConfig `yaml:"loki"`
	// IncludeRuntime includes Go runtime (goroutines, GC, memory) gauges.
	IncludeRuntime bool `yaml:"include_runtime"`
	// DurationBuckets are the histogram buckets for HTTP request duration in seconds.
	// Default: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
	DurationBuckets []float64 `yaml:"duration_buckets"`
	// SizeBuckets are the histogram buckets for request/response size in bytes.
	// Default: [100, 1000, 10000, 100000, 1000000, 10000000]
	SizeBuckets []float64 `yaml:"size_buckets"`
}

// LogFileConfig configures a single log file per AI.md PART 11.
type LogFileConfig struct {
	// Enabled controls whether this log file is written (true by default).
	Enabled bool `yaml:"enabled"`
	// Filename is the base file name (e.g. "access.log").
	Filename string `yaml:"filename"`
	// Format is the output format (varies by log type).
	Format string `yaml:"format"`
	// Custom is the custom format string when Format=="custom".
	Custom string `yaml:"custom"`
	// Rotate is the rotation policy: "daily", "weekly", "monthly", "NMB", combined.
	Rotate string `yaml:"rotate"`
	// Keep is the retention policy: "none", "N", "Nd", "Nw", "Nm", "forever".
	Keep string `yaml:"keep"`
}

// AuditEventFilterConfig configures which event categories appear in audit.log.
type AuditEventFilterConfig struct {
	Configuration bool `yaml:"configuration"`
	Security      bool `yaml:"security"`
	Backup        bool `yaml:"backup"`
	Server        bool `yaml:"server"`
}

// AuditLogFileConfig extends LogFileConfig with audit-specific options.
type AuditLogFileConfig struct {
	LogFileConfig    `yaml:",inline"`
	Compress         bool                   `yaml:"compress"`
	Events           AuditEventFilterConfig `yaml:"events"`
	IncludeUserAgent bool                   `yaml:"include_user_agent"`
}

// LoggingConfig contains logging settings per AI.md PART 11.
type LoggingConfig struct {
	// Level is the global log level: debug, info, warn, error.
	Level string `yaml:"level"`
	// AccessFormat is kept for backward YAML compatibility; prefer Access.Format.
	AccessFormat string `yaml:"access_format"`
	// Per-file configuration
	Access   LogFileConfig      `yaml:"access"`
	Server   LogFileConfig      `yaml:"server"`
	Error    LogFileConfig      `yaml:"error"`
	App      LogFileConfig      `yaml:"app"`
	Auth     LogFileConfig      `yaml:"auth"`
	Audit    AuditLogFileConfig `yaml:"audit"`
	Security LogFileConfig      `yaml:"security"`
	Debug    LogFileConfig      `yaml:"debug"`
}

// UpdateConfig holds update check settings per AI.md PART 22.
type UpdateConfig struct {
	// Branch is the release channel: stable | beta | daily
	Branch string `yaml:"branch"`
	// AutoInstall enables automatic installation of eligible updates.
	// Default false — the update_check task only notifies.
	AutoInstall bool `yaml:"auto_install"`
	// DeferDays is the number of days a release must be public before being eligible.
	// 0 = immediately eligible; 30 = adopt releases only after 30 days.
	DeferDays int `yaml:"defer_days"`
}

// GeoIPDatabasesConfig controls which MMDB databases are downloaded per AI.md PART 19.
type GeoIPDatabasesConfig struct {
	// ASN enables ASN lookups (asn.mmdb).
	ASN bool `yaml:"asn"`
	// Country enables country lookups (country.mmdb).
	Country bool `yaml:"country"`
	// City enables city lookups (dbip-city-ipv4.mmdb, dbip-city-ipv6.mmdb).
	City bool `yaml:"city"`
	// WHOIS enables the combined WHOIS lookup — no whois.mmdb file exists;
	// this joins the ASN and Country databases at query time.
	WHOIS bool `yaml:"whois"`
}

// GeoIPConfig contains GeoIP settings per AI.md PART 19.
type GeoIPConfig struct {
	Enabled bool `yaml:"enabled"`
	// Dir is the directory for downloaded MMDB files; defaults to {data_dir}/security/geoip.
	Dir string `yaml:"dir"`
	// DenyCountries blocks listed ISO 3166-1 alpha-2 country codes.
	// Mutually exclusive with AllowCountries (AllowCountries takes precedence if both set).
	DenyCountries []string `yaml:"deny_countries"`
	// AllowCountries allows ONLY listed country codes and blocks all others.
	AllowCountries []string `yaml:"allow_countries"`
	// Presets are named, operator-authored country lists (name -> []code) that
	// can be reused across the allow/deny fields and environments. Ships empty.
	// A preset is never applied on its own — only by being named in
	// DenyCountries or AllowCountries.
	Presets map[string][]string `yaml:"presets"`
	// Databases controls which MMDB databases to download and use.
	Databases GeoIPDatabasesConfig `yaml:"databases"`
}

// ResolvedDenyCountries returns DenyCountries with any preset names expanded
// to their country codes, per AI.md PART 19.
func (g GeoIPConfig) ResolvedDenyCountries() []string {
	return g.expandCountryList(g.DenyCountries)
}

// ResolvedAllowCountries returns AllowCountries with any preset names expanded
// to their country codes, per AI.md PART 19.
func (g GeoIPConfig) ResolvedAllowCountries() []string {
	return g.expandCountryList(g.AllowCountries)
}

// expandCountryList replaces every entry that names a preset with that
// preset's country codes, keeps literal codes as-is, and drops duplicates.
// Entries inside a preset are always treated as literal codes, so a preset can
// never expand into another preset.
func (g GeoIPConfig) expandCountryList(list []string) []string {
	resolved := make([]string, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	add := func(code string) {
		code = strings.ToUpper(strings.TrimSpace(code))
		if code == "" {
			return
		}
		if _, dup := seen[code]; dup {
			return
		}
		seen[code] = struct{}{}
		resolved = append(resolved, code)
	}
	for _, entry := range list {
		name := strings.TrimSpace(entry)
		if codes, ok := g.Presets[name]; ok {
			for _, code := range codes {
				add(code)
			}
			continue
		}
		add(entry)
	}
	return resolved
}

// SecurityConfig contains server-level security settings (allowlist, etc.)
type SecurityConfig struct {
	Allowlist []AllowlistEntry `yaml:"allowlist"`
	// EncryptionKey is the base64-encoded 32-byte AES-256-GCM key used to encrypt
	// sensitive at-rest data (e.g. DNS-01 provider credentials), per AI.md PART 11.
	// Auto-generated via crypto/rand on first run and persisted to server.yml.
	EncryptionKey string `yaml:"encryption_key"`
	// PreviousEncryptionKey is the pre-rotation encryption key, kept for the
	// 30-day grace period described in AI.md PART 11 "Secret Rotation" so any
	// at-rest data not yet re-encrypted under the new key remains decryptable.
	PreviousEncryptionKey string `yaml:"previous_encryption_key,omitempty"`
	// PreviousEncryptionKeyUntil is the Unix timestamp the grace period above ends.
	PreviousEncryptionKeyUntil int64 `yaml:"previous_encryption_key_until,omitempty"`
}

// AllowlistEntry is a trusted IP/CIDR that bypasses blocklist, rate limit, and GeoIP.
type AllowlistEntry struct {
	CIDR        string `yaml:"cidr"`
	Description string `yaml:"description"`
	// Confirmed must be true for an overly broad range (/0-/7 IPv4, /0-/15
	// IPv6) to be accepted; per AI.md PART 12 "Validation", broad ranges are
	// otherwise rejected (dropped, with a WARN log) since they defeat the
	// purpose of an allowlist. Ignored for narrower ranges.
	Confirmed bool `yaml:"confirmed,omitempty"`
}

// RateLimitBucketConfig defines requests and window for one rate-limit bucket.
type RateLimitBucketConfig struct {
	// Requests is the number of requests allowed per window.
	Requests int `yaml:"requests"`
	// Window is the sliding window size in seconds.
	Window int `yaml:"window"`
}

// RateLimitConfig holds per-class rate limiting settings per AI.md PART 12.
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	// Read applies to GET and HEAD requests.
	Read RateLimitBucketConfig `yaml:"read"`
	// Write applies to POST, PUT, PATCH, DELETE requests.
	Write RateLimitBucketConfig `yaml:"write"`
	// Health applies to /healthz, /readyz, /livez endpoints.
	Health RateLimitBucketConfig `yaml:"health"`
	// GlobalBurst is the absolute ceiling per IP across all classes (req/min).
	GlobalBurst int `yaml:"global_burst"`
}

// LimitsConfig defines request size and timeout limits per AI.md PART 12.
type LimitsConfig struct {
	// MaxBodySize is the maximum request body size (e.g. "10MB").
	MaxBodySize string `yaml:"max_body_size"`
	// ReadTimeout is the server read timeout (e.g. "30s").
	ReadTimeout string `yaml:"read_timeout"`
	// WriteTimeout is the server write timeout (e.g. "30s").
	WriteTimeout string `yaml:"write_timeout"`
	// IdleTimeout is the idle connection timeout (e.g. "120s").
	IdleTimeout string `yaml:"idle_timeout"`
}

// CompressionConfig controls response compression per AI.md PART 12.
type CompressionConfig struct {
	Enabled bool `yaml:"enabled"`
	// Level is the compression level 1-9.
	Level int `yaml:"level"`
	// Types is the list of MIME types to compress.
	Types []string `yaml:"types"`
}

// TrustedProxiesConfig lists additional trusted proxy CIDRs per AI.md PART 12.
// Private ranges are always trusted; this adds public CDN/reverse-proxy IPs.
type TrustedProxiesConfig struct {
	Additional []string `yaml:"additional"`
}

// URLDetectionConfig controls the smart domain learning and live-reload behaviour per AI.md PART 12.
type URLDetectionConfig struct {
	// Learning enables automatic domain learning from reverse proxy headers.
	Learning bool `yaml:"learning"`
	// MinSamples is the minimum number of requests before inferring a wildcard domain.
	MinSamples int `yaml:"min_samples"`
	// SampleWindow is the time window for pattern analysis (e.g. "5m").
	SampleWindow string `yaml:"sample_window"`
	// LogChanges logs domain or proto changes to the application log.
	LogChanges bool `yaml:"log_changes"`
	// LiveReload allows URL variable updates without a server restart.
	LiveReload bool `yaml:"live_reload"`
}

// WebUIConfig contains web UI settings
type WebUIConfig struct {
	Theme         string              `yaml:"theme"`
	Logo          string              `yaml:"logo"`
	Favicon       string              `yaml:"favicon"`
	Notifications NotificationsConfig `yaml:"notifications"`
	Announcements AnnouncementsConfig `yaml:"announcements"`
}

// NotificationsConfig contains notification settings (WebUI announcements).
type NotificationsConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Announcements []string `yaml:"announcements"`
}

// AnnouncementsConfig holds operator announcement banner configuration per AI.md PART 16.
type AnnouncementsConfig struct {
	Enabled  bool                  `yaml:"enabled"`
	Messages []AnnouncementMessage `yaml:"messages"`
}

// AnnouncementMessage is a single operator announcement per AI.md PART 16 Site Banner.
type AnnouncementMessage struct {
	// ID uniquely identifies the announcement; used for dismissal cookie tracking.
	ID string `yaml:"id"`
	// Type controls color/icon: info, warning, error, success.
	Type    string `yaml:"type"`
	Title   string `yaml:"title"`
	Message string `yaml:"message"`
	// Start is the ISO 8601 UTC time when this announcement first appears.
	Start string `yaml:"start"`
	// End is the ISO 8601 UTC time when this announcement stops appearing.
	End string `yaml:"end"`
	// Dismissible controls whether the user can dismiss this announcement.
	Dismissible bool `yaml:"dismissible"`
}

// Active returns announcements that are currently within their start–end window
// and have not been dismissed by this user (dismissed is a slice of IDs from the
// dismissed_announcements cookie).
func (a *AnnouncementsConfig) Active(dismissed []string) []AnnouncementMessage {
	if !a.Enabled {
		return nil
	}
	dismissedSet := make(map[string]bool, len(dismissed))
	for _, id := range dismissed {
		dismissedSet[id] = true
	}
	now := time.Now().UTC()
	var active []AnnouncementMessage
	for _, msg := range a.Messages {
		if msg.ID == "" || dismissedSet[msg.ID] {
			continue
		}
		if msg.Start != "" {
			start, err := time.Parse(time.RFC3339, msg.Start)
			if err == nil && now.Before(start) {
				continue
			}
		}
		if msg.End != "" {
			end, err := time.Parse(time.RFC3339, msg.End)
			if err == nil && now.After(end) {
				continue
			}
		}
		active = append(active, msg)
	}
	return active
}

// ServerNotificationsConfig contains server-level notification settings per AI.md PART 17.
type ServerNotificationsConfig struct {
	Email EmailNotificationsConfig `yaml:"email"`
}

// EmailNotificationsConfig holds email/SMTP configuration per AI.md PART 17.
type EmailNotificationsConfig struct {
	// Enabled is set automatically when SMTP is configured and reachable.
	Enabled bool           `yaml:"enabled"`
	SMTP    SMTPSubConfig  `yaml:"smtp"`
	From    SMTPFromConfig `yaml:"from"`
	// ReplyTo is the Reply-To address. Empty means no Reply-To header.
	ReplyTo string `yaml:"reply_to"`
	// Events controls which system events trigger email notifications per AI.md PART 17.
	Events EmailEventsConfig `yaml:"events"`
}

// EmailEventsConfig controls per-event email notification toggles per AI.md PART 17.
type EmailEventsConfig struct {
	Startup          bool `yaml:"startup"`
	Shutdown         bool `yaml:"shutdown"`
	BackupComplete   bool `yaml:"backup_complete"`
	BackupFailed     bool `yaml:"backup_failed"`
	SSLExpiring      bool `yaml:"ssl_expiring"`
	SSLRenewed       bool `yaml:"ssl_renewed"`
	SSLRenewalFailed bool `yaml:"ssl_renewal_failed"`
	SecurityAlert    bool `yaml:"security_alert"`
	SchedulerError   bool `yaml:"scheduler_error"`
	UpdateAvailable  bool `yaml:"update_available"`
	UpdateInstalled  bool `yaml:"update_installed"`
}

// SMTPSubConfig holds SMTP connection settings per AI.md PART 17.
type SMTPSubConfig struct {
	// Host: if empty → autodetect on first run.
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// TLS mode: auto | starttls | tls | none. Default: auto.
	TLS string `yaml:"tls"`
}

// SMTPFromConfig holds the email sender identity per AI.md PART 17.
type SMTPFromConfig struct {
	// Name: defaults to app title if empty.
	Name string `yaml:"name"`
	// Email: defaults to no-reply@{fqdn} if empty.
	Email string `yaml:"email"`
}

// WebRobotsConfig contains robots.txt settings
type WebRobotsConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
	// AIBots is per-AI-crawler access control (AI.md PART 16 "AI Crawler Rules").
	AIBots AIBotsConfig `yaml:"ai_bots"`
}

// AIBotsConfig controls which recognized AI crawlers may index the site
// (AI.md PART 16 "AI Crawler Rules"). The default posture is "allow": no bot
// is blocked unless the operator sets it — or Default — to "deny".
type AIBotsConfig struct {
	// Default applies to any recognized AI bot with no entry in Bots.
	// Valid values: "allow" (default) and "deny".
	Default string `yaml:"default"`
	// Bots holds per-bot overrides keyed by the crawler's User-agent token.
	// An explicit entry always takes precedence over Default.
	Bots map[string]string `yaml:"bots"`
}

// KnownAIBots is the canonical, ordered list of AI crawler User-agent tokens
// recognized by robots.txt generation (AI.md PART 16 robots.txt config block).
// Order is fixed so the rendered file is byte-stable across restarts.
var KnownAIBots = []string{
	"GPTBot",
	"ChatGPT-User",
	"ClaudeBot",
	"anthropic-ai",
	"Claude-Web",
	"CCBot",
	"Google-Extended",
	"Bytespider",
	"PerplexityBot",
	"Applebot-Extended",
	"Amazonbot",
	"Diffbot",
	"FacebookBot",
	"cohere-ai",
}

// DefaultAIBots returns the shipped ai_bots.bots map: every recognized crawler
// explicitly set to "allow", matching AI.md PART 16's default configuration.
func DefaultAIBots() map[string]string {
	bots := make(map[string]string, len(KnownAIBots))
	for _, name := range KnownAIBots {
		bots[name] = "allow"
	}
	return bots
}

// IsAIBotDenied reports whether the named crawler must get its own
// "Disallow: /" stanza in robots.txt. An explicit per-bot entry wins over
// Default; an unset or unrecognized Default is treated as "allow".
func (c AIBotsConfig) IsAIBotDenied(bot string) bool {
	if setting, ok := c.Bots[bot]; ok {
		return strings.EqualFold(strings.TrimSpace(setting), "deny")
	}
	return strings.EqualFold(strings.TrimSpace(c.Default), "deny")
}

// DeniedAIBots returns the recognized crawlers that must be blocked, in
// KnownAIBots order, plus any explicitly denied bot the operator added that
// is not in the canonical list.
func (c AIBotsConfig) DeniedAIBots() []string {
	denied := make([]string, 0, len(KnownAIBots))
	known := make(map[string]bool, len(KnownAIBots))
	for _, bot := range KnownAIBots {
		known[bot] = true
		if c.IsAIBotDenied(bot) {
			denied = append(denied, bot)
		}
	}
	extra := make([]string, 0, len(c.Bots))
	for bot, setting := range c.Bots {
		if known[bot] {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(setting), "deny") {
			extra = append(extra, bot)
		}
	}
	sort.Strings(extra)
	return append(denied, extra...)
}

// CSRFConfig controls CSRF middleware behaviour per AI.md PART 16.
type CSRFConfig struct {
	// Enabled controls whether CSRF protection is active. Default: true.
	Enabled bool `yaml:"enabled"`
	// TokenLength is the number of random bytes in the token. Default: 32.
	TokenLength int `yaml:"token_length"`
	// CookieName is the name of the CSRF cookie. Default: "csrf_token".
	CookieName string `yaml:"cookie_name"`
	// HeaderName is the header used for AJAX requests. Default: "X-CSRF-Token".
	HeaderName string `yaml:"header_name"`
	// Secure sets the Secure flag on the cookie. "auto" (default) sets true when proto is https.
	Secure string `yaml:"secure"`
	// ExemptPaths is a list of path patterns exempt from CSRF validation.
	// Supports glob patterns (e.g., /api/v1/webhooks/*).
	ExemptPaths []string `yaml:"exempt_paths"`
}

// BackupEncryptionConfig controls backup encryption settings per AI.md PART 21.
type BackupEncryptionConfig struct {
	// Enabled reflects whether an encryption password has been configured.
	// The password itself is never embedded in the binary at rest — see EncryptionPassword.
	Enabled bool `yaml:"enabled"`
	// EncryptionPassword is the AES-256-GCM key source (Argon2id-derived).
	// May be set in server.yml; never logged or included in backups.
	EncryptionPassword string `yaml:"encryption_password"`
	// EncryptionHint is an optional human-readable reminder for the password.
	EncryptionHint string `yaml:"encryption_hint"`
}

// BackupRetentionConfig controls backup retention policy per AI.md PART 21.
type BackupRetentionConfig struct {
	// MaxBackups is the number of daily full backups to keep. Default: 1.
	MaxBackups int `yaml:"max_backups"`
	// KeepWeekly keeps N Sunday backups (0 = disabled).
	KeepWeekly int `yaml:"keep_weekly"`
	// KeepMonthly keeps N first-of-month backups (0 = disabled).
	KeepMonthly int `yaml:"keep_monthly"`
	// KeepYearly keeps N January-1st backups (0 = disabled).
	KeepYearly int `yaml:"keep_yearly"`
	// MaxTotalSize is the hard size cap for the backup directory.
	// Accepts a percentage ("10%") or absolute size ("50G"). "0" disables.
	// Overrides count limits when the threshold is reached.
	MaxTotalSize string `yaml:"max_total_size"`
}

// BackupConfig groups backup encryption and retention policy per AI.md PART 21.
type BackupConfig struct {
	Encryption BackupEncryptionConfig `yaml:"encryption"`
	Retention  BackupRetentionConfig  `yaml:"retention"`
}

// ComplianceConfig controls compliance mode per AI.md PART 21.
// When enabled, backups are blocked unless encryption is configured.
type ComplianceConfig struct {
	Enabled bool `yaml:"enabled"`
}

// CLIBinaryDownloadConfig controls CLI binary download authentication per AI.md PART 32.
type CLIBinaryDownloadConfig struct {
	// RequireAuth gates the CLI binary download endpoint behind a bearer token.
	// Default false — CLIs are public so new users can install before obtaining a token.
	RequireAuth bool `yaml:"require_auth"`
}

// CLIConfig holds server-side CLI settings per AI.md PART 32.
type CLIConfig struct {
	BinaryDownload CLIBinaryDownloadConfig `yaml:"binary_download"`
}

var (
	current    *AppConfig
	mu         sync.RWMutex
	configPath string
)

// DefaultConfig returns the default configuration
func DefaultConfig() *AppConfig {
	return &AppConfig{
		Server: ServerConfig{
			Port:          "",
			FQDN:          "",
			Address:       "[::]",
			Mode:          "production",
			UpdateBranch:  "stable",
			CLIMinVersion: "1.0.0",
			Database: DatabaseConfig{
				Driver: "sqlite",
				Pool:   DefaultDatabasePoolConfig(),
			},
			Schedule: ScheduleConfig{
				Enabled:       true,
				GeoIPUpdate:   "weekly",
				Timezone:      "America/New_York",
				CatchUpWindow: "1h",
			},
			Tor: TorConfig{
				UseNetwork:                false,
				AllowUserPreference:       true,
				MaxCircuits:               32,
				CircuitTimeout:            60,
				BootstrapTimeout:          180,
				SafeLogging:               true,
				MaxStreamsPerCircuit:      100,
				CloseCircuitOnStreamLimit: true,
				BandwidthRate:             "1 MB",
				BandwidthBurst:            "2 MB",
				MaxMonthlyBandwidth:       "100 GB",
				NumIntroPoints:            3,
				VirtualPort:               80,
			},
			I2P: I2PConfig{
				// OPT-IN: default off, unlike Tor (auto-enabled).
				Enabled:          false,
				SAMAddress:       "127.0.0.1:7656",
				VirtualPort:      80,
				InboundLength:    3,
				OutboundLength:   3,
				InboundQuantity:  5,
				OutboundQuantity: 5,
				SignatureType:    7,
				BootstrapTimeout: 300,
			},
			Metrics: MetricsConfig{
				Enabled:       false,
				Root:          MetricsRootConfig{Enabled: true},
				Auth:          MetricsAuthConfig{AllowUnauthenticated: false},
				IncludeSystem: true,
				Loki: MetricsLokiConfig{
					MaxEntries: 1000,
					MaxAge:     "1h",
				},
				IncludeRuntime:  true,
				DurationBuckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
				SizeBuckets:     []float64{100, 1000, 10000, 100000, 1000000, 10000000},
			},
			Logging: LoggingConfig{
				Level:        "warn",
				AccessFormat: "apache",
				Access: LogFileConfig{
					Enabled:  true,
					Filename: "access.log",
					Format:   "apache",
					Rotate:   "monthly",
					Keep:     "none",
				},
				Server: LogFileConfig{
					Enabled:  true,
					Filename: "server.log",
					Format:   "text",
					Rotate:   "weekly",
					Keep:     "none",
				},
				Error: LogFileConfig{
					Enabled:  true,
					Filename: "error.log",
					Format:   "text",
					Rotate:   "weekly",
					Keep:     "none",
				},
				App: LogFileConfig{
					Enabled:  true,
					Filename: "app.log",
					Format:   "logfmt",
					Rotate:   "weekly",
					Keep:     "none",
				},
				Auth: LogFileConfig{
					Enabled:  true,
					Filename: "auth.log",
					Format:   "syslog",
					Rotate:   "weekly",
					Keep:     "none",
				},
				Audit: AuditLogFileConfig{
					LogFileConfig: LogFileConfig{
						Enabled:  true,
						Filename: "audit.log",
						Format:   "json",
						Rotate:   "daily",
						Keep:     "none",
					},
					Events: AuditEventFilterConfig{
						Configuration: true,
						Security:      true,
						Backup:        true,
						Server:        true,
					},
					IncludeUserAgent: true,
				},
				Security: LogFileConfig{
					Enabled:  true,
					Filename: "security.log",
					Format:   "fail2ban",
					Rotate:   "weekly",
					Keep:     "none",
				},
				Debug: LogFileConfig{
					Enabled:  false,
					Filename: "debug.log",
					Format:   "text",
					Rotate:   "weekly",
					Keep:     "none",
				},
			},
			GeoIP: GeoIPConfig{
				Enabled:        true,
				Dir:            "",
				DenyCountries:  []string{},
				AllowCountries: []string{},
				Presets:        map[string][]string{},
				Databases: GeoIPDatabasesConfig{
					ASN:     true,
					Country: true,
					City:    true,
					WHOIS:   true,
				},
			},
			I18n: I18nConfig{
				Enabled:            true,
				DefaultLanguage:    "en",
				AvailableLanguages: []string{"en", "es", "zh", "fr", "ar", "de", "ja"},
				FallbackLanguage:   "en",
			},
			Healthz: HealthzConfig{
				Root: RootHealthzConfig{Enabled: false},
			},
			Contact:  ContactConfig{},
			Tracking: TrackingConfig{},
			Privacy: PrivacyConfig{
				Data: DataPolicy{
					Sold:           false,
					StoredOnServer: true,
				},
				Retention: RetentionPolicy{
					Period:            "Account data is retained while your account is active. Upon account deletion, all personal data is permanently deleted within 30 days. Anonymized analytics data may be retained for up to 12 months.",
					ExportAvailable:   true,
					DeletionAvailable: true,
				},
				Consent: consentDefaults(),
				Cookies: CookieCategories{
					Essential:   CookieCategory{Enabled: true, Description: "Required for the site to function."},
					Preferences: CookieCategory{Enabled: true, Description: "Remember your preferences."},
					Analytics: AnalyticsCookie{
						CookieCategory:           CookieCategory{Enabled: true, Description: "Usage analytics."},
						DescriptionSuffixNotSold: "Data is not sold.",
						DescriptionSuffixSold:    "Data may be shared with advertising partners.",
					},
				},
			},
			Cache: CacheConfig{
				Type:     "memory",
				Host:     "localhost",
				Port:     6379,
				PoolSize: 10,
				MinIdle:  2,
				Timeout:  "5s",
				Prefix:   "ipgaze:",
				TTL:      "1h",
			},
			SSL: SSLConfig{
				Enabled:     false,
				LetsEncrypt: LetsEncryptConfig{Enabled: false, Staging: false},
			},
			Maintenance: MaintenanceConfig{
				SelfHealing: MaintenanceSelfHealingConfig{
					Enabled:       true,
					RetryInterval: "30s",
					MaxAttempts:   0,
				},
				Cleanup: MaintenanceCleanupConfig{
					DiskThreshold:    90,
					LogRetentionDays: 7,
					BackupKeepCount:  5,
				},
				Notify: MaintenanceNotifyConfig{
					OnEnter: true,
					OnExit:  true,
				},
			},
			Branding: BrandingConfig{
				ThemeColor: "#bd93f9",
			},
			SEO: DefaultSEOConfig(),
			RateLimit: RateLimitConfig{
				Enabled:     true,
				Read:        RateLimitBucketConfig{Requests: 120, Window: 60},
				Write:       RateLimitBucketConfig{Requests: 10, Window: 60},
				Health:      RateLimitBucketConfig{Requests: 120, Window: 60},
				GlobalBurst: 240,
			},
			Limits: LimitsConfig{
				MaxBodySize:  "10MB",
				ReadTimeout:  "30s",
				WriteTimeout: "30s",
				IdleTimeout:  "120s",
			},
			Compression: CompressionConfig{
				Enabled: true,
				Level:   5,
				Types: []string{
					"text/html",
					"text/css",
					"text/javascript",
					"application/json",
					"application/xml",
				},
			},
			TrustedProxies: TrustedProxiesConfig{
				Additional: []string{},
			},
			URLDetection: URLDetectionConfig{
				Learning:     true,
				MinSamples:   3,
				SampleWindow: "5m",
				LogChanges:   true,
				LiveReload:   true,
			},
			Notifications: ServerNotificationsConfig{
				Email: EmailNotificationsConfig{
					Enabled: false,
					SMTP: SMTPSubConfig{
						Port: 587,
						TLS:  "auto",
					},
					Events: EmailEventsConfig{
						Startup:          false,
						Shutdown:         false,
						BackupComplete:   false,
						BackupFailed:     true,
						SSLExpiring:      true,
						SSLRenewed:       false,
						SSLRenewalFailed: true,
						SecurityAlert:    true,
						SchedulerError:   true,
						UpdateAvailable:  false,
						UpdateInstalled:  true,
					},
				},
			},
			Backup: BackupConfig{
				Encryption: BackupEncryptionConfig{
					Enabled: false,
				},
				Retention: BackupRetentionConfig{
					MaxBackups:   1,
					KeepWeekly:   0,
					KeepMonthly:  0,
					KeepYearly:   0,
					MaxTotalSize: "10%",
				},
			},
			Compliance: ComplianceConfig{
				Enabled: false,
			},
			CLI: CLIConfig{
				BinaryDownload: CLIBinaryDownloadConfig{
					RequireAuth: false,
				},
			},
			Debug: DebugConfig{
				Pprof:                true,
				LogQueries:           true,
				LogCache:             true,
				LogBodies:            false,
				MaxBodyLogSize:       "10KB",
				BlockProfileRate:     1,
				MutexProfileFraction: 1,
				RuntimeEndpoints:     true,
			},
		},
		Web: WebConfig{
			UI: WebUIConfig{
				Theme:   "dark",
				Logo:    "",
				Favicon: "",
				Notifications: NotificationsConfig{
					Enabled:       true,
					Announcements: []string{},
				},
				Announcements: AnnouncementsConfig{
					Enabled:  false,
					Messages: []AnnouncementMessage{},
				},
			},
			Robots: WebRobotsConfig{
				Allow: []string{"/", "/api"},
				Deny:  []string{"/debug"},
				AIBots: AIBotsConfig{
					Default: "allow",
					Bots:    DefaultAIBots(),
				},
			},
			CORS: "*",
			CSRF: CSRFConfig{
				Enabled:     true,
				TokenLength: 32,
				CookieName:  "csrf_token",
				HeaderName:  "X-CSRF-Token",
				Secure:      "auto",
				ExemptPaths: []string{"/api/v1/webhooks/*"},
			},
			Security: WebSecurityConfig{
				Keyservers:    []string{"keys.openpgp.org", "keyserver.ubuntu.com"},
				PublishPGPKey: true,
			},
			HSTS:              DefaultHSTSConfig(),
			PermissionsPolicy: DefaultPermissionsPolicy(),
			CSP:               DefaultCSPConfig(),
			Headers:           DefaultSecurityHeaders(),
			Reports:           DefaultReportsConfig(),
		},
		Data: DataConfig{
			CVE: CVEDataConfig{
				Source:      "https://services.nvd.nist.gov/rest/json/cves/2.0",
				FilterByCPE: false,
			},
		},
	}
}

// migrateYamlToYml migrates .yaml files to .yml
func migrateYamlToYml(path string) string {
	// Only check if path ends with .yml
	if !strings.HasSuffix(path, ".yml") {
		return path
	}

	// Check if .yaml version exists
	yamlPath := strings.TrimSuffix(path, ".yml") + ".yaml"
	if _, err := os.Stat(yamlPath); err == nil {
		// .yaml file exists, check if .yml doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Rename .yaml to .yml
			if err := os.Rename(yamlPath, path); err == nil {
				fmt.Printf("Migrated configuration: %s -> %s\n", yamlPath, path)
			}
		}
	}

	return path
}

// Load loads configuration from a YAML file
// LoadConfigFromFile loads and returns configuration from the given YAML path.
// Creates a default config file at path if it does not exist.
func LoadConfigFromFile(path string) (*AppConfig, error) {
	mu.Lock()
	defer mu.Unlock()

	// Migrate .yaml to .yml if needed
	path = migrateYamlToYml(path)
	configPath = path

	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		// APPLICATION_NAME/APPLICATION_TAGLINE are Init-Only env vars (PART 12):
		// they seed server.yml on first run only and are never re-read afterward.
		if envName := os.Getenv("APPLICATION_NAME"); envName != "" {
			cfg.Server.Branding.Title = envName
		}
		if envTagline := os.Getenv("APPLICATION_TAGLINE"); envTagline != "" {
			cfg.Server.Branding.Tagline = envTagline
		}
		if err := saveConfig(cfg, path); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		applyRuntimeDatabaseEnv(cfg)
		current = cfg
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	validateConfig(cfg)
	applyRuntimeDatabaseEnv(cfg)
	current = cfg
	return cfg, nil
}

// applyRuntimeDatabaseEnv re-checks the DATABASE_DRIVER/DATABASE_URL Runtime
// env vars (PART 12) on every start, overriding the persisted server.yml
// values in memory only — never written back to disk.
func applyRuntimeDatabaseEnv(cfg *AppConfig) {
	if envDriver := os.Getenv("DATABASE_DRIVER"); envDriver != "" {
		cfg.Server.Database.Driver = envDriver
	}
	if envURL := os.Getenv("DATABASE_URL"); envURL != "" {
		cfg.Server.Database.URL = envURL
	}
}

// validateConfig validates all config values, replacing invalid ones with safe defaults.
// It logs warnings but never returns an error — the server must start regardless.
func validateConfig(cfg *AppConfig) {
	def := DefaultConfig()

	// The sitemap protocol caps a single file at 50000 URLs; anything outside
	// 1..50000 is meaningless (AI.md PART 24 "Sitemap Configuration").
	if cfg.Server.SEO.Sitemap.MaxURLs <= 0 || cfg.Server.SEO.Sitemap.MaxURLs > 50000 {
		warnConfigReplaced("server.seo.sitemap.max_urls", cfg.Server.SEO.Sitemap.MaxURLs,
			def.Server.SEO.Sitemap.MaxURLs)
		cfg.Server.SEO.Sitemap.MaxURLs = def.Server.SEO.Sitemap.MaxURLs
	}

	// Verification codes are validated on startup so operators see the error in
	// the log rather than silently missing meta tags (AI.md PART 24).
	cfg.Server.SEO.Verification.ValidVerificationCodes()
	cfg.Server.SEO.Verification.ValidCustomTags()

	// Cache type must be one of the supported backends.
	switch cfg.Server.Cache.Type {
	case "none", "memory", "valkey", "redis":
	default:
		warnConfigReplaced("server.cache.type", cfg.Server.Cache.Type, def.Server.Cache.Type)
		cfg.Server.Cache.Type = def.Server.Cache.Type
	}

	// Cache pool size must be positive.
	if cfg.Server.Cache.PoolSize < 1 {
		warnConfigReplaced("server.cache.pool_size", cfg.Server.Cache.PoolSize, def.Server.Cache.PoolSize)
		cfg.Server.Cache.PoolSize = def.Server.Cache.PoolSize
	}

	// Maintenance disk threshold must be 1-100.
	if cfg.Server.Maintenance.Cleanup.DiskThreshold < 1 || cfg.Server.Maintenance.Cleanup.DiskThreshold > 100 {
		warnConfigReplaced("server.maintenance.cleanup.disk_threshold",
			cfg.Server.Maintenance.Cleanup.DiskThreshold, def.Server.Maintenance.Cleanup.DiskThreshold)
		cfg.Server.Maintenance.Cleanup.DiskThreshold = def.Server.Maintenance.Cleanup.DiskThreshold
	}

	// Log retention days must be positive.
	if cfg.Server.Maintenance.Cleanup.LogRetentionDays < 1 {
		warnConfigReplaced("server.maintenance.cleanup.log_retention_days",
			cfg.Server.Maintenance.Cleanup.LogRetentionDays, def.Server.Maintenance.Cleanup.LogRetentionDays)
		cfg.Server.Maintenance.Cleanup.LogRetentionDays = def.Server.Maintenance.Cleanup.LogRetentionDays
	}

	// Database driver must be recognised.
	switch cfg.Server.Database.Driver {
	case "sqlite", "sqlite2", "sqlite3", "libsql", "turso":
	default:
		warnConfigReplaced("server.database.driver", cfg.Server.Database.Driver, def.Server.Database.Driver)
		cfg.Server.Database.Driver = def.Server.Database.Driver
	}

	// Database pool sizes must be positive and max_idle must not exceed max_open.
	if cfg.Server.Database.Pool.MaxOpen < 1 {
		warnConfigReplaced("server.database.pool.max_open",
			cfg.Server.Database.Pool.MaxOpen, def.Server.Database.Pool.MaxOpen)
		cfg.Server.Database.Pool.MaxOpen = def.Server.Database.Pool.MaxOpen
	}
	if cfg.Server.Database.Pool.MaxIdle < 1 || cfg.Server.Database.Pool.MaxIdle > cfg.Server.Database.Pool.MaxOpen {
		warnConfigReplaced("server.database.pool.max_idle",
			cfg.Server.Database.Pool.MaxIdle, def.Server.Database.Pool.MaxIdle)
		cfg.Server.Database.Pool.MaxIdle = def.Server.Database.Pool.MaxIdle
	}

	// Logging level must be a valid level.
	switch cfg.Server.Logging.Level {
	case "error", "warn", "info", "debug":
	default:
		warnConfigReplaced("server.logging.level", cfg.Server.Logging.Level, def.Server.Logging.Level)
		cfg.Server.Logging.Level = def.Server.Logging.Level
	}

	// Mode must not be empty.
	if cfg.Server.Mode == "" {
		warnConfigReplaced("server.mode", cfg.Server.Mode, def.Server.Mode)
		cfg.Server.Mode = def.Server.Mode
	}

	// PGP keyservers list must not be empty.
	if len(cfg.Web.Security.Keyservers) == 0 {
		warnConfigReplaced("web.security.keyservers", cfg.Web.Security.Keyservers, def.Web.Security.Keyservers)
		cfg.Web.Security.Keyservers = def.Web.Security.Keyservers
	}

	// CVE feed source must not be empty.
	if cfg.Data.CVE.Source == "" {
		warnConfigReplaced("data.cve.source", cfg.Data.CVE.Source, def.Data.CVE.Source)
		cfg.Data.CVE.Source = def.Data.CVE.Source
	}

	// CSP mode must be enforce, report-only, or empty (automatic).
	switch strings.ToLower(strings.TrimSpace(cfg.Web.CSP.Mode)) {
	case "", "enforce", "report-only", "report_only", "reportonly":
	default:
		warnConfigReplaced("web.csp.mode", cfg.Web.CSP.Mode, def.Web.CSP.Mode)
		cfg.Web.CSP.Mode = def.Web.CSP.Mode
	}

	// HSTS max-age must be positive.
	if cfg.Web.HSTS.MaxAgeSeconds < 1 {
		warnConfigReplaced("web.hsts.max_age_seconds", cfg.Web.HSTS.MaxAgeSeconds, def.Web.HSTS.MaxAgeSeconds)
		cfg.Web.HSTS.MaxAgeSeconds = def.Web.HSTS.MaxAgeSeconds
	}

	// NEL max-age must be positive.
	if cfg.Web.Headers.NEL.MaxAgeSeconds < 1 {
		warnConfigReplaced("web.headers.nel.max_age_seconds",
			cfg.Web.Headers.NEL.MaxAgeSeconds, def.Web.Headers.NEL.MaxAgeSeconds)
		cfg.Web.Headers.NEL.MaxAgeSeconds = def.Web.Headers.NEL.MaxAgeSeconds
	}

	// Sample rates are fractions in the 0.0..1.0 range.
	if cfg.Web.Headers.NEL.SampleRate < 0 || cfg.Web.Headers.NEL.SampleRate > 1 {
		warnConfigReplaced("web.headers.nel.sample_rate",
			cfg.Web.Headers.NEL.SampleRate, def.Web.Headers.NEL.SampleRate)
		cfg.Web.Headers.NEL.SampleRate = def.Web.Headers.NEL.SampleRate
	}
	if cfg.Web.CSP.ReportsSampleRate < 0 || cfg.Web.CSP.ReportsSampleRate > 1 {
		warnConfigReplaced("web.csp.reports_sample_rate",
			cfg.Web.CSP.ReportsSampleRate, def.Web.CSP.ReportsSampleRate)
		cfg.Web.CSP.ReportsSampleRate = def.Web.CSP.ReportsSampleRate
	}

	// Report endpoint rate limits must be positive.
	if cfg.Web.Reports.RateLimitPerMinute < 1 {
		warnConfigReplaced("web.reports.rate_limit_per_minute",
			cfg.Web.Reports.RateLimitPerMinute, def.Web.Reports.RateLimitPerMinute)
		cfg.Web.Reports.RateLimitPerMinute = def.Web.Reports.RateLimitPerMinute
	}
	if cfg.Web.Reports.RateLimitPerIPBurst < 1 {
		warnConfigReplaced("web.reports.rate_limit_per_ip_burst",
			cfg.Web.Reports.RateLimitPerIPBurst, def.Web.Reports.RateLimitPerIPBurst)
		cfg.Web.Reports.RateLimitPerIPBurst = def.Web.Reports.RateLimitPerIPBurst
	}

	// Permissions-Policy must not be empty or the header would be omitted.
	if len(cfg.Web.PermissionsPolicy) == 0 {
		cfg.Web.PermissionsPolicy = def.Web.PermissionsPolicy
	}

	// Overly broad allowlist ranges are rejected unless explicitly confirmed.
	cfg.Server.Security.Allowlist = validateAllowlist(cfg.Server.Security.Allowlist)
}

// warnConfigReplaced logs the WARN that AI.md PART 12 "Config Validation Rule"
// requires whenever an invalid setting is silently swapped for its default.
// Startup always continues — the warning is the operator's only signal that
// what they wrote in server.yml is not what the server is running.
func warnConfigReplaced(key string, invalid, replacement any) {
	slog.Warn("invalid config value replaced with default",
		"key", key, "invalid", invalid, "using", replacement)
}

// isOverlyBroadAllowlistRange reports whether cidr is broad enough that it
// defeats the purpose of an allowlist: /0 through /7 for IPv4, /0 through
// /15 for IPv6 (AI.md PART 12 "Validation"). Bare IPs (no "/" suffix) are
// never broad — normalizing them to /32 or /128 is what the allowlist
// lookup itself does. Unparseable input is treated as not broad; it is
// rejected elsewhere as simply invalid.
func isOverlyBroadAllowlistRange(rawCIDR string) bool {
	cidr := strings.TrimSpace(rawCIDR)
	if cidr == "" || !strings.Contains(cidr, "/") {
		return false
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := ipnet.Mask.Size()
	if ip.To4() != nil {
		return ones <= 7
	}
	return ones <= 15
}

// validateAllowlist drops overly broad allowlist entries that are not
// explicitly confirmed, logging a WARN for each so the operator can add
// `confirmed: true` if the broad range is intentional. Per AI.md PART 12
// "Validation": "Reject overly broad ranges with confirmation."
func validateAllowlist(entries []AllowlistEntry) []AllowlistEntry {
	if len(entries) == 0 {
		return entries
	}
	kept := make([]AllowlistEntry, 0, len(entries))
	for _, e := range entries {
		if isOverlyBroadAllowlistRange(e.CIDR) && !e.Confirmed {
			slog.Warn("allowlist entry rejected: overly broad range requires confirmed: true to accept",
				"cidr", e.CIDR, "description", e.Description)
			continue
		}
		kept = append(kept, e)
	}
	return kept
}

// getCurrentConfig returns the current in-memory configuration.
// Returns DefaultConfig() if no config has been loaded yet.
func getCurrentConfig() *AppConfig {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil {
		return DefaultConfig()
	}
	return current
}

// getConfigPath returns the path of the currently loaded configuration file.
func getConfigPath() string {
	mu.RLock()
	defer mu.RUnlock()
	return configPath
}

// SaveConfigToFile writes the current in-memory configuration to the loaded config path.
func SaveConfigToFile() error {
	mu.Lock()
	defer mu.Unlock()
	if current == nil || configPath == "" {
		return fmt.Errorf("no configuration loaded")
	}
	return saveConfig(current, configPath)
}

// reloadConfigFromFile re-reads configuration from the previously loaded path.
func reloadConfigFromFile() error {
	mu.Lock()
	defer mu.Unlock()
	if configPath == "" {
		return fmt.Errorf("no configuration path set")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	current = cfg
	return nil
}

// saveConfig writes configuration to a YAML file
func saveConfig(cfg *AppConfig, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	content := generateConfigYAML(cfg)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// formatAllowlist renders security.allowlist entries as an indented YAML block.
func formatAllowlist(entries []AllowlistEntry) string {
	if len(entries) == 0 {
		return "    allowlist: []\n"
	}
	var b strings.Builder
	b.WriteString("    allowlist:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "      - cidr: %q\n        description: %q\n", e.CIDR, e.Description)
	}
	return b.String()
}

// formatTaskOverride renders a single scheduler task override block.
func formatTaskOverride(name string, t TaskScheduleConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "      %s:\n", name)
	fmt.Fprintf(&b, "        schedule: %q\n", t.Schedule)
	if t.Enabled != nil {
		fmt.Fprintf(&b, "        enabled: %t\n", *t.Enabled)
	}
	return b.String()
}

// formatScheduleTasks renders all per-task scheduler overrides under schedule.tasks.
func formatScheduleTasks(t ScheduleTasksConfig) string {
	var b strings.Builder
	b.WriteString(formatTaskOverride("ssl_renewal", t.SSLRenewal))
	b.WriteString(formatTaskOverride("geoip_update", t.GeoIPUpdate))
	b.WriteString(formatTaskOverride("blocklist_update", t.BlocklistUpdate))
	b.WriteString(formatTaskOverride("threat_update", t.ThreatUpdate))
	b.WriteString(formatTaskOverride("cve_update", t.CVEUpdate))
	b.WriteString(formatTaskOverride("update_check", t.UpdateCheck))
	b.WriteString(formatTaskOverride("token_cleanup", t.TokenCleanup))
	b.WriteString(formatTaskOverride("log_rotation", t.LogRotation))
	b.WriteString(formatTaskOverride("backup_daily", t.BackupDaily))
	b.WriteString(formatTaskOverride("backup_hourly", t.BackupHourly))
	b.WriteString(formatTaskOverride("healthcheck_self", t.HealthcheckSelf))
	b.WriteString(formatTaskOverride("tor_health", t.TorHealth))
	return strings.TrimRight(b.String(), "\n")
}

// formatLogFile renders a single per-file logging block at 4-space indent.
func formatLogFile(name string, l LogFileConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "    %s:\n", name)
	fmt.Fprintf(&b, "      enabled: %t\n", l.Enabled)
	fmt.Fprintf(&b, "      filename: %q\n", l.Filename)
	fmt.Fprintf(&b, "      format: %q\n", l.Format)
	if l.Custom != "" {
		fmt.Fprintf(&b, "      custom: %q\n", l.Custom)
	}
	fmt.Fprintf(&b, "      rotate: %q\n", l.Rotate)
	fmt.Fprintf(&b, "      keep: %q\n", l.Keep)
	return b.String()
}

// formatAuditLogFile renders the audit log block, which extends LogFileConfig
// with compression, event-category filters, and user-agent inclusion.
func formatAuditLogFile(a AuditLogFileConfig) string {
	var b strings.Builder
	b.WriteString(formatLogFile("audit", a.LogFileConfig))
	fmt.Fprintf(&b, "      compress: %t\n", a.Compress)
	fmt.Fprintf(&b, "      include_user_agent: %t\n", a.IncludeUserAgent)
	b.WriteString("      events:\n")
	fmt.Fprintf(&b, "        configuration: %t\n", a.Events.Configuration)
	fmt.Fprintf(&b, "        security: %t\n", a.Events.Security)
	fmt.Fprintf(&b, "        backup: %t\n", a.Events.Backup)
	fmt.Fprintf(&b, "        server: %t\n", a.Events.Server)
	return b.String()
}

// formatLoggingFiles renders all per-file logging blocks under server.logging.
func formatLoggingFiles(l LoggingConfig) string {
	var b strings.Builder
	b.WriteString(formatLogFile("access", l.Access))
	b.WriteString(formatLogFile("server", l.Server))
	b.WriteString(formatLogFile("error", l.Error))
	b.WriteString(formatLogFile("app", l.App))
	b.WriteString(formatLogFile("auth", l.Auth))
	b.WriteString(formatAuditLogFile(l.Audit))
	b.WriteString(formatLogFile("security", l.Security))
	b.WriteString(formatLogFile("debug", l.Debug))
	return strings.TrimRight(b.String(), "\n")
}

// generateConfigYAML generates YAML content with comments
func generateConfigYAML(cfg *AppConfig) string {
	return fmt.Sprintf(`# IPGaze Server Configuration
# Documentation: https://ifcfg.us/docs

server:
  # Operator token for authenticated maintenance operations. Auto-generated
  # on first run; treat as a secret, never share or log the raw value.
  token: "%s"
  port: "%s"
  fqdn: "%s"
  baseurl: "%s"
  address: "%s"

  # Local SQLite or remote libsql/Turso database connection
  database:
    driver: "%s"
    url: "%s"
    token: "%s"
    # Connection pool (libsql/remote mainly; SQLite uses a single writer)
    pool:
      max_open: %d
      max_idle: %d
      max_lifetime: "%s"
      max_idle_time: "%s"

  healthz:
    root:
      enabled: %t

  schedule:
    enabled: %t
    geoip_update: "%s"
    timezone: "%s"
    catch_up_window: "%s"
    # Per-task schedule/enabled overrides; blank schedule uses the built-in default
    tasks:
%s

  metrics:
    enabled: %t
    # Root aliases /metrics and /metrics/{service}
    # (default true - Prometheus scrapers expect /metrics)
    root:
      enabled: %t
    auth:
      # true skips token checks for ALL metrics services
      # ONLY for firewalled internal networks - never on a public server
      allow_unauthenticated: %t
      # Per-service bearer tokens; blank disables that service with a 403
      tokens:
        prometheus: "%s"
        grafana: "%s"
        loki: "%s"
    include_system: %t
    include_runtime: %t
    # Loki service - how much recent log to serve
    loki:
      max_entries: %d
      max_age: "%s"

  # Per-class request rate limiting (read/write/health buckets + global ceiling)
  rate_limit:
    enabled: %t
    read:
      requests: %d
      window: %d
    write:
      requests: %d
      window: %d
    health:
      requests: %d
      window: %d
    global_burst: %d

  # Request size and timeout limits
  limits:
    max_body_size: "%s"
    read_timeout: "%s"
    write_timeout: "%s"
    idle_timeout: "%s"

  # Response compression
  compression:
    enabled: %t
    level: %d
    types: %s

  # Additional trusted reverse-proxy CIDRs beyond the built-in private ranges
  trusted_proxies:
    additional: %s

  # Smart FQDN/proto/baseurl learning from reverse proxy headers
  url_detection:
    learning: %t
    min_samples: %d
    sample_window: "%s"
    log_changes: %t
    live_reload: %t

  logging:
    access_format: "%s"
    level: "%s"
%s

  geoip:
    enabled: %t
    dir: "%s"
    deny_countries: %s
    allow_countries: %s
    # Named operator-authored country lists, reusable in the two fields above.
    # Ships empty; nothing here is ever applied unless it is named above.
    presets: %s
    databases:
      asn: %t
      country: %t
      city: %t
      whois: %t

  tor:
    binary: "%s"
    use_network: %t
    max_circuits: %d
    circuit_timeout: %d
    bootstrap_timeout: %d
    safe_logging: %t
    max_streams_per_circuit: %d
    bandwidth_rate: "%s"
    bandwidth_burst: "%s"
    max_monthly_bandwidth: "%s"
    num_intro_points: %d
    virtual_port: %d

  i2p:
    # OPT-IN: disabled by default. Unlike Tor (auto-enabled when the binary
    # is found), the eepsite is created only when this is true.
    enabled: %t
    binary: "%s"
    sam_address: "%s"
    virtual_port: %d
    inbound_length: %d
    outbound_length: %d
    inbound_quantity: %d
    outbound_quantity: %d
    signature_type: %d
    bootstrap_timeout: %d

  contact:
    admin:
      email: "%s"
      webhooks:
        telegram: "%s"
        telegram_secret: "%s"
        discord: "%s"
        discord_secret: "%s"
        slack: "%s"
        slack_secret: "%s"
        mattermost: "%s"
        mattermost_secret: "%s"
        pushover: "%s"
        pushover_secret: "%s"
        gotify: "%s"
        gotify_secret: "%s"
        generic: "%s"
        generic_secret: "%s"
    security:
      email: "%s"
      webhooks:
        telegram: "%s"
        telegram_secret: "%s"
        discord: "%s"
        discord_secret: "%s"
        slack: "%s"
        slack_secret: "%s"
        mattermost: "%s"
        mattermost_secret: "%s"
        pushover: "%s"
        pushover_secret: "%s"
        gotify: "%s"
        gotify_secret: "%s"
        generic: "%s"
        generic_secret: "%s"
    abuse:
      email: "%s"
      webhooks:
        telegram: "%s"
        telegram_secret: "%s"
        discord: "%s"
        discord_secret: "%s"
        slack: "%s"
        slack_secret: "%s"
        mattermost: "%s"
        mattermost_secret: "%s"
        pushover: "%s"
        pushover_secret: "%s"
        gotify: "%s"
        gotify_secret: "%s"
        generic: "%s"
        generic_secret: "%s"
    general:
      email: "%s"
      webhooks:
        telegram: "%s"
        telegram_secret: "%s"
        discord: "%s"
        discord_secret: "%s"
        slack: "%s"
        slack_secret: "%s"
        mattermost: "%s"
        mattermost_secret: "%s"
        pushover: "%s"
        pushover_secret: "%s"
        gotify: "%s"
        gotify_secret: "%s"
        generic: "%s"
        generic_secret: "%s"

  tracking:
    type: "%s"
    id: "%s"
    url: "%s"

  privacy:
    data:
      sold: %t
      stored_on_server: %t
    retention:
      period: "%s"
      export_available: %t
      deletion_available: %t
    consent:
      show_until_acknowledged: %t
      default_enabled: %t
      message: "%s"
      message_if_sold: "%s"
      position: "%s"

  cache:
    type: "%s"
    url: "%s"
    host: "%s"
    port: %d
    username: "%s"
    password: "%s"
    db: %d
    tls: %t
    tls_skip_verify: %t
    pool_size: %d
    min_idle: %d
    timeout: "%s"
    prefix: "%s"
    ttl: "%s"

  ssl:
    enabled: %t
    letsencrypt:
      enabled: %t
      email: "%s"
      staging: %t
      challenge: "%s"
      dns_provider: "%s"
      dns_credentials:
        provider: "%s"
        credentials_encrypted: "%s"
        validated_at: "%s"

  # EncryptionKey is the base64-encoded 32-byte AES-256-GCM key used to encrypt
  # sensitive at-rest data (e.g. DNS-01 provider credentials), per AI.md PART 11.
  security:
    encryption_key: "%s"
    # Trusted IP/CIDR entries that bypass blocklist, rate limiting, and GeoIP
%s

  maintenance:
    self_healing:
      enabled: %t
      retry_interval: "%s"
      max_attempts: %d
    cleanup:
      disk_threshold: %d
      log_retention_days: %d
      backup_keep_count: %d
    notify:
      on_enter: %t
      on_exit: %t

  branding:
    title: "%s"
    tagline: "%s"
    description: "%s"
    logo_url: "%s"
    favicon_url: "%s"
    theme_color: "%s"

  seo:
    # Meta keywords, e.g. ["ip", "geolocation", "api"]
    keywords: []
    # Author or organization name for the meta author tag
    author: "%s"
    # OpenGraph and Twitter card image URL
    og_image: "%s"
    # Twitter @handle credited on cards
    twitter_handle: "%s"
    # Site-ownership codes; invalid values are dropped, never rendered
    verification:
      # Google Search Console
      google: "%s"
      # Bing Webmaster Tools
      bing: "%s"
      # Yandex Webmaster
      yandex: "%s"
      # Baidu Webmaster
      baidu: "%s"
      # Pinterest
      pinterest: "%s"
      # Facebook domain verification
      facebook: "%s"
      # Additional tags: [{name: "...", content: "..."}]
      custom: []
    sitemap:
      # Serve the generated /sitemap.xml
      enabled: %t
      # Sitemap protocol limit
      max_urls: %d
      # Include image URLs in each entry
      include_images: %t

  notifications:
    email:
      smtp:
        host: ""
        port: 587
        username: ""
        password: ""
        tls: auto
      from:
        name: ""
        email: ""
      events:
        startup: %t
        shutdown: %t
        backup_complete: %t
        backup_failed: %t
        ssl_expiring: %t
        ssl_renewed: %t
        ssl_renewal_failed: %t
        security_alert: %t
        scheduler_error: %t
        update_available: %t
        update_installed: %t

  backup:
    encryption:
      enabled: %t
    retention:
      max_backups: %d
      keep_weekly: %d
      keep_monthly: %d
      keep_yearly: %d
      max_total_size: "%s"

  compliance:
    enabled: %t

  cli:
    binary_download:
      require_auth: %t

  # Debug-only diagnostics; every field here is inert unless --debug/DEBUG is also active
  debug:
    pprof: %t
    log_queries: %t
    log_cache: %t
    log_bodies: %t
    max_body_log_size: "%s"
    block_profile_rate: %d
    mutex_profile_fraction: %d
    runtime_endpoints: %t

tor:
  onion_address: "%s"
  contact_email: "%s"

web:
  ui:
    theme: "%s"
    logo: "%s"
    favicon: "%s"
    notifications:
      enabled: %t
      announcements: %s
  robots:
    allow: %s
    deny: %s
    # Per-AI-crawler access control (default: allow all - no AI blocking)
    ai_bots:
      # Applies to any recognized AI bot not listed individually below
      default: "%s"
      # Per-bot overrides: allow | deny
      bots:
%s
  cors: "%s"
  footer:
    custom_html: "%s"
  # Strict-Transport-Security; only emitted when SSL is enabled
  hsts:
    enabled: %t
    # 63072000 = 2 years, eligible for the browser preload list
    max_age_seconds: %d
    include_subdomains: %t
    preload: %t
  # Browser feature allowlist. "()" denies everywhere, "(self)" allows
  # same-origin only, "" omits the feature so the browser default applies
  permissions_policy:
%s
  csp:
    enabled: %t
    # "enforce" | "report-only"; empty means report-only in debug, enforce otherwise
    mode: "%s"
    # Per-directive append — added to the built-in default for that directive
    script_src_extra: "%s"
    style_src_extra: "%s"
    img_src_extra: "%s"
    font_src_extra: "%s"
    connect_src_extra: "%s"
    frame_src_extra: "%s"
    form_action_extra: "%s"
    # Per-directive override — REPLACES the built-in default. Use sparingly
    script_src_override: "%s"
    style_src_override: "%s"
    img_src_override: "%s"
    font_src_override: "%s"
    connect_src_override: "%s"
    frame_src_override: "%s"
    form_action_override: "%s"
    reports_enabled: %t
    # 0.0 .. 1.0 — sample to control volume on busy sites
    reports_sample_rate: %g
  headers:
    content_type_options: "%s"
    frame_options: "%s"
    xss_protection: "%s"
    referrer_policy: "%s"
    # Cross-Origin-Opener-Policy
    coop: "%s"
    # Cross-Origin-Embedder-Policy
    coep: "%s"
    # Cross-Origin-Resource-Policy
    corp: "%s"
    origin_agent_cluster: %t
    # X-Permitted-Cross-Domain-Policies
    cross_domain_policies: "%s"
    # "" = omit (browser default); "off" = privacy-strict
    dns_prefetch_control: "%s"
    # treat "Sec-GPC: 1" as an opt-out signal
    honor_sec_gpc: %t
    # DNT is dead in modern browsers — off by default
    honor_dnt: %t
    # reject cross-site state-changing requests
    sec_fetch_validation: %t
    # never emit Server-Timing in production
    server_timing_in_debug_only: %t
    clear_site_data:
      on_token_revocation: %t
      on_consent_withdrawal: %t
      # set true to also reload SPA tabs on token revocation
      execution_contexts: %t
    # Network Error Logging
    nel:
      enabled: %t
      # 2592000 = 30 days
      max_age_seconds: %d
      include_subdomains: %t
      # 0.0 .. 1.0 — sample failures to control report volume
      sample_rate: %g
  # Public browser-report endpoints (/api/v1/server/reports/*)
  reports:
    # max reports/min/IP across all report types
    rate_limit_per_minute: %d
    # short-burst allowance
    rate_limit_per_ip_burst: %d

data:
  cve:
    # NVD (NIST National Vulnerability Database) CVE API 2.0 endpoint
    source: "%s"
    # Filtering the feed to "relevant" CVEs requires reliably deriving CPE
    # strings from the project's dependency manifest; no such mapping is
    # defined, so this stays false — see AI.md PART 20
    filter_by_cpe: %t
`,
		cfg.Server.Token,
		cfg.Server.Port,
		cfg.Server.FQDN,
		cfg.Server.BaseURL,
		cfg.Server.Address,
		cfg.Server.Database.Driver,
		cfg.Server.Database.URL,
		cfg.Server.Database.Token,
		cfg.Server.Database.Pool.MaxOpen,
		cfg.Server.Database.Pool.MaxIdle,
		cfg.Server.Database.Pool.MaxLifetime,
		cfg.Server.Database.Pool.MaxIdleTime,
		cfg.Server.Healthz.Root.Enabled,
		cfg.Server.Schedule.Enabled,
		cfg.Server.Schedule.GeoIPUpdate,
		cfg.Server.Schedule.Timezone,
		cfg.Server.Schedule.CatchUpWindow,
		formatScheduleTasks(cfg.Server.Schedule.Tasks),
		cfg.Server.Metrics.Enabled,
		cfg.Server.Metrics.Root.Enabled,
		cfg.Server.Metrics.Auth.AllowUnauthenticated,
		cfg.Server.Metrics.Auth.Tokens.Prometheus,
		cfg.Server.Metrics.Auth.Tokens.Grafana,
		cfg.Server.Metrics.Auth.Tokens.Loki,
		cfg.Server.Metrics.IncludeSystem,
		cfg.Server.Metrics.IncludeRuntime,
		cfg.Server.Metrics.Loki.MaxEntries,
		cfg.Server.Metrics.Loki.MaxAge,
		cfg.Server.RateLimit.Enabled,
		cfg.Server.RateLimit.Read.Requests,
		cfg.Server.RateLimit.Read.Window,
		cfg.Server.RateLimit.Write.Requests,
		cfg.Server.RateLimit.Write.Window,
		cfg.Server.RateLimit.Health.Requests,
		cfg.Server.RateLimit.Health.Window,
		cfg.Server.RateLimit.GlobalBurst,
		cfg.Server.Limits.MaxBodySize,
		cfg.Server.Limits.ReadTimeout,
		cfg.Server.Limits.WriteTimeout,
		cfg.Server.Limits.IdleTimeout,
		cfg.Server.Compression.Enabled,
		cfg.Server.Compression.Level,
		formatStringSlice(cfg.Server.Compression.Types),
		formatStringSlice(cfg.Server.TrustedProxies.Additional),
		cfg.Server.URLDetection.Learning,
		cfg.Server.URLDetection.MinSamples,
		cfg.Server.URLDetection.SampleWindow,
		cfg.Server.URLDetection.LogChanges,
		cfg.Server.URLDetection.LiveReload,
		cfg.Server.Logging.AccessFormat,
		cfg.Server.Logging.Level,
		formatLoggingFiles(cfg.Server.Logging),
		cfg.Server.GeoIP.Enabled,
		cfg.Server.GeoIP.Dir,
		formatStringSlice(cfg.Server.GeoIP.DenyCountries),
		formatStringSlice(cfg.Server.GeoIP.AllowCountries),
		formatCountryPresets(cfg.Server.GeoIP.Presets),
		cfg.Server.GeoIP.Databases.ASN,
		cfg.Server.GeoIP.Databases.Country,
		cfg.Server.GeoIP.Databases.City,
		cfg.Server.GeoIP.Databases.WHOIS,
		cfg.Server.Tor.Binary,
		cfg.Server.Tor.UseNetwork,
		cfg.Server.Tor.MaxCircuits,
		cfg.Server.Tor.CircuitTimeout,
		cfg.Server.Tor.BootstrapTimeout,
		cfg.Server.Tor.SafeLogging,
		cfg.Server.Tor.MaxStreamsPerCircuit,
		cfg.Server.Tor.BandwidthRate,
		cfg.Server.Tor.BandwidthBurst,
		cfg.Server.Tor.MaxMonthlyBandwidth,
		cfg.Server.Tor.NumIntroPoints,
		cfg.Server.Tor.VirtualPort,
		cfg.Server.I2P.Enabled,
		cfg.Server.I2P.Binary,
		cfg.Server.I2P.SAMAddress,
		cfg.Server.I2P.VirtualPort,
		cfg.Server.I2P.InboundLength,
		cfg.Server.I2P.OutboundLength,
		cfg.Server.I2P.InboundQuantity,
		cfg.Server.I2P.OutboundQuantity,
		cfg.Server.I2P.SignatureType,
		cfg.Server.I2P.BootstrapTimeout,
		cfg.Server.Contact.Admin.Email,
		cfg.Server.Contact.Admin.Webhooks.Telegram,
		cfg.Server.Contact.Admin.Webhooks.TelegramSecret,
		cfg.Server.Contact.Admin.Webhooks.Discord,
		cfg.Server.Contact.Admin.Webhooks.DiscordSecret,
		cfg.Server.Contact.Admin.Webhooks.Slack,
		cfg.Server.Contact.Admin.Webhooks.SlackSecret,
		cfg.Server.Contact.Admin.Webhooks.Mattermost,
		cfg.Server.Contact.Admin.Webhooks.MattermostSecret,
		cfg.Server.Contact.Admin.Webhooks.Pushover,
		cfg.Server.Contact.Admin.Webhooks.PushoverSecret,
		cfg.Server.Contact.Admin.Webhooks.Gotify,
		cfg.Server.Contact.Admin.Webhooks.GotifySecret,
		cfg.Server.Contact.Admin.Webhooks.Generic,
		cfg.Server.Contact.Admin.Webhooks.GenericSecret,
		cfg.Server.Contact.Security.Email,
		cfg.Server.Contact.Security.Webhooks.Telegram,
		cfg.Server.Contact.Security.Webhooks.TelegramSecret,
		cfg.Server.Contact.Security.Webhooks.Discord,
		cfg.Server.Contact.Security.Webhooks.DiscordSecret,
		cfg.Server.Contact.Security.Webhooks.Slack,
		cfg.Server.Contact.Security.Webhooks.SlackSecret,
		cfg.Server.Contact.Security.Webhooks.Mattermost,
		cfg.Server.Contact.Security.Webhooks.MattermostSecret,
		cfg.Server.Contact.Security.Webhooks.Pushover,
		cfg.Server.Contact.Security.Webhooks.PushoverSecret,
		cfg.Server.Contact.Security.Webhooks.Gotify,
		cfg.Server.Contact.Security.Webhooks.GotifySecret,
		cfg.Server.Contact.Security.Webhooks.Generic,
		cfg.Server.Contact.Security.Webhooks.GenericSecret,
		cfg.Server.Contact.Abuse.Email,
		cfg.Server.Contact.Abuse.Webhooks.Telegram,
		cfg.Server.Contact.Abuse.Webhooks.TelegramSecret,
		cfg.Server.Contact.Abuse.Webhooks.Discord,
		cfg.Server.Contact.Abuse.Webhooks.DiscordSecret,
		cfg.Server.Contact.Abuse.Webhooks.Slack,
		cfg.Server.Contact.Abuse.Webhooks.SlackSecret,
		cfg.Server.Contact.Abuse.Webhooks.Mattermost,
		cfg.Server.Contact.Abuse.Webhooks.MattermostSecret,
		cfg.Server.Contact.Abuse.Webhooks.Pushover,
		cfg.Server.Contact.Abuse.Webhooks.PushoverSecret,
		cfg.Server.Contact.Abuse.Webhooks.Gotify,
		cfg.Server.Contact.Abuse.Webhooks.GotifySecret,
		cfg.Server.Contact.Abuse.Webhooks.Generic,
		cfg.Server.Contact.Abuse.Webhooks.GenericSecret,
		cfg.Server.Contact.General.Email,
		cfg.Server.Contact.General.Webhooks.Telegram,
		cfg.Server.Contact.General.Webhooks.TelegramSecret,
		cfg.Server.Contact.General.Webhooks.Discord,
		cfg.Server.Contact.General.Webhooks.DiscordSecret,
		cfg.Server.Contact.General.Webhooks.Slack,
		cfg.Server.Contact.General.Webhooks.SlackSecret,
		cfg.Server.Contact.General.Webhooks.Mattermost,
		cfg.Server.Contact.General.Webhooks.MattermostSecret,
		cfg.Server.Contact.General.Webhooks.Pushover,
		cfg.Server.Contact.General.Webhooks.PushoverSecret,
		cfg.Server.Contact.General.Webhooks.Gotify,
		cfg.Server.Contact.General.Webhooks.GotifySecret,
		cfg.Server.Contact.General.Webhooks.Generic,
		cfg.Server.Contact.General.Webhooks.GenericSecret,
		cfg.Server.Tracking.Type,
		cfg.Server.Tracking.ID,
		cfg.Server.Tracking.URL,
		cfg.Server.Privacy.Data.Sold,
		cfg.Server.Privacy.Data.StoredOnServer,
		cfg.Server.Privacy.Retention.Period,
		cfg.Server.Privacy.Retention.ExportAvailable,
		cfg.Server.Privacy.Retention.DeletionAvailable,
		cfg.Server.Privacy.Consent.ShowUntilAcknowledged,
		cfg.Server.Privacy.Consent.DefaultEnabled,
		cfg.Server.Privacy.Consent.Message,
		cfg.Server.Privacy.Consent.MessageIfSold,
		cfg.Server.Privacy.Consent.Position,
		cfg.Server.Cache.Type,
		cfg.Server.Cache.URL,
		cfg.Server.Cache.Host,
		cfg.Server.Cache.Port,
		cfg.Server.Cache.Username,
		cfg.Server.Cache.Password,
		cfg.Server.Cache.DB,
		cfg.Server.Cache.TLS,
		cfg.Server.Cache.TLSSkipVerify,
		cfg.Server.Cache.PoolSize,
		cfg.Server.Cache.MinIdle,
		cfg.Server.Cache.Timeout,
		cfg.Server.Cache.Prefix,
		cfg.Server.Cache.TTL,
		cfg.Server.SSL.Enabled,
		cfg.Server.SSL.LetsEncrypt.Enabled,
		cfg.Server.SSL.LetsEncrypt.Email,
		cfg.Server.SSL.LetsEncrypt.Staging,
		cfg.Server.SSL.LetsEncrypt.Challenge,
		cfg.Server.SSL.LetsEncrypt.DNSProvider,
		cfg.Server.SSL.LetsEncrypt.DNSCredentials.Provider,
		cfg.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted,
		cfg.Server.SSL.LetsEncrypt.DNSCredentials.ValidatedAt,
		cfg.Server.Security.EncryptionKey,
		formatAllowlist(cfg.Server.Security.Allowlist),
		cfg.Server.Maintenance.SelfHealing.Enabled,
		cfg.Server.Maintenance.SelfHealing.RetryInterval,
		cfg.Server.Maintenance.SelfHealing.MaxAttempts,
		cfg.Server.Maintenance.Cleanup.DiskThreshold,
		cfg.Server.Maintenance.Cleanup.LogRetentionDays,
		cfg.Server.Maintenance.Cleanup.BackupKeepCount,
		cfg.Server.Maintenance.Notify.OnEnter,
		cfg.Server.Maintenance.Notify.OnExit,
		cfg.Server.Branding.Title,
		cfg.Server.Branding.Tagline,
		cfg.Server.Branding.Description,
		cfg.Server.Branding.LogoURL,
		cfg.Server.Branding.FaviconURL,
		cfg.Server.Branding.ThemeColor,
		cfg.Server.SEO.Author,
		cfg.Server.SEO.OGImage,
		cfg.Server.SEO.TwitterHandle,
		cfg.Server.SEO.Verification.Google,
		cfg.Server.SEO.Verification.Bing,
		cfg.Server.SEO.Verification.Yandex,
		cfg.Server.SEO.Verification.Baidu,
		cfg.Server.SEO.Verification.Pinterest,
		cfg.Server.SEO.Verification.Facebook,
		cfg.Server.SEO.Sitemap.Enabled,
		cfg.Server.SEO.Sitemap.MaxURLs,
		cfg.Server.SEO.Sitemap.IncludeImages,
		cfg.Server.Notifications.Email.Events.Startup,
		cfg.Server.Notifications.Email.Events.Shutdown,
		cfg.Server.Notifications.Email.Events.BackupComplete,
		cfg.Server.Notifications.Email.Events.BackupFailed,
		cfg.Server.Notifications.Email.Events.SSLExpiring,
		cfg.Server.Notifications.Email.Events.SSLRenewed,
		cfg.Server.Notifications.Email.Events.SSLRenewalFailed,
		cfg.Server.Notifications.Email.Events.SecurityAlert,
		cfg.Server.Notifications.Email.Events.SchedulerError,
		cfg.Server.Notifications.Email.Events.UpdateAvailable,
		cfg.Server.Notifications.Email.Events.UpdateInstalled,
		cfg.Server.Backup.Encryption.Enabled,
		cfg.Server.Backup.Retention.MaxBackups,
		cfg.Server.Backup.Retention.KeepWeekly,
		cfg.Server.Backup.Retention.KeepMonthly,
		cfg.Server.Backup.Retention.KeepYearly,
		cfg.Server.Backup.Retention.MaxTotalSize,
		cfg.Server.Compliance.Enabled,
		cfg.Server.CLI.BinaryDownload.RequireAuth,
		cfg.Server.Debug.Pprof,
		cfg.Server.Debug.LogQueries,
		cfg.Server.Debug.LogCache,
		cfg.Server.Debug.LogBodies,
		cfg.Server.Debug.MaxBodyLogSize,
		cfg.Server.Debug.BlockProfileRate,
		cfg.Server.Debug.MutexProfileFraction,
		cfg.Server.Debug.RuntimeEndpoints,
		cfg.Tor.OnionAddress,
		cfg.Tor.ContactEmail,
		cfg.Web.UI.Theme,
		cfg.Web.UI.Logo,
		cfg.Web.UI.Favicon,
		cfg.Web.UI.Notifications.Enabled,
		formatStringSlice(cfg.Web.UI.Notifications.Announcements),
		formatStringSlice(cfg.Web.Robots.Allow),
		formatStringSlice(cfg.Web.Robots.Deny),
		formatAIBotsDefault(cfg.Web.Robots.AIBots.Default),
		formatAIBotsMap(cfg.Web.Robots.AIBots.Bots),
		cfg.Web.CORS,
		cfg.Web.Footer.CustomHTML,
		cfg.Web.HSTS.Enabled,
		cfg.Web.HSTS.MaxAgeSeconds,
		cfg.Web.HSTS.IncludeSubdomains,
		cfg.Web.HSTS.Preload,
		formatPermissionsPolicy(cfg.Web.PermissionsPolicy),
		cfg.Web.CSP.Enabled,
		cfg.Web.CSP.Mode,
		cfg.Web.CSP.ScriptSrcExtra,
		cfg.Web.CSP.StyleSrcExtra,
		cfg.Web.CSP.ImgSrcExtra,
		cfg.Web.CSP.FontSrcExtra,
		cfg.Web.CSP.ConnectSrcExtra,
		cfg.Web.CSP.FrameSrcExtra,
		cfg.Web.CSP.FormActionExtra,
		cfg.Web.CSP.ScriptSrcOverride,
		cfg.Web.CSP.StyleSrcOverride,
		cfg.Web.CSP.ImgSrcOverride,
		cfg.Web.CSP.FontSrcOverride,
		cfg.Web.CSP.ConnectSrcOverride,
		cfg.Web.CSP.FrameSrcOverride,
		cfg.Web.CSP.FormActionOverride,
		cfg.Web.CSP.ReportsEnabled,
		cfg.Web.CSP.ReportsSampleRate,
		cfg.Web.Headers.ContentTypeOptions,
		cfg.Web.Headers.FrameOptions,
		cfg.Web.Headers.XSSProtection,
		cfg.Web.Headers.ReferrerPolicy,
		cfg.Web.Headers.COOP,
		cfg.Web.Headers.COEP,
		cfg.Web.Headers.CORP,
		cfg.Web.Headers.OriginAgentCluster,
		cfg.Web.Headers.CrossDomainPolicies,
		cfg.Web.Headers.DNSPrefetchControl,
		cfg.Web.Headers.HonorSecGPC,
		cfg.Web.Headers.HonorDNT,
		cfg.Web.Headers.SecFetchValidation,
		cfg.Web.Headers.ServerTimingInDebugOnly,
		cfg.Web.Headers.ClearSiteData.OnTokenRevocation,
		cfg.Web.Headers.ClearSiteData.OnConsentWithdrawal,
		cfg.Web.Headers.ClearSiteData.ExecutionContexts,
		cfg.Web.Headers.NEL.Enabled,
		cfg.Web.Headers.NEL.MaxAgeSeconds,
		cfg.Web.Headers.NEL.IncludeSubdomains,
		cfg.Web.Headers.NEL.SampleRate,
		cfg.Web.Reports.RateLimitPerMinute,
		cfg.Web.Reports.RateLimitPerIPBurst,
		cfg.Data.CVE.Source,
		cfg.Data.CVE.FilterByCPE,
	)
}

// formatAIBotsDefault renders the ai_bots.default value for the generated
// server.yml, falling back to the spec default ("allow") when unset.
func formatAIBotsDefault(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "deny") {
		return "deny"
	}
	return "allow"
}

// formatAIBotsMap renders the ai_bots.bots block for the generated
// server.yml. Recognized crawlers come first in KnownAIBots order so the file
// is byte-stable, followed by any operator-added bot sorted by name.
func formatAIBotsMap(bots map[string]string) string {
	if len(bots) == 0 {
		bots = DefaultAIBots()
	}
	known := make(map[string]bool, len(KnownAIBots))
	lines := make([]string, 0, len(bots))
	for _, name := range KnownAIBots {
		known[name] = true
		setting, ok := bots[name]
		if !ok {
			setting = "allow"
		}
		lines = append(lines, fmt.Sprintf("        %s: %s", name, formatAIBotsDefault(setting)))
	}
	extra := make([]string, 0, len(bots))
	for name := range bots {
		if !known[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		lines = append(lines, fmt.Sprintf("        %s: %s", name, formatAIBotsDefault(bots[name])))
	}
	return strings.Join(lines, "\n")
}

// formatPermissionsPolicy renders web.permissions_policy as a YAML mapping with
// feature names sorted so a rewritten server.yml stays byte-stable. An empty
// map falls back to the AI.md PART 11 defaults so a fresh install is complete.
func formatPermissionsPolicy(features map[string]string) string {
	if len(features) == 0 {
		features = DefaultPermissionsPolicy()
	}
	names := make([]string, 0, len(features))
	for name := range features {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := make([]string, 0, len(names))
	for _, name := range names {
		lines = append(lines, fmt.Sprintf("    %s: \"%s\"", name, features[name]))
	}
	return strings.Join(lines, "\n")
}

// formatCountryPresets renders geoip.presets as an inline YAML mapping with
// preset names sorted so a rewritten server.yml stays byte-stable.
func formatCountryPresets(presets map[string][]string) string {
	if len(presets) == 0 {
		return "{}"
	}
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	sort.Strings(names)
	result := "{"
	for i, name := range names {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("\"%s\": %s", name, formatStringSlice(presets[name]))
	}
	result += "}"
	return result
}

func formatStringSlice(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	result := "["
	for i, v := range s {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("\"%s\"", v)
	}
	result += "]"
	return result
}

// getTheme returns the current theme
func getTheme() string {
	cfg := getCurrentConfig()
	return cfg.Web.UI.Theme
}

// GetCORS returns the CORS setting
func GetCORS() string {
	cfg := getCurrentConfig()
	if cfg.Web.CORS == "" {
		return "*"
	}
	return cfg.Web.CORS
}

// IsDebug returns true when debug mode is active (--debug flag or DEBUG=true env var).
// Debug state is controlled exclusively by the --debug flag / DEBUG env var per AI.md PART 6.
// The application mode string ("production", "development") never activates debug mode.
func (c *AppConfig) IsDebug() bool {
	return IsTruthy(os.Getenv("DEBUG"))
}

// Sanitized returns a copy of the config with all sensitive values redacted.
// Used by the /debug/config endpoint to safely expose config state.
// Returns a value (not a pointer) so callers cannot modify the original.
func (c *AppConfig) Sanitized() AppConfig {
	sanitized := *c
	if sanitized.Server.Token != "" {
		sanitized.Server.Token = "xxxxx"
	}
	if sanitized.Server.Metrics.Auth.Tokens.Prometheus != "" {
		sanitized.Server.Metrics.Auth.Tokens.Prometheus = "xxxxx"
	}
	if sanitized.Server.Metrics.Auth.Tokens.Grafana != "" {
		sanitized.Server.Metrics.Auth.Tokens.Grafana = "xxxxx"
	}
	if sanitized.Server.Metrics.Auth.Tokens.Loki != "" {
		sanitized.Server.Metrics.Auth.Tokens.Loki = "xxxxx"
	}
	if sanitized.Server.Database.Token != "" {
		sanitized.Server.Database.Token = "xxxxx"
	}
	if sanitized.Server.Security.EncryptionKey != "" {
		sanitized.Server.Security.EncryptionKey = "xxxxx"
	}
	if sanitized.Server.Security.PreviousEncryptionKey != "" {
		sanitized.Server.Security.PreviousEncryptionKey = "xxxxx"
	}
	if sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted != "" {
		sanitized.Server.SSL.LetsEncrypt.DNSCredentials.CredentialsEncrypted = "xxxxx"
	}
	return sanitized
}

// Get is an alias for getCurrentConfig; returns the current in-memory configuration.
func Get() *AppConfig {
	return getCurrentConfig()
}
