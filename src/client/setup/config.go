// Package setup provides CLI configuration for ipgaze-cli.
package setup

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	paths "github.com/apimgr/ipgaze/src/client/path"
	"github.com/apimgr/ipgaze/src/config"
	"gopkg.in/yaml.v3"
)

// Compiled defaults for every cli.yml setting (AI.md PART 32 canonical
// cli.yml). Accessors fall back to these whenever the corresponding key is
// absent from the config file.
const (
	DefaultAPIVersion    = "v1"
	DefaultTimeout       = "30s"
	DefaultRetry         = 3
	DefaultRetryDelay    = "1s"
	DefaultOutputFormat  = "table"
	DefaultColor         = "auto"
	DefaultPager         = "auto"
	DefaultTUITheme      = "dark"
	DefaultLogLevel      = "warn"
	DefaultLogMaxSize    = "10MB"
	DefaultLogMaxFiles   = 5
	DefaultCacheTTL      = "5m"
	DefaultCacheMaxSize  = "100MB"
	DefaultDefaultsLang  = "auto"
	DefaultUpdateChannel = "stable"
)

// OutputFormats lists every value accepted by --output and output.format
// (AI.md PART 32 "Output preferences").
var OutputFormats = []string{"table", "json", "yaml", "plain", "csv"}

// IsValidOutputFormat reports whether format is one of OutputFormats.
func IsValidOutputFormat(format string) bool {
	for _, f := range OutputFormats {
		if f == format {
			return true
		}
	}
	return false
}

// Truthy is a boolean config value kept in its raw textual form so that
// config.IsTruthy can interpret the full set of locale truthy/falsey spellings
// (true/false, yes/no, on/off, enabled/disabled, 1/0, oui/non, si/no, da/net).
// A plain Go bool field would restrict cli.yml to YAML 1.2 booleans only.
type Truthy string

// setLiteral stores the raw literal text of a scalar YAML node.
func (t *Truthy) setLiteral(value string) { *t = Truthy(value) }

// UnmarshalYAML accepts any scalar node — bool, int or string — and keeps its
// literal text for config.IsTruthy to decode.
func (t *Truthy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected a boolean value, got a non-scalar node", node.Line)
	}
	t.setLiteral(node.Value)
	return nil
}

// Bool decodes the value through config.IsTruthy; an empty value is false.
func (t Truthy) Bool() bool {
	return config.IsTruthy(string(t))
}

// CLIConfig stores the CLI configuration (cli.yml per AI.md PART 32).
type CLIConfig struct {
	Server   ServerConfig   `yaml:"server,omitempty"`
	Auth     AuthConfig     `yaml:"auth,omitempty"`
	Output   OutputConfig   `yaml:"output,omitempty"`
	TUI      TUIConfig      `yaml:"tui,omitempty"`
	Logging  LoggingConfig  `yaml:"logging,omitempty"`
	Cache    CacheConfig    `yaml:"cache,omitempty"`
	Debug    Truthy         `yaml:"debug,omitempty"`
	Defaults DefaultsConfig `yaml:"defaults,omitempty"`
	Update   UpdateConfig   `yaml:"update,omitempty"`
	Display  DisplayConfig  `yaml:"display,omitempty"`
}

// ServerConfig holds the server connection settings (AI.md PART 32:
// `server.primary` is the canonical nested key — never a flat top-level
// `server` string).
type ServerConfig struct {
	// Primary is the server base URL (empty = use {official_site} or prompt).
	Primary string `yaml:"primary,omitempty"`
	// APIVersion is the API version prefix; must match the server.
	APIVersion string `yaml:"api_version,omitempty"`
	// Timeout is the per-request timeout as a Go duration string.
	Timeout string `yaml:"timeout,omitempty"`
	// Retry is the number of retry attempts on a failed request.
	Retry int `yaml:"retry,omitempty"`
	// RetryDelay is the delay between retries as a Go duration string.
	RetryDelay string `yaml:"retry_delay,omitempty"`
}

// AuthConfig holds authentication settings (AI.md PART 32:
// `auth.token` is the canonical nested key — never a flat top-level
// `token` string).
type AuthConfig struct {
	// Token is the API token.
	Token string `yaml:"token,omitempty"`
	// TokenFile reads the token from a file instead of storing it inline.
	TokenFile string `yaml:"token_file,omitempty"`
}

// OutputConfig holds output preferences (AI.md PART 32).
type OutputConfig struct {
	// Format is the default --output value: table, json, yaml, plain, csv.
	Format string `yaml:"format,omitempty"`
	// Color is the default --color value: auto, yes, no.
	Color string `yaml:"color,omitempty"`
	// Pager controls paging of long output: auto, always, never.
	Pager string `yaml:"pager,omitempty"`
	// Quiet suppresses non-essential output when truthy.
	Quiet Truthy `yaml:"quiet,omitempty"`
	// Verbose enables extra output when truthy.
	Verbose Truthy `yaml:"verbose,omitempty"`
}

// TUIConfig holds TUI preferences (AI.md PART 32).
type TUIConfig struct {
	// Enabled allows TUI mode; a falsey value forces CLI-only mode.
	Enabled Truthy `yaml:"enabled,omitempty"`
	// Theme is the TUI colour theme: dark, light, system.
	Theme string `yaml:"theme,omitempty"`
	// Mouse enables mouse support when truthy.
	Mouse Truthy `yaml:"mouse,omitempty"`
	// Unicode uses unicode box characters when truthy, ASCII when falsey.
	Unicode Truthy `yaml:"unicode,omitempty"`
}

// LoggingConfig holds client logging settings (AI.md PART 32).
type LoggingConfig struct {
	// Level is the minimum level written to the log file: debug, info, warn, error.
	Level string `yaml:"level,omitempty"`
	// File overrides the log file path; empty uses {log_dir}/cli.log.
	File string `yaml:"file,omitempty"`
	// MaxSize is the rotation threshold for the log file (e.g. 10MB).
	MaxSize string `yaml:"max_size,omitempty"`
	// MaxFiles is the number of rotated log files to keep.
	MaxFiles int `yaml:"max_files,omitempty"`
}

// CacheConfig holds response cache settings (AI.md PART 32).
type CacheConfig struct {
	// Enabled turns response caching on when truthy.
	Enabled Truthy `yaml:"enabled,omitempty"`
	// TTL is the cache entry lifetime as a Go duration string.
	TTL string `yaml:"ttl,omitempty"`
	// MaxSize is the maximum on-disk cache size (e.g. 100MB).
	MaxSize string `yaml:"max_size,omitempty"`
}

// DefaultsConfig holds per-flag defaults (AI.md PART 32 "Flag Defaults from
// Config": every flag must have a config setting that changes its default).
type DefaultsConfig struct {
	// Lang is the --lang default; "auto" detects from the environment.
	Lang string `yaml:"lang,omitempty"`
	// Field is the --field default; empty means no single-field output.
	Field string `yaml:"field,omitempty"`
	// Server is the --server default used when server.primary is unset.
	Server string `yaml:"server,omitempty"`
}

// UpdateConfig controls CLI auto-update behaviour (AI.md PART 32).
type UpdateConfig struct {
	// Auto silently auto-updates when truthy and running non-interactively.
	Auto Truthy `yaml:"auto,omitempty"`
	// CheckInterval is per_invocation for the CLI (short-lived; no background poll).
	CheckInterval string `yaml:"check_interval,omitempty"`
	// Channel is the update channel: stable, beta, daily.
	Channel string `yaml:"channel,omitempty"`
}

// DisplayConfig controls display mode override (AI.md PART 32).
type DisplayConfig struct {
	// Mode: auto (default), gui, tui.
	Mode string `yaml:"mode,omitempty"`
}

// truthyOr returns the truthiness of value, or def when value is empty.
// All boolean config decoding goes through config.IsTruthy per AI.md PART 32
// ("ALL boolean inputs MUST use config.ParseBool() or config.IsTruthy()").
func truthyOr(value Truthy, def bool) bool {
	if value == "" {
		return def
	}
	return config.IsTruthy(string(value))
}

// stringOr returns value, or def when value is empty.
func stringOr(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

// APIVersion returns the configured API version prefix or the compiled default.
func (c *CLIConfig) APIVersion() string {
	return stringOr(c.Server.APIVersion, DefaultAPIVersion)
}

// RequestTimeout returns the configured per-request timeout. An unparsable or
// missing value falls back to the compiled 30s default.
func (c *CLIConfig) RequestTimeout() time.Duration {
	d, err := time.ParseDuration(stringOr(c.Server.Timeout, DefaultTimeout))
	if err != nil || d <= 0 {
		d = 30 * time.Second
	}
	return d
}

// RetryAttempts returns the number of retry attempts on a failed request.
func (c *CLIConfig) RetryAttempts() int {
	if c.Server.Retry <= 0 {
		return DefaultRetry
	}
	return c.Server.Retry
}

// RetryDelay returns the delay between retries.
func (c *CLIConfig) RetryDelay() time.Duration {
	d, err := time.ParseDuration(stringOr(c.Server.RetryDelay, DefaultRetryDelay))
	if err != nil || d < 0 {
		d = time.Second
	}
	return d
}

// OutputFormat returns the configured default --output value.
func (c *CLIConfig) OutputFormat() string {
	return stringOr(c.Output.Format, DefaultOutputFormat)
}

// OutputColor returns the configured default --color value.
func (c *CLIConfig) OutputColor() string {
	return stringOr(c.Output.Color, DefaultColor)
}

// OutputPager returns the configured pager mode.
func (c *CLIConfig) OutputPager() string {
	return stringOr(c.Output.Pager, DefaultPager)
}

// OutputQuiet reports whether non-essential output is suppressed.
func (c *CLIConfig) OutputQuiet() bool {
	return truthyOr(c.Output.Quiet, false)
}

// OutputVerbose reports whether extra output is enabled.
func (c *CLIConfig) OutputVerbose() bool {
	return truthyOr(c.Output.Verbose, false)
}

// TUIEnabled reports whether TUI mode may be entered. A falsey tui.enabled
// forces CLI-only mode.
func (c *CLIConfig) TUIEnabled() bool {
	return truthyOr(c.TUI.Enabled, true)
}

// TUITheme returns the configured TUI colour theme (dark, light, system).
// This is the accessor the TUI layer reads to pick its palette.
func (c *CLIConfig) TUITheme() string {
	return stringOr(c.TUI.Theme, DefaultTUITheme)
}

// TUIMouse reports whether the TUI enables mouse support.
func (c *CLIConfig) TUIMouse() bool {
	return truthyOr(c.TUI.Mouse, true)
}

// TUIUnicode reports whether the TUI draws with unicode characters.
func (c *CLIConfig) TUIUnicode() bool {
	return truthyOr(c.TUI.Unicode, true)
}

// LogLevel returns the configured log level.
func (c *CLIConfig) LogLevel() string {
	return stringOr(c.Logging.Level, DefaultLogLevel)
}

// LogFilePath returns the configured log file path, defaulting to
// {log_dir}/cli.log when logging.file is empty.
func (c *CLIConfig) LogFilePath() string {
	if c.Logging.File == "" {
		return paths.LogFile()
	}
	return c.Logging.File
}

// LogMaxSize returns the configured log rotation threshold.
func (c *CLIConfig) LogMaxSize() string {
	return stringOr(c.Logging.MaxSize, DefaultLogMaxSize)
}

// LogMaxFiles returns the number of rotated log files to keep.
func (c *CLIConfig) LogMaxFiles() int {
	if c.Logging.MaxFiles <= 0 {
		return DefaultLogMaxFiles
	}
	return c.Logging.MaxFiles
}

// CacheEnabled reports whether response caching is on.
func (c *CLIConfig) CacheEnabled() bool {
	return truthyOr(c.Cache.Enabled, true)
}

// CacheTTL returns the cache entry lifetime.
func (c *CLIConfig) CacheTTL() time.Duration {
	d, err := time.ParseDuration(stringOr(c.Cache.TTL, DefaultCacheTTL))
	if err != nil || d <= 0 {
		d = 5 * time.Minute
	}
	return d
}

// CacheMaxSize returns the maximum on-disk cache size.
func (c *CLIConfig) CacheMaxSize() string {
	return stringOr(c.Cache.MaxSize, DefaultCacheMaxSize)
}

// DebugEnabled reports whether debug mode is enabled in the config file.
func (c *CLIConfig) DebugEnabled() bool {
	return truthyOr(c.Debug, false)
}

// DefaultLang returns the --lang default from defaults.lang.
func (c *CLIConfig) DefaultLang() string {
	return stringOr(c.Defaults.Lang, DefaultDefaultsLang)
}

// UpdateAuto reports whether silent auto-update is enabled.
func (c *CLIConfig) UpdateAuto() bool {
	return truthyOr(c.Update.Auto, false)
}

// UpdateChannel returns the configured update channel.
func (c *CLIConfig) UpdateChannel() string {
	return stringOr(c.Update.Channel, DefaultUpdateChannel)
}

// DefaultCLIConfig returns a CLIConfig populated with every compiled default.
// Used to seed the auto-created cli.yml on first run.
func DefaultCLIConfig() *CLIConfig {
	return &CLIConfig{
		Server: ServerConfig{
			APIVersion: DefaultAPIVersion,
			Timeout:    DefaultTimeout,
			Retry:      DefaultRetry,
			RetryDelay: DefaultRetryDelay,
		},
		Output: OutputConfig{
			Format:  DefaultOutputFormat,
			Color:   DefaultColor,
			Pager:   DefaultPager,
			Quiet:   "false",
			Verbose: "false",
		},
		TUI: TUIConfig{
			Enabled: "true",
			Theme:   DefaultTUITheme,
			Mouse:   "true",
			Unicode: "true",
		},
		Logging: LoggingConfig{
			Level:    DefaultLogLevel,
			MaxSize:  DefaultLogMaxSize,
			MaxFiles: DefaultLogMaxFiles,
		},
		Cache: CacheConfig{
			Enabled: "true",
			TTL:     DefaultCacheTTL,
			MaxSize: DefaultCacheMaxSize,
		},
		Debug: "false",
		Defaults: DefaultsConfig{
			Lang: DefaultDefaultsLang,
		},
		Update: UpdateConfig{
			Auto:          "false",
			CheckInterval: "per_invocation",
			Channel:       DefaultUpdateChannel,
		},
		Display: DisplayConfig{Mode: "auto"},
	}
}

// defaultConfigTemplate is the commented cli.yml written on first run. It
// mirrors DefaultCLIConfig() exactly and follows the AI.md PART 32 canonical
// layout, with every comment on the line above its setting.
const defaultConfigTemplate = `# ipgaze-cli configuration - ALL options with defaults

# Server connection
server:
  # Server URL (empty = use the compiled official site)
  primary: ""
  # API version prefix (must match server)
  api_version: v1
  # Request timeout
  timeout: 30s
  # Retry attempts on failure
  retry: 3
  # Delay between retries
  retry_delay: 1s

# Authentication
auth:
  # API token
  token: ""
  # Read token from this file instead
  token_file: ""

# Output preferences
output:
  # table, json, yaml, plain, csv
  format: table
  # auto, yes, no
  color: auto
  # auto, always, never
  pager: auto
  # Suppress non-essential output
  quiet: false
  # Extra output
  verbose: false

# TUI preferences
tui:
  # Allow TUI mode (false = CLI-only)
  enabled: true
  # dark, light, system
  theme: dark
  # Enable mouse support
  mouse: true
  # Use unicode characters (false = ASCII only)
  unicode: true

# Logging
logging:
  # debug, info, warn, error
  level: warn
  # Log file path (empty = {log_dir}/cli.log)
  file: ""
  # Max log file size
  max_size: 10MB
  # Max log files to keep
  max_files: 5

# Cache
cache:
  # Enable response caching
  enabled: true
  # Cache TTL
  ttl: 5m
  # Max cache size
  max_size: 100MB

# Enable debug mode (same as --debug)
debug: false

# Flag defaults
defaults:
  # --lang default (auto = detect from environment)
  lang: auto
  # --field default (empty = full record)
  field: ""
  # --server default used when server.primary is empty
  server: ""

# Auto-update behaviour
update:
  # Silently install updates when running non-interactively
  auto: false
  # The CLI is short-lived, so updates are checked per invocation
  check_interval: per_invocation
  # stable, beta, daily
  channel: stable

# Interactive display mode
display:
  # auto, gui, tui
  mode: auto
`

// DefaultConfigYAML returns the commented default cli.yml contents.
func DefaultConfigYAML() []byte {
	return []byte(defaultConfigTemplate)
}

// EnsureConfigFile writes the commented default cli.yml at path when no file
// exists there yet, creating the parent directory first (AI.md PART 32:
// "Config file (cli.yml) is auto-created on first run with sane defaults").
// Returns true when a file was created.
func EnsureConfigFile(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, DefaultConfigYAML(), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// LoadCLIConfigFromFile reads cli.yml from the standard config path.
// Returns an empty CLIConfig (not nil) if the file does not exist.
func LoadCLIConfigFromFile() (*CLIConfig, error) {
	return LoadCLIConfigFrom(paths.ConfigFile())
}

// LoadCLIConfigFrom reads the CLI config from an explicit path.
// Returns an empty CLIConfig (not nil) if the file does not exist.
func LoadCLIConfigFrom(path string) (*CLIConfig, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &CLIConfig{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg CLIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveIfEmptyOrInvalid updates a config string value only when appropriate.
// If flagValue is empty the current value is returned unchanged.
// If flagValue is non-empty but fails validate, a warning is logged and current is returned.
// If current is empty or invalid and flagValue is valid, flagValue is returned (to be persisted).
// If current is already valid, flagValue is returned for the session but should not be persisted.
func SaveIfEmptyOrInvalid(current, flagValue string, validate func(string) bool) string {
	if flagValue == "" {
		return current
	}
	if !validate(flagValue) {
		return current
	}
	if current == "" || !validate(current) {
		return flagValue
	}
	return flagValue
}

// ValidateServerURL reports whether s is a usable server base URL: a valid
// http(s) URL with a non-empty host. Passed to SaveIfEmptyOrInvalid to
// decide whether --server should be persisted to cli.yml (AI.md PART 32
// "Server Address Resolution": "save to server.primary in cli.yml only if
// empty/invalid").
func ValidateServerURL(s string) bool {
	if s == "" {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// ValidateToken reports whether s is a non-empty API token. Passed to
// SaveIfEmptyOrInvalid to decide whether --token should be persisted to
// cli.yml (AI.md PART 32 "Authentication": "--token flag saves to cli.yml
// only if config value is empty/invalid").
func ValidateToken(s string) bool {
	return s != ""
}

// SaveCLIConfigToFile writes cfg to path with mode 0600, creating the parent
// directory when missing. path is the resolved --config target so a profile
// loaded with --config is written back to that same file.
func SaveCLIConfigToFile(cfg *CLIConfig, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
