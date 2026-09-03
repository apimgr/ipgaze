// Package config — ConfigManager watches server.yml for changes and applies
// hot-reload or signals restart-required per AI.md PART 12.
package config

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// restartRequiredPrefixes lists dot-notation config key prefixes that require
// a full process restart; all other changed keys are hot-reloaded in place.
// Matches AI.md PART 12's restartRequiredSettings exactly: ssl./database./tor.
// are whole-section prefixes (TLS listener, connection pool, and Tor child
// process must all be recreated on any change within their section, not just
// the specific subkeys previously listed here).
var restartRequiredPrefixes = []string{
	"server.port",
	"server.address",
	"server.daemonize",
	"ssl.",
	"database.",
	"tor.",
}

// ConfigManager watches server.yml for changes and applies hot-reload or
// signals restart-required. Configuration is file-only — no runtime mutation.
type ConfigManager struct {
	configPath      string
	lastFileModTime time.Time
	// pendingRestart is true when a restart-required setting changed.
	pendingRestart bool
	// restartSettings lists the setting keys that triggered the pending restart.
	restartSettings []string
	mu              sync.RWMutex
}

// NewConfigManager creates a ConfigManager for the given server.yml path.
// Call Start() to begin watching for file changes.
func NewConfigManager(path string) *ConfigManager {
	var modTime time.Time
	if info, err := os.Stat(path); err == nil {
		modTime = info.ModTime()
	}
	return &ConfigManager{
		configPath:      path,
		lastFileModTime: modTime,
	}
}

// Start launches a background goroutine that polls server.yml every 5 s.
// Returns a stop function; call it to halt polling (e.g. on graceful shutdown).
func (m *ConfigManager) Start() (stop func()) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				m.checkFileChanges()
			}
		}
	}()
	return func() { close(done) }
}

// checkFileChanges compares the current mtime of server.yml against the
// last-seen value. On change it reloads and calls applyConfigChanges.
func (m *ConfigManager) checkFileChanges() {
	info, err := os.Stat(m.configPath)
	if err != nil {
		return
	}
	if info.ModTime() == m.lastFileModTime {
		return
	}
	m.lastFileModTime = info.ModTime()

	newCfg, err := loadConfigFromFile(m.configPath)
	if err != nil {
		log.Printf("config: file parse error: %v", err)
		return
	}

	m.applyConfigChanges(newCfg)
}

// loadConfigFromFile reads and unmarshals a server.yml file into a new
// AppConfig seeded with embedded defaults so missing keys fall back correctly.
func loadConfigFromFile(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyConfigChanges categorises changed settings and either applies them
// immediately (hot-reload) or records them as requiring a restart.
func (m *ConfigManager) applyConfigChanges(newCfg *AppConfig) {
	mu.RLock()
	oldCfg := current
	mu.RUnlock()

	if oldCfg == nil {
		return
	}

	changes := compareConfigs(oldCfg, newCfg)
	if len(changes) == 0 {
		return
	}

	hotReloadable, needsRestart := categorizeChanges(changes)

	if len(hotReloadable) > 0 {
		applyHotReloadSettings(newCfg)
		log.Printf("config: hot-reloaded from file: %v", hotReloadable)
	}

	if len(needsRestart) > 0 {
		m.mu.Lock()
		m.pendingRestart = true
		m.restartSettings = append(m.restartSettings, needsRestart...)
		m.mu.Unlock()
		log.Printf("config: restart required for: %v", needsRestart)
	}
}

// applyHotReloadSettings atomically replaces the current config with newCfg.
// Only hot-reloadable changes reach this path; readers always see a consistent
// snapshot through the package-level mu lock.
func applyHotReloadSettings(newCfg *AppConfig) {
	mu.Lock()
	current = newCfg
	mu.Unlock()
}

// compareConfigs returns dot-notation keys for settings that differ between
// old and new. Only monitored keys are compared; unknown or unmonitored keys
// are silently ignored.
func compareConfigs(old, new *AppConfig) []string {
	var changed []string

	if old.Server.Port != new.Server.Port {
		changed = append(changed, "server.port")
	}
	if old.Server.Address != new.Server.Address {
		changed = append(changed, "server.address")
	}
	if old.Server.Logging.Level != new.Server.Logging.Level {
		changed = append(changed, "logging.level")
	}
	if old.Server.RateLimit.Enabled != new.Server.RateLimit.Enabled {
		changed = append(changed, "ratelimit.enabled")
	}
	if old.Server.RateLimit.Read.Requests != new.Server.RateLimit.Read.Requests {
		changed = append(changed, "ratelimit.read.requests")
	}
	if old.Server.RateLimit.Read.Window != new.Server.RateLimit.Read.Window {
		changed = append(changed, "ratelimit.read.window")
	}
	if old.Server.RateLimit.GlobalBurst != new.Server.RateLimit.GlobalBurst {
		changed = append(changed, "ratelimit.global_burst")
	}
	if old.Web.CORS != new.Web.CORS {
		changed = append(changed, "cors")
	}
	if old.Server.SSL.Enabled != new.Server.SSL.Enabled {
		changed = append(changed, "ssl.enabled")
	}
	if old.Server.SSL.LetsEncrypt != new.Server.SSL.LetsEncrypt {
		changed = append(changed, "ssl.letsencrypt")
	}
	if old.Server.Daemonize != new.Server.Daemonize {
		changed = append(changed, "server.daemonize")
	}
	if old.Server.Database != new.Server.Database {
		changed = append(changed, "database.driver")
	}
	if old.Server.Tor != new.Server.Tor {
		changed = append(changed, "tor.settings")
	}
	if old.Server.Branding.Title != new.Server.Branding.Title {
		changed = append(changed, "branding.title")
	}
	if old.Server.Branding.Tagline != new.Server.Branding.Tagline {
		changed = append(changed, "branding.tagline")
	}
	if old.Server.Branding.Description != new.Server.Branding.Description {
		changed = append(changed, "branding.description")
	}
	if old.Server.Branding.LogoURL != new.Server.Branding.LogoURL {
		changed = append(changed, "branding.logo_url")
	}
	if old.Server.Branding.FaviconURL != new.Server.Branding.FaviconURL {
		changed = append(changed, "branding.favicon_url")
	}
	if old.Server.Branding.ThemeColor != new.Server.Branding.ThemeColor {
		changed = append(changed, "branding.theme_color")
	}

	return changed
}

// categorizeChanges splits changed setting keys into hot-reloadable and
// restart-required buckets using restartRequiredPrefixes.
func categorizeChanges(changes []string) (hotReload, needsRestart []string) {
	for _, setting := range changes {
		requiresRestart := false
		for _, prefix := range restartRequiredPrefixes {
			if strings.HasPrefix(setting, prefix) {
				requiresRestart = true
				break
			}
		}
		if requiresRestart {
			needsRestart = append(needsRestart, setting)
		} else {
			hotReload = append(hotReload, setting)
		}
	}
	return
}

// PendingRestart reports whether any restart-required setting changed since
// the last call to ClearPendingRestart.
func (m *ConfigManager) PendingRestart() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pendingRestart
}

// RestartSettings returns the list of settings that triggered a pending restart.
func (m *ConfigManager) RestartSettings() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.restartSettings))
	copy(out, m.restartSettings)
	return out
}

// ClearPendingRestart resets the pending-restart flag and clears the settings
// list. Call this after the operator acknowledges or acts on the restart.
func (m *ConfigManager) ClearPendingRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingRestart = false
	m.restartSettings = nil
}
