// Package config — ConfigManager watches server.yml and yaml.d/ for changes and applies
// hot-reload or signals restart-required per AI.md PART 12.
package config

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/common/display"
)

// restartRequiredPrefixes lists dot-notation config key prefixes that require
// a full process restart. Other changed keys are classified as hot or graceful
// reloads by categorizeReloadChanges. The section prefixes match AI.md PART 12.
// server.ssl/server.database/server.tor mirror the current AppConfig YAML
// layout; the unrooted aliases retain the spec's documented prefix forms.
var restartRequiredPrefixes = []string{
	"server.port",
	"server.address",
	"server.daemonize",
	"ssl.",
	"server.ssl.",
	"database.",
	"server.database.",
	"tor.",
	"server.tor.",
}

// ConfigManager watches server.yml and yaml.d/ for changes and applies hot-reload or
// signals restart-required. Configuration is file-only — no runtime mutation.
type ConfigManager struct {
	configPath      string
	lastFileModTime time.Time
	lastFingerprint string
	reloadHandler   func(*AppConfig, []string) error
	// pendingRestart is true when a restart-required setting changed.
	pendingRestart bool
	// restartSettings lists the setting keys that triggered the pending restart.
	restartSettings []string
	mu              sync.RWMutex
}

// SetReloadHandler registers the runtime hook for applying file-backed
// configuration changes after the package-level config snapshot is updated.
func (m *ConfigManager) SetReloadHandler(handler func(*AppConfig, []string) error) {
	m.mu.Lock()
	m.reloadHandler = handler
	m.mu.Unlock()
}

// NewConfigManager creates a ConfigManager for the given server.yml path and adjacent yaml.d/ directory.
// Call Start() to begin watching for file changes.
func NewConfigManager(path string) *ConfigManager {
	var modTime time.Time
	if info, err := os.Stat(path); err == nil {
		modTime = info.ModTime()
	}
	return &ConfigManager{
		configPath:      path,
		lastFileModTime: modTime,
		lastFingerprint: mergedConfigFingerprint(path),
	}
}

// Start launches a background goroutine that polls server.yml and yaml.d/ every 5 s.
// Returns a stop function; call it to halt polling (e.g. on graceful shutdown).
func (m *ConfigManager) Start() (stop func()) {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
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
	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() { close(done) })
		<-stopped
	}
}

// checkFileChanges compares the current config tree against the last-seen
// fingerprint. On change it reloads and calls applyConfigChanges.
func (m *ConfigManager) checkFileChanges() {
	fingerprint := mergedConfigFingerprint(m.configPath)
	if fingerprint == m.lastFingerprint {
		return
	}
	info, err := os.Stat(m.configPath)
	if err != nil {
		return
	}

	newCfg, err := loadConfigFromFile(m.configPath)
	if err != nil {
		log.Printf("config: file parse error: %v", err)
		return
	}

	m.applyConfigChanges(newCfg)
	m.lastFileModTime = info.ModTime()
	m.lastFingerprint = fingerprint
}

// loadConfigFromFile merges server.yml and ordered yaml.d/ overlays into an
// AppConfig seeded with embedded defaults.
func loadConfigFromFile(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := parseMergedConfig(path, data)
	if err != nil {
		return nil, err
	}
	if err := validateOperatorSecurityConfig(cfg); err != nil {
		return nil, configValidationError(path, err)
	}
	validateConfig(cfg)
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

	hotReloadable, gracefulReload, needsRestart := categorizeReloadChanges(changes)
	gracefulHandler := m.getReloadHandler()
	if len(gracefulReload) > 0 && gracefulHandler == nil {
		preserveConfigPaths(oldCfg, newCfg, gracefulReload)
		needsRestart = append(needsRestart, gracefulReload...)
		log.Printf("config: graceful reload handler unavailable; restart required for: %v", gracefulReload)
		gracefulReload = nil
	}

	if len(hotReloadable) > 0 || len(gracefulReload) > 0 {
		preserveRestartRequiredSettings(oldCfg, newCfg)
		applyHotReloadSettings(newCfg)
		applied := append(append([]string(nil), hotReloadable...), gracefulReload...)
		if len(hotReloadable) > 0 {
			log.Printf("config: hot-reloaded from file: %v", hotReloadable)
		}
		if len(gracefulReload) > 0 {
			if err := gracefulHandler(newCfg, applied); err != nil {
				preserveConfigPaths(oldCfg, newCfg, gracefulReload)
				applyHotReloadSettings(newCfg)
				needsRestart = append(needsRestart, gracefulReload...)
				log.Printf("config: graceful reload failed; restart required for %v: %v", gracefulReload, err)
				if len(hotReloadable) > 0 {
					if hotErr := gracefulHandler(newCfg, hotReloadable); hotErr != nil {
						log.Printf("config: runtime hot-reload hook failed: %v", hotErr)
					}
				}
			} else {
				log.Printf("config: gracefully reloaded from file: %v", gracefulReload)
			}
		} else if gracefulHandler != nil && len(hotReloadable) > 0 {
			if err := gracefulHandler(newCfg, applied); err != nil {
				log.Printf("config: runtime hot-reload hook failed: %v", err)
			}
		}
	}

	if len(needsRestart) > 0 {
		m.mu.Lock()
		m.pendingRestart = true
		m.restartSettings = append(m.restartSettings, needsRestart...)
		m.mu.Unlock()
		log.Printf("config: restart required for: %v", needsRestart)
	}
}

func (m *ConfigManager) getReloadHandler() func(*AppConfig, []string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.reloadHandler
}

// applyHotReloadSettings atomically replaces the current config with newCfg.
// Only hot-reloadable changes reach this path; readers always see a consistent
// snapshot through the package-level mu lock.
func applyHotReloadSettings(newCfg *AppConfig) {
	mu.Lock()
	current = newCfg
	mu.Unlock()
	// output.color / output.emoji are hot-reloadable: terminal output must
	// follow the new server.yml values without a restart (AI.md PART 8).
	display.SetOutputPreferences(newCfg.Output.Color, newCfg.Output.Emoji)
}

// compareConfigs returns every changed setting using its YAML-tag path.
func compareConfigs(old, new *AppConfig) []string {
	var changed []string
	compareConfigValue(reflect.ValueOf(old), reflect.ValueOf(new), "", &changed)
	sort.Strings(changed)
	return changed
}

// compareConfigValue walks config values using their YAML field names so every
// setting added to the schema is included without a second hand-maintained list.
func compareConfigValue(old, new reflect.Value, path string, changed *[]string) {
	if !old.IsValid() || !new.IsValid() {
		if old.IsValid() != new.IsValid() && path != "" {
			*changed = append(*changed, path)
		}
		return
	}
	if old.Type() != new.Type() {
		if path != "" {
			*changed = append(*changed, path)
		}
		return
	}

	switch old.Kind() {
	case reflect.Interface, reflect.Pointer:
		if old.IsNil() || new.IsNil() {
			if old.IsNil() != new.IsNil() && path != "" {
				*changed = append(*changed, path)
			}
			return
		}
		compareConfigValue(old.Elem(), new.Elem(), path, changed)
	case reflect.Struct:
		for i := 0; i < old.NumField(); i++ {
			field := old.Type().Field(i)
			if field.PkgPath != "" {
				continue
			}
			name, inline, skip := yamlFieldName(field)
			if skip {
				continue
			}
			fieldPath := path
			if !inline {
				fieldPath = joinConfigPath(path, name)
			}
			compareConfigValue(old.Field(i), new.Field(i), fieldPath, changed)
		}
	case reflect.Map:
		if old.IsNil() != new.IsNil() && old.Len() == 0 && new.Len() == 0 {
			if path != "" {
				*changed = append(*changed, path)
			}
			return
		}
		type mapKeys struct {
			old reflect.Value
			new reflect.Value
		}
		keys := make(map[string]mapKeys, old.Len()+new.Len())
		for _, key := range old.MapKeys() {
			name := fmt.Sprint(key.Interface())
			entry := keys[name]
			entry.old = key
			keys[name] = entry
		}
		for _, key := range new.MapKeys() {
			name := fmt.Sprint(key.Interface())
			entry := keys[name]
			entry.new = key
			keys[name] = entry
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			entry := keys[key]
			var oldItem, newItem reflect.Value
			if entry.old.IsValid() {
				oldItem = old.MapIndex(entry.old)
			}
			if entry.new.IsValid() {
				newItem = new.MapIndex(entry.new)
			}
			compareConfigValue(oldItem, newItem, joinConfigPath(path, key), changed)
		}
	case reflect.Slice, reflect.Array:
		if old.Kind() == reflect.Slice && old.IsNil() != new.IsNil() && old.Len() == 0 && new.Len() == 0 {
			if path != "" {
				*changed = append(*changed, path)
			}
			return
		}
		maxLen := old.Len()
		if new.Len() > maxLen {
			maxLen = new.Len()
		}
		for i := 0; i < maxLen; i++ {
			var oldItem, newItem reflect.Value
			if i < old.Len() {
				oldItem = old.Index(i)
			}
			if i < new.Len() {
				newItem = new.Index(i)
			}
			compareConfigValue(oldItem, newItem, fmt.Sprintf("%s[%d]", path, i), changed)
		}
	default:
		if !reflect.DeepEqual(old.Interface(), new.Interface()) && path != "" {
			*changed = append(*changed, path)
		}
	}
}

// yamlFieldName returns the effective key and inline/skip behavior for a field.
func yamlFieldName(field reflect.StructField) (name string, inline, skip bool) {
	parts := strings.Split(field.Tag.Get("yaml"), ",")
	name = parts[0]
	for _, option := range parts[1:] {
		if option == "inline" {
			inline = true
		}
	}
	if name == "-" {
		return "", false, true
	}
	if name == "" {
		name = strings.ToLower(field.Name)
	}
	return name, inline, false
}

func joinConfigPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func requiresRestart(setting string) bool {
	for _, prefix := range restartRequiredPrefixes {
		root := strings.TrimSuffix(prefix, ".")
		if setting == root || (strings.HasSuffix(prefix, ".") && strings.HasPrefix(setting, prefix)) {
			return true
		}
	}
	return false
}

// preserveRestartRequiredSettings restores the active values for settings that
// cannot take effect without a process restart, even when other fields reload.
func preserveRestartRequiredSettings(oldCfg, newCfg *AppConfig) {
	preserveRestartValues(reflect.ValueOf(oldCfg).Elem(), reflect.ValueOf(newCfg).Elem(), "")
}

func preserveRestartValues(old, new reflect.Value, path string) {
	if !old.IsValid() || !new.IsValid() || old.Type() != new.Type() {
		return
	}
	if path != "" && requiresRestart(path) {
		if new.CanSet() {
			new.Set(old)
		}
		return
	}
	if path != "" && !isRestartPathAncestor(path) {
		return
	}

	switch old.Kind() {
	case reflect.Interface, reflect.Pointer:
		if old.IsNil() || new.IsNil() {
			if new.CanSet() {
				new.Set(old)
			}
			return
		}
		preserveRestartValues(old.Elem(), new.Elem(), path)
	case reflect.Struct:
		for i := 0; i < old.NumField(); i++ {
			field := old.Type().Field(i)
			if field.PkgPath != "" {
				continue
			}
			name, inline, skip := yamlFieldName(field)
			if skip {
				continue
			}
			fieldPath := path
			if !inline {
				fieldPath = joinConfigPath(path, name)
			}
			preserveRestartValues(old.Field(i), new.Field(i), fieldPath)
		}
	}
}

func isRestartPathAncestor(path string) bool {
	if path == "" {
		return true
	}
	for _, prefix := range restartRequiredPrefixes {
		root := strings.TrimSuffix(prefix, ".")
		if strings.HasPrefix(root, path+".") {
			return true
		}
	}
	return false
}

// categorizeChanges retains the two-bucket compatibility helper for callers
// that only need to distinguish immediate changes from restart requirements.
func categorizeChanges(changes []string) (hotReload, needsRestart []string) {
	hotReload, _, needsRestart = categorizeReloadChanges(changes)
	return append(hotReload, changesMatching(changes, requiresGracefulReload)...), needsRestart
}

func categorizeReloadChanges(changes []string) (hotReload, gracefulReload, needsRestart []string) {
	for _, setting := range changes {
		if requiresRestart(setting) {
			needsRestart = append(needsRestart, setting)
		} else if requiresGracefulReload(setting) {
			gracefulReload = append(gracefulReload, setting)
		} else {
			hotReload = append(hotReload, setting)
		}
	}
	return
}

func requiresGracefulReload(setting string) bool {
	if setting == "server.baseurl" || strings.HasPrefix(setting, "server.logging.") && setting != "server.logging.level" {
		return true
	}
	switch setting {
	case "server.limits.read_timeout", "server.limits.write_timeout", "server.limits.idle_timeout",
		"server.timeouts.read", "server.timeouts.write", "server.timeouts.idle":
		return true
	default:
		return false
	}
}

func changesMatching(changes []string, match func(string) bool) []string {
	var out []string
	for _, change := range changes {
		if match(change) {
			out = append(out, change)
		}
	}
	return out
}

func preserveConfigPaths(oldCfg, newCfg *AppConfig, paths []string) {
	oldValue := reflect.ValueOf(oldCfg).Elem()
	newValue := reflect.ValueOf(newCfg).Elem()
	for _, path := range paths {
		copyConfigPath(oldValue, newValue, strings.Split(path, "."))
	}
}

func copyConfigPath(oldValue, newValue reflect.Value, parts []string) {
	if !oldValue.IsValid() || !newValue.IsValid() || len(parts) == 0 {
		return
	}
	if oldValue.Kind() == reflect.Pointer {
		if oldValue.IsNil() || newValue.IsNil() {
			return
		}
		copyConfigPath(oldValue.Elem(), newValue.Elem(), parts)
		return
	}
	if oldValue.Kind() != reflect.Struct {
		return
	}
	for index := 0; index < oldValue.NumField(); index++ {
		field := oldValue.Type().Field(index)
		if field.PkgPath != "" {
			continue
		}
		name, inline, skip := yamlFieldName(field)
		if skip || inline || name != parts[0] {
			continue
		}
		oldField, newField := oldValue.Field(index), newValue.Field(index)
		if len(parts) == 1 {
			if newField.CanSet() {
				newField.Set(oldField)
			}
			return
		}
		copyConfigPath(oldField, newField, parts[1:])
		return
	}
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
