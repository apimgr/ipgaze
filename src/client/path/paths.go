// Package paths provides platform-aware path helpers for the ipgaze CLI client.
// Paths follow the AI.md PART 32 client directory tables: Linux and macOS share
// the same `~/.config` / `~/.local/share` / `~/.cache` / `~/.local/log` layout,
// Windows uses %APPDATA% and %LOCALAPPDATA%.
package path

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	projectOrg  = "apimgr"
	projectName = "ipgaze"
)

// ConfigDir returns the platform-appropriate config directory.
// Linux/macOS/BSD: $XDG_CONFIG_HOME/apimgr/ipgaze or ~/.config/apimgr/ipgaze
// Windows:         %APPDATA%\apimgr\ipgaze
func ConfigDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsRoaming(), projectOrg, projectName)
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, projectOrg, projectName)
}

// DataDir returns the platform-appropriate data directory.
// Linux/macOS/BSD: $XDG_DATA_HOME/apimgr/ipgaze or ~/.local/share/apimgr/ipgaze
// Windows:         %LOCALAPPDATA%\apimgr\ipgaze\data
func DataDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsLocal(), projectOrg, projectName, "data")
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, projectOrg, projectName)
}

// CacheDir returns the platform-appropriate cache directory.
// Linux/macOS/BSD: $XDG_CACHE_HOME/apimgr/ipgaze or ~/.cache/apimgr/ipgaze
// Windows:         %LOCALAPPDATA%\apimgr\ipgaze\cache
func CacheDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsLocal(), projectOrg, projectName, "cache")
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, projectOrg, projectName)
}

// LogDir returns the platform-appropriate log directory.
// Linux/macOS/BSD: ~/.local/log/apimgr/ipgaze
// Windows:         %LOCALAPPDATA%\apimgr\ipgaze\log
// There is no XDG variable for logs, so the home-relative path from AI.md
// PART 32 is used verbatim.
func LogDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsLocal(), projectOrg, projectName, "log")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "log", projectOrg, projectName)
}

// windowsRoaming returns %APPDATA% with a home-relative fallback.
func windowsRoaming() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "AppData", "Roaming")
	}
	return base
}

// windowsLocal returns %LOCALAPPDATA% with a home-relative fallback.
func windowsLocal() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "AppData", "Local")
	}
	return base
}

// ConfigFile returns the path to the default CLI config file (cli.yml).
func ConfigFile() string {
	return filepath.Join(ConfigDir(), "cli.yml")
}

// LogFile returns the path to the CLI log file (cli.log).
func LogFile() string {
	return filepath.Join(LogDir(), "cli.log")
}

// ResolveConfigPath resolves the --config flag value to an absolute config file
// path, implementing the AI.md PART 32 "--config Flag (Config File Selection)"
// resolution table:
//
//	--config test               -> {config_dir}/test.yml
//	--config dev.yml            -> {config_dir}/dev.yml
//	--config ~/testing/app.yml  -> ~/testing/app.yml
//	--config /etc/app/prod.yml  -> /etc/app/prod.yml
//	(not specified)             -> {config_dir}/cli.yml
func ResolveConfigPath(configFlag string) (string, error) {
	if configFlag == "" {
		return ConfigFile(), nil
	}

	// Expand a leading ~ to the invoking user's home directory.
	if strings.HasPrefix(configFlag, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configFlag = filepath.Join(home, configFlag[2:])
	}

	if filepath.IsAbs(configFlag) {
		return ResolveYamlExtension(configFlag), nil
	}

	return ResolveYamlExtension(filepath.Join(ConfigDir(), configFlag)), nil
}

// ResolveYamlExtension auto-detects the .yml or .yaml extension for a config
// path. An existing yaml extension is kept, a missing extension resolves to an
// existing .yml then .yaml file and otherwise defaults to .yml for new configs,
// and any other extension is left untouched.
func ResolveYamlExtension(p string) string {
	ext := filepath.Ext(p)

	if ext == ".yml" || ext == ".yaml" {
		return p
	}

	if ext == "" {
		if fileExists(p + ".yml") {
			return p + ".yml"
		}
		if fileExists(p + ".yaml") {
			return p + ".yaml"
		}
		return p + ".yml"
	}

	return p
}

// fileExists reports whether p exists and is not a directory.
func fileExists(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
