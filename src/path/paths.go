package path

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Organization name for directory structure
	OrgName = "apimgr"
	// internalName is the frozen internal project name used for default paths.
	internalName = "ipgaze"
)

// Directories holds the application directories
type Directories struct {
	Config   string
	Data     string
	Logs     string
	Cache    string
	PID      string
	SSL      string
	Security string
	DB       string
	Backup   string
}

// startedElevated is captured ONCE at package initialization, BEFORE any
// privilege drop, and never re-evaluated. After the startup sequence drops
// privileges geteuid() changes, but the directory mode (system vs user) must
// not — see AI.md PART 8 "Directory mode is locked at process start".
var startedElevated = detectElevated()

// detectElevated reports whether the process started with administrative
// privileges. Windows has no effective UID, so membership in the machine's own
// domain is used as the administrative heuristic.
func detectElevated() bool {
	if runtime.GOOS == "windows" {
		return os.Getenv("USERDOMAIN") == os.Getenv("COMPUTERNAME")
	}
	return os.Geteuid() == 0
}

// isElevated returns the locked-at-startup elevation state, honoring the
// testForceNonRoot override used by unit tests.
func isElevated() bool {
	if testForceNonRoot {
		return false
	}
	return startedElevated
}

// dirPermFor returns the directory permission for the given mode:
// 0755 for a system (root) process, 0700 for a user process.
// AI.md PART 8 "Directory Validation Rules".
func dirPermFor(isRoot bool) os.FileMode {
	if isRoot {
		return 0o755
	}
	return 0o700
}

// filePermFor returns the file permission for the given mode:
// 0644 for a system (root) process, 0600 for a user process.
// AI.md PART 8 "Directory Validation Rules".
func filePermFor(isRoot bool) os.FileMode {
	if isRoot {
		return 0o644
	}
	return 0o600
}

// cachedDirectories memoizes GetDirectories so repeat calls across the process
// lifetime can never diverge, even after a privilege drop.
var (
	cachedDirectories     Directories
	cachedDirectoriesOnce sync.Once
)

// GetDirectories returns OS-specific directories
// Uses {org}/{name} structure: /etc/apimgr/ipgaze/, ~/.config/apimgr/ipgaze/
// The result is resolved once and cached for the process lifetime.
func GetDirectories() Directories {
	cachedDirectoriesOnce.Do(func() {
		cachedDirectories = GetAllDirs(internalName)
	})
	return cachedDirectories
}

// resetDirectoriesCache clears the memoized GetDirectories result.
// It is only intended for use in unit tests that change the ambient
// environment between resolutions.
func resetDirectoriesCache() {
	cachedDirectories = Directories{}
	cachedDirectoriesOnce = sync.Once{}
}

// GetAllDirs returns all OS-specific directories for a project
func GetAllDirs(projectName string) Directories {
	configDir, dataDir, logsDir, cacheDir, pidFile, sslDir, securityDir, dbDir, backupDir := GetFullDirs(projectName)
	return Directories{
		Config:   configDir,
		Data:     dataDir,
		Logs:     logsDir,
		Cache:    cacheDir,
		PID:      pidFile,
		SSL:      sslDir,
		Security: securityDir,
		DB:       dbDir,
		Backup:   backupDir,
	}
}

// testForceNonContainer overrides container detection when set to true.
// It is only intended for use in unit tests.
var testForceNonContainer bool

// testForceNonRoot overrides root detection when set to true.
// It is only intended for use in unit tests.
var testForceNonRoot bool

// GetFullDirs returns all OS-specific directories based on privileges
// Uses {org}/{name} structure per PART 4 spec
func GetFullDirs(projectName string) (configDir, dataDir, logsDir, cacheDir, pidFile, sslDir, securityDir, dbDir, backupDir string) {
	// DATABASE_DIR/BACKUP_DIR are Init-Only env vars (PART 12): they override
	// the computed default on first run and are then persisted to server.yml.
	defer func() {
		if envDB := os.Getenv("DATABASE_DIR"); envDB != "" {
			dbDir = envDB
		}
		if envBackup := os.Getenv("BACKUP_DIR"); envBackup != "" {
			backupDir = envBackup
		}
	}()

	// Check for container environment first
	if !testForceNonContainer && IsRunningInContainer() {
		// Docker paths per PART 4: /config/{project_name}/, /data/{project_name}/
		configDir = "/config/" + projectName
		dataDir = "/data/" + projectName
		logsDir = "/data/log/" + projectName
		cacheDir = "/data/" + projectName + "/cache"
		pidFile = "/var/run/" + projectName + ".pid"
		sslDir = "/config/" + projectName + "/ssl"
		securityDir = "/data/" + projectName + "/security"
		dbDir = "/data/db/sqlite"
		backupDir = "/data/backups/" + projectName
		return
	}

	// Elevation is locked at process start, never re-derived from the live EUID.
	if isElevated() {
		configDir, dataDir, logsDir, cacheDir, pidFile, sslDir, securityDir, dbDir, backupDir = rootDirs(runtime.GOOS, projectName)
	} else {
		var homeDir string
		currentUser, err := user.Current()
		if err == nil {
			homeDir = currentUser.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
			if homeDir == "" {
				homeDir = os.Getenv("USERPROFILE")
			}
		}
		configDir, dataDir, logsDir, cacheDir, pidFile, sslDir, securityDir, dbDir, backupDir = userDirs(runtime.GOOS, projectName, homeDir)
	}

	return
}

// rootDirs returns OS-specific directories for a privileged (root/admin) process.
func rootDirs(goos, projectName string) (configDir, dataDir, logsDir, cacheDir, pidFile, sslDir, securityDir, dbDir, backupDir string) {
	switch goos {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = "C:\\ProgramData"
		}
		base := filepath.Join(programData, OrgName, projectName)
		configDir = base
		dataDir = filepath.Join(base, "data")
		logsDir = filepath.Join(base, "logs")
		cacheDir = filepath.Join(base, "cache")
		pidFile = filepath.Join(base, projectName+".pid")
		sslDir = filepath.Join(base, "ssl")
		securityDir = filepath.Join(base, "data", "security")
		dbDir = filepath.Join(base, "db")
	case "darwin":
		// macOS root per PART 4: /Library/Application Support/{org}/{project}/
		libSupport := filepath.Join("/Library/Application Support", OrgName, projectName)
		configDir = libSupport
		dataDir = filepath.Join(libSupport, "data")
		logsDir = filepath.Join("/Library/Logs", OrgName, projectName)
		cacheDir = filepath.Join("/Library/Caches", OrgName, projectName)
		pidFile = filepath.Join("/var/run", OrgName, projectName+".pid")
		sslDir = filepath.Join(libSupport, "ssl")
		securityDir = filepath.Join(libSupport, "data", "security")
		dbDir = filepath.Join(libSupport, "db")
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		// BSD root per PART 4: /usr/local/etc/{org}/{project}/
		configDir = filepath.Join("/usr/local/etc", OrgName, projectName)
		dataDir = filepath.Join("/var/db", OrgName, projectName)
		logsDir = filepath.Join("/var/log", OrgName, projectName)
		cacheDir = filepath.Join("/var/cache", OrgName, projectName)
		pidFile = filepath.Join("/var/run", OrgName, projectName+".pid")
		sslDir = filepath.Join("/usr/local/etc", OrgName, projectName, "ssl")
		securityDir = filepath.Join("/var/db", OrgName, projectName, "security")
		dbDir = filepath.Join("/var/db", OrgName, projectName, "db")
	default:
		// Linux root per PART 4
		configDir = filepath.Join("/etc", OrgName, projectName)
		dataDir = filepath.Join("/var/lib", OrgName, projectName)
		logsDir = filepath.Join("/var/log", OrgName, projectName)
		cacheDir = filepath.Join("/var/cache", OrgName, projectName)
		pidFile = filepath.Join("/var/run", OrgName, projectName+".pid")
		sslDir = filepath.Join("/etc", OrgName, projectName, "ssl")
		securityDir = filepath.Join("/var/lib", OrgName, projectName, "security")
		dbDir = filepath.Join("/var/lib", OrgName, projectName, "db")
	}
	// AI.md PART 8: prefer the system backup dir when writable. In system mode
	// the fallback is always {data_dir}/backup — never a $HOME-derived path,
	// because a service account's HOME points at the data dir.
	backupDir = preferSystemBackupDir(goos, projectName, filepath.Join(dataDir, "backup"))
	return
}

// systemBackupDir returns the system-level backup directory for the given OS.
// Linux: /mnt/Backups/{org}/{name}; macOS: /Library/Backups/{org}/{name};
// BSD: /var/backups/{org}/{name}; Windows: %ProgramData%\Backups\{org}\{name}.
func systemBackupDir(goos, projectName string) string {
	switch goos {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = "C:\\ProgramData"
		}
		return filepath.Join(programData, "Backups", OrgName, projectName)
	case "darwin":
		return filepath.Join("/Library/Backups", OrgName, projectName)
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		return filepath.Join("/var/backups", OrgName, projectName)
	// linux
	default:
		return filepath.Join("/mnt/Backups", OrgName, projectName)
	}
}

// preferSystemBackupDir returns the system backup directory when it is
// writable, otherwise the caller's mode-appropriate fallback.
func preferSystemBackupDir(goos, projectName, fallback string) string {
	return backupDirOrFallback(systemBackupDir(goos, projectName), fallback)
}

// backupDirOrFallback returns sysBackup when it is writable, else fallback.
func backupDirOrFallback(sysBackup, fallback string) string {
	if isWritable(sysBackup) {
		return sysBackup
	}
	return fallback
}

// isWritable reports whether path can be created and written to, by probing
// its parent directory with a uniquely named temporary file.
func isWritable(path string) bool {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return false
	}
	testFile := filepath.Join(parent, ".write_test_"+strconv.FormatInt(time.Now().UnixNano(), 36))
	f, err := os.Create(testFile)
	if err != nil {
		return false
	}
	if err := f.Close(); err != nil {
		os.Remove(testFile)
		return false
	}
	os.Remove(testFile)
	return true
}

// userDirs returns OS-specific directories for an unprivileged user process.
func userDirs(goos, projectName, homeDir string) (configDir, dataDir, logsDir, cacheDir, pidFile, sslDir, securityDir, dbDir, backupDir string) {
	// userBackup holds the user-mode backup path used as the fallback when the
	// system backup dir is not writable.
	var userBackup string
	switch goos {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(homeDir, "AppData", "Roaming")
		}
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(homeDir, "AppData", "Local")
		}
		configDir = filepath.Join(appData, OrgName, projectName)
		dataDir = filepath.Join(localAppData, OrgName, projectName)
		logsDir = filepath.Join(localAppData, OrgName, projectName, "logs")
		cacheDir = filepath.Join(localAppData, OrgName, projectName, "cache")
		pidFile = filepath.Join(localAppData, OrgName, projectName, projectName+".pid")
		sslDir = filepath.Join(appData, OrgName, projectName, "ssl")
		securityDir = filepath.Join(localAppData, OrgName, projectName, "security")
		dbDir = filepath.Join(localAppData, OrgName, projectName, "db")
		userBackup = filepath.Join(localAppData, "Backups", OrgName, projectName)
	case "darwin":
		// macOS user per PART 4: ~/Library/Application Support/{org}/{project}/
		libSupport := filepath.Join(homeDir, "Library", "Application Support", OrgName, projectName)
		configDir = libSupport
		dataDir = libSupport
		logsDir = filepath.Join(homeDir, "Library", "Logs", OrgName, projectName)
		cacheDir = filepath.Join(homeDir, "Library", "Caches", OrgName, projectName)
		pidFile = filepath.Join(libSupport, projectName+".pid")
		sslDir = filepath.Join(libSupport, "ssl")
		securityDir = filepath.Join(libSupport, "data", "security")
		dbDir = filepath.Join(libSupport, "db")
		// Per PART 4: ~/Library/Backups/{org}/{project}/
		userBackup = filepath.Join(homeDir, "Library", "Backups", OrgName, projectName)
	// Linux, BSD (user) — per PART 4 XDG paths
	default:
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			xdgConfig = filepath.Join(homeDir, ".config")
		}
		xdgData := os.Getenv("XDG_DATA_HOME")
		if xdgData == "" {
			xdgData = filepath.Join(homeDir, ".local", "share")
		}
		xdgCache := os.Getenv("XDG_CACHE_HOME")
		if xdgCache == "" {
			xdgCache = filepath.Join(homeDir, ".cache")
		}

		configDir = filepath.Join(xdgConfig, OrgName, projectName)
		dataDir = filepath.Join(xdgData, OrgName, projectName)
		// Per PART 4: logs go to ~/.local/log/ not ~/.local/share/…/logs/
		logsDir = filepath.Join(homeDir, ".local", "log", OrgName, projectName)
		cacheDir = filepath.Join(xdgCache, OrgName, projectName)
		pidFile = filepath.Join(xdgData, OrgName, projectName, projectName+".pid")
		sslDir = filepath.Join(xdgConfig, OrgName, projectName, "ssl")
		// Per PART 4: security DBs reside in data dir, not config dir
		securityDir = filepath.Join(xdgData, OrgName, projectName, "security")
		dbDir = filepath.Join(xdgData, OrgName, projectName, "db")
		// Per PART 4: user backups go to ~/.local/share/Backups/{org}/{project}/
		userBackup = filepath.Join(xdgData, "Backups", OrgName, projectName)
	}
	// AI.md PART 8: prefer the system backup dir when writable; in user mode
	// the fallback is the user backup dir.
	backupDir = preferSystemBackupDir(goos, projectName, userBackup)
	return
}

// GetDefaultDirs returns OS-specific default directories based on privileges (legacy)
// Uses {org}/{name} structure: /etc/apimgr/ipgaze/, ~/.config/apimgr/ipgaze/
func GetDefaultDirs(projectName string) (configDir, dataDir, logsDir string) {
	config, data, logs, _, _, _, _, _, _ := GetFullDirs(projectName)
	return config, data, logs
}

// GetDefaultDirsLegacy returns OS-specific default directories based on privileges
// Deprecated: Use GetFullDirs instead
func GetDefaultDirsLegacy(projectName string) (configDir, dataDir, logsDir string) {
	// Elevation is locked at process start, never re-derived from the live EUID.
	if isElevated() {
		configDir, dataDir, logsDir = rootDirsLegacy(runtime.GOOS, projectName)
	} else {
		var homeDir string
		currentUser, err := user.Current()
		if err == nil {
			homeDir = currentUser.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
			if homeDir == "" {
				homeDir = os.Getenv("USERPROFILE")
			}
		}
		configDir, dataDir, logsDir = userDirsLegacy(runtime.GOOS, projectName, homeDir)
	}

	return configDir, dataDir, logsDir
}

// rootDirsLegacy returns legacy OS-specific directories for a privileged process.
func rootDirsLegacy(goos, projectName string) (configDir, dataDir, logsDir string) {
	switch goos {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = "C:\\ProgramData"
		}
		configDir = filepath.Join(programData, OrgName, projectName)
		dataDir = filepath.Join(programData, OrgName, projectName, "data")
		logsDir = filepath.Join(programData, OrgName, projectName, "logs")
	// Linux, BSD, macOS
	default:
		configDir = filepath.Join("/etc", OrgName, projectName)
		dataDir = filepath.Join("/var/lib", OrgName, projectName)
		logsDir = filepath.Join("/var/log", OrgName, projectName)
	}
	return
}

// userDirsLegacy returns legacy OS-specific directories for an unprivileged user process.
func userDirsLegacy(goos, projectName, homeDir string) (configDir, dataDir, logsDir string) {
	switch goos {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(homeDir, "AppData", "Roaming")
		}
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(homeDir, "AppData", "Local")
		}
		configDir = filepath.Join(appData, OrgName, projectName)
		dataDir = filepath.Join(localAppData, OrgName, projectName)
		logsDir = filepath.Join(localAppData, OrgName, projectName, "logs")
	case "darwin":
		configDir = filepath.Join(homeDir, ".config", OrgName, projectName)
		dataDir = filepath.Join(homeDir, ".local", "share", OrgName, projectName)
		logsDir = filepath.Join(homeDir, ".local", "share", OrgName, projectName, "logs")
	// Linux, BSD
	default:
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			xdgConfig = filepath.Join(homeDir, ".config")
		}
		xdgData := os.Getenv("XDG_DATA_HOME")
		if xdgData == "" {
			xdgData = filepath.Join(homeDir, ".local", "share")
		}

		configDir = filepath.Join(xdgConfig, OrgName, projectName)
		dataDir = filepath.Join(xdgData, OrgName, projectName)
		logsDir = filepath.Join(xdgData, OrgName, projectName, "logs")
	}
	return
}

// EnsureDirectories creates all required directories with mode-appropriate
// permissions, failing fast if any of them is not writable.
func EnsureDirectories(dirs Directories) error {
	isRoot := isElevated()
	dirsToCreate := []string{
		dirs.Config,
		dirs.Data,
		dirs.Logs,
		dirs.Cache,
		dirs.SSL,
		dirs.Security,
		dirs.DB,
		dirs.Backup,
	}
	for _, dir := range dirsToCreate {
		if dir != "" {
			if err := EnsureDir(dir, isRoot); err != nil {
				return err
			}
		}
	}
	return nil
}

// EnsureDir creates a directory with the permissions mandated by AI.md PART 8
// — 0755 when isRoot, 0700 otherwise — then verifies the directory is actually
// writable by creating, writing, and removing a probe file. Creation of a new
// directory is logged at INFO level.
func EnsureDir(path string, isRoot bool) error {
	perm := dirPermFor(isRoot)

	_, statErr := os.Stat(path)
	missing := os.IsNotExist(statErr)

	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	if missing {
		log.Printf("INFO: created directory %s (mode %#o)", path, perm)
	}

	testFile := filepath.Join(path, ".write-test")
	if err := os.WriteFile(testFile, []byte{}, 0o600); err != nil {
		return fmt.Errorf("directory %s is not writable: %w", path, err)
	}
	if err := os.Remove(testFile); err != nil {
		return fmt.Errorf("directory %s write probe cleanup failed: %w", path, err)
	}

	return nil
}

// EnsurePIDFile creates the PID file's parent directory and validates that it
// is writable, per AI.md PART 8.
func EnsurePIDFile(path string, isRoot bool) error {
	return EnsureDir(filepath.Dir(path), isRoot)
}

// EnsureDirs creates all required directories using the locked-at-startup mode.
func EnsureDirs(configDir, dataDir, logsDir string) error {
	isRoot := isElevated()
	if err := EnsureDir(configDir, isRoot); err != nil {
		return err
	}
	if err := EnsureDir(dataDir, isRoot); err != nil {
		return err
	}
	if err := EnsureDir(logsDir, isRoot); err != nil {
		return err
	}
	return nil
}

// testSkipDockerEnvCheck bypasses the /.dockerenv file check in IsRunningInContainer.
// It is only intended for use in unit tests.
var testSkipDockerEnvCheck bool

// testProcCommPath and testProcCgroupPath allow tests to override /proc file paths.
var testProcCommPath = "/proc/1/comm"
var testProcCgroupPath = "/proc/1/cgroup"

// IsRunningInContainer checks if running inside a container.
// Detects Docker, Podman, LXC/LXD/Incus, Kubernetes, and generic container environments.
func IsRunningInContainer() bool {
	// File-based detection: Docker, Podman, LXC/LXD/Incus
	containerFiles := []string{
		"/.dockerenv",
		"/run/.containerenv",
		"/dev/lxc",
	}
	for _, f := range containerFiles {
		if testSkipDockerEnvCheck && f == "/.dockerenv" {
			continue
		}
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}

	// Environment variable detection
	if os.Getenv("container") != "" {
		return true
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	// Parent process name — container init systems
	parentName := getParentProcessName()
	switch parentName {
	case "tini", "dumb-init", "s6-svscan", "runsv", "runsvdir", "catatonit", "ipgaze":
		return true
	}

	// cgroup-based detection
	if data, err := os.ReadFile(testProcCgroupPath); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "lxc") {
			return true
		}
	}

	return false
}

// getParentProcessName returns the name of the parent process.
// Uses /proc/{ppid}/comm on Linux; falls back to ps on macOS/BSD.
// In tests, testProcCommPath overrides the /proc path so container
// detection logic can be exercised without a real container environment.
func getParentProcessName() string {
	ppid := os.Getppid()

	// Allow tests to override the /proc comm path.
	commPath := testProcCommPath
	if commPath == "/proc/1/comm" {
		commPath = fmt.Sprintf("/proc/%d/comm", ppid)
	}

	// Linux: read /proc/{ppid}/comm
	if data, err := os.ReadFile(commPath); err == nil {
		return strings.TrimSpace(string(data))
	}

	// macOS/BSD: use ps command
	cmd := exec.Command("ps", "-p", strconv.Itoa(ppid), "-o", "comm=")
	if output, err := cmd.Output(); err == nil {
		return strings.TrimSpace(string(output))
	}

	return ""
}

// GetBackupDir returns the backup directory from flag, env, or default,
// per AI.md PART 8.
// System mode (startedElevated): the system backup dir when writable, else
// {data_dir}/backup — NEVER a $HOME-derived path, because a service account's
// HOME is set to {data_dir} and a $HOME fallback would nest user-style dirs
// inside /var/lib/{internal_org}/{internal_name}/.
// User mode: the system backup dir when writable, else the user backup dir.
func GetBackupDir(flagValue string, dataDir string) string {
	if flagValue != "" {
		return flagValue
	}
	if envValue := os.Getenv("BACKUP_DIR"); envValue != "" {
		return envValue
	}
	// Containers and user mode already resolve the correct backup path through
	// the normal directory table.
	if !isElevated() || (!testForceNonContainer && IsRunningInContainer()) {
		return GetDirectories().Backup
	}
	if dataDir == "" {
		dataDir = GetDirectories().Data
	}
	return preferSystemBackupDir(runtime.GOOS, internalName, filepath.Join(dataDir, "backup"))
}
