package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/paths"
)

const (
	appName = "ipgaze"
	orgName = "apimgr"
)

// ServiceType represents the type of service manager.
type ServiceType int

const (
	ServiceUnknown ServiceType = iota
	ServiceSystemd
	ServiceOpenRC
	ServiceSysVinit
	ServiceRunit
	ServiceS6
	ServiceLaunchd
	ServiceWindows
	ServiceBSDRC
	ServiceContainer
)

// Service provides service management operations.
type Service struct{}

// NewSystemServiceManager returns a ready-to-use Service.
func NewSystemServiceManager() *Service { return &Service{} }

// DetectServiceManager detects the active service manager.
// Container environments are detected first; then init system detection follows the spec order.
func DetectServiceManager() ServiceType {
	// Container detection takes highest priority
	if paths.IsRunningInContainer() {
		return ServiceContainer
	}

	ppid := os.Getppid()

	switch runtime.GOOS {
	case "linux":
		// systemd: PPID=1 with /run/systemd/system, or INVOCATION_ID env var
		if (ppid == 1 && isStatOK("/run/systemd/system")) || os.Getenv("INVOCATION_ID") != "" {
			return ServiceSystemd
		}
		// Fallback systemd: /etc/systemd directory present
		if _, err := os.Stat("/etc/systemd"); err == nil {
			return ServiceSystemd
		}
		// runit: SVDIR env var
		if os.Getenv("SVDIR") != "" {
			return ServiceRunit
		}
		// runit: check for run directory
		if _, err := os.Stat("/run/runit"); err == nil {
			return ServiceRunit
		}
		// s6: S6_LOGGING env var
		if os.Getenv("S6_LOGGING") != "" {
			return ServiceS6
		}
		// OpenRC: check for its init binary
		if _, err := os.Stat("/sbin/openrc-run"); err == nil {
			return ServiceOpenRC
		}
		// SysVinit: PPID=1 + /etc/init.d without systemd
		if ppid == 1 {
			if _, err := os.Stat("/etc/init.d"); err == nil {
				if _, err2 := os.Stat("/run/systemd/system"); os.IsNotExist(err2) {
					return ServiceSysVinit
				}
			}
			// Fallback SysV via update-rc.d or chkconfig
			if _, err := os.Stat("/etc/init.d"); err == nil {
				if _, err2 := exec.LookPath("update-rc.d"); err2 == nil {
					return ServiceSysVinit
				}
				if _, err2 := exec.LookPath("chkconfig"); err2 == nil {
					return ServiceSysVinit
				}
			}
		}
		// rc.d (BSD file sometimes present on Linux-based BSD-like systems)
		if _, err := os.Stat("/etc/rc.subr"); err == nil {
			return ServiceBSDRC
		}
		return ServiceUnknown

	case "darwin":
		// launchd: macOS with PPID=1
		if ppid == 1 {
			return ServiceLaunchd
		}
		return ServiceLaunchd

	case "windows":
		return ServiceWindows

	case "freebsd", "openbsd", "netbsd":
		// rc.d: check for rc.subr
		if _, err := os.Stat("/etc/rc.subr"); err == nil {
			return ServiceBSDRC
		}
		return ServiceBSDRC

	default:
		return ServiceUnknown
	}
}

// IsUserServiceManager reports whether this process is running under a
// per-user systemd unit or LaunchAgent rather than a system-wide service.
func IsUserServiceManager() bool {
	return shouldUseUserSystemd() || shouldUseUserLaunchAgent()
}

// isStatOK returns true if the path exists.
func isStatOK(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Install installs, enables, and starts the service.
func (s *Service) Install() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			return installSystemdUser()
		}
		return installSystemd()
	case ServiceOpenRC:
		return installOpenRC()
	case ServiceSysVinit:
		return installSysVinit()
	case ServiceRunit:
		return installRunit()
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			return installLaunchAgent()
		}
		return installLaunchd()
	case ServiceS6:
		return installS6()
	case ServiceWindows:
		return installWindows()
	case ServiceBSDRC:
		return installBSDRC()
	default:
		return fmt.Errorf("unsupported service manager")
	}
}

// Uninstall stops, disables, removes the service file, deletes ALL data, and removes the OS user.
// Confirmation is always required before proceeding.
func (s *Service) Uninstall() error {
	return s.UninstallWithDirectories(paths.GetDirectories())
}

// UninstallWithDirectories removes the service and the paths resolved for the
// current command invocation.
func (s *Service) UninstallWithDirectories(dirs paths.Directories) error {
	serviceType := DetectServiceManager()

	fmt.Print("This will delete ALL data, configs, and the system user. Continue? [y/N] ")
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		fmt.Println("Aborted.")
		return nil
	}

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			return uninstallSystemdUser(dirs)
		}
		return uninstallSystemd(dirs)
	case ServiceOpenRC:
		return uninstallOpenRC(dirs)
	case ServiceSysVinit:
		return uninstallSysVinit(dirs)
	case ServiceRunit:
		return uninstallRunit(dirs)
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			return uninstallLaunchAgent(dirs)
		}
		return uninstallLaunchd(dirs)
	case ServiceS6:
		return uninstallS6(dirs)
	case ServiceWindows:
		return uninstallWindows(dirs)
	case ServiceBSDRC:
		return uninstallBSDRC(dirs)
	default:
		return fmt.Errorf("unsupported service manager")
	}
}

// Disable stops and disables the service, keeping all data and config.
func (s *Service) Disable() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			_ = exec.Command("systemctl", "--user", "stop", appName).Run()
			return exec.Command("systemctl", "--user", "disable", appName).Run()
		}
		// Stop errors are non-fatal; best-effort before disable.
		exec.Command("systemctl", "stop", appName).Run() //nolint:errcheck
		return exec.Command("systemctl", "disable", appName).Run()
	case ServiceOpenRC:
		// Stop errors are non-fatal; best-effort before disable.
		exec.Command("rc-service", appName, "stop").Run() //nolint:errcheck
		return exec.Command("rc-update", "del", appName, "default").Run()
	case ServiceSysVinit:
		// Stop errors are non-fatal; best-effort before disable.
		exec.Command("service", appName, "stop").Run() //nolint:errcheck
		// Debian-style first; fall back to RHEL-style
		if err := exec.Command("update-rc.d", appName, "disable").Run(); err != nil {
			return exec.Command("chkconfig", appName, "off").Run()
		}
		return nil
	case ServiceRunit:
		return exec.Command("sv", "down", appName).Run()
	case ServiceS6:
		_ = exec.Command("s6-rc", "-d", "change", appName).Run()
		return disableS6()
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			return disableLaunchAgent()
		}
		plistPath := launchdPlistPath()
		return exec.Command("launchctl", "unload", plistPath).Run()
	case ServiceWindows:
		// Stop errors are non-fatal; best-effort before disable.
		exec.Command("sc.exe", "stop", appName).Run() //nolint:errcheck
		return exec.Command("sc.exe", "config", appName, "start=", "disabled").Run()
	case ServiceBSDRC:
		// Stop errors are non-fatal; best-effort before disable.
		exec.Command("service", appName, "stop").Run() //nolint:errcheck
		return exec.Command("sysrc", appName+"_enable=NO").Run()
	default:
		return fmt.Errorf("unsupported service manager")
	}
}

// Start starts the service via the detected service manager.
func (s *Service) Start() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			return exec.Command("systemctl", "--user", "start", appName).Run()
		}
		return exec.Command("systemctl", "start", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "start").Run()
	case ServiceSysVinit:
		return exec.Command("service", appName, "start").Run()
	case ServiceRunit:
		return exec.Command("sv", "start", appName).Run()
	case ServiceS6:
		return exec.Command("s6-rc", "-u", "change", appName).Run()
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			return startLaunchAgent()
		}
		return exec.Command("launchctl", "load", launchdPlistPath()).Run()
	case ServiceWindows:
		return exec.Command("sc.exe", "start", appName).Run()
	case ServiceBSDRC:
		return exec.Command("service", appName, "start").Run()
	default:
		return fmt.Errorf("unsupported service manager")
	}
}

// Stop stops the service via the detected service manager.
func (s *Service) Stop() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			return exec.Command("systemctl", "--user", "stop", appName).Run()
		}
		return exec.Command("systemctl", "stop", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "stop").Run()
	case ServiceSysVinit:
		return exec.Command("service", appName, "stop").Run()
	case ServiceRunit:
		return exec.Command("sv", "stop", appName).Run()
	case ServiceS6:
		return exec.Command("s6-rc", "-d", "change", appName).Run()
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			return stopLaunchAgent()
		}
		return exec.Command("launchctl", "unload", launchdPlistPath()).Run()
	case ServiceWindows:
		return exec.Command("sc.exe", "stop", appName).Run()
	case ServiceBSDRC:
		return exec.Command("service", appName, "stop").Run()
	default:
		return fmt.Errorf("unsupported service manager")
	}
}

// Restart restarts the service.
func (s *Service) Restart() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			return exec.Command("systemctl", "--user", "restart", appName).Run()
		}
		return exec.Command("systemctl", "restart", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "restart").Run()
	case ServiceSysVinit:
		return exec.Command("service", appName, "restart").Run()
	case ServiceRunit:
		return exec.Command("sv", "restart", appName).Run()
	case ServiceS6:
		if err := s.Stop(); err != nil {
			return err
		}
		return s.Start()
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			return restartLaunchAgent()
		}
		// Stop errors are non-fatal; best-effort before restart.
		s.Stop() //nolint:errcheck
		return s.Start()
	case ServiceWindows:
		// Stop errors are non-fatal; best-effort before restart.
		exec.Command("sc.exe", "stop", appName).Run() //nolint:errcheck
		return exec.Command("sc.exe", "start", appName).Run()
	case ServiceBSDRC:
		return exec.Command("service", appName, "restart").Run()
	default:
		return fmt.Errorf("unsupported service manager")
	}
}

// Reload reloads service configuration without a full restart.
func (s *Service) Reload() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
				return err
			}
			return exec.Command("systemctl", "--user", "reload-or-restart", appName).Run()
		}
		return exec.Command("systemctl", "reload-or-restart", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "reload").Run()
	case ServiceRunit:
		return exec.Command("sv", "hup", appName).Run()
	case ServiceS6:
		return s.Restart()
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			return restartLaunchAgent()
		}
		return s.Restart()
	default:
		return s.Restart()
	}
}

// Status prints current service status to stdout in the canonical format
// from AI.md PART 23 "Service Help Output": Service/State/Auto-start/PID.
func (s *Service) Status() error {
	serviceType := DetectServiceManager()

	var installed bool
	state := "stopped"
	autostart := "disabled"
	pid := ""

	switch serviceType {
	case ServiceSystemd:
		if shouldUseUserSystemd() {
			unitPath := systemdUserUnitPath()
			installed = isStatOK(unitPath)
			if out, err := exec.Command("systemctl", "--user", "is-active", appName).Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
				state = "running"
			}
			if out, err := exec.Command("systemctl", "--user", "is-enabled", appName).Output(); err == nil && strings.TrimSpace(string(out)) == "enabled" {
				autostart = "enabled"
			}
			if out, err := exec.Command("systemctl", "--user", "show", appName, "--property=MainPID", "--value").Output(); err == nil {
				if p := strings.TrimSpace(string(out)); p != "" && p != "0" {
					pid = p
				}
			}
			break
		}
		installed = isStatOK(fmt.Sprintf("/etc/systemd/system/%s.service", appName))
		if out, err := exec.Command("systemctl", "is-active", appName).Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
			state = "running"
		}
		if out, err := exec.Command("systemctl", "is-enabled", appName).Output(); err == nil && strings.TrimSpace(string(out)) == "enabled" {
			autostart = "enabled"
		}
		if out, err := exec.Command("systemctl", "show", appName, "--property=MainPID", "--value").Output(); err == nil {
			if p := strings.TrimSpace(string(out)); p != "" && p != "0" {
				pid = p
			}
		}
	case ServiceOpenRC:
		installed = isStatOK(fmt.Sprintf("/etc/init.d/%s", appName))
		if exec.Command("rc-service", appName, "status").Run() == nil {
			state = "running"
		}
		if out, err := exec.Command("rc-update", "show", "default").Output(); err == nil && strings.Contains(string(out), appName) {
			autostart = "enabled"
		}
		pid = readPIDFile(fmt.Sprintf("/var/run/%s/%s.pid", orgName, appName))
	case ServiceSysVinit:
		installed = isStatOK(fmt.Sprintf("/etc/init.d/%s", appName))
		if exec.Command("service", appName, "status").Run() == nil {
			state = "running"
		}
		if _, err := exec.LookPath("update-rc.d"); err == nil {
			// update-rc.d has no direct query flag; presence of rc*.d symlinks implies enabled.
			if matches, _ := filepath.Glob("/etc/rc*.d/S??" + appName); len(matches) > 0 {
				autostart = "enabled"
			}
		}
		pid = readPIDFile(fmt.Sprintf("/var/run/%s/%s.pid", orgName, appName))
	case ServiceRunit:
		svDir := fmt.Sprintf("/etc/sv/%s", appName)
		installed = isStatOK(svDir)
		if out, err := exec.Command("sv", "status", appName).Output(); err == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "run:") {
			state = "running"
		}
		if isStatOK(fmt.Sprintf("/var/service/%s", appName)) {
			autostart = "enabled"
		}
	case ServiceS6:
		installed = isStatOK(s6ServiceDir())
		if out, err := exec.Command("s6-rc", "-a", "list").Output(); err == nil && strings.Contains("\n"+string(out)+"\n", "\n"+appName+"\n") {
			state = "running"
		}
		if isStatOK(filepath.Join(s6UserBundleDir, appName)) {
			autostart = "enabled"
		}
	case ServiceLaunchd:
		if shouldUseUserLaunchAgent() {
			plistPath := launchAgentPlistPath()
			installed = isStatOK(plistPath)
			if out, err := exec.Command("launchctl", "print", launchAgentDomain()+"/"+launchdLabel()).Output(); err == nil {
				state, pid = launchAgentProcessStatus(string(out))
			}
			if out, err := exec.Command("launchctl", "print-disabled", launchAgentDomain()).Output(); err == nil && launchAgentEnabled(string(out), launchdLabel()) {
				autostart = "enabled"
			}
			break
		}
		installed = isStatOK(launchdPlistPath())
		if out, err := exec.Command("launchctl", "list", launchdLabel()).Output(); err == nil {
			state = "running"
			autostart = "enabled"
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, `"PID"`) {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						pid = strings.Trim(strings.TrimSpace(parts[1]), ";")
					}
				}
			}
		} else if installed {
			autostart = "enabled"
		}
	case ServiceWindows:
		out, err := exec.Command("sc.exe", "query", appName).Output()
		installed = err == nil
		if err == nil && strings.Contains(string(out), "RUNNING") {
			state = "running"
		}
		if cfgOut, err := exec.Command("sc.exe", "qc", appName).Output(); err == nil && strings.Contains(string(cfgOut), "AUTO_START") {
			autostart = "enabled"
		}
	case ServiceBSDRC:
		installed = isStatOK(fmt.Sprintf("/usr/local/etc/rc.d/%s", appName))
		if exec.Command("service", appName, "status").Run() == nil {
			state = "running"
		}
		if out, err := exec.Command("sysrc", "-n", appName+"_enable").Output(); err == nil && strings.EqualFold(strings.TrimSpace(string(out)), "yes") {
			autostart = "enabled"
		}
		pid = readPIDFile(fmt.Sprintf("/var/run/%s/%s.pid", orgName, appName))
	default:
		return fmt.Errorf("unsupported service manager")
	}

	installedText := "not installed"
	if installed {
		installedText = "installed"
	}
	fmt.Printf("Service:    %s\n", installedText)
	fmt.Printf("State:      %s\n", state)
	fmt.Printf("Auto-start: %s\n", autostart)
	if pid != "" {
		fmt.Printf("PID:        %s\n", pid)
	}
	return nil
}

// readPIDFile reads and trims a PID file's content, returning "" if the file
// is absent or unreadable.
func readPIDFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// GetBinaryPath returns the installation path for the binary.
func GetBinaryPath() string {
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf(`C:\Program Files\%s\%s\%s.exe`, orgName, appName, appName)
	default:
		return fmt.Sprintf("/usr/local/bin/%s", appName)
	}
}

// deleteAllData removes the OS-specific config, data, cache, log, and backup
// directories plus the PID file resolved by the paths package. This follows
// AI.md PART 23 "Service Uninstall Logic".
func deleteAllData(dirs paths.Directories) {
	dirsToRemove := []string{
		dirs.Config,
		dirs.Data,
		dirs.Cache,
		dirs.Logs,
		dirs.Backup,
	}
	for _, d := range dirsToRemove {
		if err := os.RemoveAll(d); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove %s: %v\n", d, err)
		}
	}

	if err := os.Remove(dirs.PID); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: failed to remove %s: %v\n", dirs.PID, err)
	}
}

// removeSystemUser removes the OS user and group created during
// installation, per AI.md PART 23 "Service Uninstall Logic" step 5
// ("Delete system user and group").
func removeSystemUser() {
	switch runtime.GOOS {
	case "darwin":
		// Best-effort removal; missing user/group is not an error during uninstall.
		exec.Command("dscl", ".", "-delete", "/Users/"+appName).Run()  //nolint:errcheck
		exec.Command("dscl", ".", "-delete", "/Groups/"+appName).Run() //nolint:errcheck
	default:
		// Best-effort removal; missing user/group is not an error during uninstall.
		exec.Command("userdel", "-r", appName).Run() //nolint:errcheck
		exec.Command("groupdel", appName).Run()      //nolint:errcheck
	}
}

// launchdLabel returns the launchd label for this service.
// Per AI.md the plist Bundle ID is always io.github.{project_org}.{internal_name}.
func launchdLabel() string {
	return fmt.Sprintf("io.github.%s.%s", orgName, appName)
}

// launchdPlistPath returns the full path of the launchd plist.
func launchdPlistPath() string {
	return fmt.Sprintf("/Library/LaunchDaemons/%s.plist", launchdLabel())
}

func isServiceElevated() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return true
	}
	out, err := exec.Command("id", "-u").Output()
	return err == nil && strings.TrimSpace(string(out)) == "0"
}

func shouldUseUserSystemd() bool {
	return runtime.GOOS == "linux" && !isServiceElevated()
}

func systemdUserUnitPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user", appName+".service")
}

func installSystemdUser() error {
	unitPath := systemdUserUnitPath()
	if unitPath == "" {
		return fmt.Errorf("cannot determine the current user's systemd unit directory")
	}
	binaryPath, err := currentBinaryPath()
	if err != nil {
		return err
	}
	dirs := paths.GetAllDirs(appName)
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		return fmt.Errorf("create user systemd directory: %w", err)
	}
	unit := fmt.Sprintf(`[Unit]
Description=%s user service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=%s %s %s %s %s

[Install]
WantedBy=default.target
`, appName, systemdEscape(binaryPath),
		systemdEscape(dirs.Config), systemdEscape(dirs.Data), systemdEscape(dirs.Cache), systemdEscape(dirs.Logs), systemdEscape(dirs.Backup))
	if err := os.WriteFile(unitPath, []byte(unit), 0o600); err != nil {
		return fmt.Errorf("write user systemd unit: %w", err)
	}
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("reload user systemd units: %w", err)
	}
	if err := exec.Command("systemctl", "--user", "enable", "--now", appName).Run(); err != nil {
		return fmt.Errorf("enable and start user service: %w", err)
	}
	fmt.Printf("User service installed and started: %s\n", unitPath)
	return nil
}

func systemdEscape(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", "", "\r", "").Replace(value) + `"`
}

func currentBinaryPath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate current binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve current binary: %w", err)
	}
	return resolved, nil
}

func uninstallSystemdUser(dirs paths.Directories) error {
	unitPath := systemdUserUnitPath()
	_ = exec.Command("systemctl", "--user", "disable", "--now", appName).Run()
	if unitPath != "" {
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove user systemd unit: %w", err)
		}
	}
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("reload user systemd units: %w", err)
	}
	deleteAllData(dirs)
	fmt.Println("User service uninstalled. Binary and user data removed.")
	return nil
}

func shouldUseUserLaunchAgent() bool {
	return runtime.GOOS == "darwin" && !isServiceElevated()
}

func launchAgentPlistPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel()+".plist")
}

func launchAgentDomain() string {
	out, err := exec.Command("id", "-u").Output()
	if err != nil {
		return "gui/"
	}
	return "gui/" + strings.TrimSpace(string(out))
}

func installLaunchAgent() error {
	plistPath := launchAgentPlistPath()
	if plistPath == "" {
		return fmt.Errorf("cannot determine the current user's LaunchAgents directory")
	}
	binaryPath, err := currentBinaryPath()
	if err != nil {
		return err
	}
	dirs := paths.GetAllDirs(appName)
	for _, dir := range []string{filepath.Dir(plistPath), dirs.Logs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create user service directory %s: %w", dir, err)
		}
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>%s</string>
<key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, xmlEscape(launchdLabel()), xmlEscape(binaryPath),
		xmlEscape(filepath.Join(dirs.Logs, "stdout.log")), xmlEscape(filepath.Join(dirs.Logs, "stderr.log")))
	if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
		return fmt.Errorf("write user launch agent: %w", err)
	}
	if err := startLaunchAgent(); err != nil {
		return err
	}
	fmt.Printf("User LaunchAgent installed and started: %s\n", plistPath)
	return nil
}

func xmlEscape(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(value)
}

func startLaunchAgent() error {
	domain := launchAgentDomain()
	label := domain + "/" + launchdLabel()
	if err := exec.Command("launchctl", "enable", label).Run(); err != nil {
		return fmt.Errorf("enable user launch agent: %w", err)
	}
	if _, err := exec.Command("launchctl", "print", label).Output(); err != nil {
		if err := exec.Command("launchctl", "bootstrap", domain, launchAgentPlistPath()).Run(); err != nil {
			return fmt.Errorf("bootstrap user launch agent: %w", err)
		}
	}
	if err := exec.Command("launchctl", "kickstart", "-k", label).Run(); err != nil {
		return fmt.Errorf("start user launch agent: %w", err)
	}
	return nil
}

func stopLaunchAgent() error {
	if err := exec.Command("launchctl", "bootout", launchAgentDomain(), launchAgentPlistPath()).Run(); err != nil {
		return fmt.Errorf("stop user launch agent: %w", err)
	}
	return nil
}

func disableLaunchAgent() error {
	_ = stopLaunchAgent()
	if err := exec.Command("launchctl", "disable", launchAgentDomain()+"/"+launchdLabel()).Run(); err != nil {
		return fmt.Errorf("disable user launch agent: %w", err)
	}
	return nil
}

func restartLaunchAgent() error {
	return startLaunchAgent()
}

func launchAgentProcessStatus(output string) (string, string) {
	state := "stopped"
	pid := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "state = running" {
			state = "running"
		}
		if strings.HasPrefix(line, "pid = ") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "pid = "))
			if value != "0" {
				pid = value
			}
		}
	}
	return state, pid
}

func launchAgentEnabled(output, label string) bool {
	needle := `"` + label + `" => enabled`
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == needle {
			return true
		}
	}
	return false
}

func uninstallLaunchAgent(dirs paths.Directories) error {
	if err := disableLaunchAgent(); err != nil {
		return err
	}
	plistPath := launchAgentPlistPath()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove user launch agent: %w", err)
	}
	deleteAllData(dirs)
	fmt.Println("User LaunchAgent uninstalled. Binary and user data removed.")
	return nil
}

const (
	s6RCSourceDir   = "/etc/s6-overlay/s6-rc.d"
	s6ServiceName   = appName
	s6UserBundleDir = "/etc/s6-overlay/user-bundles.d/user/contents.d"
)

func s6ServiceDir() string { return filepath.Join(s6RCSourceDir, s6ServiceName) }

func installS6() error {
	if _, err := os.Stat(s6RCSourceDir); err != nil {
		return fmt.Errorf("s6-overlay service directory unavailable: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(s6ServiceDir(), "dependencies.d"), 0o755); err != nil {
		return fmt.Errorf("create s6 service definition: %w", err)
	}
	if err := os.MkdirAll(s6UserBundleDir, 0o755); err != nil {
		return fmt.Errorf("create s6 user bundle: %w", err)
	}
	binaryPath := GetBinaryPath()
	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("install binary for s6: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(s6ServiceDir(), "type"), []byte("longrun\n"), 0o644); err != nil {
		return fmt.Errorf("write s6 service type: %w", err)
	}
	runScript := "#!/bin/sh\nexec " + shellQuote(binaryPath) + "\n"
	if err := os.WriteFile(filepath.Join(s6ServiceDir(), "run"), []byte(runScript), 0o755); err != nil {
		return fmt.Errorf("write s6 run script: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s6ServiceDir(), "dependencies.d", "base"), nil, 0o644); err != nil {
		return fmt.Errorf("write s6 base dependency: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s6UserBundleDir, s6ServiceName), nil, 0o644); err != nil {
		return fmt.Errorf("enable s6 service: %w", err)
	}
	if err := updateS6Database(); err != nil {
		return err
	}
	if err := exec.Command("s6-rc", "-u", "change", s6ServiceName).Run(); err != nil {
		return fmt.Errorf("start s6 service: %w", err)
	}
	fmt.Printf("s6 service installed and started: %s\n", s6ServiceDir())
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func updateS6Database() error {
	compiledDB := filepath.Join("/run/s6", fmt.Sprintf("db.ipgaze.%d", time.Now().UnixNano()))
	if err := exec.Command("s6-rc-compile", compiledDB, s6RCSourceDir).Run(); err != nil {
		return fmt.Errorf("compile s6 service database: %w", err)
	}
	if err := exec.Command("s6-rc-update", compiledDB).Run(); err != nil {
		return fmt.Errorf("update live s6 service database: %w", err)
	}
	return nil
}

func disableS6() error {
	if err := os.Remove(filepath.Join(s6UserBundleDir, s6ServiceName)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("disable s6 service: %w", err)
	}
	return updateS6Database()
}

func uninstallS6(dirs paths.Directories) error {
	_ = exec.Command("s6-rc", "-d", "change", s6ServiceName).Run()
	if err := os.Remove(filepath.Join(s6UserBundleDir, s6ServiceName)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove s6 user bundle entry: %w", err)
	}
	if err := os.RemoveAll(s6ServiceDir()); err != nil {
		return fmt.Errorf("remove s6 service definition: %w", err)
	}
	if err := updateS6Database(); err != nil {
		return err
	}
	deleteAllData(dirs)
	removeSystemUser()
	fmt.Printf("s6 service uninstalled. Delete binary manually: rm %s\n", GetBinaryPath())
	return nil
}

// installSystemd creates and activates a systemd service.
// Per AI.md PART 24: no User= directive — binary drops privileges after port binding.
func installSystemd() error {
	binaryPath := GetBinaryPath()
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", appName)

	// Per PART 24 systemd template: no User= or Group= lines.
	// Binary drops privileges to {internal_name} user after binding ports.
	serviceContent := fmt.Sprintf(`[Unit]
Description=%s service
Documentation=https://%s.github.io/%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/etc/%s/%s
ReadWritePaths=/var/lib/%s/%s
ReadWritePaths=/var/cache/%s/%s
ReadWritePaths=/var/log/%s/%s

[Install]
WantedBy=multi-user.target
`, appName, orgName, appName,
		binaryPath,
		orgName, appName,
		orgName, appName,
		orgName, appName,
		orgName, appName)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	if err := exec.Command("systemctl", "enable", appName).Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("systemctl", "start", appName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("Service installed and started: %s\n", servicePath)
	fmt.Printf("Binary installed at: %s\n", binaryPath)
	return nil
}

// uninstallSystemd stops, disables, removes the service file, deletes all data, and removes the OS user.
func uninstallSystemd(dirs paths.Directories) error {
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", appName)
	binaryPath := GetBinaryPath()

	// Stop/disable errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("systemctl", "stop", appName).Run()    //nolint:errcheck
	exec.Command("systemctl", "disable", appName).Run() //nolint:errcheck

	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}
	// daemon-reload is best-effort; systemd will reload on next operation if this fails.
	exec.Command("systemctl", "daemon-reload").Run() //nolint:errcheck

	deleteAllData(dirs)
	removeSystemUser()

	fmt.Printf("Service uninstalled. Delete binary manually: rm %s\n", binaryPath)
	return nil
}

// installOpenRC creates and enables an OpenRC service.
func installOpenRC() error {
	binaryPath := GetBinaryPath()
	initPath := fmt.Sprintf("/etc/init.d/%s", appName)

	initContent := fmt.Sprintf(`#!/sbin/openrc-run
name="%s"
description="%s service"
command="%s"
command_args=""
command_user="%s:%s"
pidfile="/var/run/%s/%s.pid"
command_background=true
output_log="/var/log/%s/%s/server.log"
error_log="/var/log/%s/%s/error.log"

depend() {
    need net
    after firewall
    use dns logger
}

start_pre() {
    checkpath -d -m 0755 -o %s:%s /var/run/%s
    checkpath -d -m 0755 -o %s:%s /var/log/%s/%s
}
`,
		appName, appName, binaryPath,
		appName, appName,
		orgName, appName,
		orgName, appName,
		orgName, appName,
		appName, appName, orgName,
		appName, appName, orgName, appName,
	)

	if err := os.WriteFile(initPath, []byte(initContent), 0755); err != nil {
		return fmt.Errorf("failed to write OpenRC init script: %w", err)
	}

	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	if err := exec.Command("rc-update", "add", appName, "default").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("rc-service", appName, "start").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("OpenRC service installed and started: %s\n", initPath)
	return nil
}

// uninstallOpenRC removes an OpenRC service and all its data.
func uninstallOpenRC(dirs paths.Directories) error {
	initPath := fmt.Sprintf("/etc/init.d/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop/remove errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("rc-service", appName, "stop").Run()          //nolint:errcheck
	exec.Command("rc-update", "del", appName, "default").Run() //nolint:errcheck

	if err := os.Remove(initPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove init script: %w", err)
	}

	deleteAllData(dirs)
	removeSystemUser()

	fmt.Printf("Service uninstalled. Delete binary manually: rm %s\n", binaryPath)
	return nil
}

// installSysVinit creates and enables a SysVinit service.
func installSysVinit() error {
	binaryPath := GetBinaryPath()
	initPath := fmt.Sprintf("/etc/init.d/%s", appName)

	initContent := fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          %s
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: %s service
### END INIT INFO

NAME=%s
DAEMON=%s
DAEMON_USER=%s
PIDFILE=/var/run/%s/%s.pid
LOGFILE=/var/log/%s/%s/server.log

case "$1" in
    start)
        echo "Starting $NAME..."
        mkdir -p $(dirname $PIDFILE) $(dirname $LOGFILE)
        chown -R $DAEMON_USER:$DAEMON_USER $(dirname $PIDFILE) $(dirname $LOGFILE)
        start-stop-daemon --start --quiet --background --make-pidfile \
            --pidfile $PIDFILE --chuid $DAEMON_USER --exec $DAEMON \
            --no-close >> $LOGFILE 2>&1
        ;;
    stop)
        echo "Stopping $NAME..."
        start-stop-daemon --stop --quiet --pidfile $PIDFILE --retry 30
        rm -f $PIDFILE
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        if [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE) 2>/dev/null; then
            echo "$NAME is running (pid $(cat $PIDFILE))"
            exit 0
        else
            echo "$NAME is stopped"
            exit 3
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
exit 0
`,
		appName, appName,
		appName, binaryPath, appName,
		orgName, appName,
		orgName, appName,
	)

	if err := os.WriteFile(initPath, []byte(initContent), 0755); err != nil {
		return fmt.Errorf("failed to write SysVinit script: %w", err)
	}

	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Enable via Debian-style or RHEL-style; chkconfig is the fallback if update-rc.d is absent.
	if err := exec.Command("update-rc.d", appName, "defaults").Run(); err != nil {
		// chkconfig errors are non-fatal; service enable is best-effort across distros.
		exec.Command("chkconfig", "--add", appName).Run() //nolint:errcheck
		exec.Command("chkconfig", appName, "on").Run()    //nolint:errcheck
	}
	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("service", appName, "start").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("SysVinit service installed and started: %s\n", initPath)
	return nil
}

// uninstallSysVinit removes a SysVinit service and all its data.
func uninstallSysVinit(dirs paths.Directories) error {
	initPath := fmt.Sprintf("/etc/init.d/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop/deregister errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("service", appName, "stop").Run()       //nolint:errcheck
	exec.Command("update-rc.d", appName, "remove").Run() //nolint:errcheck
	exec.Command("chkconfig", "--del", appName).Run()    //nolint:errcheck

	if err := os.Remove(initPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove init script: %w", err)
	}

	deleteAllData(dirs)
	removeSystemUser()

	fmt.Printf("Service uninstalled. Delete binary manually: rm %s\n", binaryPath)
	return nil
}

// installRunit creates a runit service directory.
func installRunit() error {
	svDir := fmt.Sprintf("/etc/sv/%s", appName)
	binaryPath := GetBinaryPath()

	if err := os.MkdirAll(svDir, 0755); err != nil {
		return fmt.Errorf("failed to create service directory: %w", err)
	}

	runScript := fmt.Sprintf("#!/bin/sh\nexec %s 2>&1\n", binaryPath)
	if err := os.WriteFile(filepath.Join(svDir, "run"), []byte(runScript), 0755); err != nil {
		return fmt.Errorf("failed to write run script: %w", err)
	}

	logDir := filepath.Join(svDir, "log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logRunScript := fmt.Sprintf("#!/bin/sh\nexec svlogd -tt /var/log/%s/%s\n", orgName, appName)
	if err := os.WriteFile(filepath.Join(logDir, "run"), []byte(logRunScript), 0755); err != nil {
		return fmt.Errorf("failed to write log run script: %w", err)
	}

	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Link to active service directory to enable auto-start; symlink failure is non-fatal.
	linkPath := fmt.Sprintf("/var/service/%s", appName)
	os.Symlink(svDir, linkPath) //nolint:errcheck

	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("sv", "start", appName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("Runit service installed and started: %s\n", svDir)
	return nil
}

// uninstallRunit removes a runit service and all its data.
func uninstallRunit(dirs paths.Directories) error {
	svDir := fmt.Sprintf("/etc/sv/%s", appName)
	linkPath := fmt.Sprintf("/var/service/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("sv", "stop", appName).Run() //nolint:errcheck

	// Best-effort cleanup of symlink and service dir during uninstall.
	os.Remove(linkPath) //nolint:errcheck
	os.RemoveAll(svDir) //nolint:errcheck

	deleteAllData(dirs)
	removeSystemUser()

	fmt.Printf("Service uninstalled. Delete binary manually: rm %s\n", binaryPath)
	return nil
}

// installLaunchd creates and loads a macOS launchd plist.
func installLaunchd() error {
	binaryPath := GetBinaryPath()
	plistPath := launchdPlistPath()
	label := launchdLabel()

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/%s/%s/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/%s/%s/stderr.log</string>
</dict>
</plist>
`, label, binaryPath, orgName, appName, orgName, appName)

	dirs := []string{
		fmt.Sprintf("/Library/Application Support/%s/%s", orgName, appName),
		fmt.Sprintf("/var/log/%s/%s", orgName, appName),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write plist file: %w", err)
	}

	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("failed to load service: %w", err)
	}

	fmt.Printf("LaunchDaemon installed and started: %s\n", plistPath)
	return nil
}

// uninstallLaunchd removes a macOS launchd service and all its data.
func uninstallLaunchd(dirs paths.Directories) error {
	plistPath := launchdPlistPath()
	binaryPath := GetBinaryPath()

	// Unload errors are non-fatal during uninstall; plist removal is the critical step.
	exec.Command("launchctl", "unload", plistPath).Run() //nolint:errcheck

	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove plist file: %w", err)
	}

	deleteAllData(dirs)
	removeSystemUser()

	fmt.Printf("Service uninstalled. Delete binary manually: rm %s\n", binaryPath)
	return nil
}

// installWindows creates and starts a Windows service.
func installWindows() error {
	binaryPath := GetBinaryPath()

	binDir := filepath.Dir(binaryPath)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}
	// Use Virtual Service Account (NT SERVICE\{internal_name}) — no explicit user needed.
	cmd := exec.Command("sc.exe", "create", appName,
		"binPath=", binaryPath,
		"DisplayName=", "IPGaze API",
		"start=", "auto",
		"obj=", fmt.Sprintf(`NT SERVICE\%s`, appName))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create Windows service: %w", err)
	}
	if err := grantWindowsServiceControl(); err != nil {
		_ = exec.Command("sc.exe", "delete", appName).Run()
		return fmt.Errorf("grant Windows service restart rights: %w", err)
	}
	if err := prepareServiceDirectories(paths.GetDirectories(), binDir); err != nil {
		_ = exec.Command("sc.exe", "delete", appName).Run()
		return fmt.Errorf("prepare Windows service directories: %w", err)
	}

	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("sc.exe", "start", appName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("Windows service '%s' installed and started\n", appName)
	return nil
}

func grantWindowsServiceControl() error {
	sidOutput, err := exec.Command("sc.exe", "showsid", appName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("read service SID: %w: %s", err, strings.TrimSpace(string(sidOutput)))
	}
	serviceSID, err := parseWindowsServiceSID(string(sidOutput))
	if err != nil {
		return err
	}
	sddlOutput, err := exec.Command("sc.exe", "sdshow", appName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("read service security descriptor: %w: %s", err, strings.TrimSpace(string(sddlOutput)))
	}
	sddl := strings.TrimSpace(string(sddlOutput))
	for _, line := range strings.Split(sddl, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "D:") {
			sddl = line
			break
		}
	}
	updated, err := addWindowsServiceControlACE(sddl, serviceSID)
	if err != nil {
		return err
	}
	if updated == sddl {
		return nil
	}
	if output, err := exec.Command("sc.exe", "sdset", appName, updated).CombinedOutput(); err != nil {
		return fmt.Errorf("grant service start/stop/query rights: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func parseWindowsServiceSID(output string) (string, error) {
	for _, field := range strings.Fields(output) {
		if !strings.HasPrefix(field, "S-1-5-80-") {
			continue
		}
		parts := strings.Split(field, "-")
		if len(parts) != 9 {
			return "", fmt.Errorf("invalid service SID returned by sc.exe")
		}
		for _, part := range parts[1:] {
			if part == "" {
				return "", fmt.Errorf("invalid service SID returned by sc.exe")
			}
			for _, r := range part {
				if r < '0' || r > '9' {
					return "", fmt.Errorf("invalid service SID returned by sc.exe")
				}
			}
		}
		return field, nil
	}
	return "", fmt.Errorf("sc.exe did not return a service SID for %s", appName)
}

func addWindowsServiceControlACE(sddl, serviceSID string) (string, error) {
	if !strings.HasPrefix(sddl, "D:") {
		return "", fmt.Errorf("invalid service security descriptor")
	}
	if _, err := parseWindowsServiceSID(serviceSID); err != nil {
		return "", err
	}
	daclEnd := len(sddl)
	if sacl := strings.Index(sddl, "S:"); sacl >= 0 {
		daclEnd = sacl
	}
	dacl := sddl[:daclEnd]
	if strings.Contains(dacl, ";;LCRPWP;;;"+serviceSID+")") {
		return sddl, nil
	}
	ace := "(A;;LCRPWP;;;" + serviceSID + ")"
	return sddl[:daclEnd] + ace + sddl[daclEnd:], nil
}

// uninstallWindows removes a Windows service and all its data.
func uninstallWindows(dirs paths.Directories) error {
	binaryPath := GetBinaryPath()

	// Stop errors are non-fatal during uninstall; sc.exe delete is the critical step.
	exec.Command("sc.exe", "stop", appName).Run() //nolint:errcheck
	if err := exec.Command("sc.exe", "delete", appName).Run(); err != nil {
		return fmt.Errorf("failed to delete Windows service: %w", err)
	}

	deleteAllData(dirs)

	fmt.Printf("Service uninstalled. Delete binary manually: del \"%s\"\n", binaryPath)
	return nil
}

// installBSDRC creates and enables a BSD rc.d service.
func installBSDRC() error {
	binaryPath := GetBinaryPath()
	rcPath := fmt.Sprintf("/usr/local/etc/rc.d/%s", appName)

	rcContent := fmt.Sprintf(`#!/bin/sh

# PROVIDE: %s
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="%s"
rcvar="%s_enable"
command="%s"
pidfile="/var/run/%s/%s.pid"

load_rc_config $name
: ${%s_enable:="NO"}

run_rc_command "$1"
`, appName, appName, appName, binaryPath, orgName, appName, appName)

	if err := os.WriteFile(rcPath, []byte(rcContent), 0755); err != nil {
		return fmt.Errorf("failed to write rc.d script: %w", err)
	}

	if exePath, err := os.Executable(); err == nil && exePath != binaryPath {
		if err := copyBinary(exePath, binaryPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	if err := exec.Command("sysrc", appName+"_enable=YES").Run(); err != nil {
		return fmt.Errorf("failed to enable service in rc.conf: %w", err)
	}

	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("service", appName, "start").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("BSD rc.d service installed and started: %s\n", rcPath)
	return nil
}

// uninstallBSDRC removes a BSD rc.d service and all its data.
func uninstallBSDRC(dirs paths.Directories) error {
	rcPath := fmt.Sprintf("/usr/local/etc/rc.d/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop/deregister errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("service", appName, "stop").Run()       //nolint:errcheck
	exec.Command("sysrc", "-x", appName+"_enable").Run() //nolint:errcheck

	if err := os.Remove(rcPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove rc.d script: %w", err)
	}

	deleteAllData(dirs)
	removeSystemUser()

	fmt.Printf("Service uninstalled. Delete binary manually: rm %s\n", binaryPath)
	return nil
}

// copyBinary copies the binary from src to dst.
func copyBinary(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}
