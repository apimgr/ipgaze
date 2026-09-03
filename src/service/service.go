package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	paths "github.com/apimgr/ipgaze/src/path"
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
		return installSystemd()
	case ServiceOpenRC:
		return installOpenRC()
	case ServiceSysVinit:
		return installSysVinit()
	case ServiceRunit:
		return installRunit()
	case ServiceLaunchd:
		return installLaunchd()
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
		return uninstallSystemd()
	case ServiceOpenRC:
		return uninstallOpenRC()
	case ServiceSysVinit:
		return uninstallSysVinit()
	case ServiceRunit:
		return uninstallRunit()
	case ServiceLaunchd:
		return uninstallLaunchd()
	case ServiceWindows:
		return uninstallWindows()
	case ServiceBSDRC:
		return uninstallBSDRC()
	default:
		return fmt.Errorf("unsupported service manager")
	}
}

// Disable stops and disables the service, keeping all data and config.
func (s *Service) Disable() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
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
	case ServiceLaunchd:
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
		return exec.Command("systemctl", "start", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "start").Run()
	case ServiceSysVinit:
		return exec.Command("service", appName, "start").Run()
	case ServiceRunit:
		return exec.Command("sv", "start", appName).Run()
	case ServiceLaunchd:
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
		return exec.Command("systemctl", "stop", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "stop").Run()
	case ServiceSysVinit:
		return exec.Command("service", appName, "stop").Run()
	case ServiceRunit:
		return exec.Command("sv", "stop", appName).Run()
	case ServiceLaunchd:
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
		return exec.Command("systemctl", "restart", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "restart").Run()
	case ServiceSysVinit:
		return exec.Command("service", appName, "restart").Run()
	case ServiceRunit:
		return exec.Command("sv", "restart", appName).Run()
	case ServiceLaunchd:
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
		return exec.Command("systemctl", "reload", appName).Run()
	case ServiceOpenRC:
		return exec.Command("rc-service", appName, "reload").Run()
	case ServiceRunit:
		return exec.Command("sv", "hup", appName).Run()
	default:
		return s.Restart()
	}
}

// Status prints current service status to stdout.
func (s *Service) Status() error {
	serviceType := DetectServiceManager()

	switch serviceType {
	case ServiceSystemd:
		cmd := exec.Command("systemctl", "status", appName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		// intentionally ignore exit code — systemctl status prints even when stopped
		cmd.Run() //nolint:errcheck
		return nil
	case ServiceOpenRC:
		cmd := exec.Command("rc-service", appName, "status")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case ServiceSysVinit:
		cmd := exec.Command("service", appName, "status")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case ServiceRunit:
		cmd := exec.Command("sv", "status", appName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case ServiceLaunchd:
		cmd := exec.Command("launchctl", "list", launchdLabel())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case ServiceWindows:
		cmd := exec.Command("sc.exe", "query", appName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case ServiceBSDRC:
		cmd := exec.Command("service", appName, "status")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported service manager")
	}
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

// deleteAllData removes all runtime data dirs left by the service.
func deleteAllData() {
	dirs := []string{
		fmt.Sprintf("/etc/%s/%s", orgName, appName),
		fmt.Sprintf("/var/lib/%s/%s", orgName, appName),
		fmt.Sprintf("/var/cache/%s/%s", orgName, appName),
		fmt.Sprintf("/var/log/%s/%s", orgName, appName),
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove %s: %v\n", d, err)
		}
	}
}

// removeSystemUser removes the OS user created during installation.
func removeSystemUser() {
	switch runtime.GOOS {
	case "darwin":
		// Best-effort user removal; missing user is not an error during uninstall.
		exec.Command("dscl", ".", "-delete", "/Users/"+appName).Run() //nolint:errcheck
	default:
		// Best-effort user removal; missing user is not an error during uninstall.
		exec.Command("userdel", "-r", appName).Run() //nolint:errcheck
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
func uninstallSystemd() error {
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

	deleteAllData()
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
func uninstallOpenRC() error {
	initPath := fmt.Sprintf("/etc/init.d/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop/remove errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("rc-service", appName, "stop").Run()          //nolint:errcheck
	exec.Command("rc-update", "del", appName, "default").Run() //nolint:errcheck

	if err := os.Remove(initPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove init script: %w", err)
	}

	deleteAllData()
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
func uninstallSysVinit() error {
	initPath := fmt.Sprintf("/etc/init.d/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop/deregister errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("service", appName, "stop").Run()       //nolint:errcheck
	exec.Command("update-rc.d", appName, "remove").Run() //nolint:errcheck
	exec.Command("chkconfig", "--del", appName).Run()    //nolint:errcheck

	if err := os.Remove(initPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove init script: %w", err)
	}

	deleteAllData()
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
func uninstallRunit() error {
	svDir := fmt.Sprintf("/etc/sv/%s", appName)
	linkPath := fmt.Sprintf("/var/service/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("sv", "stop", appName).Run() //nolint:errcheck

	// Best-effort cleanup of symlink and service dir during uninstall.
	os.Remove(linkPath) //nolint:errcheck
	os.RemoveAll(svDir) //nolint:errcheck

	deleteAllData()
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
func uninstallLaunchd() error {
	plistPath := launchdPlistPath()
	binaryPath := GetBinaryPath()

	// Unload errors are non-fatal during uninstall; plist removal is the critical step.
	exec.Command("launchctl", "unload", plistPath).Run() //nolint:errcheck

	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove plist file: %w", err)
	}

	deleteAllData()
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

	// Per spec: --install installs, enables, AND starts the service.
	if err := exec.Command("sc.exe", "start", appName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("Windows service '%s' installed and started\n", appName)
	return nil
}

// uninstallWindows removes a Windows service and all its data.
func uninstallWindows() error {
	binaryPath := GetBinaryPath()

	// Stop errors are non-fatal during uninstall; sc.exe delete is the critical step.
	exec.Command("sc.exe", "stop", appName).Run() //nolint:errcheck
	if err := exec.Command("sc.exe", "delete", appName).Run(); err != nil {
		return fmt.Errorf("failed to delete Windows service: %w", err)
	}

	deleteAllData()

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
func uninstallBSDRC() error {
	rcPath := fmt.Sprintf("/usr/local/etc/rc.d/%s", appName)
	binaryPath := GetBinaryPath()

	// Stop/deregister errors are non-fatal during uninstall; removal is the critical step.
	exec.Command("service", appName, "stop").Run()       //nolint:errcheck
	exec.Command("sysrc", "-x", appName+"_enable").Run() //nolint:errcheck

	if err := os.Remove(rcPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove rc.d script: %w", err)
	}

	deleteAllData()
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
